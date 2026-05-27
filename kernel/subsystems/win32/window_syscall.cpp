/*
 * DuetOS — Win32 windowing syscalls: implementation.
 *
 * Companion to window_syscall.h — see there for the public
 * SYS_WIN_* contract (CreateWindow, DestroyWindow, ShowWindow,
 * the message-pump bridge, GDI primitive surface).
 *
 * WHAT
 *   Backs every user32!*Window* import the Win32 thunks page
 *   routes into the kernel. Owns the in-kernel window table,
 *   the per-window message queue, the WndProc dispatch state,
 *   timer table, and the paint-lifecycle (BeginPaint /
 *   EndPaint / InvalidateRect / UpdateWindow) state.
 *
 * HOW
 *   Window handles are kernel-internal indices into a fixed
 *   pool. The compositor (subsystems/graphics/graphics.cpp)
 *   walks the pool every frame and renders visible windows
 *   into the framebuffer.
 *
 *   Message dispatch: WM_TIMER / WM_PAINT / input events get
 *   posted into the per-window queue; the user-space Win32
 *   message loop drains the queue via SYS_WIN_GETMSG, the
 *   kernel runs the user-supplied WndProc by transferring
 *   control back to ring 3 with a synthetic frame on the
 *   user stack.
 *
 * WHY THIS FILE IS LARGE
 *   ~30 user32 entry points + the paint lifecycle + the GDI
 *   primitive routing live here. Each is short but they
 *   accumulate, and the message-loop trampoline plumbing
 *   spans several hundred lines on its own.
 */

#include "subsystems/win32/window_syscall.h"

#include "subsystems/win32/custom.h"

#include "arch/x86_64/cpu.h"
#include "arch/x86_64/serial.h"
#include "arch/x86_64/traps.h"
#include "diag/kdbg.h"
#include "proc/process.h"
#include "syscall/syscall.h"
#include "drivers/audio/pcspk.h"
#include "drivers/input/ps2mouse.h"
#include "drivers/video/framebuffer.h"
#include "drivers/video/menu.h"
#include "drivers/video/theme.h"
#include "drivers/video/widget.h"
#include "mm/kheap.h"
#include "mm/paging.h"
#include "sched/sched.h"
#include "subsystems/win32/gdi_objects.h"
#include "sync/spinlock.h"

namespace duetos::subsystems::win32
{

namespace
{

// Per-process title storage. WindowRegister takes the title pointer
// by reference (the kernel string lifetime must out-live the
// window). PE titles come in via user memory which we can't safely
// keep a pointer into across scheduler switches. We copy the title
// into a fixed-size arena keyed by compositor slot so the window
// has a stable kernel-owned string. kMaxWindows slots keep us
// symmetric with the registry capacity — one title per slot.
constinit char g_title_arena[duetos::drivers::video::kMaxWindows][duetos::core::kWinTitleMax + 1] = {};

// Whether each arena slot is in use. We don't free entries on
// DESTROY for v0 — the window table itself is append-only in the
// widget layer. A future process-reaper slice reclaims both.
constinit bool g_title_in_use[duetos::drivers::video::kMaxWindows] = {};

// The HWND bias keeps "0 = failure" intact at the Win32 surface:
// compositor handle 0 is a real, valid window, but Win32 callers
// check `hwnd != NULL`. Bias +1 on the way out, -1 on the way in.
// Matches the kOffReturnOne convention the legacy stubs page uses
// for CreateWindowExA/W already.
constexpr u64 kHwndBias = 1;

u32 HwndToCompositorHandle(u64 hwnd_win32)
{
    if (hwnd_win32 == 0)
    {
        return duetos::drivers::video::kWindowInvalid;
    }
    const u64 unbiased = hwnd_win32 - kHwndBias;
    if (unbiased >= duetos::drivers::video::kMaxWindows)
    {
        return duetos::drivers::video::kWindowInvalid;
    }
    return static_cast<u32>(unbiased);
}

void SerialWriteDec(u64 v)
{
    if (v == 0)
    {
        duetos::arch::SerialWrite("0");
        return;
    }
    char buf[24];
    u32 n = 0;
    while (v > 0 && n < sizeof(buf))
    {
        buf[n++] = static_cast<char>('0' + (v % 10));
        v /= 10;
    }
    // Reverse in place; SerialWrite only accepts NUL-terminated —
    // reverse into a second buffer and terminate.
    char out[25];
    for (u32 i = 0; i < n; ++i)
    {
        out[i] = buf[n - 1 - i];
    }
    out[n] = '\0';
    duetos::arch::SerialWrite(out);
}

// Bounded copy from user space into the caller-supplied kernel
// buffer. Returns true only when a NUL terminator is present within
// `cap` bytes. `kdst` is always NUL-terminated on return; short
// strings at the end of a user page do not require the next page to
// be mapped because mm::CopyUserCString probes byte-by-byte.
bool CopyUserString(char* kdst, u64 cap, u64 user_ptr)
{
    return duetos::mm::CopyUserCString(kdst, cap, reinterpret_cast<const void*>(user_ptr)).ok();
}

} // namespace

void DoWinCreate(arch::TrapFrame* frame)
{
    KDBG_4V(Win32Wm, "win32/wm", "DoWinCreate", "x", frame->rdi, "y", frame->rsi, "w", frame->rdx, "h", frame->r10);
    using namespace duetos::drivers::video;

    duetos::core::Process* proc = duetos::core::CurrentProcess();
    if (proc == nullptr)
    {
        duetos::arch::SerialWrite("[sys] DoWinCreate proc=null\n");
        frame->rax = 0;
        return;
    }

    const u32 x = static_cast<u32>(frame->rdi);
    const u32 y = static_cast<u32>(frame->rsi);
    const u32 w = static_cast<u32>(frame->rdx);
    const u32 h = static_cast<u32>(frame->r10);
    const u64 title_user = frame->r8;

    // Clamp degenerate geometry up to something paintable. Win32
    // callers sometimes pass CW_USEDEFAULT (0x80000000) which
    // wraps to a giant u32 — clamp against the framebuffer so a
    // garbage arg doesn't starve the registry slot. If the
    // framebuffer is absent (serial-only boot), fall back to a
    // notional 1024x768 canvas so the registry still records
    // something sensible — the window has no visible paint but
    // the syscall round-trip is testable from the serial log.
    const FramebufferInfo fb = FramebufferGet();
    const u32 fb_w = fb.width ? fb.width : 1024;
    const u32 fb_h = fb.height ? fb.height : 768;
    u32 cw = (w == 0 || w > fb_w) ? (fb_w / 3) : w;
    u32 ch = (h == 0 || h > fb_h) ? (fb_h / 3) : h;
    u32 cx = (x >= fb_w) ? 64 : x;
    u32 cy = (y >= fb_h) ? 64 : y;
    if (cx >= fb_w)
    {
        cx = 0;
    }
    if (cy >= fb_h)
    {
        cy = 0;
    }
    if (cw == 0 || cx + cw > fb_w)
    {
        cw = (fb_w > cx) ? (fb_w - cx) : 64;
    }
    if (ch == 0 || cy + ch > fb_h)
    {
        ch = (fb_h > cy) ? (fb_h - cy) : 64;
    }

    // Acquire the compositor lock for the full critical section:
    // arena allocation, WindowRegister, and the follow-up
    // DesktopCompose all touch UI state.
    CompositorLock();

    // Pick the first free arena slot. Slots are 1:1 with the
    // widget-layer registry but we don't know our prospective
    // compositor index until after WindowRegister returns; instead
    // we reserve a slot here and use its index as the array key.
    u32 arena_slot = kMaxWindows;
    for (u32 i = 0; i < kMaxWindows; ++i)
    {
        if (!g_title_in_use[i])
        {
            arena_slot = i;
            break;
        }
    }
    if (arena_slot == kMaxWindows)
    {
        CompositorUnlock();
        duetos::arch::SerialWrite("[sys] win_create: no free title slot\n");
        frame->rax = 0;
        return;
    }

    char* title = &g_title_arena[arena_slot][0];
    if (!CopyUserString(title, duetos::core::kWinTitleMax + 1, title_user))
    {
        // Null / faulting title is permitted — fall back to a
        // visible generic label so the chrome still reads.
        const char fallback[] = "WINDOW";
        for (u32 i = 0; i < sizeof(fallback); ++i)
        {
            title[i] = fallback[i];
        }
    }
    g_title_in_use[arena_slot] = true;

    const Theme& theme = ThemeCurrent();
    WindowChrome chrome = {};
    chrome.x = cx;
    chrome.y = cy;
    chrome.w = cw;
    chrome.h = ch;
    chrome.colour_border = theme.window_border;
    // No ThemeRole for PE-created windows — use a neutral accent
    // colour consistent with the rest of the palette (re-use the
    // taskbar accent so it reads as "a system window" at a glance).
    chrome.colour_title = theme.taskbar_accent;
    chrome.colour_client = theme.console_bg;
    chrome.colour_close_btn = theme.window_close;
    chrome.title_height = 22;

    const WindowHandle h_comp = WindowRegister(chrome, title);
    if (h_comp == kWindowInvalid)
    {
        g_title_in_use[arena_slot] = false;
        CompositorUnlock();
        duetos::arch::SerialWrite("[sys] win_create: registry full\n");
        frame->rax = 0;
        return;
    }

    // Record the owning pid so the process-exit reaper can close
    // every ring-3 window in one walk when the Process refcount
    // drops to 0. pid==0 (kernel-owned boot window) is reserved —
    // ring-3 pids start at 1.
    WindowSetOwnerPid(h_comp, proc->pid);

    // Lifecycle messages. WM_CREATE (0x0001) + WM_SIZE (0x0005)
    // + WM_SHOWWINDOW (0x0018) + WM_ACTIVATE (0x0006) +
    // WM_SETFOCUS (0x0007) land in the queue so a pump sees the
    // standard startup sequence. lParam/wParam follow the Win32
    // shape where it makes sense (WM_SIZE lParam packs w/h;
    // WM_ACTIVATE wParam = WA_ACTIVE = 1).
    constexpr u32 kWmCreate = 0x0001;
    constexpr u32 kWmSize = 0x0005;
    constexpr u32 kWmActivate = 0x0006;
    constexpr u32 kWmSetFocus = 0x0007;
    constexpr u32 kWmShowWindow = 0x0018;
    const u64 size_lp = (static_cast<u64>(cw) & 0xFFFF) | ((static_cast<u64>(ch) & 0xFFFF) << 16);
    WindowPostMessage(h_comp, kWmCreate, 0, 0);
    WindowPostMessage(h_comp, kWmSize, 0 /* SIZE_RESTORED */, size_lp);
    WindowPostMessage(h_comp, kWmShowWindow, 1, 0);
    WindowPostMessage(h_comp, kWmActivate, 1 /* WA_ACTIVE */, 0);
    WindowPostMessage(h_comp, kWmSetFocus, 0, 0);

    // Force a full repaint so the window appears in the same
    // call — without this the user sees a window "exist" (their
    // HWND is valid) but nothing on screen until the next
    // unrelated compose pass.
    DesktopCompose(theme.desktop_bg, nullptr);

    CompositorUnlock();

    duetos::arch::SerialWrite("[win] create pid=");
    duetos::arch::SerialWriteHex(proc->pid);
    duetos::arch::SerialWrite(" hwnd=");
    SerialWriteDec(h_comp + kHwndBias);
    duetos::arch::SerialWrite(" rect=(");
    SerialWriteDec(cx);
    duetos::arch::SerialWrite(",");
    SerialWriteDec(cy);
    duetos::arch::SerialWrite(" ");
    SerialWriteDec(cw);
    duetos::arch::SerialWrite("x");
    SerialWriteDec(ch);
    duetos::arch::SerialWrite(") title=\"");
    duetos::arch::SerialWrite(title);
    duetos::arch::SerialWrite("\"\n");

    const u64 hwnd_biased = static_cast<u64>(h_comp) + kHwndBias;
    custom::OnHandleAlloc(proc, hwnd_biased, static_cast<u32>(duetos::core::SYS_WIN_CREATE), frame->rip);
    frame->rax = hwnd_biased;
}

void DoWinDestroy(arch::TrapFrame* frame)
{
    KDBG_V(Win32Wm, "win32/wm", "DoWinDestroy hwnd", frame->rdi);
    using namespace duetos::drivers::video;

    duetos::core::Process* proc = duetos::core::CurrentProcess();
    if (proc == nullptr)
    {
        duetos::arch::SerialWrite("[sys] DoWinDestroy proc=null\n");
        frame->rax = 0;
        return;
    }

    const u32 h_comp = HwndToCompositorHandle(frame->rdi);
    if (h_comp == kWindowInvalid || !WindowIsAlive(h_comp))
    {
        frame->rax = 0;
        return;
    }

    CompositorLock();
    // Post WM_DESTROY just before the close — any queue
    // inspector between now and the next compose sees it.
    // WM_NCDESTROY follows but nothing in v1 differentiates
    // them, so one post covers both semantics.
    constexpr u32 kWmDestroy = 0x0002;
    WindowPostMessage(h_comp, kWmDestroy, 0, 0);
    WindowTimerReap(proc->pid, h_comp);
    WindowClose(h_comp);
    const Theme& theme = ThemeCurrent();
    DesktopCompose(theme.desktop_bg, nullptr);
    CompositorUnlock();
    WindowMsgWakeAll();

    duetos::arch::SerialWrite("[win] destroy pid=");
    duetos::arch::SerialWriteHex(proc->pid);
    duetos::arch::SerialWrite(" hwnd=");
    SerialWriteDec(frame->rdi);
    duetos::arch::SerialWrite("\n");

    custom::OnHandleClose(proc, frame->rdi);
    frame->rax = 1;
}

void DoWinShow(arch::TrapFrame* frame)
{
    using namespace duetos::drivers::video;

    const u32 h_comp = HwndToCompositorHandle(frame->rdi);
    const u64 cmd = frame->rsi;

    if (h_comp == kWindowInvalid)
    {
        frame->rax = 0;
        return;
    }

    CompositorLock();
    // v1: previous visibility state reported back as the Win32
    // ShowWindow BOOL return value. FALSE if the window wasn't
    // visible before this call.
    const bool was_visible = WindowIsVisible(h_comp);
    constexpr u32 kWmShowWindow = 0x0018;
    constexpr u32 kWmActivate = 0x0006;
    constexpr u32 kWmKillFocus = 0x0008;
    constexpr u32 kWmSetFocus = 0x0007;
    if (cmd == 0)
    {
        // SW_HIDE: clear the visible bit. Window stays alive in
        // the registry; hit-test + draw both skip it. Can be
        // re-shown with SW_SHOW / SW_SHOWNORMAL.
        if (WindowIsAlive(h_comp))
        {
            WindowSetVisible(h_comp, false);
            WindowPostMessage(h_comp, kWmShowWindow, 0, 0);
            WindowPostMessage(h_comp, kWmActivate, 0 /* WA_INACTIVE */, 0);
            WindowPostMessage(h_comp, kWmKillFocus, 0, 0);
        }
    }
    else
    {
        // SW_SHOW / SW_SHOWNORMAL / SW_MAXIMIZE / … — set
        // visible + raise to topmost / activate.
        if (WindowIsAlive(h_comp))
        {
            WindowSetVisible(h_comp, true);
            WindowRaise(h_comp);
            WindowPostMessage(h_comp, kWmShowWindow, 1, 0);
            WindowPostMessage(h_comp, kWmActivate, 1 /* WA_ACTIVE */, 0);
            WindowPostMessage(h_comp, kWmSetFocus, 0, 0);
        }
    }
    const Theme& theme = ThemeCurrent();
    DesktopCompose(theme.desktop_bg, nullptr);
    CompositorUnlock();
    WindowMsgWakeAll();

    frame->rax = was_visible ? 1 : 0;
}

void DoWinMsgBox(arch::TrapFrame* frame)
{
    duetos::core::Process* proc = duetos::core::CurrentProcess();
    const u64 pid = (proc != nullptr) ? proc->pid : 0;

    char text[duetos::core::kWinMsgBoxTextMax + 1];
    char caption[duetos::core::kWinTitleMax + 1];
    const bool have_text = CopyUserString(text, sizeof(text), frame->rdi);
    const bool have_cap = CopyUserString(caption, sizeof(caption), frame->rsi);

    duetos::arch::SerialWrite("[msgbox] pid=");
    duetos::arch::SerialWriteHex(pid);
    duetos::arch::SerialWrite(" caption=\"");
    duetos::arch::SerialWrite(have_cap ? caption : "MessageBox");
    duetos::arch::SerialWrite("\" text=\"");
    duetos::arch::SerialWrite(have_text ? text : "");
    duetos::arch::SerialWrite("\"\n");

    // IDOK per Win32 convention: every MessageBox caller that
    // branches on the return code takes the "OK" path.
    frame->rax = 1;
}

namespace
{

// Layout of the MSG slice we copy to user for PeekMessage /
// GetMessage. Matches the first 32 bytes of the Win32 MSG struct:
// { HWND hwnd; UINT message; UINT _pad; WPARAM wParam; LPARAM
// lParam; }. Time / pt / lPrivate are left for the user stub to
// zero (or ignore).
struct UserMsg
{
    u64 hwnd;
    u32 message;
    u32 _pad;
    u64 wparam;
    u64 lparam;
};

// Win32 COLORREF is 0x00BBGGRR; the framebuffer uses 0x00RRGGBB.
// Convert at the syscall boundary so ring-3 callers don't need to
// know about our internal layout.
u32 ColorRefToRgb(u64 colorref)
{
    const u32 c = static_cast<u32>(colorref);
    const u32 r = (c >> 0) & 0xFF;
    const u32 g = (c >> 8) & 0xFF;
    const u32 b = (c >> 16) & 0xFF;
    return (r << 16) | (g << 8) | b;
}

bool CopyMsgToUser(const duetos::drivers::video::WindowMsg& m, u64 user_ptr)
{
    if (user_ptr == 0)
    {
        return false;
    }
    UserMsg out{};
    out.hwnd = static_cast<u64>(m.hwnd_biased);
    out.message = m.message;
    out.wparam = m.wparam;
    out.lparam = m.lparam;
    return duetos::mm::CopyToUser(reinterpret_cast<void*>(user_ptr), &out, sizeof(out));
}

} // namespace

// Resolve a user-supplied biased HWND to a compositor handle AND
// verify it belongs to the calling process. Prevents a ring-3
// PE from reading/writing another process's message queue. For
// v0 this also refuses pid == 0 (kernel-owned boot windows) so
// a PE can't PostMessage to the Calculator. Declared in
// window_syscall.h so other subsystem modules (GDI object
// handlers in gdi_objects.cpp) can share it.
u32 HwndToCompositorHandleForCaller(u64 hwnd_biased, u64 pid)
{
    using namespace duetos::drivers::video;
    const u32 h_comp = HwndToCompositorHandle(hwnd_biased);
    if (h_comp == kWindowInvalid)
    {
        return kWindowInvalid;
    }
    if (!WindowIsAlive(h_comp))
    {
        return kWindowInvalid;
    }
    if (WindowOwnerPid(h_comp) != pid)
    {
        return kWindowInvalid;
    }
    return h_comp;
}

void DoWinPeekMsg(arch::TrapFrame* frame)
{
    using namespace duetos::drivers::video;

    duetos::core::Process* proc = duetos::core::CurrentProcess();
    if (proc == nullptr || frame->rdi == 0)
    {
        frame->rax = 0;
        return;
    }

    const u64 filter_hwnd = frame->rsi;
    const bool remove = (frame->rdx != 0);

    CompositorLock();
    WindowMsg m{};
    bool got = false;
    if (filter_hwnd == 0)
    {
        // Any window owned by this pid. Peek-only path walks the
        // first non-empty queue without mutating; remove path uses
        // WindowPopMessageAny.
        if (remove)
        {
            got = WindowPopMessageAny(proc->pid, &m);
        }
        else
        {
            got = WindowPeekMessageAny(proc->pid, &m);
        }
    }
    else
    {
        const u32 h_comp = HwndToCompositorHandleForCaller(filter_hwnd, proc->pid);
        if (h_comp != kWindowInvalid)
        {
            got = remove ? WindowPopMessage(h_comp, &m) : WindowPeekMessage(h_comp, &m);
        }
    }
    CompositorUnlock();

    if (!got)
    {
        frame->rax = 0;
        return;
    }
    if (!CopyMsgToUser(m, frame->rdi))
    {
        // Copy failed; treat as "no message available" — the
        // message is lost (peek-only case) or was already removed
        // from the ring (remove case). Match Win32 behaviour of
        // returning FALSE on invalid lpMsg.
        frame->rax = 0;
        return;
    }
    frame->rax = 1;
}

void DoWinGetMsg(arch::TrapFrame* frame)
{
    KDBG_V(Win32Wm, "win32/wm", "DoWinGetMsg msg_user", frame->rdi);
    using namespace duetos::drivers::video;
    // WM_QUIT per Win32. Breaks the user's message loop.
    constexpr u32 kWmQuit = 0x0012;

    duetos::core::Process* proc = duetos::core::CurrentProcess();
    if (proc == nullptr || frame->rdi == 0)
    {
        frame->rax = static_cast<u64>(-1);
        return;
    }

    const u64 filter_hwnd = frame->rsi;

    for (;;)
    {
        // Under the compositor lock: try to dequeue. If nothing
        // is pending, disable interrupts before we drop the
        // compositor lock + enter the wait queue, so a wake that
        // lands between those two steps can't be missed (same
        // "lost wake" pattern the WaitQueueBlock contract warns
        // about).
        CompositorLock();
        WindowMsg m{};
        bool got = false;
        if (filter_hwnd == 0)
        {
            got = WindowPopMessageAny(proc->pid, &m);
        }
        else
        {
            const u32 h_comp = HwndToCompositorHandleForCaller(filter_hwnd, proc->pid);
            if (h_comp != kWindowInvalid)
            {
                got = WindowPopMessage(h_comp, &m);
            }
        }

        if (got)
        {
            CompositorUnlock();
            if (!CopyMsgToUser(m, frame->rdi))
            {
                frame->rax = static_cast<u64>(-1);
                return;
            }
            // WM_QUIT breaks the caller's message loop. Standard
            // Win32 behaviour: GetMessage returns FALSE, the
            // message IS dequeued (the caller sees the exit code
            // in wParam).
            frame->rax = (m.message == kWmQuit) ? 0 : 1;
            return;
        }

        // Nothing pending — block on the global message wait
        // queue. `WindowMsgWakeAll` is broadcast, so we loop on
        // return to re-check our per-window ring. The 1-tick
        // (10 ms) timeout is the safety net against a lost wake
        // landing in the narrow window between "check queue"
        // and "enter wait queue" (the classic condvar race; a
        // proper fix would hold the wait-queue lock while
        // dropping the compositor lock, which needs a bigger
        // refactor).
        CompositorUnlock();
        duetos::arch::Cli();
        WindowMsgWaitBlockTimeout(1);
        duetos::arch::Sti();
    }
}

void DoWinPostMsg(arch::TrapFrame* frame)
{
    using namespace duetos::drivers::video;

    duetos::core::Process* proc = duetos::core::CurrentProcess();
    if (proc == nullptr)
    {
        frame->rax = 0;
        return;
    }
    // Cross-process PostMessage is allowed — Win32 lets any
    // caller post to any HWND. GetMessage still filters by
    // owner pid so the target is the only consumer.
    CompositorLock();
    const u32 h_comp = HwndToCompositorHandle(frame->rdi);
    bool ok = false;
    if (h_comp != kWindowInvalid && WindowIsAlive(h_comp))
    {
        ok = WindowPostMessage(h_comp, static_cast<u32>(frame->rsi), frame->rdx, frame->r10);
    }
    CompositorUnlock();
    if (ok)
    {
        // Broadcast wake so any GetMessage blocker re-checks —
        // the wake side runs OUTSIDE the compositor lock so a
        // blocker waking up can immediately reacquire.
        WindowMsgWakeAll();
    }
    frame->rax = ok ? 1 : 0;
}

void DoGdiFillRect(arch::TrapFrame* frame)
{
    KDBG(Gdi, "win32/gdi", "DoGdiFillRect");
    using namespace duetos::drivers::video;

    duetos::core::Process* proc = duetos::core::CurrentProcess();
    if (proc == nullptr)
    {
        frame->rax = 0;
        return;
    }
    CompositorLock();
    const u32 h_comp = HwndToCompositorHandleForCaller(frame->rdi, proc->pid);
    bool ok = false;
    if (h_comp != kWindowInvalid)
    {
        const i32 x = static_cast<i32>(frame->rsi);
        const i32 y = static_cast<i32>(frame->rdx);
        const i32 w = static_cast<i32>(frame->r10);
        const i32 h = static_cast<i32>(frame->r8);
        WindowClientFillRect(h_comp, x, y, w, h, ColorRefToRgb(frame->r9));
        const Theme& theme = ThemeCurrent();
        DesktopCompose(theme.desktop_bg, nullptr);
        ok = true;
    }
    CompositorUnlock();
    frame->rax = ok ? 1 : 0;
}

void DoGdiRectangle(arch::TrapFrame* frame)
{
    using namespace duetos::drivers::video;

    duetos::core::Process* proc = duetos::core::CurrentProcess();
    if (proc == nullptr)
    {
        frame->rax = 0;
        return;
    }
    CompositorLock();
    const u32 h_comp = HwndToCompositorHandleForCaller(frame->rdi, proc->pid);
    bool ok = false;
    if (h_comp != kWindowInvalid)
    {
        const i32 x = static_cast<i32>(frame->rsi);
        const i32 y = static_cast<i32>(frame->rdx);
        const i32 w = static_cast<i32>(frame->r10);
        const i32 h = static_cast<i32>(frame->r8);
        WindowClientRectangle(h_comp, x, y, w, h, ColorRefToRgb(frame->r9));
        const Theme& theme = ThemeCurrent();
        DesktopCompose(theme.desktop_bg, nullptr);
        ok = true;
    }
    CompositorUnlock();
    frame->rax = ok ? 1 : 0;
}

void DoGdiTextOut(arch::TrapFrame* frame)
{
    using namespace duetos::drivers::video;

    duetos::core::Process* proc = duetos::core::CurrentProcess();
    if (proc == nullptr)
    {
        frame->rax = 0;
        return;
    }
    char text[kWinTextOutMax + 1];
    for (u32 i = 0; i < sizeof(text); ++i)
        text[i] = '\0';
    const u64 user_text = frame->r10;
    const u64 user_len = frame->r8;
    if (user_text != 0 && user_len > 0)
    {
        const u64 copy_len = (user_len > kWinTextOutMax) ? kWinTextOutMax : user_len;
        if (!duetos::mm::CopyFromUser(text, reinterpret_cast<const void*>(user_text), copy_len))
        {
            frame->rax = 0;
            return;
        }
        text[copy_len] = '\0';
    }
    // Dispatch by HDC handle tag — memDC target paints the glyphs
    // into the selected bitmap (8x8 font), otherwise treat the HDC
    // as an HWND and record a TextOut display-list primitive.
    const i32 x = static_cast<i32>(frame->rsi);
    const i32 y = static_cast<i32>(frame->rdx);
    const u32 rgb = ColorRefToRgb(frame->r9);
    const u64 hdc = frame->rdi;
    const u64 tag = hdc & kGdiTagMask;
    bool ok = false;
    if (tag == kGdiTagMemDC)
    {
        MemDC* dc = GdiLookupMemDC(hdc);
        if (dc != nullptr && dc->selected_bitmap != 0)
        {
            Bitmap* bmp = GdiLookupBitmap(dc->selected_bitmap);
            if (bmp != nullptr)
            {
                // For memDC targets the syscall's r9 carries the
                // TextOutA fallback colour (white from the IAT stub)
                // which we ignore in favour of the DC's SetTextColor
                // state. bk_mode=OPAQUE fills the glyph cell
                // background with bk_color; TRANSPARENT leaves it
                // unchanged.
                const bool opaque = (dc->bk_mode == kBkModeOpaque);
                GdiPaintTextOnBitmap(bmp, x, y, text, dc->text_color, dc->bk_color, opaque);
                ok = true;
            }
        }
    }
    else
    {
        // Window HDC — consult per-window DC state for text colour
        // if the app called SetTextColor; otherwise fall back to
        // the syscall's colour arg (which came from the IAT stub's
        // default-white for TextOutA, or the caller's explicit
        // COLORREF for the native SYS_GDI_TEXT_OUT path).
        u32 paint_rgb = rgb;
        WindowDcState* s = GdiWindowDcState(static_cast<u32>(hdc));
        if (s != nullptr && s->text_color_set)
            paint_rgb = s->text_color;
        CompositorLock();
        const u32 h_comp = HwndToCompositorHandleForCaller(hdc, proc->pid);
        if (h_comp != kWindowInvalid)
        {
            WindowClientTextOut(h_comp, x, y, text, paint_rgb);
            const Theme& theme = ThemeCurrent();
            DesktopCompose(theme.desktop_bg, nullptr);
            ok = true;
        }
        CompositorUnlock();
    }
    frame->rax = ok ? 1 : 0;
}

void DoGdiTextOutW(arch::TrapFrame* frame)
{
    using namespace duetos::drivers::video;

    duetos::core::Process* proc = duetos::core::CurrentProcess();
    if (proc == nullptr)
    {
        frame->rax = 0;
        return;
    }
    // UTF-16 copy-in + high-byte strip. Each wchar_t (u16) becomes
    // one char. Non-ASCII (> 0x7F) falls back to '?' so the glyph
    // lookup gets a valid placeholder.
    char text[kWinTextOutMax + 1];
    for (u32 i = 0; i < sizeof(text); ++i)
        text[i] = '\0';
    const u64 user_text = frame->r10;
    const u64 user_len_wchars = frame->r8;
    if (user_text != 0 && user_len_wchars > 0)
    {
        const u64 clamp = (user_len_wchars > kWinTextOutMax) ? kWinTextOutMax : user_len_wchars;
        // Copy the UTF-16 source into a small on-stack buffer, then
        // walk it byte-by-byte to produce ASCII. Stack-bounce is
        // kWinTextOutMax * 2 = 96 bytes at kWinTextOutMax=47.
        u16 wbuf[kWinTextOutMax];
        if (!duetos::mm::CopyFromUser(wbuf, reinterpret_cast<const void*>(user_text), clamp * 2))
        {
            frame->rax = 0;
            return;
        }
        for (u64 i = 0; i < clamp; ++i)
        {
            const u16 wc = wbuf[i];
            text[i] = (wc < 0x80) ? static_cast<char>(wc) : '?';
        }
        text[clamp] = '\0';
    }
    // Dispatch — identical to DoGdiTextOut from here on.
    const i32 x = static_cast<i32>(frame->rsi);
    const i32 y = static_cast<i32>(frame->rdx);
    const u32 rgb = ColorRefToRgb(frame->r9);
    const u64 hdc = frame->rdi;
    const u64 tag = hdc & kGdiTagMask;
    bool ok = false;
    if (tag == kGdiTagMemDC)
    {
        MemDC* dc = GdiLookupMemDC(hdc);
        if (dc != nullptr && dc->selected_bitmap != 0)
        {
            Bitmap* bmp = GdiLookupBitmap(dc->selected_bitmap);
            if (bmp != nullptr)
            {
                const bool opaque = (dc->bk_mode == kBkModeOpaque);
                GdiPaintTextOnBitmap(bmp, x, y, text, dc->text_color, dc->bk_color, opaque);
                ok = true;
            }
        }
    }
    else
    {
        u32 paint_rgb = rgb;
        WindowDcState* s = GdiWindowDcState(static_cast<u32>(hdc));
        if (s != nullptr && s->text_color_set)
            paint_rgb = s->text_color;
        CompositorLock();
        const u32 h_comp = HwndToCompositorHandleForCaller(hdc, proc->pid);
        if (h_comp != kWindowInvalid)
        {
            WindowClientTextOut(h_comp, x, y, text, paint_rgb);
            const Theme& theme = ThemeCurrent();
            DesktopCompose(theme.desktop_bg, nullptr);
            ok = true;
        }
        CompositorUnlock();
    }
    frame->rax = ok ? 1 : 0;
}

void DoGdiClear(arch::TrapFrame* frame)
{
    using namespace duetos::drivers::video;

    duetos::core::Process* proc = duetos::core::CurrentProcess();
    if (proc == nullptr)
    {
        frame->rax = 0;
        return;
    }
    CompositorLock();
    const u32 h_comp = HwndToCompositorHandleForCaller(frame->rdi, proc->pid);
    bool ok = false;
    if (h_comp != kWindowInvalid)
    {
        WindowClearDisplayList(h_comp);
        const Theme& theme = ThemeCurrent();
        DesktopCompose(theme.desktop_bg, nullptr);
        ok = true;
    }
    CompositorUnlock();
    frame->rax = ok ? 1 : 0;
}

void DoWinMove(arch::TrapFrame* frame)
{
    using namespace duetos::drivers::video;

    duetos::core::Process* proc = duetos::core::CurrentProcess();
    if (proc == nullptr)
    {
        frame->rax = 0;
        return;
    }
    const u32 x = static_cast<u32>(frame->rsi);
    const u32 y = static_cast<u32>(frame->rdx);
    const u32 w = static_cast<u32>(frame->r10);
    const u32 h = static_cast<u32>(frame->r8);
    const u64 flags = frame->r9;
    constexpr u64 kNoMove = 1;
    constexpr u64 kNoSize = 2;

    CompositorLock();
    const u32 h_comp = HwndToCompositorHandleForCaller(frame->rdi, proc->pid);
    bool ok = false;
    bool did_move = false;
    bool did_size = false;
    if (h_comp != kWindowInvalid)
    {
        if ((flags & kNoMove) == 0)
        {
            WindowMoveTo(h_comp, x, y);
            did_move = true;
        }
        if ((flags & kNoSize) == 0)
        {
            WindowResizeTo(h_comp, w, h);
            did_size = true;
        }
        // Post WM_MOVE / WM_SIZE to the window. lParam packs
        // x/y or w/h per Win32 (LOWORD = x/w, HIWORD = y/h).
        constexpr u32 kWmMove = 0x0003;
        constexpr u32 kWmSize = 0x0005;
        u32 wx = 0, wy = 0, ww = 0, wh = 0;
        (void)WindowGetBounds(h_comp, &wx, &wy, &ww, &wh);
        if (did_move)
        {
            const u64 lp = (static_cast<u64>(wx) & 0xFFFF) | ((static_cast<u64>(wy) & 0xFFFF) << 16);
            WindowPostMessage(h_comp, kWmMove, 0, lp);
        }
        if (did_size)
        {
            const u64 lp = (static_cast<u64>(ww) & 0xFFFF) | ((static_cast<u64>(wh) & 0xFFFF) << 16);
            WindowPostMessage(h_comp, kWmSize, 0 /* SIZE_RESTORED */, lp);
        }
        const Theme& theme = ThemeCurrent();
        DesktopCompose(theme.desktop_bg, nullptr);
        ok = true;
    }
    CompositorUnlock();
    if (ok && (did_move || did_size))
    {
        WindowMsgWakeAll();
    }
    frame->rax = ok ? 1 : 0;
}

void DoWinGetRect(arch::TrapFrame* frame)
{
    using namespace duetos::drivers::video;

    duetos::core::Process* proc = duetos::core::CurrentProcess();
    if (proc == nullptr)
    {
        frame->rax = 0;
        return;
    }
    const u64 selector = frame->rsi;
    const u64 user_ptr = frame->rdx;
    if (user_ptr == 0)
    {
        frame->rax = 0;
        return;
    }

    CompositorLock();
    const u32 h_comp = HwndToCompositorHandleForCaller(frame->rdi, proc->pid);
    i32 rect[4] = {0, 0, 0, 0};
    bool ok = false;
    if (h_comp != kWindowInvalid)
    {
        u32 wx = 0, wy = 0, ww = 0, wh = 0;
        if (WindowGetBounds(h_comp, &wx, &wy, &ww, &wh))
        {
            if (selector == 1)
            {
                // Client rect: local coords, 0..width/height.
                // Title bar trimmed off the top (22 px default,
                // or chrome.title_height if non-zero), 2-px
                // border on every other edge.
                const u32 tbh = 22; // match widget chrome default
                rect[0] = 0;
                rect[1] = 0;
                rect[2] = static_cast<i32>((ww > 4) ? ww - 4 : 0);
                rect[3] = static_cast<i32>((wh > tbh + 4) ? wh - tbh - 4 : 0);
            }
            else
            {
                rect[0] = static_cast<i32>(wx);
                rect[1] = static_cast<i32>(wy);
                rect[2] = static_cast<i32>(wx + ww);
                rect[3] = static_cast<i32>(wy + wh);
            }
            ok = true;
        }
    }
    CompositorUnlock();

    if (!ok)
    {
        frame->rax = 0;
        return;
    }
    if (!duetos::mm::CopyToUser(reinterpret_cast<void*>(user_ptr), rect, sizeof(rect)))
    {
        frame->rax = 0;
        return;
    }
    frame->rax = 1;
}

// --- Timer syscalls -----------------------------------------------

void DoWinTimerSet(arch::TrapFrame* frame)
{
    using namespace duetos::drivers::video;

    duetos::core::Process* proc = duetos::core::CurrentProcess();
    if (proc == nullptr)
    {
        frame->rax = 0;
        return;
    }
    const u32 timer_id = static_cast<u32>(frame->rsi);
    const u32 interval_ms = static_cast<u32>(frame->rdx);
    if (interval_ms == 0)
    {
        frame->rax = 0;
        return;
    }
    CompositorLock();
    const u32 h_comp = HwndToCompositorHandleForCaller(frame->rdi, proc->pid);
    bool ok = false;
    if (h_comp != kWindowInvalid)
    {
        ok = WindowTimerSet(proc->pid, h_comp, timer_id, interval_ms);
    }
    CompositorUnlock();
    frame->rax = ok ? static_cast<u64>(timer_id) : 0;
}

void DoWinTimerKill(arch::TrapFrame* frame)
{
    using namespace duetos::drivers::video;

    duetos::core::Process* proc = duetos::core::CurrentProcess();
    if (proc == nullptr)
    {
        frame->rax = 0;
        return;
    }
    const u32 timer_id = static_cast<u32>(frame->rsi);
    CompositorLock();
    const u32 h_comp = HwndToCompositorHandleForCaller(frame->rdi, proc->pid);
    bool ok = false;
    if (h_comp != kWindowInvalid)
    {
        ok = WindowTimerKill(proc->pid, h_comp, timer_id);
    }
    CompositorUnlock();
    frame->rax = ok ? 1 : 0;
}

// --- GDI extra primitives -----------------------------------------

void DoGdiLine(arch::TrapFrame* frame)
{
    using namespace duetos::drivers::video;

    duetos::core::Process* proc = duetos::core::CurrentProcess();
    if (proc == nullptr)
    {
        frame->rax = 0;
        return;
    }
    CompositorLock();
    const u32 h_comp = HwndToCompositorHandleForCaller(frame->rdi, proc->pid);
    bool ok = false;
    if (h_comp != kWindowInvalid)
    {
        const i32 x0 = static_cast<i32>(frame->rsi);
        const i32 y0 = static_cast<i32>(frame->rdx);
        const i32 x1 = static_cast<i32>(frame->r10);
        const i32 y1 = static_cast<i32>(frame->r8);
        WindowClientLine(h_comp, x0, y0, x1, y1, ColorRefToRgb(frame->r9));
        const Theme& theme = ThemeCurrent();
        DesktopCompose(theme.desktop_bg, nullptr);
        ok = true;
    }
    CompositorUnlock();
    frame->rax = ok ? 1 : 0;
}

void DoGdiEllipse(arch::TrapFrame* frame)
{
    using namespace duetos::drivers::video;

    duetos::core::Process* proc = duetos::core::CurrentProcess();
    if (proc == nullptr)
    {
        frame->rax = 0;
        return;
    }
    CompositorLock();
    const u32 h_comp = HwndToCompositorHandleForCaller(frame->rdi, proc->pid);
    bool ok = false;
    if (h_comp != kWindowInvalid)
    {
        const i32 x = static_cast<i32>(frame->rsi);
        const i32 y = static_cast<i32>(frame->rdx);
        const i32 w = static_cast<i32>(frame->r10);
        const i32 h = static_cast<i32>(frame->r8);
        WindowClientEllipse(h_comp, x, y, w, h, ColorRefToRgb(frame->r9));
        const Theme& theme = ThemeCurrent();
        DesktopCompose(theme.desktop_bg, nullptr);
        ok = true;
    }
    CompositorUnlock();
    frame->rax = ok ? 1 : 0;
}

void DoGdiSetPixel(arch::TrapFrame* frame)
{
    using namespace duetos::drivers::video;

    duetos::core::Process* proc = duetos::core::CurrentProcess();
    if (proc == nullptr)
    {
        frame->rax = 0;
        return;
    }
    CompositorLock();
    const u32 h_comp = HwndToCompositorHandleForCaller(frame->rdi, proc->pid);
    bool ok = false;
    if (h_comp != kWindowInvalid)
    {
        const i32 x = static_cast<i32>(frame->rsi);
        const i32 y = static_cast<i32>(frame->rdx);
        WindowClientPixel(h_comp, x, y, ColorRefToRgb(frame->r10));
        const Theme& theme = ThemeCurrent();
        DesktopCompose(theme.desktop_bg, nullptr);
        ok = true;
    }
    CompositorUnlock();
    frame->rax = ok ? 1 : 0;
}

void DoGdiBitBlt(arch::TrapFrame* frame)
{
    using namespace duetos::drivers::video;

    duetos::core::Process* proc = duetos::core::CurrentProcess();
    if (proc == nullptr)
    {
        frame->rax = 0;
        return;
    }
    const i32 dst_x = static_cast<i32>(frame->rsi);
    const i32 dst_y = static_cast<i32>(frame->rdx);
    const u32 src_w = static_cast<u32>(frame->r10);
    const u32 src_h = static_cast<u32>(frame->r8);
    const u64 user_src = frame->r9;

    // Reject empty / absurd sizes up front; cap against the pool
    // so a malicious caller can't burn kheap on a huge allocation.
    if (src_w == 0 || src_h == 0 || user_src == 0)
    {
        frame->rax = 0;
        return;
    }
    const u64 bytes64 = static_cast<u64>(src_w) * static_cast<u64>(src_h) * 4;
    if (bytes64 > kWinBlitPoolBytes)
    {
        frame->rax = 0;
        return;
    }
    const u32 bytes = static_cast<u32>(bytes64);

    // Stage pixels in a kheap bounce buffer. Two copies (user →
    // staging → blit pool) but bounded by pool size = 16 KiB, so
    // cheap; avoids holding the compositor lock while we touch
    // user memory.
    u32* staging = static_cast<u32*>(duetos::mm::KMalloc(bytes));
    if (staging == nullptr)
    {
        frame->rax = 0;
        return;
    }
    if (!duetos::mm::CopyFromUser(staging, reinterpret_cast<const void*>(user_src), bytes))
    {
        duetos::mm::KFree(staging);
        frame->rax = 0;
        return;
    }

    CompositorLock();
    const u32 h_comp = HwndToCompositorHandleForCaller(frame->rdi, proc->pid);
    bool ok = false;
    if (h_comp != kWindowInvalid)
    {
        WindowClientBitBlt(h_comp, dst_x, dst_y, staging, src_w, src_h);
        const Theme& theme = ThemeCurrent();
        DesktopCompose(theme.desktop_bg, nullptr);
        ok = true;
    }
    CompositorUnlock();

    duetos::mm::KFree(staging);
    frame->rax = ok ? 1 : 0;
}

// --- Async input state + cursor + capture -------------------------
//
// kCapInput is gated centrally by `SyscallGate` (cap_table.def) for
// SYS_WIN_GET_KEYSTATE and SYS_WIN_GET_CURSOR — a process missing
// the cap returns -1 from the gate before ever reaching these
// handlers.

void DoWinGetKeyState(arch::TrapFrame* frame)
{
    using namespace duetos::drivers::video;
    const u16 code = static_cast<u16>(frame->rdi & 0xFFFF);
    // Win32 layout: high bit of low word set iff currently
    // down; bit 0 set iff toggled (v1 doesn't track toggled —
    // zero for now, except for CapsLock/NumLock which
    // WindowKeyIsDown tracks as press events, not toggles).
    const bool down = WindowKeyIsDown(code);
    frame->rax = down ? 0x8000u : 0;
}

void DoWinGetCursor(arch::TrapFrame* frame)
{
    using namespace duetos::drivers::video;
    const u64 user_ptr = frame->rdi;
    if (user_ptr == 0)
    {
        frame->rax = 0;
        return;
    }
    u32 x = 0, y = 0;
    CompositorLock();
    WindowGetCursor(&x, &y);
    CompositorUnlock();
    i32 pt[2] = {static_cast<i32>(x), static_cast<i32>(y)};
    if (!duetos::mm::CopyToUser(reinterpret_cast<void*>(user_ptr), pt, sizeof(pt)))
    {
        frame->rax = 0;
        return;
    }
    frame->rax = 1;
}

void DoWinSetCursor(arch::TrapFrame* frame)
{
    using namespace duetos::drivers::video;
    const u32 x = static_cast<u32>(frame->rdi);
    const u32 y = static_cast<u32>(frame->rsi);
    CompositorLock();
    WindowSetCursor(x, y);
    CompositorUnlock();
    frame->rax = 1;
}

// Mouse motion + wheel accumulator — drained by SYS_WIN_GET_MOUSE_DELTA
// (DirectInput's `IDirectInputDevice8::GetDeviceState` for mouse
// devices). Each input source (PS/2, xHCI HID) calls
// `MouseInputAccumulate` for every packet; readers drain the totals.
//
// Why a separate path from the cursor: the cursor position can be
// programmatically warped (SetCursor / WindowSetCursor for capture
// confinement). DirectInput consumers want raw motion regardless of
// any warps, so we accumulate the per-packet `dx/dy` here, untouched
// by the warp logic in the compositor.
namespace
{
struct MouseAccum
{
    sync::SpinLock lock;
    i32 dx;
    i32 dy;
    i32 dz;     // wheel (z axis); positive = away from user (Win32 convention)
    u8 buttons; // last-seen button mask (snapshot, not accumulated)
};
MouseAccum g_mouse_accum{};
} // namespace

void MouseInputAccumulate(i32 dx, i32 dy, i32 dz, u8 buttons)
{
    sync::SpinLockGuard g(g_mouse_accum.lock);
    // Saturate at i32 limits — a stuck IRQ source must not overflow
    // and wrap into the opposite sign.
    auto add_sat = [](i32 cur, i32 add) -> i32
    {
        const i64 sum = static_cast<i64>(cur) + static_cast<i64>(add);
        if (sum > 0x7FFFFFFFll)
            return 0x7FFFFFFF;
        if (sum < -0x80000000ll)
            return static_cast<i32>(-0x80000000ll);
        return static_cast<i32>(sum);
    };
    g_mouse_accum.dx = add_sat(g_mouse_accum.dx, dx);
    g_mouse_accum.dy = add_sat(g_mouse_accum.dy, dy);
    g_mouse_accum.dz = add_sat(g_mouse_accum.dz, dz);
    g_mouse_accum.buttons = buttons;
}

void DoWinGetMouseDelta(arch::TrapFrame* frame)
{
    const u64 user_ptr = frame->rdi;
    if (user_ptr == 0)
    {
        frame->rax = 0;
        return;
    }

    // Snapshot + zero under the lock so two concurrent readers (e.g.
    // a Win32 PE polling DI mouse and a kernel diagnostic shell
    // command) see disjoint deltas — the bytes a reader sees are the
    // bytes the next reader doesn't.
    i32 dx, dy, dz;
    u8 buttons;
    {
        sync::SpinLockGuard g(g_mouse_accum.lock);
        dx = g_mouse_accum.dx;
        dy = g_mouse_accum.dy;
        dz = g_mouse_accum.dz;
        buttons = g_mouse_accum.buttons;
        g_mouse_accum.dx = 0;
        g_mouse_accum.dy = 0;
        g_mouse_accum.dz = 0;
    }

    // DIMOUSESTATE-shaped output: lX, lY, lZ as i32; rgbButtons[4]
    // each high-bit-set when down. Match the layout dinput8 expected
    // from the previous keystate-poll path so the DLL doesn't need a
    // second packing.
    u8 out[16] = {};
    out[0] = static_cast<u8>(dx & 0xFF);
    out[1] = static_cast<u8>((dx >> 8) & 0xFF);
    out[2] = static_cast<u8>((dx >> 16) & 0xFF);
    out[3] = static_cast<u8>((dx >> 24) & 0xFF);
    out[4] = static_cast<u8>(dy & 0xFF);
    out[5] = static_cast<u8>((dy >> 8) & 0xFF);
    out[6] = static_cast<u8>((dy >> 16) & 0xFF);
    out[7] = static_cast<u8>((dy >> 24) & 0xFF);
    out[8] = static_cast<u8>(dz & 0xFF);
    out[9] = static_cast<u8>((dz >> 8) & 0xFF);
    out[10] = static_cast<u8>((dz >> 16) & 0xFF);
    out[11] = static_cast<u8>((dz >> 24) & 0xFF);
    out[12] = (buttons & duetos::drivers::input::kMouseButtonLeft) ? 0x80 : 0;
    out[13] = (buttons & duetos::drivers::input::kMouseButtonRight) ? 0x80 : 0;
    out[14] = (buttons & duetos::drivers::input::kMouseButtonMiddle) ? 0x80 : 0;
    out[15] = 0; // X1 — not reported by PS/2; xHCI HID can fill once wired

    if (!duetos::mm::CopyToUser(reinterpret_cast<void*>(user_ptr), out, sizeof(out)))
    {
        frame->rax = 0;
        return;
    }
    frame->rax = 1;
}

void DoWinSetCapture(arch::TrapFrame* frame)
{
    using namespace duetos::drivers::video;

    duetos::core::Process* proc = duetos::core::CurrentProcess();
    if (proc == nullptr)
    {
        frame->rax = 0;
        return;
    }
    CompositorLock();
    const u32 h_comp = HwndToCompositorHandleForCaller(frame->rdi, proc->pid);
    const WindowHandle prev = WindowSetCapture(h_comp);
    CompositorUnlock();
    frame->rax = (prev == kWindowInvalid) ? 0 : (static_cast<u64>(prev) + 1);
}

void DoWinReleaseCapture(arch::TrapFrame* frame)
{
    using namespace duetos::drivers::video;
    CompositorLock();
    WindowReleaseCapture();
    CompositorUnlock();
    frame->rax = 1;
}

void DoWinGetCapture(arch::TrapFrame* frame)
{
    using namespace duetos::drivers::video;
    CompositorLock();
    const WindowHandle h = WindowGetCapture();
    CompositorUnlock();
    frame->rax = (h == kWindowInvalid) ? 0 : (static_cast<u64>(h) + 1);
}

// --- Clipboard ---------------------------------------------------

void DoWinClipSetText(arch::TrapFrame* frame)
{
    using namespace duetos::drivers::video;
    char text[kWindowClipboardMax];
    if (!CopyUserString(text, sizeof(text), frame->rdi))
    {
        text[0] = '\0';
    }
    CompositorLock();
    WindowClipboardSetText(text);
    CompositorUnlock();
    frame->rax = 1;
}

void DoWinClipGetText(arch::TrapFrame* frame)
{
    using namespace duetos::drivers::video;
    const u64 user_ptr = frame->rdi;
    const u64 cap = frame->rsi;
    if (user_ptr == 0 || cap == 0)
    {
        frame->rax = 0;
        return;
    }
    const u32 bounded_cap = (cap > kWindowClipboardMax) ? kWindowClipboardMax : static_cast<u32>(cap);
    char kbuf[kWindowClipboardMax];
    CompositorLock();
    const u32 n = WindowClipboardGetText(kbuf, bounded_cap);
    CompositorUnlock();
    if (!duetos::mm::CopyToUser(reinterpret_cast<void*>(user_ptr), kbuf, n + 1))
    {
        frame->rax = 0;
        return;
    }
    frame->rax = n;
}

// --- Window longs + dirty / paint / active / metrics / enum ------

void DoWinGetLong(arch::TrapFrame* frame)
{
    using namespace duetos::drivers::video;
    duetos::core::Process* proc = duetos::core::CurrentProcess();
    if (proc == nullptr)
    {
        frame->rax = 0;
        return;
    }
    CompositorLock();
    const u32 h_comp = HwndToCompositorHandleForCaller(frame->rdi, proc->pid);
    u64 val = 0;
    if (h_comp != kWindowInvalid)
    {
        val = WindowGetLong(h_comp, static_cast<u32>(frame->rsi));
    }
    CompositorUnlock();
    frame->rax = val;
}

void DoWinSetLong(arch::TrapFrame* frame)
{
    using namespace duetos::drivers::video;
    duetos::core::Process* proc = duetos::core::CurrentProcess();
    if (proc == nullptr)
    {
        frame->rax = 0;
        return;
    }
    CompositorLock();
    const u32 h_comp = HwndToCompositorHandleForCaller(frame->rdi, proc->pid);
    u64 prev = 0;
    if (h_comp != kWindowInvalid)
    {
        prev = WindowSetLong(h_comp, static_cast<u32>(frame->rsi), frame->rdx);
    }
    CompositorUnlock();
    frame->rax = prev;
}

void DoWinInvalidate(arch::TrapFrame* frame)
{
    using namespace duetos::drivers::video;
    duetos::core::Process* proc = duetos::core::CurrentProcess();
    if (proc == nullptr)
    {
        frame->rax = 0;
        return;
    }
    CompositorLock();
    const u32 h_comp = HwndToCompositorHandleForCaller(frame->rdi, proc->pid);
    bool ok = false;
    if (h_comp != kWindowInvalid)
    {
        WindowInvalidate(h_comp);
        ok = true;
    }
    CompositorUnlock();
    // Fire the paint drain immediately so the PE's pump sees
    // WM_PAINT on its next GetMessage without waiting for a
    // ticker. Doesn't actually paint — just posts.
    if (ok)
    {
        CompositorLock();
        (void)WindowDrainPaints();
        CompositorUnlock();
    }
    frame->rax = ok ? 1 : 0;
}

// Win32 PAINTSTRUCT layout. Lays out 72 B which matches the Win32
// SDK across 64-bit builds (hdc=8, fErase=4, rcPaint=16, fRestore=4,
// fIncUpdate=4, rgbReserved=32 + 4 trailing = padded to 72 due to
// 8-byte alignment on the leading pointer). Written whole-struct
// via CopyToUser so stale user-side bytes don't leak into later
// reads. No memcpy is emitted: struct is built on the kernel stack
// and filled field by field.
struct Win32PaintStruct
{
    u64 hdc;
    u32 fErase;
    i32 rcPaint_left;
    i32 rcPaint_top;
    i32 rcPaint_right;
    i32 rcPaint_bottom;
    u32 fRestore;
    u32 fIncUpdate;
    u8 rgbReserved[32];
};
static_assert(sizeof(Win32PaintStruct) == 72, "PAINTSTRUCT size must be 72 B for Win32 ABI");

void DoWinBeginPaint(arch::TrapFrame* frame)
{
    using namespace duetos::drivers::video;

    duetos::core::Process* proc = duetos::core::CurrentProcess();
    if (proc == nullptr)
    {
        frame->rax = 0;
        return;
    }
    const u64 hwnd_biased = frame->rdi;
    const u64 user_ps_ptr = frame->rsi;
    if (user_ps_ptr == 0)
    {
        frame->rax = 0;
        return;
    }

    CompositorLock();
    const u32 h_comp = HwndToCompositorHandleForCaller(hwnd_biased, proc->pid);
    bool ok = false;
    Win32PaintStruct ps{};
    ps.hdc = hwnd_biased; // HDC == HWND in v0 (no separate DC handle table)
    if (h_comp != kWindowInvalid)
    {
        u32 wx = 0, wy = 0, ww = 0, wh = 0;
        if (WindowGetBounds(h_comp, &wx, &wy, &ww, &wh))
        {
            const u32 tbh = 22; // matches widget chrome default
            ps.rcPaint_left = 0;
            ps.rcPaint_top = 0;
            ps.rcPaint_right = static_cast<i32>((ww > 4) ? ww - 4 : 0);
            ps.rcPaint_bottom = static_cast<i32>((wh > tbh + 4) ? wh - tbh - 4 : 0);
            ps.fErase = WindowIsDirty(h_comp) ? 1u : 0u;
            ps.fRestore = 0;
            ps.fIncUpdate = 0;
            for (u32 i = 0; i < sizeof(ps.rgbReserved); ++i)
                ps.rgbReserved[i] = 0;
            // Win32: BeginPaint implicitly validates the dirty
            // region. Our WindowValidate clears the whole-window
            // dirty bit — matches v1 behaviour (no partial-region
            // tracking).
            WindowValidate(h_comp);
            ok = true;
        }
    }
    CompositorUnlock();

    if (!ok)
    {
        frame->rax = 0;
        return;
    }
    if (!duetos::mm::CopyToUser(reinterpret_cast<void*>(user_ps_ptr), &ps, sizeof(ps)))
    {
        frame->rax = 0;
        return;
    }
    frame->rax = hwnd_biased; // HDC == HWND
}

void DoWinEndPaint(arch::TrapFrame* frame)
{
    // BeginPaint already validated the window; EndPaint is a no-op
    // modulo returning TRUE, matching Win32 semantics for our v1
    // whole-client repaint model.
    (void)frame->rdi;
    (void)frame->rsi;
    frame->rax = 1;
}

void DoGdiFillRectUser(arch::TrapFrame* frame)
{
    using namespace duetos::drivers::video;

    duetos::core::Process* proc = duetos::core::CurrentProcess();
    if (proc == nullptr)
    {
        frame->rax = 0;
        return;
    }
    const u64 user_rect = frame->rsi;
    if (user_rect == 0)
    {
        frame->rax = 0;
        return;
    }
    i32 rect[4] = {0, 0, 0, 0};
    if (!duetos::mm::CopyFromUser(rect, reinterpret_cast<const void*>(user_rect), sizeof(rect)))
    {
        frame->rax = 0;
        return;
    }
    // Win32 RECT: (left, top, right, bottom). Convert to (x, y, w, h).
    const i32 x = rect[0];
    const i32 y = rect[1];
    const i32 r = rect[2];
    const i32 b = rect[3];
    if (r <= x || b <= y)
    {
        frame->rax = 1; // empty rect is a valid no-op
        return;
    }
    const i32 w = r - x;
    const i32 h = b - y;
    const u32 rgb = ColorRefToRgb(frame->rdx);

    // Dispatch by handle tag: memDC targets paint directly into
    // the selected bitmap; window targets record a FillRect prim
    // that the compositor replays.
    const u64 hdc = frame->rdi;
    const u64 tag = hdc & kGdiTagMask;
    bool ok = false;
    if (tag == kGdiTagMemDC)
    {
        MemDC* dc = GdiLookupMemDC(hdc);
        if (dc != nullptr && dc->selected_bitmap != 0)
        {
            Bitmap* bmp = GdiLookupBitmap(dc->selected_bitmap);
            if (bmp != nullptr)
            {
                GdiPaintRectOnBitmap(bmp, x, y, w, h, rgb);
                ok = true;
            }
        }
    }
    else
    {
        CompositorLock();
        const u32 h_comp = HwndToCompositorHandleForCaller(hdc, proc->pid);
        if (h_comp != kWindowInvalid)
        {
            WindowClientFillRect(h_comp, x, y, w, h, rgb);
            const Theme& theme = ThemeCurrent();
            DesktopCompose(theme.desktop_bg, nullptr);
            ok = true;
        }
        CompositorUnlock();
    }
    frame->rax = ok ? 1 : 0;
}

// DrawTextA format flags (Win32 subset).
namespace
{
constexpr u32 kDtLeft = 0x00000000;
[[maybe_unused]] constexpr u32 kDtTop = 0x00000000;
constexpr u32 kDtCenter = 0x00000001;
constexpr u32 kDtRight = 0x00000002;
constexpr u32 kDtVCenter = 0x00000004;
[[maybe_unused]] constexpr u32 kDtBottom = 0x00000008;
constexpr u32 kDtSingleLine = 0x00000020;
} // namespace

// Shared core for DrawTextA / DrawTextW after the source text has
// been copied in + decoded to ASCII. `copy_len` is the ASCII
// length (not counting NUL). Returns the painted text height
// (in px) on success, 0 on failure — same contract as Win32
// DrawText's return value.
static u64 DrawTextAsciiOnDc(u64 hdc, const char* text, u64 copy_len, u64 user_rect, u32 format,
                             duetos::core::Process* proc)
{
    using namespace duetos::drivers::video;

    i32 rect[4] = {0, 0, 0, 0};
    if (!duetos::mm::CopyFromUser(rect, reinterpret_cast<const void*>(user_rect), sizeof(rect)))
        return 0;
    const i32 rx = rect[0];
    const i32 ry = rect[1];
    const i32 rr = rect[2];
    const i32 rb = rect[3];
    if (rr <= rx || rb <= ry)
        return 0;
    const i32 rw = rr - rx;
    const i32 rh = rb - ry;

    const i32 text_w = static_cast<i32>(copy_len) * 8;
    const i32 text_h = 8;
    (void)kDtSingleLine;

    i32 px = rx;
    i32 py = ry;
    if (format & kDtCenter)
        px = rx + (rw - text_w) / 2;
    else if (format & kDtRight)
        px = rr - text_w;
    else
        (void)kDtLeft;

    if (format & kDtVCenter)
        py = ry + (rh - text_h) / 2;

    const u64 tag = hdc & kGdiTagMask;
    bool ok = false;
    if (tag == kGdiTagMemDC)
    {
        MemDC* dc = GdiLookupMemDC(hdc);
        if (dc != nullptr && dc->selected_bitmap != 0)
        {
            Bitmap* bmp = GdiLookupBitmap(dc->selected_bitmap);
            if (bmp != nullptr)
            {
                const bool opaque = (dc->bk_mode == kBkModeOpaque);
                GdiPaintTextOnBitmap(bmp, px, py, text, dc->text_color, dc->bk_color, opaque);
                ok = true;
            }
        }
    }
    else if (tag == 0)
    {
        u32 fg = 0x00FFFFFF;
        WindowDcState* s = GdiWindowDcState(static_cast<u32>(hdc));
        if (s != nullptr && s->text_color_set)
            fg = s->text_color;
        CompositorLock();
        const u32 h_comp = HwndToCompositorHandleForCaller(hdc, proc->pid);
        if (h_comp != kWindowInvalid)
        {
            WindowClientTextOut(h_comp, px, py, text, fg);
            const Theme& theme = ThemeCurrent();
            DesktopCompose(theme.desktop_bg, nullptr);
            ok = true;
        }
        CompositorUnlock();
    }
    return ok ? static_cast<u64>(text_h) : 0;
}

void DoGdiDrawText(arch::TrapFrame* frame)
{
    duetos::core::Process* proc = duetos::core::CurrentProcess();
    if (proc == nullptr)
    {
        frame->rax = 0;
        return;
    }
    const u64 hdc = frame->rdi;
    const u64 user_text = frame->rsi;
    const i64 len_in = static_cast<i64>(frame->rdx);
    const u64 user_rect = frame->r10;
    const u32 format = static_cast<u32>(frame->r8);
    if (user_text == 0 || user_rect == 0)
    {
        frame->rax = 0;
        return;
    }

    constexpr u64 kDrawTextMax = 127;
    char text[kDrawTextMax + 1];
    for (u32 i = 0; i < sizeof(text); ++i)
        text[i] = '\0';
    u64 copy_len = (len_in < 0) ? kDrawTextMax : static_cast<u64>(len_in);
    if (copy_len > kDrawTextMax)
        copy_len = kDrawTextMax;
    if (!duetos::mm::CopyFromUser(text, reinterpret_cast<const void*>(user_text), copy_len))
    {
        frame->rax = 0;
        return;
    }
    text[copy_len] = '\0';
    if (len_in < 0)
    {
        for (u64 i = 0; i < copy_len; ++i)
        {
            if (text[i] == '\0')
            {
                copy_len = i;
                break;
            }
        }
    }
    frame->rax = DrawTextAsciiOnDc(hdc, text, copy_len, user_rect, format, proc);
}

void DoGdiDrawTextW(arch::TrapFrame* frame)
{
    duetos::core::Process* proc = duetos::core::CurrentProcess();
    if (proc == nullptr)
    {
        frame->rax = 0;
        return;
    }
    const u64 hdc = frame->rdi;
    const u64 user_text = frame->rsi;
    const i64 len_in = static_cast<i64>(frame->rdx);
    const u64 user_rect = frame->r10;
    const u32 format = static_cast<u32>(frame->r8);
    if (user_text == 0 || user_rect == 0)
    {
        frame->rax = 0;
        return;
    }

    constexpr u64 kDrawTextMax = 127;
    char text[kDrawTextMax + 1];
    for (u32 i = 0; i < sizeof(text); ++i)
        text[i] = '\0';
    // UTF-16 copy-in + strip to ASCII. Negative `len_in` (-1) means
    // NUL-terminated — walk the u16 stream until we hit a 0.
    u64 copy_len = 0;
    {
        u16 wbuf[kDrawTextMax];
        const u64 cap = (len_in < 0) ? kDrawTextMax : static_cast<u64>(len_in);
        const u64 clamp = (cap > kDrawTextMax) ? kDrawTextMax : cap;
        if (clamp > 0 && !duetos::mm::CopyFromUser(wbuf, reinterpret_cast<const void*>(user_text), clamp * 2))
        {
            frame->rax = 0;
            return;
        }
        for (u64 i = 0; i < clamp; ++i)
        {
            const u16 wc = wbuf[i];
            if (len_in < 0 && wc == 0)
                break;
            text[copy_len++] = (wc < 0x80) ? static_cast<char>(wc) : '?';
        }
        text[copy_len] = '\0';
    }
    frame->rax = DrawTextAsciiOnDc(hdc, text, copy_len, user_rect, format, proc);
}

void DoWinValidate(arch::TrapFrame* frame)
{
    using namespace duetos::drivers::video;
    duetos::core::Process* proc = duetos::core::CurrentProcess();
    if (proc == nullptr)
    {
        frame->rax = 0;
        return;
    }
    CompositorLock();
    const u32 h_comp = HwndToCompositorHandleForCaller(frame->rdi, proc->pid);
    bool ok = false;
    if (h_comp != kWindowInvalid)
    {
        WindowValidate(h_comp);
        ok = true;
    }
    CompositorUnlock();
    frame->rax = ok ? 1 : 0;
}

void DoWinGetActive(arch::TrapFrame* frame)
{
    using namespace duetos::drivers::video;
    CompositorLock();
    const WindowHandle h = WindowActive();
    CompositorUnlock();
    frame->rax = (h == kWindowInvalid) ? 0 : (static_cast<u64>(h) + 1);
}

void DoWinSetActive(arch::TrapFrame* frame)
{
    using namespace duetos::drivers::video;
    duetos::core::Process* proc = duetos::core::CurrentProcess();
    if (proc == nullptr)
    {
        frame->rax = 0;
        return;
    }
    CompositorLock();
    const WindowHandle prev = WindowActive();
    const u32 h_comp = HwndToCompositorHandleForCaller(frame->rdi, proc->pid);
    if (h_comp != kWindowInvalid)
    {
        WindowRaise(h_comp); // raise also marks active
        const Theme& theme = ThemeCurrent();
        DesktopCompose(theme.desktop_bg, nullptr);
    }
    CompositorUnlock();
    frame->rax = (prev == kWindowInvalid) ? 0 : (static_cast<u64>(prev) + 1);
}

void DoWinGetMetric(arch::TrapFrame* frame)
{
    using namespace duetos::drivers::video;
    // Common Win32 SM_* selectors. Values from Win32 headers;
    // 0 for unknown indices per Win32 convention.
    enum : u64
    {
        kSmCxScreen = 0,
        kSmCyScreen = 1,
        kSmCxFrame = 32,
        kSmCyFrame = 33,
        kSmCxCaption = 4,
        kSmCyCaption = 4, // same alias in some docs
        kSmMouseButtons = 43,
        kSmCMonitors = 80,
        kSmCxMinTrack = 28,
        kSmCyMinTrack = 29,
    };
    const u64 idx = frame->rdi;
    const FramebufferInfo fb = FramebufferGet();
    const u32 fb_w = fb.width ? fb.width : 1024;
    const u32 fb_h = fb.height ? fb.height : 768;
    u64 rv = 0;
    switch (idx)
    {
    case kSmCxScreen:
        rv = fb_w;
        break;
    case kSmCyScreen:
        rv = fb_h;
        break;
    case kSmCxFrame:
        rv = 2;
        break;
    case 33 /* SM_CYFRAME */:
        rv = 2;
        break;
    case 4 /* SM_CYCAPTION */:
        rv = 22;
        break;
    case 43 /* SM_CMOUSEBUTTONS */:
        rv = 3;
        break;
    case 80 /* SM_CMONITORS */:
        rv = 1;
        break;
    case 28 /* SM_CXMINTRACK */:
        rv = 100;
        break;
    case 29 /* SM_CYMINTRACK */:
        rv = 50;
        break;
    default:
        rv = 0;
        break;
    }
    frame->rax = rv;
}

void DoWinEnum(arch::TrapFrame* frame)
{
    using namespace duetos::drivers::video;
    const u64 user_ptr = frame->rdi;
    const u64 cap = frame->rsi;
    if (user_ptr == 0 || cap == 0)
    {
        frame->rax = 0;
        return;
    }
    u64 buf[kMaxWindows];
    u32 n = 0;
    CompositorLock();
    const u32 total = WindowRegistryCount();
    for (u32 i = 0; i < total && n < cap && n < kMaxWindows; ++i)
    {
        if (WindowIsAlive(i) && WindowIsVisible(i))
        {
            buf[n++] = static_cast<u64>(i) + 1; // biased
        }
    }
    CompositorUnlock();
    if (n > 0 && !duetos::mm::CopyToUser(reinterpret_cast<void*>(user_ptr), buf, sizeof(u64) * n))
    {
        frame->rax = 0;
        return;
    }
    frame->rax = n;
}

namespace
{

// Case-insensitive ASCII equality over two NUL-terminated
// strings. Max scan length `cap`.
bool AsciiEqualIcase(const char* a, const char* b, u64 cap)
{
    for (u64 i = 0; i < cap; ++i)
    {
        char ca = a[i];
        char cb = b[i];
        if (ca >= 'A' && ca <= 'Z')
            ca = static_cast<char>(ca + ('a' - 'A'));
        if (cb >= 'A' && cb <= 'Z')
            cb = static_cast<char>(cb + ('a' - 'A'));
        if (ca != cb)
            return false;
        if (ca == '\0')
            return true;
    }
    return true;
}

} // namespace

void DoWinFind(arch::TrapFrame* frame)
{
    using namespace duetos::drivers::video;
    char target[duetos::core::kWinTitleMax + 1];
    if (!CopyUserString(target, sizeof(target), frame->rdi))
    {
        frame->rax = 0;
        return;
    }
    u64 result = 0;
    CompositorLock();
    const u32 total = WindowRegistryCount();
    for (u32 i = 0; i < total; ++i)
    {
        if (!WindowIsAlive(i))
            continue;
        const char* title = WindowTitle(i);
        if (title != nullptr && AsciiEqualIcase(title, target, duetos::core::kWinTitleMax))
        {
            result = static_cast<u64>(i) + 1;
            break;
        }
    }
    CompositorUnlock();
    frame->rax = result;
}

// --- Parent / child / focus / caret / beep ------------------------

void DoWinSetParent(arch::TrapFrame* frame)
{
    using namespace duetos::drivers::video;
    duetos::core::Process* proc = duetos::core::CurrentProcess();
    if (proc == nullptr)
    {
        frame->rax = 0;
        return;
    }
    CompositorLock();
    const u32 child = HwndToCompositorHandleForCaller(frame->rdi, proc->pid);
    const u32 parent = (frame->rsi == 0) ? kWindowInvalid : HwndToCompositorHandle(frame->rsi);
    const WindowHandle prev = (child != kWindowInvalid) ? WindowGetParent(child) : kWindowInvalid;
    if (child != kWindowInvalid)
    {
        WindowSetParent(child, parent);
    }
    CompositorUnlock();
    frame->rax = (prev == kWindowInvalid) ? 0 : (static_cast<u64>(prev) + 1);
}

void DoWinGetParent(arch::TrapFrame* frame)
{
    using namespace duetos::drivers::video;
    CompositorLock();
    const u32 h = HwndToCompositorHandle(frame->rdi);
    const WindowHandle p = (h != kWindowInvalid) ? WindowGetParent(h) : kWindowInvalid;
    CompositorUnlock();
    frame->rax = (p == kWindowInvalid) ? 0 : (static_cast<u64>(p) + 1);
}

void DoWinGetRelated(arch::TrapFrame* frame)
{
    using namespace duetos::drivers::video;
    CompositorLock();
    const u32 h = HwndToCompositorHandle(frame->rdi);
    WindowHandle r = kWindowInvalid;
    if (frame->rsi <= 5 && (h != kWindowInvalid || frame->rsi == 2 || frame->rsi == 3))
    {
        r = WindowGetRelated(h, static_cast<WindowRel>(frame->rsi));
    }
    CompositorUnlock();
    frame->rax = (r == kWindowInvalid) ? 0 : (static_cast<u64>(r) + 1);
}

void DoWinSetFocus(arch::TrapFrame* frame)
{
    using namespace duetos::drivers::video;
    duetos::core::Process* proc = duetos::core::CurrentProcess();
    if (proc == nullptr)
    {
        frame->rax = 0;
        return;
    }
    CompositorLock();
    const WindowHandle prev = WindowGetFocus();
    const u32 h = (frame->rdi == 0) ? kWindowInvalid : HwndToCompositorHandleForCaller(frame->rdi, proc->pid);
    WindowSetFocus(h);
    CompositorUnlock();
    WindowMsgWakeAll();
    frame->rax = (prev == kWindowInvalid) ? 0 : (static_cast<u64>(prev) + 1);
}

void DoWinGetFocus(arch::TrapFrame* frame)
{
    using namespace duetos::drivers::video;
    CompositorLock();
    const WindowHandle h = WindowGetFocus();
    CompositorUnlock();
    frame->rax = (h == kWindowInvalid) ? 0 : (static_cast<u64>(h) + 1);
}

void DoWinCaret(arch::TrapFrame* frame)
{
    using namespace duetos::drivers::video;
    const u64 op = frame->rdi;
    bool ok = true;
    CompositorLock();
    switch (op)
    {
    case 0: // Create(w, h, owner)
    {
        const WindowHandle owner = (frame->r10 == 0) ? kWindowInvalid : HwndToCompositorHandle(frame->r10);
        WindowCaretCreate(owner, static_cast<u32>(frame->rsi), static_cast<u32>(frame->rdx));
        break;
    }
    case 1: // Destroy
        WindowCaretDestroy();
        break;
    case 2: // SetPos(x, y)
        WindowCaretSetPos(static_cast<u32>(frame->rsi), static_cast<u32>(frame->rdx));
        break;
    case 3: // Show
        WindowCaretShow(true);
        break;
    case 4: // Hide
        WindowCaretShow(false);
        break;
    default:
        ok = false;
        break;
    }
    CompositorUnlock();
    frame->rax = ok ? 1 : 0;
}

void DoWinBeep(arch::TrapFrame* frame)
{
    const u32 freq = (frame->rdi == 0) ? 800 : static_cast<u32>(frame->rdi);
    const u32 dur = (frame->rsi == 0) ? 100 : static_cast<u32>(frame->rsi);
    const bool ok = duetos::drivers::audio::PcSpeakerBeep(freq, dur);
    frame->rax = ok ? 1 : 0;
}

void DoWinSetText(arch::TrapFrame* frame)
{
    using namespace duetos::drivers::video;

    duetos::core::Process* proc = duetos::core::CurrentProcess();
    if (proc == nullptr)
    {
        frame->rax = 0;
        return;
    }
    char text[duetos::core::kWinTitleMax + 1];
    if (!CopyUserString(text, sizeof(text), frame->rsi))
    {
        // Treat a null / faulting pointer as "clear the title" —
        // Win32 SetWindowTextA with a null pointer is documented
        // as setting an empty string, not an error.
        text[0] = '\0';
    }
    CompositorLock();
    const u32 h_comp = HwndToCompositorHandleForCaller(frame->rdi, proc->pid);
    bool ok = false;
    if (h_comp != kWindowInvalid)
    {
        ok = WindowSetTitle(h_comp, text);
        if (ok)
        {
            const Theme& theme = ThemeCurrent();
            DesktopCompose(theme.desktop_bg, nullptr);
        }
    }
    CompositorUnlock();
    frame->rax = ok ? 1 : 0;
}

// =====================================================================
// SYS_WIN_TRACK_POPUP — modal popup-menu syscall (USER32 TrackPopupMenu).
// =====================================================================

namespace
{

// Flat-array popup-menu wire format holds the root menu followed by every
// submenu's children, all in one fixed-size array. A v0 PE pop-up rarely
// exceeds a couple of submenus of a few items each, so 32 slots covers
// the realistic worst case (e.g. a 6-row root with three 6-row
// submenus = 24 items) while keeping the static label arena cheap.
// Bumped from 12 → 32 when submenu marshaling landed (see
// `wiki/subsystems/Compositor.md` §Popup Menus).
constexpr u32 kTpMaxItems = 32;
constexpr u32 kTpLabelMax = 32;
constexpr u32 kTpFlagReturnCmd = 0x0100; // matches Win32 TPM_RETURNCMD
constexpr u32 kTpFlagNoNotify = 0x0080;  // matches Win32 TPM_NONOTIFY
// Horizontal alignment bits — TPM_LEFTALIGN is the default (0).
constexpr u32 kTpFlagCenterAlign = 0x0004; // matches Win32 TPM_CENTERALIGN
constexpr u32 kTpFlagRightAlign = 0x0008;  // matches Win32 TPM_RIGHTALIGN
// Vertical alignment bits — TPM_TOPALIGN is the default (0).
constexpr u32 kTpFlagVCenterAlign = 0x0010; // matches Win32 TPM_VCENTERALIGN
constexpr u32 kTpFlagBottomAlign = 0x0020;  // matches Win32 TPM_BOTTOMALIGN

// Menu primitive geometry mirrors `kernel/drivers/video/menu.cpp` —
// 240 px fixed width, 22 px per row, +4 px for the 2-px border on
// top and bottom. Aligning the menu against (x, y) needs these
// before we open, since the menu primitive itself only takes a
// top-left anchor.
constexpr u32 kMenuWidth = 240;
constexpr u32 kMenuRowHeight = 22;
constexpr u32 kMenuVPadding = 4;

// Wire format the userland TrackPopupMenu thunk packs onto the
// caller's stack and passes via rdi. Fixed-size to keep the
// kernel-side copy a single CopyFromUser. Layout is part of the
// SYS_WIN_TRACK_POPUP ABI.
//
// Submenu marshaling: items are laid out as a single flat array.
// `root_count` items at the start form the root menu; subsequent
// items are the flattened children of submenu-flagged rows. An item
// with `flags & kMenuItemFlagSubmenu` sets `child_index` to the
// index of the first child in the same flat array and `child_count`
// to the number of children at that index. `child_index == -1`
// means "no children" (flat item, ignored even if the submenu bit
// is incidentally set). The kernel rejects:
//   - child_index < 0 with child_count > 0
//   - child_index + child_count > count
//   - child_index <= self_index (forward-only — also kills cycles)
//   - effective panel depth > kMenuMaxStack
struct TpItemWire
{
    u32 action_id;
    u32 flags;       // mirrors kMenuItemFlag* (low 4 bits)
    i32 child_index; // -1 = no children; otherwise index into the same flat array
    u32 child_count; // number of children at child_index (0 if no children)
    char label[kTpLabelMax];
};

struct TpReqWire
{
    u32 count;      // total items in the flat array (root + every submenu's children)
    u32 root_count; // first `root_count` items form the root menu; bounded by kTpMaxItems
    u32 flags;
    i32 screen_x;
    i32 screen_y;
    u64 hwnd_biased;
    TpItemWire items[kTpMaxItems];
};

// Single-instance state. The kernel menu primitive itself is a
// single global, so a popup syscall owns it for the open lifetime.
// A second concurrent caller is rejected (returns 0) — documented
// limitation.
constinit duetos::sched::Mutex g_tp_lock{};
constinit duetos::sched::Condvar g_tp_done{};
constinit bool g_tp_in_flight = false;
constinit bool g_tp_completed = false;
constinit u64 g_tp_owner_pid = 0;
constinit u32 g_tp_result = 0;
constinit u32 g_tp_caller_flags = 0;
constinit u64 g_tp_hwnd_biased = 0;

// Persistent label storage so the kernel menu primitive's
// borrowed string pointers remain valid for the menu's open
// lifetime. Sized to the worst case (one label per slot), which
// is small enough to keep static.
constinit char g_tp_labels[kTpMaxItems][kTpLabelMax + 1] = {};
// MenuItem array the menu primitive sees. Same lifetime as the
// label storage. We rebuild this on every open.
constinit duetos::drivers::video::MenuItem g_tp_items[kTpMaxItems] = {};

} // namespace

void DoWinTrackPopup(arch::TrapFrame* frame)
{
    using namespace duetos::drivers::video;
    using duetos::arch::SerialWrite;
    using duetos::arch::SerialWriteHex;
    KDBG_V(Win32Wm, "win32/menu", "DoWinTrackPopup req", frame->rdi);

    duetos::core::Process* proc = duetos::core::CurrentProcess();
    if (proc == nullptr)
    {
        frame->rax = 0;
        return;
    }

    const u32 max_count = static_cast<u32>(frame->rsi);
    if (max_count == 0 || max_count > kTpMaxItems)
    {
        // Caller's own sanity cap. A 0 or oversized value is a
        // bug on the userland side; refuse rather than guess.
        frame->rax = 0;
        return;
    }

    TpReqWire req{};
    if (frame->rdi == 0 ||
        !duetos::mm::CopyFromUser(&req, reinterpret_cast<const void*>(frame->rdi), sizeof(TpReqWire)))
    {
        frame->rax = 0;
        return;
    }
    // `count` is the TOTAL flat-array population (root + every nested
    // submenu's children); `root_count` is what gets passed to MenuOpen.
    // Root must fit the kernel menu primitive's per-panel cap (also
    // bounded by kTpMaxItems for the same reason).
    if (req.count == 0 || req.count > max_count || req.count > kTpMaxItems)
    {
        frame->rax = 0;
        return;
    }
    if (req.root_count == 0 || req.root_count > req.count ||
        req.root_count > duetos::drivers::video::kMenuMaxItemsPerPanel)
    {
        // Per-panel cap mirrors the menu primitive — anything longer
        // would get silently truncated inside MenuOpen, which is a
        // worse failure mode than a refused syscall.
        frame->rax = 0;
        return;
    }

    // Pass 1: validate every item's child range before we touch the
    // shared kernel state. Reject malformed layouts (negative index
    // with non-zero count, out-of-bounds child range, non-forward /
    // self-overlapping reference) and any item whose label exceeds
    // the wire cap. Also compute effective panel depth via a simple
    // BFS from the root range and reject deeper than kMenuMaxStack
    // (matches the menu primitive's own cap).
    for (u32 i = 0; i < req.count; ++i)
    {
        const TpItemWire& w = req.items[i];
        const bool wants_submenu = (w.flags & kMenuItemFlagSubmenu) != 0;
        if (w.child_index < 0)
        {
            if (w.child_count != 0)
            {
                frame->rax = 0;
                return;
            }
            // Submenu bit without children: tolerated as a flat item
            // (we strip the bit below) — matches Win32 USER which
            // ignores MF_POPUP if the item has no submenu attached.
            (void)wants_submenu;
        }
        else
        {
            const u32 idx = static_cast<u32>(w.child_index);
            // Forward-only reference catches self-loops and any
            // cycle in one check: a child range that starts at or
            // before its parent's own slot would let a cycle close.
            if (idx <= i)
            {
                frame->rax = 0;
                return;
            }
            if (w.child_count == 0)
            {
                frame->rax = 0;
                return;
            }
            if (idx >= req.count || w.child_count > req.count || idx + w.child_count > req.count)
            {
                frame->rax = 0;
                return;
            }
            // Per-panel cap: each submenu also has to fit the menu
            // primitive's per-panel slot count, otherwise children
            // would silently vanish inside MenuOpenSubmenu.
            if (w.child_count > duetos::drivers::video::kMenuMaxItemsPerPanel)
            {
                frame->rax = 0;
                return;
            }
        }
    }

    // BFS the panel tree starting at the root range. Each item with a
    // valid child range bumps the depth of its children by 1. We track
    // the deepest level reached and reject if it exceeds kMenuMaxStack.
    // Cycles are already impossible (forward-only check above), so a
    // single linear scan with per-item depth memo terminates.
    {
        u32 depth[kTpMaxItems] = {};
        for (u32 i = 0; i < req.root_count; ++i)
            depth[i] = 1; // root panel is depth 1
        u32 max_depth_reached = req.root_count > 0 ? 1u : 0u;
        for (u32 i = 0; i < req.count; ++i)
        {
            if (depth[i] == 0)
                continue; // unreachable from root; will get rejected as orphan below
            const TpItemWire& w = req.items[i];
            if (w.child_index < 0 || (w.flags & kMenuItemFlagSubmenu) == 0)
                continue;
            const u32 child_depth = depth[i] + 1;
            if (child_depth > duetos::drivers::video::kMenuMaxStack)
            {
                frame->rax = 0;
                return;
            }
            const u32 base = static_cast<u32>(w.child_index);
            for (u32 c = 0; c < w.child_count; ++c)
                depth[base + c] = child_depth;
            if (child_depth > max_depth_reached)
                max_depth_reached = child_depth;
        }
        // Every item must be reachable — otherwise the caller wired
        // extra slots that nothing references, which is either a bug
        // or a leak vector (e.g. probing the kernel's static label
        // arena). Refuse rather than silently waste a slot.
        for (u32 i = 0; i < req.count; ++i)
        {
            if (depth[i] == 0)
            {
                frame->rax = 0;
                return;
            }
        }
        (void)max_depth_reached;
    }

    // Acquire the popup lock. Single-instance: a second caller
    // collides here and gets 0. We could block, but blocking on
    // a UI primitive while the user is interacting with the
    // first popup risks indefinite latency on the second app —
    // the documented v0 limit is "second caller cancels."
    duetos::sched::MutexLock(&g_tp_lock);
    if (g_tp_in_flight)
    {
        duetos::sched::MutexUnlock(&g_tp_lock);
        SerialWrite("[win32/menu] track_popup busy; second caller cancelled\n");
        frame->rax = 0;
        return;
    }
    g_tp_in_flight = true;
    g_tp_completed = false;
    g_tp_owner_pid = proc->pid;
    g_tp_result = 0;
    g_tp_caller_flags = req.flags;
    g_tp_hwnd_biased = req.hwnd_biased;

    // Pass 2: build the label arena + MenuItem table while holding
    // the popup lock — the mouse-reader's MenuFeedKey path won't
    // fire until MenuOpen runs below, so g_tp_items can't be
    // observed mid-write. We populate every slot first (so submenu
    // back-pointers land in fully-initialised MenuItems), then walk
    // the array a third time to patch parent → child pointers.
    for (u32 i = 0; i < req.count; ++i)
    {
        const TpItemWire& w = req.items[i];
        for (u32 c = 0; c < kTpLabelMax; ++c)
        {
            char ch = w.label[c];
            // Sanitise: replace non-printable / non-ASCII with
            // '?' so the menu renderer doesn't trip on stray
            // bytes. Spaces and printable ASCII pass through.
            if (ch == '\0')
            {
                g_tp_labels[i][c] = '\0';
                break;
            }
            if (ch < 0x20 || static_cast<unsigned char>(ch) > 0x7E)
                ch = '?';
            g_tp_labels[i][c] = ch;
        }
        g_tp_labels[i][kTpLabelMax] = '\0';
        g_tp_items[i].label = g_tp_labels[i];
        g_tp_items[i].action_id = w.action_id;
        // Translate caller flags. Submenu bit is preserved only
        // when this item actually points at a non-empty child
        // range (validated above); otherwise it's stripped so the
        // kernel never tries to follow a null pointer.
        u32 base_flags = w.flags & (kMenuItemFlagDisabled | kMenuItemFlagChecked | kMenuItemFlagSeparator);
        const bool has_children = (w.flags & kMenuItemFlagSubmenu) != 0 && w.child_index >= 0 && w.child_count > 0;
        if (has_children)
            base_flags |= kMenuItemFlagSubmenu;
        g_tp_items[i].flags = base_flags;
        g_tp_items[i].submenu = nullptr;
        g_tp_items[i].submenu_count = 0;
    }
    // Pass 3: patch parent → child pointers. Safe to take the
    // address of `g_tp_items[child_index]` now that every slot is
    // populated and the array's storage is stable.
    for (u32 i = 0; i < req.count; ++i)
    {
        const TpItemWire& w = req.items[i];
        if ((g_tp_items[i].flags & kMenuItemFlagSubmenu) == 0)
            continue;
        // Validated above: child_index >= 0, child_count > 0,
        // child_index + child_count <= req.count.
        g_tp_items[i].submenu = &g_tp_items[static_cast<u32>(w.child_index)];
        g_tp_items[i].submenu_count = w.child_count;
    }
    duetos::sched::MutexUnlock(&g_tp_lock);

    // Open the menu under the compositor lock so the mouse-reader
    // sees a consistent state.
    CompositorLock();

    // Apply TPM_*ALIGN flags. Default is TPM_LEFTALIGN | TPM_TOPALIGN
    // (both bits zero), which matches the historical behaviour of
    // treating (screen_x, screen_y) as the top-left anchor.
    //   TPM_CENTERALIGN  → menu centred on screen_x (shift left by w/2)
    //   TPM_RIGHTALIGN   → menu right edge at screen_x (shift left by w)
    //   TPM_VCENTERALIGN → menu centred on screen_y (shift up by h/2)
    //   TPM_BOTTOMALIGN  → menu bottom edge at screen_y (shift up by h)
    // Anchor math uses the root panel's height — submenus open
    // adjacent to their parent rows and don't grow the root.
    const u32 menu_h = req.root_count * kMenuRowHeight + kMenuVPadding;
    i32 ax = req.screen_x;
    i32 ay = req.screen_y;
    if ((req.flags & kTpFlagCenterAlign) != 0)
        ax -= static_cast<i32>(kMenuWidth / 2);
    else if ((req.flags & kTpFlagRightAlign) != 0)
        ax -= static_cast<i32>(kMenuWidth);
    if ((req.flags & kTpFlagVCenterAlign) != 0)
        ay -= static_cast<i32>(menu_h / 2);
    else if ((req.flags & kTpFlagBottomAlign) != 0)
        ay -= static_cast<i32>(menu_h);
    // Clamp the anchor into the framebuffer to keep the panel on
    // screen even when the caller passes a negative or off-screen
    // origin (or alignment math pushed it off-screen).
    if (ax < 0)
        ax = 0;
    if (ay < 0)
        ay = 0;
    MenuOpen(g_tp_items, req.root_count, static_cast<u32>(ax), static_cast<u32>(ay), kTrackPopupSentinelCtx);
    DesktopCompose(ThemeCurrent().desktop_bg, nullptr);
    CompositorUnlock();

    SerialWrite("[win32/menu] track_popup hwnd=");
    SerialWriteHex(req.hwnd_biased);
    SerialWrite(" count=");
    SerialWriteHex(req.count);
    SerialWrite(" root=");
    SerialWriteHex(req.root_count);
    SerialWrite(" flags=");
    SerialWriteHex(req.flags);
    SerialWrite("\n");

    // Wait for the dispatcher (mouse-reader / kbd-reader) to
    // signal completion. A spurious wake re-checks g_tp_completed.
    duetos::sched::MutexLock(&g_tp_lock);
    while (!g_tp_completed)
        duetos::sched::CondvarWait(&g_tp_done, &g_tp_lock);
    const u32 action = g_tp_result;
    const u32 caller_flags = g_tp_caller_flags;
    const u64 hwnd_biased = g_tp_hwnd_biased;
    g_tp_in_flight = false;
    g_tp_owner_pid = 0;
    duetos::sched::MutexUnlock(&g_tp_lock);

    SerialWrite("[win32/menu] track_popup result action=");
    SerialWriteHex(action);
    SerialWrite("\n");

    // If TPM_RETURNCMD is NOT set, also post WM_COMMAND to the
    // owner so a Win32 app that wires its menu through WndProc
    // sees the click without inspecting the syscall return.
    // TPM_NONOTIFY suppresses the WM_COMMAND notification
    // regardless of RETURNCMD — used by callers that read the
    // syscall result directly but don't want a WndProc roundtrip.
    if (action != 0 && (caller_flags & kTpFlagReturnCmd) == 0 && (caller_flags & kTpFlagNoNotify) == 0)
    {
        constexpr u32 kWmCommand = 0x0111;
        CompositorLock();
        const u32 h_comp = HwndToCompositorHandle(hwnd_biased);
        if (h_comp != kWindowInvalid && WindowIsAlive(h_comp))
        {
            WindowPostMessage(h_comp, kWmCommand, action, 0);
        }
        CompositorUnlock();
        WindowMsgWakeAll();
    }

    frame->rax = action;
}

void TrackPopupCompleteFromKernel(u32 action_id)
{
    duetos::sched::MutexLock(&g_tp_lock);
    if (g_tp_in_flight && !g_tp_completed)
    {
        g_tp_result = action_id;
        g_tp_completed = true;
        duetos::sched::CondvarSignal(&g_tp_done);
    }
    duetos::sched::MutexUnlock(&g_tp_lock);
}

void TrackPopupCancelByOwner(u64 pid)
{
    using namespace duetos::drivers::video;
    bool need_close_menu = false;
    duetos::sched::MutexLock(&g_tp_lock);
    if (g_tp_in_flight && g_tp_owner_pid == pid && !g_tp_completed)
    {
        g_tp_result = 0;
        g_tp_completed = true;
        need_close_menu = true;
        duetos::sched::CondvarSignal(&g_tp_done);
    }
    duetos::sched::MutexUnlock(&g_tp_lock);
    if (need_close_menu)
    {
        // Close the kernel menu since its owner is gone. Done
        // outside g_tp_lock to keep lock ordering simple
        // (compositor lock vs. tp_lock — never both at once).
        CompositorLock();
        if (MenuIsOpen() && MenuContext() == kTrackPopupSentinelCtx)
        {
            MenuClose();
        }
        CompositorUnlock();
    }
}

} // namespace duetos::subsystems::win32
