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

#include "window_syscall.h"

#include "../../arch/x86_64/cpu.h"
#include "../../arch/x86_64/serial.h"
#include "../../arch/x86_64/traps.h"
#include "../../core/kdbg.h"
#include "../../core/process.h"
#include "../../core/syscall.h"
#include "../../drivers/audio/pcspk.h"
#include "../../drivers/video/framebuffer.h"
#include "../../drivers/video/theme.h"
#include "../../drivers/video/widget.h"
#include "../../mm/kheap.h"
#include "../../mm/paging.h"
#include "../../sched/sched.h"
#include "gdi_objects.h"

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
// buffer. Returns true on success, false on fault / NUL-in-bounds
// verification failure. `kdst` is always NUL-terminated at `cap`
// on return (even on fault, it's zero-initialised). Max `cap-1`
// user bytes are copied plus a guaranteed trailing NUL.
bool CopyUserString(char* kdst, u64 cap, u64 user_ptr)
{
    if (cap == 0)
    {
        return false;
    }
    for (u64 i = 0; i < cap; ++i)
    {
        kdst[i] = '\0';
    }
    if (user_ptr == 0)
    {
        return false;
    }
    if (!duetos::mm::CopyFromUser(kdst, reinterpret_cast<const void*>(user_ptr), cap - 1))
    {
        kdst[0] = '\0';
        return false;
    }
    kdst[cap - 1] = '\0';
    return true;
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
    DesktopCompose(theme.desktop_bg, "WELCOME TO DUETOS   BOOT OK");

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

    frame->rax = static_cast<u64>(h_comp) + kHwndBias;
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
    DesktopCompose(theme.desktop_bg, "WELCOME TO DUETOS   BOOT OK");
    CompositorUnlock();
    WindowMsgWakeAll();

    duetos::arch::SerialWrite("[win] destroy pid=");
    duetos::arch::SerialWriteHex(proc->pid);
    duetos::arch::SerialWrite(" hwnd=");
    SerialWriteDec(frame->rdi);
    duetos::arch::SerialWrite("\n");

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
    DesktopCompose(theme.desktop_bg, "WELCOME TO DUETOS   BOOT OK");
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
            for (u32 i = 0; i < kMaxWindows; ++i)
            {
                if (WindowIsAlive(i) && WindowOwnerPid(i) == proc->pid && WindowPeekMessage(i, &m))
                {
                    got = true;
                    break;
                }
            }
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
        DesktopCompose(theme.desktop_bg, "WELCOME TO DUETOS   BOOT OK");
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
        DesktopCompose(theme.desktop_bg, "WELCOME TO DUETOS   BOOT OK");
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
            DesktopCompose(theme.desktop_bg, "WELCOME TO DUETOS   BOOT OK");
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
            DesktopCompose(theme.desktop_bg, "WELCOME TO DUETOS   BOOT OK");
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
        DesktopCompose(theme.desktop_bg, "WELCOME TO DUETOS   BOOT OK");
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
        DesktopCompose(theme.desktop_bg, "WELCOME TO DUETOS   BOOT OK");
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
        DesktopCompose(theme.desktop_bg, "WELCOME TO DUETOS   BOOT OK");
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
        DesktopCompose(theme.desktop_bg, "WELCOME TO DUETOS   BOOT OK");
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
        DesktopCompose(theme.desktop_bg, "WELCOME TO DUETOS   BOOT OK");
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
        DesktopCompose(theme.desktop_bg, "WELCOME TO DUETOS   BOOT OK");
        ok = true;
    }
    CompositorUnlock();

    duetos::mm::KFree(staging);
    frame->rax = ok ? 1 : 0;
}

// --- Async input state + cursor + capture -------------------------

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
            DesktopCompose(theme.desktop_bg, "WELCOME TO DUETOS   BOOT OK");
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
            DesktopCompose(theme.desktop_bg, "WELCOME TO DUETOS   BOOT OK");
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
        DesktopCompose(theme.desktop_bg, "WELCOME TO DUETOS   BOOT OK");
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
            DesktopCompose(theme.desktop_bg, "WELCOME TO DUETOS   BOOT OK");
        }
    }
    CompositorUnlock();
    frame->rax = ok ? 1 : 0;
}

} // namespace duetos::subsystems::win32
