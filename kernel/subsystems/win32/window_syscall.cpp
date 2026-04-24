#include "window_syscall.h"

#include "../../arch/x86_64/serial.h"
#include "../../arch/x86_64/traps.h"
#include "../../core/process.h"
#include "../../core/syscall.h"
#include "../../drivers/video/framebuffer.h"
#include "../../drivers/video/theme.h"
#include "../../drivers/video/widget.h"
#include "../../mm/paging.h"

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
    WindowClose(h_comp);
    const Theme& theme = ThemeCurrent();
    DesktopCompose(theme.desktop_bg, "WELCOME TO DUETOS   BOOT OK");
    CompositorUnlock();

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
    if (cmd == 0)
    {
        // SW_HIDE: v0 implements hide as a destroy — no "re-show"
        // path yet. Document in the knowledge entry. Still better
        // than a no-op because the window visually leaves.
        if (WindowIsAlive(h_comp))
        {
            WindowClose(h_comp);
        }
    }
    else
    {
        // SW_SHOW / SW_SHOWNORMAL / SW_MAXIMIZE / … — all treated
        // as "raise + activate" in v0. The chrome is already
        // painted; Raise makes it the active focus + topmost.
        if (WindowIsAlive(h_comp))
        {
            WindowRaise(h_comp);
        }
    }
    const Theme& theme = ThemeCurrent();
    DesktopCompose(theme.desktop_bg, "WELCOME TO DUETOS   BOOT OK");
    CompositorUnlock();

    frame->rax = 0;
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

} // namespace duetos::subsystems::win32
