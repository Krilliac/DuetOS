#include "apps/dbg.h"

#include "apps/dbg_core.h"
#include "apps/dbg_internal.h"
#include "debug/disasm.h"
#include "drivers/video/framebuffer.h"
#include "drivers/video/widget.h"
#include "log/klog.h"
#include "util/types.h"

namespace duetos::apps::dbg::internal
{
DbgState g_state{};
} // namespace duetos::apps::dbg::internal

namespace duetos::apps::dbg
{

using internal::g_state;

void DbgInit()
{
    if (g_state.inited)
        return;

    using duetos::drivers::video::WindowChrome;
    WindowChrome chrome{};
    chrome.x = 80;
    chrome.y = 60;
    chrome.w = 700;
    chrome.h = 500;
    chrome.title_height = 20;
    // Slate-10-friendly chrome — the theme module overrides these
    // on first DesktopCompose if the active theme isn't Classic.
    chrome.colour_border = 0x202830;
    chrome.colour_title = 0x303A4A;
    chrome.colour_client = 0x101418;
    chrome.colour_close_btn = 0x803030;

    g_state.window = duetos::drivers::video::WindowRegister(chrome, "DuetOS Debugger");
    g_state.current_tab = Tab::Processes;
    g_state.current_pid = 0;
    g_state.mem_cursor_va = 0;
    g_state.active_bp = debug::kBpIdNone;
    g_state.mem_scroll_rows = 0;
    g_state.proc_scroll_rows = 0;
    g_state.disasm_scroll_rows = 0;
    g_state.inited = true;

    if (g_state.window == duetos::drivers::video::kWindowInvalid)
    {
        KLOG_WARN("dbg", "DbgInit: WindowRegister returned kWindowInvalid (table full?)");
        return;
    }
    duetos::drivers::video::WindowSetContentDraw(g_state.window, &render::Paint, nullptr);
    KLOG_INFO_V("dbg", "DbgInit: window=", g_state.window);
}

duetos::drivers::video::WindowHandle DbgWindow()
{
    return g_state.window;
}

namespace
{

// Cycle the current tab. dir = +1 for next, -1 for prev.
void TabAdvance(int dir)
{
    int t = static_cast<int>(g_state.current_tab) + dir;
    const int n = static_cast<int>(Tab::Count);
    if (t < 0)
        t += n;
    if (t >= n)
        t -= n;
    g_state.current_tab = static_cast<Tab>(t);
}

// Promote the currently-highlighted process row to current_pid.
// Driven by the Enter key in the Processes tab.
void PickCurrentProcess()
{
    core::ProcInfo rows[64];
    const usize n = core::EnumerateProcesses(rows, 64);
    if (n == 0)
        return;
    u32 idx = g_state.proc_scroll_rows;
    if (idx >= n)
        idx = static_cast<u32>(n - 1);
    g_state.current_pid = rows[idx].pid;
    KLOG_INFO_V("dbg", "selected pid=", g_state.current_pid);
}

} // namespace

bool DbgFeedChar(char c)
{
    if (!g_state.inited || g_state.window == duetos::drivers::video::kWindowInvalid)
        return false;

    // Cross-tab keys.
    if (c == '\t')
    {
        TabAdvance(+1);
        return true;
    }
    if (c == 27 /* ESC */)
    {
        // Release focus by cycling the active window forward.
        duetos::drivers::video::WindowCycleActive();
        return true;
    }
    if (c >= '1' && c <= '7')
    {
        // Quick-jump to tab 1..7.
        const u8 idx = static_cast<u8>(c - '1');
        if (idx < static_cast<u8>(Tab::Count))
            g_state.current_tab = static_cast<Tab>(idx);
        return true;
    }

    // Tab-specific keys.
    switch (g_state.current_tab)
    {
    case Tab::Processes:
        if (c == 'j' || c == 'J')
        {
            ++g_state.proc_scroll_rows;
            return true;
        }
        if ((c == 'k' || c == 'K') && g_state.proc_scroll_rows > 0)
        {
            --g_state.proc_scroll_rows;
            return true;
        }
        if (c == '\r' || c == '\n')
        {
            PickCurrentProcess();
            return true;
        }
        return false;

    case Tab::Memory:
        if (c == 'j' || c == 'J')
        {
            ++g_state.mem_scroll_rows;
            g_state.mem_cursor_va += 16;
            return true;
        }
        if (c == 'k' || c == 'K')
        {
            if (g_state.mem_scroll_rows > 0)
                --g_state.mem_scroll_rows;
            if (g_state.mem_cursor_va >= 16)
                g_state.mem_cursor_va -= 16;
            return true;
        }
        return false;

    case Tab::Disasm:
        if (c == 'j' || c == 'J')
        {
            // Advance one decoded instruction. The actual length
            // is known to the renderer; we approximate by 1 byte
            // so the next paint resyncs at the correct boundary.
            g_state.mem_cursor_va += 1;
            return true;
        }
        if ((c == 'k' || c == 'K') && g_state.mem_cursor_va > 0)
        {
            --g_state.mem_cursor_va;
            return true;
        }
        return false;

    default:
        return false;
    }
}

bool DbgOnWidgetEvent(u32 id)
{
    if (id < kIdBase || id >= kIdBase + kIdCount)
        return false;
    // Tab-bar widgets occupy ids kIdBase..kIdBase+6.
    const u32 rel = id - kIdBase;
    if (rel < static_cast<u32>(Tab::Count))
    {
        g_state.current_tab = static_cast<Tab>(rel);
        return true;
    }
    return true; // claimed but no-op for now
}

void DbgTick()
{
    if (!g_state.inited)
        return;
    core::WatchRefresh();
    // Renderer paints lazily — actual repaint happens when the
    // compositor recomposes after a click / keystroke. This tick
    // exists to keep watch values fresh; the WatchRefresh above
    // updates the strings, the next compose picks them up.
}

void DbgSelfTest()
{
    // Stage 1 — disassembler self-test. Delegated entirely to the
    // module so a single FAIL line points at the decoder. Already
    // emits its own structural log line; we just gate on its rv.
    if (!debug::disasm::SelfTest())
    {
        KLOG_WARN("dbg", "[smoke] dbg=FAIL stage=disasm");
        return;
    }

    // Stage 2 — process enumeration. There must be at least one
    // process at boot (the boot task is pid 0).
    core::ProcInfo rows[8];
    const usize np = core::EnumerateProcesses(rows, 8);
    if (np == 0)
    {
        KLOG_WARN("dbg", "[smoke] dbg=FAIL stage=enum");
        return;
    }

    // Stage 3 — watchlist add + refresh + remove round-trip.
    // We watch a stable kernel symbol (pid=0, the boot task's AS
    // is a kernel-only AS, so reads will likely fail — that's
    // fine, we're testing the bookkeeping, not the value).
    const u32 slot = core::WatchAdd(0, 0xFFFFFFFF80000000ULL, 4, core::WatchType::U32, "selftest");
    if (slot == 0xFFFFFFFFu)
    {
        KLOG_WARN("dbg", "[smoke] dbg=FAIL stage=watch_add");
        return;
    }
    core::WatchRefresh();
    if (!core::WatchRemove(slot))
    {
        KLOG_WARN("dbg", "[smoke] dbg=FAIL stage=watch_remove");
        return;
    }

    // Stage 4 — window registration.
    if (g_state.window == duetos::drivers::video::kWindowInvalid)
    {
        KLOG_WARN("dbg", "[smoke] dbg=FAIL stage=window");
        return;
    }

    KLOG_INFO_V("dbg", "[smoke] dbg=ok rows=", np);
}

} // namespace duetos::apps::dbg
