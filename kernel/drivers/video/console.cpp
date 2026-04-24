#include "console.h"

#include "font8x8.h"
#include "framebuffer.h"

namespace duetos::drivers::video
{

namespace
{

// Per-console state. The existing shell console lives in
// slot 0; a secondary "klog" viewer lives in slot 1. Adding
// a third is a matter of bumping kConsoleCount + pointing a
// writer at it.
struct ConsoleState
{
    u32 origin_x;
    u32 origin_y;
    u32 fg;
    u32 bg;
    u32 cursor_col;
    u32 cursor_row;
    bool ready;
    char buffer[kConsoleRows][kConsoleCols];
};

constexpr u32 kConsoleShellIdx = 0;
constexpr u32 kConsoleKlogIdx = 1;
constexpr u32 kConsoleCount = 2;

constinit ConsoleState g_consoles[kConsoleCount] = {};

// Which console the `ConsoleRedraw` path renders. Writes to
// ConsoleWrite / ConsoleWriteChar / ConsoleClear still target
// `kConsoleShellIdx` unconditionally — the shell is the
// canonical interactive surface. ConsoleWriteCharKlog targets
// the klog slot explicitly. Switching render target does not
// move any written content; it only swaps which buffer is
// painted on next recompose.
constinit u32 g_render_target = kConsoleShellIdx;

// Capture-mode state — when set, shell-console writes divert
// into the buffer instead of the scrollback. Klog writes are
// unaffected. Used by the shell's pipe dispatch to route
// segment N's output to segment N+1's input.
constinit char* g_capture_buf = nullptr;
constinit u32 g_capture_cap = 0;
constinit u32* g_capture_len = nullptr;

ConsoleState& Shell()
{
    return g_consoles[kConsoleShellIdx];
}
ConsoleState& Klog()
{
    return g_consoles[kConsoleKlogIdx];
}

void FillSpaces(ConsoleState& cs)
{
    for (u32 r = 0; r < kConsoleRows; ++r)
    {
        for (u32 c = 0; c < kConsoleCols; ++c)
        {
            cs.buffer[r][c] = ' ';
        }
    }
}

void ScrollUp(ConsoleState& cs)
{
    for (u32 r = 1; r < kConsoleRows; ++r)
    {
        for (u32 c = 0; c < kConsoleCols; ++c)
        {
            cs.buffer[r - 1][c] = cs.buffer[r][c];
        }
    }
    for (u32 c = 0; c < kConsoleCols; ++c)
    {
        cs.buffer[kConsoleRows - 1][c] = ' ';
    }
}

void AdvanceCursor(ConsoleState& cs)
{
    ++cs.cursor_col;
    if (cs.cursor_col >= kConsoleCols)
    {
        cs.cursor_col = 0;
        ++cs.cursor_row;
    }
    if (cs.cursor_row >= kConsoleRows)
    {
        ScrollUp(cs);
        cs.cursor_row = kConsoleRows - 1;
    }
}

void WriteCharImpl(ConsoleState& cs, char c)
{
    // Shell-slot writes under capture mode divert to the
    // buffer instead of the scrollback. Klog-slot writes
    // always take the normal path so kernel activity still
    // lands in its dedicated console even during a pipe.
    if (&cs == &g_consoles[kConsoleShellIdx] && g_capture_buf != nullptr)
    {
        if (g_capture_len != nullptr && *g_capture_len + 1 < g_capture_cap)
        {
            g_capture_buf[(*g_capture_len)++] = c;
        }
        return;
    }
    if (!cs.ready)
    {
        return;
    }
    if (c == '\n')
    {
        cs.cursor_col = 0;
        ++cs.cursor_row;
        if (cs.cursor_row >= kConsoleRows)
        {
            ScrollUp(cs);
            cs.cursor_row = kConsoleRows - 1;
        }
        return;
    }
    if (c == '\r')
    {
        cs.cursor_col = 0;
        return;
    }
    if (c == '\b')
    {
        if (cs.cursor_col > 0)
        {
            --cs.cursor_col;
            cs.buffer[cs.cursor_row][cs.cursor_col] = ' ';
        }
        return;
    }
    cs.buffer[cs.cursor_row][cs.cursor_col] = c;
    AdvanceCursor(cs);
}

void RedrawImpl(const ConsoleState& cs)
{
    if (!cs.ready)
    {
        return;
    }
    constexpr u32 px_w = kConsoleCols * 8;
    constexpr u32 px_h = kConsoleRows * 8;
    FramebufferFillRect(cs.origin_x, cs.origin_y, px_w, px_h, cs.bg);
    for (u32 r = 0; r < kConsoleRows; ++r)
    {
        for (u32 c = 0; c < kConsoleCols; ++c)
        {
            const char ch = cs.buffer[r][c];
            if (ch == ' ' || ch == '\0')
            {
                continue;
            }
            FramebufferDrawChar(cs.origin_x + c * 8, cs.origin_y + r * 8, ch, cs.fg, cs.bg);
        }
    }
}

} // namespace

void ConsoleInit(u32 x, u32 y, u32 fg, u32 bg)
{
    ConsoleState& cs = Shell();
    cs.origin_x = x;
    cs.origin_y = y;
    cs.fg = fg;
    cs.bg = bg;
    cs.cursor_col = 0;
    cs.cursor_row = 0;
    FillSpaces(cs);
    cs.ready = true;

    // Klog console shares the shell's origin and size so the
    // Ctrl+Alt+F1/F2 flip renders in the same rectangle without
    // any layout dance. Colour picks a muted blue-grey so the
    // two channels are visually distinct at a glance.
    ConsoleState& k = Klog();
    k.origin_x = x;
    k.origin_y = y;
    k.fg = 0x00A0C8FF;
    k.bg = bg;
    k.cursor_col = 0;
    k.cursor_row = 0;
    FillSpaces(k);
    k.ready = true;
}

void ConsoleClear()
{
    ConsoleState& cs = Shell();
    if (!cs.ready)
    {
        return;
    }
    FillSpaces(cs);
    cs.cursor_col = 0;
    cs.cursor_row = 0;
}

void ConsoleWriteChar(char c)
{
    WriteCharImpl(Shell(), c);
}

void ConsoleWrite(const char* s)
{
    if (s == nullptr)
    {
        return;
    }
    ConsoleState& cs = Shell();
    while (*s != '\0')
    {
        WriteCharImpl(cs, *s);
        ++s;
    }
}

void ConsoleWriteln(const char* s)
{
    ConsoleWrite(s);
    ConsoleWriteChar('\n');
}

void ConsoleWriteKlog(const char* s)
{
    if (s == nullptr)
    {
        return;
    }
    ConsoleState& cs = Klog();
    while (*s != '\0')
    {
        WriteCharImpl(cs, *s);
        ++s;
    }
}

void ConsoleRedraw()
{
    if (g_render_target >= kConsoleCount)
    {
        g_render_target = kConsoleShellIdx;
    }
    RedrawImpl(g_consoles[g_render_target]);
}

void ConsoleSetOrigin(u32 x, u32 y)
{
    // Move BOTH consoles so flipping between them doesn't
    // shuffle layout. TTY mode relocates to (16, 16); desktop
    // mode to (16, 400); both paint in the same spot.
    for (u32 i = 0; i < kConsoleCount; ++i)
    {
        g_consoles[i].origin_x = x;
        g_consoles[i].origin_y = y;
    }
}

void ConsoleSetColours(u32 fg, u32 bg)
{
    // Apply colours to the shell console only — the klog
    // console keeps its own palette so the visual distinction
    // survives a mode flip.
    Shell().fg = fg;
    Shell().bg = bg;
}

void ConsoleSelectShell()
{
    g_render_target = kConsoleShellIdx;
}

void ConsoleSelectKlog()
{
    g_render_target = kConsoleKlogIdx;
}

bool ConsoleIsKlogActive()
{
    return g_render_target == kConsoleKlogIdx;
}

void ConsoleBeginCapture(char* buf, u32 cap, u32* len_out)
{
    g_capture_buf = buf;
    g_capture_cap = cap;
    g_capture_len = len_out;
    if (len_out != nullptr)
    {
        *len_out = 0;
    }
}

void ConsoleEndCapture()
{
    g_capture_buf = nullptr;
    g_capture_cap = 0;
    g_capture_len = nullptr;
}

} // namespace duetos::drivers::video
