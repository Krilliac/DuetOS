#include "console.h"

#include "font8x8.h"
#include "framebuffer.h"

namespace customos::drivers::video
{

namespace
{

constinit u32 g_origin_x = 0;
constinit u32 g_origin_y = 0;
constinit u32 g_fg = 0x00FFFFFF;
constinit u32 g_bg = 0x00101020;
constinit u32 g_cursor_col = 0;
constinit u32 g_cursor_row = 0;
constinit bool g_ready = false;

// Character buffer. Initialised to spaces on ConsoleInit /
// ConsoleClear. 80x40 chars = 3200 bytes — cheap and static.
constinit char g_buffer[kConsoleRows][kConsoleCols] = {};

void FillSpaces()
{
    for (u32 r = 0; r < kConsoleRows; ++r)
    {
        for (u32 c = 0; c < kConsoleCols; ++c)
        {
            g_buffer[r][c] = ' ';
        }
    }
}

void ScrollUp()
{
    // Shift every row up by one; the last row becomes blank.
    // O(rows*cols) memcpy — fine at 80x40.
    for (u32 r = 1; r < kConsoleRows; ++r)
    {
        for (u32 c = 0; c < kConsoleCols; ++c)
        {
            g_buffer[r - 1][c] = g_buffer[r][c];
        }
    }
    for (u32 c = 0; c < kConsoleCols; ++c)
    {
        g_buffer[kConsoleRows - 1][c] = ' ';
    }
}

void AdvanceCursor()
{
    ++g_cursor_col;
    if (g_cursor_col >= kConsoleCols)
    {
        g_cursor_col = 0;
        ++g_cursor_row;
    }
    if (g_cursor_row >= kConsoleRows)
    {
        ScrollUp();
        g_cursor_row = kConsoleRows - 1;
    }
}

} // namespace

void ConsoleInit(u32 x, u32 y, u32 fg, u32 bg)
{
    g_origin_x = x;
    g_origin_y = y;
    g_fg = fg;
    g_bg = bg;
    g_cursor_col = 0;
    g_cursor_row = 0;
    FillSpaces();
    g_ready = true;
}

void ConsoleClear()
{
    if (!g_ready)
    {
        return;
    }
    FillSpaces();
    g_cursor_col = 0;
    g_cursor_row = 0;
}

void ConsoleWriteChar(char c)
{
    if (!g_ready)
    {
        return;
    }
    if (c == '\n')
    {
        g_cursor_col = 0;
        ++g_cursor_row;
        if (g_cursor_row >= kConsoleRows)
        {
            ScrollUp();
            g_cursor_row = kConsoleRows - 1;
        }
        return;
    }
    if (c == '\r')
    {
        g_cursor_col = 0;
        return;
    }
    g_buffer[g_cursor_row][g_cursor_col] = c;
    AdvanceCursor();
}

void ConsoleWrite(const char* s)
{
    if (s == nullptr)
    {
        return;
    }
    while (*s != '\0')
    {
        ConsoleWriteChar(*s);
        ++s;
    }
}

void ConsoleWriteln(const char* s)
{
    ConsoleWrite(s);
    ConsoleWriteChar('\n');
}

void ConsoleRedraw()
{
    if (!g_ready)
    {
        return;
    }
    constexpr u32 px_w = kConsoleCols * 8;
    constexpr u32 px_h = kConsoleRows * 8;
    FramebufferFillRect(g_origin_x, g_origin_y, px_w, px_h, g_bg);
    for (u32 r = 0; r < kConsoleRows; ++r)
    {
        for (u32 c = 0; c < kConsoleCols; ++c)
        {
            const char ch = g_buffer[r][c];
            if (ch == ' ' || ch == '\0')
            {
                continue; // bg fill already there
            }
            FramebufferDrawChar(g_origin_x + c * 8, g_origin_y + r * 8, ch, g_fg, g_bg);
        }
    }
}

} // namespace customos::drivers::video
