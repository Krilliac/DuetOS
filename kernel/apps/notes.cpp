#include "notes.h"

#include "../drivers/video/framebuffer.h"

namespace duetos::apps::notes
{

namespace
{

// Buffer cap chosen to comfortably hold any note a user would
// hand-type at boot but small enough that it doesn't add
// meaningful weight to the kernel image's .bss. 4 KiB = one
// full page.
constexpr u32 kNotesBufCap = 4096;

// 8x8 glyphs with 2 pixels of leading on each row: an 8 px
// glyph stride horizontally, a 10 px row stride vertically.
// Matches the kernel-log viewer's convention in main.cpp so
// two neighbouring windows look consistent.
constexpr u32 kGlyphW = 8;
constexpr u32 kGlyphH = 10;

// Ink + paper colours. Paper matches the window's client
// colour defined in main.cpp (0x00E0E0D8) so the glyph
// background blends into the surrounding chrome.
constexpr u32 kInkColour = 0x00101028;
constexpr u32 kPaperColour = 0x00E0E0D8;

constinit char g_buf[kNotesBufCap] = {};
constinit u32 g_len = 0;
constinit duetos::drivers::video::WindowHandle g_handle = duetos::drivers::video::kWindowInvalid;

// Append one byte unconditionally; silently drops at cap.
void Append(char c)
{
    if (g_len < kNotesBufCap)
    {
        g_buf[g_len++] = c;
    }
}

void DrawFn(u32 cx, u32 cy, u32 cw, u32 ch, void* /*cookie*/)
{
    using duetos::drivers::video::FramebufferDrawChar;
    // Reserve a small inset so text doesn't touch the window's
    // border — matches the padding the kernel-log viewer uses.
    constexpr u32 kPad = 4;
    if (cw <= 2 * kPad || ch <= 2 * kPad)
        return;
    const u32 x0 = cx + kPad;
    const u32 y0 = cy + kPad;
    const u32 max_col = (cw - 2 * kPad) / kGlyphW;
    const u32 max_row = (ch - 2 * kPad) / kGlyphH;
    if (max_col == 0 || max_row == 0)
        return;

    u32 col = 0;
    u32 row = 0;
    for (u32 i = 0; i < g_len; ++i)
    {
        if (row >= max_row)
            break;
        const char c = g_buf[i];
        if (c == '\n')
        {
            ++row;
            col = 0;
            continue;
        }
        if (col >= max_col)
        {
            ++row;
            col = 0;
            if (row >= max_row)
                break;
        }
        FramebufferDrawChar(x0 + col * kGlyphW, y0 + row * kGlyphH, c, kInkColour, kPaperColour);
        ++col;
    }
    // Caret (steady underscore) at the insert position. Steady
    // rather than blinking — blinking would require a redraw
    // cadence decoupled from the 1 Hz ui-ticker, and a steady
    // caret is perfectly legible.
    if (row < max_row && col < max_col)
    {
        FramebufferDrawChar(x0 + col * kGlyphW, y0 + row * kGlyphH, '_', kInkColour, kPaperColour);
    }
}

} // namespace

void NotesInit(duetos::drivers::video::WindowHandle handle)
{
    g_handle = handle;
    duetos::drivers::video::WindowSetContentDraw(handle, DrawFn, nullptr);

    // Seed with a short greeting so the window isn't blank at
    // boot — also gives the smoke harness a deterministic
    // string to grep for ("DuetOS Notes").
    const char kInit[] = "DuetOS Notes v0\nType to add text.\n";
    for (const char* p = kInit; *p != 0; ++p)
    {
        Append(*p);
    }
}

duetos::drivers::video::WindowHandle NotesWindow()
{
    return g_handle;
}

bool NotesFeedChar(char c)
{
    if (static_cast<u8>(c) == 0x08)
    {
        // Backspace — drop the tail byte. Rewind across a
        // newline too so visual Backspace from column 0 lands
        // at the end of the previous line.
        if (g_len > 0)
            --g_len;
        return true;
    }
    if (c == 0x0A)
    {
        Append('\n');
        return true;
    }
    const u8 uc = static_cast<u8>(c);
    if (uc >= 0x20 && uc <= 0x7E)
    {
        Append(c);
        return true;
    }
    return false;
}

} // namespace duetos::apps::notes
