#include "apps/notes.h"

#include "arch/x86_64/serial.h"
#include "drivers/input/ps2kbd.h"
#include "drivers/video/framebuffer.h"

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
// Cursor is an index into g_buf, valid range [0, g_len]. The
// caret is visually drawn to the left of g_buf[g_cursor] (or
// at the final trailing position when g_cursor == g_len).
constinit u32 g_cursor = 0;
constinit duetos::drivers::video::WindowHandle g_handle = duetos::drivers::video::kWindowInvalid;

// Insert `c` at g_cursor, shifting the tail right by one.
// Returns true iff the buffer had room.
bool InsertAtCursor(char c)
{
    if (g_len >= kNotesBufCap)
        return false;
    for (u32 i = g_len; i > g_cursor; --i)
    {
        g_buf[i] = g_buf[i - 1];
    }
    g_buf[g_cursor] = c;
    ++g_len;
    ++g_cursor;
    return true;
}

// Delete the char to the right of the cursor (forward delete).
// Returns true iff anything was deleted.
bool DeleteAtCursor()
{
    if (g_cursor >= g_len)
        return false;
    for (u32 i = g_cursor; i + 1 < g_len; ++i)
    {
        g_buf[i] = g_buf[i + 1];
    }
    --g_len;
    return true;
}

// Backspace: delete the char to the left of the cursor.
bool BackspaceAtCursor()
{
    if (g_cursor == 0)
        return false;
    --g_cursor;
    return DeleteAtCursor();
}

// Start of the logical line (newline-delimited) containing
// position `pos`. Returns 0 or the index right after the
// preceding '\n'.
u32 LineStart(u32 pos)
{
    u32 i = pos;
    while (i > 0 && g_buf[i - 1] != '\n')
    {
        --i;
    }
    return i;
}

// End of the logical line containing `pos`: points at the
// trailing '\n' or at g_len for the last (unterminated) line.
u32 LineEnd(u32 pos)
{
    u32 i = pos;
    while (i < g_len && g_buf[i] != '\n')
    {
        ++i;
    }
    return i;
}

void MoveLeft()
{
    if (g_cursor > 0)
        --g_cursor;
}

void MoveRight()
{
    if (g_cursor < g_len)
        ++g_cursor;
}

void MoveHome()
{
    g_cursor = LineStart(g_cursor);
}

void MoveEnd()
{
    g_cursor = LineEnd(g_cursor);
}

// Arrow Up: move to the same logical-line column on the
// preceding line, clamped if that line is shorter.
void MoveUp()
{
    const u32 start = LineStart(g_cursor);
    if (start == 0)
    {
        return; // Already on the first line.
    }
    const u32 col = g_cursor - start;
    const u32 prev_end = start - 1; // The '\n' ending the previous line.
    const u32 prev_start = LineStart(prev_end);
    const u32 prev_len = prev_end - prev_start;
    g_cursor = prev_start + (col < prev_len ? col : prev_len);
}

// Arrow Down: mirror of MoveUp against the following line.
void MoveDown()
{
    const u32 end = LineEnd(g_cursor);
    if (end >= g_len)
    {
        return; // No newline after the cursor — no next line.
    }
    const u32 start = LineStart(g_cursor);
    const u32 col = g_cursor - start;
    const u32 next_start = end + 1; // Skip past the '\n'.
    const u32 next_end = LineEnd(next_start);
    const u32 next_len = next_end - next_start;
    g_cursor = next_start + (col < next_len ? col : next_len);
}

// Walk the buffer to the index `target` using the same wrap
// discipline the draw loop uses, returning the visual (row, col).
// If `target == g_len` and the final char would have wrapped the
// next position, the returned col may equal max_col — the caller
// is expected to treat that as "wrap to (row+1, 0)" before
// painting.
struct VisualPos
{
    u32 row;
    u32 col;
};

VisualPos ComputeVisualPos(u32 target, u32 max_col)
{
    VisualPos p{0, 0};
    for (u32 i = 0; i < target; ++i)
    {
        const char c = g_buf[i];
        if (c == '\n')
        {
            ++p.row;
            p.col = 0;
            continue;
        }
        if (p.col >= max_col)
        {
            ++p.row;
            p.col = 0;
        }
        ++p.col;
    }
    return p;
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

    // Paint the caret. Compute its visual position independently
    // of the draw loop because the cursor may sit mid-buffer, not
    // just at the tail. A trailing-column cursor wraps to the
    // start of the next row so it's visible in the client area.
    VisualPos cp = ComputeVisualPos(g_cursor, max_col);
    if (cp.col >= max_col)
    {
        ++cp.row;
        cp.col = 0;
    }
    if (cp.row < max_row && cp.col < max_col)
    {
        FramebufferDrawChar(x0 + cp.col * kGlyphW, y0 + cp.row * kGlyphH, '_', kInkColour, kPaperColour);
    }
}

} // namespace

void NotesInit(duetos::drivers::video::WindowHandle handle)
{
    g_handle = handle;
    duetos::drivers::video::WindowSetContentDraw(handle, DrawFn, nullptr);

    // Seed with a short greeting so the window isn't blank at
    // boot — also gives the smoke harness a deterministic
    // string to grep for ("DuetOS Notes"). Cursor lands at the
    // end so the user can start typing immediately.
    const char kInit[] = "DuetOS Notes v1\nArrow keys move, Home/End/Del work.\n";
    for (const char* p = kInit; *p != 0; ++p)
    {
        InsertAtCursor(*p);
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
        BackspaceAtCursor();
        return true;
    }
    if (c == 0x0A)
    {
        InsertAtCursor('\n');
        return true;
    }
    const u8 uc = static_cast<u8>(c);
    if (uc >= 0x20 && uc <= 0x7E)
    {
        InsertAtCursor(c);
        return true;
    }
    return false;
}

bool NotesFeedKey(u16 keycode)
{
    using namespace duetos::drivers::input;
    switch (keycode)
    {
    case kKeyArrowLeft:
        MoveLeft();
        return true;
    case kKeyArrowRight:
        MoveRight();
        return true;
    case kKeyArrowUp:
        MoveUp();
        return true;
    case kKeyArrowDown:
        MoveDown();
        return true;
    case kKeyHome:
        MoveHome();
        return true;
    case kKeyEnd:
        MoveEnd();
        return true;
    case kKeyDelete:
        DeleteAtCursor();
        return true;
    default:
        return false;
    }
}

void NotesSelfTest()
{
    using duetos::arch::SerialWrite;
    using duetos::drivers::input::kKeyArrowDown;
    using duetos::drivers::input::kKeyArrowLeft;
    using duetos::drivers::input::kKeyArrowRight;
    using duetos::drivers::input::kKeyArrowUp;
    using duetos::drivers::input::kKeyDelete;
    using duetos::drivers::input::kKeyEnd;
    using duetos::drivers::input::kKeyHome;

    // Save the live buffer so the post-Init greeting survives
    // the scratch-state the test produces. 4 KiB on the boot
    // stack is well within the kernel thread's frame budget.
    char saved_buf[kNotesBufCap];
    const u32 saved_len = g_len;
    const u32 saved_cursor = g_cursor;
    for (u32 i = 0; i < saved_len; ++i)
    {
        saved_buf[i] = g_buf[i];
    }

    g_len = 0;
    g_cursor = 0;

    bool pass = true;
    u32 failed_step = 0;
    u32 step = 0;
    auto check = [&](bool ok)
    {
        ++step;
        if (!ok && pass)
        {
            pass = false;
            failed_step = step;
        }
    };

    // Build "abc\ndef": two lines, cursor should end at 7.
    NotesFeedChar('a');
    NotesFeedChar('b');
    NotesFeedChar('c');
    NotesFeedChar('\n');
    NotesFeedChar('d');
    NotesFeedChar('e');
    NotesFeedChar('f');
    check(g_len == 7 && g_cursor == 7); // 1

    // Home on the second line lands on the 'd'.
    MoveHome();
    check(g_cursor == 4); // 2

    // Left across the newline, then Right back.
    MoveLeft();
    check(g_cursor == 3); // 3
    MoveRight();
    check(g_cursor == 4); // 4

    // End of the second logical line.
    MoveEnd();
    check(g_cursor == 7); // 5

    // Up preserves column (col 3 on "def" -> col 3 on "abc").
    MoveUp();
    check(g_cursor == 3); // 6
    // Down symmetric.
    MoveDown();
    check(g_cursor == 7); // 7

    // Insert 'X' at the tail, then Backspace removes it.
    NotesFeedChar('X');
    check(g_len == 8 && g_buf[7] == 'X' && g_cursor == 8); // 8
    NotesFeedChar(0x08);
    check(g_len == 7 && g_cursor == 7); // 9

    // Delete at end is a no-op.
    NotesFeedKey(kKeyDelete);
    check(g_len == 7 && g_cursor == 7); // 10

    // Delete mid-buffer: Home to line 2, Delete removes 'd'.
    MoveHome();
    NotesFeedKey(kKeyDelete);
    check(g_len == 6 && g_buf[4] == 'e' && g_cursor == 4); // 11

    // Up from col 0 of line 2 lands on col 0 of line 1.
    NotesFeedKey(kKeyArrowUp);
    check(g_cursor == 0); // 12

    // Right 3 places, then insert at the '\n' boundary shifts tail.
    NotesFeedKey(kKeyArrowRight);
    NotesFeedKey(kKeyArrowRight);
    NotesFeedKey(kKeyArrowRight);
    check(g_cursor == 3); // 13
    NotesFeedChar('Z');
    check(g_len == 7 && g_buf[3] == 'Z' && g_buf[4] == '\n'); // 14

    // End on line 1 (after insert) lands at index 4 (the '\n').
    MoveEnd();
    check(g_cursor == 4); // 15

    // Restore pre-test state.
    g_len = saved_len;
    g_cursor = saved_cursor;
    for (u32 i = 0; i < saved_len; ++i)
    {
        g_buf[i] = saved_buf[i];
    }

    if (pass)
    {
        SerialWrite("[notes] self-test OK (insert + backspace + delete + every nav binding)\n");
    }
    else
    {
        char msg[64] = "[notes] self-test FAILED at step ";
        u32 o = 33;
        if (failed_step == 0)
        {
            msg[o++] = '?';
        }
        else
        {
            char tmp[8];
            u32 n = 0;
            u32 v = failed_step;
            while (v > 0 && n < sizeof(tmp))
            {
                tmp[n++] = static_cast<char>('0' + (v % 10));
                v /= 10;
            }
            for (u32 i = 0; i < n; ++i)
            {
                msg[o++] = tmp[n - 1 - i];
            }
        }
        msg[o++] = '\n';
        msg[o] = '\0';
        SerialWrite(msg);
    }
}

} // namespace duetos::apps::notes
