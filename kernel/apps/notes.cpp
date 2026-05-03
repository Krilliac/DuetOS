#include "apps/notes.h"

#include "apps/notes_internal.h"
#include "arch/x86_64/serial.h"
#include "drivers/input/ps2kbd.h"
#include "drivers/video/framebuffer.h"

namespace duetos::apps::notes
{

// Cross-TU detail surface (shared with notes_persist.cpp). The
// state and the InsertAtCursor primitive live here so persistence
// can drive the same buffer the input path mutates.
namespace detail
{

constinit char g_buf[kBufCap] = {};
constinit duetos::u32 g_len = 0;
// Cursor is an index into g_buf, valid range [0, g_len]. The
// caret is visually drawn to the left of g_buf[g_cursor] (or
// at the final trailing position when g_cursor == g_len).
constinit duetos::u32 g_cursor = 0;
constinit bool g_dirty = false;

// Path walker tolerates a missing leading slash (verified in
// shell_filesystem.cpp's CmdFatappend handling).
const char kSaveFile[] = "NOTES.TXT";

bool InsertAtCursor(char c)
{
    if (g_len >= kBufCap)
        return false;
    for (duetos::u32 i = g_len; i > g_cursor; --i)
    {
        g_buf[i] = g_buf[i - 1];
    }
    g_buf[g_cursor] = c;
    ++g_len;
    ++g_cursor;
    g_dirty = true;
    return true;
}

} // namespace detail

namespace
{

using detail::g_buf;
using detail::g_cursor;
using detail::g_dirty;
using detail::g_len;
using detail::InsertAtCursor;
using detail::kBufCap;

// Backwards-compatible alias for the cap. Kept so the body of
// this TU reads as it did before the persistence split.
constexpr u32 kNotesBufCap = detail::kBufCap;

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

constinit duetos::drivers::video::WindowHandle g_handle = duetos::drivers::video::kWindowInvalid;

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
    detail::g_dirty = true;
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

// Append `s` (NUL-terminated) onto `dst` at offset `*o`, capped
// at `cap - 1` bytes. Stops early if either runs out. Helper for
// the status-footer formatter.
void AppendStr(char* dst, u32 cap, u32* o, const char* s)
{
    while (*s != '\0' && *o + 1 < cap)
    {
        dst[(*o)++] = *s++;
    }
}

// Append a u32 in decimal. Same cap discipline as AppendStr.
void AppendU32(char* dst, u32 cap, u32* o, u32 v)
{
    char tmp[12];
    u32 n = 0;
    if (v == 0)
    {
        tmp[n++] = '0';
    }
    else
    {
        while (v > 0 && n < sizeof(tmp))
        {
            tmp[n++] = static_cast<char>('0' + (v % 10));
            v /= 10;
        }
    }
    while (n > 0 && *o + 1 < cap)
    {
        dst[(*o)++] = tmp[--n];
    }
}

// Logical line + column of the cursor — \n-delimited, NOT wrap
// aware. Both 1-indexed for the user-facing footer ("L:1 C:1"
// at the start of the buffer).
struct LogicalPos
{
    u32 line;
    u32 col;
};

LogicalPos LogicalCursor()
{
    LogicalPos p{1, 1};
    for (u32 i = 0; i < g_cursor; ++i)
    {
        if (g_buf[i] == '\n')
        {
            ++p.line;
            p.col = 1;
        }
        else
        {
            ++p.col;
        }
    }
    return p;
}

// Total logical line count: newline count + 1 (an empty buffer
// reports "1 line", same convention as VS Code / vim's `set
// nonumber` status).
u32 LogicalLineCount()
{
    u32 n = 1;
    for (u32 i = 0; i < g_len; ++i)
    {
        if (g_buf[i] == '\n')
            ++n;
    }
    return n;
}

// Whitespace-delimited word count. A "word" is a maximal run of
// non-whitespace; transitions whitespace → non-whitespace
// increment the counter. Newlines, spaces, and tabs all count
// as separators.
u32 WordCount()
{
    u32 n = 0;
    bool in_word = false;
    for (u32 i = 0; i < g_len; ++i)
    {
        const char c = g_buf[i];
        const bool ws = (c == ' ' || c == '\t' || c == '\n');
        if (!ws && !in_word)
        {
            ++n;
            in_word = true;
        }
        else if (ws)
        {
            in_word = false;
        }
    }
    return n;
}

void DrawFn(u32 cx, u32 cy, u32 cw, u32 ch, void* /*cookie*/)
{
    using duetos::drivers::video::FramebufferDrawChar;
    using duetos::drivers::video::FramebufferDrawString;
    using duetos::drivers::video::FramebufferFillRect;
    // Reserve a small inset so text doesn't touch the window's
    // border — matches the padding the kernel-log viewer uses.
    constexpr u32 kPad = 4;
    // Reserve one glyph row + two pixels of separator at the
    // bottom for the status footer (line:col, counts, modified
    // flag). Text wraps inside the upper region only.
    constexpr u32 kStatusH = kGlyphH + 2;
    if (cw <= 2 * kPad || ch <= 2 * kPad + kStatusH)
        return;
    const u32 x0 = cx + kPad;
    const u32 y0 = cy + kPad;
    const u32 max_col = (cw - 2 * kPad) / kGlyphW;
    const u32 max_row = (ch - 2 * kPad - kStatusH) / kGlyphH;
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

    // Status footer: paint a thin band along the bottom of the
    // client area showing the cursor's logical line:col, total
    // line count, character count, word count, and a "*MOD"
    // flag when the buffer is dirty since the last save / load.
    const u32 status_y = cy + ch - kStatusH;
    const u32 status_band_h = kStatusH - 1;
    constexpr u32 kStatusBg = 0x00C8C8B8; // a tone darker than kPaperColour
    constexpr u32 kStatusFg = 0x00181828;
    constexpr u32 kStatusFgDirty = 0x00B82020; // red-ish for "*MOD"
    FramebufferFillRect(cx, status_y, cw, status_band_h, kStatusBg);

    char buf[80];
    u32 o = 0;
    const LogicalPos lp = LogicalCursor();
    AppendStr(buf, sizeof(buf), &o, "L:");
    AppendU32(buf, sizeof(buf), &o, lp.line);
    AppendStr(buf, sizeof(buf), &o, "/");
    AppendU32(buf, sizeof(buf), &o, LogicalLineCount());
    AppendStr(buf, sizeof(buf), &o, "  C:");
    AppendU32(buf, sizeof(buf), &o, lp.col);
    AppendStr(buf, sizeof(buf), &o, "  CHARS:");
    AppendU32(buf, sizeof(buf), &o, g_len);
    AppendStr(buf, sizeof(buf), &o, "  WORDS:");
    AppendU32(buf, sizeof(buf), &o, WordCount());
    buf[o] = '\0';

    const u32 sx = cx + kPad;
    const u32 sy = status_y + 1;
    FramebufferDrawString(sx, sy, buf, kStatusFg, kStatusBg);

    if (g_dirty)
    {
        // Right-align the "*MOD" tag inside the status band so it
        // never collides with the running counts on the left.
        constexpr const char* kModTag = "*MOD";
        constexpr u32 kModW = 4 * kGlyphW;
        if (cw > kModW + 2 * kPad)
        {
            const u32 mx = cx + cw - kPad - kModW;
            FramebufferDrawString(mx, sy, kModTag, kStatusFgDirty, kStatusBg);
        }
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
    // The boot greeting is a fresh-state seed, not a user edit —
    // clear the dirty flag so the status footer doesn't show
    // "*MOD" the moment the desktop comes up.
    g_dirty = false;
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

u32 NotesCopyToClipboard()
{
    using duetos::drivers::video::kWindowClipboardMax;
    char tmp[kWindowClipboardMax + 1];
    const u32 cap = (g_len < kWindowClipboardMax) ? g_len : kWindowClipboardMax;
    for (u32 i = 0; i < cap; ++i)
    {
        tmp[i] = g_buf[i];
    }
    tmp[cap] = '\0';
    duetos::drivers::video::WindowClipboardSetText(tmp);
    return cap;
}

u32 NotesPasteFromClipboard()
{
    using duetos::drivers::video::kWindowClipboardMax;
    char tmp[kWindowClipboardMax + 1];
    const u32 got = duetos::drivers::video::WindowClipboardGetText(tmp, kWindowClipboardMax);
    if (got == 0)
    {
        return 0;
    }
    tmp[got] = '\0';
    u32 inserted = 0;
    for (u32 i = 0; i < got; ++i)
    {
        const char c = tmp[i];
        if (c == '\n' || (static_cast<u8>(c) >= 0x20 && static_cast<u8>(c) <= 0x7E))
        {
            InsertAtCursor(c);
            ++inserted;
        }
    }
    return inserted;
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

    const bool saved_dirty = g_dirty;

    g_len = 0;
    g_cursor = 0;
    g_dirty = false;

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

    // Dirty flag starts false on a fresh test buffer.
    check(!g_dirty); // dirty/0

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

    // Dirty flag is true after edits.
    check(g_dirty); // 16

    // LogicalCursor reports L:1 C:5 here (line 1, column 5 of
    // "abZcZ\nef" — wait, the buffer is "abZc\nef" — cursor at
    // index 4 is the '\n', logical col 5 of line 1).
    {
        const auto lp = LogicalCursor();
        check(lp.line == 1 && lp.col == 5); // 17
    }
    // Total logical lines = 2.
    check(LogicalLineCount() == 2); // 18

    // Word count for "abZc\nef" — two whitespace-delimited words.
    check(WordCount() == 2); // 19

    // Inserting whitespace doesn't bump word count.
    NotesFeedChar(' ');
    NotesFeedChar(' ');
    check(WordCount() == 2); // 20

    // ...but a non-ws after a ws starts a new word.
    NotesFeedChar('X');
    check(WordCount() == 3); // 21

    // Restore pre-test state.
    g_len = saved_len;
    g_cursor = saved_cursor;
    g_dirty = saved_dirty;
    for (u32 i = 0; i < saved_len; ++i)
    {
        g_buf[i] = saved_buf[i];
    }

    if (pass)
    {
        SerialWrite("[notes] self-test OK (insert + nav + dirty flag + status counts)\n");
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
