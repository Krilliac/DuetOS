#include "apps/notes.h"

#include "apps/notes_internal.h"
#include "arch/x86_64/serial.h"
#include "arch/x86_64/timer.h"
#include "drivers/input/ps2kbd.h"
#include "drivers/video/dnd.h"
#include "drivers/video/framebuffer.h"
#include "drivers/video/notify.h"
#include "drivers/video/theme.h"

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
// Selection anchor — see notes_internal.h for semantics.
constinit duetos::i32 g_sel_anchor = kNoSelection;

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
    // Any insert clears a pending selection — typing anywhere
    // is a non-shifted edit. (A future "type-replaces-selection"
    // semantic would delete the selected range first; v1 keeps
    // the simpler clear-and-insert behaviour.)
    g_sel_anchor = kNoSelection;
    return true;
}

} // namespace detail

namespace
{

using detail::g_buf;
using detail::g_cursor;
using detail::g_dirty;
using detail::g_len;
using detail::g_sel_anchor;
using detail::InsertAtCursor;
using detail::kBufCap;
using detail::kNoSelection;

// Undo ring. Each frame snapshots the live buffer + cursor +
// selection state at the moment a mutation lands. The ring is
// 16 deep; the oldest frame is dropped silently when an insert
// would otherwise overflow. NotesUndo pops the most-recent
// frame off the head.
constexpr u32 kUndoCap = 16;

struct UndoFrame
{
    char buf[kBufCap];
    u32 len;
    u32 cursor;
    i32 sel_anchor;
    u64 tick; // arch::TimerTicks() at push time — drives 250 ms coalesce
};

constinit UndoFrame g_undo[kUndoCap] = {};
constinit u32 g_undo_count = 0;

// Coalesce window — see PushUndo. Wall-clock-equivalent
// 250ms at the kernel's 100Hz scheduler tick rate, so 25
// ticks. Tunable on the first user complaint about either
// too-greedy or too-fine-grained undo steps.
constexpr u64 kUndoCoalesceTicks = 25;

// Capture the live state into the head undo frame. Coalesce
// rule: if the previous push happened within 250 ms AND the
// content delta is "additive within one word" (length differs
// by ±1 and the cursor moved by ±1), overwrite the previous
// frame instead of pushing a new one. Keeps the 16-slot ring
// useful for word-level undo without wasting frames on every
// keystroke.
void PushUndo()
{
    const u64 now = duetos::arch::TimerTicks();
    if (g_undo_count > 0)
    {
        UndoFrame& last = g_undo[g_undo_count - 1];
        const bool fresh = (now - last.tick) <= kUndoCoalesceTicks;
        const i32 dlen = static_cast<i32>(g_len) - static_cast<i32>(last.len);
        const bool small_delta = (dlen >= -1 && dlen <= 1);
        if (fresh && small_delta)
        {
            // Overwrite head frame — keep its older content as
            // the snapshot we'd undo back to.
            last.tick = now;
            return;
        }
    }
    if (g_undo_count == kUndoCap)
    {
        // Ring full. Drop the oldest by shifting everything down
        // one slot. 16 entries × 4 KiB = 64 KiB total — the shift
        // is rare enough (each gesture, not each keystroke) and
        // small enough that a memmove-equivalent is fine.
        for (u32 i = 1; i < kUndoCap; ++i)
        {
            g_undo[i - 1] = g_undo[i];
        }
        g_undo_count = kUndoCap - 1;
    }
    UndoFrame& f = g_undo[g_undo_count++];
    f.len = g_len;
    f.cursor = g_cursor;
    f.sel_anchor = g_sel_anchor;
    f.tick = now;
    for (u32 i = 0; i < g_len && i < kBufCap; ++i)
    {
        f.buf[i] = g_buf[i];
    }
}

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

// Viewport scroll offset, in visual rows. Wheel adjusts this
// directly; the draw loop skips painting until the row counter
// reaches g_view_top, then paints up to max_row rows. When the
// cursor moves outside the visible band, the input path calls
// AutoScrollIntoView to nudge g_view_top so the caret stays
// visible.
constinit u32 g_view_top = 0;

// Last (max_col, max_row) the draw loop used. Captured each
// frame so the wheel + nav handlers can clamp scroll bounds
// without re-deriving the geometry. Defaults to a sane non-
// zero so a wheel event before the first compose doesn't
// divide by zero.
constinit u32 g_last_max_col = 80;
constinit u32 g_last_max_row = 24;

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
    g_sel_anchor = kNoSelection;
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

// Word-class for Ctrl+arrow word-wise navigation. v0 splits
// on transitions between alphanumeric runs and everything
// else — same heuristic every editor in this category uses.
bool IsWordChar(char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_';
}

// Walk one word to the left: skip the run of non-word chars
// immediately to the left, then skip the run of word chars.
// Lands on the first char of the leftward word boundary, or 0
// if the cursor was already at the start.
void MoveWordLeft()
{
    if (g_cursor == 0)
        return;
    u32 i = g_cursor;
    while (i > 0 && !IsWordChar(g_buf[i - 1]))
        --i;
    while (i > 0 && IsWordChar(g_buf[i - 1]))
        --i;
    g_cursor = i;
}

// Mirror of MoveWordLeft.
void MoveWordRight()
{
    if (g_cursor >= g_len)
        return;
    u32 i = g_cursor;
    while (i < g_len && IsWordChar(g_buf[i]))
        ++i;
    while (i < g_len && !IsWordChar(g_buf[i]))
        ++i;
    g_cursor = i;
}

// Step the cursor by N visual lines. Reuses MoveUp/Down so
// column-preservation discipline matches single-line motion.
// PageUp / PageDown bind to a fixed step count; the v0 status
// footer doesn't expose visible-row count, so 8 lines is a
// reasonable static page (matches a typical 200-px content
// area at the existing 10-px row stride).
constexpr u32 kPageStep = 8;

void MovePage(bool up)
{
    for (u32 i = 0; i < kPageStep; ++i)
    {
        if (up)
            MoveUp();
        else
            MoveDown();
    }
}

void MoveDocStart()
{
    g_cursor = 0;
}

void MoveDocEnd()
{
    g_cursor = g_len;
}

// Selection-aware delete: if a selection is live, drop the
// selected range and clear the anchor. Returns true iff
// something was deleted. Callers branch on this so a Backspace
// or Delete with a live selection consumes the selection
// rather than the single char before/after the cursor.
bool DeleteSelectionIfAny()
{
    if (g_sel_anchor == kNoSelection || static_cast<u32>(g_sel_anchor) == g_cursor)
    {
        g_sel_anchor = kNoSelection;
        return false;
    }
    u32 lo = static_cast<u32>(g_sel_anchor);
    u32 hi = g_cursor;
    if (lo > hi)
    {
        const u32 t = lo;
        lo = hi;
        hi = t;
    }
    const u32 span = hi - lo;
    for (u32 i = lo; i + span < g_len; ++i)
    {
        g_buf[i] = g_buf[i + span];
    }
    g_len -= span;
    g_cursor = lo;
    g_sel_anchor = kNoSelection;
    detail::g_dirty = true;
    return true;
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

// Total visual-row count assuming `max_col` wrap. Walks the
// buffer once. Used by AutoScrollIntoView + the wheel clamp
// to bound g_view_top against "no scroll past last line".
u32 TotalVisualRows(u32 max_col)
{
    if (max_col == 0)
        return 0;
    u32 row = 0;
    u32 col = 0;
    for (u32 i = 0; i < g_len; ++i)
    {
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
        }
        ++col;
    }
    return row + 1;
}

// Bring the caret into the visible band by adjusting
// g_view_top. Does nothing if the caret is already visible.
void AutoScrollIntoView()
{
    const u32 max_col = (g_last_max_col > 0) ? g_last_max_col : 80;
    const u32 max_row = (g_last_max_row > 0) ? g_last_max_row : 24;
    VisualPos cp = ComputeVisualPos(g_cursor, max_col);
    if (cp.col >= max_col)
    {
        ++cp.row;
        cp.col = 0;
    }
    if (cp.row < g_view_top)
    {
        g_view_top = cp.row;
    }
    else if (cp.row >= g_view_top + max_row)
    {
        g_view_top = cp.row - max_row + 1;
    }
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
    // Cache geometry so the wheel + nav handlers can compute
    // scroll bounds without re-deriving from cw / ch.
    g_last_max_col = max_col;
    g_last_max_row = max_row;
    // Clamp g_view_top against the current buffer size — a
    // delete that shrinks past the visible band shouldn't
    // strand the viewport pointing at empty rows.
    const u32 total_rows = TotalVisualRows(max_col);
    if (total_rows > max_row)
    {
        const u32 max_top = total_rows - max_row;
        if (g_view_top > max_top)
            g_view_top = max_top;
    }
    else
    {
        g_view_top = 0;
    }

    // Selection range — half-open [sel_lo, sel_hi). When no
    // selection is live both bounds collapse to g_cursor and
    // the in-range test in the loop is always false, so the
    // historic non-highlighted draw path reduces to the same
    // pixels.
    u32 sel_lo = g_cursor;
    u32 sel_hi = g_cursor;
    if (g_sel_anchor != kNoSelection)
    {
        const u32 a = static_cast<u32>(g_sel_anchor);
        sel_lo = (a < g_cursor) ? a : g_cursor;
        sel_hi = (a > g_cursor) ? a : g_cursor;
    }
    const u32 sel_paper = duetos::drivers::video::ThemeCurrent().taskbar_accent;

    // Walk the buffer tracking the absolute visual row + col;
    // skip painting while row < g_view_top, paint into the
    // visible band [g_view_top, g_view_top + max_row), stop
    // once we're past the band. This keeps the existing wrap
    // discipline intact while gaining a real viewport.
    u32 col = 0;
    u32 row = 0;
    for (u32 i = 0; i < g_len; ++i)
    {
        if (row >= g_view_top + max_row)
            break;
        const char c = g_buf[i];
        const bool in_sel = (i >= sel_lo && i < sel_hi);
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
            if (row >= g_view_top + max_row)
                break;
        }
        if (row >= g_view_top)
        {
            const u32 paper = in_sel ? sel_paper : kPaperColour;
            const u32 vis_row = row - g_view_top;
            FramebufferDrawChar(x0 + col * kGlyphW, y0 + vis_row * kGlyphH, c, kInkColour, paper);
        }
        ++col;
    }

    // Paint the caret in the visible band. ComputeVisualPos
    // returns absolute (row, col); subtract g_view_top to land
    // in viewport coords.
    VisualPos cp = ComputeVisualPos(g_cursor, max_col);
    if (cp.col >= max_col)
    {
        ++cp.row;
        cp.col = 0;
    }
    if (cp.row >= g_view_top && cp.row < g_view_top + max_row && cp.col < max_col)
    {
        const u32 vis_row = cp.row - g_view_top;
        FramebufferDrawChar(x0 + cp.col * kGlyphW, y0 + vis_row * kGlyphH, '_', kInkColour, kPaperColour);
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

    // Find indicator — visible whenever a query is set, even
    // when it has no matches (so the user knows the search ran).
    // Layout: above the line/col status row, sharing the same
    // band on a row reserved for Find. We render it in-band
    // when there's room (full status band height) by drawing
    // the find row immediately to the right of the counts.
    const char* fq = NotesFindQuery();
    if (fq != nullptr && fq[0] != '\0')
    {
        u32 total = 0;
        u32 current = 0;
        NotesFindStats(&total, &current);
        char fbuf[80];
        u32 fo = 0;
        AppendStr(fbuf, sizeof(fbuf), &fo, "  FIND:");
        for (u32 i = 0; fq[i] != '\0' && fo + 1 < sizeof(fbuf); ++i)
            fbuf[fo++] = fq[i];
        AppendStr(fbuf, sizeof(fbuf), &fo, "  ");
        if (total == 0)
        {
            AppendStr(fbuf, sizeof(fbuf), &fo, "(NO MATCH)");
        }
        else
        {
            AppendU32(fbuf, sizeof(fbuf), &fo, current);
            AppendStr(fbuf, sizeof(fbuf), &fo, "/");
            AppendU32(fbuf, sizeof(fbuf), &fo, total);
        }
        fbuf[fo] = '\0';
        // Anchor to the existing status row, after the counts:
        // sx + 8 px per existing glyph * o is the cell after
        // the line/col/chars/words string.
        const u32 fx = sx + o * kGlyphW;
        const u32 max_x = cx + cw - kPad;
        if (fx + fo * kGlyphW < max_x)
            FramebufferDrawString(fx, sy, fbuf, kStatusFgDirty, kStatusBg);
    }
}

} // namespace

void NotesOnWheel(duetos::i32 dz, duetos::u8 modifiers)
{
    // Real viewport scroll: dz > 0 (wheel up) moves the view
    // toward row 0; dz < 0 moves it toward end-of-buffer.
    // Clamps against [0, total_rows - max_row]. The cursor
    // stays where it is — only the visible band shifts.
    if (dz == 0)
        return;
    const u32 max_col = (g_last_max_col > 0) ? g_last_max_col : 80;
    const u32 max_row = (g_last_max_row > 0) ? g_last_max_row : 24;
    const u32 total_rows = TotalVisualRows(max_col);
    if (total_rows <= max_row)
    {
        g_view_top = 0;
        return;
    }
    const u32 max_top = total_rows - max_row;
    if (dz > 0)
    {
        const u32 step = static_cast<u32>(dz);
        g_view_top = (g_view_top > step) ? (g_view_top - step) : 0;
    }
    else
    {
        const u32 step = static_cast<u32>(-dz);
        g_view_top = (g_view_top + step > max_top) ? max_top : (g_view_top + step);
    }
}

// Map screen (sx, sy) coordinates to a buffer index. Mirrors the
// forward (index → visual row/col) walk in `ComputeVisualPos`,
// re-using the content-area geometry cached by the most recent
// `DrawFn` (`g_last_max_col` / `g_last_max_row` / `g_view_top`).
// Lands on the buffer position whose visual cell contains the
// click; if the click is past end-of-line, lands on the line's
// terminator (or g_len at end-of-buffer). Returns g_len if the
// click is below the last visual row.
u32 ClickToBufferIndex(u32 sx, u32 sy)
{
    constexpr u32 kPad = 4;
    constexpr u32 kBorder = 2;
    constexpr u32 kTitleH = 22;
    duetos::u32 wx = 0, wy = 0;
    if (!duetos::drivers::video::WindowGetBounds(g_handle, &wx, &wy, nullptr, nullptr))
        return g_len;
    const u32 content_x = wx + kBorder;
    const u32 content_y = wy + kTitleH + kBorder;
    if (sx < content_x + kPad || sy < content_y + kPad)
        return 0;
    const u32 cx_in_content = sx - content_x - kPad;
    const u32 cy_in_content = sy - content_y - kPad;
    const u32 max_col = (g_last_max_col > 0) ? g_last_max_col : 80;
    const u32 max_row = (g_last_max_row > 0) ? g_last_max_row : 24;
    u32 vrow = cy_in_content / kGlyphH;
    if (vrow >= max_row)
        vrow = max_row - 1;
    u32 vcol = cx_in_content / kGlyphW;
    if (vcol > max_col)
        vcol = max_col;
    const u32 target_row = g_view_top + vrow;

    u32 row = 0;
    u32 col = 0;
    for (u32 i = 0; i < g_len; ++i)
    {
        if (row == target_row && col == vcol)
            return i;
        const char c = g_buf[i];
        if (c == '\n')
        {
            if (row == target_row)
                return i;
            ++row;
            col = 0;
            continue;
        }
        if (col >= max_col)
        {
            if (row == target_row)
                return i;
            ++row;
            col = 0;
        }
        ++col;
    }
    return g_len;
}

// Word-snap at a buffer index: walk outward through the
// surrounding run of `IsWordChar` bytes and anchor the selection
// [lo, hi). Returns true iff a non-empty word was found and the
// selection was placed; non-word indices (whitespace, punctuation,
// past-end-of-buffer) leave selection state untouched.
bool WordSnapAt(u32 idx)
{
    if (idx >= g_len || !IsWordChar(g_buf[idx]))
        return false;
    u32 lo = idx;
    while (lo > 0 && IsWordChar(g_buf[lo - 1]))
        --lo;
    u32 hi = idx;
    while (hi < g_len && IsWordChar(g_buf[hi]))
        ++hi;
    if (lo == hi)
        return false;
    g_sel_anchor = static_cast<duetos::i32>(lo);
    g_cursor = hi;
    return true;
}

bool NotesOnDoubleClick(duetos::u32 sx, duetos::u32 sy)
{
    // Map the click to a buffer index and word-snap. Clicks
    // landing on non-word chars (whitespace, punctuation) still
    // consume the event so the dispatcher's compose-on-DC path
    // doesn't fall through to the desktop background, but they
    // leave the existing selection alone.
    const u32 idx = ClickToBufferIndex(sx, sy);
    if (WordSnapAt(idx))
        AutoScrollIntoView();
    return true;
}

// Drop-target callback. Loads a `.TXT` payload into the live
// buffer; non-`.TXT` files notify and reject. Wired in
// NotesInit via DndRegisterDropTarget.
bool NotesOnDrop(const duetos::drivers::video::DndPayload& payload, u32 /*cx*/, u32 /*cy*/)
{
    if (payload.kind != duetos::drivers::video::DndKind::FileEntry)
        return false;
    const char* name = payload.text;
    u32 nlen = 0;
    while (name[nlen] != '\0')
        ++nlen;
    auto ends_with_ci = [&](const char* ext) -> bool
    {
        u32 elen = 0;
        while (ext[elen] != '\0')
            ++elen;
        if (nlen < elen)
            return false;
        for (u32 i = 0; i < elen; ++i)
        {
            char a = name[nlen - elen + i];
            char b = ext[i];
            if (a >= 'a' && a <= 'z')
                a -= 32;
            if (b >= 'a' && b <= 'z')
                b -= 32;
            if (a != b)
                return false;
        }
        return true;
    };
    if (!ends_with_ci(".TXT"))
    {
        duetos::drivers::video::NotifyShow("notes: not a .TXT");
        return false;
    }
    if (NotesLoadFile(name))
    {
        duetos::drivers::video::NotifyShow("loaded into notes");
        return true;
    }
    duetos::drivers::video::NotifyShow("notes: load failed");
    return false;
}

void NotesInit(duetos::drivers::video::WindowHandle handle)
{
    g_handle = handle;
    duetos::drivers::video::WindowSetContentDraw(handle, DrawFn, nullptr);
    duetos::drivers::video::WindowSetWheelHandler(handle, NotesOnWheel);
    duetos::drivers::video::DndRegisterDropTarget(handle, NotesOnDrop,
                                                  1u << static_cast<u32>(duetos::drivers::video::DndKind::FileEntry));

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
    bool consumed = false;
    if (static_cast<u8>(c) == 0x08)
    {
        PushUndo();
        if (!DeleteSelectionIfAny())
            BackspaceAtCursor();
        consumed = true;
    }
    else if (c == 0x0A)
    {
        PushUndo();
        DeleteSelectionIfAny();
        InsertAtCursor('\n');
        consumed = true;
    }
    else
    {
        const u8 uc = static_cast<u8>(c);
        if (uc >= 0x20 && uc <= 0x7E)
        {
            PushUndo();
            DeleteSelectionIfAny();
            InsertAtCursor(c);
            consumed = true;
        }
    }
    if (consumed)
    {
        AutoScrollIntoView();
    }
    return consumed;
}

bool NotesFeedKey(u16 keycode, u8 modifiers)
{
    using namespace duetos::drivers::input;
    const bool shift = (modifiers & kKeyModShift) != 0;
    const bool ctrl = (modifiers & kKeyModCtrl) != 0;

    auto pre_motion = [&]()
    {
        if (shift)
        {
            if (g_sel_anchor == kNoSelection)
                g_sel_anchor = static_cast<i32>(g_cursor);
        }
        else
        {
            g_sel_anchor = kNoSelection;
        }
    };

    bool consumed = true;
    switch (keycode)
    {
    case kKeyArrowLeft:
        pre_motion();
        if (ctrl)
            MoveWordLeft();
        else
            MoveLeft();
        break;
    case kKeyArrowRight:
        pre_motion();
        if (ctrl)
            MoveWordRight();
        else
            MoveRight();
        break;
    case kKeyArrowUp:
        pre_motion();
        MoveUp();
        break;
    case kKeyArrowDown:
        pre_motion();
        MoveDown();
        break;
    case kKeyPageUp:
        pre_motion();
        MovePage(true);
        break;
    case kKeyPageDown:
        pre_motion();
        MovePage(false);
        break;
    case kKeyHome:
        pre_motion();
        if (ctrl)
            MoveDocStart();
        else
            MoveHome();
        break;
    case kKeyEnd:
        pre_motion();
        if (ctrl)
            MoveDocEnd();
        else
            MoveEnd();
        break;
    case kKeyDelete:
        PushUndo();
        if (!DeleteSelectionIfAny())
            DeleteAtCursor();
        break;
    default:
        consumed = false;
        break;
    }
    if (consumed)
    {
        AutoScrollIntoView();
    }
    return consumed;
}

bool NotesUndo()
{
    if (g_undo_count == 0)
        return false;
    --g_undo_count;
    const UndoFrame& f = g_undo[g_undo_count];
    g_len = (f.len < kBufCap) ? f.len : kBufCap;
    for (u32 i = 0; i < g_len; ++i)
    {
        g_buf[i] = f.buf[i];
    }
    g_cursor = (f.cursor <= g_len) ? f.cursor : g_len;
    g_sel_anchor = f.sel_anchor;
    AutoScrollIntoView();
    // Undo doesn't clear the dirty flag — the buffer still
    // differs from disk after popping. A subsequent Save
    // clears it normally.
    return true;
}

bool NotesIsDirty()
{
    return g_dirty;
}

u32 NotesCopyToClipboard()
{
    using duetos::drivers::video::kWindowClipboardMax;
    char tmp[kWindowClipboardMax + 1];
    // Selection-aware copy: when a selection is live + non-empty,
    // copy [min(anchor, cursor), max(anchor, cursor)) instead of
    // the whole buffer. The empty-selection / no-selection
    // fallback preserves the v0 "Ctrl+C copies everything"
    // behaviour so a fresh user always gets something useful on
    // the clipboard.
    u32 lo = 0;
    u32 hi = g_len;
    if (g_sel_anchor != kNoSelection && static_cast<u32>(g_sel_anchor) != g_cursor)
    {
        lo = static_cast<u32>(g_sel_anchor);
        hi = g_cursor;
        if (lo > hi)
        {
            const u32 t = lo;
            lo = hi;
            hi = t;
        }
    }
    const u32 span = (hi > lo) ? hi - lo : 0;
    const u32 cap = (span < kWindowClipboardMax) ? span : kWindowClipboardMax;
    for (u32 i = 0; i < cap; ++i)
    {
        tmp[i] = g_buf[lo + i];
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

    // Word-snap: build a known buffer "hello world foo_bar", then
    // snap-test at indices that land inside / on word boundaries /
    // on whitespace. WordSnapAt should set [lo, hi) on a hit and
    // leave state alone on a miss.
    g_len = 0;
    g_cursor = 0;
    g_sel_anchor = kNoSelection;
    const char kSnap[] = "hello world foo_bar";
    for (u32 i = 0; kSnap[i] != '\0'; ++i)
        InsertAtCursor(kSnap[i]);
    // Click inside "hello" — selection becomes [0, 5).
    check(WordSnapAt(2));                      // 22
    check(g_sel_anchor == 0 && g_cursor == 5); // 23
    // Click on the space at index 5 — non-word, no change.
    g_sel_anchor = kNoSelection;
    g_cursor = 0;
    check(!WordSnapAt(5));                                // 24
    check(g_sel_anchor == kNoSelection && g_cursor == 0); // 25
    // Click inside "foo_bar" — selection [12, 19), underscore is a
    // word char so the whole identifier snaps.
    check(WordSnapAt(15));                       // 26
    check(g_sel_anchor == 12 && g_cursor == 19); // 27
    // Click past end-of-buffer — no-op.
    g_sel_anchor = kNoSelection;
    g_cursor = 0;
    check(!WordSnapAt(g_len));           // 28
    check(g_sel_anchor == kNoSelection); // 29

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

// ---------------------------------------------------------------
// Find / Find-Next — case-insensitive substring search across the
// live buffer. Stores the query so a follow-up F3 / Ctrl+G can
// step to the next match; selection painter highlights each match
// via the existing g_sel_anchor + g_cursor band.
// ---------------------------------------------------------------

namespace
{

constinit char g_find_query[64] = {};
constinit u32 g_find_query_len = 0;

char ToUpperAscii(char c)
{
    if (c >= 'a' && c <= 'z')
        return static_cast<char>(c - 32);
    return c;
}

// Case-insensitive forward substring search. Returns the byte
// offset of the first match at or after `start` in g_buf, or
// (u32)-1 if none. Empty / 0-length query returns -1.
u32 FindForwardCi(u32 start)
{
    using detail::g_buf;
    using detail::g_len;
    if (g_find_query_len == 0 || g_len == 0 || g_find_query_len > g_len)
        return static_cast<u32>(-1);
    if (start > g_len - g_find_query_len)
        return static_cast<u32>(-1);
    for (u32 i = start; i + g_find_query_len <= g_len; ++i)
    {
        bool match = true;
        for (u32 j = 0; j < g_find_query_len; ++j)
        {
            if (ToUpperAscii(g_buf[i + j]) != ToUpperAscii(g_find_query[j]))
            {
                match = false;
                break;
            }
        }
        if (match)
            return i;
    }
    return static_cast<u32>(-1);
}

// Highlight the match at [pos, pos + qlen): cursor lands at the
// match's tail, selection anchor at the head. Mirrors the
// pattern Shift+End / Shift+Home use for selections.
void SelectMatchAt(u32 pos)
{
    detail::g_sel_anchor = static_cast<i32>(pos);
    detail::g_cursor = pos + g_find_query_len;
}

} // namespace

bool NotesFindSet(const char* query)
{
    using detail::g_buf;
    using detail::g_cursor;
    using detail::g_len;
    using detail::g_sel_anchor;
    using detail::kNoSelection;
    g_find_query_len = 0;
    if (query == nullptr)
    {
        g_find_query[0] = '\0';
        g_sel_anchor = kNoSelection;
        return false;
    }
    for (u32 i = 0; i + 1 < sizeof(g_find_query) && query[i] != '\0'; ++i)
    {
        g_find_query[i] = query[i];
        g_find_query_len = i + 1;
    }
    g_find_query[g_find_query_len] = '\0';
    if (g_find_query_len == 0)
    {
        g_sel_anchor = kNoSelection;
        return false;
    }
    // Search forward from the current cursor; if no match,
    // wrap once from byte 0. Skips an immediate-cursor false
    // match by starting at min(cursor, g_len - qlen) so the
    // current selection's tail doesn't trivially re-match.
    const u32 start = (g_cursor <= g_len) ? g_cursor : 0;
    u32 pos = FindForwardCi(start);
    if (pos == static_cast<u32>(-1) && start > 0)
        pos = FindForwardCi(0);
    if (pos == static_cast<u32>(-1))
    {
        g_sel_anchor = kNoSelection;
        return false;
    }
    SelectMatchAt(pos);
    return true;
}

bool NotesFindNext()
{
    using detail::g_cursor;
    using detail::g_len;
    using detail::g_sel_anchor;
    using detail::kNoSelection;
    if (g_find_query_len == 0)
        return false;
    // Step past the current cursor so an existing selection's
    // tail position doesn't trivially re-match.
    const u32 start = (g_cursor < g_len) ? g_cursor : 0;
    u32 pos = FindForwardCi(start);
    if (pos == static_cast<u32>(-1))
        pos = FindForwardCi(0); // wrap to start
    if (pos == static_cast<u32>(-1))
    {
        g_sel_anchor = kNoSelection;
        return false;
    }
    SelectMatchAt(pos);
    return true;
}

bool NotesFindStats(u32* total_out, u32* current_out)
{
    using detail::g_buf;
    using detail::g_cursor;
    using detail::g_len;
    if (total_out)
        *total_out = 0;
    if (current_out)
        *current_out = 0;
    if (g_find_query_len == 0 || g_len == 0)
        return false;
    u32 total = 0;
    u32 current = 0;
    // Walk every position. Ordinal matches by checking which
    // position equals (g_cursor - qlen) — that's where the
    // SelectMatchAt landed.
    const u32 head_of_current = (g_cursor >= g_find_query_len) ? g_cursor - g_find_query_len : static_cast<u32>(-1);
    if (g_find_query_len > g_len)
        return false;
    for (u32 i = 0; i + g_find_query_len <= g_len; ++i)
    {
        bool match = true;
        for (u32 j = 0; j < g_find_query_len; ++j)
        {
            if (ToUpperAscii(g_buf[i + j]) != ToUpperAscii(g_find_query[j]))
            {
                match = false;
                break;
            }
        }
        if (match)
        {
            ++total;
            if (i == head_of_current)
                current = total;
            // Skip past the match tail so overlapping matches
            // don't double-count (mirrors `grep` and most
            // editors' default behaviour).
            i += g_find_query_len - 1;
        }
    }
    if (total_out)
        *total_out = total;
    if (current_out)
        *current_out = current;
    return total > 0;
}

const char* NotesFindQuery()
{
    return g_find_query;
}

void NotesSelectAll()
{
    using detail::g_buf;
    using detail::g_cursor;
    using detail::g_len;
    using detail::g_sel_anchor;
    if (g_len == 0)
        return;
    g_sel_anchor = 0;
    g_cursor = g_len;
    (void)g_buf;
}

void NotesGotoLine(u32 line_1based)
{
    using detail::g_buf;
    using detail::g_cursor;
    using detail::g_len;
    using detail::g_sel_anchor;
    using detail::kNoSelection;
    g_sel_anchor = kNoSelection;
    if (line_1based <= 1)
    {
        g_cursor = 0;
        return;
    }
    // Walk g_buf counting newlines; the start of line N is the
    // byte right after the (N-1)th newline. If the buffer has
    // fewer logical lines than `line_1based`, land on the start
    // of the last line (post the final newline, or the final
    // line head when no trailing newline).
    u32 line = 1;
    u32 i = 0;
    u32 last_line_head = 0;
    while (i < g_len)
    {
        if (g_buf[i] == '\n')
        {
            ++line;
            last_line_head = i + 1;
            if (line == line_1based)
            {
                g_cursor = i + 1;
                return;
            }
        }
        ++i;
    }
    g_cursor = last_line_head;
}

u32 NotesReplaceAll(const char* query, const char* replacement)
{
    using detail::g_buf;
    using detail::g_cursor;
    using detail::g_dirty;
    using detail::g_len;
    using detail::g_sel_anchor;
    using detail::kBufCap;
    using detail::kNoSelection;
    if (query == nullptr || query[0] == '\0' || g_len == 0)
        return 0;
    u32 qlen = 0;
    while (query[qlen] != '\0')
        ++qlen;
    if (qlen > g_len)
        return 0;
    const char* repl = (replacement == nullptr) ? "" : replacement;
    u32 rlen = 0;
    while (repl[rlen] != '\0')
        ++rlen;

    // Build the result into a scratch buffer, then copy back.
    // Bounded by kBufCap so the post-replace buffer can't overflow.
    char scratch[kBufCap];
    u32 sout = 0;
    u32 sin = 0;
    u32 count = 0;
    u32 first_pos = static_cast<u32>(-1);
    while (sin < g_len)
    {
        bool match = false;
        if (sin + qlen <= g_len)
        {
            match = true;
            for (u32 j = 0; j < qlen; ++j)
            {
                char ca = g_buf[sin + j];
                char cb = query[j];
                if (ca >= 'a' && ca <= 'z')
                    ca = static_cast<char>(ca - 32);
                if (cb >= 'a' && cb <= 'z')
                    cb = static_cast<char>(cb - 32);
                if (ca != cb)
                {
                    match = false;
                    break;
                }
            }
        }
        if (match)
        {
            // Bail out cleanly if the replacement would push the
            // scratch buffer past kBufCap. Whatever has been
            // committed so far is preserved.
            if (sout + rlen > kBufCap)
                break;
            for (u32 k = 0; k < rlen; ++k)
                scratch[sout++] = repl[k];
            if (first_pos == static_cast<u32>(-1))
                first_pos = sout - rlen;
            sin += qlen;
            ++count;
        }
        else
        {
            if (sout + 1 > kBufCap)
                break;
            scratch[sout++] = g_buf[sin++];
        }
    }
    if (count == 0)
        return 0;
    // Copy the rest of the buffer that wasn't scanned (only
    // happens when we bailed out on overflow above).
    while (sin < g_len && sout < kBufCap)
        scratch[sout++] = g_buf[sin++];

    for (u32 i = 0; i < sout; ++i)
        g_buf[i] = scratch[i];
    g_len = sout;
    g_cursor = (first_pos == static_cast<u32>(-1) || first_pos > g_len) ? g_len : first_pos + rlen;
    g_sel_anchor = kNoSelection;
    g_dirty = true;
    return count;
}

} // namespace duetos::apps::notes
