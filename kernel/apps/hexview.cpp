#include "apps/hexview.h"

#include "arch/x86_64/serial.h"
#include "drivers/input/ps2kbd.h"
#include "drivers/video/framebuffer.h"
#include "drivers/video/notify.h"
#include "drivers/video/scrollbar.h"
#include "drivers/video/theme.h"
#include "fs/fat32.h"
#include "mm/kheap.h"

namespace duetos::apps::hexview
{

namespace
{

using duetos::drivers::video::FramebufferDrawString;
using duetos::drivers::video::FramebufferFillRect;
using duetos::drivers::video::kWindowInvalid;
using duetos::drivers::video::ThemeCurrent;
using duetos::drivers::video::WindowHandle;
using duetos::drivers::video::WindowSetContentDraw;

constexpr u32 kRowH = 10;
constexpr u32 kPad = 4;
constexpr u32 kBytesPerRow = 16;
constexpr u32 kMaxFiles = 64;
constexpr u32 kNameCap = 16;
constexpr u32 kStatusCap = 96;

struct State
{
    WindowHandle handle;

    char names[kMaxFiles][kNameCap];
    u32 count;
    u32 index;

    u8* bytes; // owned via KMalloc; nullptr if no file loaded
    u32 bytes_len;
    u32 file_size; // total file size (may exceed bytes_len when capped)
    u32 row_offset;
    char status[kStatusCap];
    bool needs_load; // re-load on next draw
};

constinit State g_state = {kWindowInvalid, {}, 0, 0, nullptr, 0, 0, 0, {}, false};

void StatusSet(const char* msg)
{
    u32 i = 0;
    for (; i + 1 < kStatusCap && msg[i] != '\0'; ++i)
        g_state.status[i] = msg[i];
    g_state.status[i] = '\0';
}

void StatusAppendStr(const char* s)
{
    u32 len = 0;
    while (g_state.status[len] != '\0' && len + 1 < kStatusCap)
        ++len;
    for (u32 i = 0; s[i] != '\0' && len + 1 < kStatusCap; ++i)
        g_state.status[len++] = s[i];
    g_state.status[len] = '\0';
}

void StatusAppendDec(u32 v)
{
    char tmp[16];
    u32 n = 0;
    if (v == 0)
        tmp[n++] = '0';
    else
        while (v > 0 && n < sizeof(tmp))
        {
            tmp[n++] = static_cast<char>('0' + (v % 10));
            v /= 10;
        }
    u32 len = 0;
    while (g_state.status[len] != '\0' && len + 1 < kStatusCap)
        ++len;
    while (n > 0 && len + 1 < kStatusCap)
        g_state.status[len++] = tmp[--n];
    g_state.status[len] = '\0';
}

// Format a 32-bit byte offset as 8 uppercase hex digits.
void FormatHex8(char* out, u32 v)
{
    static const char kHex[] = "0123456789ABCDEF";
    for (u32 i = 0; i < 8; ++i)
    {
        out[7 - i] = kHex[v & 0xF];
        v >>= 4;
    }
    out[8] = '\0';
}

// Format a single byte as 2 uppercase hex digits.
void FormatHex2(char* out, u8 v)
{
    static const char kHex[] = "0123456789ABCDEF";
    out[0] = kHex[(v >> 4) & 0xF];
    out[1] = kHex[v & 0xF];
    out[2] = '\0';
}

// Map a byte to its printable form, or '.' for non-printable.
char PrintableByte(u8 b)
{
    if (b >= 0x20 && b <= 0x7E)
        return static_cast<char>(b);
    return '.';
}

// Free the loaded bytes, if any. Idempotent.
void FreeBytes()
{
    if (g_state.bytes != nullptr)
    {
        mm::KFree(g_state.bytes);
        g_state.bytes = nullptr;
    }
    g_state.bytes_len = 0;
    g_state.file_size = 0;
    g_state.row_offset = 0;
}

// Re-scan the FAT32 root. No extension filter — every regular
// file is a candidate. Caps at kMaxFiles to bound memory.
void RescanRoot()
{
    namespace fat = fs::fat32;
    char prev_name[kNameCap];
    bool had_prev = false;
    if (g_state.index < g_state.count)
    {
        for (u32 i = 0; i < kNameCap; ++i)
            prev_name[i] = g_state.names[g_state.index][i];
        had_prev = (prev_name[0] != '\0');
    }
    g_state.count = 0;
    g_state.index = 0;

    const fat::Volume* v = fat::Fat32Volume(0);
    if (v == nullptr)
        return;
    fat::DirEntry entries[fat::kMaxDirEntries];
    const u32 n = fat::Fat32ListDirByCluster(v, v->root_cluster, entries, fat::kMaxDirEntries);
    for (u32 i = 0; i < n && g_state.count < kMaxFiles; ++i)
    {
        if ((entries[i].attributes & 0x10) != 0)
            continue;
        const char* src = entries[i].name;
        char* dst = g_state.names[g_state.count];
        u32 j = 0;
        for (; j + 1 < kNameCap && src[j] != '\0'; ++j)
            dst[j] = src[j];
        dst[j] = '\0';
        ++g_state.count;
    }

    if (had_prev)
    {
        for (u32 i = 0; i < g_state.count; ++i)
        {
            const char* a = g_state.names[i];
            bool match = true;
            for (u32 k = 0; k < kNameCap; ++k)
            {
                if (a[k] != prev_name[k])
                {
                    match = false;
                    break;
                }
                if (a[k] == '\0')
                    break;
            }
            if (match)
            {
                g_state.index = i;
                break;
            }
        }
    }
}

// Load the current file's bytes into g_state.bytes (capped at
// kHexViewMaxFileBytes). Returns true on success.
bool LoadCurrent()
{
    namespace fat = fs::fat32;
    FreeBytes();
    StatusSet("");
    if (g_state.count == 0)
    {
        StatusSet("(no files in /)");
        return false;
    }
    if (g_state.index >= g_state.count)
        g_state.index = 0;
    const fat::Volume* v = fat::Fat32Volume(0);
    if (v == nullptr)
    {
        StatusSet("(no FAT32 volume)");
        return false;
    }
    const char* name = g_state.names[g_state.index];
    fat::DirEntry e;
    if (!fat::Fat32LookupPath(v, name, &e))
    {
        StatusSet("lookup FAILED: ");
        StatusAppendStr(name);
        return false;
    }
    g_state.file_size = e.size_bytes;
    const u32 want = (e.size_bytes < kHexViewMaxFileBytes) ? e.size_bytes : kHexViewMaxFileBytes;
    if (want == 0)
    {
        StatusSet(name);
        StatusAppendStr("  (empty file)");
        return true;
    }
    void* alloc = mm::KMalloc(want);
    if (alloc == nullptr)
    {
        StatusSet("out of kheap memory");
        return false;
    }
    const i64 got = fat::Fat32ReadFile(v, &e, alloc, want);
    if (got <= 0)
    {
        mm::KFree(alloc);
        StatusSet("read FAILED: ");
        StatusAppendStr(name);
        return false;
    }
    g_state.bytes = static_cast<u8*>(alloc);
    g_state.bytes_len = static_cast<u32>(got);
    g_state.row_offset = 0;
    StatusSet(name);
    StatusAppendStr("  ");
    StatusAppendDec(g_state.file_size);
    StatusAppendStr(" B");
    if (e.size_bytes > kHexViewMaxFileBytes)
        StatusAppendStr(" (truncated)");
    return true;
}

// -------------------------------------------------------------------
// Draw — paints the current page of bytes.
// -------------------------------------------------------------------
//
// Layout per row: 8-char offset + 2 spaces + 16 hex bytes
// (split 8/8 with a space between groups) + 2 spaces + 16 ASCII
// characters. At 8 px per glyph that's roughly:
//   8 + 2 + (16*3 + 1) + 2 + 16 = 77 char cells = 616 px wide.
// Window content of < 616 px clips the right edge; the operator
// resizes the window as needed.

void DrawFn(u32 cx, u32 cy, u32 cw, u32 ch, void* /*cookie*/)
{
    const auto& th = ThemeCurrent();
    const u32 bg = 0x00101828;
    const u32 fg = th.console_fg;
    const u32 dim = th.banner_fg;
    const u32 ink_addr = 0x00808FA0;
    const u32 ink_hex = fg;
    const u32 ink_ascii = 0x00B0B8C8;
    FramebufferFillRect(cx, cy, cw, ch, bg);

    // Two header rows: file index/name, status.
    char header[64];
    u32 ho = 0;
    header[ho++] = '[';
    {
        u32 v = (g_state.count == 0) ? 0 : (g_state.index + 1);
        char tmp[8];
        u32 n = 0;
        if (v == 0)
            tmp[n++] = '0';
        while (v > 0 && n < sizeof(tmp))
        {
            tmp[n++] = static_cast<char>('0' + (v % 10));
            v /= 10;
        }
        while (n > 0 && ho + 1 < sizeof(header))
            header[ho++] = tmp[--n];
    }
    if (ho + 1 < sizeof(header))
        header[ho++] = '/';
    {
        u32 v = g_state.count;
        char tmp[8];
        u32 n = 0;
        if (v == 0)
            tmp[n++] = '0';
        while (v > 0 && n < sizeof(tmp))
        {
            tmp[n++] = static_cast<char>('0' + (v % 10));
            v /= 10;
        }
        while (n > 0 && ho + 1 < sizeof(header))
            header[ho++] = tmp[--n];
    }
    if (ho + 1 < sizeof(header))
        header[ho++] = ']';
    header[ho] = '\0';
    FramebufferDrawString(cx + kPad, cy + 1, header, ink_addr, bg);
    FramebufferDrawString(cx + kPad, cy + 1 + kRowH, g_state.status, fg, bg);

    if (g_state.needs_load)
    {
        LoadCurrent();
        g_state.needs_load = false;
    }

    if (g_state.bytes == nullptr || g_state.bytes_len == 0)
    {
        if (ch > kRowH * 4)
            FramebufferDrawString(cx + kPad, cy + 1 + kRowH * 3, "N/P=NEXT/PREV  R=RESCAN  G=GOTO  WHEEL=SCROLL", dim,
                                  bg);
        return;
    }

    const u32 reserved_top = kRowH * 2 + 4;
    const u32 reserved_bot = kRowH + 2;
    if (ch <= reserved_top + reserved_bot)
        return;
    const u32 view_y = cy + reserved_top;
    const u32 view_h = ch - reserved_top - reserved_bot;
    const u32 rows_visible = view_h / kRowH;

    const u32 total_rows = (g_state.bytes_len + kBytesPerRow - 1) / kBytesPerRow;
    if (g_state.row_offset >= total_rows)
        g_state.row_offset = (total_rows == 0) ? 0 : (total_rows - 1);
    const u32 first_row = g_state.row_offset;
    const u32 to_draw = (rows_visible < (total_rows - first_row)) ? rows_visible : (total_rows - first_row);

    char hex2[3];
    char addr8[9];
    for (u32 r = 0; r < to_draw; ++r)
    {
        const u32 row_idx = first_row + r;
        const u32 byte_off = row_idx * kBytesPerRow;
        FormatHex8(addr8, byte_off);
        const u32 row_y = view_y + r * kRowH;
        FramebufferDrawString(cx + kPad, row_y, addr8, ink_addr, bg);

        // 16 hex bytes split 8 / 8.
        u32 col_x = cx + kPad + 8 * 8 + 8; // after offset + 1 space
        for (u32 b = 0; b < kBytesPerRow; ++b)
        {
            const u32 ofs = byte_off + b;
            if (ofs >= g_state.bytes_len)
                break;
            FormatHex2(hex2, g_state.bytes[ofs]);
            FramebufferDrawString(col_x, row_y, hex2, ink_hex, bg);
            col_x += 3 * 8; // "XX " = 3 cells
            if (b == 7)
                col_x += 8; // extra gap between two groups of 8
        }
        // ASCII gutter.
        char ascii[kBytesPerRow + 1];
        u32 a = 0;
        for (u32 b = 0; b < kBytesPerRow; ++b)
        {
            const u32 ofs = byte_off + b;
            if (ofs >= g_state.bytes_len)
                break;
            ascii[a++] = PrintableByte(g_state.bytes[ofs]);
        }
        ascii[a] = '\0';
        // Anchor ASCII gutter at a fixed column so short rows
        // don't slide it left.
        const u32 ascii_x = cx + kPad + (8 + 1 + (16 * 3 + 1) + 1) * 8;
        FramebufferDrawString(ascii_x, row_y, ascii, ink_ascii, bg);
    }

    // Scrollbar registration so the kernel mouse loop can drag.
    if (total_rows > rows_visible && cw > duetos::drivers::video::kScrollbarWidth)
    {
        const u32 sb_x = cx + cw - duetos::drivers::video::kScrollbarWidth;
        const u32 sb_y = view_y;
        const u32 sb_w = duetos::drivers::video::kScrollbarWidth;
        const u32 sb_h = rows_visible * kRowH;
        duetos::drivers::video::ScrollbarPaint(sb_x, sb_y, sb_w, sb_h, {total_rows, rows_visible, first_row});
        duetos::drivers::video::WindowScrollbarSurface s{};
        s.present = true;
        s.x = sb_x;
        s.y = sb_y;
        s.w = sb_w;
        s.h = sb_h;
        s.total = total_rows;
        s.visible = rows_visible;
        s.first = first_row;
        duetos::drivers::video::WindowSetScrollbar(g_state.handle, s);
    }
    else
    {
        duetos::drivers::video::WindowScrollbarSurface s{};
        s.present = false;
        duetos::drivers::video::WindowSetScrollbar(g_state.handle, s);
    }

    if (ch > kRowH * 2)
        FramebufferDrawString(cx + kPad, cy + ch - kRowH - 1,
                              "N/P=FILE  J/K=ROW  PG=PAGE  HOME/END  R=RELOAD  WHEEL=SCROLL", dim, bg);
}

void StepIndex(bool forward)
{
    if (g_state.count == 0)
        return;
    if (forward)
        g_state.index = (g_state.index + 1) % g_state.count;
    else
        g_state.index = (g_state.index == 0) ? (g_state.count - 1) : (g_state.index - 1);
    g_state.needs_load = true;
}

void ScrollRows(i32 delta)
{
    const u32 total_rows = (g_state.bytes_len + kBytesPerRow - 1) / kBytesPerRow;
    if (total_rows == 0)
        return;
    if (delta < 0)
    {
        const u32 step = static_cast<u32>(-delta);
        g_state.row_offset = (g_state.row_offset > step) ? (g_state.row_offset - step) : 0;
    }
    else
    {
        const u32 step = static_cast<u32>(delta);
        const u32 max_first = (total_rows > 0) ? (total_rows - 1) : 0;
        g_state.row_offset = (g_state.row_offset + step > max_first) ? max_first : (g_state.row_offset + step);
    }
}

} // namespace

void HexViewInit(WindowHandle handle)
{
    g_state.handle = handle;
    g_state.count = 0;
    g_state.index = 0;
    g_state.bytes = nullptr;
    g_state.bytes_len = 0;
    g_state.file_size = 0;
    g_state.row_offset = 0;
    g_state.status[0] = '\0';
    g_state.needs_load = true;
    RescanRoot();
    WindowSetContentDraw(handle, DrawFn, nullptr);
    duetos::drivers::video::WindowSetWheelHandler(handle, HexViewOnWheel);
    duetos::drivers::video::WindowSetScrollHandler(handle, [](u32 first) { g_state.row_offset = first; });
}

WindowHandle HexViewWindow()
{
    return g_state.handle;
}

bool HexViewFeedChar(char c)
{
    if (c == 'n' || c == 'N')
    {
        StepIndex(true);
        return true;
    }
    if (c == 'p' || c == 'P')
    {
        StepIndex(false);
        return true;
    }
    if (c == 'r' || c == 'R')
    {
        RescanRoot();
        g_state.needs_load = true;
        duetos::drivers::video::NotifyShow("hexview: reloaded");
        return true;
    }
    if (c == 'j' || c == 'J')
    {
        ScrollRows(1);
        return true;
    }
    if (c == 'k' || c == 'K')
    {
        ScrollRows(-1);
        return true;
    }
    return false;
}

bool HexViewFeedArrow(duetos::u16 keycode)
{
    using namespace duetos::drivers::input;
    switch (keycode)
    {
    case kKeyArrowDown:
        ScrollRows(1);
        return true;
    case kKeyArrowUp:
        ScrollRows(-1);
        return true;
    case kKeyArrowRight:
        StepIndex(true);
        return true;
    case kKeyArrowLeft:
        StepIndex(false);
        return true;
    case kKeyPageDown:
        ScrollRows(16);
        return true;
    case kKeyPageUp:
        ScrollRows(-16);
        return true;
    case kKeyHome:
        g_state.row_offset = 0;
        return true;
    case kKeyEnd:
    {
        const u32 total = (g_state.bytes_len + kBytesPerRow - 1) / kBytesPerRow;
        g_state.row_offset = (total > 0) ? (total - 1) : 0;
        return true;
    }
    default:
        return false;
    }
}

void HexViewOnWheel(duetos::i32 dz, duetos::u8 modifiers)
{
    using duetos::drivers::input::kKeyModCtrl;
    if (dz == 0)
        return;
    const bool ctrl = (modifiers & kKeyModCtrl) != 0;
    const i32 step = ctrl ? 16 : 1;
    // Convention: wheel-up scrolls toward earlier bytes.
    ScrollRows((dz > 0) ? -step * dz : step * (-dz));
}

bool HexViewSelectByName(const char* name)
{
    if (name == nullptr || name[0] == '\0')
        return false;
    RescanRoot();
    auto up = [](char ch) { return (ch >= 'a' && ch <= 'z') ? static_cast<char>(ch - ('a' - 'A')) : ch; };
    for (u32 i = 0; i < g_state.count; ++i)
    {
        const char* a = g_state.names[i];
        u32 k = 0;
        for (; a[k] != '\0' && name[k] != '\0'; ++k)
            if (up(a[k]) != up(name[k]))
                break;
        if (a[k] == '\0' && name[k] == '\0')
        {
            g_state.index = i;
            g_state.needs_load = true;
            return true;
        }
    }
    return false;
}

void HexViewSelfTest()
{
    using arch::SerialWrite;
    bool ok = true;
    char buf[9];
    FormatHex8(buf, 0);
    ok = ok && buf[0] == '0' && buf[7] == '0' && buf[8] == '\0';
    FormatHex8(buf, 0xDEADBEEF);
    ok = ok && buf[0] == 'D' && buf[1] == 'E' && buf[2] == 'A' && buf[3] == 'D' && buf[4] == 'B' && buf[5] == 'E' &&
         buf[6] == 'E' && buf[7] == 'F';
    char hex2[3];
    FormatHex2(hex2, 0xAB);
    ok = ok && hex2[0] == 'A' && hex2[1] == 'B' && hex2[2] == '\0';
    ok = ok && PrintableByte('A') == 'A';
    ok = ok && PrintableByte(0x00) == '.';
    ok = ok && PrintableByte(0x7F) == '.';
    ok = ok && PrintableByte(0x20) == ' ';
    ok = ok && PrintableByte(0x7E) == '~';
    SerialWrite(ok ? "[hexview] self-test OK\n" : "[hexview] self-test FAILED\n");
}

} // namespace duetos::apps::hexview
