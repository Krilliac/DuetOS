/*
 * Aurora app-interior content type — implementation.
 *
 * Public API + rationale: drivers/video/app_widgets/app_text.h.
 *
 * Measurement contract: every entry point measures through
 * `ChromeTextMeasure` and paints through `ChromeTextDraw`. Those two
 * share `TtfMeasureString`'s per-glyph `hmtx` advance sum on the TTF
 * path and `chars * scale * 8` on the bitmap path, so a column table
 * built here and hit-tested against the same table agrees with the
 * pixels by construction. That is the whole point of the file — the
 * previous round's cell-counted columns had the paint site and the
 * hit-test site each re-deriving `col * 8 + pad`, and they drifted.
 */

#include "drivers/video/app_widgets/app_text.h"

#include "arch/x86_64/serial.h"
#include "debug/probes.h"
#include "drivers/video/blend_math.h"
#include "drivers/video/framebuffer.h"

namespace duetos::drivers::video::app_widgets
{

namespace
{

/// Leading added to a role's line box to get a comfortable row pitch.
///
/// The reference's tables run their rows at ~2.7x the cap height of
/// the name in them; round 4's 5 px put us at ~2.0x, which is the
/// "reads tighter than the reference" the review called out. 8 px
/// lands Body at 21 px against a 13 px line box — ~2.6x — and still
/// leaves 9 rows visible in the smallest window the shell opens
/// (Files at 240 px of client). Any larger and the list stops being
/// a list at 1024x768.
constexpr u32 kRowLeading = 8;

/// Chip geometry. 5 px of horizontal padding either side of the
/// label, 2 px of vertical padding around the Caption line box.
constexpr u32 kPillPadX = 5;
constexpr u32 kPillPadY = 2;
constexpr u32 kPillTintAlpha = 46; // ~18 % — the design's tag fill

/// Status-dot radius, and the cell width a dot claims (diameter plus
/// the gap to the text that follows it).
constexpr u32 kDotRadius = 2;
constexpr u32 kDotCell = 12;

/// File-type tile: a 13 px rounded square with an 8 px gap to the
/// name. The outline sits at ~62 % of the row ink so the tile reads
/// as a container rather than as a second piece of text.
constexpr u32 kIconTile = 13;
constexpr u32 kIconGap = 8;
constexpr u32 kIconRadius = 4;
constexpr u32 kIconEdgeAlpha = 158;

constinit bool s_passed = false;

u32 StrLen(const char* s)
{
    u32 n = 0;
    while (s[n] != '\0')
    {
        ++n;
    }
    return n;
}

} // namespace

u32 AppRowHeight(ChromeTextRole role)
{
    return ChromeTextRoleHeight(role) + kRowLeading;
}

u32 AppTextRowY(ChromeTextRole role, u32 y, u32 row_h)
{
    const u32 line = ChromeTextRoleHeight(role);
    if (row_h <= line)
    {
        return y;
    }
    return y + (row_h - line) / 2;
}

u32 AppTextMeasure(ChromeTextRole role, const char* text)
{
    return ChromeTextMeasure(role, text);
}

u32 AppTextFit(ChromeTextRole role, const char* src, char* dst, u32 dst_cap, u32 max_px)
{
    if (dst == nullptr || dst_cap == 0)
    {
        return 0;
    }
    dst[0] = '\0';
    if (src == nullptr || src[0] == '\0' || max_px == 0)
    {
        return 0;
    }

    const u32 src_len = StrLen(src);
    const u32 copy_cap = (src_len < dst_cap - 1) ? src_len : (dst_cap - 1);

    // Fast path: the whole string (as far as dst can hold it) fits.
    for (u32 i = 0; i < copy_cap; ++i)
    {
        dst[i] = src[i];
    }
    dst[copy_cap] = '\0';
    const u32 full = ChromeTextMeasure(role, dst);
    if (full <= max_px)
    {
        return full;
    }

    // Binary-search the longest prefix whose measured width, with the
    // ".." truncation marker appended, still fits the budget. ~6
    // measures for a 40-char name instead of the 40 a linear scan
    // would cost — measurement is the expensive half on the TTF path.
    u32 lo = 0;                              // known-fitting prefix length
    u32 hi = (copy_cap >= 2) ? copy_cap : 0; // known-overflowing bound
    while (lo < hi)
    {
        const u32 mid = lo + (hi - lo + 1) / 2;
        if (mid + 2 >= dst_cap)
        {
            hi = mid - 1;
            continue;
        }
        for (u32 i = 0; i < mid; ++i)
        {
            dst[i] = src[i];
        }
        dst[mid] = '.';
        dst[mid + 1] = '.';
        dst[mid + 2] = '\0';
        if (ChromeTextMeasure(role, dst) <= max_px)
        {
            lo = mid;
        }
        else
        {
            hi = mid - 1;
        }
    }

    if (lo == 0)
    {
        // Not even one character plus the marker fits. Emit nothing
        // rather than a bare "..", which reads as a real entry.
        dst[0] = '\0';
        return 0;
    }
    for (u32 i = 0; i < lo; ++i)
    {
        dst[i] = src[i];
    }
    dst[lo] = '.';
    dst[lo + 1] = '.';
    dst[lo + 2] = '\0';
    return ChromeTextMeasure(role, dst);
}

void AppTextCell(ChromeTextRole role, u32 x, u32 y, u32 row_h, const char* text, u32 fg, u32 bg,
                 ChromeTextWeight weight)
{
    if (text == nullptr || text[0] == '\0')
    {
        return;
    }
    ChromeTextDraw(role, x, AppTextRowY(role, y, row_h), text, fg, bg, weight);
}

void AppTextCellRight(ChromeTextRole role, u32 x_right, u32 x_min, u32 y, u32 row_h, const char* text, u32 fg, u32 bg,
                      ChromeTextWeight weight)
{
    if (text == nullptr || text[0] == '\0')
    {
        return;
    }
    const u32 w = ChromeTextMeasure(role, text);
    if (w > x_right || x_right - w < x_min)
    {
        return;
    }
    ChromeTextDraw(role, x_right - w, AppTextRowY(role, y, row_h), text, fg, bg, weight);
}

u32 AppPillWidth(const char* label)
{
    if (label == nullptr || label[0] == '\0')
    {
        return 0;
    }
    return ChromeTextMeasure(ChromeTextRole::Caption, label) + 2 * kPillPadX;
}

void AppPillDraw(u32 x, u32 y, u32 row_h, const char* label, u32 ink, u32 bg)
{
    if (label == nullptr || label[0] == '\0')
    {
        return;
    }
    const u32 line = ChromeTextRoleHeight(ChromeTextRole::Caption);
    const u32 pill_h = line + 2 * kPillPadY;
    const u32 pill_w = AppPillWidth(label);
    const u32 pill_y = (row_h > pill_h) ? y + (row_h - pill_h) / 2 : y;
    const u32 fill = BlendOver(bg, ink, static_cast<u8>(kPillTintAlpha));
    FramebufferFillRoundRect(x, pill_y, pill_w, pill_h, 3, fill);
    ChromeTextDraw(ChromeTextRole::Caption, x + kPillPadX, pill_y + kPillPadY, label, ink, fill);
}

u32 AppRowDotWidth()
{
    return kDotCell;
}

void AppRowDotDraw(u32 x, u32 y, u32 row_h, u32 rgb)
{
    const i32 cx = static_cast<i32>(x + kDotRadius + 1);
    const i32 cy = static_cast<i32>(y + row_h / 2);
    FramebufferFillCircle(cx, cy, kDotRadius, rgb);
}

u32 AppRowIconWidth()
{
    return kIconTile + kIconGap;
}

void AppRowIconDraw(u32 x, u32 y, u32 row_h, char glyph, u32 ink, u32 bg)
{
    const u32 tile_y = (row_h > kIconTile) ? y + (row_h - kIconTile) / 2 : y;
    const u32 edge = BlendOver(bg, ink, static_cast<u8>(kIconEdgeAlpha));
    FramebufferDrawRoundRect(x, tile_y, kIconTile, kIconTile, kIconRadius, edge);

    if (glyph == '\0')
    {
        return;
    }
    // The glyph is centred on the tile's measured width, not on a
    // character-cell assumption — a proportional 'P' and a
    // proportional 'D' are different widths.
    const char label[2] = {glyph, '\0'};
    const u32 gw = ChromeTextMeasure(ChromeTextRole::Caption, label);
    const u32 gh = ChromeTextRoleHeight(ChromeTextRole::Caption);
    if (gw >= kIconTile || gh >= kIconTile)
    {
        return;
    }
    ChromeTextDraw(ChromeTextRole::Caption, x + (kIconTile - gw) / 2, tile_y + (kIconTile - gh) / 2, label, edge, bg);
}

u32 AppFormatSize(u64 bytes, char* out, u32 cap)
{
    if (out == nullptr || cap == 0)
    {
        return 0;
    }
    out[0] = '\0';

    constexpr u64 kKiB = 1024ull;
    constexpr u64 kMiB = 1024ull * 1024ull;
    constexpr u64 kGiB = 1024ull * 1024ull * 1024ull;

    // Whole part, optional tenth, and the unit. Bytes and KB are
    // whole-number units in the reference ("4 KB"); MB and GB carry a
    // single decimal ("1.4 MB").
    u64 whole = 0;
    u64 tenth = 0;
    bool has_tenth = false;
    const char* unit = " B";
    if (bytes < kKiB)
    {
        whole = bytes;
    }
    else if (bytes < kMiB)
    {
        whole = (bytes + kKiB / 2) / kKiB;
        unit = " KB";
    }
    else
    {
        const u64 scale = (bytes < kGiB) ? kMiB : kGiB;
        unit = (bytes < kGiB) ? " MB" : " GB";
        // Split the scaling so the x10 never touches the full
        // magnitude — a multi-TiB volume would overflow `bytes * 10`.
        const u64 tenths = (bytes / scale) * 10ull + ((bytes % scale) * 10ull + scale / 2) / scale;
        whole = tenths / 10ull;
        tenth = tenths % 10ull;
        has_tenth = true;
    }

    // Render the whole part most-significant digit first.
    char digits[24];
    u32 nd = 0;
    if (whole == 0)
    {
        digits[nd++] = '0';
    }
    while (whole > 0 && nd < sizeof(digits))
    {
        digits[nd++] = static_cast<char>('0' + (whole % 10ull));
        whole /= 10ull;
    }

    u32 o = 0;
    auto put = [&](char ch)
    {
        if (o + 1 < cap)
        {
            out[o++] = ch;
        }
    };
    for (u32 i = nd; i > 0; --i)
    {
        put(digits[i - 1]);
    }
    if (has_tenth)
    {
        put('.');
        put(static_cast<char>('0' + tenth));
    }
    for (u32 i = 0; unit[i] != '\0'; ++i)
    {
        put(unit[i]);
    }
    out[o] = '\0';
    return o;
}

void AppTextSelfTest()
{
    using duetos::arch::SerialWrite;

    auto mark_fail = [](u32 code, const char* msg)
    {
        SerialWrite(msg);
        SerialWrite("\n");
        KBP_PROBE_V(duetos::debug::ProbeId::kBootSelftestFail, code);
    };

    // (1) A row must always be taller than the line box it leads, or
    //     AppTextRowY's centring underflows and every list view
    //     paints its text hard against the row's top edge.
    for (u32 i = 0; i < 4; ++i)
    {
        const ChromeTextRole role = static_cast<ChromeTextRole>(i);
        if (AppRowHeight(role) <= ChromeTextRoleHeight(role))
        {
            mark_fail(0xD8, "[app-text-selftest] FAIL RowHeight not above line box");
            return;
        }
    }

    // (2) Fit never exceeds its budget. This is the invariant the
    //     column tables rely on: a name cell that measured wider than
    //     its column would bleed into the next column's hit zone.
    const char* long_name = "windowed_hello_world_with_a_very_long_name.exe";
    char buf[64];
    for (u32 budget = 8; budget <= 240; budget += 8)
    {
        const u32 w = AppTextFit(ChromeTextRole::Body, long_name, buf, sizeof(buf), budget);
        if (w > budget)
        {
            mark_fail(0xD9, "[app-text-selftest] FAIL Fit exceeded its pixel budget");
            return;
        }
        if (w != ChromeTextMeasure(ChromeTextRole::Body, buf))
        {
            mark_fail(0xDA, "[app-text-selftest] FAIL Fit width disagrees with Measure");
            return;
        }
    }

    // (3) Fit is monotone in budget — a wider column never shows less
    //     of the name than a narrower one did.
    char narrow[64];
    char wide[64];
    const u32 wn = AppTextFit(ChromeTextRole::Body, long_name, narrow, sizeof(narrow), 60);
    const u32 ww = AppTextFit(ChromeTextRole::Body, long_name, wide, sizeof(wide), 160);
    if (wn > ww)
    {
        mark_fail(0xDB, "[app-text-selftest] FAIL Fit not monotone in budget");
        return;
    }

    // (4) A short name is returned untouched — no gratuitous "..".
    char shortbuf[64];
    AppTextFit(ChromeTextRole::Body, "a.txt", shortbuf, sizeof(shortbuf), 400);
    if (shortbuf[0] != 'a' || shortbuf[1] != '.' || shortbuf[2] != 't')
    {
        mark_fail(0xDC, "[app-text-selftest] FAIL Fit truncated a string that fits");
        return;
    }

    // (5) A pill is always wider than the label it wraps, and an
    //     absent badge costs zero width (rows with an undeterminable
    //     ABI render nothing — never a guessed chip).
    if (AppPillWidth("WIN32 PE") <= ChromeTextMeasure(ChromeTextRole::Caption, "WIN32 PE"))
    {
        mark_fail(0xDD, "[app-text-selftest] FAIL pill narrower than its label");
        return;
    }
    if (AppPillWidth(nullptr) != 0 || AppPillWidth("") != 0)
    {
        mark_fail(0xDE, "[app-text-selftest] FAIL empty pill claimed width");
        return;
    }

    // (6) Row-Y centring keeps the whole line box inside the band.
    const u32 row_h = AppRowHeight(ChromeTextRole::Body);
    const u32 ty = AppTextRowY(ChromeTextRole::Body, 100, row_h);
    if (ty < 100 || ty + ChromeTextRoleHeight(ChromeTextRole::Body) > 100 + row_h)
    {
        mark_fail(0xDF, "[app-text-selftest] FAIL RowY pushed text outside the band");
        return;
    }

    // (7) Human-readable sizes match the reference's shape exactly.
    //     A file listing that printed "4096 BYTES" where the design
    //     prints "4 KB" is the single loudest content tell, so the
    //     boundaries are pinned rather than eyeballed.
    struct SizeCase
    {
        u64 bytes;
        const char* want;
    };
    static constexpr SizeCase kSizeCases[] = {
        {0, "0 B"},       {512, "512 B"},      {1023, "1023 B"},    {1024, "1 KB"},        {4096, "4 KB"},
        {81920, "80 KB"}, {1468006, "1.4 MB"}, {1048576, "1.0 MB"}, {22020096, "21.0 MB"}, {2147483648ull, "2.0 GB"},
    };
    for (const auto& c : kSizeCases)
    {
        char got[16];
        const u32 n = AppFormatSize(c.bytes, got, sizeof(got));
        u32 i = 0;
        for (; c.want[i] != '\0' && got[i] != '\0'; ++i)
        {
            if (c.want[i] != got[i])
            {
                break;
            }
        }
        if (c.want[i] != '\0' || got[i] != '\0' || n != i)
        {
            mark_fail(0xE0, "[app-text-selftest] FAIL AppFormatSize disagreed with the reference shape");
            return;
        }
    }

    // (8) The icon cell always leaves a gap between the tile and the
    //     name that follows it — a name budget computed as
    //     `cell - tile` must stay positive or the two collide.
    if (AppRowIconWidth() <= kIconTile)
    {
        mark_fail(0xE1, "[app-text-selftest] FAIL icon cell left no gap for the name");
        return;
    }

    SerialWrite("[app-text-selftest] PASS\n");
    s_passed = true;
}

bool AppTextSelfTestPassed()
{
    return s_passed;
}

} // namespace duetos::drivers::video::app_widgets
