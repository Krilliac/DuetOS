#include "drivers/video/ttf.h"

#include "arch/x86_64/serial.h"

namespace duetos::drivers::video
{

namespace
{

using ::duetos::core::Err;
using ::duetos::core::ErrorCode;
using ::duetos::core::Result;

// TrueType / OpenType is big-endian on disk. Every multi-byte field
// in the file format reads MSB-first regardless of host byte order;
// these helpers enforce that and bound-check against the buffer
// length so a malformed font can't walk us off the end.

inline u16 ReadU16(const u8* p)
{
    return static_cast<u16>((u16{p[0]} << 8) | u16{p[1]});
}
inline i16 ReadI16(const u8* p)
{
    return static_cast<i16>(ReadU16(p));
}
inline u32 ReadU32(const u8* p)
{
    return (u32{p[0]} << 24) | (u32{p[1]} << 16) | (u32{p[2]} << 8) | u32{p[3]};
}

// Bounded reads — return false (or default) when the requested span
// is outside `[0, size)`. Used during the table-directory walk where
// a malformed offset/length must not be dereferenced.
inline bool BoundsOk(u32 offset, u32 length, u32 size)
{
    if (offset > size)
        return false;
    if (length > size - offset)
        return false;
    return true;
}

// Pack a 4-character ASCII tag into a u32 the way the TrueType
// directory stores it (big-endian: 'h','e','a','d' -> 0x68656164).
constexpr u32 MakeTag(char a, char b, char c, char d)
{
    return (u32{static_cast<u8>(a)} << 24) | (u32{static_cast<u8>(b)} << 16) | (u32{static_cast<u8>(c)} << 8) |
           u32{static_cast<u8>(d)};
}

constexpr u32 kTagHead = MakeTag('h', 'e', 'a', 'd');
constexpr u32 kTagMaxp = MakeTag('m', 'a', 'x', 'p');
constexpr u32 kTagHhea = MakeTag('h', 'h', 'e', 'a');
constexpr u32 kTagHmtx = MakeTag('h', 'm', 't', 'x');
constexpr u32 kTagCmap = MakeTag('c', 'm', 'a', 'p');
constexpr u32 kTagLoca = MakeTag('l', 'o', 'c', 'a');
constexpr u32 kTagGlyf = MakeTag('g', 'l', 'y', 'f');

constexpr u32 kSfntTrueType = 0x00010000u;                    // TrueType outlines
constexpr u32 kSfntTrueTypeAlt = MakeTag('t', 'r', 'u', 'e'); // Apple variant
constexpr u32 kSfntOpenType = MakeTag('O', 'T', 'T', 'O');    // CFF outlines (we reject)

// `glyf` simple-glyph flag bits (per TrueType spec).
constexpr u8 kGlyfFlagOnCurve = 0x01;
constexpr u8 kGlyfFlagXShort = 0x02;
constexpr u8 kGlyfFlagYShort = 0x04;
constexpr u8 kGlyfFlagRepeat = 0x08;
constexpr u8 kGlyfFlagXSamePos = 0x10; // when XShort: positive sign; when !XShort: same as previous
constexpr u8 kGlyfFlagYSamePos = 0x20;

// Find the format-4 subtable inside the font's `cmap` table. Returns
// (offset, length) into the file buffer on success. Walks the encoding
// records preferring (platformID=3 Microsoft, encodingID=1 Unicode-BMP)
// then (platformID=0 Unicode, any encodingID) as a fallback. Returns
// false if no format-4 subtable is reachable.
bool FindCmapFormat4(const u8* bytes, u32 size, u32 cmap_off, u32& fmt4_off, u32& fmt4_size)
{
    // cmap header: u16 version, u16 num_tables. Each encoding record
    // is u16 platformID, u16 encodingID, u32 offset (into cmap table).
    if (!BoundsOk(cmap_off, 4, size))
        return false;
    const u16 num_tables = ReadU16(bytes + cmap_off + 2);
    if (num_tables == 0)
        return false;
    if (!BoundsOk(cmap_off + 4, static_cast<u32>(num_tables) * 8u, size))
        return false;

    u32 best_subtable_off = 0;
    int best_priority = -1; // higher wins
    for (u16 i = 0; i < num_tables; ++i)
    {
        const u8* rec = bytes + cmap_off + 4 + static_cast<u32>(i) * 8u;
        const u16 platform = ReadU16(rec);
        const u16 encoding = ReadU16(rec + 2);
        const u32 sub_off = cmap_off + ReadU32(rec + 4);
        if (sub_off + 6 > size) // need at least format + length + lang
            continue;
        const u16 fmt = ReadU16(bytes + sub_off);
        if (fmt != 4)
            continue;
        int prio = -1;
        if (platform == 3 && encoding == 1)
            prio = 2; // Microsoft Unicode BMP — best
        else if (platform == 0)
            prio = 1; // Unicode (any encoding) — fallback
        if (prio > best_priority)
        {
            best_priority = prio;
            best_subtable_off = sub_off;
        }
    }
    if (best_priority < 0)
        return false;

    // Format-4 subtable: u16 format, u16 length, u16 language, ...
    const u16 length = ReadU16(bytes + best_subtable_off + 2);
    if (length < 14) // smallest viable format-4 has 14-byte fixed header
        return false;
    if (!BoundsOk(best_subtable_off, length, size))
        return false;
    fmt4_off = best_subtable_off;
    fmt4_size = length;
    return true;
}

} // namespace

Result<TtfFont> TtfLoad(const u8* bytes, u32 size)
{
    if (bytes == nullptr || size < 12)
        return Err{ErrorCode::InvalidArgument};

    // sfnt header: u32 version, u16 num_tables, u16 search_range,
    // u16 entry_selector, u16 range_shift. We only validate version
    // + num_tables.
    const u32 sfnt_version = ReadU32(bytes);
    if (sfnt_version == kSfntOpenType)
        return Err{ErrorCode::Unsupported}; // CFF outlines, not glyf
    if (sfnt_version != kSfntTrueType && sfnt_version != kSfntTrueTypeAlt)
        return Err{ErrorCode::InvalidArgument};

    const u16 num_tables = ReadU16(bytes + 4);
    if (num_tables == 0 || num_tables > 64) // 64 = generous sanity cap
        return Err{ErrorCode::InvalidArgument};

    const u32 dir_size = static_cast<u32>(num_tables) * 16u; // 16 bytes per entry
    if (!BoundsOk(12u, dir_size, size))
        return Err{ErrorCode::InvalidArgument};

    TtfFont f{};
    f.bytes = bytes;
    f.size = size;

    // Walk the table directory. Each entry is: u32 tag, u32 checksum,
    // u32 offset, u32 length. We don't validate the checksum (it's
    // optional even per spec) but we DO validate that every offset+
    // length stays inside `size`.
    for (u16 i = 0; i < num_tables; ++i)
    {
        const u8* entry = bytes + 12 + static_cast<u32>(i) * 16u;
        const u32 tag = ReadU32(entry);
        const u32 off = ReadU32(entry + 8);
        const u32 len = ReadU32(entry + 12);
        if (!BoundsOk(off, len, size))
            return Err{ErrorCode::InvalidArgument};

        switch (tag)
        {
        case kTagHead:
            if (len < 54)
                return Err{ErrorCode::InvalidArgument};
            f.head_offset = off;
            break;
        case kTagMaxp:
            if (len < 6)
                return Err{ErrorCode::InvalidArgument};
            f.maxp_offset = off;
            break;
        case kTagHhea:
            if (len < 36)
                return Err{ErrorCode::InvalidArgument};
            f.hhea_offset = off;
            break;
        case kTagHmtx:
            f.hmtx_offset = off;
            break;
        case kTagCmap:
            if (len < 4)
                return Err{ErrorCode::InvalidArgument};
            f.cmap_offset = off;
            break;
        case kTagLoca:
            f.loca_offset = off;
            break;
        case kTagGlyf:
            f.glyf_offset = off;
            break;
        default:
            break; // ignore other tables (name, post, OS/2, etc.)
        }
    }

    if (f.head_offset == 0 || f.maxp_offset == 0 || f.hhea_offset == 0 || f.hmtx_offset == 0 || f.cmap_offset == 0 ||
        f.loca_offset == 0 || f.glyf_offset == 0)
        return Err{ErrorCode::InvalidArgument};

    // head: units_per_em at offset 18, index_to_loc_format at 50.
    f.units_per_em = ReadU16(bytes + f.head_offset + 18);
    f.index_to_loc_format = ReadU16(bytes + f.head_offset + 50);
    if (f.units_per_em == 0 || f.index_to_loc_format > 1)
        return Err{ErrorCode::InvalidArgument};

    // maxp: num_glyphs at offset 4 (after the u32 version).
    f.num_glyphs = ReadU16(bytes + f.maxp_offset + 4);
    if (f.num_glyphs == 0)
        return Err{ErrorCode::InvalidArgument};

    // hhea: number_of_hMetrics is the LAST u16, at offset 34.
    f.num_hmetrics = ReadU16(bytes + f.hhea_offset + 34);
    if (f.num_hmetrics == 0 || f.num_hmetrics > f.num_glyphs)
        return Err{ErrorCode::InvalidArgument};

    if (!FindCmapFormat4(bytes, size, f.cmap_offset, f.cmap_fmt4_off, f.cmap_fmt4_size))
        return Err{ErrorCode::Unsupported};

    return f;
}

u16 TtfGlyphIndex(const TtfFont& font, u32 codepoint)
{
    // cmap format-4 layout (after the format/length/language u16s):
    //   u16 seg_count_x2
    //   u16 search_range / entry_selector / range_shift  (3 x u16)
    //   u16 end_code[seg_count]
    //   u16 reserved_pad (always 0)
    //   u16 start_code[seg_count]
    //   i16 id_delta[seg_count]
    //   u16 id_range_offset[seg_count]
    //   u16 glyph_id_array[remaining]
    //
    // Our search is a linear scan over end_code looking for the first
    // segment whose end_code >= codepoint. The spec defines a binary
    // search via the search_range/etc. fields, but linear is fine for
    // the chrome paint path's small codepoint set and avoids a class
    // of bugs around malformed search_range.
    if (codepoint > 0xFFFFu)
        return 0;

    const u8* cmap = font.bytes + font.cmap_fmt4_off;
    const u32 sub_size = font.cmap_fmt4_size;
    if (sub_size < 14)
        return 0;
    const u16 seg_count = ReadU16(cmap + 6) >> 1; // / 2
    if (seg_count == 0)
        return 0;

    const u32 end_off = 14u;
    const u32 start_off = end_off + 2u + 2u * seg_count; // skip end[] + pad
    const u32 delta_off = start_off + 2u * seg_count;
    const u32 ro_off = delta_off + 2u * seg_count;
    const u32 gid_off = ro_off + 2u * seg_count;
    if (gid_off > sub_size)
        return 0;

    const u16 cp16 = static_cast<u16>(codepoint);
    for (u16 seg = 0; seg < seg_count; ++seg)
    {
        const u16 end_code = ReadU16(cmap + end_off + 2u * seg);
        if (end_code < cp16)
            continue;
        const u16 start_code = ReadU16(cmap + start_off + 2u * seg);
        if (start_code > cp16)
            return 0; // gap — not in any segment
        const i16 id_delta = ReadI16(cmap + delta_off + 2u * seg);
        const u16 id_range_offset = ReadU16(cmap + ro_off + 2u * seg);
        if (id_range_offset == 0)
        {
            // Direct mapping: glyph_index = (codepoint + id_delta) mod 65536
            return static_cast<u16>(static_cast<u16>(cp16 + static_cast<u16>(id_delta)));
        }
        // Indirected via glyph_id_array. Per-spec offset arithmetic
        // is RELATIVE to the address of the id_range_offset field
        // itself, which is what the obfuscated formula encodes.
        const u32 ro_field = ro_off + 2u * seg;
        const u32 gid_index_bytes = ro_field + id_range_offset + 2u * static_cast<u32>(cp16 - start_code);
        if (gid_index_bytes + 2u > sub_size)
            return 0;
        const u16 gid_raw = ReadU16(cmap + gid_index_bytes);
        if (gid_raw == 0)
            return 0; // explicit notdef
        return static_cast<u16>(gid_raw + static_cast<u16>(id_delta));
    }
    return 0;
}

Result<TtfHMetric> TtfGetHMetric(const TtfFont& font, u16 glyph_index)
{
    if (glyph_index >= font.num_glyphs)
        return Err{ErrorCode::InvalidArgument};
    const u8* hmtx = font.bytes + font.hmtx_offset;
    TtfHMetric m{};
    if (glyph_index < font.num_hmetrics)
    {
        const u32 off = static_cast<u32>(glyph_index) * 4u;
        if (font.hmtx_offset + off + 4u > font.size)
            return Err{ErrorCode::Corrupt};
        m.advance_width = ReadU16(hmtx + off);
        m.lsb = ReadI16(hmtx + off + 2u);
    }
    else
    {
        // Glyph past num_hmetrics: advance comes from the last full
        // hmtx entry; lsb is in the trailing i16[] section.
        const u32 last_full = static_cast<u32>(font.num_hmetrics - 1) * 4u;
        if (font.hmtx_offset + last_full + 2u > font.size)
            return Err{ErrorCode::Corrupt};
        m.advance_width = ReadU16(hmtx + last_full);
        const u32 tail_off =
            static_cast<u32>(font.num_hmetrics) * 4u + static_cast<u32>(glyph_index - font.num_hmetrics) * 2u;
        if (font.hmtx_offset + tail_off + 2u > font.size)
            return Err{ErrorCode::Corrupt};
        m.lsb = ReadI16(hmtx + tail_off);
    }
    return m;
}

namespace
{

// Look up `glyph_index`'s offset + byte length inside the `glyf`
// table via `loca`. `loca` has `num_glyphs + 1` entries; entry N is
// glyph N's start, entry N+1 - entry N is glyph N's length. Short
// loca format halves the offsets (multiply by 2 on read).
bool LocaLookup(const TtfFont& font, u16 glyph_index, u32& glyph_off, u32& glyph_len)
{
    if (glyph_index >= font.num_glyphs)
        return false;

    u32 lo = 0;
    u32 hi = 0;
    if (font.index_to_loc_format == 0)
    {
        // Short: u16[num_glyphs+1], stored offsets are /2
        const u32 off = font.loca_offset + static_cast<u32>(glyph_index) * 2u;
        if (off + 4u > font.size)
            return false;
        lo = static_cast<u32>(ReadU16(font.bytes + off)) * 2u;
        hi = static_cast<u32>(ReadU16(font.bytes + off + 2u)) * 2u;
    }
    else
    {
        const u32 off = font.loca_offset + static_cast<u32>(glyph_index) * 4u;
        if (off + 8u > font.size)
            return false;
        lo = ReadU32(font.bytes + off);
        hi = ReadU32(font.bytes + off + 4u);
    }
    if (hi < lo)
        return false;
    glyph_off = font.glyf_offset + lo;
    glyph_len = hi - lo;
    if (!BoundsOk(glyph_off, glyph_len, font.size))
        return false;
    return true;
}

} // namespace

Result<TtfGlyph> TtfDecodeGlyph(const TtfFont& font, u16 glyph_index, TtfPoint* points_scratch, u32 max_points,
                                u16* endpoints_scratch, u16 max_contours)
{
    if (points_scratch == nullptr || endpoints_scratch == nullptr)
        return Err{ErrorCode::InvalidArgument};
    if (glyph_index >= font.num_glyphs)
        return Err{ErrorCode::InvalidArgument};

    u32 g_off = 0;
    u32 g_len = 0;
    if (!LocaLookup(font, glyph_index, g_off, g_len))
        return Err{ErrorCode::Corrupt};

    TtfGlyph out{};
    out.endpoints = endpoints_scratch;
    out.points = points_scratch;

    if (g_len == 0)
    {
        // Empty glyph (e.g. space). Valid; returns 0 contours.
        return out;
    }
    if (g_len < 10) // glyph header is 10 bytes
        return Err{ErrorCode::Corrupt};

    const u8* g = font.bytes + g_off;
    const i16 num_contours = ReadI16(g);
    out.x_min = ReadI16(g + 2);
    out.y_min = ReadI16(g + 4);
    out.x_max = ReadI16(g + 6);
    out.y_max = ReadI16(g + 8);

    if (num_contours < 0)
        return Err{ErrorCode::Unsupported}; // composite glyph
    if (num_contours == 0)
        return out;
    if (static_cast<u16>(num_contours) > max_contours)
        return Err{ErrorCode::OutOfMemory};

    // Simple glyph: u16 endpoints[num_contours], u16 inst_len, u8 inst[],
    //               u8 flags[], xCoords, yCoords (variable per-flag).
    u32 cur = 10u;
    if (cur + static_cast<u32>(num_contours) * 2u + 2u > g_len)
        return Err{ErrorCode::Corrupt};

    u16 last_endpoint = 0;
    for (i16 i = 0; i < num_contours; ++i)
    {
        const u16 ep = ReadU16(g + cur);
        cur += 2u;
        endpoints_scratch[i] = ep;
        last_endpoint = ep;
    }
    out.contour_count = static_cast<u16>(num_contours);

    const u32 total_pts = static_cast<u32>(last_endpoint) + 1u;
    if (total_pts > max_points)
        return Err{ErrorCode::OutOfMemory};

    // Skip instructions.
    const u16 inst_len = ReadU16(g + cur);
    cur += 2u;
    if (cur + inst_len > g_len)
        return Err{ErrorCode::Corrupt};
    cur += inst_len;

    // Decode flags. Each flag covers one point; the Repeat bit means
    // "the next byte tells you how many MORE points share this flag".
    u8 flags_buf[256]; // bounded; max_points caller is responsible for capping below this
    if (total_pts > sizeof(flags_buf))
        return Err{ErrorCode::OutOfMemory};
    u32 fi = 0;
    while (fi < total_pts)
    {
        if (cur >= g_len)
            return Err{ErrorCode::Corrupt};
        const u8 flag = g[cur++];
        flags_buf[fi++] = flag;
        if (flag & kGlyfFlagRepeat)
        {
            if (cur >= g_len)
                return Err{ErrorCode::Corrupt};
            u8 reps = g[cur++];
            while (reps-- > 0 && fi < total_pts)
                flags_buf[fi++] = flag;
        }
    }
    if (fi != total_pts)
        return Err{ErrorCode::Corrupt};

    // Decode X coordinates (delta-encoded). Then Y similarly.
    i16 x_acc = 0;
    for (u32 p = 0; p < total_pts; ++p)
    {
        const u8 flag = flags_buf[p];
        i16 dx = 0;
        if (flag & kGlyfFlagXShort)
        {
            if (cur >= g_len)
                return Err{ErrorCode::Corrupt};
            const i16 mag = static_cast<i16>(g[cur++]);
            dx = (flag & kGlyfFlagXSamePos) ? mag : static_cast<i16>(-mag);
        }
        else if (!(flag & kGlyfFlagXSamePos))
        {
            if (cur + 2u > g_len)
                return Err{ErrorCode::Corrupt};
            dx = ReadI16(g + cur);
            cur += 2u;
        }
        x_acc = static_cast<i16>(x_acc + dx);
        points_scratch[p].x = x_acc;
        points_scratch[p].on_curve = (flag & kGlyfFlagOnCurve) != 0;
    }
    i16 y_acc = 0;
    for (u32 p = 0; p < total_pts; ++p)
    {
        const u8 flag = flags_buf[p];
        i16 dy = 0;
        if (flag & kGlyfFlagYShort)
        {
            if (cur >= g_len)
                return Err{ErrorCode::Corrupt};
            const i16 mag = static_cast<i16>(g[cur++]);
            dy = (flag & kGlyfFlagYSamePos) ? mag : static_cast<i16>(-mag);
        }
        else if (!(flag & kGlyfFlagYSamePos))
        {
            if (cur + 2u > g_len)
                return Err{ErrorCode::Corrupt};
            dy = ReadI16(g + cur);
            cur += 2u;
        }
        y_acc = static_cast<i16>(y_acc + dy);
        points_scratch[p].y = y_acc;
    }
    out.total_points = static_cast<u16>(total_pts);
    return out;
}

bool TtfSelfTest()
{
    using arch::SerialWrite;
    // 1. Null + too-small inputs reject cleanly.
    {
        auto r = TtfLoad(nullptr, 1024);
        if (r.has_value() || r.error() != ErrorCode::InvalidArgument)
        {
            SerialWrite("[video/ttf] selftest FAIL: null buffer accepted\n");
            return false;
        }
    }
    {
        u8 tiny[8] = {0, 1, 0, 0, 0, 1, 0, 0};
        auto r = TtfLoad(tiny, sizeof(tiny));
        if (r.has_value() || r.error() != ErrorCode::InvalidArgument)
        {
            SerialWrite("[video/ttf] selftest FAIL: undersized buffer accepted\n");
            return false;
        }
    }
    // 2. Wrong sfnt version (CFF outlines / OTTO) rejects with Unsupported.
    {
        u8 otto[16] = {'O', 'T', 'T', 'O', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
        auto r = TtfLoad(otto, sizeof(otto));
        if (r.has_value() || r.error() != ErrorCode::Unsupported)
        {
            SerialWrite("[video/ttf] selftest FAIL: OTTO buffer not flagged Unsupported\n");
            return false;
        }
    }
    // 3. Junk bytes reject.
    {
        u8 junk[16] = {'J', 'U', 'N', 'K', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
        auto r = TtfLoad(junk, sizeof(junk));
        if (r.has_value() || r.error() != ErrorCode::InvalidArgument)
        {
            SerialWrite("[video/ttf] selftest FAIL: junk sfnt version accepted\n");
            return false;
        }
    }
    SerialWrite("[video/ttf] selftest ok (parser bounds-check + sfnt sniff)\n");
    return true;
}

} // namespace duetos::drivers::video
