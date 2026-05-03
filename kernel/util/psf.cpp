#include "util/psf.h"

#include "core/panic.h"

namespace duetos::util
{

namespace
{

inline u32 LoadU32Le(const u8* p)
{
    return u32(p[0]) | (u32(p[1]) << 8) | (u32(p[2]) << 16) | (u32(p[3]) << 24);
}

// PSF1 mode bits (per linux/include/uapi/linux/font.h, public).
constexpr u8 kPsf1Mode512 = 0x01;
constexpr u8 kPsf1ModeHasTab = 0x02;
constexpr u8 kPsf1ModeHasSeq = 0x04;

// PSF2 flags.
constexpr u32 kPsf2HasUnicodeTable = 0x01;

} // namespace

PsfInfo PsfParse(const u8* src, u32 src_len)
{
    PsfInfo info = {};
    if (src_len < 4)
        return info;

    if (src[0] == kPsf1Magic0 && src[1] == kPsf1Magic1)
    {
        // PSF1 header: magic(2) + mode(1) + height(1).
        const u8 mode = src[2];
        const u8 height = src[3];
        if (height == 0 || height > 32)
            return info;
        info.version = PsfVersion::Psf1;
        info.glyph_count = (mode & kPsf1Mode512) ? 512u : 256u;
        info.glyph_bytes = u32(height); // width 8 → 1 byte per row
        info.width_px = 8;
        info.height_px = u32(height);
        info.glyph_data_offset = 4;
        info.glyph_data_bytes = info.glyph_count * info.glyph_bytes;
        info.has_unicode = (mode & (kPsf1ModeHasTab | kPsf1ModeHasSeq)) != 0;
        if (u64(info.glyph_data_offset) + info.glyph_data_bytes > u64(src_len))
            return info;
        if (info.has_unicode)
        {
            info.unicode_offset = info.glyph_data_offset + info.glyph_data_bytes;
            info.unicode_bytes = src_len - info.unicode_offset;
        }
        info.ok = true;
        return info;
    }

    if (src_len < 32)
        return info;
    if (src[0] == kPsf2Magic0 && src[1] == kPsf2Magic1 && src[2] == kPsf2Magic2 && src[3] == kPsf2Magic3)
    {
        // PSF2 header: 8 × u32 LE.
        const u32 version = LoadU32Le(src + 4);
        const u32 header_size = LoadU32Le(src + 8);
        const u32 flags = LoadU32Le(src + 12);
        const u32 length = LoadU32Le(src + 16);
        const u32 charsize = LoadU32Le(src + 20);
        const u32 height = LoadU32Le(src + 24);
        const u32 width = LoadU32Le(src + 28);
        (void)version;
        if (header_size < 32 || header_size > src_len)
            return info;
        if (length == 0 || length > 0x100000)
            return info;
        if (charsize == 0 || charsize > 1024)
            return info;
        if (height == 0 || height > 256 || width == 0 || width > 256)
            return info;
        // Sanity: charsize must equal ceil(width/8) × height.
        const u32 expected_cs = ((width + 7u) / 8u) * height;
        if (charsize != expected_cs)
            return info;

        info.version = PsfVersion::Psf2;
        info.glyph_count = length;
        info.glyph_bytes = charsize;
        info.width_px = width;
        info.height_px = height;
        info.glyph_data_offset = header_size;
        info.glyph_data_bytes = length * charsize;
        info.has_unicode = (flags & kPsf2HasUnicodeTable) != 0;
        if (u64(info.glyph_data_offset) + info.glyph_data_bytes > u64(src_len))
            return info;
        if (info.has_unicode)
        {
            info.unicode_offset = info.glyph_data_offset + info.glyph_data_bytes;
            info.unicode_bytes = (info.unicode_offset < src_len) ? (src_len - info.unicode_offset) : 0;
        }
        info.ok = true;
        return info;
    }

    return info;
}

const u8* PsfGlyph(const u8* src, const PsfInfo& info, u32 index)
{
    if (!info.ok || index >= info.glyph_count)
        return nullptr;
    return src + info.glyph_data_offset + index * info.glyph_bytes;
}

void PsfSelfTest()
{
    // ----- Build a minimal PSF1: 256 glyphs × 8 px tall.
    {
        u8 buf[4 + 256 * 8] = {};
        buf[0] = kPsf1Magic0;
        buf[1] = kPsf1Magic1;
        buf[2] = 0x00; // mode: 256 glyphs, no unicode
        buf[3] = 0x08; // height = 8
        // Glyph 'A' (index 65) — make row 0 = 0x18 so the parser
        // sees a non-zero byte; actual font shape doesn't matter.
        buf[4 + 65 * 8 + 0] = 0x18;
        const PsfInfo info = PsfParse(buf, sizeof(buf));
        KASSERT(info.ok, "util/psf", "PSF1 parse failed");
        KASSERT(info.version == PsfVersion::Psf1, "util/psf", "PSF1 version wrong");
        KASSERT(info.glyph_count == 256, "util/psf", "PSF1 glyph count wrong");
        KASSERT(info.glyph_bytes == 8 && info.width_px == 8 && info.height_px == 8, "util/psf", "PSF1 dims wrong");
        KASSERT(info.glyph_data_offset == 4, "util/psf", "PSF1 data offset wrong");
        KASSERT(!info.has_unicode, "util/psf", "PSF1 has_unicode wrong");

        const u8* g = PsfGlyph(buf, info, 65);
        KASSERT(g != nullptr && g[0] == 0x18, "util/psf", "PSF1 glyph fetch wrong");
        KASSERT(PsfGlyph(buf, info, 256) == nullptr, "util/psf", "out-of-range glyph index not rejected");
    }

    // ----- PSF1 with 512 glyphs + unicode table.
    {
        constexpr u32 glyph_data = 512 * 16;
        u8 buf[4 + glyph_data + 4] = {};
        buf[0] = kPsf1Magic0;
        buf[1] = kPsf1Magic1;
        buf[2] = kPsf1Mode512 | kPsf1ModeHasTab;
        buf[3] = 0x10; // height 16
        const PsfInfo info = PsfParse(buf, sizeof(buf));
        KASSERT(info.ok, "util/psf", "PSF1-512 parse failed");
        KASSERT(info.glyph_count == 512, "util/psf", "PSF1-512 count wrong");
        KASSERT(info.has_unicode, "util/psf", "PSF1-512 has_unicode wrong");
        KASSERT(info.unicode_offset == 4 + glyph_data, "util/psf", "unicode offset wrong");
        KASSERT(info.unicode_bytes == 4, "util/psf", "unicode bytes wrong");
    }

    // ----- PSF2: 100 glyphs at 8×16 px (so charsize = 16, no Unicode).
    {
        constexpr u32 glyph_count = 100;
        constexpr u32 charsize = 16;
        u8 buf[32 + glyph_count * charsize] = {};
        buf[0] = kPsf2Magic0;
        buf[1] = kPsf2Magic1;
        buf[2] = kPsf2Magic2;
        buf[3] = kPsf2Magic3;
        // version=0, header_size=32, flags=0, length=100, charsize=16, height=16, width=8.
        const u32 header_size = 32;
        for (u32 i = 0; i < 4; ++i)
            buf[4 + i] = 0; // version
        buf[8] = u8(header_size);
        buf[12] = 0; // flags
        buf[16] = u8(glyph_count);
        buf[17] = u8(glyph_count >> 8);
        buf[20] = u8(charsize);
        buf[24] = 16; // height
        buf[28] = 8;  // width
        const PsfInfo info = PsfParse(buf, sizeof(buf));
        KASSERT(info.ok, "util/psf", "PSF2 parse failed");
        KASSERT(info.version == PsfVersion::Psf2, "util/psf", "PSF2 version tag wrong");
        KASSERT(info.glyph_count == 100, "util/psf", "PSF2 count wrong");
        KASSERT(info.width_px == 8 && info.height_px == 16, "util/psf", "PSF2 dims wrong");
    }

    // ----- Negative cases.
    {
        u8 buf[16] = {};
        // Bad magic.
        PsfInfo info = PsfParse(buf, sizeof(buf));
        KASSERT(!info.ok, "util/psf", "zero buffer not rejected");

        buf[0] = kPsf1Magic0;
        buf[1] = kPsf1Magic1;
        buf[2] = 0;
        buf[3] = 0; // height=0
        info = PsfParse(buf, sizeof(buf));
        KASSERT(!info.ok, "util/psf", "PSF1 height=0 not rejected");

        // PSF2 charsize-vs-(w,h) mismatch.
        u8 buf2[32 + 100 * 16] = {};
        buf2[0] = kPsf2Magic0;
        buf2[1] = kPsf2Magic1;
        buf2[2] = kPsf2Magic2;
        buf2[3] = kPsf2Magic3;
        buf2[8] = 32;
        buf2[16] = 100;
        buf2[20] = 17; // charsize = 17 — wrong for 8×16
        buf2[24] = 16;
        buf2[28] = 8;
        info = PsfParse(buf2, sizeof(buf2));
        KASSERT(!info.ok, "util/psf", "PSF2 charsize mismatch not rejected");
    }
}

} // namespace duetos::util
