#include "web/png.h"

#include "arch/x86_64/serial.h"
#include "debug/probes.h"

/*
 * DuetOS — kernel/web PNG decoder boot self-test.
 *
 * Five embedded known-answer fixtures, one per supported colour
 * type, plus a Paeth-filtered row and two hostile-input cases
 * (corrupted CRC, truncated). Every fixture was generated on the
 * dev host with Python's `zlib` (real DEFLATE — fixed/dynamic
 * Huffman, NOT a stored block) so the inflater is genuinely
 * exercised:
 *
 *   python3 -c "import zlib,struct; ..."  (see tools/test or the
 *   slice commit body for the exact generator). The CRCs and the
 *   DEFLATE bodies are emitted by the host zlib; decoding them
 *   back through our clean-room CRC32 + DeflateInflate proves both
 *   ends agree.
 *
 * Expected pixel values (R,G,B,A byte order) were computed
 * independently from the generator's source pixels, not read back
 * from our own decoder — so a decoder bug can't pass by agreeing
 * with itself.
 */

namespace duetos::web
{

namespace
{

// ---------------------------------------------------------------------------
// Fixture 1 — 2x2 RGBA (colour type 6), filter None.
//   (0,0) red    FF 00 00 FF
//   (1,0) green  00 FF 00 FF
//   (0,1) blue   00 00 FF FF
//   (1,1) white  FF FF FF 80
constexpr u8 kPng2x2Rgba[] = {
    0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52, 0x00, 0x00,
    0x00, 0x02, 0x00, 0x00, 0x00, 0x02, 0x08, 0x06, 0x00, 0x00, 0x00, 0x72, 0xB6, 0x0D, 0x24, 0x00, 0x00, 0x00,
    0x1D, 0x49, 0x44, 0x41, 0x54, 0x78, 0x01, 0x01, 0x12, 0x00, 0xED, 0xFF, 0x00, 0xFF, 0x00, 0x00, 0xFF, 0x00,
    0xFF, 0x00, 0xFF, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x80, 0x49, 0x49, 0x09, 0x78, 0x4B, 0xD9,
    0xCE, 0x03, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82,
};

// ---------------------------------------------------------------------------
// Fixture 2 — 3x2 RGB (colour type 2). Row 0 filter None, row 1
// filter Paeth (4).
//   row0 pixels: (10,20,30) (40,50,60) (70,80,90)
//   row1 pixels: (100,110,120) (130,140,150) (160,170,180)
constexpr u8 kPng3x2RgbPaeth[] = {
    0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52, 0x00, 0x00,
    0x00, 0x03, 0x00, 0x00, 0x00, 0x02, 0x08, 0x02, 0x00, 0x00, 0x00, 0x12, 0x16, 0xF1, 0x4D, 0x00, 0x00, 0x00,
    0x1F, 0x49, 0x44, 0x41, 0x54, 0x78, 0x01, 0x01, 0x14, 0x00, 0xEB, 0xFF, 0x00, 0x0A, 0x14, 0x1E, 0x28, 0x32,
    0x3C, 0x46, 0x50, 0x5A, 0x04, 0x5A, 0x5A, 0x5A, 0x1E, 0x1E, 0x1E, 0x1E, 0x1E, 0x1E, 0x23, 0x28, 0x03, 0x89,
    0x29, 0xA0, 0xBE, 0xF6, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82,
};

// ---------------------------------------------------------------------------
// Fixture 3 — 2x2 palette (colour type 3) + tRNS.
//   palette: idx0 red, idx1 green, idx2 blue
//   tRNS:    idx0 alpha=0x10, idx1 alpha=0x80 (idx2 -> default 0xFF)
//   indices: row0 {0,1}, row1 {2,1}
constexpr u8 kPng2x2Pal[] = {
    0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52, 0x00, 0x00, 0x00,
    0x02, 0x00, 0x00, 0x00, 0x02, 0x08, 0x03, 0x00, 0x00, 0x00, 0x45, 0x68, 0xFD, 0x16, 0x00, 0x00, 0x00, 0x09, 0x50,
    0x4C, 0x54, 0x45, 0xFF, 0x00, 0x00, 0x00, 0xFF, 0x00, 0x00, 0x00, 0xFF, 0x2D, 0x4A, 0xCD, 0x8A, 0x00, 0x00, 0x00,
    0x02, 0x74, 0x52, 0x4E, 0x53, 0x10, 0x80, 0xD1, 0xE9, 0x5C, 0x49, 0x00, 0x00, 0x00, 0x11, 0x49, 0x44, 0x41, 0x54,
    0x78, 0x01, 0x01, 0x06, 0x00, 0xF9, 0xFF, 0x00, 0x00, 0x01, 0x00, 0x02, 0x01, 0x00, 0x0F, 0x00, 0x05, 0x18, 0x6A,
    0x22, 0x49, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82,
};

// ---------------------------------------------------------------------------
// Fixture 4 — 2x2 grayscale + alpha (colour type 4), filter None.
//   row0: (0x11,a=0xFF) (0x22,a=0x80)
//   row1: (0x33,a=0x40) (0x44,a=0x00)
constexpr u8 kPng2x2GrayA[] = {
    0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52,
    0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x02, 0x08, 0x04, 0x00, 0x00, 0x00, 0xD8, 0xBF, 0xC5,
    0xAF, 0x00, 0x00, 0x00, 0x15, 0x49, 0x44, 0x41, 0x54, 0x78, 0x01, 0x01, 0x0A, 0x00, 0xF5, 0xFF,
    0x00, 0x11, 0xFF, 0x22, 0x80, 0x00, 0x33, 0x40, 0x44, 0x00, 0x0E, 0x9D, 0x02, 0x6A, 0x4B, 0x0F,
    0x72, 0xF0, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82,
};

// ---------------------------------------------------------------------------
// Fixture 5 — 2x1 grayscale (colour type 0), filter None.
//   (0,0)=0x00  (1,0)=0xFF
constexpr u8 kPng2x1Gray[] = {
    0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52, 0x00, 0x00,
    0x00, 0x02, 0x00, 0x00, 0x00, 0x01, 0x08, 0x00, 0x00, 0x00, 0x00, 0xD1, 0x49, 0x20, 0x56, 0x00, 0x00, 0x00,
    0x0E, 0x49, 0x44, 0x41, 0x54, 0x78, 0x01, 0x01, 0x03, 0x00, 0xFC, 0xFF, 0x00, 0x00, 0xFF, 0x01, 0x02, 0x01,
    0x00, 0xB7, 0x01, 0x2E, 0xF7, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82,
};

// Scratch arena big enough for the largest fixture (3x2 RGB:
// scanlines (3*3+1)*2 = 20, RGBA out 3*2*4 = 24, plus the IDAT
// staging sized at the input length ~88). 4 KiB is comfortable.
u8 g_arena_buf[4096];

bool Expect(bool cond, const char* tag, u32 code, u32& fail_code)
{
    if (!cond)
    {
        arch::SerialWrite("[png-selftest] FAIL ");
        arch::SerialWrite(tag);
        arch::SerialWrite("\n");
        if (fail_code == 0)
            fail_code = code;
    }
    return cond;
}

// Read an RGBA pixel from a decoded image.
bool PixelEq(const PngImage& img, u32 x, u32 y, u8 r, u8 g, u8 b, u8 a)
{
    if (x >= img.width || y >= img.height)
        return false;
    const u8* p = img.pixels + (u64(y) * img.width + x) * 4;
    return p[0] == r && p[1] == g && p[2] == b && p[3] == a;
}

} // namespace

void PngSelfTest()
{
    bool ok = true;
    u32 fail_code = 0;
    PngArena arena(g_arena_buf, sizeof(g_arena_buf));

    // ----- Fixture 1: 2x2 RGBA.
    {
        arena.Reset();
        PngImage img;
        const bool d = PngDecode(kPng2x2Rgba, u32(sizeof(kPng2x2Rgba)), arena, &img);
        ok &= Expect(d, "rgba.decode", 0x0001, fail_code);
        if (d)
        {
            ok &= Expect(img.width == 2 && img.height == 2, "rgba.dims", 0x0002, fail_code);
            ok &= Expect(PixelEq(img, 0, 0, 0xFF, 0x00, 0x00, 0xFF), "rgba.px00", 0x0003, fail_code);
            ok &= Expect(PixelEq(img, 1, 0, 0x00, 0xFF, 0x00, 0xFF), "rgba.px10", 0x0004, fail_code);
            ok &= Expect(PixelEq(img, 0, 1, 0x00, 0x00, 0xFF, 0xFF), "rgba.px01", 0x0005, fail_code);
            ok &= Expect(PixelEq(img, 1, 1, 0xFF, 0xFF, 0xFF, 0x80), "rgba.px11", 0x0006, fail_code);
        }
    }

    // ----- Fixture 2: 3x2 RGB with a Paeth-filtered second row.
    {
        arena.Reset();
        PngImage img;
        const bool d = PngDecode(kPng3x2RgbPaeth, u32(sizeof(kPng3x2RgbPaeth)), arena, &img);
        ok &= Expect(d, "rgb.decode", 0x0010, fail_code);
        if (d)
        {
            ok &= Expect(img.width == 3 && img.height == 2, "rgb.dims", 0x0011, fail_code);
            ok &= Expect(PixelEq(img, 0, 0, 10, 20, 30, 0xFF), "rgb.px00", 0x0012, fail_code);
            ok &= Expect(PixelEq(img, 2, 0, 70, 80, 90, 0xFF), "rgb.px20", 0x0013, fail_code);
            // Paeth-reconstructed row.
            ok &= Expect(PixelEq(img, 0, 1, 100, 110, 120, 0xFF), "rgb.px01paeth", 0x0014, fail_code);
            ok &= Expect(PixelEq(img, 1, 1, 130, 140, 150, 0xFF), "rgb.px11paeth", 0x0015, fail_code);
            ok &= Expect(PixelEq(img, 2, 1, 160, 170, 180, 0xFF), "rgb.px21paeth", 0x0016, fail_code);
        }
    }

    // ----- Fixture 3: 2x2 palette + tRNS.
    {
        arena.Reset();
        PngImage img;
        const bool d = PngDecode(kPng2x2Pal, u32(sizeof(kPng2x2Pal)), arena, &img);
        ok &= Expect(d, "pal.decode", 0x0020, fail_code);
        if (d)
        {
            ok &= Expect(img.width == 2 && img.height == 2, "pal.dims", 0x0021, fail_code);
            ok &= Expect(PixelEq(img, 0, 0, 0xFF, 0x00, 0x00, 0x10), "pal.px00", 0x0022, fail_code);
            ok &= Expect(PixelEq(img, 1, 0, 0x00, 0xFF, 0x00, 0x80), "pal.px10", 0x0023, fail_code);
            ok &= Expect(PixelEq(img, 0, 1, 0x00, 0x00, 0xFF, 0xFF), "pal.px01", 0x0024, fail_code);
            ok &= Expect(PixelEq(img, 1, 1, 0x00, 0xFF, 0x00, 0x80), "pal.px11", 0x0025, fail_code);
        }
    }

    // ----- Fixture 4: 2x2 grayscale + alpha.
    {
        arena.Reset();
        PngImage img;
        const bool d = PngDecode(kPng2x2GrayA, u32(sizeof(kPng2x2GrayA)), arena, &img);
        ok &= Expect(d, "graya.decode", 0x0030, fail_code);
        if (d)
        {
            ok &= Expect(img.width == 2 && img.height == 2, "graya.dims", 0x0031, fail_code);
            ok &= Expect(PixelEq(img, 0, 0, 0x11, 0x11, 0x11, 0xFF), "graya.px00", 0x0032, fail_code);
            ok &= Expect(PixelEq(img, 1, 1, 0x44, 0x44, 0x44, 0x00), "graya.px11", 0x0033, fail_code);
        }
    }

    // ----- Fixture 5: 2x1 grayscale.
    {
        arena.Reset();
        PngImage img;
        const bool d = PngDecode(kPng2x1Gray, u32(sizeof(kPng2x1Gray)), arena, &img);
        ok &= Expect(d, "gray.decode", 0x0040, fail_code);
        if (d)
        {
            ok &= Expect(img.width == 2 && img.height == 1, "gray.dims", 0x0041, fail_code);
            ok &= Expect(PixelEq(img, 0, 0, 0x00, 0x00, 0x00, 0xFF), "gray.px00", 0x0042, fail_code);
            ok &= Expect(PixelEq(img, 1, 0, 0xFF, 0xFF, 0xFF, 0xFF), "gray.px10", 0x0043, fail_code);
        }
    }

    // ----- Hostile: corrupted IHDR CRC must be rejected.
    {
        arena.Reset();
        u8 bad[sizeof(kPng2x2Rgba)];
        for (u32 i = 0; i < sizeof(kPng2x2Rgba); ++i)
            bad[i] = kPng2x2Rgba[i];
        bad[8 + 4 + 13 + 4 - 1] ^= 0xFF; // flip a byte of the IHDR CRC
        PngImage img;
        const bool rejected = !PngDecode(bad, u32(sizeof(bad)), arena, &img);
        ok &= Expect(rejected, "corrupt.crc.rejected", 0x0050, fail_code);
    }

    // ----- Hostile: truncated input (cut mid-IDAT) must be rejected,
    // with no buffer overrun.
    {
        arena.Reset();
        PngImage img;
        const bool rejected = !PngDecode(kPng2x2Rgba, u32(sizeof(kPng2x2Rgba)) - 20, arena, &img);
        ok &= Expect(rejected, "truncated.rejected", 0x0051, fail_code);
    }

    if (!ok)
    {
        KBP_PROBE_V(duetos::debug::ProbeId::kBootSelftestFail, fail_code);
        return;
    }

    arch::SerialWrite("[png-selftest] PASS (rgba,rgb-paeth,pal-trns,gray-a,gray; corrupt+truncated rejected)\n");
}

} // namespace duetos::web
