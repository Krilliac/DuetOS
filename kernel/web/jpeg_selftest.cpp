#include "web/jpeg.h"

#include "arch/x86_64/serial.h"
#include "debug/probes.h"

/*
 * DuetOS — kernel/web baseline-JPEG decoder boot self-test.
 *
 * Three embedded baseline JPEG fixtures plus two hostile cases:
 *
 *   - kJpegColor420 — 16x16 RGB photo-like gradient, 4:2:0 chroma
 *     subsampling (the dominant web encoding).
 *   - kJpegGray     — 8x8 single-component grayscale.
 *   - kJpegColor422 — 16x8 RGB gradient, 4:2:2 chroma subsampling.
 *   - kJpegProgressive — an 8x8 SOF2 progressive frame, which the
 *     baseline decoder must REJECT cleanly (not crash).
 *   - a truncated copy of the colour fixture (cut mid-scan), which
 *     must be rejected with no buffer overrun.
 *
 * Provenance — generated on the dev host with Python Pillow 12
 * (which wraps libjpeg-turbo). The generator (kept in the slice's
 * commit body) was, in essence:
 *
 *   from PIL import Image
 *   img = Image.new('RGB',(16,16)); px=img.load()
 *   for y in range(16):
 *     for x in range(16):
 *       px[x,y]=((x*16)&255,(y*16)&255,((x+y)*8)&255)
 *   img.save('color.jpg','JPEG',quality=80,subsampling='4:2:0')
 *   # gray: Image.new('L',(8,8)) px=x*32+y*4, quality=85
 *   # c422: 16x8 RGB, subsampling='4:2:2', quality=80
 *   # prog: 8x8 solid, progressive=True   (rejection fixture)
 *
 * Reference pixel values below were read back by decoding the same
 * files through Pillow/libjpeg (the host reference decoder), NOT
 * from our own decoder — so a decoder bug cannot pass by agreeing
 * with itself. JPEG is lossy and our chroma upsampling is
 * nearest-neighbour (libjpeg uses "fancy" bilinear), so each
 * checked channel is asserted WITHIN +/- kTol of the reference
 * (kTol = 12; observed worst-case delta on a chroma-block edge was
 * 8, the rest are 0..1).
 */

namespace duetos::web
{

namespace
{

#include "web/jpeg_fixtures.inc"

// Lossy-decode channel tolerance vs the host libjpeg reference.
constexpr i32 kTol = 12;

u8 g_arena_buf[512 * 1024];

bool Expect(bool cond, const char* tag, u32 code, u32& fail_code)
{
    if (!cond)
    {
        arch::SerialWrite("[jpeg-selftest] FAIL ");
        arch::SerialWrite(tag);
        arch::SerialWrite("\n");
        if (fail_code == 0)
            fail_code = code;
    }
    return cond;
}

// True when the decoded pixel at (x,y) is within kTol of (r,g,b) on
// every channel and alpha is exactly 255.
bool PixelNear(const JpegImage& img, u32 x, u32 y, i32 r, i32 g, i32 b)
{
    if (x >= img.width || y >= img.height)
        return false;
    const u8* p = img.pixels + (static_cast<u64>(y) * img.width + x) * 4;
    const i32 dr = static_cast<i32>(p[0]) - r;
    const i32 dg = static_cast<i32>(p[1]) - g;
    const i32 db = static_cast<i32>(p[2]) - b;
    const i32 ar = dr < 0 ? -dr : dr;
    const i32 ag = dg < 0 ? -dg : dg;
    const i32 ab = db < 0 ? -db : db;
    return ar <= kTol && ag <= kTol && ab <= kTol && p[3] == 255;
}

} // namespace

void JpegSelfTest()
{
    bool ok = true;
    u32 fail_code = 0;
    PngArena arena(g_arena_buf, sizeof(g_arena_buf));

    // ----- Fixture 1: 16x16 RGB gradient, 4:2:0 chroma subsampling.
    {
        arena.Reset();
        JpegImage img;
        const bool d = JpegDecode(kJpegColor420, u32(sizeof(kJpegColor420)), arena, &img);
        ok &= Expect(d, "c420.decode", 0x0001, fail_code);
        if (d)
        {
            ok &= Expect(img.width == 16 && img.height == 16, "c420.dims", 0x0002, fail_code);
            ok &= Expect(PixelNear(img, 0, 0, 0, 0, 0), "c420.px00", 0x0003, fail_code);
            ok &= Expect(PixelNear(img, 15, 0, 222, 9, 115), "c420.px150", 0x0004, fail_code);
            ok &= Expect(PixelNear(img, 0, 15, 18, 231, 125), "c420.px015", 0x0005, fail_code);
            ok &= Expect(PixelNear(img, 15, 15, 241, 241, 241), "c420.px1515", 0x0006, fail_code);
            ok &= Expect(PixelNear(img, 8, 8, 128, 128, 128), "c420.px88", 0x0007, fail_code);
        }
    }

    // ----- Fixture 2: 8x8 single-component grayscale.
    {
        arena.Reset();
        JpegImage img;
        const bool d = JpegDecode(kJpegGray, u32(sizeof(kJpegGray)), arena, &img);
        ok &= Expect(d, "gray.decode", 0x0010, fail_code);
        if (d)
        {
            ok &= Expect(img.width == 8 && img.height == 8, "gray.dims", 0x0011, fail_code);
            ok &= Expect(PixelNear(img, 0, 0, 0, 0, 0), "gray.px00", 0x0012, fail_code);
            ok &= Expect(PixelNear(img, 7, 0, 225, 225, 225), "gray.px70", 0x0013, fail_code);
            ok &= Expect(PixelNear(img, 0, 7, 28, 28, 28), "gray.px07", 0x0014, fail_code);
            ok &= Expect(PixelNear(img, 7, 7, 252, 252, 252), "gray.px77", 0x0015, fail_code);
            ok &= Expect(PixelNear(img, 4, 4, 146, 146, 146), "gray.px44", 0x0016, fail_code);
        }
    }

    // ----- Fixture 3: 16x8 RGB gradient, 4:2:2 chroma subsampling.
    {
        arena.Reset();
        JpegImage img;
        const bool d = JpegDecode(kJpegColor422, u32(sizeof(kJpegColor422)), arena, &img);
        ok &= Expect(d, "c422.decode", 0x0020, fail_code);
        if (d)
        {
            ok &= Expect(img.width == 16 && img.height == 8, "c422.dims", 0x0021, fail_code);
            ok &= Expect(PixelNear(img, 0, 0, 8, 251, 0), "c422.px00", 0x0022, fail_code);
            ok &= Expect(PixelNear(img, 15, 0, 214, 38, 1), "c422.px150", 0x0023, fail_code);
            ok &= Expect(PixelNear(img, 0, 7, 12, 248, 208), "c422.px07", 0x0024, fail_code);
            ok &= Expect(PixelNear(img, 15, 7, 216, 35, 210), "c422.px157", 0x0025, fail_code);
            ok &= Expect(PixelNear(img, 8, 4, 117, 136, 114), "c422.px84", 0x0026, fail_code);
        }
    }

    // ----- Hostile: progressive (SOF2) JPEG must be rejected, not crash.
    {
        arena.Reset();
        JpegImage img;
        const bool rejected = !JpegDecode(kJpegProgressive, u32(sizeof(kJpegProgressive)), arena, &img);
        ok &= Expect(rejected, "progressive.rejected", 0x0030, fail_code);
    }

    // ----- Hostile: truncated scan (cut mid-entropy) must be rejected,
    // with no buffer overrun.
    {
        arena.Reset();
        JpegImage img;
        const bool rejected = !JpegDecode(kJpegColor420, u32(sizeof(kJpegColor420)) - 30, arena, &img);
        ok &= Expect(rejected, "truncated.rejected", 0x0031, fail_code);
    }

    // ----- Hostile: random garbage (no SOI) must be rejected.
    {
        arena.Reset();
        JpegImage img;
        const u8 garbage[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
        const bool rejected = !JpegDecode(garbage, u32(sizeof(garbage)), arena, &img);
        ok &= Expect(rejected, "garbage.rejected", 0x0032, fail_code);
    }

    if (!ok)
    {
        KBP_PROBE_V(duetos::debug::ProbeId::kBootSelftestFail, fail_code);
        return;
    }

    arch::SerialWrite("[jpeg-selftest] PASS (4:2:0,gray,4:2:2; progressive+truncated+garbage rejected)\n");
}

} // namespace duetos::web
