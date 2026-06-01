#pragma once

#include "util/types.h"

/*
 * DuetOS — web PNG decoder (RFC 2083 / W3C PNG 2nd Ed., clean room).
 *
 * This is the decoder the web stack's <img> path consumes. It is a
 * strict superset of the colour-type coverage in util/png (which
 * only handles 8-bit RGB / RGBA via the Rust img_meta header
 * walker). This decoder handles every 8-bit non-interlaced colour
 * type the modern web actually ships:
 *
 *   - colour-type 0 (grayscale)            bit_depth 8
 *   - colour-type 2 (truecolour, RGB)      bit_depth 8
 *   - colour-type 3 (palette / PLTE)       bit_depth 8, optional tRNS
 *   - colour-type 4 (grayscale + alpha)    bit_depth 8
 *   - colour-type 6 (truecolour + alpha)   bit_depth 8
 *
 * Output is always RGBA8888: a contiguous `width * height * 4`
 * byte buffer, four bytes per pixel in R, G, B, A order (byte 0 =
 * red). This byte-order spelling is endian-unambiguous, unlike a
 * packed u32, which matters because the web compositor and the
 * GPU upload path both consume the raw bytes.
 *
 * Built on the existing kernel utilities:
 *   - util/crc32   — every chunk's CRC32 trailer is validated.
 *   - util/deflate — IDAT is a zlib stream; the 2-byte zlib
 *                    header is skipped and the DEFLATE body fed to
 *                    DeflateInflate. The trailing Adler-32 is not
 *                    re-verified (DEFLATE structural checks + the
 *                    expected-output-length check already gate a
 *                    corrupt stream).
 *
 * Hostile-input safe: dimensions are capped at 4096 x 4096, the
 * total input length is bounded, every chunk offset/length is
 * bounds-checked against src_len before use, and the inflated
 * scanline length must match exactly what IHDR implies.
 *
 * Memory: all working buffers (concatenated IDAT, inflated
 * scanlines, and the output RGBA pixels) come from a caller-
 * supplied bump Arena — no kheap, no global state. The Arena is a
 * thin freestanding bump allocator over a caller-owned byte span
 * (see Arena below); when it runs dry the decode fails cleanly
 * rather than overrunning.
 *
 * GAP — deliberately unimplemented (web targets don't need them
 * in v0; revisit when a real page demands one):
 *   - Adam7 interlacing.
 *   - 16-bit sample depth.
 *   - 1 / 2 / 4-bit sub-byte sample depths.
 *   - APNG (animation).
 *   - gAMA / sRGB / iCCP gamma & colour-profile correction.
 *   - Ancillary chunks beyond tRNS (all walked past tolerantly).
 */

namespace duetos::web
{

inline constexpr u32 kPngSignatureBytes = 8;

/// Hard caps — a malformed IHDR cannot make us size a buffer to
/// gigabytes. 4096 x 4096 RGBA is 64 MiB, already far past what a
/// boot-time web image will ever be.
inline constexpr u32 kPngMaxDimension = 4096;
inline constexpr u32 kPngMaxInputBytes = 16u * 1024u * 1024u;

/// Freestanding bump allocator over a caller-owned byte span. No
/// free — the whole arena is reclaimed by the caller when the
/// decode is done. Allocation past capacity returns nullptr, which
/// the decoder treats as a clean failure.
struct Arena
{
    u8* base = nullptr;
    u32 cap = 0;
    u32 used = 0;

    Arena() = default;
    Arena(u8* b, u32 c) : base(b), cap(c), used(0) {}

    /// Allocate `n` bytes, 8-byte aligned. Returns nullptr if the
    /// request (after alignment) would exceed capacity.
    u8* Alloc(u32 n)
    {
        const u32 aligned = (used + 7u) & ~7u;
        if (aligned > cap || n > cap - aligned)
            return nullptr;
        u8* p = base + aligned;
        used = aligned + n;
        return p;
    }

    void Reset() { used = 0; }
};

struct PngImage
{
    u32 width = 0;
    u32 height = 0;
    u8* pixels = nullptr; // width * height * 4 bytes, R,G,B,A order
};

/// Decode a PNG file in `data` (`len` bytes) to RGBA8888. On
/// success fills `out` (width, height, and `pixels` allocated from
/// `arena`) and returns true. On any malformed / unsupported /
/// oversized input returns false without writing past any buffer.
/// `out->pixels` is owned by `arena`; it stays valid as long as the
/// arena's backing span does.
bool PngDecode(const u8* data, u32 len, Arena& arena, PngImage* out);

/// Boot-time self-test. Decodes embedded known-answer fixtures
/// covering every supported colour type + a Paeth-filtered row,
/// asserts exact dimensions and pixel values, and proves that a
/// corrupted-CRC input and a truncated input are both rejected.
/// Emits `[png-selftest] PASS (...)` on success; on failure emits a
/// FAIL line and fires KBP_PROBE_V(kBootSelftestFail, ...).
void PngSelfTest();

} // namespace duetos::web
