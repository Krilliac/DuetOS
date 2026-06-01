#pragma once

#include "util/types.h"
#include "web/png.h" // reuse PngArena (do not introduce a second arena type)

/*
 * DuetOS — web baseline-JPEG decoder (ITU-T T.81 / JFIF, clean room).
 *
 * This is the second decoder behind the web stack's <img> path, a
 * sibling of kernel/web/png. It decodes a BASELINE (sequential DCT,
 * Huffman-coded) JPEG file to RGBA8888 — the same output shape as
 * PngImage so the compositor / GPU upload path consumes both the
 * same way.
 *
 * Supported (the baseline web actually ships):
 *   - SOI / EOI framing, APPn + COM skipped.
 *   - DQT  — quantisation tables, 8-bit and 16-bit precision.
 *   - SOF0 — baseline sequential DCT, 8-bit sample precision,
 *            1 component (grayscale) or 3 components (YCbCr).
 *   - DHT  — Huffman tables, DC and AC classes.
 *   - SOS  — single interleaved scan.
 *   - DRI / RSTn — restart interval + restart-marker resync.
 *   - Chroma subsampling 4:4:4, 4:2:2, 4:2:0 (any H/V sampling
 *     factor in {1,2}); grayscale (1 component).
 *
 * Decode pipeline (all INTEGER — the kernel builds -mno-sse
 * -mno-80387, so there is no hardware float/double; the inverse
 * DCT and the YCbCr->RGB convert are fixed-point, no FP at all):
 *   marker parse -> per-MCU Huffman entropy decode (DC differential
 *   + AC run/length, ZRL, EOB) -> dequantise in zig-zag order ->
 *   integer AAN inverse DCT (row pass + column pass, fixed-point
 *   13-bit constants) -> level shift (+128) + clamp [0,255] ->
 *   upsample chroma -> integer YCbCr->RGB -> RGBA8888 (A = 255).
 *
 * Hostile-input safe: every marker segment length, every table
 * count, and every component/sampling field is bounds-checked
 * before use; dimensions are capped at 4096x4096 and total input
 * at 16 MiB; a truncated entropy stream or an exhausted arena
 * fails cleanly (returns false) rather than overrunning. The bit
 * reader saturates to a synthetic EOI past the end of input so a
 * malformed scan cannot read out of bounds.
 *
 * GAP — deliberately unimplemented (revisit when a real page needs
 * one):
 *   - Progressive JPEG (SOF2) — rejected with a clear unsupported
 *     return, never a crash.
 *   - Arithmetic coding (SOF9..SOFB) — rejected.
 *   - Extended sequential / lossless / 12-bit (SOF1, SOF3, 12-bit
 *     precision) — rejected.
 *   - CMYK / YCCK / Adobe APP14 colour transforms (only JFIF
 *     grayscale + YCbCr).
 *   - EXIF orientation, ICC profiles (APP1/APP2 skipped).
 *   - Corrupt-stream resync beyond the RSTn restart markers.
 */

namespace duetos::web
{

/// Hard caps — a malformed SOF0 cannot size a buffer to gigabytes.
inline constexpr u32 kJpegMaxDimension = 4096;
inline constexpr u32 kJpegMaxInputBytes = 16u * 1024u * 1024u;

struct JpegImage
{
    u32 width = 0;
    u32 height = 0;
    u8* pixels = nullptr; // width * height * 4 bytes, R,G,B,A order
};

/// Decode a baseline JPEG in `data` (`len` bytes) to RGBA8888. On
/// success fills `out` (width, height, and `pixels` allocated from
/// `arena`) and returns true. On any malformed / unsupported /
/// oversized input returns false without writing past any buffer.
/// `out->pixels` is owned by `arena`; it stays valid as long as the
/// arena's backing span does.
bool JpegDecode(const u8* data, u32 len, PngArena& arena, JpegImage* out);

/// Boot-time self-test. Decodes embedded baseline fixtures (a 4:2:0
/// colour gradient, a 4:2:2 colour gradient, a grayscale image)
/// generated on the dev host with Pillow/libjpeg, asserts exact
/// dimensions and per-channel pixel values within a lossy tolerance
/// against the host libjpeg reference, and proves that a truncated
/// input and a progressive (SOF2) JPEG are both rejected without a
/// crash. Emits `[jpeg-selftest] PASS (...)` on success; on failure
/// emits a FAIL line and fires KBP_PROBE_V(kBootSelftestFail, ...).
void JpegSelfTest();

} // namespace duetos::web
