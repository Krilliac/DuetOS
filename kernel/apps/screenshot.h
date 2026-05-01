#pragma once

#include "util/types.h"

/*
 * DuetOS Screenshot — v0.
 *
 * One-shot framebuffer capture to a 32-bit top-down BMP file on
 * the FAT32 root volume. Triggered via Ctrl+Alt+P (wired in
 * kernel/core/main.cpp); also exposed via the boot self-test and
 * shell command for headless verification.
 *
 * The output filename is the next available `SHOTNNNN.BMP` slot
 * — the root directory is scanned, the highest existing N is
 * found, and N+1 is used. Format: 32-bpp uncompressed, top-down
 * (negative DIB height) so source-row order matches framebuffer
 * order, no extra row-flip pass.
 *
 * Implementation streams the file in 64 KiB chunks via
 * Fat32CreateAtPath (first chunk) and Fat32AppendAtPath (rest);
 * the kernel heap is too small to buffer a full 1024×768 frame
 * at once. Chunks are row-aligned so any practical resolution
 * fits at least one row per chunk.
 *
 * Scope limits:
 *   - Single buffer (the primary framebuffer). No window-region
 *     capture, no compositor snapshot — what's on screen is what
 *     gets written.
 *   - 32-bpp framebuffer assumed (the only mode FramebufferInit
 *     accepts in v0).
 *   - 9999 slots per session — beyond that, ScreenshotCapture
 *     refuses (no slot recycle).
 *   - No compression, no PNG. BMP is the simplest format that
 *     downstream tooling can decode.
 *
 * Context: kernel. Caller MUST hold the compositor lock — the
 * framebuffer is read directly without an MMIO copy fence, and a
 * concurrent draw would race with the row copy.
 */

namespace duetos::apps::screenshot
{

/// Capture the current framebuffer to the FAT32 root volume as
/// the next available `SHOTNNNN.BMP`. Returns true on success.
/// Returns false (and logs a one-line reason) when no FAT32
/// volume is mounted, no framebuffer is available, the kernel
/// heap can't satisfy the scratch allocation, or the filename
/// counter overflows. On a partial write the partial file is
/// deleted before return so the FAT doesn't accumulate
/// corrupted entries.
bool ScreenshotCapture();

/// Boot self-test: skipped silently if FAT32 isn't mounted.
/// Synthesises a 4×4 BMP via the same write path
/// ScreenshotCapture uses (against `SHOTTEST.BMP` to avoid
/// colliding with real captures), verifies the file size on
/// disk matches the BMP header (54 + 4×4×4 = 118 bytes),
/// then deletes the test file. Prints PASS / FAIL / SKIP to
/// COM1.
void ScreenshotSelfTest();

} // namespace duetos::apps::screenshot
