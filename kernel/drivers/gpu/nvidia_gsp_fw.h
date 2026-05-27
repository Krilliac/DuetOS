#pragma once

#include "util/result.h"
#include "util/types.h"

/*
 * DuetOS — NVIDIA GSP firmware-image (nvfw_bin_hdr) parser.
 *
 * NVIDIA Turing+ GPUs ship the GSP (GPU System Processor) firmware
 * as a single per-asic file (`gsp_tu10x.bin`, `gsp_ga10x.bin`,
 * `gsp_ad10x.bin`, ...) wrapped in NVIDIA's binary container format.
 * The container layout is published in `open-gpu-kernel-modules`
 * and consumed by both the proprietary driver and the in-tree Linux
 * `nouveau` GSP support since kernel 6.7.
 *
 * Container layout (little-endian throughout):
 *
 *   nvfw_bin_hdr   (24 bytes)
 *     bin_magic        u32   0x10de (NVIDIA vendor ID)
 *     bin_ver          u32   1
 *     bin_size         u32   total size padded to 256-byte alignment
 *     header_offset    u32   offset of the inner descriptor — = 24
 *                             for v0 outer headers, since the inner
 *                             descriptor sits immediately after.
 *     data_offset      u32   offset of the GSP payload (post-
 *                             descriptor / post-HS header). The
 *                             payload itself is ELF64 RISC-V.
 *     data_size        u32   GSP payload size in bytes.
 *
 * For Turing TU10x / Ampere GA100 the inner descriptor is 76 bytes.
 * For Ampere GA102+ / Ada / Hopper / Blackwell it is 84 bytes. The
 * difference comes from a wider per-arch field at the tail; the
 * parser uses `data_offset - header_offset` to detect which.
 *
 * This parser is freestanding and clean-room. It validates the
 * outer container — bin_magic, bin_ver, header/data offset bounds,
 * inner-descriptor size — and exposes the GSP payload as a span
 * back into the caller's blob. The HS (high-security) signature
 * header that gates a real GSP boot, plus the inner ELF64 RISC-V
 * walker, land in follow-on slices once the surrounding boot
 * sequence (WPR layout, FWSEC FRTS, SEC2 booter) is in place.
 *
 * Scope (v0):
 *   - Validate `bin_magic` == 0x10de.
 *   - Validate `bin_ver` == 1 (refuse newer container revisions —
 *     they may have a different field layout).
 *   - Validate `header_offset` is exactly 24 (immediate descriptor).
 *   - Validate `data_offset >= header_offset + 76`, i.e. there's
 *     room for at least the smaller Turing descriptor.
 *   - Validate `data_offset + data_size <= blob_size`.
 *   - Classify the descriptor as `TU10x` (76 bytes) or `GA102+`
 *     (84 bytes) by descriptor size; report `Unknown` for any
 *     other size and keep the parse valid (forward-compat).
 *   - Surface the payload data pointer + size to the caller. The
 *     payload starts with the inner ELF64 — recognising the
 *     `\x7fELF` magic is exposed as a bool but not enforced; the
 *     amdgpu/nouveau code paths tolerate compressed payloads on
 *     some legacy SKUs.
 *
 * Out of scope (deferred):
 *   - Per-arch descriptor fields (FRTS offset, WPR2 size, GFW
 *     boot table). Each follows a slightly different layout per
 *     asic; capturing the spans is enough for the next slice to
 *     decode each cleanly.
 *   - HS (`nvfw_hs_header_v2`, 9 × u32) parsing — gates the GSP
 *     bootloader push; lands when the SEC2 booter slice arrives.
 *   - ELF64 walk of the GSP payload (`.fwimage` + `.fwsignature_*`).
 *   - Container signature verification. The proprietary driver
 *     does a SHA-2 hash chain that the open-source path defers to
 *     the GSP's own ROM.
 *
 * Threading: pure function. No global state. Safe from any context
 * where the caller already holds `blob` valid for the duration.
 *
 * Subsystem isolation: this parser is freestanding. It is invoked
 * by kernel-only callers (the NVIDIA GPU probe, the boot self-test).
 * No subsystem (Win32 / Linux ABI) reaches it directly — the FwLoad
 * cap-gate stands between every guest process and the on-disk image.
 */

namespace duetos::drivers::gpu::nvidia
{

inline constexpr u32 kNvidiaBinHdrMagic = 0x10deu; // NVIDIA vendor ID
inline constexpr u32 kNvidiaBinHdrVerExpected = 1u;
inline constexpr u32 kNvidiaBinHdrBytes = 24u;
inline constexpr u32 kNvidiaDescBytesTuringGa100 = 76u;             // TU10x / GA100
inline constexpr u32 kNvidiaDescBytesGa102Plus = 84u;               // GA102+ / Ada / Hopper / Blackwell
inline constexpr u32 kNvidiaMaxGspImageBytes = 64u * 1024u * 1024u; // 64 MiB sanity cap

enum class NvidiaGspArchClass : u8
{
    Unknown = 0,       // descriptor size doesn't match a known layout
    TuringOrGa100 = 1, // 76-byte descriptor
    Ga102OrNewer = 2,  // 84-byte descriptor
};

/// Per-image parsed view. Pointers reference back into the caller's
/// blob — no allocation, no copy. `valid == false` means the image
/// failed validation; `reject_reason` indicates which check(s)
/// tripped.
struct NvidiaGspFwParsed
{
    bool valid;

    // Container-header fields.
    u32 bin_magic;
    u32 bin_ver;
    u32 bin_size;      // declared total file size (256-byte aligned)
    u32 header_offset; // inner-descriptor offset (== 24 in v0)
    u32 data_offset;   // GSP payload offset
    u32 data_size;     // GSP payload size

    // Derived: descriptor span (between header_offset and data_offset).
    u32 descriptor_offset;
    u32 descriptor_size;
    NvidiaGspArchClass arch_class;

    // Convenience: payload pointer + size. nullptr / 0 when invalid.
    const u8* payload;
    u32 payload_size;

    // True iff the first four bytes of `payload` are the ELF magic
    // `\x7fELF`. Advisory: a future ELF walker will assert this; the
    // parser keeps the image "valid" even when false so legacy
    // compressed-payload images don't get refused at this gate.
    bool payload_looks_elf;

    // Bookkeeping for diagnostic logs / triage.
    u32 reject_reason; // bit per failing check
};

// reject_reason codes — bit per failing check so multiple
// independent failures can be reported without losing detail.
inline constexpr u32 kNvFwRejectBlobTooShort = 1u << 0;
inline constexpr u32 kNvFwRejectBadMagic = 1u << 1;
inline constexpr u32 kNvFwRejectBadVersion = 1u << 2;
inline constexpr u32 kNvFwRejectHeaderOffset = 1u << 3; // header_offset != 24
inline constexpr u32 kNvFwRejectDataBounds = 1u << 4;   // data_offset + data_size > blob
inline constexpr u32 kNvFwRejectDescTooSmall = 1u << 5; // data_offset - header_offset < 76
inline constexpr u32 kNvFwRejectOversize = 1u << 6;     // data_size > kNvidiaMaxGspImageBytes

/// Parse an NVIDIA GSP firmware container. `parsed` is populated
/// with views into `blob`, so `blob` MUST remain valid for the
/// lifetime of `parsed`.
///
/// Returns:
///   - Ok on a structurally valid image.
///   - Err{InvalidArgument} for null/short input.
///   - Err{Corrupt} when a structural check fails (reject_reason
///     populated in the output struct for diagnosis).
::duetos::core::Result<void> NvidiaGspFwParse(const u8* blob, u32 blob_size, NvidiaGspFwParsed* parsed);

/// Pretty-print a 1-line summary to the kernel serial log. Used by
/// `nvidia::Probe` to record which GSP firmware an operator has
/// installed. No-op when `parsed.valid == false` (the caller logged
/// the reject_reason via the Result path).
void NvidiaGspFwLog(const char* basename, const NvidiaGspFwParsed& parsed);

/// Map a descriptor size to an arch-class enum. Stable; lives here so
/// a future shell command can render the class cleanly.
NvidiaGspArchClass NvidiaGspClassifyDescriptor(u32 descriptor_size);

/// Boot-time self-test. Constructs synthetic images in a static
/// buffer and asserts the parser pulls the expected fields out.
/// Tests the happy paths for TU10x-class and GA102+-class images,
/// plus reject paths for each failure mode. Emits
/// `[gpu/nvidia-fw] selftest PASS (parse + N reject paths)` on
/// success and FAILs with a probe fire + KLOG_WARN sentinel on
/// regression.
void NvidiaGspFwSelfTest();

} // namespace duetos::drivers::gpu::nvidia
