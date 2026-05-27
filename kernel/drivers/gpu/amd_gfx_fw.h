#pragma once

#include "util/result.h"
#include "util/types.h"

/*
 * DuetOS — AMD GFX9+ microcode-image (gfx_firmware_header_v1_0) parser.
 *
 * AMD's per-engine microcode files (`vega10_pfp.bin`, `vega10_me.bin`,
 * `vega10_ce.bin`, `vega10_mec.bin`, `vega10_rlc.bin`, `vega10_sdma.bin`,
 * etc., or their Navi / Renoir equivalents) share a common header
 * structure that the amdgpu driver's `amdgpu_ucode.h` defines:
 *
 *   common_firmware_header  (32 bytes)
 *     size_bytes              u32  total header + image
 *     header_size_bytes       u32  header size only
 *     header_version_major    u16
 *     header_version_minor    u16
 *     ip_version_major        u16
 *     ip_version_minor        u16
 *     ucode_version           u32  value written to *_UCODE_ADDR at end
 *     ucode_size_bytes        u32  microcode payload size
 *     ucode_array_offset_bytes u32 offset from start of file to payload
 *     crc32                   u32  payload checksum
 *
 *   gfx_firmware_header_v1_0  (44 bytes)
 *     common_firmware_header  (32 bytes embedded)
 *     ucode_feature_version   u32
 *     jt_offset               u32  jump-table dword offset inside payload
 *     jt_size                 u32  jump-table size in dwords
 *
 * This parser is freestanding (no heap, no kernel-only deps beyond
 * `util/types.h`) and clean-room — only the publicly-documented
 * header layout is carried over from amdgpu_ucode.h. It validates the
 * header version, the ucode_array_offset_bytes bound, and the jump-
 * table bounds. The output `AmdGfxFwParsed` carries pointers back
 * into the caller's blob (no copying, no allocation).
 *
 * The parser is intentionally lenient on the IP version fields — those
 * vary per ASIC and per engine and aren't useful for validation. The
 * upload code (in a follow-on slice) is the place that asserts "this
 * payload matches the expected engine".
 *
 * Scope (v0):
 *   - Validate header size + total size are consistent.
 *   - Validate ucode_array_offset_bytes and ucode_size_bytes bound
 *     the payload inside the blob.
 *   - For v1 headers (44+ bytes), validate jt_offset + jt_size fit
 *     inside the ucode payload (jump-table is dwords, payload is
 *     bytes, so the bound is `(jt_offset + jt_size) * 4 <= ucode_size`).
 *   - Expose the (data, size) view back into the blob so a follow-on
 *     upload slice can stream `ucode_size_bytes / 4` dwords into the
 *     appropriate `mmCP_*_UCODE_DATA` register pair.
 *
 * Out of scope (deferred):
 *   - Actual MMIO push to the CP. The upload sequence is documented
 *     in the wiki's GPU-Implementation-Notes — this parser is its
 *     pre-flight gate.
 *   - PSP-mediated upload (mandatory on GFX11+ where microcode is
 *     signed). The PSP ring, KGD↔PSP RPC, and the matching signed-
 *     image format land in a separate slice.
 *   - RLC SAVE/RESTORE list. The RLC microcode payload covered by
 *     this parser is enough to satisfy the CP's "RLC alive" gate;
 *     the SRLC list is a separate side-band image (RLC SAVE) that
 *     needs its own parser.
 *
 * Threading: pure function. No global state. Safe from any context
 * where the caller already holds `blob` valid for the duration.
 *
 * Subsystem isolation: this parser is freestanding. It is invoked by
 * kernel-only callers (the AMD GPU probe, the boot self-test). No
 * subsystem (Win32 / Linux ABI) reaches it directly — the FwLoad
 * cap-gate stands between every guest process and the on-disk image.
 */

namespace duetos::drivers::gpu::amd
{

inline constexpr u32 kAmdCommonFwHeaderBytes = 32;
inline constexpr u32 kAmdGfxFwHeaderV1Bytes = 44;
inline constexpr u32 kAmdMaxFwSizeBytes = 4u * 1024u * 1024u; // 4 MiB sanity cap

/// Per-image parsed view. Pointers reference back into the caller's
/// blob — no allocation, no copy. `valid == false` means the image
/// failed validation; the bookkeeping fields below indicate which
/// check tripped.
struct AmdGfxFwParsed
{
    // True iff the header validated and bounds the payload inside
    // the blob.
    bool valid;

    // True iff the header is at least 44 bytes and the v1 gfx-
    // header fields (feature_version + jt_offset + jt_size) were
    // populated. Some side-band images (RLC SAVE) use the common
    // header alone — those report `is_v1_gfx_header = false` and
    // the jt fields stay at 0.
    bool is_v1_gfx_header;

    // Common-header fields.
    u32 size_bytes;        // total file size as the header declares
    u32 header_size_bytes; // header length
    u16 header_version_major;
    u16 header_version_minor;
    u16 ip_version_major;
    u16 ip_version_minor;
    u32 ucode_version;      // final write to *_UCODE_ADDR after streaming
    u32 ucode_size_bytes;   // microcode payload size
    u32 ucode_array_offset; // payload offset within the blob
    u32 crc32;              // payload checksum (declared; not verified by v0)

    // v1-only gfx-header fields.
    u32 ucode_feature_version;
    u32 jt_offset_dwords; // jump-table base, dword offset within payload
    u32 jt_size_dwords;   // jump-table size in dwords

    // Convenience: pointer to the first dword of the ucode payload
    // and dword count. The follow-on upload code walks this directly
    // to feed `mmCP_*_UCODE_DATA`. nullptr / 0 when `valid` is false.
    const u32* ucode;
    u32 ucode_dword_count;

    // Bookkeeping for diagnostic logs / triage.
    u32 reject_reason; // 0 = ok; non-zero codes below for each check
};

// reject_reason codes — bit per failing check so multiple
// independent failures can be reported without losing detail.
inline constexpr u32 kAmdFwRejectBlobTooShort = 1u << 0;
inline constexpr u32 kAmdFwRejectHeaderShort = 1u << 1;
inline constexpr u32 kAmdFwRejectHeaderInconsistent = 1u << 2; // size_bytes < header_size_bytes etc.
inline constexpr u32 kAmdFwRejectUcodeOverflow = 1u << 3;      // ucode_offset + size > blob
inline constexpr u32 kAmdFwRejectJtOverflow = 1u << 4;         // jt_offset + jt_size > ucode payload dwords
inline constexpr u32 kAmdFwRejectOversize = 1u << 5;           // size_bytes > kAmdMaxFwSizeBytes

/// Parse an AMD GFX microcode image. `parsed` is populated with views
/// into `blob`, so `blob` MUST remain valid for the lifetime of
/// `parsed`.
///
/// Returns:
///   - Ok on a structurally valid image.
///   - Err{InvalidArgument} for null/short input.
///   - Err{Corrupt} when a structural check fails (reject_reason
///     populated in the output struct for diagnosis).
::duetos::core::Result<void> AmdGfxFwParse(const u8* blob, u32 blob_size, AmdGfxFwParsed* parsed);

/// Pretty-print a 1-line summary to the kernel serial log. Used by
/// `amd::Probe` to record which images an operator has installed.
/// No-op when `parsed.valid == false` (the caller logged the
/// reject_reason via the Result path).
void AmdGfxFwLog(const char* basename, const AmdGfxFwParsed& parsed);

/// Boot-time self-test. Constructs a synthetic image in a static
/// buffer and asserts the parser pulls the expected fields out.
/// Tests the happy path (valid v1 image), the short-blob path, the
/// header-inconsistent path, the ucode-overflow path, and the
/// jt-overflow path. Emits `[gpu/amd-fw] selftest PASS` on success
/// and FAILs with a probe fire + KLOG_WARN sentinel on regression.
void AmdGfxFwSelfTest();

} // namespace duetos::drivers::gpu::amd
