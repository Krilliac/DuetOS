#pragma once

#include "util/result.h"
#include "util/types.h"

/*
 * DuetOS — Intel discrete-GPU GSC firmware-image (FPT) parser.
 *
 * Intel discrete graphics (DG2 / Arc / Alchemist / Battlemage) and
 * recent integrated GPUs (Meteor Lake / Lunar Lake) carry a small
 * companion controller — the "Graphics System Controller" (GSC).
 * The GSC owns power-management, OPROM-data dispatch, and a handful
 * of security paths that the Render engines themselves do not
 * touch. Firmware updates for the GSC ship as a single binary image
 * structured as a Flash Partition Table (FPT), the same overall
 * shape Intel has used for the Management Engine since Skylake.
 *
 * Intel publishes a userland updater (https://github.com/intel/igsc)
 * that consumes these images and pushes them to the GSC over MEI.
 * DuetOS does not yet have an MEI driver, so we cannot push an
 * update — but we can already parse an image at boot time, log
 * which partitions an operator has installed at
 * /lib/firmware/duetos/open/intel-gsc/<image>.bin, and refuse to
 * proceed if the image is structurally bogus.
 *
 * This parser is freestanding (no heap, no kernel-only deps beyond
 * `util/types.h`) and clean-room — only the publicly-documented
 * FPT header / entry layout is carried over from Intel's firmware
 * specification. It validates the marker, walks the entry array,
 * and populates an `IntelGscFwParsed` view that points back into
 * the caller's blob (no copying, no allocation).
 *
 * Scope (v0):
 *   - Validate the `$FPT` header marker. Accept it at byte 0
 *     (modern GSC images) OR after a 16-byte "ROM-bypass" prelude
 *     (older Intel ME images, kept for diagnostic completeness).
 *   - Walk every entry; bail on declared length / offset that
 *     leaves the blob.
 *   - Recognise the standard partition names (FTPR / OPRO / OPRC /
 *     IAFW / MDMV / GLUT / MFTP / DLMP). Each match stores a
 *     (data, size) view back into the blob.
 *   - Capture the FITC version dwords + the firmware-flash CRC.
 *   - Count "unknown" entries so a caller can spot a wildly-out-
 *     of-band image without losing the parse.
 *
 * Out of scope (deferred):
 *   - Per-partition manifest validation (CPD/SHA-256 hash chain).
 *   - MEI talk-back. Pushing an image to the GSC needs an MEI
 *     driver and a kCapDriverIntelGsc capability gate that does
 *     not exist.
 *   - The OPROM .bin format inside the OPRO partition. igsc parses
 *     a further header inside the partition; we only record the
 *     outer span.
 *
 * Threading: pure function. No global state. Safe from any context
 * where the caller already holds `blob` valid for the duration.
 *
 * Subsystem isolation: this parser is freestanding. It is invoked
 * by kernel-only callers (the Intel GPU probe, the boot self-test).
 * No subsystem (Win32 / Linux ABI) reaches it directly — the FwLoad
 * gate stands between every guest process and the on-disk image.
 */

namespace duetos::drivers::gpu::intel
{

inline constexpr u32 kIntelGscFptMarker = 0x54504624u; // "$FPT" LE
inline constexpr u32 kIntelGscRomBypassBytes = 16;
inline constexpr u32 kIntelGscFptHeaderBytes = 32;
inline constexpr u32 kIntelGscFptEntryBytes = 32;
inline constexpr u32 kIntelGscPartitionNameBytes = 4;
inline constexpr u32 kIntelGscMaxEntries = 32;

enum class IntelGscPartitionKind : u8
{
    Unknown = 0,
    Ftpr,   // Code partition — operational firmware. (igsc "fw")
    Oprom,  // OPROM data partition. (igsc "oprom-data")
    OpromC, // OPROM code partition. (igsc "oprom-code")
    IaFw,   // Intel Audio Firmware partition.
    Mdmv,   // Manufacturing diagnostic / vendor info partition.
    Glut,   // Global lookup table.
    Mftp,   // Manufacturing test partition. Not present in production
            // images; flag it loudly when seen.
    Dlmp,   // Debug-logger manufacturing partition.
    Fpfs,   // Field-programmable fuse store.
    Pmcp,   // Power-management controller partition.
};

struct IntelGscFwSection
{
    // Pointer back into the firmware blob (not owned). Null if the
    // section was not present in the image.
    const u8* data;
    u32 size;
    // Byte offset inside the FPT image. Useful for diagnostic logs.
    u32 image_offset;
};

struct IntelGscFwEntry
{
    char name[kIntelGscPartitionNameBytes + 1];
    IntelGscPartitionKind kind;
    u32 offset;
    u32 length;
    u32 partition_flags;
};

struct IntelGscFwParsed
{
    // True iff the FPT header validated and at least one entry
    // walked cleanly.
    bool valid;

    // True iff the image started with a 16-byte ROM-bypass prelude
    // (older ME-style image). Modern GSC images set this false.
    bool rom_bypass_present;

    // Header dwords pulled out for diagnostics.
    u32 num_entries_declared;
    u32 num_entries_walked;
    u32 fitc_version_packed; // major | minor<<8 | hotfix<<16 | build<<24
    u8 header_version;
    u8 entry_version;
    u8 header_length;
    u8 header_checksum;

    // Recognised partitions. Set if the image carries them.
    IntelGscFwSection ftpr;
    IntelGscFwSection oprom;
    IntelGscFwSection oprom_code;
    IntelGscFwSection ia_fw;

    // Per-entry roll-up (bounded). Lets a caller list partitions
    // without re-walking.
    IntelGscFwEntry entries[kIntelGscMaxEntries];

    // Bookkeeping.
    u32 unknown_entries;     // entries whose name we don't recognise
    u32 invalid_entries;     // entries whose offset+length leaves the blob
    u32 manufacturing_flags; // bit per "test-only" partition seen (MFTP / DLMP)
    u32 walked_bytes;        // bytes consumed (header + entries actually walked)
};

/// Parse an Intel GSC firmware image. The output `parsed` is
/// populated with views into `blob`, so `blob` MUST remain valid
/// for the lifetime of `parsed`.
///
/// Returns:
///   - `Ok` on a structurally valid image (marker validated +
///     at least one entry walked).
///   - `Err{InvalidArgument}` for null/short input.
///   - `Err{Corrupt}` for a missing `$FPT` marker, an out-of-range
///     `num_entries`, or an entry whose declared offset/length
///     leaves the blob.
::duetos::core::Result<void> IntelGscFwParse(const u8* blob, u32 blob_size, IntelGscFwParsed* parsed);

/// Map a 4-byte ASCII partition name to a kind enum. Stable; lives
/// here so a future shell command can render the kind cleanly.
IntelGscPartitionKind IntelGscClassifyName(const char* four_bytes);

/// Pretty-print a 1-line summary to the kernel serial log for use
/// during driver bring-up. Idempotent / no allocation.
void IntelGscFwLog(const IntelGscFwParsed& parsed);

/// Boot-time self-test. Constructs a synthetic FPT image in a
/// static buffer and asserts the parser pulls the expected fields
/// out. Logs `[intel-gsc-fw] selftest pass/fail` and panics on
/// failure.
void IntelGscFwSelfTest();

} // namespace duetos::drivers::gpu::intel
