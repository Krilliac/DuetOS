#pragma once

#include "util/result.h"
#include "util/types.h"

/*
 * DuetOS — kernel firmware loader (scaffold).
 *
 * Centralizes the "load this vendor blob" surface that wireless and
 * GPU drivers need before they can do real work. The loader now uses
 * a VFS-backed lookup path (`/lib/firmware/<vendor>/<basename>` then
 * `/lib/firmware/<basename>`) and enforces optional size bounds.
 * Signature verification remains a follow-up slice:
 *
 *   1. A scan of `/lib/firmware/<vendor>/<filename>` (or a
 *      wireless-specific path) on the boot filesystem once
 *      VFS lookup of arbitrary paths is wired up.
 *   2. Per-vendor blob signature checks (Intel iwlwifi has a
 *      TLV format with vendor signatures; Realtek + Broadcom
 *      ship raw binaries).
 *   3. A small in-kernel cache of loaded blobs so the first
 *      bring-up of a chip doesn't re-read the boot media.
 *
 * Drivers use the loader through one call:
 *
 *   FwLoadRequest req{vendor="intel-iwlwifi", basename="iwlwifi-9000-pu-b0-jf-b0-46.ucode"};
 *   auto r = FwLoad(req);
 *   if (r.has_value()) { use(r.value()); }
 *
 * Threading: callable from any kernel thread; not safe from IRQ.
 */

namespace duetos::core
{

struct FwLoadRequest
{
    // Short vendor key — "intel-iwlwifi", "realtek-rtl88xx", "broadcom-bcm43xx".
    // Used to namespace the lookup path; not part of the on-disk
    // filename.
    const char* vendor;
    // On-disk basename. Vendor convention: iwlwifi uses
    // `iwlwifi-<gen>-<rev>.ucode`; rtl88xx uses
    // `rtlwifi/rtl<chip>fw.bin`; bcm43xx uses `b43/<chip>.fw`.
    const char* basename;
    // Optional minimum + maximum size hints. The loader rejects
    // blobs outside the range as malformed without parsing them.
    // 0 means "no constraint".
    u32 min_bytes;
    u32 max_bytes;
};

struct FwBlob
{
    const u8* data;
    u32 size;
    // True iff the loader verified a vendor-format signature on
    // the blob before returning it. v0: always false (no
    // verification implemented). Drivers that REQUIRE signed
    // firmware should refuse blobs where this is false until the
    // verifier slice lands.
    bool verified;
    // Stable handle the caller passes back to `FwRelease`. v0: 0.
    u64 handle;
};

enum class FwBackendKind : u8
{
    None,          // no backend installed — every lookup misses
    Vfs,           // /lib/firmware/<vendor>/<basename> via VFS
    EmbeddedTable, // hand-curated kBlob table linked into the kernel
};

enum class FwSourcePolicy : u8
{
    OpenThenVendor = 0, // prefer DuetOS/open firmware paths, then vendor path
    OpenOnly,           // reject vendor paths entirely
    VendorOnly,         // skip open firmware paths
};

struct FwBackendStats
{
    FwBackendKind kind;
    FwSourcePolicy policy;
    u32 lookups;
    u32 hits;
    u32 misses;
    u32 verification_failures;
};

inline constexpr u32 kFwTracePathMax = 159;
inline constexpr u32 kFwTraceNameMax = 63;
inline constexpr u32 kFwTraceCapacity = 64;

struct FwTraceEntry
{
    char vendor[kFwTraceNameMax + 1];
    char basename[kFwTraceNameMax + 1];
    char attempted_path[kFwTracePathMax + 1];
    ErrorCode result;
    FwSourcePolicy policy;
};

/// Look up a firmware blob from the VFS-backed firmware tree. Returns
/// `Err{ErrorCode::NotFound}` when no candidate path exists and
/// `Err{ErrorCode::Corrupt}` when size bounds are violated.
::duetos::core::Result<FwBlob> FwLoad(const FwLoadRequest& req);

/// Release a blob obtained from `FwLoad`. Current backends return
/// stable in-memory bytes, so this is a no-op.
void FwRelease(const FwBlob& blob);

/// Snapshot of the current backend's stats. Useful for the
/// boot-time logger + a future shell command that lists firmware
/// availability.
FwBackendStats FwBackendStatsRead();

/// Select firmware source policy globally.
void FwSetSourcePolicy(FwSourcePolicy policy);

/// Read current firmware source policy.
FwSourcePolicy FwSourcePolicyRead();

/// Number of trace entries currently retained (bounded ring buffer).
u32 FwTraceCount();

/// Read a trace entry by index where 0 is oldest and
/// `FwTraceCount()-1` is newest. Returns false if out-of-range.
bool FwTraceRead(u32 index, FwTraceEntry* out);

/// Clear all trace entries.
void FwTraceClear();

/// Initialize the firmware loader. Idempotent.
void FwLoaderInit();

} // namespace duetos::core
