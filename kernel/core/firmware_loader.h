#pragma once

#include "result.h"
#include "types.h"

/*
 * DuetOS — kernel firmware loader (scaffold).
 *
 * Centralizes the "load this vendor blob" surface that wireless and
 * GPU drivers need before they can do real work. v0 is honest:
 * there is no firmware-bearing filesystem mounted at boot, no
 * signature verifier, no microcode-format parser — every lookup
 * returns `Err{ErrorCode::NotFound}`. The shape of the API is
 * stable so a follow-up slice can drop in:
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

struct FwBackendStats
{
    FwBackendKind kind;
    u32 lookups;
    u32 hits;
    u32 misses;
    u32 verification_failures;
};

/// Look up a firmware blob. v0 implementation always returns
/// `Err{ErrorCode::NotFound}` — no backend is installed. The
/// driver-side caller is expected to handle this gracefully (mark
/// `firmware_pending` and continue), which is how the wireless
/// driver shells already behave.
::duetos::core::Result<FwBlob> FwLoad(const FwLoadRequest& req);

/// Release a blob obtained from `FwLoad`. v0: no-op (no
/// allocations, nothing to free). Stays in the API so the caller
/// pattern is correct from day one.
void FwRelease(const FwBlob& blob);

/// Snapshot of the current backend's stats. Useful for the
/// boot-time logger + a future shell command that lists firmware
/// availability.
FwBackendStats FwBackendStatsRead();

/// Initialize the firmware loader. Idempotent. v0: just records
/// `FwBackendKind::None` and logs that no backend is wired up yet.
/// A future slice that mounts /lib/firmware will replace this with
/// a VFS-backed scanner.
void FwLoaderInit();

} // namespace duetos::core
