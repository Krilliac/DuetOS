#pragma once

#include "util/result.h"
#include "util/types.h"

/*
 * DuetOS — Qualcomm Atheros ath9k_htc open firmware validator.
 *
 * The HTC firmware shipped by the `qca/open-ath9k-htc-firmware`
 * tree (and re-distributed by `linux-firmware` as `htc_9271.fw` /
 * `htc_7010.fw`) is a raw target binary: no on-disk record header,
 * no signature, no TLV envelope. The device's bootrom expects the
 * blob to be copied verbatim into target SRAM at a chip-specific
 * load address and then jumped to.
 *
 * That makes "parsing" trivial — but a thin validator still pays
 * its way: it pins a sane size band, computes a stable Fletcher-32
 * digest the boot log can show, and classifies the target chip so
 * the upload state machine picks the right load address without a
 * second filename lookup.
 *
 * Why open firmware matters: ath9k_htc is currently the only
 * commodity Wi-Fi target with source-available firmware that can be
 * rebuilt end-to-end. DuetOS's policy matrix flags it `Preferred`
 * (see `kernel/drivers/net/firmware_policy.*`) and the firmware
 * loader's default `OpenThenVendor` search order finds it under
 * `/lib/firmware/duetos/open/ath9k-htc/` before the legacy vendor
 * namespace.
 *
 * Threading: pure function over caller-owned bytes. No global state.
 */

namespace duetos::drivers::net
{

enum class AthHtcTarget : u8
{
    Unknown = 0,
    Ar9271 = 1, // USB 802.11n single-chip; firm load addr 0x501000
    Ar7010 = 2, // USB bridge to AR9280/AR9285 PHY; firm load addr 0x903000
};

inline constexpr u32 kAthHtcMinBytes = 16u * 1024;  // open-fw ~50 KiB, refuse < 16 KiB
inline constexpr u32 kAthHtcMaxBytes = 256u * 1024; // bound at 256 KiB

// Chip-specific load addresses, from the open-ath9k-htc-firmware
// build system. These are the byte addresses in target SRAM where
// the bootrom expects the image to land.
inline constexpr u32 kAthHtcLoadAddrAr9271 = 0x00501000u;
inline constexpr u32 kAthHtcLoadAddrAr7010 = 0x00903000u;

// USB control transfer chunk size used by the HTC firmware download
// protocol. Devices accept up to 4 KiB per FIRMWARE_DOWNLOAD request.
inline constexpr u32 kAthHtcDownloadChunkBytes = 4096;

struct AthHtcFirmwareParsed
{
    bool valid;
    AthHtcTarget target;
    u32 declared_size;
    u32 load_address;
    u32 fletcher32;       // payload Fletcher-32 (little-endian 16-bit words)
    u32 chunk_count;      // ceil(declared_size / kAthHtcDownloadChunkBytes)
    u32 tail_chunk_bytes; // bytes in the final chunk (< or == chunk size)
};

/// Validate an ath9k_htc firmware blob and populate `parsed`.
/// Returns `InvalidArgument` for null args, `Corrupt` if the size
/// is outside `[kAthHtcMinBytes, kAthHtcMaxBytes]`. Length-only
/// validation is intentional: the blob has no on-disk identifier
/// because the bootrom does not inspect it before copying it into
/// target SRAM.
::duetos::core::Result<void> AthHtcFirmwareParse(const u8* blob, u32 blob_size, AthHtcFirmwareParsed* parsed);

/// Guess the target chip from blob size when the basename is not
/// definitive. Returns Unknown when the size doesn't match any
/// known build of `htc_9271.fw` / `htc_7010.fw`.
AthHtcTarget AthHtcTargetFromSize(u32 blob_size);

/// Map a target enum to its hardware load address. Returns 0 for
/// `Unknown`.
u32 AthHtcLoadAddressForTarget(AthHtcTarget target);

const char* AthHtcTargetName(AthHtcTarget target);

void AthHtcFirmwareLog(const AthHtcFirmwareParsed& parsed);

void AthHtcFirmwareSelfTest();

} // namespace duetos::drivers::net
