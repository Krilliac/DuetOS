#pragma once

#include "drivers/net/ath9k_htc_fw.h"
#include "util/result.h"
#include "util/types.h"

/*
 * DuetOS — ath9k_htc open firmware download protocol.
 *
 * AR9271 / AR7010 USB Wi-Fi adapters boot with a small ROM that
 * waits for the host to push a target image into SRAM via a pair
 * of vendor-specific control transfers. The protocol is two
 * requests, no acknowledgements above USB status:
 *
 *   bRequest = 0x30 (FIRMWARE_DOWNLOAD)
 *     bmRequestType = 0x40 (host-to-device, vendor, device)
 *     wValue        = (load_addr + chunk_offset) >> 8  (24-bit hi)
 *     wIndex        = 0
 *     wLength       = chunk_bytes (≤ 4 KiB)
 *     payload       = chunk bytes
 *
 *   bRequest = 0x31 (FIRMWARE_DOWNLOAD_COMP)
 *     bmRequestType = 0x40
 *     wValue        = load_addr >> 8
 *     wIndex        = 0
 *     wLength       = 0  (no payload)
 *
 * The bootrom infers the post-load entry point from `load_addr`
 * and jumps to it on completion. This TU implements the chunk
 * planner so it can be exercised entirely without USB hardware,
 * and exposes a thin USB-bound `Drive` function that drains the
 * plan onto an xHCI-bound slot. Linux reference:
 * `drivers/net/wireless/ath/ath9k/hif_usb.c::ath9k_hif_usb_download_fw`.
 *
 * Threading: caller-owned. Drive() blocks on USB control transfers.
 */

namespace duetos::drivers::net
{

// USB vendor-specific control-transfer request IDs. These are
// hardware ABI numbers defined by the open-ath9k-htc-firmware
// bootrom; copying the constants is fine.
inline constexpr u8 kAthHtcReqFirmwareDownload = 0x30;
inline constexpr u8 kAthHtcReqFirmwareDownloadComplete = 0x31;

// bmRequestType = host→device | vendor | device.
inline constexpr u8 kAthHtcVendorOutDevice = 0x40;

enum class AthHtcUploadStage : u8
{
    Idle = 0,
    PlanReady = 1,
    StreamingChunks = 2,
    SendingComplete = 3,
    Complete = 4,
    Failed = 5,
};

const char* AthHtcUploadStageName(AthHtcUploadStage s);

struct AthHtcUploadResult
{
    bool ok;
    AthHtcUploadStage failed_at;
    u32 chunks_planned;
    u32 chunks_sent;
    u32 bytes_sent;
    u32 last_chunk_bytes;
    u32 last_wvalue; // wValue at the failure / completion point
};

struct AthHtcChunkPlan
{
    u32 offset; // byte offset into the firmware blob
    u32 length; // chunk length in bytes (≤ 4 KiB)
    u32 wvalue; // wValue for the USB control transfer
};

// Maximum chunks for any AR9271/AR7010 image we plan to ship:
// kAthHtcMaxBytes / kAthHtcDownloadChunkBytes = 64 entries. Bound
// the table at 128 to absorb future builds.
inline constexpr u32 kAthHtcMaxPlanChunks = 128;

struct AthHtcUploadPlan
{
    AthHtcTarget target;
    u32 load_address;
    u32 chunk_count;
    AthHtcChunkPlan chunks[kAthHtcMaxPlanChunks];
    u32 finalize_wvalue; // wValue for FIRMWARE_DOWNLOAD_COMPLETE
};

/// Build the chunk plan from a parsed firmware blob. Returns
/// `Corrupt` if the parsed record is not `.valid`, or if the plan
/// would exceed `kAthHtcMaxPlanChunks`. The plan is deterministic
/// and self-tested below; an upload that uses it does not need to
/// re-derive chunk offsets at run time.
::duetos::core::Result<void> AthHtcBuildUploadPlan(const AthHtcFirmwareParsed& parsed, AthHtcUploadPlan* plan);

/// Drive the plan on an xHCI-addressed device slot. Walks every
/// planned chunk, issues `XhciControlOut` with bRequest=0x30, then
/// sends the FIRMWARE_DOWNLOAD_COMPLETE request to start execution.
/// `blob` must remain valid for the duration of the call and must
/// match the plan that produced `plan`. Result fields are populated
/// regardless of success.
::duetos::core::Result<void> AthHtcUploadDrive(u8 slot_id, const u8* blob, u32 blob_size, const AthHtcUploadPlan& plan,
                                               AthHtcUploadResult* result);

void AthHtcUploadSelfTest();

} // namespace duetos::drivers::net
