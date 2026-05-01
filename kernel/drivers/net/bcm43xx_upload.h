#pragma once

#include "drivers/net/bcm43xx_fw.h"
#include "drivers/net/net.h"
#include "util/result.h"
#include "util/types.h"

/*
 * DuetOS — Broadcom bcm43xx microcode upload state machine.
 *
 * The b43 protocol uploads microcode through the SHM (Shared
 * Memory) interface mapped via the SiBA / Backplane bus. The
 * sequence:
 *
 *   1. Bring the chip out of reset via ChipCommon CORE_CTL.
 *   2. Stop the MAC core (write 0x10 to MACCTL register).
 *   3. Window each ucode/pcm/iv record into SHM via SHM_CONTROL +
 *      SHM_DATA_WORD writes. The MMIO window is at offset 0x100.
 *   4. Issue MACCTL_PSM_RUN; poll IRQS register for SUCCESS bit.
 *
 * v0 records the intent for each step + every register write.
 * Reference: Linux drivers/net/wireless/broadcom/b43/main.c
 * (`b43_upload_microcode`, `b43_run_initvals`).
 */

namespace duetos::drivers::net
{

inline constexpr u32 kBcmRegMacCtl = 0x120;
inline constexpr u32 kBcmRegShmControl = 0x160;
inline constexpr u32 kBcmRegShmData = 0x164;
inline constexpr u32 kBcmRegIrqs = 0x158;
inline constexpr u32 kBcmRegIrqMask = 0x150;

inline constexpr u32 kBcmMacCtlPsmRun = 1u << 1;
inline constexpr u32 kBcmMacCtlEnabled = 1u << 0;
inline constexpr u32 kBcmIrqMacSuspended = 1u << 1;
inline constexpr u32 kBcmIrqUcodeStarted = 1u << 26;

inline constexpr u32 kBcmShmUcode = 0x0000;
inline constexpr u32 kBcmShmPcm = 0x4000;

enum class BcmUploadStage : u8
{
    Idle = 0,
    BringOutOfReset = 1,
    StopMac = 2,
    UploadUcode = 3,
    UploadPcm = 4,
    UploadIv = 5,
    StartUcode = 6,
    Complete = 7,
    Failed = 8,
};

const char* BcmUploadStageName(BcmUploadStage s);

struct BcmUploadResult
{
    bool ok;
    BcmUploadStage failed_at;
    u32 ucode_words_written;
    u32 pcm_words_written;
    u32 iv_words_written;
    u32 last_irqs;
    u32 ucode_started_polls;
};

::duetos::core::Result<void> BcmUploadDrive(NicInfo& n, const BcmFirmwareParsed& parsed, BcmUploadResult* result);

void BcmUploadSelfTest();

} // namespace duetos::drivers::net
