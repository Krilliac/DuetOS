#pragma once

#include "drivers/net/net.h"
#include "drivers/net/rtl88xx_fw.h"
#include "util/result.h"
#include "util/types.h"

/*
 * DuetOS — Realtek rtl88xx microcode upload state machine.
 *
 * Realtek silicon uses a different upload protocol than Intel:
 * the firmware is copied through the chip's TX FIFO via the
 * `H2C` (host-to-chip) command channel, not via a DMA pull
 * engine. The firmware blob is divided into 4 KiB pages (rtlwifi
 * v1) or signature-prefixed sections (rtw88/rtw89).
 *
 * Sequence:
 *   1. Read REG_MCUFWDL (0x0080) to confirm driver mode.
 *   2. Set FWDL_ENABLE bit; wait for FWDL_READY.
 *   3. Page-by-page write firmware bytes through REG_FW_START_ADDRESS
 *      (0x0080..0x10F0 windowed).
 *   4. Set FWDL_CHKSUM_RPT; wait for ROM_DLREADY.
 *   5. Set H2C_INIT bit; wait for H2C_INIT_OK.
 *
 * Reference: Linux drivers/net/wireless/realtek/rtlwifi/rtl8821ae/fw.c.
 */

namespace duetos::drivers::net
{

inline constexpr u32 kRtlRegMcuFwDl = 0x0080;
inline constexpr u32 kRtlRegHmeBoxExt = 0x01F0;
inline constexpr u32 kRtlRegHmeBoxNum = 0x01D0;
inline constexpr u32 kRtlRegSysFunctionEnable = 0x0002;

inline constexpr u8 kRtlFwDlEnable = 0x01;
inline constexpr u8 kRtlFwDlReady = 0x02;
inline constexpr u8 kRtlFwDlChksumRpt = 0x04;
inline constexpr u8 kRtlFwDlRomDlReady = 0x08;
inline constexpr u8 kRtlFwDlH2cInit = 0x10;
inline constexpr u8 kRtlFwDlH2cInitOk = 0x20;

inline constexpr u32 kRtlFwPageBytes = 4096;
inline constexpr u32 kRtlUploadDefaultTimeoutTicks = 200; // 2s

enum class RtlUploadStage : u8
{
    Idle = 0,
    EnableFwDl = 1,
    PageWrite = 2,
    ChecksumWait = 3,
    H2cInit = 4,
    Complete = 5,
    Failed = 6,
};

const char* RtlUploadStageName(RtlUploadStage s);

struct RtlUploadResult
{
    bool ok;
    RtlUploadStage failed_at;
    u32 pages_written;
    u32 bytes_written;
    u32 last_mcu_fwdl;
    u32 chksum_wait_polls;
    u32 h2c_init_polls;
};

::duetos::core::Result<void> RtlUploadDrive(NicInfo& n, const RtlFirmwareParsed& parsed, RtlUploadResult* result);

void RtlUploadSelfTest();

} // namespace duetos::drivers::net
