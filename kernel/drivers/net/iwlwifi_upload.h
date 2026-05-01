#pragma once

#include "drivers/net/iwlwifi_fw.h"
#include "drivers/net/net.h"
#include "util/result.h"
#include "util/types.h"

/*
 * DuetOS — iwlwifi microcode upload state machine.
 *
 * Drives the per-silicon reset → power-up → microcode-copy →
 * ALIVE-wait sequence. Each step writes one of the CSR (Control
 * + Status Register) bits documented by Intel and mirrors the
 * shape of Linux's `iwlwifi/pcie/trans-gen2.c::iwl_pcie_load_*`
 * paths, but adapted for the freestanding DuetOS environment.
 *
 * Heavy diag logging is the core feature: this code ships
 * untested on the dev host (no QEMU emulation of iwlwifi), so
 * every state transition, every register read/write, every
 * timeout records a `wifi-diag` event on `Layer::FwUpload`. A
 * crash dump from real hardware will carry the entire upload
 * timeline so a remote debug cycle is tractable.
 *
 * Scope (v0):
 *   - 7000-series and later (modern iwlwifi). 1000/4965/5000
 *     legacy paths share the same skeleton but use different
 *     bits in CSR_RESET; we record but don't drive them yet.
 *   - Non-secure-boot path (the secure-boot variant requires a
 *     code-signing chain we don't have).
 *
 * Reference register map: Linux
 * `drivers/net/wireless/intel/iwlwifi/iwl-csr.h`. Constants are
 * Intel hardware ABI — copying the numeric offsets is fine.
 */

namespace duetos::drivers::net
{

// CSR register offsets (BAR0-relative).
inline constexpr u32 kCsrReset = 0x020;
inline constexpr u32 kCsrEepromReg = 0x02C;
inline constexpr u32 kCsrIntCoalescing = 0x004;
inline constexpr u32 kCsrInt = 0x008;
inline constexpr u32 kCsrIntMask = 0x00C;
inline constexpr u32 kCsrFhIntStatus = 0x010;
inline constexpr u32 kCsrGpioIn = 0x018;
inline constexpr u32 kCsrGpCntrlReg = 0x024;
inline constexpr u32 kCsrHwRevReg = 0x028;
inline constexpr u32 kCsrEepromGp = 0x030;
inline constexpr u32 kCsrOtpGp = 0x034;
inline constexpr u32 kCsrUcodeDrvGp1 = 0x054;
inline constexpr u32 kCsrUcodeDrvGp1Set = 0x058;
inline constexpr u32 kCsrUcodeDrvGp1Clr = 0x05C;
inline constexpr u32 kCsrLedReg = 0x094;
inline constexpr u32 kCsrDramIntTblReg = 0x0A0;
inline constexpr u32 kCsrMboxSet = 0x0AC;
inline constexpr u32 kCsrMacShadowingReg = 0x0A8;

// CSR_RESET bits.
inline constexpr u32 kCsrResetSwReset = 1u << 7;
inline constexpr u32 kCsrResetMaster = 1u << 8;
inline constexpr u32 kCsrResetStopMaster = 1u << 9;
inline constexpr u32 kCsrResetForceNmi = 1u << 11;

// CSR_GP_CNTRL bits (subset).
inline constexpr u32 kCsrGpCntrlMacAccessReq = 1u << 3;
inline constexpr u32 kCsrGpCntrlMacAccessEna = 1u << 0;
inline constexpr u32 kCsrGpCntrlMacInitDone = 1u << 2;
inline constexpr u32 kCsrGpCntrlMacClockReady = 1u << 0;
inline constexpr u32 kCsrGpCntrlInitDone = 1u << 2;
inline constexpr u32 kCsrGpCntrlMacWakeup = 1u << 3;

// Interrupt source bits.
inline constexpr u32 kCsrIntBitFhRx = 1u << 31;
inline constexpr u32 kCsrIntBitHwErr = 1u << 29;
inline constexpr u32 kCsrIntBitRxPeriodic = 1u << 28;
inline constexpr u32 kCsrIntBitFhTx = 1u << 27;
inline constexpr u32 kCsrIntBitScd = 1u << 26;
inline constexpr u32 kCsrIntBitAlive = 1u << 0;
inline constexpr u32 kCsrIntBitWakeup = 1u << 1;
inline constexpr u32 kCsrIntBitSwRx = 1u << 3;

// Driver-firmware mailbox bits in UCODE_DRV_GP1.
inline constexpr u32 kCsrUcodeDrvGp1ResetCmd = 1u << 0;
inline constexpr u32 kCsrUcodeDrvGp1AliveOk = 1u << 1;

enum class IwlUploadStage : u8
{
    Idle = 0,
    PrepareCard = 1,
    SwReset = 2,
    NicInit = 3,
    SectionLoad = 4,
    AliveWait = 5,
    Complete = 6,
    Failed = 7,
};

const char* IwlUploadStageName(IwlUploadStage s);

inline constexpr u32 kIwlUploadDefaultTimeoutTicks = 200; // 2s @ 100Hz

struct IwlUploadResult
{
    bool ok;
    IwlUploadStage failed_at;
    u32 last_csr_int; // captured when the upload halted
    u32 last_gp_cntrl;
    u32 sections_uploaded;
    u32 bytes_uploaded;
    u32 alive_wait_polls;
};

/// Drive the upload state machine. Call once per BringUp after
/// `IwlFirmwareParse` succeeds. Returns Ok if ALIVE is asserted
/// before the timeout; populates `result` either way for caller
/// diagnostics.
::duetos::core::Result<void> IwlUploadDrive(NicInfo& n, const IwlFirmwareParsed& parsed, IwlUploadResult* result);

void IwlUploadSelfTest();

} // namespace duetos::drivers::net
