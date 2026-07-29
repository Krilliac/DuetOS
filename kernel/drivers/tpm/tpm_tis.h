#pragma once

#include "util/result.h"
#include "util/types.h"

/*
 * DuetOS — TPM 2.0 TIS/FIFO transport.
 *
 * Covers the byte pipe only: locality handshake, FIFO write with
 * burst-count flow control, tpmGo, and the response read. It knows
 * nothing about TPM command semantics; `kernel/drivers/tpm/tpm.cpp`
 * owns those and is the only caller.
 *
 * Hardware: the TCG PC Client Platform TPM Profile puts the FIFO
 * interface at a fixed MMIO window, 0x1000 bytes per locality starting
 * at 0xFED40000. That covers both a discrete TPM on LPC/SPI and an
 * fTPM in AMD PSP / Intel PTT — from the OS side they are the same
 * register file, which is why there is one driver and not three.
 *
 * Context: kernel, process context, boot path. Polls with `pause`; no
 * interrupts and no sleeping, so it is safe before the scheduler and
 * before the timer subsystem exists. Timeouts are TSC cycle bounds
 * rather than wall-clock deadlines for exactly that reason (same idiom
 * as `WaitPitTerminal` in arch/x86_64/timer.cpp) — they are safety
 * nets against dead hardware, not calibrated delays.
 *
 * Locking: `TpmTisTransact` is NOT reentrant and does not lock. The
 * command layer in tpm.cpp serialises callers behind its own lock.
 *
 * ABSENCE IS NOT AN ERROR, AND IT IS NEVER FAKED. An unbacked MMIO
 * window reads back all-ones, so a machine with no TPM reports
 * DID/VID = 0xFFFFFFFF. `TpmTisProbe` maps that to `NoDevice` and the
 * driver reports `present=no`. It never reports a TPM that answered
 * zero as absent, and never reports absent hardware as present — the
 * two are distinct observable states and callers can tell them apart.
 */

namespace duetos::drivers::tpm
{

/// Architectural base of locality 0 (TCG PC Client PTP §6).
inline constexpr u64 kTisPhysBase = 0xFED40000;

/// Bytes per locality window; we only ever drive locality 0.
inline constexpr u64 kTisLocalityBytes = 0x1000;

/// What the probe learned about the chip. `vendor_id` 0xFFFF or 0x0000
/// are both rejected as "no responder" rather than reported as a
/// vendor, since they are what an unbacked or wedged bus reads back.
///
/// Deliberately a plain aggregate with NO default member initialisers:
/// `core::Result<T>` stores `T` in a union, which requires a trivial
/// default constructor. Callers value-initialise with `TisIdentity{}`.
struct TisIdentity
{
    u16 vendor_id;
    u16 device_id;
    u8 revision_id;
};

/// Map the TIS window and read TPM_DID_VID / TPM_RID.
///
/// Returns `NoDevice` when the window reads back all-ones or all-zeros
/// (no responder), `OutOfMemory` if the MMIO mapping failed. Success
/// means a chip acknowledged — it does NOT yet mean the chip is a
/// TPM 2.0 or that it is operational; `TpmInit` establishes that by
/// issuing TPM2_Startup and reading a capability.
::duetos::core::Result<TisIdentity> TpmTisProbe();

/// Run one command/response transaction against locality 0.
///
/// `command` / `command_length` is a fully framed TPM 2.0 command.
/// `response` receives the reply including its 10-byte header; the
/// number of bytes read is returned.
///
/// Errors: `NotReady` (chip never reported commandReady), `Timeout`
/// (no response within the cycle bound), `IoError` (chip cleared
/// Expect early, or advertised a zero burst forever), `Truncated`
/// (reply larger than `response_capacity`), `BadState` (probe never
/// ran). The FIFO is left in commandReady on every exit path,
/// including the error ones, so one failed transaction does not wedge
/// the next.
::duetos::core::Result<u32> TpmTisTransact(const u8* command, u32 command_length, u8* response, u32 response_capacity);

/// True once `TpmTisProbe` has succeeded. Transactions before this
/// return `BadState` rather than dereferencing an unmapped window.
bool TpmTisReady();

/// Exercise the burst-count and status-decoding helpers against
/// synthetic register values. Pure logic — does not touch the bus, so
/// it runs identically on a machine with no TPM.
void TpmTisSelfTest();

} // namespace duetos::drivers::tpm
