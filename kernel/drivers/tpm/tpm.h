#pragma once

#include "util/result.h"
#include "util/types.h"

/*
 * DuetOS — TPM 2.0 command layer (sealing half only).
 *
 * Sits on `drivers/tpm/tpm_tis` (byte pipe) and `drivers/tpm/tpm_wire`
 * (marshalling) and exposes the small set of operations DuetOS is
 * willing to perform. Read the header of `tpm_wire.h` before extending
 * this file: the set of commands that may reach the bus is an
 * allow-list, and the identity half is permanently excluded from it.
 *
 * WHAT THIS DELIBERATELY DOES NOT EXPOSE, at any privilege level:
 *   - the endorsement key, its public half, or its certificate
 *   - attestation identity keys
 *   - quote signing or any other signed assertion
 *   - a raw "submit this buffer to the TPM" entrypoint
 *
 * That last one matters as much as the others. A generic passthrough
 * would let any caller hand-marshal TPM2_Quote and defeat the
 * allow-list, so every operation below is a typed function that builds
 * its own command. There is intentionally no way to say "send these
 * bytes".
 *
 * Context: kernel. `TpmInit` runs once from BootBringupKernelServices
 * alongside the other ACPI-discovered drivers. Every entrypoint below
 * takes `g_tpm_lock` and may spin for milliseconds; none may be called
 * from an interrupt handler.
 *
 * On a machine with no TPM every operation returns `NoDevice`. That is
 * a distinct answer from a TPM that answered — no path in this file
 * ever substitutes a zero, an empty digest, or a fabricated success
 * for an absent chip.
 */

namespace duetos::drivers::tpm
{

/// Chip identity. This is a MODEL identifier (vendor / part / stepping),
/// not a unit identifier — every chip of the same part reports the same
/// values, so it cannot single out a machine. It is surfaced to the
/// kernel shell for diagnostics and is not reachable from ring 3.
struct TpmIdentity
{
    u16 vendor_id = 0;
    u16 device_id = 0;
    u8 revision_id = 0;
    bool started = false; // TPM2_Startup accepted (or was already done)
};

/// Probe the TIS window, start the TPM if firmware has not, and mix a
/// sample of its RNG into the kernel entropy pool. Safe to call once;
/// later calls are no-ops. Never panics — a missing or broken TPM
/// degrades to `present=no` and the rest of boot continues.
void TpmInit();

/// True iff a TPM responded to the probe AND accepted TPM2_Startup.
/// A chip that answered the bus but failed startup is NOT present for
/// the purposes of sealing, and reports so rather than half-working.
bool TpmPresent();

/// Identity as read at probe. Zeroed when `TpmPresent()` is false.
TpmIdentity TpmGetIdentity();

/// Fill `out` with `length` bytes from the TPM's hardware RNG.
///
/// The TPM may return fewer bytes per command than requested; this
/// loops until `length` is satisfied or the chip stops making
/// progress. Returns `NoDevice` with no TPM, `IoError` if the chip
/// returns a short read twice in a row.
///
/// NOTE: kernel callers should normally use `core::RandomFillBytes`
/// instead. This is the source that feeds it, not a competitor to it —
/// `TpmInit` mixes TPM output into the shared pool, so the pool already
/// carries this entropy and cannot be made worse by it.
::duetos::core::Result<void> TpmGetRandom(u8* out, u32 length);

/// Read one SHA-256 bank PCR. `index` must be < 24.
::duetos::core::Result<void> TpmPcrRead(u32 index, u8 out_digest[32]);

/// Extend one SHA-256 bank PCR: PCR[index] = SHA256(PCR[index] || digest).
///
/// Extension is one-way and cannot be undone short of a platform
/// reset, which is the entire point — it is what makes a PCR a
/// tamper-evident record of what ran.
::duetos::core::Result<void> TpmPcrExtend(u32 index, const u8 digest[32]);

/// Software mirror of the PCR extend rule, for computing an expected
/// value without touching hardware. `pcr` is updated in place.
void TpmPcrExtendSoftware(u8 pcr[32], const u8 digest[32]);

/// Boot self-test. The wire/decode assertions always run; the live
/// round-trip (GetRandom + PCR read) only runs when a TPM is present,
/// and reports which of the two it did so a passing line can never be
/// mistaken for evidence about hardware that is not there.
void TpmSelfTest();

} // namespace duetos::drivers::tpm
