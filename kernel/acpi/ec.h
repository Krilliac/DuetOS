#pragma once

#include "util/types.h"

/*
 * DuetOS — ACPI Embedded Controller (EC) driver, v0.
 *
 * The EC is the laptop microcontroller behind battery state, AC
 * presence, lid, thermal and Fn-keys. ACPI talks to it through the
 * `EmbeddedControl` OperationRegion: the AML method interpreter
 * (aml_eval.cpp) calls a registered region handler, and THIS driver
 * is that handler.
 *
 * Transport: the de-facto-standard ACPI EC IO ports — 0x66
 * (command/status, EC_SC) and 0x62 (data, EC_DATA). Single-byte
 * polled transactions (RD_EC / WR_EC) with a bounded busy-wait on
 * the monotonic clock. Burst mode and SCI/_Qxx query dispatch are
 * not used in v0.
 *
 * Presence is firmware-driven: an EC exists iff the namespace
 * declared an `EmbeddedControl` OperationRegion (recorded by the
 * AML region index in aml.cpp). On platforms without one (e.g.
 * QEMU's default machine) the driver reports absent, registers no
 * handler, and every EC field reads back as Ones — the correct,
 * non-crashing v0 behaviour.
 *
 * GAP: EC IO ports are assumed 0x66/0x62 rather than parsed from
 * the ECDT table or the PNP0C09 `_CRS` — revisit if a target board
 * relocates them (rare on x86). No burst mode, no GPE/_Qxx query
 * handler (battery/lid still work via polled _BST/_PSR/_LID).
 *
 * Context: kernel, process context only (polled busy-wait). Init
 * runs once after the AML namespace is built.
 */

namespace duetos::acpi
{

/// Detect the EC (EmbeddedControl region present?), latch the IO
/// ports, and — if present — register the EmbeddedControl region
/// handler with the AML interpreter. Idempotent.
void AcpiEcInit();

/// True iff an EC was detected and the region handler is live.
bool AcpiEcPresent();

/// Read / write one byte of EC address space (0x00..0xFF). Returns
/// false if the EC is absent or the transaction timed out.
bool AcpiEcRead(u8 addr, u8* value);
bool AcpiEcWrite(u8 addr, u8 value);

/// Boot self-test: asserts init is idempotent and that — when the
/// EC is absent (the QEMU case) — reads fail cleanly rather than
/// hanging or faulting. Emits one `[acpi/ec] selftest PASS` line.
void AcpiEcSelfTest();

} // namespace duetos::acpi
