#pragma once

#include "ivrs_rust.h"
#include "util/types.h"

/*
 * DuetOS — AMD-Vi IVRS discovery + parse.
 *
 * Mirror of kernel/drivers/iommu/dmar.h (Intel VT-d) for AMD.
 * Walks the ACPI IVRS table at boot and surfaces:
 *   - whether IVRS is reported by firmware,
 *   - IVHD entries: each one is an AMD-Vi IOMMU with a base MMIO
 *     address, PCI segment, and (for extended IVHD types 0x11/0x40)
 *     a cached EFR (Extended Feature Register) image.
 *   - IVMD entries: must-identity-map memory regions, analogous to
 *     VT-d's RMRR.
 *
 * Parser only — no register access, no IOMMU enable. AMD-Vi
 * register decode + page tables + enable belong in separate slices
 * (28b/c/d, mirroring the VT-d sequence).
 *
 * Context: kernel. IvrsInit runs once after AcpiInit(); the IVRS
 * table address is fetched via acpi::AcpiFindTablePhys.
 */

namespace duetos::drivers::iommu
{

/// Locate the ACPI IVRS table, parse it through the Rust walker,
/// and cache the result. Idempotent. Logs
/// `[ivrs] present=...` so the boot log records whether AMD-Vi
/// is reported.
void IvrsInit();

/// True when firmware reported an IVRS AND the parse succeeded.
/// False on Intel-only / QEMU-default / VirtualBox; false on AMD
/// boxes with a malformed IVRS.
bool IvrsPresent();

/// 4-byte IVinfo field from the IVRS header. Bits decoded by AMD
/// IOMMU spec §5.2 — PASmax, PA size, VA size, EFR support.
/// Returns 0 if !IvrsPresent.
u32 IvrsInfo();

u32 IvrsIvhdCount();
const ivrs::DuetosIvrsIvhd* IvrsIvhd(u32 index);

u32 IvrsIvmdCount();
const ivrs::DuetosIvrsIvmd* IvrsIvmd(u32 index);

/// Boot-time self-test. Synthesises an IVRS (one fixed IVHD +
/// one extended IVHD + one IVMD), passes it through the Rust
/// parser, asserts every field round-trips. Saves/restores live
/// cached state so it's safe to call after IvrsInit on real
/// firmware. Emits `[ivrs-selftest] PASS`.
void IvrsSelfTest();

} // namespace duetos::drivers::iommu
