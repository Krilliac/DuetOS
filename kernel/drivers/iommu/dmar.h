#pragma once

#include "dmar_rust.h"
#include "util/types.h"

/*
 * DuetOS — Intel VT-d DMAR discovery + parse.
 *
 * Walks the ACPI DMAR table at boot, surfaces:
 *   - whether VT-d is reported by firmware at all,
 *   - the Host Address Width (HAW) — the physical-address width the
 *     IOMMU must address-translate,
 *   - the DMA Remapping Hardware Unit Definitions (DRHDs) — each
 *     one of these is a distinct IOMMU MMIO base + segment.
 *   - the Reserved Memory Region Reporting (RMRR) entries that any
 *     IOMMU page tables MUST identity-map (legacy USB ECRC, VGA
 *     framebuffer hand-off, etc.).
 *
 * This module is a *parser*, not an enabler. It does not touch any
 * IOMMU register set; that's a separate slice that consumes this
 * module's output. The byte-walker itself is in Rust (the
 * `duetos_dmar` crate); the C++ wrapper here owns the cached state
 * and the boot-bringup hook.
 *
 * Context: kernel. DmarInit() runs once after AcpiInit() — the
 * DMAR table address is fetched via acpi::AcpiFindTablePhys.
 */

namespace duetos::drivers::iommu
{

/// Locate the ACPI DMAR table, parse it through the Rust walker,
/// and cache the result. Idempotent. Logs `[dmar] present=...` at
/// the end so the boot log records whether VT-d is reported.
void DmarInit();

/// True when firmware reported a DMAR AND the parse succeeded.
/// False on machines without VT-d (QEMU-default, VirtualBox), and
/// on machines with a malformed table.
bool DmarPresent();

/// Host Address Width from the DMAR header (0 if !DmarPresent).
/// `HAW + 1` is the number of physical-address bits the IOMMU
/// supports.
u8 DmarHostAddressWidth();

/// DMAR header flags bitmask (0 if !DmarPresent). Bits per
/// kDmarHeaderFlag*.
u8 DmarHeaderFlags();

/// Number of DRHD entries cached (0 if !DmarPresent).
u32 DmarDrhdCount();

/// Get the i-th DRHD. Returns nullptr for out-of-range.
const dmar::DuetosDmarDrhd* DmarDrhd(u32 index);

/// Number of RMRR entries cached.
u32 DmarRmrrCount();

/// Get the i-th RMRR. Returns nullptr for out-of-range.
const dmar::DuetosDmarRmrr* DmarRmrr(u32 index);

/// Boot-time self-test. Synthesises a small DMAR (one DRHD + one
/// RMRR), passes it through `duetos_dmar_parse`, and asserts that
/// every field round-trips correctly. Also exercises the malformed-
/// table rejection paths. Saves/restores live cached state so it's
/// safe to call after DmarInit on real firmware. Emits
/// `[dmar-selftest] PASS` on success; panics on a wrong result.
void DmarSelfTest();

} // namespace duetos::drivers::iommu
