#pragma once

#include "util/result.h"
#include "util/types.h"

/*
 * DuetOS — vendor-neutral IOMMU facade.
 *
 * Both Intel VT-d and AMD-Vi expose the same conceptual surface
 * (parse the firmware table → decode capability registers → build
 * page tables → enable translation), but the concrete register
 * layouts and ACPI tables differ. This module is the thin
 * dispatcher that boot_bringup calls; vendor-specific work lives
 * in drivers/iommu/{vtd,vtd_paging,dmar,ivrs}.{h,cpp}.
 *
 * v0 wiring matrix:
 *
 *     vendor   parse           reg-decode     paging        enable
 *     ------   -------------   -----------    ---------     ---------
 *     Intel    DmarInit        VtdInit        VtdPagingInit VtdProgramAndEnable
 *     AMD      IvrsInit        TODO           TODO          TODO
 *
 * AMD-Vi register decode / page tables / enable are deferred until
 * an AMD test machine is available; today only the IVRS parser
 * runs. IommuEnableAtBoot logs and skips the AMD path when called
 * on an AMD platform.
 *
 * Context: kernel. IommuInit runs after AcpiInit() (depends on the
 * RSDP cache). IommuEnableAtBoot runs ONCE after IommuInit and is
 * gated by the build-time DUETOS_IOMMU_ENABLE flag.
 */

namespace duetos::drivers::iommu
{

enum class IommuVendor : u8
{
    None,
    Intel,
    Amd,
    Both, // observed both DMAR + IVRS — unusual but spec-permitted
};

/// Parse both vendors' ACPI tables + (Intel only in v0) decode
/// register MMIO + build identity-passthrough page tables. Run
/// after AcpiInit. Always logs which vendor(s) were found.
void IommuInit();

/// Which IOMMU vendor(s) the firmware advertised. Returns None on
/// machines without DMAR or IVRS (most QEMU defaults, VirtualBox).
IommuVendor IommuDetectedVendor();

/// True iff the kernel was built with DUETOS_IOMMU_ENABLE=1 AND
/// at least one vendor reports an IOMMU.
bool IommuEnableEffective();

/// True iff the kernel was built with DUETOS_IOMMU_REQUIRE=1 —
/// when set, a failed IommuEnableAtBoot panics the kernel instead
/// of silently leaving translation off. The deployment-safety
/// gate: release builds set this so the kernel refuses to run
/// without IOMMU protection.
bool IommuRequireEffective();

/// Program every discovered IOMMU and flip translation on. Picks
/// the right vendor path based on what was discovered:
///   - Intel: VtdProgramAndEnable (slice 27d)
///   - AMD: not yet implemented (logs, returns Unsupported)
///   - None: no-op (returns Ok — "nothing to enable" is success)
///
/// Caller is responsible for gating on IommuEnableEffective().
/// When IommuRequireEffective() is true and this function returns
/// an error, the boot path panics — the IOMMU was REQUIRED but
/// the enable failed.
::duetos::core::Result<void> IommuEnableAtBoot();

} // namespace duetos::drivers::iommu
