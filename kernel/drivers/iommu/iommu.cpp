#include "drivers/iommu/iommu.h"

#include "arch/x86_64/serial.h"
#include "core/panic.h"
#include "drivers/iommu/dmar.h"
#include "drivers/iommu/ivrs.h"
#include "drivers/iommu/vtd.h"
#include "drivers/iommu/vtd_paging.h"

namespace duetos::drivers::iommu
{

void IommuInit()
{
    // Intel side: DMAR parse → VtdInit (register decode) →
    // VtdPagingInit (page tables). Each is a no-op when its
    // predecessor produced no data.
    DmarInit();
    VtdInit();
    if (VtdAvailable())
    {
        auto paging = vtd_paging::VtdPagingInit();
        if (!paging.has_value())
        {
            arch::SerialWrite("[iommu] VtdPagingInit failed — VT-d enable path will be unavailable\n");
        }
    }

    // AMD side: IVRS parse. Register decode + page tables + enable
    // are future slices (28b/c/d). Today the parser surfaces what
    // was found and the enable path below logs Unsupported.
    IvrsInit();
}

IommuVendor IommuDetectedVendor()
{
    const bool intel = DmarPresent();
    const bool amd = IvrsPresent();
    if (intel && amd)
        return IommuVendor::Both;
    if (intel)
        return IommuVendor::Intel;
    if (amd)
        return IommuVendor::Amd;
    return IommuVendor::None;
}

bool IommuEnableEffective()
{
    return VtdEnableRequested() && IommuDetectedVendor() != IommuVendor::None;
}

bool IommuRequireEffective()
{
#if defined(DUETOS_IOMMU_REQUIRE) && DUETOS_IOMMU_REQUIRE
    return true;
#else
    return false;
#endif
}

::duetos::core::Result<void> IommuEnableAtBoot()
{
    const IommuVendor v = IommuDetectedVendor();
    if (v == IommuVendor::None)
    {
        arch::SerialWrite("[iommu] no IOMMU present — nothing to enable\n");
        return {};
    }
    if (v == IommuVendor::Amd)
    {
        // AMD-Vi enable not yet implemented. Surface that fact
        // without panic; IommuRequireEffective callers will catch
        // the Unsupported and panic at the boot site.
        arch::SerialWrite("[iommu] AMD-Vi enable not yet implemented — translation remains off\n");
        return ::duetos::core::Err{::duetos::core::ErrorCode::Unsupported};
    }
    // Intel or Both: enable Intel VT-d. The AMD half of `Both`
    // would also enable here once 28d lands.
    return VtdProgramAndEnable();
}

} // namespace duetos::drivers::iommu
