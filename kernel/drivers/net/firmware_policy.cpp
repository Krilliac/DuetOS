#include "drivers/net/firmware_policy.h"

#include "arch/x86_64/serial.h"
#include "core/panic.h"

namespace duetos::drivers::net
{

namespace
{

constexpr FirmwareSourceFacts kSources[] = {
    {FirmwareFamily::IntelIwlwifi, FirmwareSourceKind::RedistributableBinary, FirmwareDisposition::RuntimePackage,
     "iwlwifi", "Intel Wi-Fi 6/6E/7 PCIe and CNVi families", "linux-firmware iwlwifi-*.ucode / *.pnvm",
     "Intel firmware license: redistributable binary; no source in public linux-firmware packages", false, false, false,
     true, true, true},
    {FirmwareFamily::IntelGpuUc, FirmwareSourceKind::RedistributableBinary, FirmwareDisposition::RuntimePackage,
     "intel-gpu-uc", "Intel Gen9+ graphics GuC/HuC/DMC/GSC firmware", "linux-firmware i915/ and xe/ firmware trees",
     "redistributable binary firmware used by Linux i915/xe; treat as out-of-tree package", false, false, false, true,
     true, true},
    {FirmwareFamily::AtherosAth9kHtc, FirmwareSourceKind::OpenSource, FirmwareDisposition::Preferred, "ath9k-htc-open",
     "Qualcomm Atheros AR7010 / AR9271 USB 802.11n adapters", "qca/open-ath9k-htc-firmware",
     "source-available firmware; mixed permissive/GPL-compatible tree in common distro packages", true, true, true,
     true, false, true},
    {FirmwareFamily::BroadcomB43OpenFwwf, FirmwareSourceKind::OpenSource, FirmwareDisposition::Preferred,
     "b43-openfwwf", "older Broadcom/AirForce BCM4306/4311 rev1/4318/4320 class devices",
     "OpenFWWF / b43-openfwwf distro packages",
     "GPL-2.0-only open firmware; limited feature set compared with proprietary b43 blobs", true, true, true, true,
     false, true},
    {FirmwareFamily::BroadcomBrcmFullMac, FirmwareSourceKind::PatchFramework, FirmwareDisposition::ResearchOnly,
     "nexmon-brcm", "Broadcom/Cypress FullMAC chips used by phones and some laptops",
     "Nexmon firmware patching framework",
     "open patching framework, but normal workflow depends on proprietary base firmware images", true, true, false,
     false, true, true},
    {FirmwareFamily::RealtekRtl88xx, FirmwareSourceKind::RedistributableBinary, FirmwareDisposition::RuntimePackage,
     "rtl88xx", "Realtek rtlwifi/rtw88/rtw89 USB and PCIe devices", "linux-firmware realtek/rtlwifi blobs",
     "redistributable binary firmware; no generally usable open replacement for current targets", false, false, false,
     true, true, true},
    {FirmwareFamily::MediatekMt76, FirmwareSourceKind::RedistributableBinary, FirmwareDisposition::RuntimePackage,
     "mt76", "MediaTek MT7615 / MT7663 / MT7915/16 / MT7921/22/25 Wi-Fi (very common in 2021+ AMD/Intel laptops)",
     "linux-firmware mediatek/ blobs",
     "redistributable binary firmware under MediaTek's firmware licence; no open replacement available", false, false,
     false, true, true, true},
};

constexpr u32 kSourceCount = sizeof(kSources) / sizeof(kSources[0]);

bool Streq(const char* a, const char* b)
{
    if (a == nullptr || b == nullptr)
        return false;
    while (*a != '\0' && *b != '\0')
    {
        if (*a != *b)
            return false;
        ++a;
        ++b;
    }
    return *a == '\0' && *b == '\0';
}

} // namespace

const char* FirmwareFamilyName(FirmwareFamily family)
{
    switch (family)
    {
    case FirmwareFamily::IntelIwlwifi:
        return "intel-iwlwifi";
    case FirmwareFamily::IntelGpuUc:
        return "intel-gpu-uc";
    case FirmwareFamily::AtherosAth9kHtc:
        return "ath9k-htc";
    case FirmwareFamily::BroadcomB43OpenFwwf:
        return "b43-openfwwf";
    case FirmwareFamily::BroadcomBrcmFullMac:
        return "brcm-fullmac";
    case FirmwareFamily::RealtekRtl88xx:
        return "rtl88xx";
    case FirmwareFamily::MediatekMt76:
        return "mediatek-mt76";
    }
    return "unknown";
}

const char* FirmwareSourceKindName(FirmwareSourceKind kind)
{
    switch (kind)
    {
    case FirmwareSourceKind::OpenSource:
        return "open-source";
    case FirmwareSourceKind::RedistributableBinary:
        return "redistributable-binary";
    case FirmwareSourceKind::ExtractedVendorBinary:
        return "extracted-vendor-binary";
    case FirmwareSourceKind::PatchFramework:
        return "patch-framework";
    }
    return "unknown";
}

const char* FirmwareDispositionName(FirmwareDisposition disposition)
{
    switch (disposition)
    {
    case FirmwareDisposition::Preferred:
        return "preferred";
    case FirmwareDisposition::RuntimePackage:
        return "runtime-package";
    case FirmwareDisposition::ResearchOnly:
        return "research-only";
    case FirmwareDisposition::Reject:
        return "reject";
    }
    return "unknown";
}

const FirmwareSourceFacts* FirmwarePolicyFind(FirmwareFamily family)
{
    for (u32 i = 0; i < kSourceCount; ++i)
    {
        if (kSources[i].family == family)
            return &kSources[i];
    }
    return nullptr;
}

const FirmwareSourceFacts* FirmwarePolicyFindByName(const char* short_name)
{
    for (u32 i = 0; i < kSourceCount; ++i)
    {
        if (Streq(kSources[i].short_name, short_name))
            return &kSources[i];
    }
    return nullptr;
}

bool FirmwarePolicyCanBundle(const FirmwareSourceFacts& facts)
{
    return facts.disposition == FirmwareDisposition::Preferred && facts.source_available &&
           facts.modification_allowed && facts.may_ship_in_tree;
}

bool FirmwarePolicyCanLoadRuntime(const FirmwareSourceFacts& facts)
{
    if (FirmwarePolicyCanBundle(facts))
        return true;
    return facts.disposition == FirmwareDisposition::RuntimePackage && !facts.may_ship_in_tree &&
           facts.may_ship_as_release_artifact && facts.requires_license_notice && facts.requires_exact_hash;
}

void FirmwarePolicySelfTest()
{
    const FirmwareSourceFacts* iwl = FirmwarePolicyFind(FirmwareFamily::IntelIwlwifi);
    KASSERT(iwl != nullptr, "drivers/net/firmware_policy", "missing iwlwifi policy");
    KASSERT(!FirmwarePolicyCanBundle(*iwl), "drivers/net/firmware_policy", "iwlwifi blob should not bundle");
    KASSERT(FirmwarePolicyCanLoadRuntime(*iwl), "drivers/net/firmware_policy", "iwlwifi should be runtime-loadable");
    KASSERT(iwl->may_ship_as_release_artifact, "drivers/net/firmware_policy",
            "iwlwifi should be allowed in release firmware kit");
    KASSERT(iwl->requires_license_notice && iwl->requires_exact_hash, "drivers/net/firmware_policy",
            "iwlwifi runtime firmware needs notice + exact hash");

    const FirmwareSourceFacts* ath = FirmwarePolicyFindByName("ath9k-htc-open");
    KASSERT(ath != nullptr, "drivers/net/firmware_policy", "missing ath9k policy");
    KASSERT(FirmwarePolicyCanBundle(*ath), "drivers/net/firmware_policy", "ath9k open firmware should bundle");
    KASSERT(FirmwarePolicyCanLoadRuntime(*ath), "drivers/net/firmware_policy", "ath9k open firmware should load");
    KASSERT(ath->may_ship_as_release_artifact && !ath->requires_license_notice, "drivers/net/firmware_policy",
            "ath9k open firmware kit flags wrong");

    const FirmwareSourceFacts* nexmon = FirmwarePolicyFind(FirmwareFamily::BroadcomBrcmFullMac);
    KASSERT(nexmon != nullptr, "drivers/net/firmware_policy", "missing nexmon policy");
    KASSERT(!FirmwarePolicyCanBundle(*nexmon), "drivers/net/firmware_policy", "nexmon should not bundle");
    KASSERT(!FirmwarePolicyCanLoadRuntime(*nexmon), "drivers/net/firmware_policy", "nexmon should stay research-only");

    const FirmwareSourceFacts* mt76 = FirmwarePolicyFind(FirmwareFamily::MediatekMt76);
    KASSERT(mt76 != nullptr, "drivers/net/firmware_policy", "missing mt76 policy");
    KASSERT(!FirmwarePolicyCanBundle(*mt76), "drivers/net/firmware_policy", "mt76 blob should not bundle");
    KASSERT(FirmwarePolicyCanLoadRuntime(*mt76), "drivers/net/firmware_policy", "mt76 should be runtime-loadable");

    KASSERT(FirmwarePolicyFindByName("does-not-exist") == nullptr, "drivers/net/firmware_policy",
            "unknown firmware name should miss");
    KASSERT(FirmwareDispositionName(FirmwareDisposition::Preferred)[0] == 'p', "drivers/net/firmware_policy",
            "disposition name mismatch");

    arch::SerialWrite("[firmware-policy] selftest pass\n");
}

} // namespace duetos::drivers::net
