// test_nic_ids.cpp — host tests for kernel/drivers/net/nic_ids.h.
//
// Covers the NIC PCI-ID classification tables: the Intel wired-family
// dispatch (the e1000 bring-up gate must never fire on igb / igc /
// ixgbe / i40e silicon whose IDs interleave with the e1000e space),
// the wireless matcher predicates shared by net.cpp and the wireless
// driver shells, the Broadcom firmware chip-name formatting rule, and
// the family-string wireless heuristic.
//
// The header is freestanding (util/types.h only), so no kernel TU is
// linked.

#include "drivers/net/nic_ids.h"
#include "drivers/net/mt76.h"
#include "host_test_helper.h"

using namespace duetos;
using namespace duetos::drivers::net;
using namespace duetos::drivers::net::nic_ids;

namespace
{

void TestIntelWiredDispatch()
{
    // Classic e1000 is an explicit PCI table, never a numeric range.
    EXPECT_EQ(IntelWiredFamilyFromDeviceId(0x1000), IntelWiredFamily::E1000Classic); // 82542
    EXPECT_EQ(IntelWiredFamilyFromDeviceId(0x100E), IntelWiredFamily::E1000Classic); // 82540EM (QEMU default)
    EXPECT_EQ(IntelWiredFamilyFromDeviceId(0x107C), IntelWiredFamily::E1000Classic);
    EXPECT_EQ(IntelWiredFamilyFromDeviceId(0x107F), IntelWiredFamily::E1000e); // 82572EI serdes
    EXPECT_EQ(IntelWiredFamilyFromDeviceId(0x108A), IntelWiredFamily::E1000Classic);
    EXPECT_EQ(IntelWiredFamilyFromDeviceId(0x2E6E), IntelWiredFamily::E1000Classic);
    EXPECT_EQ(IntelWiredFamilyFromDeviceId(0x0FFF), IntelWiredFamily::None);
    EXPECT_EQ(IntelWiredFamilyFromDeviceId(0x1080), IntelWiredFamily::None);

    // Intel e100/8255x IDs occupy holes in the former 0x1000..0x107f
    // range and must never reach the e1000 MMIO path.
    const u16 kIncompatibleE100[] = {0x1029, 0x1030, 0x103E, 0x1050, 0x1057, 0x1059, 0x1064, 0x106B};
    for (const u16 did : kIncompatibleE100)
    {
        EXPECT_EQ(IntelWiredFamilyFromDeviceId(did), IntelWiredFamily::None);
        EXPECT_FALSE(IntelE1000BringUpEligible(did));
    }

    // Common e1000e parts.
    EXPECT_EQ(IntelWiredFamilyFromDeviceId(0x10D3), IntelWiredFamily::E1000e); // 82574L (QEMU e1000e)
    EXPECT_EQ(IntelWiredFamilyFromDeviceId(0x1502), IntelWiredFamily::E1000e); // 82579LM
    EXPECT_EQ(IntelWiredFamilyFromDeviceId(0x153A), IntelWiredFamily::E1000e); // i217-LM
    EXPECT_EQ(IntelWiredFamilyFromDeviceId(0x155A), IntelWiredFamily::E1000e); // i218-LM
    EXPECT_EQ(IntelWiredFamilyFromDeviceId(0x156F), IntelWiredFamily::E1000e); // i219-LM
    EXPECT_EQ(IntelWiredFamilyFromDeviceId(0x15E3), IntelWiredFamily::E1000e); // i219-LM5

    // igb silicon that the old range-based gate mis-dispatched.
    EXPECT_EQ(IntelWiredFamilyFromDeviceId(0x10C9), IntelWiredFamily::Igb); // 82576
    EXPECT_EQ(IntelWiredFamilyFromDeviceId(0x1521), IntelWiredFamily::Igb); // I350
    EXPECT_EQ(IntelWiredFamilyFromDeviceId(0x1533), IntelWiredFamily::Igb); // I210
    EXPECT_EQ(IntelWiredFamilyFromDeviceId(0x1539), IntelWiredFamily::Igb); // I211

    // igc (I225/I226 2.5 G).
    EXPECT_EQ(IntelWiredFamilyFromDeviceId(0x15F2), IntelWiredFamily::Igc); // I225-LM
    EXPECT_EQ(IntelWiredFamilyFromDeviceId(0x15F3), IntelWiredFamily::Igc); // I225-V
    EXPECT_EQ(IntelWiredFamilyFromDeviceId(0x125B), IntelWiredFamily::Igc); // I226-LM

    // ixgbe 10 G.
    EXPECT_EQ(IntelWiredFamilyFromDeviceId(0x10B6), IntelWiredFamily::Ixgbe); // 82598
    EXPECT_EQ(IntelWiredFamilyFromDeviceId(0x10FB), IntelWiredFamily::Ixgbe); // 82599 SFP
    EXPECT_EQ(IntelWiredFamilyFromDeviceId(0x1528), IntelWiredFamily::Ixgbe); // X540-T
    EXPECT_EQ(IntelWiredFamilyFromDeviceId(0x1563), IntelWiredFamily::Ixgbe); // X550-T
    EXPECT_EQ(IntelWiredFamilyFromDeviceId(0x15AD), IntelWiredFamily::Ixgbe); // X550EM_X 10G-T

    // i40e 40/25 G block.
    EXPECT_EQ(IntelWiredFamilyFromDeviceId(0x1572), IntelWiredFamily::I40e); // X710 SFP+
    EXPECT_EQ(IntelWiredFamilyFromDeviceId(0x158B), IntelWiredFamily::I40e); // XXV710 SFP28
    EXPECT_EQ(IntelWiredFamilyFromDeviceId(0x1582), IntelWiredFamily::None); // gap in i40e table
}

void TestE1000BringUpGate()
{
    // Functional support is narrower than family inventory: only the two
    // QEMU-backed profiles exercised by DuetOS are authorized today.
    EXPECT_TRUE(IntelE1000BringUpEligible(0x100E));
    EXPECT_TRUE(IntelE1000BringUpEligible(0x10D3));
    EXPECT_EQ(IntelE1000BringUpProfileFromDeviceId(0x100E), IntelE1000BringUpProfile::Legacy82540Emulated);
    EXPECT_EQ(IntelE1000BringUpProfileFromDeviceId(0x10D3), IntelE1000BringUpProfile::E1000e82574Emulated);

    // Same-family devices are inventory-only until their exact hardware
    // generation and media contracts have evidence.
    constexpr u16 kInventoryOnlySameFamily[] = {0x1000, 0x100F, 0x107C, 0x107F, 0x156F, 0x2E6E};
    for (const u16 did : kInventoryOnlySameFamily)
    {
        EXPECT_FALSE(IntelE1000BringUpEligible(did));
        EXPECT_EQ(IntelE1000BringUpProfileFromDeviceId(did), IntelE1000BringUpProfile::None);
    }

    // NEVER eligible: queue-based ring register files. This is the
    // regression the explicit tables exist to prevent — the old
    // 0x10A4..0x10FF / 0x1500..0x15FF range gate accepted all of
    // these and ran e1000 register writes against them.
    const u16 kForeignRegisterFile[] = {
        0x10B6, 0x10C6, 0x10FB, 0x10FC, // ixgbe 82598/82599
        0x1528, 0x1560, 0x1563, 0x15AA, // ixgbe X540/X550
        0x10C9, 0x1521, 0x1533, 0x1539, // igb 82576/I350/I210/I211
        0x15F2, 0x15F3, 0x125B,         // igc I225/I226
        0x1572, 0x1583, 0x158B,         // i40e X710/XL710/XXV710
    };
    for (const u16 did : kForeignRegisterFile)
        EXPECT_FALSE(IntelE1000BringUpEligible(did));

    // Exact i40e rows classify, but never enter the e1000 register path;
    // unrelated gaps inside the old coarse ranges stay inventory-only.
    EXPECT_EQ(IntelWiredFamilyFromDeviceId(0x15FF), IntelWiredFamily::I40e);
    EXPECT_FALSE(IntelE1000BringUpEligible(0x15FF));
    EXPECT_FALSE(IntelE1000BringUpEligible(0x10FE));

    // Exhaustive consistency: eligibility must exactly equal the two tested
    // profile IDs, and no ID may classify as both wired and wireless.
    for (u32 did = 0; did <= 0xFFFF; ++did)
    {
        const auto f = IntelWiredFamilyFromDeviceId(static_cast<u16>(did));
        const bool eligible = IntelE1000BringUpEligible(static_cast<u16>(did));
        const bool tested_profile = did == 0x100E || did == 0x10D3;
        EXPECT_EQ(eligible, tested_profile);
        EXPECT_EQ(eligible,
                  IntelE1000BringUpProfileFromDeviceId(static_cast<u16>(did)) != IntelE1000BringUpProfile::None);
        if (IntelWirelessTag(static_cast<u16>(did)) != nullptr)
            EXPECT_EQ(f, IntelWiredFamily::None);
    }
}

void TestVirtioNetBringUpGate()
{
    EXPECT_FALSE(VirtioNetBringUpEligible(0x1000)); // transitional transport
    EXPECT_TRUE(VirtioNetBringUpEligible(0x1041));  // modern virtio-net
    for (u32 did = 0; did <= 0xFFFF; ++did)
        EXPECT_EQ(VirtioNetBringUpEligible(static_cast<u16>(did)), did == 0x1041);
}

void TestIntelWireless()
{
    // Representative IDs per generation.
    EXPECT_STREQ(IntelWirelessTag(0x4229), "iwlegacy-4965");
    EXPECT_STREQ(IntelWirelessTag(0x4232), "iwlwifi-5000");
    EXPECT_STREQ(IntelWirelessTag(0x0083), "iwlwifi-1000/6000");
    EXPECT_STREQ(IntelWirelessTag(0x08B1), "iwlwifi-7260");
    EXPECT_STREQ(IntelWirelessTag(0x095A), "iwlwifi-7265");
    EXPECT_STREQ(IntelWirelessTag(0x24F3), "iwlwifi-8260");
    EXPECT_STREQ(IntelWirelessTag(0x2526), "iwlwifi-9000");
    EXPECT_STREQ(IntelWirelessTag(0x2723), "iwlwifi-AX2xx");
    EXPECT_STREQ(IntelWirelessTag(0x272B), "iwlwifi-Be2xx");

    // Boundaries of the dense 0x008x block.
    EXPECT_TRUE(IntelWirelessTag(0x0082) != nullptr);
    EXPECT_TRUE(IntelWirelessTag(0x0091) != nullptr);
    EXPECT_TRUE(IntelWirelessTag(0x0081) == nullptr);
    EXPECT_TRUE(IntelWirelessTag(0x0092) == nullptr);

    // Wired IDs must not read as wireless.
    EXPECT_TRUE(IntelWirelessTag(0x100E) == nullptr);
    EXPECT_TRUE(IntelWirelessTag(0x10D3) == nullptr);
    EXPECT_TRUE(IntelWirelessTag(0x15F2) == nullptr);

    // Inventory classification is intentionally wider than functional
    // eligibility. The retired shell selected firmware from an incorrect
    // HW-revision decode, so every Intel wireless backend is fail-closed.
    for (u32 did = 0; did <= 0xFFFF; ++did)
    {
        if (IntelWirelessTag(static_cast<u16>(did)) != nullptr)
            EXPECT_FALSE(IntelIwlwifiProbeEligible(static_cast<u16>(did)));
    }
    EXPECT_EQ(IntelWirelessBackendFromDeviceId(0x4222), WirelessBackend::IntelIwlegacy);
    EXPECT_EQ(IntelWirelessBackendFromDeviceId(0x2723), WirelessBackend::IntelIwlwifi);
}

void TestRealtek()
{
    constexpr u16 kRtlwifiBar1[] = {0x8171, 0x8172, 0x8173, 0x8174, 0x8192}; // rtl8192se
    constexpr u16 kRtlwifiBar2[] = {0x002B, 0x8176, 0x8177, 0x8178, 0x8179, 0x818B,
                                    0x8191, 0x8193, 0x8723, 0xB723, 0x8812, 0x8821};
    constexpr u16 kRtw88[] = {0x8813, 0xB821, 0xB822, 0xC821, 0xC822, 0xC82F, 0xD723};
    constexpr u16 kRtw89[] = {0x8852, 0x8922, 0x892B, 0xA85A, 0xB520, 0xB851, 0xB852, 0xB85B, 0xC852};

    for (const u16 did : kRtlwifiBar1)
    {
        EXPECT_EQ(RealtekWirelessBackendFromDeviceId(did), WirelessBackend::RealtekRtlwifi);
        EXPECT_STREQ(RealtekWirelessTag(did), "rtlwifi-pci");
        EXPECT_EQ(RealtekWirelessPreferredMmioBar(did), 1u);
        EXPECT_FALSE(RealtekWirelessProbeEligible(did));
    }
    for (const u16 did : kRtlwifiBar2)
    {
        EXPECT_EQ(RealtekWirelessBackendFromDeviceId(did), WirelessBackend::RealtekRtlwifi);
        EXPECT_STREQ(RealtekWirelessTag(did), "rtlwifi-pci");
        EXPECT_EQ(RealtekWirelessPreferredMmioBar(did), 2u);
        EXPECT_FALSE(RealtekWirelessProbeEligible(did));
    }
    for (const u16 did : kRtw88)
    {
        EXPECT_EQ(RealtekWirelessBackendFromDeviceId(did), WirelessBackend::RealtekRtw88);
        EXPECT_STREQ(RealtekWirelessTag(did), "rtw88-pci");
        EXPECT_EQ(RealtekWirelessPreferredMmioBar(did), 2u);
        EXPECT_FALSE(RealtekWirelessProbeEligible(did));
    }
    for (const u16 did : kRtw89)
    {
        EXPECT_EQ(RealtekWirelessBackendFromDeviceId(did), WirelessBackend::RealtekRtw89);
        EXPECT_STREQ(RealtekWirelessTag(did), "rtw89-pci");
        EXPECT_EQ(RealtekWirelessPreferredMmioBar(did), 2u);
        EXPECT_FALSE(RealtekWirelessProbeEligible(did));
    }
    EXPECT_TRUE(RealtekWirelessTag(0xB812) == nullptr); // USB-only product ID
    EXPECT_TRUE(RealtekWirelessTag(0xC820) == nullptr); // USB-only RTL8821CU product ID
    constexpr u16 kUnsupported[] = {0xB813, 0x8814, 0xB814, 0x8822};
    for (const u16 did : kUnsupported)
    {
        EXPECT_TRUE(RealtekWirelessTag(did) == nullptr);
        EXPECT_EQ(RealtekWirelessPreferredMmioBar(did), kInvalidPciBar);
    }
    EXPECT_EQ(RealtekWirelessPreferredMmioBar(0xB812), kInvalidPciBar);
    EXPECT_EQ(RealtekWirelessPreferredMmioBar(0x8168), kInvalidPciBar);

    // Wired parts are not wireless, and vice versa.
    EXPECT_TRUE(RealtekWirelessTag(0x8168) == nullptr);
    EXPECT_TRUE(RealtekWirelessTag(0x8125) == nullptr);
    EXPECT_STREQ(RealtekWiredTag(0x8168), "rtl8169");
    EXPECT_STREQ(RealtekWiredTag(0x8125), "rtl8125-2.5g");
    EXPECT_TRUE(RealtekWiredTag(0x8852) == nullptr);

    // No ID may carry both a wired and a wireless tag.
    for (u32 did = 0; did <= 0xFFFF; ++did)
    {
        const bool wifi = RealtekWirelessTag(static_cast<u16>(did)) != nullptr;
        const bool wired = RealtekWiredTag(static_cast<u16>(did)) != nullptr;
        EXPECT_FALSE(wifi && wired);
    }

    u32 wireless_candidates = 0;
    for (u32 did = 0; did <= 0xFFFF; ++did)
    {
        if (RealtekWirelessBackendFromDeviceId(static_cast<u16>(did)) != WirelessBackend::None)
            ++wireless_candidates;
    }
    EXPECT_EQ(wireless_candidates, 33u);
}

void TestBroadcom()
{
    constexpr u16 kB43Ssb[] = {0x4301, 0x4306, 0x4307, 0x4311, 0x4312, 0x4315, 0x4318, 0x4319, 0x4320, 0x4321,
                               0x4322, 0x4324, 0x4325, 0x4328, 0x4329, 0x432B, 0x432C, 0x4350, 0x4351, 0xA8D6};
    constexpr u16 kBcma[] = {0x0576, 0x4313, 0x4331, 0x4353, 0x4357, 0x4358, 0x4359, 0x4360,
                             0x43A0, 0x43A9, 0x43AA, 0x43B1, 0x4727, 0xA8D8, 0xA8DB, 0xA8DC};
    constexpr u16 kBrcmfmacGeneric[] = {0x4354, 0x43A3, 0x43BA, 0x43BB, 0x43BC, 0x43C3, 0x43C4, 0x43C5, 0x43CA,
                                        0x43CB, 0x43CC, 0x43D3, 0x43D9, 0x43DC, 0x43E9, 0x43EC, 0x43EF, 0x440D,
                                        0x4415, 0x4417, 0x4425, 0x4433, 0x4464, 0x4488, 0x449D, 0xAA31, 0xAA52};
    constexpr WirelessBackendMask kB43Mask = WirelessBackendBit(WirelessBackend::BroadcomB43Ssb);
    constexpr WirelessBackendMask kBcmaMask = WirelessBackendBit(WirelessBackend::BroadcomBcma);
    constexpr WirelessBackendMask kBrcmfmacMask = WirelessBackendBit(WirelessBackend::BroadcomBrcmfmac);

    for (const u16 did : kB43Ssb)
    {
        EXPECT_EQ(BroadcomWirelessCandidateBackendsFromDeviceId(did), kB43Mask);
        EXPECT_EQ(BroadcomWirelessBackendFromIdentity(did, 0, 0, false), WirelessBackend::BroadcomB43Ssb);
        EXPECT_STREQ(BroadcomWirelessTag(did), "b43-ssb-wifi");
        EXPECT_FALSE(BroadcomWirelessProbeEligible(WirelessBackend::BroadcomB43Ssb, did));
    }
    for (const u16 did : kBcma)
    {
        EXPECT_EQ(BroadcomWirelessCandidateBackendsFromDeviceId(did), kBcmaMask);
        EXPECT_EQ(BroadcomWirelessBackendFromIdentity(did, 0, 0, false), WirelessBackend::BroadcomBcma);
        EXPECT_STREQ(BroadcomWirelessTag(did), "brcm-bcma-wifi");
        EXPECT_FALSE(BroadcomWirelessProbeEligible(WirelessBackend::BroadcomBcma, did));
    }
    for (const u16 did : kBrcmfmacGeneric)
    {
        EXPECT_EQ(BroadcomWirelessCandidateBackendsFromDeviceId(did), kBrcmfmacMask);
        EXPECT_EQ(BroadcomWirelessBackendFromIdentity(did, 0, 0, false), WirelessBackend::BroadcomBrcmfmac);
        EXPECT_STREQ(BroadcomWirelessTag(did), "brcmfmac-pcie");
        EXPECT_FALSE(BroadcomWirelessProbeEligible(WirelessBackend::BroadcomBrcmfmac, did));
    }

    // Raw 4355 is brcmfmac only for 14E4:4355. Raw 4365 is ambiguous
    // at device-ID level and resolves to BCMA or brcmfmac by subsystem.
    EXPECT_EQ(BroadcomWirelessCandidateBackendsFromDeviceId(0x4355), kBrcmfmacMask);
    EXPECT_EQ(BroadcomWirelessCandidateBackendsFromDeviceId(0x4365), kBcmaMask | kBrcmfmacMask);
    EXPECT_TRUE(WirelessBackendMaskContains(BroadcomWirelessCandidateBackendsFromDeviceId(0x4365),
                                            WirelessBackend::BroadcomBcma));
    EXPECT_TRUE(WirelessBackendMaskContains(BroadcomWirelessCandidateBackendsFromDeviceId(0x4365),
                                            WirelessBackend::BroadcomBrcmfmac));
    EXPECT_STREQ(BroadcomWirelessTag(0x4355), "brcm-wifi-candidate");
    EXPECT_STREQ(BroadcomWirelessTag(0x4365), "brcm-wifi-candidate");

    EXPECT_EQ(BroadcomWirelessBackendFromIdentity(0x4355, 0, 0, false), WirelessBackend::None);
    EXPECT_EQ(BroadcomWirelessBackendFromIdentity(0x4355, 0x14E4, 0x4355, true), WirelessBackend::BroadcomBrcmfmac);
    EXPECT_EQ(BroadcomWirelessBackendFromIdentity(0x4355, 0x14E4, 0x4354, true), WirelessBackend::None);
    EXPECT_STREQ(BroadcomWirelessTagFromIdentity(0x4355, 0x14E4, 0x4355, true), "brcmfmac-pcie");
    EXPECT_STREQ(BroadcomWirelessTagFromIdentity(0x4355, 0x14E4, 0x4354, true), "brcm-wifi-candidate");

    EXPECT_EQ(BroadcomWirelessBackendFromIdentity(0x4365, 0, 0, false), WirelessBackend::None);
    EXPECT_EQ(BroadcomWirelessBackendFromIdentity(0x4365, 0x14E4, 0x4365, true), WirelessBackend::BroadcomBrcmfmac);
    EXPECT_EQ(BroadcomWirelessBackendFromIdentity(0x4365, 0x1028, 0x0016, true), WirelessBackend::BroadcomBcma);
    EXPECT_EQ(BroadcomWirelessBackendFromIdentity(0x4365, 0x1028, 0x0018, true), WirelessBackend::BroadcomBcma);
    EXPECT_EQ(BroadcomWirelessBackendFromIdentity(0x4365, 0x105B, 0xE092, true), WirelessBackend::BroadcomBcma);
    EXPECT_EQ(BroadcomWirelessBackendFromIdentity(0x4365, 0x103C, 0x804A, true), WirelessBackend::BroadcomBcma);
    EXPECT_EQ(BroadcomWirelessBackendFromIdentity(0x4365, 0x1028, 0x4365, true), WirelessBackend::None);
    EXPECT_STREQ(BroadcomWirelessTagFromIdentity(0x4365, 0x14E4, 0x4365, true), "brcmfmac-pcie");
    EXPECT_STREQ(BroadcomWirelessTagFromIdentity(0x4365, 0x1028, 0x0016, true), "brcm-bcma-wifi");
    EXPECT_STREQ(BroadcomWirelessTagFromIdentity(0x4365, 0, 0, false), "brcm-wifi-candidate");

    // Wired tg3 range and arbitrary outsiders are not wireless.
    constexpr u16 kUnsupported[] = {0x0000, 0x1600, 0x16FF, 0x42FF, 0x4300, 0x4302, 0x4323, 0x4326,
                                    0x4327, 0x432A, 0x4330, 0x4340, 0x4370, 0x43FF, 0x4400};
    for (const u16 did : kUnsupported)
    {
        EXPECT_EQ(BroadcomWirelessCandidateBackendsFromDeviceId(did), 0u);
        EXPECT_TRUE(BroadcomWirelessTag(did) == nullptr);
    }

    u32 wireless_candidates = 0;
    for (u32 did = 0; did <= 0xFFFF; ++did)
    {
        const u16 candidate = static_cast<u16>(did);
        if (BroadcomWirelessCandidateBackendsFromDeviceId(candidate) != 0)
        {
            ++wireless_candidates;
            EXPECT_FALSE(BroadcomWirelessProbeEligible(WirelessBackend::None, candidate));
        }
    }
    EXPECT_EQ(wireless_candidates, 65u);
}

void TestBcmChipNameFormat()
{
    char buf[8] = {};

    // Decimal band > 0xA000: BCM43602 reads back 0xAA52 == 43602.
    EXPECT_EQ(BcmChipNameFormat(0xAA52, buf, sizeof(buf)), 5u);
    EXPECT_STREQ(buf, "43602");

    // Hex band 0x4000..0x9FFF.
    EXPECT_EQ(BcmChipNameFormat(0x4331, buf, sizeof(buf)), 4u);
    EXPECT_STREQ(buf, "4331");
    EXPECT_EQ(BcmChipNameFormat(0x4350, buf, sizeof(buf)), 4u);
    EXPECT_STREQ(buf, "4350");

    // Linux uses a strict > 0xA000 comparison: 0xA000 itself remains
    // hex; 0xA001 switches to decimal. Values below 0x4000 are decimal.
    EXPECT_EQ(BcmChipNameFormat(0xA000, buf, sizeof(buf)), 4u);
    EXPECT_STREQ(buf, "a000");
    EXPECT_EQ(BcmChipNameFormat(0xA001, buf, sizeof(buf)), 5u);
    EXPECT_STREQ(buf, "40961");
    EXPECT_EQ(BcmChipNameFormat(0x9FFF, buf, sizeof(buf)), 4u);
    EXPECT_STREQ(buf, "9fff");
    EXPECT_EQ(BcmChipNameFormat(0x3FFF, buf, sizeof(buf)), 5u);
    EXPECT_STREQ(buf, "16383");
    EXPECT_EQ(BcmChipNameFormat(0x0000, buf, sizeof(buf)), 1u);
    EXPECT_STREQ(buf, "0");

    // Hostile buffers: too small or null must refuse, not overrun.
    // (Runtime-valued arguments so MSVC can't constant-fold the
    // whole expression into a C4127 constant conditional.)
    u32 small_len = 5;
    u32 zero_len = 0;
    char* null_buf = nullptr;
    EXPECT_EQ(BcmChipNameFormat(0xAA52, buf, small_len), 0u);
    EXPECT_EQ(BcmChipNameFormat(0xAA52, null_buf, 64), 0u);
    EXPECT_EQ(BcmChipNameFormat(0xAA52, buf, zero_len), 0u);
}

void TestMediaTekInventoryFamilies()
{
    struct Candidate
    {
        u16 device_id;
        Mt76Family family;
        const char* tag;
    };

    constexpr Candidate kPrimary[] = {
        {0x7615, Mt76Family::Mt7615, "mt7615-wifi"}, {0x7611, Mt76Family::Mt7615, "mt7615-wifi"},
        {0x7663, Mt76Family::Mt7663, "mt7663-wifi"}, {0x7915, Mt76Family::Mt7915, "mt7915-wifi"},
        {0x7906, Mt76Family::Mt7916, "mt7916-wifi"}, {0x7961, Mt76Family::Mt7921, "mt7921-wifi"},
        {0x0608, Mt76Family::Mt7921, "mt7921-wifi"}, {0x7922, Mt76Family::Mt7922, "mt7922-wifi"},
        {0x0616, Mt76Family::Mt7922, "mt7922-wifi"}, {0x7920, Mt76Family::Mt7920, "mt7920-wifi"},
        {0x7902, Mt76Family::Mt7902, "mt7902-wifi"}, {0x7925, Mt76Family::Mt7925, "mt7925-wifi"},
        {0x0717, Mt76Family::Mt7925, "mt7925-wifi"}, {0x7927, Mt76Family::Mt7927, "mt7927-wifi"},
        {0x6639, Mt76Family::Mt7927, "mt7927-wifi"}, {0x0738, Mt76Family::Mt7927, "mt7927-wifi"},
    };
    for (const Candidate& candidate : kPrimary)
    {
        EXPECT_EQ(Mt76FamilyFromIdentity(kVendorMediaTek, candidate.device_id), candidate.family);
        EXPECT_TRUE(Mt76FamilyIsPrimaryAdapter(candidate.family));
        EXPECT_STREQ(Mt76InventoryTag(candidate.family), candidate.tag);
        EXPECT_TRUE(NicFamilyLooksWireless(candidate.tag));
    }

    // The ITTIM rebadge is one exact tuple, not a vendor-wide admission.
    EXPECT_EQ(Mt76FamilyFromIdentity(kVendorIttim, 0x7922), Mt76Family::Mt7922);
    EXPECT_EQ(Mt76FamilyFromIdentity(kVendorIttim, 0x7961), Mt76Family::Unknown);
    EXPECT_EQ(Mt76FamilyFromIdentity(0x1234, 0x7922), Mt76Family::Unknown);

    // These are the secondary PCI transport rows for an MT7915/MT7916
    // device. They remain classifiable but never become standalone NICs.
    constexpr u16 kCompanions[] = {0x7916, 0x790A};
    for (const u16 companion : kCompanions)
    {
        const Mt76Family family = Mt76FamilyFromIdentity(kVendorMediaTek, companion);
        EXPECT_EQ(family, Mt76Family::HifCompanion);
        EXPECT_FALSE(Mt76FamilyIsPrimaryAdapter(family));
        EXPECT_TRUE(Mt76InventoryTag(family) == nullptr);
    }

    EXPECT_EQ(Mt76FamilyFromIdentity(kVendorMediaTek, 0), Mt76Family::Unknown);
    EXPECT_FALSE(Mt76FamilyIsPrimaryAdapter(Mt76Family::Unknown));
    EXPECT_TRUE(Mt76InventoryTag(Mt76Family::Unknown) == nullptr);
}

void TestFamilyLooksWireless()
{
    EXPECT_TRUE(NicFamilyLooksWireless("iwlwifi-9000"));
    EXPECT_TRUE(NicFamilyLooksWireless("rtlwifi-pci"));
    EXPECT_TRUE(NicFamilyLooksWireless("rtw88-pci"));
    EXPECT_TRUE(NicFamilyLooksWireless("rtw89-pci"));
    EXPECT_TRUE(NicFamilyLooksWireless("brcmfmac-pcie"));
    EXPECT_TRUE(NicFamilyLooksWireless("brcm-wifi-candidate"));
    EXPECT_TRUE(NicFamilyLooksWireless("mt7921-wifi"));
    EXPECT_TRUE(NicFamilyLooksWireless("mt7902-wifi"));
    EXPECT_TRUE(NicFamilyLooksWireless("mt7920-wifi"));
    EXPECT_TRUE(NicFamilyLooksWireless("mt7927-wifi"));

    EXPECT_FALSE(NicFamilyLooksWireless("rtl8169"));
    EXPECT_FALSE(NicFamilyLooksWireless("rtl8125-2.5g"));
    EXPECT_FALSE(NicFamilyLooksWireless("e1000e"));
    EXPECT_FALSE(NicFamilyLooksWireless("igc-i225/i226"));
    EXPECT_FALSE(NicFamilyLooksWireless("bcm57xx-tg3"));
    EXPECT_FALSE(NicFamilyLooksWireless(nullptr));
    EXPECT_FALSE(NicFamilyLooksWireless(""));

    // Every wireless tag the classifiers can emit must satisfy the
    // heuristic — otherwise a subclass-0x00 wireless card would be
    // treated as Ethernet by NicIsWireless.
    for (u32 did = 0; did <= 0xFFFF; ++did)
    {
        const char* r = RealtekWirelessTag(static_cast<u16>(did));
        if (r != nullptr)
            EXPECT_TRUE(NicFamilyLooksWireless(r));
        const char* b = BroadcomWirelessTag(static_cast<u16>(did));
        if (b != nullptr)
            EXPECT_TRUE(NicFamilyLooksWireless(b));
        const char* i = IntelWirelessTag(static_cast<u16>(did));
        if (i != nullptr)
            EXPECT_TRUE(NicFamilyLooksWireless(i));
    }
}

} // namespace

int main()
{
    TestIntelWiredDispatch();
    TestE1000BringUpGate();
    TestVirtioNetBringUpGate();
    TestIntelWireless();
    TestRealtek();
    TestBroadcom();
    TestBcmChipNameFormat();
    TestMediaTekInventoryFamilies();
    TestFamilyLooksWireless();
    return ::duetos_host_test::finish_main("nic_ids");
}
