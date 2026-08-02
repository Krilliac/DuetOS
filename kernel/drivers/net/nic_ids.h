#pragma once

#include "util/types.h"

/*
 * DuetOS — NIC PCI-ID classification (single source of truth).
 *
 * WHAT
 *   Pure device-ID → family classification for every PCI network
 *   controller the net driver layer knows about, plus the chip-ID →
 *   firmware-name formatting rule for Broadcom FullMAC parts.
 *
 * WHY ONE HEADER
 *   Before this header existed the same knowledge lived in two
 *   parallel whitelists: the family-tag tables in `net.cpp`
 *   (IntelNicTag / RealtekNicTag / BroadcomNicTag) and each wireless
 *   driver's `*Matches` predicate (iwlwifi.cpp / rtl88xx.cpp /
 *   bcm43xx.cpp). Parallel whitelists drift — the classic
 *   "whitelist incompleteness" class of bug — and the Intel table's
 *   coarse ranges actually mis-dispatched: ixgbe 82598/82599
 *   (0x10B6..0x10FB) and X540/X550/i40e/igb/igc IDs interleave with
 *   the e1000e ID space, so 10/40 G and igb/igc silicon classified
 *   as "e1000e" and received a full e1000 register bring-up against
 *   the wrong register file. Everything here is keyed on explicit,
 *   evidence-backed ID sets instead.
 *
 * EVIDENCE
 *   Every ID below is taken from the corresponding Linux driver's
 *   `pci_device_id` table (device IDs are hardware ABI; copying the
 *   numeric values is fine):
 *     - e1000/e1000e:  drivers/net/ethernet/intel/{e1000,e1000e}
 *     - igb/igc:       drivers/net/ethernet/intel/{igb,igc}
 *     - ixgbe/i40e:    drivers/net/ethernet/intel/{ixgbe,i40e}
 *     - iwlwifi:       drivers/net/wireless/intel/iwlwifi/pcie/drv.c
 *     - rtlwifi/rtw88/rtw89: drivers/net/wireless/realtek/
 *     - b43/brcmfmac:  drivers/net/wireless/broadcom/
 *   Do NOT add an ID here without a matching row in one of those
 *   tables (or the vendor datasheet).
 *
 * CONTEXT
 *   Freestanding — depends on `util/types.h` only, no kernel state,
 *   all functions constexpr/pure. Host-tested by
 *   `tests/host/test_nic_ids.cpp`.
 */

namespace duetos::drivers::net
{

// Common vendor IDs. A few are duplicated with drivers/gpu — PCI
// vendor IDs are global, not per-class.
inline constexpr u16 kVendorIntel = 0x8086;
inline constexpr u16 kVendorRealtek = 0x10EC;
inline constexpr u16 kVendorBroadcom = 0x14E4;
inline constexpr u16 kVendorMarvell = 0x11AB;
inline constexpr u16 kVendorMellanox = 0x15B3;
inline constexpr u16 kVendorRedHatVirt = 0x1AF4; // virtio-net
inline constexpr u16 kVendorAmd = 0x1022;        // AMD PCnet (VirtualBox default NIC)

namespace nic_ids
{

// Device recognition and hardware access are deliberately separate.
// A candidate says only that an upstream PCI table contains the ID; it
// does not prove that DuetOS implements that backend's BAR, reset, firmware,
// or DMA contract.  Callers must never turn a non-None backend into MMIO
// access or an "online" claim without an explicit safe-probe gate.
enum class WirelessBackend : u8
{
    None = 0,
    IntelIwlegacy,
    IntelIwlwifi,
    RealtekRtlwifi,
    RealtekRtw88,
    RealtekRtw89,
    BroadcomB43Ssb,
    BroadcomBcma,
    BroadcomBrcmfmac,
    MediaTekMt76,
};

using WirelessBackendMask = u16;

constexpr WirelessBackendMask WirelessBackendBit(WirelessBackend backend)
{
    if (backend == WirelessBackend::None)
        return 0;
    return static_cast<WirelessBackendMask>(1u << static_cast<u8>(backend));
}

constexpr bool WirelessBackendMaskContains(WirelessBackendMask mask, WirelessBackend backend)
{
    return (mask & WirelessBackendBit(backend)) != 0;
}

inline constexpr u8 kInvalidPciBar = 0xFF;

// ---------------------------------------------------------------
// Intel wired families.
// ---------------------------------------------------------------

enum class IntelWiredFamily : u8
{
    None = 0,     // not a known Intel wired NIC (may still be iwlwifi)
    E1000Classic, // 8254x/8254x-derived — legacy PCI e1000
    E1000e,       // 82571..82583 + ICH/PCH LOMs + i217/i218/i219
    Igb,          // 82575/82576/82580/I350/I210/I211 (queue-based rings)
    Igc,          // I225/I226 2.5 G
    Ixgbe,        // 82598/82599/X540/X550 10 G
    I40e,         // X710/XL710/XXV710 40/25 G
};

// Functional profiles are deliberately narrower than family inventory.
// These are the two emulated devices exercised by DuetOS' QEMU paths; other
// exact e1000/e1000e IDs remain visible as candidates until their generation,
// media, reset, PHY, and DMA contracts have their own verification evidence.
enum class IntelE1000BringUpProfile : u8
{
    None = 0,
    Legacy82540Emulated, // 8086:100E, QEMU `-device e1000`
    E1000e82574Emulated, // 8086:10D3, QEMU `-device e1000e`
};

// e1000 classic PCI table. This MUST remain an explicit set: Intel's
// incompatible e100/8255x devices occupy holes inside 0x1000..0x107f,
// so a range check would make the e1000 path program the wrong MMIO
// register file.
constexpr bool IntelIsE1000ClassicId(u16 did)
{
    switch (did)
    {
    case 0x1000:
    case 0x1001:
    case 0x1004:
    case 0x1008:
    case 0x1009:
    case 0x100C:
    case 0x100D:
    case 0x100E:
    case 0x100F:
    case 0x1010:
    case 0x1011:
    case 0x1012:
    case 0x1013:
    case 0x1014:
    case 0x1015:
    case 0x1016:
    case 0x1017:
    case 0x1018:
    case 0x1019:
    case 0x101A:
    case 0x101D:
    case 0x101E:
    case 0x1026:
    case 0x1027:
    case 0x1028:
    case 0x1075:
    case 0x1076:
    case 0x1077:
    case 0x1078:
    case 0x1079:
    case 0x107A:
    case 0x107B:
    case 0x107C:
    case 0x108A:
    case 0x1099:
    case 0x10B5:
    case 0x2E6E:
        return true;
    default:
        return false;
    }
}

// ixgbe — 82598 (0x10B6..0x150B rows), 82599, X540, X550/X550EM.
constexpr bool IntelIsIxgbeId(u16 did)
{
    switch (did)
    {
    case 0x10B6: // 82598
    case 0x1508: // 82598 BX
    case 0x10C6: // 82598AF dual port
    case 0x10C7: // 82598AF single port
    case 0x10C8: // 82598AT
    case 0x150B: // 82598AT2
    case 0x10DB: // 82598EB SFP
    case 0x10DD: // 82598EB CX4
    case 0x10E1: // 82598 CX4 dual port
    case 0x10EC: // 82598EB XF LR
    case 0x10F1: // 82598AF dual port (DA)
    case 0x10F4: // 82598EB XF LR
    case 0x10F7: // 82599 KX4
    case 0x1514: // 82599 KX4 mezzanine
    case 0x10F8: // 82599 combined backplane
    case 0x10F9: // 82599 CX4
    case 0x10FB: // 82599 SFP
    case 0x1507: // 82599 SFP EM
    case 0x1529: // 82599 SFP FCoE
    case 0x152A: // 82599 backplane FCoE
    case 0x10FC: // 82599 XAUI
    case 0x1517: // 82599 KR
    case 0x151C: // 82599 T3 LOM
    case 0x154D: // 82599 SFP SF2
    case 0x154A: // 82599 SFP quad-port
    case 0x154F: // 82599 LS
    case 0x1558: // 82599 QSFP quad-port
    case 0x1557: // 82599EN SFP
    case 0x1528: // X540-T
    case 0x1560: // X540-T1
    case 0x1563: // X550-T
    case 0x15D1: // X550-T1
    case 0x15AA: // X550EM_X KX4
    case 0x15AB: // X550EM_X KR
    case 0x15AC: // X550EM_X SFP
    case 0x15AD: // X550EM_X 10G-T
    case 0x15AE: // X550EM_X 1G-T
    case 0x15B0: // X550EM_X XFI
    case 0x15C2: // X550EM_A KR
    case 0x15C3: // X550EM_A KR L
    case 0x15C4: // X550EM_A SFP N
    case 0x15C6: // X550EM_A SGMII
    case 0x15C7: // X550EM_A SGMII L
    case 0x15C8: // X550EM_A 10G-T
    case 0x15CE: // X550EM_A SFP
    case 0x15E4: // X550EM_A 1G-T
    case 0x15E5: // X550EM_A 1G-T L
    case 0x57AE: // E610 backplane
    case 0x57AF: // E610 SFP
    case 0x57B0: // E610 10G-T
    case 0x57B1: // E610 2.5G-T
    case 0x57B2: // E610 SGMII
    case 0x10ED: // 82599 VF
    case 0x1515: // X540 VF
    case 0x1565: // X550 VF
    case 0x15A8: // X550EM_X VF
    case 0x15C5: // X550EM_A VF
    case 0x57AD: // E610 VF
        return true;
    default:
        return false;
    }
}

// igb — 82575/82576/82580/I350/I210/I211.
constexpr bool IntelIsIgbId(u16 did)
{
    switch (did)
    {
    case 0x10A7: // 82575EB copper
    case 0x10A9: // 82575EB fiber/serdes
    case 0x10D6: // 82575GB quad copper
    case 0x0438: // DH89xxCC SGMII
    case 0x043A: // DH89xxCC serdes
    case 0x043C: // DH89xxCC backplane
    case 0x0440: // DH89xxCC SFP
    case 0x10C9: // 82576
    case 0x10E6: // 82576 fiber
    case 0x10E7: // 82576 serdes
    case 0x10E8: // 82576 quad copper
    case 0x1526: // 82576 quad copper ET2
    case 0x150A: // 82576NS
    case 0x1518: // 82576NS serdes
    case 0x150D: // 82576 serdes quad
    case 0x150E: // 82580 copper
    case 0x150F: // 82580 fiber
    case 0x1510: // 82580 backplane
    case 0x1511: // 82580 sgmii
    case 0x1516: // 82580 copper dual
    case 0x1527: // 82580 quad fiber
    case 0x1521: // I350 copper
    case 0x1522: // I350 fiber
    case 0x1523: // I350 serdes
    case 0x1524: // I350 sgmii
    case 0x1533: // I210 copper
    case 0x1536: // I210 fiber
    case 0x1537: // I210 serdes
    case 0x1538: // I210 sgmii
    case 0x1539: // I211 copper
    case 0x157B: // I210 copper flashless
    case 0x157C: // I210 serdes flashless
    case 0x1F40: // I354 backplane 1G
    case 0x1F41: // I354 SGMII
    case 0x1F45: // I354 backplane 2.5G
        return true;
    default:
        return false;
    }
}

// igc — I220/I221/I225/I226 2.5 G, including embedded and blank-NVM
// variants from the upstream igc PCI table.
constexpr bool IntelIsIgcId(u16 did)
{
    switch (did)
    {
    case 0x15F2: // I225-LM
    case 0x15F3: // I225-V
    case 0x15F8: // I225-I
    case 0x15F7: // I220-V
    case 0x3100: // I225-K
    case 0x3101: // I225-K2
    case 0x3102: // I226-K
    case 0x5502: // I225-LMVP
    case 0x5503: // I226-LMVP
    case 0x0D9F: // I225-IT
    case 0x125B: // I226-LM
    case 0x125C: // I226-V
    case 0x125D: // I226-IT
    case 0x125E: // I221-V
    case 0x125F: // I226 blank NVM
    case 0x15FD: // I225 blank NVM
        return true;
    default:
        return false;
    }
}

// i40e/X710/X722 PCI table. Exact rows avoid assigning unrelated Intel
// devices that happen to occupy gaps in the old 0x1572..0x158b range.
constexpr bool IntelIsI40eId(u16 did)
{
    switch (did)
    {
    case 0x0CF8:
    case 0x0D58:
    case 0x1572:
    case 0x1574:
    case 0x1580:
    case 0x1581:
    case 0x1583:
    case 0x1584:
    case 0x1585:
    case 0x1586:
    case 0x1587:
    case 0x1588:
    case 0x1589:
    case 0x158A:
    case 0x158B:
    case 0x15FF:
    case 0x104F:
    case 0x104E:
    case 0x101F:
    case 0x0DD2:
    case 0x37CE:
    case 0x37CF:
    case 0x37D0:
    case 0x37D1:
    case 0x37D2:
    case 0x37D3:
    case 0x0DDA:
        return true;
    default:
        return false;
    }
}

// e1000e — PCIe descendants of e1000 that keep the legacy register
// layout the DuetOS e1000 driver touches (CTRL/STATUS/RCTL/TCTL,
// RAL/RAH at 0x5400, legacy ring registers at 0x2800/0x3800).
// Explicit rows, NOT a range: the 0x10xx/0x15xx spaces interleave
// with ixgbe/igb/igc (see header comment).
constexpr bool IntelIsE1000eId(u16 did)
{
    switch (did)
    {
    case 0x105E: // 82571EB copper
    case 0x105F: // 82571EB fiber
    case 0x1060: // 82571EB serdes
    case 0x10A4: // 82571EB quad copper
    case 0x10A5: // 82571EB quad fiber
    case 0x10BC: // 82571EB quad copper LP
    case 0x10D5: // 82571PT quad copper
    case 0x10D9: // 82571EB serdes dual
    case 0x10DA: // 82571EB serdes quad
    case 0x10B9: // 82572EI copper
    case 0x107D: // 82572EI copper
    case 0x107E: // 82572EI fiber
    case 0x107F: // 82572EI serdes
    case 0x108B: // 82573V
    case 0x108C: // 82573E
    case 0x109A: // 82573L
    case 0x10D3: // 82574L (QEMU's e1000e model)
    case 0x10F6: // 82574LA
    case 0x150C: // 82583V
    case 0x1096: // 80003ES2LAN copper dual
    case 0x1098: // 80003ES2LAN serdes dual
    case 0x10BA: // 80003ES2LAN copper single
    case 0x10BB: // 80003ES2LAN serdes single
    case 0x1501: // ICH8 82567V-3
    case 0x1049: // ICH8 IGP M AMT
    case 0x104A: // ICH8 IGP AMT
    case 0x104B: // ICH8 IGP C
    case 0x104C: // ICH8 IFE
    case 0x10C4: // ICH8 IFE GT
    case 0x10C5: // ICH8 IFE G
    case 0x104D: // ICH8 IGP M
    case 0x10BD: // ICH9 IGP AMT
    case 0x10BF: // ICH9 IGP M
    case 0x10C0: // ICH9 IFE
    case 0x10C2: // ICH9 IFE G
    case 0x10C3: // ICH9 IFE GT
    case 0x10CB: // ICH9 IGP M V
    case 0x10E5: // ICH9 BM
    case 0x10F5: // ICH9 IGP M AMT
    case 0x294C: // ICH9 IGP C
    case 0x10CC: // ICH10 R BM LM
    case 0x10CD: // ICH10 R BM LF
    case 0x10CE: // ICH10 R BM V
    case 0x10DE: // ICH10 D BM LM
    case 0x10DF: // ICH10 D BM LF
    case 0x1525: // ICH10 D BM V
    case 0x10EA: // PCH 82577LM
    case 0x10EB: // PCH 82577LC
    case 0x10EF: // PCH 82578DM
    case 0x10F0: // PCH 82578DC
    case 0x1502: // PCH2 82579LM
    case 0x1503: // PCH2 82579V
    case 0x153A: // i217-LM
    case 0x153B: // i217-V
    case 0x1559: // i218-V
    case 0x155A: // i218-LM
    case 0x15A0: // i218-LM2
    case 0x15A1: // i218-V2
    case 0x15A2: // i218-LM3
    case 0x15A3: // i218-V3
    case 0x156F: // i219-LM (SPT)
    case 0x1570: // i219-V (SPT)
    case 0x15B7: // i219-LM2
    case 0x15B8: // i219-V2
    case 0x15B9: // i219-LM3
    case 0x15BB: // i219-LM7 (CNP)
    case 0x15BC: // i219-V7
    case 0x15BD: // i219-LM6
    case 0x15BE: // i219-V6
    case 0x15D6: // i219-V5
    case 0x15D7: // i219-LM4
    case 0x15D8: // i219-V4
    case 0x15DF: // i219-LM8 (ICP)
    case 0x15E0: // i219-V8
    case 0x15E1: // i219-LM9
    case 0x15E2: // i219-V9
    case 0x15E3: // i219-LM5
    case 0x0D4E: // i219-LM10
    case 0x0D4F: // i219-V10
    case 0x0D4C: // i219-LM11
    case 0x0D4D: // i219-V11
    case 0x0D53: // i219-LM12
    case 0x0D55: // i219-V12
    case 0x15FB: // i219-LM13
    case 0x15FC: // i219-V13
    case 0x15F9: // i219-LM14
    case 0x15FA: // i219-V14
    case 0x15F4: // i219-LM15
    case 0x15F5: // i219-V15
    case 0x1A1E: // i219-LM16
    case 0x1A1F: // i219-V16
    case 0x1A1C: // i219-LM17
    case 0x1A1D: // i219-V17
    case 0x550A: // i219-LM18
    case 0x550B: // i219-V18
    case 0x550C: // i219-LM19
    case 0x550D: // i219-V19
    case 0x550E: // i219-LM20
    case 0x550F: // i219-V20
    case 0x5510: // i219-LM21
    case 0x5511: // i219-V21
    case 0x0DC7: // i219-LM22
    case 0x0DC8: // i219-V22
    case 0x0DC5: // i219-LM23
    case 0x0DC6: // i219-V23
    case 0x57A0: // i219-LM24
    case 0x57A1: // i219-V24
    case 0x57B3: // i219-LM25
    case 0x57B4: // i219-V25
    case 0x57B7: // i219-LM27
    case 0x57B8: // i219-V27
    case 0x57B9: // i219-LM29
    case 0x57BA: // i219-V29
        return true;
    default:
        return false;
    }
}

constexpr IntelWiredFamily IntelWiredFamilyFromDeviceId(u16 did)
{
    // Specific families first — their IDs interleave with the classic
    // and e1000e spaces, so ordering is load-bearing.
    if (IntelIsIgbId(did))
        return IntelWiredFamily::Igb;
    if (IntelIsIgcId(did))
        return IntelWiredFamily::Igc;
    if (IntelIsIxgbeId(did))
        return IntelWiredFamily::Ixgbe;
    if (IntelIsI40eId(did))
        return IntelWiredFamily::I40e;
    if (IntelIsE1000ClassicId(did))
        return IntelWiredFamily::E1000Classic;
    if (IntelIsE1000eId(did))
        return IntelWiredFamily::E1000e;
    return IntelWiredFamily::None;
}

constexpr IntelE1000BringUpProfile IntelE1000BringUpProfileFromDeviceId(u16 did)
{
    switch (did)
    {
    case 0x100E:
        return IntelE1000BringUpProfile::Legacy82540Emulated;
    case 0x10D3:
        return IntelE1000BringUpProfile::E1000e82574Emulated;
    default:
        return IntelE1000BringUpProfile::None;
    }
}

/// True iff the DuetOS e1000 driver may run its full register bring-up on
/// this exact tested profile. Family classification is intentionally much
/// broader: even other classic/e1000e devices can require different reset,
/// media, PHY, MSI-X, and manageability handling. The safe failure mode is
/// inventory-only, never speculative writes to a merely related device.
constexpr bool IntelE1000BringUpEligible(u16 did)
{
    return IntelE1000BringUpProfileFromDeviceId(did) != IntelE1000BringUpProfile::None;
}

// ---------------------------------------------------------------
// Intel wireless (iwlwifi).
// ---------------------------------------------------------------

/// Family tag for an Intel PCIe wireless device, nullptr for any device
/// absent from the upstream iwlwifi/iwlegacy PCI tables. Keep this an exact
/// set: Intel assigns unrelated devices inside every apparent numeric band.
constexpr const char* IntelWirelessTag(u16 did)
{
    switch (did)
    {
    // Current iwlegacy tables. The DuetOS iwlwifi shell deliberately does
    // not probe these: this tag is identification, not a register contract.
    case 0x4222:
    case 0x4227:
        return "iwlegacy-3945";
    case 0x4229:
    case 0x4230:
        return "iwlegacy-4965";

    // iwlwifi DVM: 5000/5150.
    case 0x4232:
    case 0x4235:
    case 0x4236:
    case 0x4237:
    case 0x423A:
    case 0x423B:
    case 0x423C:
    case 0x423D:
        return "iwlwifi-5000";

    // iwlwifi DVM: 100/1000/130/2x00/6x00/6x30/6x35/6x50/6150.
    case 0x0082:
    case 0x0083:
    case 0x0084:
    case 0x0085:
    case 0x0087:
    case 0x0089:
    case 0x008A:
    case 0x008B:
    case 0x0090:
    case 0x0091:
    case 0x0885:
    case 0x0886:
    case 0x0887:
    case 0x0888:
    case 0x088E:
    case 0x088F:
    case 0x0890:
    case 0x0891:
    case 0x0892:
    case 0x0893:
    case 0x0894:
    case 0x0895:
    case 0x0896:
    case 0x0897:
    case 0x08AE:
    case 0x08AF:
    case 0x422B:
    case 0x422C:
    case 0x4238:
    case 0x4239:
        return "iwlwifi-1000/6000";

    // iwlwifi MVM: 7260/3160.
    case 0x08B1:
    case 0x08B2:
    case 0x08B3:
    case 0x08B4:
        return "iwlwifi-7260";
    // 7265/3165/3168.
    case 0x095A:
    case 0x095B:
    case 0x24FB:
    case 0x3165:
    case 0x3166:
        return "iwlwifi-7265";
    // 8260/8265.
    case 0x24F3:
    case 0x24F4:
    case 0x24F5:
    case 0x24F6:
    case 0x24FD:
        return "iwlwifi-8260";
    // 9000 family (9260/9560/Killer 1550).
    case 0x2526:
    case 0x271B:
    case 0x271C:
    case 0x30DC:
    case 0x31DC:
    case 0x9DF0:
    case 0xA370:
        return "iwlwifi-9000";
    // Qu/Ty/So/Ma (Wi-Fi 6/6E).
    case 0x02F0:
    case 0x06F0:
    case 0x2723:
    case 0x2725:
    case 0x2729:
    case 0x34F0:
    case 0x3DF0:
    case 0x43F0:
    case 0x4DF0:
    case 0x51F0:
    case 0x51F1:
    case 0x54F0:
    case 0x7A70:
    case 0x7AF0:
    case 0x7E40:
    case 0x7F70:
    case 0xA0F0:
        return "iwlwifi-AX2xx";
    // Bz/Sc and discrete Glacier Lake (Wi-Fi 7 and successors).
    case 0x272B:
    case 0x4D40:
    case 0x6E70:
    case 0x7740:
    case 0xA840:
    case 0xD240:
    case 0xD340:
    case 0xE340:
    case 0xE440:
        return "iwlwifi-Be2xx";
    default:
        return nullptr;
    }
}

/// The current DuetOS shell implements the iwlwifi CSR contract, not the
/// older iwlegacy register/firmware contract. Classification remains broad;
/// probe eligibility is intentionally narrower and fail-closed.
constexpr bool IntelIwlwifiProbeEligible(u16 did)
{
    // The old shell did more than identify the transport: it selected
    // firmware from an incorrectly decoded HW revision and drove an upload
    // state machine without preserving subsystem-qualified PCI matches.
    // Keep every exact ID visible to inventory, but fail closed until that
    // backend is split by transport generation and audited end-to-end.
    (void)did;
    return false;
}

constexpr WirelessBackend IntelWirelessBackendFromDeviceId(u16 did)
{
    switch (did)
    {
    case 0x4222:
    case 0x4227:
    case 0x4229:
    case 0x4230:
        return WirelessBackend::IntelIwlegacy;
    default:
        return IntelWirelessTag(did) != nullptr ? WirelessBackend::IntelIwlwifi : WirelessBackend::None;
    }
}

// ---------------------------------------------------------------
// Realtek.
// ---------------------------------------------------------------

/// Exact upstream PCI backend for a Realtek wireless device.  USB product
/// IDs such as B812 and C820 are intentionally absent.
constexpr WirelessBackend RealtekWirelessBackendFromDeviceId(u16 did)
{
    switch (did)
    {
    // rtlwifi (one backend shared by several generation-specific modules).
    case 0x002B:
    case 0x8171:
    case 0x8172:
    case 0x8173:
    case 0x8174:
    case 0x8176:
    case 0x8177:
    case 0x8178:
    case 0x8179:
    case 0x818B:
    case 0x8191:
    case 0x8192:
    case 0x8193:
    case 0x8723:
    case 0xB723:
    case 0x8812:
    case 0x8821:
        return WirelessBackend::RealtekRtlwifi;

    // rtw88.  0x8813 is RTL8814AE despite the PCI product number.
    case 0x8813:
    case 0xB821:
    case 0xC821:
    case 0xB822:
    case 0xC822:
    case 0xC82F:
    case 0xD723:
        return WirelessBackend::RealtekRtw88;

    // rtw89.
    case 0x8852:
    case 0xA85A:
    case 0xB520:
    case 0xB852:
    case 0xB85B:
    case 0xC852:
    case 0xB851:
    case 0x8922:
    case 0x892B:
        return WirelessBackend::RealtekRtw89;
    default:
        return WirelessBackend::None;
    }
}

/// Family tag for a Realtek PCIe wireless device, nullptr otherwise.
/// Tags identify the upstream backend rather than guessing a chip revision
/// from unrelated SYS_CFG bits.
constexpr const char* RealtekWirelessTag(u16 did)
{
    switch (RealtekWirelessBackendFromDeviceId(did))
    {
    case WirelessBackend::RealtekRtlwifi:
        return "rtlwifi-pci";
    case WirelessBackend::RealtekRtw88:
        return "rtw88-pci";
    case WirelessBackend::RealtekRtw89:
        return "rtw89-pci";
    default:
        return nullptr;
    }
}

/// Preferred register aperture from each current upstream PCI driver. The
/// rtl8192se module uses BAR1; the other rtlwifi modules plus rtw88 and rtw89
/// use BAR2. This is classification metadata only and never authorizes MMIO.
constexpr u8 RealtekWirelessPreferredMmioBar(u16 did)
{
    switch (did)
    {
    case 0x8171:
    case 0x8172:
    case 0x8173:
    case 0x8174:
    case 0x8192:
        return 1; // rtl8192se
    default:
        return RealtekWirelessBackendFromDeviceId(did) == WirelessBackend::None ? kInvalidPciBar : 2;
    }
}

constexpr bool RealtekWirelessProbeEligible(u16 did)
{
    // The retired generic rtl88xx shell mixed rtlwifi/rtw88/rtw89 register
    // and firmware layouts.  Exact inventory remains available, but no
    // backend may touch its register aperture until its contract is implemented.
    (void)did;
    return false;
}

/// Wired Realtek family tag ("realtek-unknown" fallback keeps the
/// historic behaviour for IDs we can't classify).
constexpr const char* RealtekWiredTag(u16 did)
{
    switch (did)
    {
    case 0x8139:
        return "rtl8139";
    case 0x8168:
    case 0x8169:
        return "rtl8169";
    case 0x8136:
        return "rtl8101e";
    case 0x8125:
        return "rtl8125-2.5g";
    default:
        return nullptr;
    }
}

// ---------------------------------------------------------------
// Broadcom.
// ---------------------------------------------------------------

/// Exact upstream PCI backend candidates for Broadcom wireless silicon.
/// The mask is deliberately plural: raw 4365 appears in both the BCMA and
/// brcmfmac tables under different subsystem tuples. A candidate mask is
/// inventory metadata, never a flat safe-probe match.
constexpr WirelessBackendMask BroadcomWirelessCandidateBackendsFromDeviceId(u16 did)
{
    switch (did)
    {
    // b43 over SSB.
    case 0x4301:
    case 0x4306:
    case 0x4307:
    case 0x4311:
    case 0x4312:
    case 0x4315:
    case 0x4318:
    case 0x4319:
    case 0x4320:
    case 0x4321:
    case 0x4322:
    case 0x4324:
    case 0x4325:
    case 0x4328:
    case 0x4329:
    case 0x432B:
    case 0x432C:
    case 0x4350:
    case 0x4351:
    case 0xA8D6:
        return WirelessBackendBit(WirelessBackend::BroadcomB43Ssb);

    // BCMA host PCI rows.
    case 0x0576:
    case 0x4313:
    case 0x4331:
    case 0x4353:
    case 0x4357:
    case 0x4358:
    case 0x4359:
    case 0x4360:
    case 0x43A0:
    case 0x43A9:
    case 0x43AA:
    case 0x43B1:
    case 0x4727:
    case 0xA8D8:
    case 0xA8DB:
    case 0xA8DC:
        return WirelessBackendBit(WirelessBackend::BroadcomBcma);

    // Subsystem-qualified raw IDs. 4355 is brcmfmac-only; 4365 is
    // ambiguous until its subsystem tuple selects BCMA or brcmfmac.
    case 0x4355:
        return WirelessBackendBit(WirelessBackend::BroadcomBrcmfmac);
    case 0x4365:
        return WirelessBackendBit(WirelessBackend::BroadcomBcma) |
               WirelessBackendBit(WirelessBackend::BroadcomBrcmfmac);

    // Generic brcmfmac PCIe rows. 0xAA52 is decimal 43602 in a u16.
    case 0x4354:
    case 0x43A3:
    case 0x43BA:
    case 0x43BB:
    case 0x43BC:
    case 0x43C3:
    case 0x43C4:
    case 0x43C5:
    case 0x43CA:
    case 0x43CB:
    case 0x43CC:
    case 0x43D3:
    case 0x43D9:
    case 0x43DC:
    case 0x43E9:
    case 0x43EC:
    case 0x43EF:
    case 0x440D:
    case 0x4415:
    case 0x4417:
    case 0x4425:
    case 0x4433:
    case 0x4464:
    case 0x4488:
    case 0x449D:
    case 0xAA31:
    case 0xAA52:
        return WirelessBackendBit(WirelessBackend::BroadcomBrcmfmac);
    default:
        return 0;
    }
}

/// Resolve a Broadcom candidate to the exact upstream backend using the PCI
/// subsystem tuple. `subsystem_known=false` fails closed for raw 4355/4365;
/// generic rows do not require a subsystem qualifier.
constexpr WirelessBackend BroadcomWirelessBackendFromIdentity(u16 did, u16 subsystem_vendor_id, u16 subsystem_device_id,
                                                              bool subsystem_known)
{
    if (did == 0x4355)
    {
        return subsystem_known && subsystem_vendor_id == kVendorBroadcom && subsystem_device_id == 0x4355
                   ? WirelessBackend::BroadcomBrcmfmac
                   : WirelessBackend::None;
    }
    if (did == 0x4365)
    {
        if (!subsystem_known)
            return WirelessBackend::None;
        if (subsystem_vendor_id == kVendorBroadcom && subsystem_device_id == 0x4365)
            return WirelessBackend::BroadcomBrcmfmac;
        if ((subsystem_vendor_id == 0x1028 && (subsystem_device_id == 0x0016 || subsystem_device_id == 0x0018)) ||
            (subsystem_vendor_id == 0x105B && subsystem_device_id == 0xE092) ||
            (subsystem_vendor_id == 0x103C && subsystem_device_id == 0x804A))
            return WirelessBackend::BroadcomBcma;
        return WirelessBackend::None;
    }

    const WirelessBackendMask candidates = BroadcomWirelessCandidateBackendsFromDeviceId(did);
    if (candidates == WirelessBackendBit(WirelessBackend::BroadcomB43Ssb))
        return WirelessBackend::BroadcomB43Ssb;
    if (candidates == WirelessBackendBit(WirelessBackend::BroadcomBcma))
        return WirelessBackend::BroadcomBcma;
    if (candidates == WirelessBackendBit(WirelessBackend::BroadcomBrcmfmac))
        return WirelessBackend::BroadcomBrcmfmac;
    return WirelessBackend::None;
}

constexpr const char* BroadcomWirelessTag(u16 did)
{
    if (did == 0x4355 || did == 0x4365)
        return BroadcomWirelessCandidateBackendsFromDeviceId(did) != 0 ? "brcm-wifi-candidate" : nullptr;

    const WirelessBackendMask candidates = BroadcomWirelessCandidateBackendsFromDeviceId(did);
    if (candidates == WirelessBackendBit(WirelessBackend::BroadcomB43Ssb))
        return "b43-ssb-wifi";
    if (candidates == WirelessBackendBit(WirelessBackend::BroadcomBcma))
        return "brcm-bcma-wifi";
    if (candidates == WirelessBackendBit(WirelessBackend::BroadcomBrcmfmac))
        return "brcmfmac-pcie";
    return nullptr;
}

constexpr bool BroadcomWirelessProbeEligible(u16 did)
{
    // b43/SSB, BCMA, and brcmfmac have different core enumeration and
    // firmware formats.  In particular, brcmfmac must program the BAR0
    // backplane window before core access; BAR0+0 is not a universal
    // ChipCommon register.  The old generic shell is therefore disabled.
    (void)did;
    return false;
}

/// Format a Broadcom ChipCommon chip ID the way vendor firmware
/// files are named. Mirrors Linux `brcmf_chip_name()`: IDs above
/// 0xA000 (and below 0x4000) are decimal chip numbers —
/// BCM43602 reads back 0xAA52 == 43602 — while the 0x4000..0x9FFF
/// band prints as lowercase hex (0x4331 → "4331"). Writes a
/// NUL-terminated string, returns the character count (0 if the
/// buffer can't hold the worst case).
constexpr u32 BcmChipNameFormat(u16 chip_id, char* buf, u32 buf_len)
{
    if (buf == nullptr || buf_len < 6) // 5 digits/nibbles max + NUL
        return 0;
    u32 off = 0;
    if (chip_id > 0xA000 || chip_id < 0x4000)
    {
        // Decimal. u16 max is 65535 — 5 digits.
        char tmp[5] = {};
        u32 n = chip_id;
        u32 digits = 0;
        do
        {
            tmp[digits++] = static_cast<char>('0' + (n % 10));
            n /= 10;
        } while (n != 0);
        while (digits != 0)
            buf[off++] = tmp[--digits];
    }
    else
    {
        constexpr const char* kHex = "0123456789abcdef";
        buf[off++] = kHex[(chip_id >> 12) & 0xF];
        buf[off++] = kHex[(chip_id >> 8) & 0xF];
        buf[off++] = kHex[(chip_id >> 4) & 0xF];
        buf[off++] = kHex[chip_id & 0xF];
    }
    buf[off] = '\0';
    return off;
}

// ---------------------------------------------------------------
// Family-string heuristics.
// ---------------------------------------------------------------

constexpr bool StrPrefixMatches(const char* s, const char* prefix)
{
    if (s == nullptr || prefix == nullptr)
        return false;
    for (u32 i = 0; prefix[i] != '\0'; ++i)
    {
        if (s[i] == '\0' || s[i] != prefix[i])
            return false;
    }
    return true;
}

/// True iff a family tag names a wireless adapter. Secondary signal
/// behind the PCI subclass check — some vendors put wireless on
/// subclass 0x00. Prefixes must cover every tag the wireless tag
/// functions above (and MediatekNicTag in net.cpp) can emit.
constexpr bool NicFamilyLooksWireless(const char* family)
{
    return StrPrefixMatches(family, "iwlwifi") || StrPrefixMatches(family, "iwlegacy") ||
           StrPrefixMatches(family, "rtlwifi") || StrPrefixMatches(family, "rtw88") ||
           StrPrefixMatches(family, "rtw89") || StrPrefixMatches(family, "b43") || StrPrefixMatches(family, "brcm-") ||
           StrPrefixMatches(family, "brcmfmac") || StrPrefixMatches(family, "mt76") ||
           StrPrefixMatches(family, "mt7615") || StrPrefixMatches(family, "mt7663") ||
           StrPrefixMatches(family, "mt7915") || StrPrefixMatches(family, "mt7916") ||
           StrPrefixMatches(family, "mt7921") || StrPrefixMatches(family, "mt7922") ||
           StrPrefixMatches(family, "mt7925") || StrPrefixMatches(family, "mt7902") ||
           StrPrefixMatches(family, "mt7920") || StrPrefixMatches(family, "mt7927");
}

} // namespace nic_ids

} // namespace duetos::drivers::net
