#pragma once

#include "util/result.h"
#include "util/types.h"

/*
 * DuetOS — Intel Management Engine Interface (MEI / HECI), v0.
 *
 * The MEI is the hardware mailbox the host CPU uses to talk to
 * Intel platform service engines: the Management Engine itself
 * (CSME), the Graphics System Controller (GSC) on discrete GPUs,
 * the Trusted Execution Engine (TXE) on Atom platforms, and the
 * platform-controller-hub firmware on recent Core SoCs. It is a
 * single PCI device per platform (chipset-integrated) plus a
 * second device per discrete GPU (the Arc / Battlemage / DG2
 * GSC).
 *
 * On the wire the MEI exposes a tiny memory-mapped register
 * file: H_CB (host circular buffer write), ME_CB (controller
 * circular buffer read), H_CSR / ME_CSR (control/status). A
 * full driver implements the HECI client-multiplexing protocol
 * on top — every consumer (gscfw, mkhi, hbm) gets a guid-
 * addressed virtual channel.
 *
 * v0 scope:
 *   - PCI probe of every Intel device whose (class, subclass,
 *     prog_if) matches the well-known MEI signature (class
 *     0x07 Communications, subclass 0x80 Other). Vendor 0x8086
 *     is required.
 *   - Map BAR0 as MMIO so a future driver can reach H_CSR /
 *     ME_CSR without re-running the size probe.
 *   - Inventory of discovered devices behind a stable accessor
 *     (`MeiDeviceCount` / `MeiDevice`).
 *   - Boot-log line per device + the high-level role it likely
 *     plays based on its PCI device-ID family (CSME / GSC / TXE).
 *
 * Out of scope (deferred):
 *   - HECI bus protocol. The H2M / M2H handshake, version-
 *     negotiation, and per-client multiplexing each need their
 *     own slice. The PCI scaffold is a prerequisite for all of
 *     them.
 *   - Firmware update over MEI. The GSC firmware-image parser
 *     (drivers/gpu/intel_gsc_fw) lands the image side of the
 *     update path; pushing the bytes to the GSC needs the HECI
 *     bus + the GSC client-handshake.
 *
 * Threading: kernel context only. Probe runs once at boot.
 *
 * Subsystem isolation: this is a freestanding kernel driver. No
 * subsystem (Win32 / Linux ABI) reaches it directly.
 */

namespace duetos::drivers::mei
{

inline constexpr u16 kVendorIntel = 0x8086;
// Intel MEI / HECI uses Communications-class (0x07) / Other (0x80) /
// prog_if 0x00.
inline constexpr u8 kPciClassCommunications = 0x07;
inline constexpr u8 kPciSubclassMeiOther = 0x80;

inline constexpr u32 kMaxMeiDevices = 4;

enum class MeiRole : u8
{
    Unknown = 0,
    Csme, // Chipset CSME (laptops/desktops/servers)
    Gsc,  // Discrete-GPU Graphics System Controller (DG2/Arc/BM)
    Txe,  // Trusted Execution Engine (Atom platforms)
    Sps,  // Server platform services (Xeon SP)
};

/// Decoded ME operating mode from the HFS1 register (bits 16:19).
/// "Disabled-HAP" is the success signal an operator running
/// `me_cleaner` is looking for — the ME ran BRINGUP, saw the HAP
/// bit set in the firmware blob, and halted itself instead of
/// loading the full management stack. "Normal" means the ME is
/// fully active; everything else is a vendor-specific halt path
/// that may or may not be honoured across firmware updates.
enum class MeiOperatingMode : u8
{
    Unknown = 0,
    Normal,          // 0x0 — ME fully operational
    AltDisable,      // 0x1 — alternate disable mode
    SoftTempDisable, // 0x2 — temp disable via SW
    SecurityJumper,  // 0x3 — security override via jumper
    SecurityMei,     // 0x4 — security override via MEI message
    EnhancedDebug,   // 0x5 — enhanced debug mode
    DisabledHap,     // 0x6/0x7 — HAP-driven disable (me_cleaner success)
};

const char* MeiOperatingModeTag(MeiOperatingMode m);

struct MeiDeviceInfo
{
    bool live;
    u16 vendor_id;
    u16 device_id;
    u8 bus;
    u8 device;
    u8 function;
    MeiRole role;
    const char* role_tag; // "csme" / "gsc" / "txe" / "sps" / "?"
    u64 mmio_phys;
    u64 mmio_size;
    void* mmio_virt;
    // Vendor state captured before fencing — once the device is
    // registered with the guard, further config writes are denied,
    // so these are observed exactly once at probe time.
    u32 hfs1; // PCI config 0x40 — host firmware status 1
    u32 hfs2; // PCI config 0x48 — host firmware status 2
    MeiOperatingMode mode;
    const char* mode_tag; // human-readable form of `mode`
    bool bme_cleared;     // true if we successfully cleared Bus Master Enable
};

/// Walk the PCI cache, register every Intel MEI/HECI device, map
/// each one's primary BAR. Idempotent — early-returns once the
/// inventory is populated.
void MeiInit();

/// Number of MEI devices found.
u32 MeiDeviceCount();

/// Accessor for an MEI record. Panics on out-of-range index.
const MeiDeviceInfo& MeiDevice(u32 index);

/// Map an Intel MEI device-ID to a coarse role tag. Looks at the
/// well-known device-ID families (CSME, GSC, TXE, SPS). Defaults
/// to MeiRole::Unknown for anything unrecognised.
MeiRole MeiClassifyDeviceId(u16 device_id);

/// Short string for an MeiRole.
const char* MeiRoleTag(MeiRole r);

/// Boot self-test. Drives MeiClassifyDeviceId against a handful
/// of known device-IDs and asserts the tag table is wired up.
/// Logs `[mei] selftest pass/fail` and panics on failure.
void MeiSelfTest();

} // namespace duetos::drivers::mei
