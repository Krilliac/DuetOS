#pragma once

#include "drivers/net/nic_ids.h"
#include "util/result.h"
#include "util/types.h"

/*
 * DuetOS — PCI network discovery and concrete-driver dispatch.
 *
 * `NetInit` walks the PCI cache after enumeration, records exact
 * evidence-backed family candidates, and runs only a backend whose
 * register contract is explicitly enabled. Classification never authorizes
 * MMIO: unsupported wired families and all current PCI Wi-Fi candidates are
 * inventory-only. Packet I/O is enabled only for the 8086:100E and 8086:10D3
 * emulated Intel profiles, exact AMD PCnet 1022:2000, and modern virtio-net
 * 1AF4:1041. The transitional virtio identity 1AF4:1000 remains inventory-only.
 * Functional backends must own callback admission, worker join, and
 * bus-master-off teardown; focused QEMU restart proof remains a separate
 * release gate.
 *
 * A selected backend owns its BAR choice. Mappings are cached by BDF, BAR,
 * physical address, and size so restart cycles reuse the monotonic MMIO
 * arena rather than consuming a fresh aperture. No generic "map BAR0 for
 * every network controller" path is permitted.
 *
 * The device tier maps to wiki/drivers/Driver-Overview.md (Hardware
 * Target Matrix):
 *   Tier 1: Intel e1000 / e1000e (100E/10D3 functional profiles today)
 *   Tier 2: Realtek rtl8169, Broadcom bcm57xx
 *   Tier 3: modern virtio-net 1041 (dev-only functional profile)
 *   Tier 4: Intel/Realtek/Broadcom/MediaTek PCI Wi-Fi (inventory only)
 *
 * Context: kernel. `NetInit` runs after `PciEnumerate` and can run again
 * after a successful `NetShutdown`.
 */

namespace duetos::drivers::net
{

// Vendor IDs live in drivers/net/nic_ids.h alongside the device-ID
// classification tables (single source of truth, host-testable).

// PCI class codes.
inline constexpr u8 kPciClassNetwork = 0x02;
inline constexpr u8 kPciSubclassEthernet = 0x00;
inline constexpr u8 kPciSubclassTokenRing = 0x01;
inline constexpr u8 kPciSubclassOther = 0x80;

inline constexpr u64 kMaxNics = 4;

struct NicInfo
{
    enum class WirelessFwState : u8
    {
        NotApplicable = 0, // wired NIC or non-wireless probe path
        Ready,             // blob located and accepted by loader
        Missing,           // lookup miss in /lib/firmware
        Incompatible,      // blob found but rejected by size/format gates
        LoadError,         // generic backend / argument / I/O failure
        UploadFailed,      // blob parsed, but hardware upload did not reach ALIVE
    };

    u16 vendor_id;
    u16 device_id;
    u16 subsystem_vendor_id;
    u16 subsystem_device_id;
    u8 bus;
    u8 device;
    u8 function;
    u8 class_code;
    u8 subclass; // 0x00 Ethernet, 0x80 Other (Wi-Fi)
    u8 programming_interface;
    u8 revision_id;
    bool subsystem_known;
    const char* vendor; // short string ("Intel", "Realtek", ...)
    const char* family; // chip family ("e1000e-82574", "rtl8169", ...)
    u64 mmio_phys;
    u64 mmio_size; // bytes actually mapped at mmio_virt, never the larger raw BAR extent
    void* mmio_virt;
    u8 mmio_bar; // PCI BAR index selected by the concrete backend contract
    u8 mac[6];   // all-zero if the vendor probe didn't read it
    bool mac_valid;
    bool link_up; // filled by the vendor probe; false on NICs
                  // whose status register we don't read yet
    // True only when a chip-specific backend has completed its supported
    // bring-up. Candidate classification and read-only inventory never set it.
    bool driver_online;
    // Wireless-only backend state. Probe-only candidates leave this false;
    // a future safe backend may set it while an accepted firmware load is
    // pending. Wired NICs always leave it false.
    bool firmware_pending;
    WirelessFwState wireless_fw_state;
    // Backend-specific chip-identification dword. Zero unless a safe backend
    // reached an authorized MMIO read.
    u32 chip_id;
};

/// Walk the PCI cache, register every network controller, and run only an
/// admitted vendor backend. Repeated calls while Running are idempotent.
/// Returns Busy while teardown is in progress or a failed teardown has left
/// quarantined contexts that must be drained by another `NetShutdown`.
::duetos::core::Result<void> NetInit();

/// Quiesce live NIC workers and operations, then clear the discovery records
/// so the next `NetInit` re-walks PCI. Returns Busy rather than releasing DMA
/// if an exact worker generation or operation pin does not drain in time.
/// Stable MMIO mappings remain owned by the bounded BDF/BAR cache.
::duetos::core::Result<void> NetShutdown();

/// Number of NICs discovered.
u64 NicCount();

/// Copy one discovered record while the registry is Running. Returns false
/// for a stale/out-of-range index or while init, shutdown, or quarantine owns
/// the registry. Callers never retain a reference into mutable global storage.
bool NicSnapshot(u64 index, NicInfo* out);

/// True iff the NIC at `index` is a wireless adapter — discriminated
/// by either the PCI subclass (0x80 = "other / wireless" historically
/// used for Wi-Fi) or by family-string heuristics backed by exact Intel,
/// Realtek, Broadcom, and MediaTek candidate sets. Used by the
/// shell `netscan` and the GUI network flyout to separate wired
/// from wireless adapters honestly — DuetOS has no wireless driver
/// online, so detected wireless adapters are advertised as "no
/// driver" rather than silently treated as Ethernet.
bool NicIsWireless(u64 index);

/// Display-friendly summary of the wireless story for the GUI net
/// flyout: how many wireless adapters were detected and whether any
/// have a driver online (today: always 0 — no wireless driver).
struct WirelessStatus
{
    u32 adapters_detected;
    u32 drivers_online;
    u32 firmware_ready;
    u32 firmware_missing;
    u32 firmware_incompatible;
    u32 firmware_load_error;
    u32 firmware_upload_failed;
};
WirelessStatus WirelessStatusRead();

// Vendor candidate classifiers. A returned tag is inventory metadata, not
// proof that a concrete driver is online or that MMIO is safe.

const char* IntelNicTag(u16 device_id);
const char* RealtekNicTag(u16 device_id);
const char* BroadcomNicTag(u16 device_id, u16 subsystem_vendor_id, u16 subsystem_device_id, bool subsystem_known);
const char* VirtioNetTag(u16 device_id);
const char* MediatekNicTag(u16 vendor_id, u16 device_id);

} // namespace duetos::drivers::net
