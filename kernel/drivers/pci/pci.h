#pragma once

#include "arch/x86_64/traps.h"
#include "util/result.h"
#include "util/types.h"

/*
 * DuetOS — PCI / PCIe enumeration and configuration access.
 *
 * Walks the PCI config space via the classic 0xCF8 / 0xCFC port pair:
 *   - 0xCF8 CONFIG_ADDRESS — write (enable|bus|dev|fn|offset) here
 *   - 0xCFC CONFIG_DATA    — then read/write the 32-bit register
 *
 * MMCONFIG (ECAM) from the ACPI MCFG table is preferred when available;
 * the classic 0xCF8 / 0xCFC port pair remains the fallback. Both paths
 * share one config-space lock. ECAM does not need that lock for a single
 * naturally aligned dword, but multi-register transactions such as BAR
 * sizing do: no peer may observe or overwrite a temporary probe value.
 *
 * Scope limits that will be fixed in later commits:
 *   - Bus enumeration is shallow: bus 0..3, device 0..31, function
 *     0..7. Recursive walking into PCI bridges comes when we care
 *     about anything beyond the root bus (q35 hangs everything
 *     interesting on bus 0; bus 1+ is typically empty until we hit
 *     a board with bridges).
 *   - BAR resource allocation is deferred. Drivers can inspect and size
 *     firmware-assigned type-0 BARs, but this layer does not relocate them.
 *   - No interrupt line / INTx routing (needs ACPI _PRT or MSI).
 *
 * Context: kernel. `PciEnumerate` runs once at boot; accessors are
 * read-only after.
 */

namespace duetos::drivers::pci
{

constexpr u64 kMaxDevices = 64;

struct DeviceAddress
{
    u8 bus;
    u8 device;   // 0..31
    u8 function; // 0..7
    u8 _pad;
};

struct Device
{
    DeviceAddress addr;
    u16 vendor_id; // 0xFFFF means no device
    u16 device_id;
    u16 subsystem_vendor_id;
    u16 subsystem_device_id;
    u8 class_code;            // high-level group (e.g. 0x01 mass storage)
    u8 subclass;              // subgroup (e.g. 0x06 SATA)
    u8 programming_interface; // canonical PCI name (e.g. 0x01 AHCI)
    u8 revision_id;           // canonical PCI Revision ID name
    u8 prog_if;               // immutable compatibility mirror
    u8 revision;              // immutable compatibility mirror
    u8 header_type;           // 0x00 endpoint, 0x01 PCI-to-PCI bridge, 0x02 CardBus
    bool subsystem_known;
};

/// Walk every (bus, device, function) on bus 0..3; cache and log each
/// present device. Idempotent: a second call without an intervening
/// `PciTeardown` returns immediately so the cached device list and
/// ECAM mapping survive. Used as the driver fault-domain init hook
/// for the "pci" domain.
void PciEnumerate();

/// Drop the cached device list + ECAM aperture so a subsequent
/// `PciEnumerate` runs the bus walk again. The MMIO mapping for
/// the previous ECAM aperture leaks (the arena is a bump
/// allocator); same caveat the framebuffer teardown documents.
/// Idempotent.
void PciTeardown();

/// Number of devices discovered by the most recent `PciEnumerate`.
u64 PciDeviceCount();

/// Accessor for a cached device record. Panics on out-of-range index.
const Device& PciDevice(u64 index);

// -----------------------------------------------------------------
// Raw config-space access. Useful for drivers that need to read
// vendor-specific registers past the standard header fields.
// -----------------------------------------------------------------

u32 PciConfigRead32(DeviceAddress addr, u8 offset);
u16 PciConfigRead16(DeviceAddress addr, u8 offset);
u8 PciConfigRead8(DeviceAddress addr, u8 offset);
void PciConfigWrite32(DeviceAddress addr, u8 offset, u32 value);

// -----------------------------------------------------------------
// BAR (Base Address Register) inspection.
//
// Each header-type-0 endpoint has up to 6 BARs at config offsets
// 0x10, 0x14, 0x18, 0x1C, 0x20, 0x24. Each BAR is either a 32-bit
// MMIO window (including the obsolete below-1-MiB encoding), a
// 64-bit MMIO window (consumes the next BAR slot too), or an I/O
// port range. The size of each region is discovered by writing all
// 1s and reading back the one-bits mask.
//
// PciReadBar performs that size probe non-destructively (saves +
// restores the BAR value) and returns the decoded result.
//   bar.address      : base MMIO/IO address (already decoded).
//                      For 64-bit BARs, includes the upper half.
//   bar.size         : size in bytes. 0 means the BAR is unused.
//   bar.is_io        : true for I/O port BAR, false for MMIO.
//   bar.is_64bit     : true if BAR consumes this index + index+1.
//   bar.is_prefetchable : MMIO-only; true if the spec allows
//                      prefetching (controller framebuffer etc.).
// -----------------------------------------------------------------

struct Bar
{
    u64 address;
    u64 size;
    bool is_io;
    bool is_64bit;
    bool is_prefetchable;
    bool _pad;
};

namespace detail
{

// Decode the standard identity dwords into one cached record. Offset 0x2C is
// a subsystem tuple only in a type-0 header; bridge/CardBus layouts reuse that
// address for unrelated fields. Unknown subsystem identity is normalized to
// {0, 0, false} so a consumer that forgets the boolean still fails closed.
constexpr Device DecodeDeviceIdentity(DeviceAddress addr, u32 vendor_device, u32 class_revision, u32 header,
                                      u32 subsystem, bool subsystem_register_read)
{
    Device device{};
    device.addr = addr;
    device.addr._pad = 0;
    device.vendor_id = static_cast<u16>(vendor_device & 0xFFFFu);
    device.device_id = static_cast<u16>((vendor_device >> 16) & 0xFFFFu);
    device.revision_id = static_cast<u8>(class_revision & 0xFFu);
    device.programming_interface = static_cast<u8>((class_revision >> 8) & 0xFFu);
    device.revision = device.revision_id;
    device.prog_if = device.programming_interface;
    device.subclass = static_cast<u8>((class_revision >> 16) & 0xFFu);
    device.class_code = static_cast<u8>((class_revision >> 24) & 0xFFu);
    device.header_type = static_cast<u8>((header >> 16) & 0xFFu);

    const bool endpoint_layout = (device.header_type & 0x7Fu) == 0;
    const u16 subsystem_vendor = static_cast<u16>(subsystem & 0xFFFFu);
    if (endpoint_layout && subsystem_register_read && subsystem_vendor != 0 && subsystem_vendor != 0xFFFFu)
    {
        device.subsystem_vendor_id = subsystem_vendor;
        device.subsystem_device_id = static_cast<u16>((subsystem >> 16) & 0xFFFFu);
        device.subsystem_known = true;
    }
    return device;
}

// Pure BAR-mask decoder shared by the kernel transaction and hosted tests.
// The caller supplies the exact original and all-ones-probe dwords. Invalid,
// non-canonical, misaligned, or overflowing encodings fail closed as Bar{}.
constexpr Bar DecodeBarProbe(u8 index, u32 original_low, u32 original_high, u32 probe_low, u32 probe_high)
{
    if (index >= 6 || original_low == 0 || original_low == 0xFFFFFFFFu)
    {
        return Bar{};
    }

    const bool is_io = (original_low & 0x1u) != 0;
    const u32 memory_type = (original_low >> 1) & 0x3u;
    const bool is_below_1m = !is_io && memory_type == 0x1u;
    const bool is_64bit = !is_io && memory_type == 0x2u;
    if ((!is_io && memory_type == 0x3u) || (is_64bit && index + 1 >= 6))
    {
        return Bar{};
    }

    const u32 attribute_mask = is_io ? 0x3u : 0xFu;
    if ((original_low & attribute_mask) != (probe_low & attribute_mask) || (is_io && (original_low & 0x2u) != 0))
    {
        return Bar{};
    }

    // Memory type 01 is the obsolete but valid below-1-MiB format. Its
    // address field is only bits 19:4; accepting residue in bits 31:20 would
    // turn a malformed device response into an aliased resource.
    if (is_below_1m && ((original_low | probe_low) & 0xFFF00000u) != 0)
    {
        return Bar{};
    }

    const u64 width_mask = is_64bit ? ~u64{0} : is_below_1m ? 0xFFFFFULL : 0xFFFFFFFFULL;
    const u64 address_mask = is_io         ? 0xFFFFFFFCULL
                             : is_64bit    ? 0xFFFFFFFFFFFFFFF0ULL
                             : is_below_1m ? 0x000FFFF0ULL
                                           : 0xFFFFFFF0ULL;
    const u64 address =
        is_64bit ? (u64(original_high) << 32) | (u64(original_low) & 0xFFFFFFF0ULL) : u64(original_low) & address_mask;
    const u64 probe_mask =
        is_64bit ? (u64(probe_high) << 32) | (u64(probe_low) & 0xFFFFFFF0ULL) : u64(probe_low) & address_mask;
    if (probe_mask == 0)
    {
        return Bar{};
    }

    const u64 size = (~probe_mask + 1) & width_mask;
    if (size == 0 || (size & (size - 1)) != 0)
    {
        return Bar{};
    }

    // A legal BAR mask is a contiguous run of implemented high address
    // bits. Reject sparse or otherwise hostile masks even if their two's-
    // complement happens to look like a power of two.
    const u64 canonical_mask = (~(size - 1)) & width_mask;
    if (probe_mask != canonical_mask || (address & (size - 1)) != 0)
    {
        return Bar{};
    }

    // Keep the end-address calculation representable in the BAR's width.
    // Alignment normally implies this, but the explicit guard makes the
    // fail-closed contract independent of that arithmetic observation.
    if (address > width_mask - (size - 1))
    {
        return Bar{};
    }

    return Bar{.address = address,
               .size = size,
               .is_io = is_io,
               .is_64bit = is_64bit,
               .is_prefetchable = !is_io && (original_low & 0x8u) != 0,
               ._pad = false};
}

} // namespace detail

/// Read and size BAR `index` (0..5) on a header-type-0 endpoint.
/// Returns Bar{size=0} for empty / invalid BARs. The entire probe is
/// serialized against every other config-space access. I/O and memory
/// decode are disabled while the BAR value is transient, then every BAR
/// dword is restored before the exact low-16 Command value is restored.
///
/// This is still a bring-up operation: bus mastering and unrelated Command
/// bits stay unchanged by contract, and device-specific agents can exist
/// outside this config lock. Call before the driver starts device traffic.
Bar PciReadBar(DeviceAddress addr, u8 index);

// -----------------------------------------------------------------
// PCI capability list iteration. Each capability is at least two
// bytes: {id, next_offset}. next_offset == 0 terminates the list.
// Status register bit 4 (offset 0x06) gates whether a capabilities
// list is present at all.
//
// Common capability IDs:
//   0x01 PM  (power management)
//   0x05 MSI (message-signalled interrupts)
//   0x10 PCIe (express capability)
//   0x11 MSI-X (MSI with separate vector table)
//   0x12 SATA (SATA HBA-specific)
//   0x13 AF  (advanced features)
// -----------------------------------------------------------------

constexpr u8 kPciCapMsi = 0x05;
constexpr u8 kPciCapPcie = 0x10;
constexpr u8 kPciCapMsix = 0x11;

/// Find the first standard capability with the given ID. Returns
/// the config-space offset where that capability's header lives
/// (always non-zero for the low 16 reserved offsets), or 0 if not
/// found / no capabilities list present.
u8 PciFindCapability(DeviceAddress addr, u8 cap_id);

/// Find the first PCIe extended capability with the given ID
/// (offset 0x100+ in ECAM). Returns the offset where the cap
/// header lives, or 0 if the chain doesn't carry that cap,
/// nothing's in the extended region, or the device isn't reachable
/// via MMCONFIG (legacy I/O-port reads can't see past 0xFF, so we
/// return 0 unconditionally on the legacy path).
///
/// Common ext-cap IDs:
///   0x0001 — Advanced Error Reporting (AER)
///   0x000F — Address Translation Services (ATS)
///   0x0010 — Single-Root I/O Virtualization (SR-IOV)
u16 PciFindExtCapability(DeviceAddress addr, u16 ext_cap_id);

// -----------------------------------------------------------------
// MSI-X routing helpers.
//
// MSI-X is the PCIe interrupt path every modern high-throughput
// device prefers (xHCI, NVMe, modern NICs). Each vector has its own
// target address + data, written into a table whose location is
// described by the MSI-X capability structure. This module exposes
// the plumbing; drivers own the table-BAR mapping.
//
// Typical driver sequence:
//     pci::MsixInfo info;
//     if (!pci::PciMsixFind(dev.addr, &info)) goto legacy_intx;
//     pci::Bar table_bar = pci::PciReadBar(dev.addr, info.table_bir);
//     void* table = mm::MapMmio(table_bar.address + info.table_offset,
//                                info.table_size * sizeof(pci::MsixEntry));
//     pci::PciMsixSetEntry(table, info.table_size, 0, bsp_apic_id, kVectorMyDevice);
//     pci::PciMsixEnable(dev.addr);
//
// For x86_64, the message-address format is fixed: 0xFEE0_0000 |
// (apic_id << 12), physical destination, redirection hint = 0. The
// message-data field carries {vector, delivery_mode, trigger, level};
// we always emit fixed + edge + assert. Drivers that need exotic
// delivery modes can reach in with PciMsixSetEntryRaw.
// -----------------------------------------------------------------

struct MsixInfo
{
    u8 cap_offset; // config-space offset of the MSI-X capability
    u8 table_bir;  // 0..5 — which BAR contains the table
    u8 pba_bir;    // 0..5 — which BAR contains the Pending Bit Array
    u8 _pad;
    u32 table_offset; // byte offset into table_bir
    u32 pba_offset;   // byte offset into pba_bir
    u16 table_size;   // number of entries in the table (1..2048)
    u16 _pad2;
};

/// MSI-X table entry (each is 16 bytes, aligned to 16).
struct MsixEntry
{
    u32 addr_lo;
    u32 addr_hi;
    u32 data;
    u32 vector_control; // bit 0 = mask
};

static_assert(sizeof(MsixEntry) == 16, "MSI-X entry must be 16 bytes");

/// Populate `info` with the device's MSI-X parameters. Returns false
/// if the device doesn't support MSI-X. Safe to call on any device.
bool PciMsixFind(DeviceAddress addr, MsixInfo* info);

/// Program a single table entry to route IRQ (vector) to lapic_id
/// using physical-destination + fixed-delivery + edge-triggered +
/// assert. `table_base` is the virtual pointer returned by the
/// caller's MapMmio of the table region; `table_size` is the
/// capability-reported entry count and is used to bounds-check
/// `index` — passing a stale or wrong size is a kernel panic,
/// never a silent out-of-bounds write into adjacent MMIO.
void PciMsixSetEntry(volatile void* table_base, u16 table_size, u16 index, u8 lapic_id, u8 vector);

/// Mask (or unmask) a single table entry's vector_control bit 0.
/// Safer than PciMsixEnable/Disable for per-vector gating once the
/// overall function is already enabled. `table_size` bounds-checks
/// `index` (same contract as PciMsixSetEntry).
void PciMsixMaskEntry(volatile void* table_base, u16 table_size, u16 index);
void PciMsixUnmaskEntry(volatile void* table_base, u16 table_size, u16 index);

/// Flip the Enable bit in the MSI-X message-control register, taking
/// the device from "legacy INTx" to "fire MSI-X interrupts per table
/// entries." Callers must have programmed at least one table entry
/// first — enabling with all vectors still masked is fine.
void PciMsixEnable(DeviceAddress addr);

/// Flip the Function-Mask bit instead of Enable — masks every MSI-X
/// vector at once while leaving per-entry control bits as the driver
/// programmed them. Useful for quiescing a device at reset time.
void PciMsixFunctionMask(DeviceAddress addr);
void PciMsixFunctionUnmask(DeviceAddress addr);

// -----------------------------------------------------------------
// All-in-one MSI-X routing helper.
//
// Replaces the boilerplate every driver writes when it just wants
// "fire vector V on LAPIC L when I'm done with this transfer":
//
//     pci::MsixInfo info;
//     pci::PciMsixFind(addr, &info);
//     pci::Bar bar = pci::PciReadBar(addr, info.table_bir);
//     void* tbl = mm::MapMmio(bar.address + info.table_offset, ...);
//     pci::PciMsixSetEntry(tbl, info.table_size, 0, lapic, vector);
//     pci::PciMsixUnmaskEntry(tbl, info.table_size, 0);
//     pci::PciMsixEnable(addr);
//
// becomes:
//
//     RESULT_TRY_ASSIGN(pci::MsixRoute r,
//                       pci::PciMsixRouteSimple(addr, 0, lapic, vector));
//
// Or for callers that want to handle the error inline:
//
//     auto r = pci::PciMsixRouteSimple(addr, 0, lapic, vector);
//     if (!r) goto legacy_intx;
//     pci::MsixRoute route = r.take();
//
// `MsixRoute` carries the mapped table base + table_size so the
// caller can later mask / unmask vectors without re-walking config
// space. Error codes returned:
//   Unsupported      — function doesn't expose MSI-X
//   InvalidArgument  — entry_index >= table_size
//   IoError          — table BAR is I/O-space (shouldn't happen)
//   OutOfMemory      — MapMmio couldn't claim a spot in the arena
// -----------------------------------------------------------------

struct MsixRoute
{
    volatile void* table_base; // mapped MMIO; valid for the kernel's lifetime
    u64 table_phys;            // physical base of the mapped region
    u16 table_size;            // entry count
    u16 entry_index;           // entry the helper programmed
    MsixInfo info;             // capability snapshot
};

::duetos::core::Result<MsixRoute> PciMsixRouteSimple(DeviceAddress addr, u16 entry_index, u8 lapic_id, u8 vector);

/// One-shot MSI-X setup for a single-vector device. Allocates an
/// IRQ vector from the kernel pool (`IrqAllocVector`), installs
/// `handler` on it, calls `PciMsixRouteSimple` to program the
/// device's MSI-X entry `entry_index` routed to the BSP's LAPIC.
/// Returns the allocated vector on success so the caller can enable
/// device-specific interrupt-generation bits (USBCMD.IE, NVMe CQ
/// IEN, etc.) that live OUTSIDE the PCI capability. The mapped
/// table base is written into `*out_route` if non-null.
///
/// Failure modes: device lacks MSI-X capability → `Unsupported`;
/// BAR missing / I/O → `IoError`; vector pool exhausted →
/// `OutOfMemory`; table map failed → `OutOfMemory`.
::duetos::core::Result<u8> PciMsixBindSimple(DeviceAddress addr, u16 entry_index, ::duetos::arch::IrqHandler handler,
                                             MsixRoute* out_route);

// -----------------------------------------------------------------
// Class-code string for diagnostic logs. Returns a stable pointer to
// a short label ("mass storage", "network", "display", "bridge", ...)
// or "unknown" for codes we haven't named yet.
// -----------------------------------------------------------------
const char* PciClassName(u8 class_code);

// More specific name for the (class, subclass, prog_if) triple. For
// the common cases this names the actual controller flavour — e.g.
// `0x01/0x06/0x01` -> "SATA AHCI", `0x0C/0x03/0x30` -> "USB xHCI",
// `0x01/0x08/0x02` -> "NVMe". Returns "" for triples we haven't
// catalogued yet, so callers can `if (*detail) { print " - ", detail }`
// without polluting the log when there's nothing useful to say.
const char* PciSubclassDetail(u8 class_code, u8 subclass, u8 prog_if);

} // namespace duetos::drivers::pci
