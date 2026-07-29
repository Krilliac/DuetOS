#pragma once

#include "util/types.h"

/*
 * DuetOS — hardware telemetry query surface.
 *
 * ONE place a UI (Task Manager's Performance view, `sysinfo`, a future
 * telemetry sink) asks "what is this machine and what is it doing".
 * Every function here is a READ over counters and inventories that
 * other subsystems already own — this file adds no counters of its
 * own, it aggregates:
 *
 *   CPU       sched per-CPU tick counters (kernel/cpu/percpu.h),
 *             cpu::Topology, arch::CpuInfo, arch::CpuFreqRead
 *   Memory    mm::TotalFrames / FreeFramesCount, mm::KernelHeapStatsRead,
 *             arch::SmbiosGet (per-DIMM Type 17)
 *   Network   drivers::net::Nic* registry + net::InterfaceCountersRead
 *   Graphics  drivers::video::RenderStatsRead,
 *             subsystems::graphics::GraphicsStatsRead
 *
 * HONESTY CONTRACT — the whole point of this header.
 *
 * Every struct below can represent "I do not know", and the callers
 * MUST render that state rather than substituting a zero. A Task
 * Manager that shows "0%" for a quantity it cannot measure is lying,
 * and the lie is indistinguishable from a real idle reading. So:
 *
 *   - `*_valid` / `*_present` flags gate every field that can be
 *     unavailable. False means "no data", NOT "zero".
 *   - Absent hardware is absent, not idle. A machine with no Wi-Fi
 *     adapter reports zero wireless interfaces; it never reports a
 *     wireless interface sitting at 0 bytes.
 *   - There is deliberately NO gpu_busy_pct field. See
 *     TelemetryGraphics below.
 *
 * Context: kernel. All sampling is lock-free counter reads, safe from
 * task context. Not intended for IRQ context (the SMBIOS and NIC walks
 * are O(slots)).
 */

namespace duetos::diag
{

// ---------------------------------------------------------------------
// CPU
// ---------------------------------------------------------------------

// Ceiling on per-core rows. arch::SmpCpuIdLimit() is the live bound;
// this caps the array so the snapshot stays a plain value type.
inline constexpr u32 kTelemetryMaxCpus = 64;

/// Lifetime tick counters for one logical CPU, plus its topology.
struct TelemetryCpuCore
{
    u32 cpu_id;
    bool online;      // AP finished bring-up and services a runqueue
    u64 total_ticks;  // every timer tick that fired on this CPU
    u64 idle_ticks;   // the subset spent in this CPU's idle task
    u16 core_group;   // dense physical-core index; SMT siblings share it
    bool smt_primary; // first logical CPU of its physical core
    u8 core_class;    // cpu::kCoreClass{Unknown,Perf,Eff} (hybrid parts)
};

/// A point-in-time CPU snapshot: identity, topology, and lifetime
/// counters. Percentages are NOT here on purpose — see
/// TelemetryCpuWindow.
struct TelemetryCpuInfo
{
    // --- identity (from CPUID) ---
    char vendor[13]; // "GenuineIntel" / "AuthenticAMD"
    char brand[49];  // marketing brand string
    u32 family;
    u32 model;
    u32 stepping;
    bool identity_valid;

    // --- topology ---
    u32 logical_cpus;   // logical CPUs the kernel has brought up
    u32 physical_cores; // distinct core_group values among them
    u32 online_cpus;
    u32 core_count; // rows populated in `cores`

    // --- frequency ---
    // From arch::CpuFreqRead, which PROBES each frequency MSR through
    // the fault-recoverable read rather than predicting availability
    // from the vendor string. `freq_valid` means "at least one figure
    // came back"; the two per-field flags say which. A platform that
    // exposes neither reports every flag false, which is the honest
    // answer and is a different fact from 0 MHz.
    u32 current_mhz;
    bool current_mhz_valid;
    u32 base_mhz;
    bool base_mhz_valid;
    bool freq_valid;

    TelemetryCpuCore cores[kTelemetryMaxCpus];
};

/// Sample CPU identity, topology and lifetime tick counters.
TelemetryCpuInfo TelemetryCpuSample();

/// Caller-owned rolling window for CPU utilisation.
///
/// Utilisation is only meaningful over an interval, so the caller keeps
/// the previous snapshot and asks for the delta since ITS last call.
/// Making the window caller-owned rather than a module global is
/// deliberate: two consumers polling at different cadences (a 1 Hz
/// Task Manager graph and an on-demand shell command) would otherwise
/// consume each other's deltas and both would read wrong.
///
/// Zero-initialise before first use; the first TelemetryCpuUsageSample
/// call against a fresh window returns `valid == false`, because a
/// single reading of a monotonic counter carries no rate information.
struct TelemetryCpuWindow
{
    u64 prev_total[kTelemetryMaxCpus];
    u64 prev_idle[kTelemetryMaxCpus];
    bool seeded;
};

/// Per-core and aggregate utilisation over the window.
struct TelemetryCpuUsage
{
    bool valid; // false on the first sample against a fresh window
    u32 core_count;

    /// Busy percent per logical CPU, indexed by cpu_id.
    u8 core_busy_pct[kTelemetryMaxCpus];
    /// False when that CPU logged no ticks in the window (offline, or
    /// sampled twice within one tick). Render as "no data", not 0%.
    bool core_valid[kTelemetryMaxCpus];

    /// Aggregate across all CPUs that reported ticks.
    ///
    /// DERIVED from the same per-core deltas as `core_busy_pct` — the
    /// sum of busy deltas over the sum of total deltas — so the summary
    /// figure and the per-core breakdown agree by construction. There
    /// is no second global counter maintained alongside this one.
    u8 aggregate_busy_pct;
};

/// Advance `window` and return utilisation since its previous state.
TelemetryCpuUsage TelemetryCpuUsageSample(TelemetryCpuWindow& window);

// ---------------------------------------------------------------------
// Memory
// ---------------------------------------------------------------------

/// Physical RAM, kernel heap, and per-DIMM inventory.
struct TelemetryMemory
{
    // --- physical frames (always available) ---
    u64 total_bytes;
    u64 used_bytes;
    u64 free_bytes;
    u8 used_pct;

    // --- kernel heap ---
    u64 heap_pool_bytes;
    u64 heap_used_bytes;
    u64 heap_free_bytes;
    u8 heap_used_pct;

    // --- per-module (SMBIOS Type 17) ---
    /// False when the firmware published no SMBIOS at all. A UI must
    /// render "unavailable" — NOT "0 modules", which would wrongly
    /// claim the machine has no RAM sticks.
    bool modules_available;
    /// Records in arch::SmbiosGet().memory_devices. Zero with
    /// `modules_available == true` means SMBIOS existed but carried no
    /// Type 17 records — a different fact from "unavailable".
    u32 module_count;
    /// Sum of populated modules' capacities, per firmware. May exceed
    /// `total_bytes`, which counts only what the frame allocator owns
    /// (firmware reservations, MMIO holes and the kernel image are not
    /// in the allocator's pool).
    u64 modules_installed_bytes;
};

TelemetryMemory TelemetryMemorySample();

// ---------------------------------------------------------------------
// Network
// ---------------------------------------------------------------------

inline constexpr u32 kTelemetryMaxNics = 8;

enum class TelemetryNicKind : u8
{
    Unknown = 0,
    Ethernet = 1,
    Wireless = 2,
};

/// One bound network adapter.
struct TelemetryNic
{
    TelemetryNicKind kind;
    u16 vendor_id;
    u16 device_id;
    const char* vendor_name; // never null; "?" when unrecognised
    const char* family_name; // driver's chip-family tag; never null
    u8 mac[6];
    bool mac_valid;
    bool link_up;
    bool driver_online; // a chip-specific driver bound to it

    /// True when this adapter is wired to a stack interface index, so
    /// the counters below are meaningful. False means the NIC was
    /// enumerated on the bus but carries no IP stack binding — its
    /// counters are absent, not zero.
    bool stack_bound;
    u32 iface_index;
    u64 rx_packets;
    u64 rx_bytes;
    u64 tx_packets;
    u64 tx_bytes;
};

/// Network adapter inventory.
///
/// `count == 0` means NO adapter is present. That is a different fact
/// from an adapter present with zero traffic (`count == 1` with
/// `stack_bound && rx_bytes == 0`), and conflating the two is exactly
/// what makes a UI look broken. Under QEMU with no NIC model attached
/// the honest answer is zero adapters; the UI should say "no adapter",
/// not draw an idle graph.
struct TelemetryNet
{
    u32 count;
    TelemetryNic nics[kTelemetryMaxNics];
};

TelemetryNet TelemetryNetSample();

// ---------------------------------------------------------------------
// Graphics
// ---------------------------------------------------------------------

/// Graphics ACTIVITY — deliberately not "GPU utilisation".
///
/// There is no engine-busy percentage in this struct because DuetOS
/// cannot currently measure one:
///   - Intel  : no RC6-residency or RING_TIMESTAMP read exists.
///   - AMD    : mmGRBM_STATUS (GUI_ACTIVE, bit 31) IS read, but only
///              once during probe. A single boot-time sample of a
///              level-triggered bit is not a duty cycle; turning it
///              into one needs a periodic sampler that does not exist
///              yet.
///   - NVIDIA : identity register only.
///   - Virtual adapters (bochs_vbe, virtio-gpu) have no engine at all,
///              so the correct answer there is "not applicable" and
///              never a number.
///
/// What IS real is the work the software stack demonstrably did: frames
/// composed and presented by the compositor, and operations recorded /
/// replayed by the Vulkan ICD. Those are named for what they measure.
/// A UI may graph them as "graphics activity"; it must not label them
/// GPU load.
struct TelemetryGraphics
{
    // --- compositor (drivers::video::RenderStatsRead) ---
    u64 frames_composed;
    u64 frames_presented;
    u64 presents_coalesced;
    u64 dirty_pixels_total;

    // --- Vulkan ICD (subsystems::graphics::GraphicsStatsRead) ---
    u32 vk_queue_submits;
    u32 vk_commands_recorded;
    u32 vk_commands_replayed;
    u32 vk_swapchain_presents;

    /// Number of GPU adapters the kernel enumerated.
    u32 adapter_count;
    /// True when at least one adapter reports live MMIO. Even then
    /// there is no busy percentage — see the note above.
    bool any_adapter_mmio_live;
};

TelemetryGraphics TelemetryGraphicsSample();

// ---------------------------------------------------------------------
// Firmware / board identity
// ---------------------------------------------------------------------

/// Motherboard + firmware identity, from SMBIOS Types 0/1/2/3.
/// `available == false` when no SMBIOS entry point was found; every
/// string is then empty and a UI must render "unavailable".
struct TelemetryBoard
{
    bool available;
    const char* bios_vendor;
    const char* bios_version;
    const char* system_manufacturer;
    const char* system_product;
    const char* baseboard_manufacturer;
    const char* baseboard_product;
    const char* baseboard_version;
    const char* chassis_name;
    bool laptop_chassis;
};

TelemetryBoard TelemetryBoardSample();

/// Boot self-test: exercises every sampler once and checks the
/// invariants that hold on any machine (idle <= total per CPU,
/// free + used == total, aggregate derived from per-core, absent-vs-idle
/// flags coherent). Emits one PASS/FAIL line.
void TelemetrySelfTest();

/// True once TelemetrySelfTest has run and passed.
bool TelemetrySelfTestPassed();

} // namespace duetos::diag
