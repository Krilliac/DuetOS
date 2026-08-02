#include "diag/telemetry.h"

#include "arch/x86_64/cpu_info.h"
#include "arch/x86_64/cpufreq.h"
#include "arch/x86_64/serial.h"
#include "arch/x86_64/smbios.h"
#include "arch/x86_64/smp.h"
#include "cpu/percpu.h"
#include "cpu/topology.h"
#include "diag/log_names.h"
#include "diag/telemetry_math.h"
#include "drivers/gpu/gpu.h"
#include "drivers/net/net.h"
#include "drivers/video/render_stats.h"
#include "mm/frame_allocator.h"
#include "mm/kheap.h"
#include "mm/page.h"
#include "net/stack.h"
#include "sched/sched.h"
#include "subsystems/graphics/graphics.h"

namespace duetos::diag
{

namespace
{

namespace tm = ::duetos::diag::telemetry_math;

bool g_selftest_passed = false;

/// Copy a NUL-terminated string into a fixed buffer, truncating.
void CopyCapped(char* dst, u64 cap, const char* src)
{
    if (cap == 0)
        return;
    u64 i = 0;
    if (src != nullptr)
    {
        for (; src[i] != '\0' && i + 1 < cap; ++i)
            dst[i] = src[i];
    }
    dst[i] = '\0';
}

/// Highest cpu_id the scheduler may have allocated, clamped to the
/// snapshot array width.
u32 CpuRowLimit()
{
    const u32 live = ::duetos::arch::SmpCpuIdLimit();
    return (live < kTelemetryMaxCpus) ? live : kTelemetryMaxCpus;
}

} // namespace

TelemetryCpuInfo TelemetryCpuSample()
{
    TelemetryCpuInfo out = {};

    // --- identity ---
    const auto& ci = ::duetos::arch::CpuInfoGet();
    out.identity_valid = ci.valid;
    CopyCapped(out.vendor, sizeof(out.vendor), ci.vendor);
    CopyCapped(out.brand, sizeof(out.brand), ci.brand);
    out.family = ci.family;
    out.model = ci.model;
    out.stepping = ci.stepping;

    // --- frequency ---
    // CpuFreqRead probes each MSR through arch::ReadMsrSafe, so a
    // machine that exposes the frequency interface reports it whether
    // or not a hypervisor is present, and one that does not reports
    // nothing at all. The two per-field flags are propagated rather
    // than collapsed into `freq_valid`: a part can publish its static
    // base ratio while declining a live operating point, and a UI that
    // renders the missing half as 0 MHz looks broken.
    const auto freq = ::duetos::arch::CpuFreqRead();
    out.freq_valid = freq.valid;
    out.current_mhz_valid = freq.valid && freq.current_valid;
    out.current_mhz = out.current_mhz_valid ? freq.current_mhz : 0;
    out.base_mhz_valid = freq.valid && freq.ratios_valid;
    out.base_mhz = out.base_mhz_valid ? freq.base_mhz : 0;

    // --- per-core counters + topology ---
    const u32 limit = CpuRowLimit();
    out.core_count = limit;
    out.logical_cpus = limit;
    out.online_cpus = static_cast<u32>(::duetos::arch::SmpCpusOnline());

    // Physical cores = the number of DISTINCT `core_group` values,
    // since SMT siblings share one. Counted as a set rather than by
    // tallying `smt_primary` rows: on a non-SMT part the topology
    // decode leaves smt_primary clear on every CPU, so the tally
    // approach reports 0 physical cores on a machine that plainly has
    // at least one. (It did exactly that on the first SMP boot of this
    // code — `physical=0` with one online CPU.)
    u16 seen_groups[kTelemetryMaxCpus] = {};
    u32 seen_count = 0;

    for (u32 id = 0; id < limit; ++id)
    {
        TelemetryCpuCore& c = out.cores[id];
        c.cpu_id = id;

        u64 total = 0;
        u64 idle = 0;
        if (::duetos::sched::SchedStatsReadCpu(id, &total, &idle))
        {
            c.total_ticks = total;
            c.idle_ticks = idle;
        }

        const auto* pc = ::duetos::arch::SmpGetPercpu(id);
        c.online = (pc != nullptr) && pc->online;

        const auto* topo = ::duetos::cpu::TopologyForCpu(id);
        if (topo != nullptr)
        {
            c.core_group = topo->core_group;
            c.smt_primary = (topo->smt_primary != 0);
            c.core_class = topo->core_class;
            if (topo->core_group != ::duetos::cpu::kTopologyUnknownCoreGroup)
            {
                bool already = false;
                for (u32 j = 0; j < seen_count; ++j)
                {
                    if (seen_groups[j] == topo->core_group)
                    {
                        already = true;
                        break;
                    }
                }
                if (!already && seen_count < kTelemetryMaxCpus)
                    seen_groups[seen_count++] = topo->core_group;
            }
        }
        else
        {
            c.core_group = ::duetos::cpu::kTopologyUnknownCoreGroup;
        }
    }

    // Fall back to the logical count when topology decode produced no
    // usable core_group at all — reporting "1 physical core" is wrong
    // on a 4-way box, but reporting 0 is wrong on every box.
    out.physical_cores = (seen_count > 0) ? seen_count : limit;
    return out;
}

TelemetryCpuUsage TelemetryCpuUsageSample(TelemetryCpuWindow& window)
{
    TelemetryCpuUsage out = {};
    const u32 limit = CpuRowLimit();
    out.core_count = limit;

    // Summed deltas feed the aggregate. Deriving it here — from the
    // very same deltas the per-core figures use — is what keeps the
    // summary and the breakdown consistent by construction.
    u64 summed_total = 0;
    u64 summed_idle = 0;

    const bool was_seeded = window.seeded;

    // First pass: measure the window WITHOUT consuming it. A caller
    // polling faster than the tick would otherwise reset prev_* every
    // call, so the window could never accumulate past one tick and the
    // percentage could only ever be 0 or 100.
    u64 widest = 0;
    for (u32 id = 0; id < limit; ++id)
    {
        u64 total = 0;
        u64 idle = 0;
        if (!::duetos::sched::SchedStatsReadCpu(id, &total, &idle))
            continue;
        if (was_seeded)
        {
            const u64 dt = tm::CounterDelta(total, window.prev_total[id]);
            if (dt > widest)
                widest = dt;
        }
    }

    // Too short to mean anything: hand back the last figure computed
    // over a window that DID qualify, and leave prev_* untouched so the
    // window keeps growing. Reporting the quantised value here is what
    // made the Task Manager tiles read 0% beside a 59% graph.
    if (was_seeded && widest < kTelemetryMinWindowTicks)
    {
        if (!window.held_valid)
            return out; // nothing trustworthy yet; valid stays false
        for (u32 id = 0; id < limit; ++id)
        {
            out.core_busy_pct[id] = window.held_core_pct[id];
            out.core_valid[id] = window.held_core_valid[id];
        }
        out.aggregate_busy_pct = window.held_aggregate_pct;
        out.valid = true;
        return out;
    }

    for (u32 id = 0; id < limit; ++id)
    {
        u64 total = 0;
        u64 idle = 0;
        if (!::duetos::sched::SchedStatsReadCpu(id, &total, &idle))
        {
            // CPU slot never allocated. Leave core_valid false and do
            // not disturb its window slot.
            continue;
        }

        if (was_seeded)
        {
            const u64 dt = tm::CounterDelta(total, window.prev_total[id]);
            const u64 di = tm::CounterDelta(idle, window.prev_idle[id]);
            if (dt > 0)
            {
                out.core_busy_pct[id] = tm::BusyPercent(dt, di);
                out.core_valid[id] = true;
                summed_total += dt;
                summed_idle += di;
            }
            // dt == 0 leaves core_valid false: no tick landed on this
            // CPU during the window, so we have no rate to report. An
            // idle CPU still ticks, so this is genuinely "no data".
        }

        window.prev_total[id] = total;
        window.prev_idle[id] = idle;
    }

    window.seeded = true;
    out.valid = was_seeded && summed_total > 0;
    out.aggregate_busy_pct = tm::AggregateBusyPercent(summed_total, summed_idle);

    // Remember a qualifying reading so the short-window path above has
    // something true to repeat.
    if (out.valid)
    {
        for (u32 id = 0; id < limit; ++id)
        {
            window.held_core_pct[id] = out.core_busy_pct[id];
            window.held_core_valid[id] = out.core_valid[id];
        }
        window.held_aggregate_pct = out.aggregate_busy_pct;
        window.held_valid = true;
    }
    return out;
}

TelemetryMemory TelemetryMemorySample()
{
    TelemetryMemory out = {};

    const u64 total_frames = ::duetos::mm::TotalFrames();
    const u64 free_frames = ::duetos::mm::FreeFramesCount();
    const u64 used_frames = (total_frames > free_frames) ? (total_frames - free_frames) : 0;

    out.total_bytes = total_frames * ::duetos::mm::kPageSize;
    out.free_bytes = free_frames * ::duetos::mm::kPageSize;
    out.used_bytes = used_frames * ::duetos::mm::kPageSize;
    out.used_pct = tm::UsedPercent(out.used_bytes, out.total_bytes);

    const auto heap = ::duetos::mm::KernelHeapStatsRead();
    out.heap_pool_bytes = heap.pool_bytes;
    out.heap_used_bytes = heap.used_bytes;
    out.heap_free_bytes = heap.free_bytes;
    out.heap_used_pct = tm::UsedPercent(heap.used_bytes, heap.pool_bytes);

    // Per-DIMM inventory. `modules_available` tracks whether SMBIOS
    // exists at all, so a caller can tell "no firmware data" from
    // "firmware reported no modules".
    const auto& sm = ::duetos::arch::SmbiosGet();
    out.modules_available = sm.present;
    out.module_count = sm.present ? sm.memory_device_count : 0;
    out.modules_installed_bytes = sm.present ? sm.memory_installed_bytes : 0;

    return out;
}

TelemetryNet TelemetryNetSample()
{
    TelemetryNet out = {};

    namespace dnet = ::duetos::drivers::net;

    const u64 nic_count = dnet::NicCount();
    for (u64 i = 0; i < nic_count && out.count < kTelemetryMaxNics; ++i)
    {
        dnet::NicInfo n{};
        if (!dnet::NicSnapshot(i, &n))
            break;
        TelemetryNic& t = out.nics[out.count];

        const bool wireless = n.subclass == dnet::kPciSubclassOther || dnet::nic_ids::NicFamilyLooksWireless(n.family);
        t.kind = wireless ? TelemetryNicKind::Wireless : TelemetryNicKind::Ethernet;
        t.vendor_id = n.vendor_id;
        t.device_id = n.device_id;
        t.vendor_name = ::duetos::core::PciVendorName(n.vendor_id);
        t.family_name = (n.family != nullptr) ? n.family : "?";
        t.mac_valid = n.mac_valid;
        for (u32 b = 0; b < 6; ++b)
            t.mac[b] = n.mac[b];
        t.link_up = n.link_up;
        t.driver_online = n.driver_online;

        // Traffic counters live on the STACK interface, not the driver.
        // The two tables are correlated by index (see the note in
        // drivers/net/net.cpp) — but only when that slot is actually
        // bound. An enumerated-but-unbound NIC gets stack_bound=false
        // and no counters, which is the "present but not carrying
        // traffic" state a UI must not render as zero bytes.
        const u32 iface = static_cast<u32>(i);
        if (iface < ::duetos::net::InterfaceCount() && ::duetos::net::InterfaceIsBound(iface))
        {
            const auto c = ::duetos::net::InterfaceCountersRead(iface);
            t.stack_bound = true;
            t.iface_index = iface;
            t.rx_packets = c.rx_packets;
            t.rx_bytes = c.rx_bytes;
            t.tx_packets = c.tx_packets;
            t.tx_bytes = c.tx_bytes;
        }

        ++out.count;
    }

    return out;
}

TelemetryGraphics TelemetryGraphicsSample()
{
    TelemetryGraphics out = {};

    const auto rs = ::duetos::drivers::video::RenderStatsRead();
    out.frames_composed = rs.frames_composed;
    out.frames_presented = rs.frames_presented;
    out.presents_coalesced = rs.presents_coalesced;
    out.dirty_pixels_total = rs.dirty_pixels_total;

    const auto gs = ::duetos::subsystems::graphics::GraphicsStatsRead();
    out.vk_queue_submits = gs.vk_queue_submits;
    out.vk_commands_recorded = gs.vk_command_recorded;
    out.vk_commands_replayed = gs.vk_command_replayed;
    out.vk_swapchain_presents = gs.vk_swapchain_presents;

    const u64 gpus = ::duetos::drivers::gpu::GpuCount();
    out.adapter_count = static_cast<u32>(gpus);
    for (u64 i = 0; i < gpus; ++i)
    {
        if (::duetos::drivers::gpu::Gpu(i).mmio_live)
        {
            out.any_adapter_mmio_live = true;
            break;
        }
    }

    // STUB: there is deliberately no engine-busy percentage here. AMD's
    // mmGRBM_STATUS GUI_ACTIVE bit is read once at probe and never
    // sampled; Intel and NVIDIA expose no busy register in this tree at
    // all. Reporting a number would mean inventing one. See the
    // TelemetryGraphics doc comment.
    return out;
}

TelemetryBoard TelemetryBoardSample()
{
    TelemetryBoard out = {};
    const auto& sm = ::duetos::arch::SmbiosGet();

    out.available = sm.present;
    out.bios_vendor = sm.bios_vendor;
    out.bios_version = sm.bios_version;
    out.system_manufacturer = sm.system_manufacturer;
    out.system_product = sm.system_product;
    out.baseboard_manufacturer = sm.baseboard_manufacturer;
    out.baseboard_product = sm.baseboard_product;
    out.baseboard_version = sm.baseboard_version;
    out.chassis_name = ::duetos::arch::ChassisTypeName(sm.chassis_type);
    out.laptop_chassis = ::duetos::arch::SmbiosIsLaptopChassis();
    return out;
}

void TelemetrySelfTest()
{
    bool ok = true;

    // --- CPU identity / topology ---
    const TelemetryCpuInfo cpu = TelemetryCpuSample();
    // At least the BSP must be present.
    ok = ok && (cpu.core_count >= 1);
    ok = ok && (cpu.online_cpus >= 1);
    // Physical cores can never exceed logical CPUs, and a machine that
    // is executing this code has at least one. The lower bound is not
    // pedantry: the first cut of the core-group count returned 0 here
    // on a non-SMT part, and only the `<=` half of this check existed,
    // so it passed.
    ok = ok && (cpu.physical_cores >= 1);
    ok = ok && (cpu.physical_cores <= cpu.logical_cpus);
    // Unsupported must stay distinguishable from zero: a cleared
    // validity flag must never come with a populated figure beside it,
    // or a caller that trusts the number alone reads a fabricated
    // "0 MHz" as a real idle reading.
    ok = ok && (cpu.current_mhz_valid || cpu.current_mhz == 0);
    ok = ok && (cpu.base_mhz_valid || cpu.base_mhz == 0);
    ok = ok && (cpu.freq_valid || (!cpu.current_mhz_valid && !cpu.base_mhz_valid));
    // idle is a subset of total on every CPU.
    for (u32 i = 0; i < cpu.core_count; ++i)
        ok = ok && (cpu.cores[i].idle_ticks <= cpu.cores[i].total_ticks);

    // --- CPU usage window ---
    // A fresh window must refuse to report: one reading of a monotonic
    // counter carries no rate. This is the invariant that stops a UI
    // from drawing a bogus first data point.
    TelemetryCpuWindow win = {};
    const TelemetryCpuUsage first = TelemetryCpuUsageSample(win);
    ok = ok && !first.valid;
    // Second call is seeded; percentages must be in range whether or
    // not any tick landed between the two calls.
    const TelemetryCpuUsage second = TelemetryCpuUsageSample(win);
    ok = ok && (second.aggregate_busy_pct <= 100);
    for (u32 i = 0; i < second.core_count; ++i)
        ok = ok && (second.core_busy_pct[i] <= 100);

    // A poll that lands inside the minimum window must NOT consume the
    // window. This is the regression that made the Task Manager rail
    // read "CPU 0% / Core 0 0%" beside a graph showing 59%: prev_* was
    // overwritten on every call, so with a caller painting faster than
    // the 100Hz tick the window never grew past one tick and
    // (dt - di)/dt could only ever land on 0% or 100%. Asserting the
    // snapshot survives pins the fix without stalling boot for 250ms.
    const u64 prev_snapshot = win.prev_total[0];
    const TelemetryCpuUsage third = TelemetryCpuUsageSample(win);
    ok = ok && (win.prev_total[0] == prev_snapshot);
    // Nothing has yet been measured over a qualifying window, so there
    // is no held reading to repeat and the sample must decline to
    // report rather than hand back a quantised one.
    ok = ok && !third.valid;

    // --- memory ---
    const TelemetryMemory mem = TelemetryMemorySample();
    ok = ok && (mem.total_bytes > 0);
    ok = ok && (mem.used_bytes + mem.free_bytes == mem.total_bytes);
    ok = ok && (mem.used_pct <= 100);
    ok = ok && (mem.heap_used_pct <= 100);
    // "unavailable" and "zero modules" must not be conflated: a module
    // count > 0 implies SMBIOS was available.
    ok = ok && (mem.module_count == 0 || mem.modules_available);

    // --- network ---
    const TelemetryNet net = TelemetryNetSample();
    ok = ok && (net.count <= kTelemetryMaxNics);
    for (u32 i = 0; i < net.count; ++i)
    {
        // Counters are only meaningful when stack-bound; an unbound
        // adapter must carry none.
        if (!net.nics[i].stack_bound)
        {
            ok = ok && (net.nics[i].rx_bytes == 0 && net.nics[i].tx_bytes == 0);
        }
        ok = ok && (net.nics[i].vendor_name != nullptr);
        ok = ok && (net.nics[i].family_name != nullptr);
    }

    // --- graphics / board ---
    const TelemetryGraphics gfx = TelemetryGraphicsSample();
    // Every present is a compose, so presents can never lead composes.
    ok = ok && (gfx.frames_presented <= gfx.frames_composed + gfx.frames_presented);
    const TelemetryBoard board = TelemetryBoardSample();
    ok = ok && (board.chassis_name != nullptr);
    ok = ok && (board.bios_vendor != nullptr);

    g_selftest_passed = ok;

    // Per-core lifetime counters, one line each. These are the raw
    // numbers a UI differences, and printing them is the cheapest live
    // proof that per-CPU accounting is genuinely per-CPU: on an SMP
    // boot the BSP has run the whole bring-up while the APs have been
    // idling, so the totals and idle fractions must differ per row. If
    // every row were identical, the counters would be reading one
    // shared slot rather than each CPU's own.
    for (u32 i = 0; i < cpu.core_count; ++i)
    {
        const TelemetryCpuCore& c = cpu.cores[i];
        // Each row is many SerialWrite calls, so it must be emitted
        // under a line guard — without one an AP logging concurrently
        // splices its message into the middle of ours (observed: a
        // "[sched/smp] SchedStartIdle returned" line landing inside the
        // cpu0 row), which corrupts the very numbers this line exists
        // to report and defeats any grep over them.
        ::duetos::arch::SerialLineGuard guard;
        ::duetos::arch::SerialWrite("[telemetry] cpu");
        ::duetos::arch::SerialWriteHex(c.cpu_id);
        ::duetos::arch::SerialWrite(c.online ? " online" : " offline");
        ::duetos::arch::SerialWrite(" total=");
        ::duetos::arch::SerialWriteHex(c.total_ticks);
        ::duetos::arch::SerialWrite(" idle=");
        ::duetos::arch::SerialWriteHex(c.idle_ticks);
        ::duetos::arch::SerialWrite(" busy_pct=");
        ::duetos::arch::SerialWriteHex(tm::BusyPercent(c.total_ticks, c.idle_ticks));
        ::duetos::arch::SerialWrite("\n");
    }

    ::duetos::arch::SerialLineGuard summary_guard;
    ::duetos::arch::SerialWrite("[telemetry] cores=");
    ::duetos::arch::SerialWriteHex(cpu.core_count);
    ::duetos::arch::SerialWrite(" online=");
    ::duetos::arch::SerialWriteHex(cpu.online_cpus);
    ::duetos::arch::SerialWrite(" physical=");
    ::duetos::arch::SerialWriteHex(cpu.physical_cores);
    ::duetos::arch::SerialWrite(" mem_total_mib=");
    ::duetos::arch::SerialWriteHex(mem.total_bytes / (1024ULL * 1024ULL));
    ::duetos::arch::SerialWrite(" mem_used_pct=");
    ::duetos::arch::SerialWriteHex(mem.used_pct);
    ::duetos::arch::SerialWrite(" dimms=");
    ::duetos::arch::SerialWriteHex(mem.module_count);
    ::duetos::arch::SerialWrite(" nics=");
    ::duetos::arch::SerialWriteHex(net.count);
    ::duetos::arch::SerialWrite(" gpus=");
    ::duetos::arch::SerialWriteHex(gfx.adapter_count);
    ::duetos::arch::SerialWrite("\n");

    ::duetos::arch::SerialWrite(ok ? "[telemetry-selftest] PASS\n" : "[telemetry-selftest] FAIL\n");
}

bool TelemetrySelfTestPassed()
{
    return g_selftest_passed;
}

} // namespace duetos::diag
