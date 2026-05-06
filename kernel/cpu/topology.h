#pragma once

#include "acpi/acpi.h"
#include "util/types.h"

/*
 * DuetOS — CPU topology + scheduler clustering, v0.
 *
 * Each CPU's package / core / SMT identity is decoded from CPUID
 * leaf 0x1F (preferred) / 0x0B / legacy leaf 4 + leaf 1, paired
 * with its SRAT-reported NUMA node. The two together collapse to
 * a single `cluster_id` per CPU that the scheduler's work-stealing
 * path uses to bias steals toward locality:
 *
 *   - >1 NUMA node -> cluster = NUMA node
 *   - else >1 package -> cluster = package
 *   - else single cluster (every CPU gets cluster_id = 0)
 *
 * This means a UMA single-package desktop sees zero behavioural
 * change vs. the pre-clustering scheduler — the steal path's
 * two-pass scan finds every peer in pass 0 just as before.
 *
 * Init flow:
 *   1. AcpiInit -> SratInit (acpi/srat.cpp): builds APIC -> node table.
 *   2. PerCpuInitBsp -> TopologyInitBsp: BSP decodes its own row.
 *   3. Each AP, in ApEntryFromTrampoline before signaling online_flag,
 *      calls TopologyInitAp(cpu_id) so the BSP's WaitForApOnline
 *      poll doubles as the rendezvous on AP topology decode.
 *   4. After SmpStartAps returns, BSP calls TopologyAssignClusters
 *      to pick the collapse rule and write each CPU's cluster_id.
 *   5. TopologyDump emits the per-CPU detail at debug log level.
 *
 * Failure handling: every step is non-fatal. Decode failures fire
 * `debug::ProbeId::kTopologyParseFailed` and leave the affected
 * CPU at cluster_id = 0; locality stealing degrades to round-robin
 * for that CPU but the system keeps running.
 *
 * Context: kernel. Decode runs once per CPU on its own stack;
 * read-only afterwards from any context.
 */

namespace duetos::cpu
{

inline constexpr u16 kTopologyUnknownPackage = 0xFFFF;
inline constexpr u16 kTopologyUnknownCore = 0xFFFF;
inline constexpr u8 kTopologyUnknownSmt = 0xFF;
inline constexpr u8 kTopologyUnknownNode = 0xFF;
inline constexpr u16 kTopologyUnknownCluster = 0xFFFF;

struct alignas(64) Topology
{
    u32 cpu_id;
    u32 apic_id;    // 32-bit value when CPUID 0x0B/0x1F is available
    u16 package_id; // kTopologyUnknownPackage on decode failure
    u16 core_id;    // index within package
    u8 smt_id;      // index within core
    u8 numa_node;   // dense node index, kTopologyUnknownNode if no SRAT entry
    u16 cluster_id; // mirrors PerCpu.cluster_id once AssignClusters runs
    u8 _pad[2];     // explicit pad to keep cache-line discipline
};

/// Decode the BSP's own topology and populate slot 0 of the
/// per-CPU topology table. Must run after `PerCpuInitBsp` (so
/// `cpu::CurrentCpu()->lapic_id` is valid) and after `AcpiInit`
/// (so the SRAT parser is ready). Idempotent.
void TopologyInitBsp();

/// Decode the AP's own topology and populate slot `cpu_id` of
/// the per-CPU topology table. Must run on the AP itself, after
/// its GS-base has been programmed and before signaling
/// `online_flag` to the BSP — the trampoline's online handshake
/// doubles as the rendezvous point so `TopologyAssignClusters`
/// is safe to run on the BSP after `SmpStartAps` returns.
void TopologyInitAp(u32 cpu_id);

/// Walk the per-CPU topology table and pick a cluster-id rule.
/// Writes each `PerCpu(cpu_id)->cluster_id`. Runs once on the
/// BSP after every AP has finished bring-up.
void TopologyAssignClusters();

/// Dump the per-CPU topology to the debug log. Gated by the
/// kernel's klog level; clean release boots stay silent.
void TopologyDump();

/// Read the topology row for a given CPU id. Returns nullptr
/// when `cpu_id >= acpi::kMaxCpus` or that slot was never
/// populated. Plain memory read after `TopologyInitBsp`/Ap
/// returned, safe from any context.
const Topology* TopologyForCpu(u32 cpu_id);

/// Number of distinct cluster IDs after `TopologyAssignClusters`
/// has run. Returns 1 before that (single-cluster default) or
/// when the system collapses to single-cluster.
u8 TopologyClusterCount();

} // namespace duetos::cpu
