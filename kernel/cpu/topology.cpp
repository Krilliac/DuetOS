#include "cpu/topology.h"

#include "acpi/srat.h"
#include "arch/x86_64/smp.h"
#include "cpu/percpu.h"
#include "debug/probes.h"
#include "log/klog.h"

namespace duetos::cpu
{

namespace
{

struct Cpuid
{
    u32 eax;
    u32 ebx;
    u32 ecx;
    u32 edx;
};

Cpuid DoCpuid(u32 leaf, u32 subleaf = 0)
{
    Cpuid r{};
    asm volatile("cpuid" : "=a"(r.eax), "=b"(r.ebx), "=c"(r.ecx), "=d"(r.edx) : "a"(leaf), "c"(subleaf));
    return r;
}

// CPUID extended-topology level types (leaves 0x0B / 0x1F).
constexpr u8 kLevelTypeSmt = 1;
constexpr u8 kLevelTypeCore = 2;

constinit Topology k_topo[acpi::kMaxCpus] = {};
constinit u8 g_cluster_count = 1;
constinit bool g_assigned = false;

// Smallest power-of-two-shift that covers `n` distinct values.
// e.g. n=1 -> 0, n=2 -> 1, n=4 -> 2, n=5 -> 3.
u32 CeilLog2(u32 n)
{
    if (n <= 1)
    {
        return 0;
    }
    u32 shift = 0;
    u32 v = n - 1;
    while (v != 0)
    {
        v >>= 1;
        ++shift;
    }
    return shift;
}

// Decode using CPUID leaf 0x0B / 0x1F (extended topology). Returns
// true on success. On a successful leaf-0x1F walk we also overwrite
// `apic_id` with the 32-bit x2APIC value from the last sub-leaf's
// EDX, since x2APIC IDs are wider than the 8-bit LAPIC field.
bool DecodeExtTopology(u32 max_basic_leaf, u32* apic_id, u16* package_id, u16* core_id, u8* smt_id)
{
    const u32 leaf = (max_basic_leaf >= 0x1F) ? 0x1F : ((max_basic_leaf >= 0x0B) ? 0x0B : 0);
    if (leaf == 0)
    {
        return false;
    }
    u32 smt_shift = 0;
    u32 core_shift = 0;
    u32 last_edx = *apic_id;
    bool any_level = false;
    for (u32 level = 0; level < 8; ++level)
    {
        const Cpuid r = DoCpuid(leaf, level);
        // Per spec, an EAX==0 && EBX==0 sub-leaf marks end of the
        // topology enumeration.
        if (r.eax == 0 && r.ebx == 0)
        {
            break;
        }
        const u8 level_type = static_cast<u8>((r.ecx >> 8) & 0xFFu);
        const u32 shift = r.eax & 0x1Fu;
        if (level_type == kLevelTypeSmt)
        {
            smt_shift = shift;
        }
        else if (level_type == kLevelTypeCore)
        {
            core_shift = shift;
        }
        last_edx = r.edx;
        any_level = true;
    }
    if (!any_level)
    {
        return false;
    }
    // Sanity: core_shift must be >= smt_shift, else the package mask
    // would underflow. Bogus hardware (or a quirky VM) trips this.
    if (core_shift < smt_shift)
    {
        return false;
    }
    const u32 smt_mask = (smt_shift == 0) ? 0u : ((1u << smt_shift) - 1u);
    const u32 core_bits = core_shift - smt_shift;
    const u32 core_mask = (core_bits == 0) ? 0u : ((1u << core_bits) - 1u);

    *apic_id = last_edx; // x2APIC-correct identifier
    *smt_id = static_cast<u8>(last_edx & smt_mask);
    *core_id = static_cast<u16>((last_edx >> smt_shift) & core_mask);
    *package_id = static_cast<u16>(last_edx >> core_shift);
    return true;
}

// Fall-back decode using leaf 0x01 (logical processors per package)
// + leaf 0x04 sub-leaf 0 (cores per package on Intel). Used when
// the extended-topology leaves aren't present (very old CPUs,
// some legacy VM configurations).
bool DecodeLegacyTopology(u32 apic_id, u16* package_id, u16* core_id, u8* smt_id)
{
    const Cpuid r1 = DoCpuid(1);
    const u32 logical_per_pkg = (r1.ebx >> 16) & 0xFFu;
    if (logical_per_pkg == 0)
    {
        return false;
    }

    // Leaf 4 is Intel-only. AMD pre-Zen returns zeros — guard the
    // divisor and fall back to "1 core per package, all logicals
    // are SMT" which yields package_id = apic_id, core_id = 0,
    // smt_id = apic_id & smt_mask. That's still a valid (if coarse)
    // grouping for the cluster collapse rule.
    const Cpuid r4 = DoCpuid(4, 0);
    const u32 cores_per_pkg_raw = ((r4.eax >> 26) & 0x3Fu);
    const u32 cores_per_pkg = (cores_per_pkg_raw == 0) ? 1u : (cores_per_pkg_raw + 1u);
    const u32 smt_per_core = (cores_per_pkg == 0) ? 1u : (logical_per_pkg / cores_per_pkg);
    const u32 smt_per_core_eff = (smt_per_core == 0) ? 1u : smt_per_core;

    const u32 pkg_shift = CeilLog2(logical_per_pkg);
    const u32 smt_shift = CeilLog2(smt_per_core_eff);
    if (pkg_shift < smt_shift)
    {
        return false;
    }
    const u32 smt_mask = (smt_shift == 0) ? 0u : ((1u << smt_shift) - 1u);
    const u32 core_bits = pkg_shift - smt_shift;
    const u32 core_mask = (core_bits == 0) ? 0u : ((1u << core_bits) - 1u);

    *smt_id = static_cast<u8>(apic_id & smt_mask);
    *core_id = static_cast<u16>((apic_id >> smt_shift) & core_mask);
    *package_id = static_cast<u16>(apic_id >> pkg_shift);
    return true;
}

void PopulateRow(u32 cpu_id, u32 starting_apic_id)
{
    if (cpu_id >= acpi::kMaxCpus)
    {
        KLOG_WARN_V("cpu/topo", "cpu_id out of range, skipping topology decode", cpu_id);
        KBP_PROBE_V(::duetos::debug::ProbeId::kTopologyParseFailed, cpu_id);
        return;
    }
    Topology& row = k_topo[cpu_id];
    row.cpu_id = cpu_id;
    row.apic_id = starting_apic_id;
    row.package_id = kTopologyUnknownPackage;
    row.core_id = kTopologyUnknownCore;
    row.smt_id = kTopologyUnknownSmt;
    row.numa_node = kTopologyUnknownNode;
    row.cluster_id = 0;

    const Cpuid r0 = DoCpuid(0);
    const u32 max_basic_leaf = r0.eax;

    u32 apic_id = starting_apic_id;
    bool decoded = DecodeExtTopology(max_basic_leaf, &apic_id, &row.package_id, &row.core_id, &row.smt_id);
    if (!decoded)
    {
        decoded = DecodeLegacyTopology(starting_apic_id, &row.package_id, &row.core_id, &row.smt_id);
        apic_id = starting_apic_id;
    }
    row.apic_id = apic_id;

    if (!decoded)
    {
        // Neither extended nor legacy decode succeeded — leaves
        // package_id/core_id/smt_id at their unknown sentinels.
        // Cluster assignment will collapse to single-cluster, and
        // the steal path keeps round-robin behaviour.
        KLOG_WARN_V("cpu/topo", "CPUID topology decode failed", cpu_id);
        KBP_PROBE_V(::duetos::debug::ProbeId::kTopologyParseFailed, cpu_id);
    }

    // SRAT lookup keyed by the wider x2APIC value when available;
    // it falls through to the LAPIC-ID-keyed entry otherwise. The
    // SRAT parser handles apic_id >= 256 internally (skips +
    // probes) so we don't need a guard here.
    u8 node = kTopologyUnknownNode;
    if (acpi::srat::SratNodeForApic(row.apic_id, &node))
    {
        row.numa_node = node;
    }
}

u32 ReadCurrentApicId()
{
    PerCpu* self = CurrentCpu();
    if (self == nullptr)
    {
        return 0;
    }
    return self->lapic_id;
}

// Assign a dense physical-core index (core_group) to every
// populated topology row, then derive each row's SMT sibling
// count and "primary thread" flag. Runs once on the BSP at the
// tail of TopologyAssignClusters, after every row is finalized.
// Rows whose SMT identity never decoded (sentinel package / core
// / smt) get core_group = kTopologyUnknownCoreGroup so they can
// never match a sibling — the scheduler's EffectiveLoad then
// treats them as plain non-SMT CPUs (byte-for-byte legacy path).
void AssignCoreGroups()
{
    const u32 limit = arch::SmpCpuIdLimit();

    // Dense (package_id, core_id) -> core_group map, built by
    // walking populated rows in cpu_id order. Same bounded-stack
    // idiom as the pkg_dense[] walk in TopologyAssignClusters;
    // one slot per CPU bounds the distinct-physical-core count.
    struct CoreKey
    {
        u16 package_id;
        u16 core_id;
    };
    CoreKey keys[acpi::kMaxCpus] = {};
    u16 group_n = 0;

    for (u32 i = 0; i < limit && i < acpi::kMaxCpus; ++i)
    {
        Topology& row = k_topo[i];
        if (arch::SmpGetPercpu(i) == nullptr && i != 0)
        {
            continue;
        }
        if (row.smt_id == kTopologyUnknownSmt || row.package_id == kTopologyUnknownPackage ||
            row.core_id == kTopologyUnknownCore)
        {
            row.core_group = kTopologyUnknownCoreGroup;
            row.smt_sibling_count = 0;
            row.smt_primary = 1;
            continue;
        }
        u16 group = kTopologyUnknownCoreGroup;
        for (u16 d = 0; d < group_n; ++d)
        {
            if (keys[d].package_id == row.package_id && keys[d].core_id == row.core_id)
            {
                group = d;
                break;
            }
        }
        if (group == kTopologyUnknownCoreGroup && group_n < acpi::kMaxCpus)
        {
            keys[group_n] = CoreKey{row.package_id, row.core_id};
            group = group_n;
            ++group_n;
        }
        row.core_group = group;
    }

    // Second pass: per core_group, count the other members and
    // flag the lowest cpu_id in the group as the primary thread.
    for (u32 i = 0; i < limit && i < acpi::kMaxCpus; ++i)
    {
        Topology& row = k_topo[i];
        if (arch::SmpGetPercpu(i) == nullptr && i != 0)
        {
            continue;
        }
        if (row.core_group == kTopologyUnknownCoreGroup)
        {
            continue; // finalized in pass 1
        }
        u8 members = 0;
        bool is_lowest = true;
        for (u32 j = 0; j < limit && j < acpi::kMaxCpus; ++j)
        {
            if (j == i)
            {
                continue;
            }
            if (arch::SmpGetPercpu(j) == nullptr && j != 0)
            {
                continue;
            }
            if (k_topo[j].core_group != row.core_group)
            {
                continue;
            }
            ++members;
            if (j < i)
            {
                is_lowest = false;
            }
        }
        row.smt_sibling_count = members;
        row.smt_primary = is_lowest ? 1 : 0;
    }
}

} // namespace

void TopologyInitBsp()
{
    // BSP always lives at slot 0. Read its LAPIC ID off PerCpu so
    // we honour any firmware-assigned identity rather than assuming
    // 0; PerCpuInitBsp programs this from the LAPIC ID register.
    const u32 apic_id = ReadCurrentApicId();
    PopulateRow(0, apic_id);
}

void TopologyInitAp(u32 cpu_id)
{
    const u32 apic_id = ReadCurrentApicId();
    PopulateRow(cpu_id, apic_id);
}

void TopologyAssignClusters()
{
    const u32 limit = arch::SmpCpuIdLimit();
    if (limit == 0)
    {
        g_cluster_count = 1;
        g_assigned = true;
        return;
    }

    // Tally distinct NUMA nodes and packages across populated rows.
    bool nodes_seen[acpi::kMaxCpus] = {};
    bool pkgs_seen[acpi::kMaxCpus] = {};
    u8 distinct_nodes = 0;
    u8 distinct_pkgs = 0;
    for (u32 i = 0; i < limit; ++i)
    {
        if (i >= acpi::kMaxCpus)
        {
            break;
        }
        const Topology& row = k_topo[i];
        // Skip slots for AP IDs that never came online.
        if (arch::SmpGetPercpu(i) == nullptr && i != 0)
        {
            continue;
        }
        if (row.numa_node != kTopologyUnknownNode)
        {
            if (!nodes_seen[row.numa_node])
            {
                nodes_seen[row.numa_node] = true;
                ++distinct_nodes;
            }
        }
        if (row.package_id != kTopologyUnknownPackage)
        {
            // Compress package id to a small index by walking
            // pkgs_seen[] keyed on row.package_id directly. Not
            // every package_id fits in [0..kMaxCpus); accept the
            // cap and treat IDs >= kMaxCpus as conflicting in the
            // count — close enough for the collapse rule.
            const u32 idx = (row.package_id < acpi::kMaxCpus) ? row.package_id : (acpi::kMaxCpus - 1);
            if (!pkgs_seen[idx])
            {
                pkgs_seen[idx] = true;
                ++distinct_pkgs;
            }
        }
    }

    enum class ClusterMode : u8
    {
        Single,
        ByNode,
        ByPackage,
    };
    ClusterMode mode = ClusterMode::Single;
    if (distinct_nodes >= 2)
    {
        mode = ClusterMode::ByNode;
    }
    else if (distinct_pkgs >= 2)
    {
        mode = ClusterMode::ByPackage;
    }

    // Assign cluster_id for each populated row + push into PerCpu.
    g_cluster_count =
        (mode == ClusterMode::Single) ? 1 : ((mode == ClusterMode::ByNode) ? distinct_nodes : distinct_pkgs);

    // For ByPackage mode we need a dense 0..N-1 index keyed by
    // package_id. Build it by walking again.
    u16 pkg_dense[acpi::kMaxCpus] = {};
    u8 pkg_dense_n = 0;
    if (mode == ClusterMode::ByPackage)
    {
        for (u32 i = 0; i < limit && i < acpi::kMaxCpus; ++i)
        {
            const Topology& row = k_topo[i];
            if (arch::SmpGetPercpu(i) == nullptr && i != 0)
            {
                continue;
            }
            if (row.package_id == kTopologyUnknownPackage)
            {
                continue;
            }
            bool found = false;
            for (u8 d = 0; d < pkg_dense_n; ++d)
            {
                if (pkg_dense[d] == row.package_id)
                {
                    found = true;
                    break;
                }
            }
            if (!found && pkg_dense_n < acpi::kMaxCpus)
            {
                pkg_dense[pkg_dense_n++] = row.package_id;
            }
        }
    }

    bool any_failed = false;
    for (u32 i = 0; i < limit && i < acpi::kMaxCpus; ++i)
    {
        Topology& row = k_topo[i];
        PerCpu* pcpu = arch::SmpGetPercpu(i);
        if (pcpu == nullptr && i != 0)
        {
            continue;
        }
        u16 cluster = 0;
        switch (mode)
        {
        case ClusterMode::Single:
            cluster = 0;
            break;
        case ClusterMode::ByNode:
            if (row.numa_node != kTopologyUnknownNode)
            {
                cluster = row.numa_node;
            }
            else
            {
                // Fall back to package mapping when SRAT skipped this CPU.
                any_failed = true;
            }
            break;
        case ClusterMode::ByPackage:
            if (row.package_id != kTopologyUnknownPackage)
            {
                for (u8 d = 0; d < pkg_dense_n; ++d)
                {
                    if (pkg_dense[d] == row.package_id)
                    {
                        cluster = d;
                        break;
                    }
                }
            }
            else
            {
                any_failed = true;
            }
            break;
        }
        row.cluster_id = cluster;
        if (pcpu != nullptr)
        {
            pcpu->cluster_id = cluster;
        }
    }

    g_assigned = true;

    if (any_failed)
    {
        KBP_PROBE_V(::duetos::debug::ProbeId::kTopologyParseFailed, limit);
    }

    if (mode == ClusterMode::ByPackage && !acpi::srat::SratPresent())
    {
        KLOG_WARN_S("cpu/topo", "SRAT absent on multi-package box; clustering by package", "mode", "package");
    }

    // Derive SMT sibling grouping from the now-finalized rows so
    // the scheduler's wake/balance placement can spread across
    // distinct physical cores before packing SMT siblings.
    AssignCoreGroups();

    KLOG_WARN_2V("cpu/topo", "topology summary", "cpus", static_cast<u64>(limit), "clusters",
                 static_cast<u64>(g_cluster_count));
}

void TopologyDump()
{
    const u32 limit = arch::SmpCpuIdLimit();
    for (u32 i = 0; i < limit && i < acpi::kMaxCpus; ++i)
    {
        const Topology& row = k_topo[i];
        // Pack the per-CPU detail into one u64 so a single
        // KLOG_DEBUG_V call covers all of pkg/core/smt/node/cluster.
        // Layout (high -> low):
        //   bits 56..63 reserved (0)
        //   bits 48..55 cluster_id (low byte)
        //   bits 40..47 numa_node
        //   bits 32..39 smt_id
        //   bits 16..31 core_id
        //   bits  0..15 package_id
        const u64 packed = (static_cast<u64>(row.cluster_id & 0xFFu) << 48) | (static_cast<u64>(row.numa_node) << 40) |
                           (static_cast<u64>(row.smt_id) << 32) | (static_cast<u64>(row.core_id) << 16) |
                           static_cast<u64>(row.package_id);
        KLOG_DEBUG_V("cpu/topo", "cpu pkg|core|smt|node|cluster", packed);
    }
}

const Topology* TopologyForCpu(u32 cpu_id)
{
    if (cpu_id >= acpi::kMaxCpus)
    {
        return nullptr;
    }
    return &k_topo[cpu_id];
}

u8 TopologyClusterCount()
{
    return g_cluster_count;
}

} // namespace duetos::cpu
