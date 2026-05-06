# CPU Topology & Scheduler Clustering

> **Maturity:** v0 — locality-aware work-stealing only. NUMA-aware page allocation, per-cluster runqueues, cluster-broadcast IPIs, and placement affinity at task spawn/wake are deferred follow-ups.

## What this is

Each CPU is decoded into a topology row at boot:

- **APIC ID** — 32-bit value when CPUID 0x0B / 0x1F is available, 8-bit LAPIC ID otherwise.
- **package_id / core_id / smt_id** — derived from CPUID 0x1F (preferred), 0x0B, or legacy leaf 4 + leaf 1.
- **numa_node** — dense 0..N-1 index sourced from ACPI SRAT (subtypes 0 and 2). `kTopologyUnknownNode` if no SRAT entry exists for the APIC.
- **cluster_id** — the scheduler-visible grouping. Assigned once at boot from the rule below.

The cluster collapse rule is intentionally simple — the innermost meaningful grouping wins:

1. If SRAT reports **≥2 distinct NUMA nodes**: `cluster_id = numa_node`.
2. Otherwise if topology shows **≥2 distinct packages**: `cluster_id = package_id` (densely indexed).
3. Otherwise (single package, no SRAT): every CPU gets `cluster_id = 0`.

Single-cluster systems are the common case (every commodity desktop CPU). They collapse cleanly to one cluster — the scheduler's two-pass steal loop visits every peer in pass 0 and finds nothing to do in pass 1, so the behaviour is identical to the pre-clustering round-robin path.

## Scheduler integration

`StealNormalFromPeer` (`kernel/sched/sched.cpp`) is the only consumer of `cluster_id` today. The work-stealing walk is two passes:

```
pass 0: for each peer in round-robin order, skip if peer.cluster_id != self.cluster_id; try steal
pass 1: for each peer in round-robin order, skip if peer.cluster_id == self.cluster_id; try steal
```

No new locks. `g_sched_lock` still covers all per-CPU runqueue access. `cluster_id` is a `u16` field on `cpu::PerCpu`, appended past the syscall-stub-relevant offsets (`kPerCpuKernelRsp = 32`, `kPerCpuUserRspScratch = 40` are guarded by `static_assert`s in `kernel/cpu/percpu.h`).

## Init order

| # | Where | Call |
|---|-------|------|
| 1 | `kernel/acpi/acpi.cpp` tail of `AcpiInit` | `srat::SratInit(srat_hdr)` |
| 2 | `kernel/core/main.cpp` after `PerCpuInitBsp()` | `cpu::TopologyInitBsp()` |
| 3 | `kernel/arch/x86_64/smp.cpp` in `ApEntryFromTrampoline` **before** the `online_flag = 1` write | `cpu::TopologyInitAp(cpu_id)` |
| 4 | `kernel/core/main.cpp` after `SmpStartAps()` returns | `cpu::TopologyAssignClusters(); cpu::TopologyDump();` |

The trampoline sets `online_flag = 1` only after the AP has populated its own `k_topo[cpu_id]` row. The BSP's `WaitForApOnline` poll inside `SmpStartAps` therefore doubles as the rendezvous on AP topology decode — no separate done flag, no race when `TopologyAssignClusters` runs.

## Failure handling

Every step is non-fatal:

- CPUID extended-topology decode failure → fall back to legacy leaf-4 + leaf-1 path.
- Both decode paths failed → `package_id` / `core_id` / `smt_id` stay at sentinel values; `kTopologyParseFailed` probe fires; `KLOG_WARN_V("cpu/topo", "CPUID topology decode failed", cpu_id)`.
- SRAT absent / bad checksum → treated as UMA; `SratPresent()` returns false; cluster rule falls through to package-mode.
- SRAT entry with `apic_id >= 256` → logged once, skipped (out of v0 scope).
- Cluster assignment encounters CPUs without a NUMA entry in `ByNode` mode → `kTopologyParseFailed` probe fires; that CPU stays at `cluster_id = 0`.

The probe (`debug::ProbeId::kTopologyParseFailed`, `topo.parse_failed`) is `ArmedLog` by default — clean boots stay quiet, regression boots leave a sentinel + the value of whatever tripped the path.

## Diagnostics

```
[acpi] srat=present nodes=2     # or "absent"
[cpu/topo] topology summary cpus=4 clusters=2     # KLOG_WARN_2V — exactly one row
[cpu/topo] cpu pkg|core|smt|node|cluster <packed>  # KLOG_DEBUG_V — one row per CPU
```

The packed value layout (from `TopologyDump`):

```
bits 48..55: cluster_id (low byte)
bits 40..47: numa_node
bits 32..39: smt_id
bits 16..31: core_id
bits  0..15: package_id
```

## Verification

- **Single-package QEMU** (`-smp 4`, no `-numa`): `topology summary cpus=4 clusters=1`; `topo.parse_failed` does not fire; existing AP-online rows still emit.
- **Multi-NUMA QEMU** (`-smp 4 -numa node,cpus=0-1 -numa node,cpus=2-3`): `topology summary cpus=4 clusters=2`; per-CPU dump shows cpus 0–1 cluster=0, cpus 2–3 cluster=1.
- **CPUID-fallback QEMU** (`-cpu qemu64` or similar masking 0x0B): legacy leaf-4 path succeeds; probe stays unfired.
- **Single-CPU regression** (`-smp 1`): `StealNormalFromPeer` returns at the `limit <= 1` guard before reading cluster bits — identical timing to pre-change.
- **Manual locality trace**: arm `sched.context_switch`, boot multi-NUMA, observe stolen tasks' `last_cpu` stays within the original cluster on first pass.

## Files

- `kernel/cpu/topology.h` / `topology.cpp` — public API + implementation
- `kernel/acpi/srat.h` / `srat.cpp` — SRAT walker
- `kernel/cpu/percpu.h` — `PerCpu.cluster_id` (with offset `static_assert`s)
- `kernel/sched/sched.cpp` — `StealNormalFromPeer` two-pass loop
- `kernel/arch/x86_64/smp.cpp` — `TopologyInitAp` invocation in `ApEntryFromTrampoline`
- `kernel/core/main.cpp` — `TopologyInitBsp` + `TopologyAssignClusters` + `TopologyDump` wiring
- `kernel/debug/probes.h` / `probes.cpp` — `kTopologyParseFailed`

## Follow-on slices (deferred)

- **NUMA-aware page allocator** — frame allocator queries SRAT memory-affinity records (subtype 1) and prefers the requesting CPU's node.
- **Per-cluster runqueue split** — decompose `g_sched_lock` along cluster boundaries; intra-cluster moves bypass the global lock. Roadmap entry **B2-followup**.
- **Cluster-broadcast IPIs** — extend `arch::SmpSendIpi` with cluster-scoped destination bits when `x2APIC` cluster mode is in use.
- **Placement affinity** — at task creation / wake, route to the parent's cluster's least-loaded CPU rather than just `last_cpu`.

## Related pages

- [Scheduler](Scheduler.md) — work-stealing and per-CPU runqueues
- [SMP AP Bringup Scope](../advanced/SMP-AP-Bringup-Scope.md) — AP enumeration and bring-up
- [Memory Management](Memory-Management.md) — frame allocator (NUMA-unaware today)
