# CPU Topology & Scheduler Clustering

> **Audience:** Kernel hackers, scheduler / SMP authors
>
> **Execution context:** Kernel — topology decode at boot (BSP + each AP);
> per-CPU infrastructure (`critical`, `ipi_call`, `percpu`) runs at any
> level per its own contract
>
> **Maturity:** v0 — locality-aware work-stealing, NUMA-aware frame allocator, cluster-aware wake placement, periodic active load balancing, SMT-aware placement, and hybrid P/E-core bias. Per-cluster runqueues and cluster-broadcast IPIs remain deferred follow-ups.

## What this is

Each CPU is decoded into a topology row at boot:

- **APIC ID** — 32-bit value when CPUID 0x0B / 0x1F is available, 8-bit LAPIC ID otherwise.
- **package_id / core_id / smt_id** — derived from CPUID 0x1F (preferred), 0x0B, or legacy leaf 4 + leaf 1.
- **numa_node** — dense 0..N-1 index sourced from ACPI SRAT (subtypes 0 and 2). `kTopologyUnknownNode` if no SRAT entry exists for the APIC.
- **cluster_id** — the scheduler-visible grouping. Assigned once at boot from the rule below.
- **core_group** — dense 0..N-1 index identifying the physical core (CPUs sharing `(package_id, core_id)`). `kTopologyUnknownCoreGroup` (0xFFFF) when SMT identity never decoded, so it can never match a sibling and the scheduler treats the CPU as plain non-SMT.
- **smt_sibling_count** — number of *other* logical CPUs sharing this physical core (0 on non-SMT). Drives the scheduler's SMT penalty fast-path.
- **smt_primary** — 1 iff this is the lowest `cpu_id` in its `core_group`. Exactly one per group; consumed by the SMT placement self-test.
- **core_class** — hybrid performance class from CPUID 0x1A (gated on the CPUID.7.0:EDX[15] hybrid bit): `kCoreClassPerf` (P-core), `kCoreClassEff` (E-core), or `kCoreClassUnknown` on every non-hybrid CPU. Decoded per-CPU in `PopulateRow` (each CPU runs it on itself, so 0x1A reports its own core type). Drives the scheduler's hybrid bias; Unknown everywhere ⇒ bias inert.

The cluster collapse rule is intentionally simple — the innermost meaningful grouping wins:

1. If SRAT reports **≥2 distinct NUMA nodes**: `cluster_id = numa_node`.
2. Otherwise if topology shows **≥2 distinct packages**: `cluster_id = package_id` (densely indexed).
3. Otherwise (single package, no SRAT): every CPU gets `cluster_id = 0`.

Single-cluster systems are the common case (every commodity desktop CPU). They collapse cleanly to one cluster — the scheduler's two-pass steal loop visits every peer in pass 0 and finds nothing to do in pass 1, so the behaviour is identical to the pre-clustering round-robin path.

## Scheduler integration

Three scheduler paths consume `cluster_id`:

1. **Work-stealing** (`StealNormalFromPeer`, idle-pull). Two-pass walk:

   ```
   pass 0: for each peer in round-robin order, skip if peer.cluster_id != self.cluster_id; try steal
   pass 1: for each peer in round-robin order, skip if peer.cluster_id == self.cluster_id; try steal
   ```

2. **Wake placement** (`PickClusterPlacement`, on every Normal-band
   wake-side enqueue). Routes from the task's `last_cpu` to the
   least-loaded peer in the same cluster when `last_cpu.runq_normal_len
   - peer.runq_normal_len ≥ kClusterPlacementMargin (2)`. Cross-cluster
   peers are skipped; cross-cluster routing is the work-stealing
   pass-1 fallback's job.

3. **Periodic active load balancing** (`PeriodicBalanceTick`, fired
   from `OnTimerTick` every `kBalancePeriodTicks` per CPU,
   phase-shifted by `cpu_id`). Pulls one Ready task from the heaviest
   same-cluster peer when the imbalance is `≥ kBalanceMargin (4)`.
   Same-cluster only — see `kernel/sched/sched.cpp` `PickBalanceVictim`
   for the design rationale.

4. **SMT-aware placement** (`EffectiveLoad`, consumed by
   `PickClusterPlacement` and `PickBalanceVictim`). Effective load =
   `runq_normal_len + kSmtSiblingPenalty (2)` when a CPU's SMT sibling
   already has Normal-band work, else the raw length. Set equal to
   `kClusterPlacementMargin` so a fully-idle physical core always wins
   placement over an SMT sibling of a busy core with the same
   no-oscillation equilibrium. **`StealNormalFromPeer` is intentionally
   *not* SMT-weighted**: it is the idle-pull path, so `self` is going
   idle and handing it work can never create a two-on-one-core
   situation — weighting it would only risk the byte-for-byte non-SMT
   ordering invariant for zero benefit. On non-SMT / undecoded CPUs
   (`core_group == kTopologyUnknownCoreGroup` or `smt_sibling_count ==
   0`) `EffectiveLoad` returns the raw length verbatim, so every
   decision stays byte-for-byte identical to the pre-SMT scheduler.

No new locks. `g_sched_lock` still covers all per-CPU runqueue access. `cluster_id` is a `u16` field on `cpu::PerCpu`, appended past the syscall-stub-relevant offsets (`kPerCpuKernelRsp = 32`, `kPerCpuUserRspScratch = 40` are guarded by `static_assert`s in `kernel/cpu/percpu.h`).

## Init order

| # | Where | Call |
|---|-------|------|
| 1 | `kernel/acpi/acpi.cpp` tail of `AcpiInit` | `srat::SratInit(srat_hdr)` |
| 2 | `kernel/core/main.cpp` after `PerCpuInitBsp()` | `cpu::TopologyInitBsp()` |
| 3 | `kernel/arch/x86_64/smp.cpp` in `ApEntryFromTrampoline` **before** the `online_flag = 1` write | `cpu::TopologyInitAp(cpu_id)` |
| 4 | `kernel/core/main.cpp` after `SmpStartAps()` returns | `cpu::TopologyAssignClusters(); cpu::TopologyDump();` |

`TopologyAssignClusters` (step 4) also runs `AssignCoreGroups()` at its tail, after every row's `cluster_id` is finalized — the SMT `core_group` / `smt_sibling_count` / `smt_primary` fields are derived there. No new init step or rendezvous: it reuses the same one-shot-on-BSP point, so the order above is unchanged.

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

## Per-CPU Infrastructure

`kernel/cpu/` is more than the topology decoder. Five further file
pairs provide the per-CPU plumbing the scheduler and SMP paths build on:

- **`percpu.{h,cpp}`** — the `PerCpu` struct, one per CPU, reached via
  `IA32_GS_BASE` so any CPU reads its own data with a `gs:`-relative
  load and zero synchronisation. `PerCpuInitBsp()` runs before
  `SchedInit`; each AP trampoline allocates its own `PerCpu` and writes
  GSBASE before entering kernel code. Offsets used by the syscall stub
  (`kPerCpuKernelRsp = 32`, `kPerCpuUserRspScratch = 40`) are pinned by
  `static_assert`.
- **`cpuhp.{h,cpp}`** — the CPU hotplug state machine (modelled on the
  Linux hotplug state machine): a sparse ordered sequence of per-CPU states
  (`Offline` … `Online`) with `(startup, teardown)` callbacks
  registered per state. Bring-up walks forward (`CpuhpBringUp`),
  takedown backward (`CpuhpTakeDown`); a failed startup rolls back
  through the teardowns of every state already entered. PREPARE states
  run on the BSP before SIPI; STARTING/ONLINE states run on the target
  AP from `ApEntryFromTrampoline`.
- **`critical.{h,cpp}`** — a preemption-off (IRQs-on) critical section
  (FreeBSD `critical_enter(9)` shape). A per-CPU `critnest` counter
  blocks the scheduler from migrating/preempting the current thread
  *without* masking interrupts: ticks still fire, but a reschedule that
  wants this CPU sets `deferred_preempt` and runs synchronously on
  `CriticalExit`. ~5× cheaper than `cli`/`sti` per pair. Use
  `CriticalGuard` (RAII) rather than the bare `CriticalEnter`/`Exit`.
- **`ipi_call.{h,cpp}`** — the cross-CPU function-call primitive (Linux
  `smp_call_function*` / Windows `KeIpiGenericCall` shape). Any CPU can
  invoke an arbitrary function on one peer (`IpiCallOne`) or every
  online CPU, with optional spin-wait for completion, via a per-CPU
  16-slot MPSC mailbox ring. The callee `fn` runs in IRQ context with
  IF=0 on the target CPU and must not sleep. Unblocks correct per-CPU
  TLB shootdown and future stop-machine / live-patch primitives.
- **`percpu_counter.{h,cpp}`** — a split per-CPU counter with bounded
  slop. Hot writers (`Add`) bump only their CPU's stash and fold into
  the 64-bit global under a short spinlock when the stash exceeds
  `batch`. `ReadApproximate()` is a single atomic load (drift ≤
  `batch * NR_CPUS`); `ReadExact()` sums every stash under the lock.
  For read-mostly counters (free-page count, open-handle count,
  scheduler stats) where a global atomic per increment would dominate.

## Files

- `kernel/cpu/topology.h` / `topology.cpp` — public API + implementation
- `kernel/acpi/srat.h` / `srat.cpp` — SRAT walker
- `kernel/cpu/percpu.h` — `PerCpu.cluster_id` (with offset `static_assert`s)
- `kernel/sched/sched.cpp` — `StealNormalFromPeer` two-pass loop, `PickClusterPlacement` wake-side router, `PickBalanceVictim` / `PeriodicBalanceTick` periodic balancer
- `kernel/arch/x86_64/smp.cpp` — `TopologyInitAp` invocation in `ApEntryFromTrampoline`
- `kernel/core/main.cpp` — `TopologyInitBsp` + `TopologyAssignClusters` + `TopologyDump` wiring
- `kernel/debug/probes.h` / `probes.cpp` — `kTopologyParseFailed`

## Known Limits / GAPs

- **NUMA-unaware frame allocator detail** — SRAT NUMA ranges feed
  `cluster_id`, but the frame allocator itself is still a single global
  pool; per-node pools are deferred (see [Memory Management](Memory-Management.md)).
- **SRAT entries with `apic_id >= 256`** — logged once and skipped,
  out of v0 scope (see [Failure handling](#failure-handling) above).
- The deferred follow-on slices below.

## Follow-on slices (deferred)

- **Per-cluster runqueue split** — decompose `g_sched_lock` along cluster boundaries; intra-cluster moves bypass the global lock. Roadmap entry **B2-followup**.
- **Cluster-broadcast IPIs** — extend `arch::SmpSendIpi` with cluster-scoped destination bits when `x2APIC` cluster mode is in use.

## Related pages

- [Scheduler](Scheduler.md) — work-stealing and per-CPU runqueues
- [SMP AP Bringup Scope](../advanced/SMP-AP-Bringup-Scope.md) — AP enumeration and bring-up
- [Memory Management](Memory-Management.md) — frame allocator (NUMA-unaware today)
