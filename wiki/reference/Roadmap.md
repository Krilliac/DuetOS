# DuetOS Roadmap — pending and deferred work

> **Audience:** Maintainers, contributors picking the next slice
>
> **Maturity:** Living document; edit when an item lands or a new gap is found

This page consolidates every multi-session work item that is **not
yet in tree**. Each entry names the surface that owns the gap and
the residual that remains, so a contributor can pick one without
re-deriving the field.

**Policy:** when a roadmap item lands, **delete its entry here in
the same commit that delivers the code**, record the landing in
[`Design-Decisions`](Design-Decisions.md), and update the owning
subsystem wiki page. Landed work does **not** live on this page —
if you find a "shipped / landed / DONE" paragraph here, it is
cleanup debt: move the residual up and delete the rest.

---

## Kernel / runtime

### B2-followup — split `g_sched_lock` per-CPU

- **Bridge phase LANDED (2026-06-10, step 2 of 4).** The per-CPU
  runqueue locks now exist — `g_runq_locks[acpi::kMaxCpus]`
  (class `kLockClassSchedRunq`, kept OUTSIDE `cpu::PerCpu` to dodge
  the syscall-stub layout static_asserts + false sharing on the
  lock-free length/online fields). The four mutation funnels
  (`RunqueuePushOn` / `RunqueuePop` / `StealNormalFromPeer` /
  `BalancePullOnce`) take the owning CPU's lock for the duration of
  the list+counter mutation **under the still-global lock**, so the
  `g_sched_lock → runq` ordering and lockdep edge are validated on
  every boot. Step 1 (close the unlocked-walker gap) also landed.
- **Residual (steps 3-4 — the actual contention win):** (3) make
  the context-switch lock-pass slot 2-deep + dynamically seed a
  fresh task's lockdep held-set, then (4) drop `g_sched_lock` from
  the pure-`Schedule()` path (local `runq_lock` only), keep
  global+local on the blocking primitives (the no-gap double-run
  invariant requires the lock the task marked itself Blocked under
  to ride the switch), and convert steal/balance to `SpinLockTryGuard`.
- **Blocks on:** a profile showing contention on `g_sched_lock`.
  This is the deliberate stop: the bridge phase de-risked the split
  (infrastructure + ordering proven), and steps 3-4 rewrite the
  hard-won context-switch UAF-prevention handshake — not worth that
  risk in the kernel's most dangerous code until a workload shows
  the global lock actually hurts. The full step-3/4 design (31-site
  lock inventory, 2-deep slot stack, try-lock steal) is captured in
  the [[expansion-campaign-2026-06-10]] session scoping.
- **Cascading items unlocked when steps 3-4 land:**
  - Index the lockdep / event-trace / soft-lockup `g_per_cpu`
    arrays by current-CPU ID (currently keyed on `g_per_cpu[0]`
    aliases).
  - SMP-stress versions of the RwLock + SeqLock + KMailbox
    contention self-tests.
  - Buddy coalescing + per-CPU lock-free allocator fast paths
    (frame warm-pool / slab magazine) — correctness is already
    in place under one global allocator lock; this is the
    scalability follow-on.
  - Move LAPIC-divider + tick-frequency programming out of
    `arch::TimerInit` into `time::TimerConfigure(hz)` once an
    ARM64 / generic-timer backend justifies the abstraction.
  - (MLFQ priority bands no longer block on the lock-drop — the
    per-CPU runqueue *structure* is enough; tracked as
    T8-01-followon.)

### Lockdep held-set — watch for a residual false inversion

- **Landed:** the held-class stack is now per-task (swapped at the
  context-switch boundary) for sleeping `sched::Mutex` classes and
  per-CPU for spinlock classes, plus the WITNESS-style
  `LockKind { Spin, Sleep, Irq }` acquire-time taxonomy
  (`LOCKDEP_ASSERT_HELD`). The compositor↔fat32 sleeping-mutex false
  inversion is gone. (History in git; the design constraints — no
  `Task*` threaded through every hook, restore after the fresh-AP
  guard — are documented in `kernel/sched/sched.cpp`.)
- **Blocks on:** a workload that produces a false inversion the
  per-CPU + per-task pair doesn't already absorb. None observed
  since 2026-05-22.

### Topology — cluster-scoped IPI fan-out

- **Residual:** the *cluster-scoped* fan-out (one ICR write to
  the CPUs of one scheduler cluster, not all peers) needs x2APIC
  *logical* destination mode (LDR/cluster addressing) on top of
  the physical-mode x2APIC already in tree.
- **Blocks on:** profile evidence that a per-cluster (not
  all-peer) fan-out is workload-justified — reschedule is
  single-target, shootdown is kernel-AS-broadcast or
  per-AS-targeted, never per-cluster. Pre-emptive build avoided.
  (Clustering v0, NUMA frame allocator, wake/periodic balance,
  SMT + hybrid P/E bias, hard affinity, MWAIT idle, single-ICR
  broadcast, and x2APIC enablement all landed — see
  [CPU Topology](../kernel/CPU-Topology.md) /
  [Scheduler](../kernel/Scheduler.md).)

### AddressSpace region table — synchronise reads against the swap-with-last compaction

- **Historical finding (audit R1-14, fixed in this audit):** `AddressSpace::regions_lock` was
  acquired in exactly ONE place — `AddressSpaceMapUserPage`
  (`mm/address_space.cpp:396`). `AddressSpaceUnmapUserPage`,
  `AddressSpaceClearUserMappings`, `AddressSpaceFork`,
  `AddressSpaceLookupUserFrame` and `AddressSpaceRelease` all
  read or mutate `regions[]` / `region_count` with no
  synchronisation at all. Two threads in the SAME address space
  reach these concurrently — Win32 processes are genuinely
  multithreaded (`kWin32ThreadCap == 8`) and Linux `clone` shares
  the AS — so this is reachable, not theoretical.
- **Why it corrupts rather than merely races:**
  `UnmapUserPageByIndex` compacts the table by SWAP-WITH-LAST
  (`regions[idx] = regions[last]; --region_count`). A concurrent
  `AddressSpaceLookupUserFrame` scanning upward can therefore miss
  a live entry that was just moved *behind* its cursor, or observe
  a half-copied row. The failure mode is "a mapped page reports as
  unmapped", which the loaders treat as "safe to map here".
- **The naive fix is WRONG, and this is the part the finding does
  not capture.** `regions_lock` is a SLEEPING lock — `RwLock` is
  built on `sched::MutexLock` + `sched::CondvarWait`
  (`sync/rwlock.cpp:81`). But `AddressSpaceLookupUserFrame` has a
  caller that runs holding a SPINLOCK:
  `debug/breakpoints.cpp:848 ResolveStoppedUserByte(...)` is
  annotated `/* MUST hold g_lock */`, and `g_lock` is a
  `sync::SpinLock` (`breakpoints.cpp:105`). Adding a shared
  acquire to the read path would sleep while holding a spinlock —
  a worse defect than the race being fixed.
- **Shape a real fix has to take.** Separate the table's
  STRUCTURAL integrity from the long operations around it: a short
  IRQ-safe spinlock covering only the scan / swap / count update,
  with allocation/free, page copying, cross-subsystem calls, and TLB
  shootdown waits kept outside it. Bounded page-table edits belong
  inside the structural commit; allocating their intermediate tables
  does not.
- **Implemented on the audit branch:** each AS now has a task-context
  `sched::Mutex` transaction lock above the existing structural
  `sync::SpinLock`. Map operations inspect under the spinlock, prepare
  region-table storage and up to three page-table frames outside it,
  then commit the PTE and ledger atomically under it. Unmap/protect
  detach or rewrite under the spinlock, drop it, then complete the TLB
  shootdown and frame retirement while the mutex prevents a same-VA
  mutation from overtaking them. User-AS reclamation snapshots the active
  CPU mask while migration is pinned, walks the sparse ready-CPU set, and
  waits for confirmed per-target IPI completion; there is no timeout-based
  reuse of an owned frame. Empty user-half table paths are pruned during the
  structural commit, and leaf/table frames are released only after every
  targeted peer acknowledges invalidation. Fork snapshots one row/PTE at a
  time and performs frame allocation/copying outside the spinlock. Readers,
  including the breakpoint resolver, still take only the bounded spinlock
  and never sleep.
- **Process/cross-AS lifetime slice implemented on the audit branch:**
  Win32 process-handle slots now have an IRQ-safe owner lock. Lookup takes a
  target reference before dropping that lock; close and final drain detach
  rows under it and release afterward. Every VM/query/terminate/info/section
  consumer holds the transient reference through the operation. Cross-AS
  read/write uses a bounded address-space transaction-copy API, so PTE
  resolution, permission validation, and direct-map access cannot race
  unmap/protect/remap; caller user-copy runs outside the AS transaction. The
  scheduler reaper now removes task lookup visibility before dropping its
  Process/AS references, and public borrowed PID/TID lookups are replaced by
  retained, existence-only, or scheduler-owned by-ID operations. Owner Jobs
  drain at the last-task boundary, and SpawnEx installs inherited stdio before
  the child Task becomes runnable.
- **Remaining lifetime contracts:** raw frame lookup remains for callers that
  must be classified as pre-publication/stopped-task safe or moved behind a
  transaction operation. Win32 section mapping must pin its section and
  frames before it can wait for the AS transaction, and its handle/view/W^X
  ledgers need serialized reserve/publish/retire state. Multi-threaded fork
  also needs sibling quiescence, COW, or an explicit rejection contract to
  promise a coherent memory snapshot.
- **Verification boundary:** source diff/format checks are complete.
  Full MSVC build, rebuilt tests, multi-vCPU QEMU boot, allocation-failure
  injection, and concurrent map/protect/unmap stress remain required.
- **Historical blocker:** deciding between those two, since it changes an
  mm-core invariant. Not attempted as a drive-by: `address_space.cpp`
  is the highest-blast-radius file in the tree and a partial fix here
  (locking writers only, leaving the spinlock-holding reader
  unsynchronised) would buy very little while looking like a
  resolution.

### AdaptiveMutex — scheduler-owned compatibility surface

- **Resolved on the audit branch:** `AdaptiveMutex` retains its public API but
  delegates acquire, try-acquire, release, FIFO enrollment, and direct handoff
  to `sched::Mutex`. The raw `Task*` owner and the split owner-check/wait-queue
  enrollment are gone, so scheduler lifetime accounting covers every holder
  and a peer unlock cannot overtake waiter publication.
- **Compatibility contract:** the current implementation deliberately does not
  spin. A small publication spinlock protects only the race-free diagnostic
  snapshot used by `AdaptiveMutexIsHeld`; it is not a second ownership source
  and cannot be used to guard protected data.
- **Verification:** the deterministic self-test waits until the contender is
  observably blocked before allowing the owner to release, then requires FIFO
  handoff and successor release. Source/format and structural checks are
  complete; delete this section after the final strict multi-vCPU boot gate.


### PS/2 scan-code ring — SMP single-producer/single-consumer invariant

- **Landed:** ring overflow now drops the incoming (newest) scan code
  instead of advancing the task-owned `g_ring_tail` from IRQ context.
  The IRQ writes only `g_ring_head`; readers write only `g_ring_tail`,
  so the ring no longer has two unsynchronised writers on SMP.
- **Trade-off:** under overflow, a new byte may be lost instead of the
  oldest queued byte. This is intentional: preserving cursor ownership
  is more important than the previous overflow preference, and either
  policy loses input once the consumer is too slow.
- **Residual:** the raw API remains single-reader, and the blocking
  reader still uses the existing `Cli()` check-then-block handoff.


### Cooperative cancellation of blocked user waits — core path landed

- **Landed:** scheduler result-bearing cancellable WaitQueue, mutex, and
  condvar APIs opt a suspended call stack into cross-queue detach under
  `g_sched_lock`. A killer only publishes intent and makes the Task ready;
  the resumed Task receives `Cancelled` and unwinds its own references and
  locks before the outer syscall/trap boundary finalizes it. Condvar
  cancellation re-acquires the companion mutex on every return path.
- **Integrated:** KEvent, KSemaphore, KMailbox, KWaitable wait-any, and the
  GUI message wait use the cancellable APIs and preserve cancellation as a
  distinct result through their user-visible adapters. Hostile structural
  contracts guard dequeue ownership, unwind ordering, timeout accounting,
  and the rule that a foreign CPU never destroys a suspended kernel stack.
- **Process-wide kill is linearized with spawn:** each Process now owns a
  monotonic Task-publication tombstone, separate from lifecycle. PID and
  retained-Process kill close it under `g_sched_lock` before their exact
  task scan; first and additional Task publication check it under that same
  lock and fully roll back on rejection. Individual-TID kill does not close
  the Process, and lifecycle remains Published until last-Task reap.
- **Residual:** ordinary kernel-only/non-result-bearing waits remain
  intentionally non-cancellable because their callers cannot report and
  safely unwind interruption. Each additional user-visible blocking API
  must migrate deliberately or await its natural producer. Runtime SMP
  kill-versus-wake and kill-versus-spawn stress is still required beyond
  the structural contracts and exact object compilation gates.


### Real KASAN

- **Residual:** shadow-memory mapping, compiler-plugin
  integration, per-access shadow lookup. Big lift; deferred until
  a use-after-free hunt needs it. (Slab allocator + freed-object
  poison landed; automatic KMalloc→slab routing for ≤512 B
  allocations landed 2026-06-10 — 8 `kmalloc-N` irq-safe caches,
  route-header discrimination, `[kmalloc-route-selftest]` boot
  gate; see `kernel/mm/kmalloc_route.h` + Design-Decisions.)

### Re-check F-040 hung-task soft-panic under saturation

- **F-050 (timer-IRQ preemption livelock) landed 2026-06-08** — the fix,
  kill-switch (`g_timer_nest_defer_enabled`), and verification are recorded
  in `wiki/reference/Design-Decisions.md` and `docs/usability/findings.md`;
  not repeated here.
- **Still open:** re-check **F-040** (intermittent hung-task soft-panic,
  `selftest-42` stuck under the same `resource`-vector load that triggered
  F-050). Both are saturation-induced scheduler-progress failures and likely
  share a root; confirm whether the F-050 nesting-defer also clears F-040, or
  whether F-040 needs its own fix. Evidence: `docs/usability/findings.md` F-040
  row (calendar run-1 serial).

### Usability campaign — app gaps that need a real subsystem (2026-06-07)

These E-8 findings each cite a concrete rubric bar the app does
not meet, but closing the gap needs a kernel/driver subsystem that does
not exist yet — so they are **filed**, not patched (a fake slider /
read-only "selector" would be worse than the honest read-only panel).

(F-029 — Settings ▸ Display runtime resolution selector — **landed
2026-06-08**: a real virtio-gpu modeset path + revert-timeout. See
`wiki/drivers/Graphics-Drivers.md` ("Runtime modeset") and
`wiki/reference/Design-Decisions.md`.)

- **Evidence:** `docs/usability/findings.md` rows F-019 /
  F-030; campaign screenshots under `docs/usability/screenshots/`.

### Linux CVE audit — invariants to honour before the surface lands

Each must be honoured **when the matching surface lands**, not
retrofitted after. See
[`Linux-CVE-Audit`](../security/Linux-CVE-Audit.md) for the
verdict matrix. (Classes E, M, N, O, CC, FF, GG, II-scaffolding
landed.)

- **Class D — COW / `fork()`.** Dirty-bit clear-and-fault must be
  atomic w.r.t. any region-shrink primitive (`madvise(DONTNEED)`).
  Mirror Linux's `FOLL_WRITE` gate in the v0 design.
- **Class C — zero-copy sendmsg / IPsec.** Every externally-backed
  skb fragment carries an ownership marker; every in-place
  transform refuses to operate on a marked fragment. Bake into
  the network-stack ABI from day one.
- **Class B — user-facing crypto API.** An AF_ALG-equivalent must
  refuse src/dst aliasing on user scatterlists for any op that
  doesn't byte-copy the full output.
- **Class I — Bluetooth upper stack.** L2CAP / RFCOMM / SDP
  parser invariants per class C.
- **Class L — IPv6 reassembly.** Every fragment length/offset
  comparison uses `len > end - off` form (never `end - len`).
- **Class K — FS write paths.** Re-audit when ext4 write / NTFS
  directory parsing / any write-remount path lands.
- **Class V — programmable kernel filters.** Do **not** adopt an
  unprivileged-JIT BPF-equivalent; gate any programmable filter
  behind a capability or a formally-verified interpreter.
- **Class W — GPU command submission.** Interpose a kernel
  translation step producing a verified-shape submission the user
  cannot edit post-validation, before any user-mode GPU
  command-buffer surface.
- **Class II follow-up (apply the KASLR slide).** Candidate slide
  is computed at boot (`KaslrGetCandidateSlide`); the follow-on
  builds the kernel PIE, emits a relocation table the early-boot
  stub iterates, applies the slide, and flips
  `KaslrGetKernelSlide` to return it. **Same work as T5-03.**
  Must land before any multi-tenant deployment.
- **When to revisit:** every time a high-impact public
  Linux/Windows kernel CVE drops, walk the audit doc and update
  verdicts before the next slice lands in the affected area.

### Intel CET enable

- **Scope:** write `IA32_S_CET` / `IA32_PL0_SSP`, allocate
  shadow stacks, recompile with `-fcf-protection=branch`.
- **Blocks on:** kernel-image rebuild flag wiring + per-task
  shadow-stack allocator + per-IDT-vector ENDBR64 prologue.
  Probe (`arch::CetGet`) is in place to gate the enable code.
- **When to land:** when a test-fleet machine advertises
  CET-SS / CET-IBT and a workload benefits from software-enforced
  CFI on top of the silicon protection.

### KPTI enable (settled — DEFERRED)

- **Status:** runtime probe
  (`arch::CpuMitigationsGet().needs_kpti`) is in tree; on a
  `RDCL_NO=0` boot it emits a loud serial WARN.
- **Why deferred:** every CPU in the hardware-target matrix
  reports `RDCL_NO=1` in silicon, making KPTI a 5–30% syscall
  cost mitigating an attack the hardware already prevents.
- **Re-open triggers:** a target-fleet CPU lacking `RDCL_NO=1`,
  or a workload that crosses a trust boundary the hardware can't
  enforce.

---

## Storage and filesystem

### FAT32 — driver-wide mutex saturation under concurrent writers

- **Residual:** `kernel/fs/fat32.cpp:68` declares one global
  `sched::Mutex g_fat32_mutex` (`Fat32Guard` RAII at every public
  entry) protecting both metadata (BPB, FAT chain cache, path
  cache) AND the **single** I/O staging buffer `g_scratch[4096]`.
  Every lookup / read / write / mkdir / rename serializes on it.
  Correct (the recursive-entry handling in `Fat32Guard::Fat32Guard`
  is the standard pattern) but **two saturation corners** are
  visible without rewriting the locking:
  1. **Priority inversion** — there is no priority inheritance
     today. A low-priority task holding the mutex while a
     high-priority task waits is blocked by a peer at the same
     scheduling class. v0 has one priority band so the symptom
     is "fair-share starvation under contention," not a hard
     hang — but `Process::win32_priority_class` is wired
     (T8-01-followon) and the moment band-aware enqueue lands
     this becomes a real inversion.
  2. **Livelock under wake-storm** — many tasks repeatedly
     contesting `g_fat32_mutex` spend cycles waking + parking
     instead of doing FS work. Repro under stress=cpu workloads
     that touch FAT32 from the boot tail: `fs/fat32 : lookup`
     debug lines fire hundreds of times per second per worker,
     each round-tripping through `MutexLock` / `MutexUnlock` and
     the per-task held-stack snapshot/restore.
- **Lock-free path-cache fast path — LANDED (2026-05-22).** The
  smallest-concrete-fix bullet's original "per-CPU `g_scratch`"
  approach turned out to be invasive (the buffer is read
  throughout the parsers, not just by `ReadSector`), so the
  actually-smallest fix that helps shipped instead: a
  seqlock-guarded `PathCacheGetSeqlock` probed BEFORE
  `Fat32Guard` in `Fat32LookupPath`. Every cache-hit lookup —
  the boot-storm pattern of repeated NOTES.TXT / TEST.* /
  TRTEST.BIN / KERNEL.FIX probes — now skips the mutex acquire
  + held-stack push + cli/sti + release entirely. Writers
  (under the mutex) bump a per-entry `write_seq` to odd before
  fields, back to even after; readers (lock-free) snapshot the
  seq before + after their copy and bail on any mismatch. The
  generation counter store became `__ATOMIC_RELEASE` so
  concurrent invalidation downgrades to a miss instead of a
  stale entry. Saves a `MutexLock`/`MutexUnlock` round-trip per
  cache hit — observable on `tools/test/fat32-concurrent.sh`
  contention metric.
- **Residual (per-CPU `g_scratch` + lock-drop during block-IO):**
  the actual "release the mutex during the slow block read"
  win still needs the buffer split. Audit-wise that's:
  thread a `scratch_ptr` parameter through ReadSector /
  ReadCluster and the BPB / DirEntry parsers in fat32.cpp,
  fat32_dir.cpp, fat32_lookup.cpp, fat32_read.cpp,
  fat32_write.cpp, fat32_create.cpp — about 40 call sites and
  every consumer line that reads `g_scratch[N]`. With the
  buffer per-CPU, the mutex can be dropped around the
  `BlockDeviceRead` itself (the slow path). Larger but
  mechanical; gated until a workload shows the path-cache
  fast-path doesn't already absorb the contention.
- **Baseline measurement (2026-05-22 — gates the refactor):**
  `tools/test/fat32-concurrent.sh 30` on x86_64-release reports
  zero `fs/fat32 : lookup` debug lines, zero `MutexLock waiter`
  parking sentinels, zero non-deliberate lockdep inversions,
  and zero `fs/fat32 [E]` lines over the 30 s window. The
  path-cache fast path is doing its job — boot-storm probes
  (NOTES.TXT / TEST.* / TRTEST.BIN / KERNEL.FIX et al.) all
  retire lock-free before the slow walker is consulted, so the
  driver-wide mutex never serialises under the present
  workload. Per the gate below, the per-CPU `g_scratch` +
  lock-drop refactor stays deferred — the cost (≈ 120
  reference-site edits across 5 TUs, in the same area as the
  just-landed SMP=8 UAF fix) does not buy a measurable win
  today. Revisit when a workload shows the seqlock probe
  missing (e.g. write-heavy + sustained eviction beyond the
  32-slot cache) or when a profile attributes wall-time to
  the in-mutex `BlockDeviceRead`.
- **Larger refactor (deferred):** split into per-volume mutex +
  per-cache RwLock + lock-free FAT entry cache. Wants its own
  slice once the path-cache fast path + per-CPU scratch are
  measured.
- **Saturation harness:** `tools/test/fat32-concurrent.sh`
  spawns the linux-smoke synfs + win32 PE smokes concurrently
  and captures the boot log. Look for `fs/fat32 : lookup`
  line-rate vs `MutexLock waiter` parking lines as the
  contention signal. (Script-side fix landed 2026-05-22 — the
  `|| echo 0` fall-back was chained onto `grep -c`, which
  already prints 0 on no-match and exits 1, so on a clean run
  the variable captured "0\n0" and the arithmetic below it
  bombed with "syntax error in expression". Replaced with `;
  true` so a clean baseline run completes its report.)
- **Blocks on:** evidence that the path-cache fast path didn't
  close the live livelock corner. The 2026-05-22 baseline run
  above shows it HAS closed it under the present workload, so
  this entry stays gated until a future workload shows the
  symptom.

### Stage 6 — per-process namespace roots (residual)

- **Residual:** teach `Process::root` to carry a `VfsNode` (or a
  thin `VfsDir*` handle) so a sandboxed process can be rooted at
  a non-ramfs subtree (e.g. `/disk/0/SANDBOX`). Today every
  process root is a `const RamfsNode*`; trusted roots see the
  global mount namespace by policy and custom roots can expose
  individual graft points, but the root itself can't be a
  non-ramfs backend node. The wider syscall surface (open / stat
  / readdir) still lands in `RamfsNode*` for ramfs fall-through —
  migrating those is a per-syscall follow-on once a workload
  demands a non-ramfs sandbox root. (Global-namespace VFS mount
  registry + cross-mount resolver landed.)

### Stage 7+ — writable / native FS / NTFS read

In rough priority:

1. **Native DuetOS FS** — journalled, ext-like, done in Rust.
   Partly landed (DuetFS v3) — see **DuetFS follow-ups** below.
2. **NTFS read-only** — required by the Windows-PE pillar to load
   a `.exe` from a real NTFS partition. (NTFS metadata walker +
   read path landed, including VFS integration: `VfsResolve` on an
   NTFS mount surfaces an `Ntfs`-tagged `VfsNode` that the shell
   read path streams via `NtfsReadMftRecord` → `NtfsResolveData` →
   `NtfsReadFile`; ext4 read-only landed identically — see
   `Ext4Lookup` / `NtfsLookup` in `kernel/fs/mount.cpp` and the
   `[ext4-selftest]` / `[ntfs-selftest]` "VFS resolve verified"
   boot gates. Both walk **multi-component** paths (`/sub/file`):
   ext4 via `Ext4FindInDir`, NTFS via `NtfsFindInDir` over each
   record's resident `$I30` index. ext4 file reads follow depth>0
   extent trees (`MapLogicalBlock`, capped at `kMaxExtentDepth=16`).
   NTFS large (`$INDEX_ALLOCATION`-spilled) directories are walked
   since 2026-06-10 (multi-run runlist + `$BITMAP` gating + INDX
   USA fixups; bounded linear scan — b-tree VCN descent is the
   remaining GAP in `ntfs.cpp`). **Residual:** neither FS follows
   symlinks/reparse points; ext4 htree directories are unwalked.
   NTFS *write* is a separate item — **T7-04** below.)

### Foreign-FAT interop read — explicit opt-in mount

- **Residual:** `Fat32Probe` now adopts ONLY DuetOS-owned volumes
  (BPB serial `kDuetOsVolumeId` + label `kDuetOsVolumeLabel`, via
  `Fat32VolumeIsDuetOsOwned`). A FAT32 volume without those markers —
  a Windows EFI System Partition, a real Linux FAT, a USB stick — is
  recognised and logged but **not** registered, so it can never become
  `Fat32Volume(0)` and have the boot persistence sinks write into it.
  This closed the bare-metal vector where DuetOS wrote `KERNEL.LOG` /
  `KERNEL.FIX` into a foreign partition.
- **Gap:** the long-term FAT32 *interop-read* goal (mount a foreign
  FAT read-only for `.exe` loading / data import) now needs an
  **explicit, user-invoked, read-only mount path** that bypasses the
  ownership gate deliberately — it must register the foreign volume at
  an index ≥1 (never slot 0) and mark it read-only so no sink targets
  it. Not wired at boot today; marked `// GAP:` in
  `kernel/fs/fat32.cpp` (`Fat32Probe` foreign-volume branch).
- **Precondition (geometry validation) for this slice:** today the
  divide-by-zero / cluster-size safety of the FAT walkers rests on
  `Fat32Probe`'s implicit `bytes_per_sector == 512` /
  `sectors_per_cluster != 0` pin (fat32.cpp), which the adopt path runs
  before any access. A foreign-volume mount that builds a `Volume`
  without that screen would expose `ReadFatEntry` (`byte_off /
  bytes_per_sector`) and the `offset / cluster_bytes` write-path math to
  a divide-by-zero panic (2026-06-17 audit SEC-001/007). When this slice
  lands, extract a single `ValidateGeometry(const Volume&)` —
  power-of-two `bytes_per_sector ≥ 512` with `bytes_per_sector *
  sectors_per_cluster ≤ sizeof(g_scratch)`, `sectors_per_cluster` a
  nonzero power of two, `num_fats ≥ 1`, `fat_size_sectors ≥ 1`,
  `root_cluster ≥ 2`, `total_sectors ≥ data_start_sector` — and call it
  from EVERY `Volume`-building path, not just adopt. (Widening
  `bytes_per_sector` past 512 also requires bumping `g_scratch` and the
  `sizeof(g_scratch)/512` guards in lockstep.)
- **Owner:** `kernel/fs/fat32.cpp`, `kernel/fs/mount.cpp`.

### Crash-dump persistence — real-hardware verification

- **Residual:** an unforced panic on an installed laptop is the
  last step to graduate this from "shipped" to "lived through it
  once." The encode + transport layers (QEMU debugcon + in-RAM
  minidump + NVMe/AHCI reserved-region + installer
  `kDuetCrashDumpTypeGuid` partition) are all in tree.
- **Safety invariant (landed):** the disk-persist path writes ONLY
  into a DuetOS-owned `kDuetCrashDumpTypeGuid` partition, discovered
  via `GptFindCrashDumpRegion` and bounds-checked by
  `GptCrashDumpRegionSane`. There is **no** "tail of namespace"
  fallback — on a disk DuetOS didn't partition (a real machine's SSD
  with Windows/Linux installed) a crash dump is NOT written to disk
  (the serial/debugcon copy still emits). `DiskPersistSelfTest` SKIPs
  (rather than writing) when no owned reservation exists, so the
  real-HW verification above requires booting the **installer** first
  to lay the crash-dump partition; until then disk persistence is
  intentionally inert.

---

## Drivers

### Audio — real-hardware audible + per-producer cursors

- **Residual:** (1) real-hardware audible validation (no HW in
  CI — the QEMU smoke proves the routed-codec DMA path:
  `[audio-selftest] DMA LPIB advanced (routed, audible path)`);
  (2) per-producer write cursors — today producers all choose
  their own `frame_offset` and the additive `WritePcmS16Stereo`
  path composes (saturating-add) when two writes hit the same
  offset, but staggered-offset multi-stream needs a per-producer
  cursor table anchored ahead of LPIB. (Saturating-add mixer +
  explicit `WritePcmS16StereoOverwrite` for fill-the-buffer
  producers landed.)
- **Owner:** `kernel/drivers/audio/`,
  `kernel/subsystems/audio/`.

### Wireless — real-hardware verification

- **Residual / blocks on:** real-hardware verification cycles;
  firmware-package signing root / key IDs; per-vendor MSI/MSI-X
  IRQ wiring; iwlwifi TFD descriptor build / doorbell / per-RBD
  data buffers; installer integration for the offline Wi-Fi
  firmware kit (`tools/firmware/prepare-wifi-firmware.py` output
  staged from install media before the network picker opens).
  The AR9271/AR7010 `ath9k_htc` open-firmware scaffold is in tree
  (`kernel/drivers/net/ath9k_htc{,_fw,_upload}.{h,cpp}`) but
  needs a physical dongle — open firmware exists for no on-board
  commodity Wi-Fi chip. (Data-decode + control tier + crypto +
  4-way handshake + per-vendor upload + ring scaffolds + regdb
  US/EU/JP + 802.11d Country-IE intersector all landed; 17
  self-tests pass.)
- **Unlocks:** Network flyout SSID picker, Settings → Network →
  Wi-Fi tab, captive-portal handler.
- **Owner:** `kernel/drivers/net/wireless/`, `kernel/net/wireless/`.

### iwlwifi — live-silicon TX / RX

- **Residual:** PCIe MSI-X negotiation (IVAR LUT writes at
  `CSR_MSIX_IVAR_AD_REG = 0x2890`, route every cause to vec 0 for
  single-vector start); per-TFD `iwl_pcie_txq_build_tfd` (legacy
  format: 20 TBs, `__le16 hi_n_len` packed, `HBUS_TARG_WRPTR =
  0x460` doorbell); RX queue init via `FH_RSCSR_*` (`0xBC0`,
  `0xBC4`, `0xBC8` — note write-ptr must be multiple of 8);
  `iwl_rx_packet` cmd dispatch on `REPLY_RX_MPDU_CMD` →
  wdev::OnDataRx. ALIVE handler in MSI-X "other" vector.
- **Reference:** `drivers/net/wireless/intel/iwlwifi/pcie/{tx,rx,trans}.c`
  in Linux. Start with legacy gen1 (7000/8000/9000) — gen2's BC
  table + dynamic scheduler is a separate slice.
- **Owner:** `kernel/drivers/net/iwlwifi_rings.cpp` (598 lines),
  `kernel/drivers/net/iwlwifi.cpp`.

### ath9k_htc — HTC service negotiation

- **Residual:** post-firmware-upload HTC state machine. Wait for
  `HTC_MSG_READY_ID` on `USB_REG_IN_PIPE`, send
  `HTC_MSG_CONFIG_PIPE_ID`, then `HTC_MSG_CONNECT_SERVICE_ID` for
  `WMI_CONTROL_SVC` / `WMI_BEACON_SVC` / `WMI_MGMT_SVC`. Surface
  `WmiSend(cmd_id, buf)` to wdev. `WMI_INIT_CMDID` →
  `WMI_SET_CHANNEL_CMDID` → `WMI_START_RECV_CMDID` lights up the
  scan path.
- **Reference:** `drivers/net/wireless/ath/ath9k/{htc_hst,hif_usb}.c`.
- **Owner:** `kernel/drivers/net/ath9k_htc.cpp` (301 lines).

### USB mouse — high-DPI real-hardware verification

- **Residual:** plug in a high-DPI USB mouse and verify the
  device-supplied HID Report descriptor produces the expected
  12/16-bit X/Y layout, button mask, wheel, and AC-Pan fields on
  real interrupt-IN reports. (Descriptor-driven decoding +
  injector + synthetic self-tests landed.)
- **Owner:** `kernel/drivers/usb/`.

### Intel iGPU command submission (GGTT batch + 2D BLT)

- **Today:** the RCS ring at MMIO 0x2000 is programmed and the boot
  self-test verifies `MI_STORE_DWORD_IMM` read-back. Everything
  graphics-accelerated still falls back to a software rasterizer.
- **Plan (research landed 2026-05-29 — see
  [`GPU-Implementation-Notes` §Intel](GPU-Implementation-Notes.md)):**
  five slices, in order —
  1. **Forcewake + GT-init** — hold RENDER+GT domains (Gen9 set/ack
     `0xA278`/`0x0D84` + `0xA188`/`0x130044`) with the Gen9–11
     fallback-ack erratum, RC6 off, un-stop the ring via
     `RING_MI_MODE`.
  2. **GGTT manager** — encode 64-bit PTEs (`phys | present`, LM=0),
     write through the BAR0 GTTMMADR upper-half alias, scratch-fill
     all slots, allocate GPU-VA above the GMADR aperture.
  3. **Batch submission + breadcrumb** — `MI_BATCH_BUFFER_START`
     (full 48-bit lo/hi addr) from a GGTT batch, `wmb` before the
     `RING_TAIL` doorbell, PIPE_CONTROL post-sync seqno + poll.
  4. **2D BLT → GDI accel (the T4-03 win)** — `XY_COLOR_BLT`
     (ROP `0xF0` fill) + `XY_SRC_COPY_BLT` (ROP `0xCC` copy) on the
     BCS ring; wire GDI `FillRect`/`BitBlt` to it.
  5. **Display detect/modeset** (independent) — GMBUS EDID read +
     `SDEISR`/`GEN11_DE_HPD_ISR` connector detect + primary-plane
     reprogram (keep firmware timings; defer PLL math).
- **Verification ceiling:** QEMU has no Intel-iGPU model, so the
  encoders (PTE / MI_* / BLT command builders) are pinned by boot
  self-tests asserting exact DWORDs (run + PASS under QEMU), but the
  MMIO submission paths are gated and **unverified on silicon** — they
  need a Gen9 NUC (Skylake/Kaby-Lake, no Optimus) + serial UART. The
  non-destructive proof ladder is in the notes page.
- **Blocks:** GPU-accelerated GDI paint (Track 4 → T4-03), DirectX
  real-device backends, multi-monitor mode-set.
- **Owner:** `kernel/drivers/gpu/intel_gpu.{h,cpp}` + a new GGTT/BLT unit.

### Brightness — per-vendor register backlight

- **Residual:** per-vendor *register* backlight (Intel/AMD PWM,
  vendor WMI / Fn-key hotkeys) for laptops that do brightness
  outside ACPI `_BCM`; wire the UI brightness control + Fn-key
  events to `AcpiBacklightSet`. (ACPI `_BCL`/`_BQC`/`_BCM` path +
  EC driver landed.)

### Source-tree GAP markers

Live edge-case index — the v0 happy path skips these:

- `kernel/drivers/net/iwlwifi_rings.cpp` — legacy <7000-series
  RBD format; real MSI-X interrupt-driven dispatch (TX-completion
  polling + periodic-poll wiring landed).
- `kernel/mm/dma.cpp` — ARM64 port (`dsb ishst` + per-line
  `dc cvac`).
- `kernel/subsystems/translation/translate.cpp` — `rseq`
  (restartable sequences).

Re-derive the full inventory with `git grep -nE "// (STUB|GAP):"`.

---

## Hardware safety

> The governing contract — *default to inert; mutate persistent /
> physical hardware state only on positive DuetOS ownership + explicit
> operator action* — lives in
> [`security/Hardware-Safety`](../security/Hardware-Safety.md). That page
> carries the full **pre-landing precondition table**: the safety gate
> each unimplemented risky controller (UEFI NVRAM, SPI flash, GPU
> VBIOS/fan/clock, NIC EEPROM, voltage/RAPL/thermal MSRs, Wi-Fi TX power,
> secure-erase, …) **must ship in the same slice** that implements it.
> The items below are the *active* safety work; everything else is the
> "don't build the writer without its gate" rule enforced at review.

### IOMMU — AMD-Vi enable + DMAR fault-IRQ handler (residual)

- **Landed 2026-06-06:** Intel VT-d is now **enforcing by default**
  (`DUETOS_IOMMU_ENABLE` defaults ON). It builds a full identity map
  (IOVA==phys, 0..512 GiB) + programs GCMD.TE when a DMAR is present;
  every existing driver's physical-address DMA keeps working while a
  rogue device is confined. No-ops without a DMAR; `iommu=off` cmdline
  escape hatch; verified under `DUETOS_IOMMU_DEVICE=1 tools/qemu/run.sh`
  (translation ENABLED, all device I/O works, 0 faults).
- **Residual:** (1) **AMD-Vi** is parse-only (IVRS) — register decode /
  paging / enable deferred until an AMD test machine exists. (2) **DMAR
  fault reporting landed 2026-06-06** (`VtdDecodeFault` + `LogAndClearFaults`
  read FSTS + the fault-record buffer after enable and log + clear any
  pending DMA fault; `VtdFaultPoll()` is wired into the `kheartbeat` loop
  (silent when clean — no per-beat spam — no-op when VT-d is off);
  `[vtd] no DMA faults pending` verified). Residual: wire FECTL + a fault
  MSI so faults raise an *interrupt* instead of a once-per-beat poll. (3) Interrupt remapping
  (intremap) is decoded but not programmed. (4) Per-device domains (real
  isolation vs the shared identity map) are a later slice.
- **Precondition for every new bus-master driver:** map only
  driver-owned buffers into device address space; validate descriptor
  targets. (Hardware-Safety pre-landing row "DMA without IOMMU".)

### Storage surprise-removal — re-attach recovery (residual)

- **Landed 2026-06-06:** runtime surprise-removal *detection* for both
  block drivers. A SATA/NVMe device unplugged or hard-link-dropped while
  running is detected via the all-ones MMIO-decode sentinel (`kMmioGone`),
  SATA `PxSSTS.DET` loss, or NVMe `CSTS.CFS`, and latched offline so I/O
  fails fast instead of spinning the full per-command timeout against
  absent hardware. The hot poll loops (`IssueSlot0`, `SubmitAndWait`) bail
  in microseconds; idle devices are swept by `AhciHealthPoll` /
  `NvmeHealthPoll` from the `kheartbeat` beat (next to `VtdFaultPoll`);
  each loss leaves a `KLOG_WARN` + `kStorageDeviceGone` probe +
  `StorageError` ereport. Predicate self-tests (`[ahci/nvme-selftest] PASS
  (surprise-removal predicate)`) run unconditionally. Full rationale:
  [`security/Hardware-Safety` → Runtime hardware faults](../security/Hardware-Safety.md#runtime-hardware-faults--device-disappears-or-misbehaves-at-runtime).
- **Residual:** (1) **Re-attach** — bringing a re-plugged drive back
  online (re-enumerate, COMRESET / NVMe CC.EN reset, re-IDENTIFY,
  re-register with the block layer) is unimplemented; a latched-offline
  device stays offline until reboot. (2) **Block-layer unregister** — a
  vanished device's `BlockDeviceRegister` handle leaks (no
  `BlockDeviceUnregister` yet), so the name slot isn't reclaimed. (3) A
  **PCIe hot-plug IRQ** (Downstream Port Containment / PME) would replace
  the once-per-beat poll, same way the VT-d fault MSI replaces
  `VtdFaultPoll`. (4) **xHCI/USB + NIC** surprise-removal detection is not
  yet wired — the same all-ones sentinel pattern applies and is the
  natural next slice.

### Ownership write-chokepoint — populate the registry + flip to Deny

- **Landed 2026-06-06:** the mechanism. `DiskRegionIsOwned(handle, lba,
  count)` + an owned-region registry (`BlockOwnedRegionAdd`) + an
  owned-write enforcement mode (`BlockOwnedWriteSetMode`
  Off/Advisory/Deny) live at the `BlockDeviceWrite` boundary: under Deny a
  write not fully contained in a registered owned region is refused. The
  single property that supersedes the per-call-site ownership checks.
  `BlockOwnedRegionSelfTest` proves containment / straddle / wrong-handle
  / wildcard + a RAM-disk allowed/denied write pair. **Default mode is
  Off** — no behaviour change yet.
- **Registration pass landed 2026-06-06 (boot writers):** RAM scratch
  devices auto-own on create; the FAT32 system volume's partition
  registers at `Fat32Probe` adoption. `BlockOwnedRegionAdd` resolves a
  partition handle down to its parent disk + LBA offset and owns the
  region in BOTH terms (the chokepoint runs at the FS-facing handle AND
  again when `PartitionBlockWrite` re-enters on the parent). An
  `ownedwrite=advisory|deny` cmdline opt-in drives enforcement. **Verified
  at boot: zero writes fall outside an owned region under both Advisory
  and Deny** — the registry fully covers the boot write set, so Deny does
  not break the boot.
- **Residual:** (1) register the remaining writers before flipping the
  default — the disk installer's target (declared before it formats a
  not-yet-owned disk), disk-backed DuetFS volumes, and the crash-dump
  partition (panic-only). (2) Runtime soak under Advisory (boot is clean;
  confirm steady-state app/FS writes are too) → then flip the default to
  Advisory and finally Deny. The mechanism is proven enforceable; the
  flip waits on installer/DuetFS registration + the runtime soak.

### DuetFS superblock owner GUID (probe hardening)

- **Residual:** `ProbeBlockHandle` mounts a DuetFS volume on a bare
  superblock-magic match with no DuetOS-owner GUID. Real-world risk is
  very low (a foreign disk would need valid DuetFS magic at the exact
  offset), but it's inconsistent with the FAT32/exFAT ownership gates.
- **What's needed:** add a DuetOS-owner GUID/UUID to the DuetFS
  superblock (Rust crate) and verify it in `ProbeBlockHandle` before
  mounting. Optional / low priority.

### Wi-Fi regulatory + TX-power clamp (before live TX lands)

- **Residual:** the wireless stack has no TX-power programming yet (safe
  by absence). When live silicon TX lands (see *Drivers → iwlwifi /
  ath9k_htc*), TX power must be clamped to the lesser of the regulatory
  limit and the EEPROM-calibrated max, defaulting to the most-restrictive
  ("world") domain until a country is set — exceeding limits overheats
  the PA/PHY and is illegal. See
  [`drivers/Wireless-Regulatory`](../drivers/Wireless-Regulatory.md) and
  the Hardware-Safety "Wi-Fi TX power" row. **Precondition, not a
  standalone slice** — it ships with the TX path.

---

## Win32 / NT subsystem

### Security follow-ups from the 2026-06-17 adversarial audit

The 2026-06-17 sweep of code merged since the 2026-06-06 audit fixed the
guest-reachable kernel-memory-corruption + cross-process findings (VK
SPIR-V id bounds + call-depth cap; Win32 job `owner_pid` + spinlock +
retain-before-kill; `vmap` shift `static_assert`; TCP `rtx_count`
underflow guard — all in the same slice). These lower-severity residuals
were filed rather than rushed, each because the right fix is a design
choice, not a one-liner:

- **`SYS_SECTION_CREATE` resource-exhaustion DoS (Medium).** Ungated, so
  a zero-cap PE can `CreateFileMapping` eight 4-MiB sections and exhaust
  the global pool + 32 MiB of frames. Do **not** gate on
  `kCapSpawnThread` (semantically wrong — mapping memory ≠ spawning
  threads, and it would deny a legit capless PE its file mappings).
  Correct fix: a **per-process section budget** (sections already carry
  a per-process handle table, so the owner is known) capping how many
  pool slots / bytes one process can hold. Owner: `win32/section.cpp`.
- **Cross-process `PostMessage` (`DoWinPostMsg`) (High-ish / design).**
  Uses the raw `HwndToCompositorHandle` (no owner check), so any PE can
  post `WM_QUIT`/`WM_CLOSE` to another process's window (DoS) with no
  cap. Real Win32 *does* allow cross-process posts; the right model is
  UIPI-style (restrict by integrity/owner for the dangerous system
  messages while allowing benign ones), not a blanket cap gate that
  would break shell↔app messaging. Needs the integrity-level surface to
  exist first. Owner: `win32/window_syscall.cpp`.
- **Win32 pipe pool calls `linux::internal::Pipe*` directly (Rule 5).**
  `named_pipe_syscall.cpp` / `pipe_syscall.cpp` reach into the Linux
  subsystem's pipe pool — a subsystem-to-subsystem coupling that shares
  resource accounting across ABIs. Fix: extract the pool into a
  kernel-owned `kernel/ipc/pipe_pool.{h,cpp}` both subsystems call. A
  refactor, not a patch. Owner: `kernel/ipc/`, both pipe syscall TUs.
- **TCP ECN reactions not gated on segment acceptability (Low).**
  `EcnOnEce` (`cwnd/2`) and `peer_ce_pending` (ECE-echo obligation) fire
  in `tcp_segment.cpp` *before* the in-window/ACK acceptability check, so
  a single spoofed ECE/CE segment in the 4-tuple can repeatedly collapse
  throughput. Move the ECN block below the §3.9 acceptability gate.
  Throughput-DoS only (no memory safety); touches input-processing order
  so it wants its own careful slice. Owner: `kernel/net/tcp_segment.cpp`.

### DirectX real device backends

- **Still gated:** HLSL bytecode execution (the `d3dcompiler.dll`
  frontend emits a DXBC-shaped blob the draw path ignores; a
  DXBC->SPIR-V transpiler would feed the now-live in-kernel
  SPIR-V interpreter — see [Vulkan ICD](../subsystems/Vulkan-ICD.md)),
  texture sampling, geometry/hull/domain/compute shaders,
  multi-stream input, Z-buffer, D3D9 fixed-function lighting,
  real GPU command-ring submission.
- **Blocks on:** per-vendor GPU drivers landing real
  command-ring submission; DXBC→SPIR-V transpile for app HLSL.
  (The **D3D11→Vulkan thunk v0 landed 2026-06-10**:
  HARDWARE/UNKNOWN/REFERENCE swap chains use a kernel `VkImage`
  back buffer; Clear/Draw record real VkOps via `SYS_VK_CALL`
  and replay through the kernel ICD's rasterizer into the image
  backing — `dx_raster.h` no longer runs on that path; boot gate
  `[vk-selftest] PASS (image-backed clear+draw)`. Remaining on
  the thunk: bind a SPIR-V passthrough pipeline so draws run the
  in-kernel interpreter (needs the paint-target refactor in
  `graphics_vk_shaderraster.cpp`); D3D12 reuses `dx_vk.h` as a
  follow-on. D3D9/11/12 COM vtables + shared software rasterizer
  + DXGI swap-chain present into compositor windows landed; the
  software back end remains for WARP/SOFTWARE + fallback.)

### Windowing — modal dialogs, common controls

- **Residual:** common controls, multi-threaded message queues.
  Menu GAPs: `TPM_LEFTBUTTON`/`TPM_RIGHTBUTTON` activation
  filtering, menubars + `LoadMenu` resource loading. See
  [`Compositor`](../subsystems/Compositor.md) §"Popup Menus" for
  live state. (Message pump, GDI paint, popup menus +
  `WM_CONTEXTMENU` + `TPM_*` flags, modal dialog primitive,
  native scroll bars with drag-the-thumb + click-on-track,
  interactive Move/Size via `modal_input.{h,cpp}`, Files-app
  rename UI, Trash + ramfs Files per-row context menus landed.)

### TCP AccECN (RFC 9768)

- **Lands:** 4 ECN counters per direction for L4S / DOCSIS
  prioritisation, on top of the now-complete classic ECN plumbing.
- **State:** classic RFC 3168 ECN is done — SYN-time negotiation
  plus the data plane (ECT(0) marking on outbound data, inbound
  CE → ECE echo, inbound ECE → cwnd halve + CWR) landed
  2026-06-12, alongside the RFC 6675 sender-side SACK scoreboard
  (`kernel/net/tcp_sack.{h,cpp}`).
- **Owner:** `kernel/net/stack.cpp`, `kernel/net/tcp_segment.cpp`.

### TCP BBR congestion control

- **Deferred indefinitely.** CUBIC (RFC 9438) is the default CA
  (integer-only `kernel/net/tcp_cubic.cpp`, `max(cubic, reno)` floor,
  `Tcb.cubic.enabled` kill switch). BBR needs a pacer + delivery-rate
  estimator + 4-state machine (~2000 LoC) on top — no workload justifies
  it yet.

### Open-firmware adoption (per Wireless / GPU)

- See [Open Firmware Landscape 2026](../drivers/Open-Firmware-Landscape-2026.md)
  for the full decision matrix. Concrete next slices:
  - **Wire ath9k_htc HTC service negotiation against
    `qca/open-ath9k-htc-firmware` builds** — first physical-
    hardware Wi-Fi target with zero closed firmware.
  - **`.duetfw` package signing root** — Ed25519 offline HSM
    project root + yearly intermediate; signer-key-ID format as
    SHA-256 truncated to 16 B (Sigstore convention).
  - **Quarterly firmware-landscape refresh** — rotate
    `Open-Firmware-Landscape-2026.md` every quarter; key items
    to recheck: Nexmon supported chips, openwifi releases, any
    Realtek open-firmware emergence (currently zero).

---

## End-user features

### .NET / CLR hosting — deferred, owner-acknowledged (2026-07-29)

Running managed (.NET) executables is **explicitly deferred**, not forgotten.
The project owner marked it "todo later" on 2026-07-29 while prioritising the
native download-and-run path.

Why it is a different class of work from the rest of the Win32 backlog: a
managed PE's entry point is a stub that hands control to a runtime. Supporting
it is not a DLL surface to fill in but a **runtime to host** — metadata and IL
parsing, a JIT or interpreter, a garbage collector, and the CLR's own threading
and exception models layered on top of the SEH work already landed. Every other
open Win32 item (COM, SxS manifests, console, fibers, D3D9, DirectWrite) is
bounded by "implement these functions"; this one is bounded by "implement
another language runtime", and is a multi-session project of its own.

Nothing else in the backlog depends on it, so deferring costs no ordering.
A managed binary today should fail with a clear diagnostic naming the CLR
header rather than a confusing loader error -- worth checking that it does.


### DECISION: should `theme=duet` become the boot default?

The Aurora redesign is implemented across the `Duet*` theme family
(`duet`, `duetlight`, `duetblue`, `duetviolet`, `duetgreen`,
`duetclassic`) but is **not the boot default**. `kernel/core/boot_bringup.cpp`
selects a theme from the kernel cmdline (`theme=classic|slate10|amber|duet`)
and otherwise leaves the Classic teal palette the first GUI slice shipped.
Aurora is reachable at runtime via Ctrl+Alt+Y or Settings.

Consequence, and why this is filed rather than fixed: a default-configuration
screenshot shows **Classic**, so any "does the implementation match the
design?" comparison run without `theme=duet` is not merely inconclusive, it
is misleading — it compares the new design against a different theme
entirely. At least one such comparison was made during the 2026-07-28/29
session before this was noticed.

**Open question for the project owner:** the redesign was commissioned as
*the* look, which argues for making `duet` the default. Against: the change
touches every default-configuration screenshot in the wiki, and any test
that asserts on chrome geometry or colour would need re-baselining. Until
this is decided, visual-fidelity work must be verified with
`DUETOS_EXTRA_CMDLINE="theme=duet"`.



### Aurora desktop-shell residuals (updated 2026-07-30)

The four fidelity deltas from the first valid `theme=duet` comparison have
landed -- desktop icon set, taskbar search pill + pinned app row, the
clock/date gadget, and the wallpaper glow geometry. See
`wiki/subsystems/Compositor.md` for what shipped.

Closed on 2026-07-30: the scheduler owns a 1 Hz sample ring shared by
the desktop gadget column and the taskbar stats pill. The gadget column
now paints the kernel stats and ABI-peers panels beneath the clock, the
kernel panel includes the FPS figure, and the taskbar pill includes the
README §10 CPU sparkline. The compositor reads the ring without taking
`g_sched_lock`.

What is still open:

1. **START paints a solid accent tile, not the design's sheer mark.** The
   reference's START is a dark cell carrying only the teal/amber arcs; the
   implementation fills the whole 44-px cell with `taskbar_accent`, which
   makes it the loudest object on the island. Surfaced while landing the
   search pill next to it; not fixed because it is a separate cell with its
   own hover/open states.
2. **The pinned row is five buttons, not the design's nine.** Deliberate --
   see Design-Decisions "Pinned taskbar launchers are scaled by island
   budget, not transcribed from the 1920 canvas".


### Run a real 32-bit application — PE32 game executable (failure ladder)

The standing target for the "run real Windows apps" pillar is a
representative **32-bit PE32** (`pei-i386`) GUI game, ~4.8 MB on disk /
9.4 MB image, Windows-GUI subsystem, importing KERNEL32, USER32, GDI32,
ADVAPI32, COMCTL32, SHELL32, IMM32, WININET, WSOCK32, WINMM, **OPENGL32**
(this build renders via OpenGL, not D3D), plus bundled third-party
DLLs (`fmod.dll` audio, an image codec, a video codec). Its data lives
in large bundled archive files (multi-GB).

**Landed (2026-06-17):** large-exe support (dynamic peexec read buffer +
heap-backed loader unwind guard — see Design-Decisions); the exe reads,
maps all sections, resolves imports, spawns, and **executes in 32-bit
ring 3** (`mode=pe32`). The **`[win32-32miss]` instrumentation**
(`SYS_EXIT` handler logs the caller's return address on the
unresolved-import sentinel `0xDEAD0042`) turns each fatal import into a
named RVA. The static-MSVC-CRT startup cluster is now covered in
`kernel32_32` (OutputDebugStringA, GetVersionExA, Tls\*, locale/codepage,
HeapCreate/Destroy, GetEnvironmentVariableA, GetModuleFileNameA,
VirtualQuery, FlushInstructionCache) and a **`GetModuleHandleA`
wrong-syscall bug** (was calling SYS_WIN_SET_CURSOR) was fixed. The exe
now **clears CRT startup entirely and runs into its own application
code** without faulting. **Milestone: a 32-bit game exe runs on DuetOS.**

The remaining rungs, in order (each the proven attempt→trace-exact-
fault→fix→re-run loop, `tools/test/run-exe.sh` + `peexec=`, using the
`[win32-32miss] ret=` line → `i686-w64-mingw32-objdump -d
--start-address` to name the import):

1. **Post-CRT application init.** The exe clears CRT startup and reaches
   its own code; the climb from there is import coverage plus the
   surfaces those imports need to be real. This is the long middle.

   **Landed (2026-07-28): the USER32 rung.** The quiet loop was
   `user32_32` lying — every export in `userland/libs/user32_32/` and
   `userland/libs/gdi32_32/` returned a constant and neither file
   issued a single syscall. Both are real surfaces now, on the same
   ~40 `SYS_WIN_*` / `SYS_GDI_*` handlers (58..100, 65-68/74-76) the
   64-bit siblings use: class registration storing a live WNDPROC,
   window create/destroy/show/move, the full pump (Get / Peek / Post /
   Dispatch / Send / PostQuitMessage), per-window long slots,
   invalidate + BeginPaint/EndPaint, rects and metrics from the
   compositor, focus/activation, key state, cursor, capture, timers,
   clipboard, and the fill / rect / ellipse / line / text / pixel
   primitives. `user32_32` split into `user32_32.c` + `user32_32_misc.c`;
   the shared i386 syscall trampolines and the HDC / brush / pen
   encodings moved to `userland/libs/common/`. See Win32-Surface-Status
   §11b for the full inventory and the three i386-specific traps
   (28-byte MSG, divergent WNDCLASSEX offsets, USER32-homed FillRect).

   Proved live, not by compile: `userland/apps/pe32_window/` registers
   a class, creates a window, and drives post → peek → dispatch →
   WndProc → paint → quit, asserting 22 conditions including a canary
   immediately after its 28-byte MSG. It is an `Always` row in the
   PE-compat battery (`ring3-pe32-window`), so every ring3 boot
   exercises it.

   **Still open on this rung:** `msvcrt_32` stdio (`fopen`/`fread`) has
   not been rebased onto the new file-I/O surface. The remaining
   `gdi32_32` bitmap / blit / DIB STUBs are now unblocked but not yet
   written: the 64-bit `gdi32` gained real off-screen surfaces on
   2026-07-29 and the syscalls it uses (`SYS_GDI_SET_DIBITS` /
   `_GET_DIBITS`) are register-argument only, so the i386 port can reach
   them through `duet_syscall6` with no struct shape to mirror.
   ~~Icon and cursor resources~~ **LANDED 2026-07-29:**
   `SYS_GDI_CREATE_CURSOR_RGBA` (216) takes RGBA image bits + hotspot;
   `duet_res_pick_icon` / `duet_res_decode_icon` in `pe_resources.h`
   walk `RT_GROUP_ICON` -> `RT_ICON`, decode BIH + bottom-up DIB + AND-mask
   -> BGRA; `LoadIconA/W`, `LoadCursorA/W`, `LoadImageA/W` are REAL on
   both bitnesses; `icon_smoke` PE fixture in the ring3 battery.

2. **Large bundled-data staging + FAT large volume.** The exe reads
   multi-GB archive files. Staging needs a much larger disk image than
   the 16 MiB `make-gpt-image.py` default, exercising the FAT32
   large-volume + write paths. NOTE: the run-exe.sh staging-image boot
   currently trips the screenshot / trash / fix-journal-persist
   disk-write self-tests and a wild-LBA FAT read (the known transient
   emulated-block flake) — triage those here, where the FAT image work
   is.
3. **OpenGL.** `OPENGL32` is a NO-OP stub; the renderer needs a real
   GL implementation (GL 1.x fixed-function → the in-kernel Vulkan ICD,
   or a software GL). The big rendering-subsystem expansion.
4. **WSOCK32 / WININET** (realm/login networking) and **FMOD** audio —
   later rungs once it renders.

### Runtime LoadLibrary sees only a hand-picked subset of the shipped DLLs

`spawn.cpp`'s preload set is the authoritative list of ~44 DLLs the
kernel embeds, but the **runtime** `SYS_DLL_LOAD_FROM_PATH` path resolves
against ramfs `/lib/`, which `kernel/fs/ramfs.cpp` populates with a
hand-written `constinit` node per DLL - `customdll`, `customdll2` and
(2026-07-28) `vulkan-1`. Every other embedded DLL is unreachable by name
at runtime, even though its bytes are already linked into the image and
the node costs nothing (the node borrows the blob pointer).

This bit for real: stock `vulkaninfo.exe` `LoadLibrary`s `vulkan-1.dll`
rather than importing it, missed, and died with an unhandled C++
exception on a kernel whose Vulkan ICD was online and self-tested. It
was only reachable at all because `vulkan-1` is marked non-essential and
the `arch::IsEmulator()` preload trim skips it - so the preload fast path
did not paper over the gap.

Adding one node per observed miss is the whitelist-incompleteness bug
class: the next app to `LoadLibrary` a shipped DLL by name hits the same
wall. The fix is to derive the `/lib` node set from the SAME list
`spawn.cpp` uses, so a DLL cannot be preloadable-but-not-loadable. Doing
that needs the preload table hoisted out of its enclosing function to
file scope (it is a function-local `static const` today) and exposed
through `proc/spawn.h`; that refactor is the whole item.

**Amendment (2026-07-29, side-by-side DLL slice).** Two corrections to
the diagnosis above, from reading the live path rather than the `/lib`
node list:

1. The exposure is narrower than "every other embedded DLL is
   unreachable". `SYS_DLL_LOAD_FROM_PATH` consults
   `ProcessFindDllBaseByName` FIRST, and `SpawnPeFile` registers every
   preloaded DLL into `proc->dll_images[]` — so for an import-bearing PE
   a runtime `LoadLibrary("user32.dll")` already hits the process image
   table and never reaches `/lib`. The real hole is exactly the case the
   `vulkaninfo` story describes: a DLL that the `arch::IsEmulator()`
   preload trim skipped (`essential = false`) was never registered, so
   there was nothing in the table to find. Deriving `/lib` from the
   preload list still fixes it; so would not trimming.
2. There is now a third answer for the same shape: a DLL shipped on the
   volume beside the `.exe` is reachable at runtime via the same
   syscall, because `SYS_DLL_LOAD_FROM_PATH` falls through to the
   side-by-side resolver using `Process::sxs_dir`. That does not close
   this item — it covers app-supplied DLLs, not kernel-shipped ones —
   but it removes the "the app must ask us to embed it" pressure that
   made this item urgent.

### BattleBit's next blocker: the guard default-denies UnityPlayer.dll

**This item replaces an earlier one that named the api-set surface as
the blocker. That diagnosis was wrong, and the thing that made it wrong
is now fixed — see the correction below before acting on it.**

`BattleBit.exe` exits with status **0** and no fault. Grading a run of
it by "did anything crash" scores this as a success. It is not one.

What actually happens, read off a live boot
(`tools/test/run-exe.sh`, `DUETOS_IMAGE_MB=48`,
`DUETOS_STAGE_EXTRA=UNITYPLA.DLL=<path>`):

```
[guard] WARN kind=pe name="/UNITYPLA.DLL" findings=0x1
[guard]   - PE_SUSPICIOUS: 2+ injection-family APIs
[guard]  Allow [y] / Deny [n] — 10s default-deny. >
[guard] prompt timeout: default-deny
[sxs] security guard blocked path="/UNITYPLA.DLL"
[pe-resolve] unknown import -> catch-all NO-OP fn="UnityMain"
[win32-miss] fn="UnityMain" slot=0x140edb210 called-from=0x140ed11f2 in-module=0x140ed0000
[dll-load] api-set contract has no host (returning NULL, as Windows does) name="api-ms-win-appmodel-runtime-l1-1-2"
[sys] exit rc val=0x0
```

The chain is: the image guard flags a 26 MiB game engine for importing
two or more injection-family APIs (which every game engine does), opens
an **interactive** allow/deny prompt, and in an unattended boot nobody
answers, so it default-denies. `UnityPlayer.dll` therefore never loads,
`UnityMain` binds to the catch-all no-op, `BattleBit.exe`'s `main`
calls it, gets 0 back, and returns 0. `exit(0)` is the honest
consequence of a `main` that returned 0.

**The api-set line is a red herring.** It happens *after* the process
has already decided to exit: the MSVC UCRT's exit path probes
`api-ms-win-appmodel-runtime-l1-1-2` for
`AppPolicyGetProcessTerminationMethod`, and takes the NULL branch to
plain `ExitProcess`. Returning NULL there is the correct Windows answer
for a non-packaged app — it is what any Windows build predating the
contract does. Mapping that contract onto a host DLL that does not
export its functions would convert a correct refusal into a confusing
"function missing from a DLL that claims to exist". Do not do it. The
contract now says so in the log rather than reporting
`miss path=/lib/...`, which is what made it look like a missing file.

So the open work is the guard, not the loader:

- An unattended PE run cannot load **any** WARN-verdict side-by-side
  DLL, because the prompt always times out to deny. That is correct as
  a default and must stay the default.
- What is missing is a deliberate operator opt-in — a boot-time
  pre-authorisation for a named image, so an automated run can consent
  in advance instead of relying on a human at a serial console.
  Flipping the timeout default to allow is **not** an acceptable
  substitute; it would silently weaken the gate for every image.

Until that exists, a BattleBit run measures the guard's default, not
the loader's. Whoever picks this up should confirm with
`grep -n "sxs. security guard blocked" <log>` before drawing any
conclusion about import coverage.

### Win32 CreateThread stacks are still fixed-size

Demand growth covers the PE main thread only. `SYS_THREAD_CREATE`
carves `Process::kV0ThreadStackPages` off the thread-stack arena at
0x68000000 with no guard region between slots, so a worker thread that
recurses overflows into its neighbour's stack silently. The machinery
to fix it already exists (`core::UserStackPlan` / `UserStackClassify`
in `kernel/proc/user_stack.h`); what it needs is a per-thread
`UserStackRange` instead of the single per-process one, and an arena
that leaves guard gaps between slots.

### Win32 handle lifecycle — teardown + close-dispatch gaps (audited 2026-07-26)

A read-only audit of the PE loader and Win32 handle lifecycle found one
root shape with several symptoms: the handle **bands** are declared
across `kernel/proc/process.h` and the per-type pool modules, but the
two functions that must enumerate them all — `DoFileClose`
(`kernel/subsystems/win32/file_syscall.cpp`) and `ProcessRelease`
(`kernel/proc/process.cpp`) — each carry a hand-maintained list that has
drifted behind the set. Verified against the code, not inferred.

Ranked, with the security one first:

1. **(FIXED 2026-07-28)** Section handles are now released at process
   teardown - `ProcessRelease` walks the section pool (`process.cpp`
   ~758 / ~877). The sandbox-reachable pool-exhaustion path this
   described is closed.
2. **(FIXED 2026-07-29)** `DoFileClose` now has a `kJobHandleBase`
   arm that routes job-handle close to `SysJobClose`. Constants
   exported from `job_syscall.h`.
3. **Fixed 2026-07-27 — local thread handles (0x400 band) now have
   stable identity and lifecycle.** `DoFileClose` has the missing
   local-thread arm, and slot claim, identity/exit publication, wait
   polling, and close/reuse are serialized by the per-process
   `win32_thread_lock` instead of local-CPU `cli`. Local and foreign
   thread-handle rows record the scheduler's immutable, non-reused TID
   rather than retaining a raw, non-owning `Task*`; operations resolve
   that ID through the scheduler's locked task-lifetime boundary.
   Reaping can therefore never leave a dereferenceable stale task
   pointer in either public handle table. This also fixes the
   optimized SMP failure where
   `SYS_THREAD_WAIT` retained `STILL_ACTIVE` after a peer CPU had
   exited and been reaped. User tasks use a prepared pre-publication
   initializer: their TID and per-thread GS/TLS metadata are complete
   before the scheduler can run them, and closing the returned handle
   before the first timeslice no longer suppresses entry. An internal
   row generation prevents creator-cleanup ABA. A separate completion
   bit also makes an actual thread exit code of `STILL_ACTIVE` (259)
   waitable. The mixed-provider PE fixture covers
   close-before-first-run, runs twelve create/wait/exit-code/close
   cycles against the eight-slot table, and checks the 259-valued exit
   case.
   **Still queued:** `TerminateThread` cancellation is not yet a full
   asynchronous unwind contract. A target blocked on a wait queue
   remains kill-requested until its normal producer wakes it, and an
   in-flight asynchronous syscall has no general cancellation hook
   that unwinds its subsystem-owned reservations. Add cancellable
   wait/async-syscall cleanup before treating forced termination as
   immediate or resource-complete.
4. **(FIXED 2026-07-29)** `ProcessRelease` now calls
   `ProcessDropOwnedProcessHandles(p)` early in the teardown
   sequence, releasing any retained process handles before the AS
   goes away. Idempotent with the sched-reaper call.
5. **Mutex ownership is not force-released when the owning task dies.**
   Only the explicit-`CloseHandle`-while-holding path drops it, so a
   worker killed while holding a mutex leaves `m->owner` a dead `Task*`
   and any sibling thread blocks forever, with no `WAIT_ABANDONED`.
   **Larger refactor** — needs per-task held-lock bookkeeping or a
   task-death hook; the handle table stores type-erased `KObject*`.
6. **(FIXED 2026-07-29)** `SpawnPeFile` Win32HeapInit error path now
   calls `ProcessRelease(proc)` instead of `AddressSpaceRelease(as)`,
   matching the ownership transfer at `ProcessCreate`.

**(DONE 2026-07-29)** `tools/test/check-handle-bands.py` is the
property-test companion to the hand-fixes above: it greps every
declared `kWin32*Base` / `kJobHandleBase` constant and verifies each
appears in both `DoFileClose` and `ProcessRelease` (or is in a
documented exempt list). Currently 12/12 pass. Add future bands to
this check.

Not audited, out of that audit's fence and still open: whether
`mm::CopyFromUser`/`CopyToUser` validate a 32-bit process's range with
no 64-bit canonical-address assumption baked in.

The focused `thread3_smoke` regression now opens a live worker by TID
through `SYS_THREAD_OPEN`, exercises suspend/context/resume through the
foreign-handle row, then proves exit/reaping rejects the retained stale
handle and that closing it permits a clean numeric-slot reuse.

A local KVM-backed x86_64-debug validation run also exposed an older
socket IRQ-state livelock before any PE fixture launched: `SocketAlloc`
executed a raw `sti` inside the `int 0x80` trap, so the timer repeatedly
entered at nesting depth two and the debug defer log could starve the
instruction after `sti`.

**Landed 2026-07-27:** `kernel/net/socket.cpp` is off raw `Cli`/`Sti`
entirely — one file-local `sync::SpinLock` guards the pool and the
stats, and `SpinLockRelease` restores the caller's saved RFLAGS instead
of unconditionally re-enabling. That is the IRQ-save lock contract, and
it also closes the cross-CPU use-after-free on a released socket's UDP
RX ring.

**Landed 2026-07-31:** socket operations now take a transient lifetime pin
before sleeping or entering TCP/pipe code. Last-handle and owner teardown
mark the entry closing and defer resource release until pins drain; stream,
datagram, and poll paths snapshot mutable endpoint state under the pool lock.
Raw `SocketGet` access has been removed from syscall handlers. Runtime build,
boot, and concurrent socket validation remain outstanding for this slice.

**Still open:** make interrupt nesting distinguish hardware IRQ frames
from syscall/exception frames and rate-limit the defer diagnostic. Do
not weaken the nested-IRQ scheduling guard. Separately, the TCB table
(`kernel/net/tcp*.cpp`, 18 remaining `arch::Cli` sites), the ARP
cache, and the DHCP lease are still on the UP-only scheme; the socket
pool is the worked example to copy.

### Other Win32 thunk defects found 2026-07-26 (not yet fixed)

- **`vulkan_1.c` — 20 call sites pass their real argument in the wrong
  register.** All use the correct multiplexed `SYS_VK_CALL` (211), but
  the payload lands in `rsi` where `DoVkCall`
  (`kernel/syscall/syscall_vk.cpp`) reads `rdx`. Worst cases:
  `vkAllocateMemory` and `vkCreateBuffer` always request size 0;
  `vkCmdClearColorImage` always clears to 0; `vkCreateComputePipelines`
  loses the shader handle. `userland/libs/dx_vk.h` already carries a
  developer warning that these are "latently misaligned". Two stale
  `rsi = …` comments on `kVkOpGetStatsCounter` /
  `kVkOpClearFramebufferRgba` in `syscall.h` contradict the kernel
  implementation and are what misled the call sites. **Left alone
  deliberately: adjacent to the concurrent graphics work.**
- **Fixed 2026-07-26: `iphlpapi::GetAdaptersInfo` lease query.**
  `kSockOpGetLease` now passes `out` in `rsi` and capacity in `rdx`;
  the trampoline's third argument uses a named asm operand rather than
  the formerly wrong `%4`. The `iphlpapi_socket_abi` hosted CTest pins
  the userland call, trampoline mapping, and kernel consumption.
- These are the *right number, wrong register* shape, which
  `check-syscall-numbers.py` explicitly does not cover — it validates
  numbers, not argument slots. An argument-contract checker would need
  to parse the per-syscall register documentation out of `syscall.h`.

### Chrome tactility (Pass A) - residual

23 of 28 plan tasks landed (blend math, 9-slice soft shadow, 7 Theme
fields, per-theme intensity matrix). QEMU verification passed 2026-05-24;
`boot-log-analyze.sh` reports the TACTILITY line every boot.

**Residual: VBox boot verification only.** LAPIC / GS-base differences
from QEMU have caught real bugs before (see the `vbox-bringup-pr266`
notes). Everything else in this pass is landed and documented in
[`Compositor`](../subsystems/Compositor.md).

### Chrome tactility (Pass B) - residual

Landed and verified; `boot-log-analyze.sh` reports the PASS B line
(splash / wallpaper-motion / login-gui / umbrella) every boot.

**Residual: none known.** Retained only as a pointer - the subsystem
detail lives in [`Compositor`](../subsystems/Compositor.md).

### Chrome typography (Pass C) - residual

All 21 planned tasks landed, plus 5 settings sub-panel migrations.
`chrome-text-selftest` PASSes every boot.

**Residual: none known.** Proportional metrics for list CONTENT landed
2026-07-29 (`app_widgets/app_text.{h,cpp}` plus the Files / Task Manager
column-model refactor); `[app-text-selftest]` PASSes every boot.

### App widgets (Pass D) - residual

The widget library landed (`app_button`, `app_label`, `app_panel`,
`app_divider`, `app_list_row`, `app_toolbar`, `app_input`,
`app_scrollbar`) plus 28 per-app migrations. `[app-widgets-selftest]` and
`[pass-d-selftest] PASS (widgets=ok, apps=28/28)` fire every boot.
Aurora (2026-07-28) added `app_palette` on top, so interiors now theme
from one owner.

**Residuals:** the Task Manager Performance resource rail is wired and
boot-clean but has never been photographed - the demo-windows profile
opens Task Manager on the Processes tab and the headless QMP harness
could not drive a tab switch, so its per-core tiles are compile- and
boot-verified only. ABI pills, per-row dots and the Files quick-access
rail landed 2026-07-29. Files shows an ABI badge only where the image
bytes are already resident (ramfs); FAT32 rows deliberately show none
rather than inherit the launch path's extension guess. See
[`AppWidgets`](../subsystems/AppWidgets.md).

### RBAC + elevation broker — v1 follow-ups

- **v1 — Argon2id with lazy migration.** Blake2b primitive
  (RFC 7693) is in tree and passes the Appendix-A vectors;
  Argon2id (RFC 9106) sits on top. **Blocked on a record-format
  extension** — the 56-byte `PasswordHashRecord` can't carry
  Argon2id's memory/time/parallelism params; needs a V2 shape
  sized for both old PBKDF2 + new Argon2id rows. See
  [`RBAC-and-Elevation`](../security/RBAC-and-Elevation.md#argon2id-rollout).
- **v1 — Persistence.** `/system/secrets/` holds the account +
  role tables encrypted at rest; Argon2id-derived key wraps the
  table; TPM seals the wrap key when that driver lands. Until
  then `AuthInit` / `RbacInit` re-seed defaults every boot and
  runtime additions are lost.
- **v1 — First-boot installer flow.** Replace the hardcoded
  `admin / admin` seed with a userland install wizard launched
  by init when `/system/secrets/` is empty. Blocks on the
  persistence work above.
- **v1 — Secure Attention Key.** Reserve Ctrl+Alt+Del at the
  PS/2 driver level → kernel-drawn full-screen broker prompt, so
  a paranoid user can force a known-good prompt. The v0 modal is
  drawn under the compositor lock but doesn't pre-empt a focused
  full-screen surface. (v0 broker + role table + grace cache +
  CLI/GUI prompt + `NtAdjustPrivilegesToken` facade routing
  landed.)

### Device Manager — eject + hot-unplug + virtio per-class I/O

- **Residual:** `Eject` capability gating; a hot-unplug driver
  path (AHCI / xHCI don't support it yet); virtio per-class
  queue-setup + I/O (rng/blk/net probes are attach-only in v0 —
  see **VirtIO per-class polish** below). (PCI + USB + VirtIO
  read-only device tables landed.)

### Network Status — real RF scan + multi-iface lease

- **Residual:** a real wireless backend (per the Wireless row)
  so the SSID list reflects an actual RF scan rather than the
  empty placeholder; multi-iface DHCP lease tracking (single
  lease today). (Iface table, rx/tx counters, firewall-drop
  column, routing/DNS section, Wi-Fi-scan section UI landed.)

### Terminal emulator (windowed userland shell)

- **Today:** `Ctrl+Alt+T` opens the kernel shell (ring-0).
- **Blocks on:** console-multiplex refactor — the kernel shell
  is wired to a single global `ConsoleWrite`; a windowed
  terminal needs the shell to take a per-session sink.
- **Owner:** `userland/shell/` + a PTY layer.

### PNG / JPEG / PDF / video viewers

- **Today:** BMP works (`kernel/apps/imageview.cpp`).
- **Blocks on:** PNG needs a zlib port (none in tree); JPEG
  needs a Huffman+IDCT decoder; PDF is huge; video needs HDA.

### IME / non-Latin input

- PS/2 + xHCI HID drivers hardcode US layout. Blocks on an
  input-method framework refactor.

### Locale / language switching

- UI strings are C++ literals in `kernel/apps/*.cpp`. Blocks on
  a string-table layer with id → text indirection; refactor
  across all apps.

### Disk installer — real-hardware boot verification

- **Residual:** boot an installed disk on real UEFI hardware.
  The orchestration layer (`install <handle> INSTALL [--duetfs]`
  → GPT with ESP / system / crash-dump partitions, FAT32 or
  DuetFS system partition, GRUB stub, real `BOOTX64.EFI` stamped
  to the spec-mandated removable path, opt-in kernel-ELF embed
  via `DUETOS_INSTALLER_KERNEL_EMBED`) is all in tree and the
  layout math runs a boot self-test every boot.

### System updater

- **Blocks on:** code-signing infrastructure. (A/B kernel-slot
  layout — state machine, installer staging to the inactive slot,
  and the generated dual-menuentry GRUB cfg — landed 2026-06-12.)

### Accessibility — screen reader + on-screen keyboard

- **Residual:** screen reader (blocks on an AT-SPI-equivalent
  kernel surface); on-screen keyboard (blocks on a widget-slot
  bump). (Magnifier landed.)

---

## Rust subsystems

The Rust bring-up checklist is **closed out** — thirteen
production crates are live with C++ callers. Future Rust work
happens only through the two channels documented in
[`Rust-Subsystems`](../tooling/Rust-Subsystems.md): existing
crates growing to cover their successor surface, or a new
crate landing **with** its first real C++ caller. Not triggers:
"memory safety is cool" / "a library exists in Rust". The
crate-authoring rules also live in that page.

### DuetFS follow-ups

DuetFS v3 ships per-block CRCs, sym/hard links, fsck, on-disk
auto-mount, userland syscall surface, auto-symlink resolution,
and `mkfs.duetfs`. Image cap is 4 MiB (single-block CRC table).
Pending, in rough priority:

1. **Multi-block CRC table** — restore the 32/128 MiB image cap.
2. **CoW** — copy-on-write file-data writes on top of the existing
   journal (journal already lands per `journal.rs`).
3. **Separate dirent table** — decouple hard-link names from the
   inode's `name` (today's v3 caveat).
4. **Indirect extents** — files needing > 8 extents.
5. **Multi-block dirs + B-tree directory index** — bump the
   1024-child cap.

(AES-XTS + Argon2 KDF encryption tier in `crypto.rs`, LZ4
compression in `compress.rs`, and snapshots in `snapshot.rs`
all landed.)

---

## Imported backlog — remaining rows

The "Full Project TODO" import (2026-05-09) is closed except the
rows below; everything else landed and is recorded in
[`Design-Decisions`](Design-Decisions.md) /
[`Win32-Surface-Status`](Win32-Surface-Status.md). Syscall numbers
are ABI — do not reuse retired numbers.

| ID | Scope | Pri | Task | Acceptance |
| --- | --- | --- | --- | --- |
| T4-03 | gfx | P2 | Intel iGPU Gen9+/Xe driver basics: GTT setup, command ring, 2D blitter acceleration (PCI probe + register peek + software fallback landed). | BitBlt-heavy paths use the Intel blitter instead of software fills. |
| T5-03 | mm | P2 | Real KASLR in the UEFI loader (memory-map scan, random 2 MiB-aligned base in a 64 MiB window, boot-info handoff, boot-log report). **Same work as Linux-CVE Class II follow-up.** | Two cold boots show different kernel `.text` load addresses. |
| T6-05 | win32 | complete — 2026-07-26 | MSVC x64 C++ EH now captures the caller's complete aligned `CONTEXT`, validates bounded PE unwind metadata, restores GPR/XMM state, binds by-value and reference catches from the correct HandlerType metadata, and defers catch execution to `TARGET_UNWIND` so crossed-frame destructors run first. The `pe-runtime` QEMU profile passes scalar catch, class-reference catch, cross-frame destructor unwind, catch-all, TLS, SEH, and synchronization with 51/51 boot self-tests. Remaining extensions are non-trivial copy-ctor catch objects, FH4 compressed FuncInfo, ESTypeList, and rethrow (`throw;` — attempted 2026-07-28 and backed out: supplying the in-flight object is easy, but the re-raise's frame walk returns to the same function with `ControlPc` still inside the inner `try` and re-selects the catch it just left; needs the funclet-to-tryblock link threaded through the dispatch). | `cxxeh_pe` prints all four subtest PASS markers, `[cxxeh] RESULT PASS`, and exits 0. |
| T7-04 | fs | P2 | Scoped NTFS write: create, write, truncate, delete, rename with MFT/index/journal/bitmap updates; no compression/encryption/ADS for v0. | PEs can perform basic writes to NTFS volumes. |
| T8-01-followon | sched | P3 | **Bands landed 2026-06-10** (4 MLFQ bands from `win32_priority_class`, band-0-first pop, wake-preempt, escape valve — acceptance met: high-prio preempts low within one tick). **Residual:** behavioural *aging/decay* (demote a quantum-hog, promote a starved task) — v0 fixes band by priority class, not behaviour; the escape valve is the only anti-starvation mechanism. Lower priority now (the user-visible preemption works); revisit if a workload shows fixed bands mis-schedule. | A CPU-bound band-2 task that never yields is demoted below a freshly-ready band-2 interactive task. |
| T10-04 | build | P2 | Extend hosted `ctest` to mirror the PE-parser contract (Result / string / syscall_error / cvt / text_hash / d3dcompiler / damage_rect / wild_address / disk_path / vfs_resolve / registry_path already wired). PE parser is kernel-only — use the algorithmic-contract pattern (re-state the routine inline, assert canonical cases) as primitives grow self-contained. | Host `ctest` covers Result + PE parser + VFS + registry + string helpers without QEMU. |

---

## Tier-1/2 follow-ups (next-slice integration points)

The kernel-side primitive is in tree for each; what's missing is
the per-call wiring.

### VirtIO — per-class polish

- **Lands:** virtio-console multiport (`VIRTIO_CONSOLE_F_MULTIPORT` +
  control-queue protocol); virtio-balloon inflate/deflate policy
  (the "when do we agree to give up memory?" half — spec
  dispatch is straightforward); virtio-input statusq for LED /
  force-feedback delivery (eventq + EV_REL + EV_ABS already
  landed — virtio-tablet absolute coordinates are converted to
  `MousePacket` deltas at the driver boundary so the unified
  one-source-of-truth pointer API stays intact);
  IRQ wire-up across rng/net/console/balloon/input — virtio-blk
  landed MSI-X IRQ completion + 10 in-flight request slots
  (2026-06-10); the transport helper (`VirtioQueueMsixVectorSet`)
  and the BME enable are shared, so per-class wire-up is now the
  thin part. (Every per-class probe v0 + RX/TX poll tasks landed.)

---

## Testing / fuzzing

> **CI wiring landed.** `.github/workflows/build.yml` now has a
> `fuzz` job (sibling of `check-rust`/`build-debug`) that runs
> `FUZZ_SECONDS=90 tools/test/fuzz-all.sh` on every push/PR,
> uploading `crash-*` artifacts on failure. The optional cron
> long-run (`FUZZ_SECONDS=900` + persisted corpus cache) remains
> a future follow-up, not a blocker.

### Fuzz harness — next parser targets (residual)

Untrusted-input byte parsers still **without** a harness, in
rough bug-probability order (hand-written C++ bit/TLV parsers
first — that is where every memory-safety bug found so far
lived; the Rust-backed parsers held up). All follow the
established `tests/fuzz/` pattern (host harness + `host_shim/`
stubs + a `seeds/gen_*_seeds.py`); the codec/cert ones are pure
`bytes → struct` and need *less* shimming than the FS probes.

<!-- AML interpreter bullet retired 2026-06-06: fuzz_aml harness
     (tests/fuzz/fuzz_aml.cpp) + seeds/gen_aml_seeds.py landed, and
     the recursive TermList walker was then PORTED to the memory-safe
     no_std duetos_aml Rust crate (kernel/acpi/aml_rust/) — aml.cpp is
     now a thin FFI caller (namespace storage + accessors + the offset
     slicers AmlMethodBody/AmlNameValue/AmlReadS5). fuzz_aml drives the
     real integrated path and serves the fuzz input as the DSDT via
     self-defined AcpiMapTable/DsdtAddress accessors. Found + fixed a
     1-byte heap-OOB read in the original C++ ReadNameString — an
     under-length PkgLength underflowed pkg_end - name_off; the Rust
     port carries the guard at all four package sites. Verified
     byte-for-byte equivalent to the C++ walker on QEMU's DSDT (275
     entries / 81 methods / 42 devices / 15 scopes / 7 opregions, both
     builds) and fuzzes ≈ 50k execs/s clean (4.5M runs). The firmware
     ACPI *tables* (RSDP / header / MADT / FADT / MCFG / HPET / SRAT)
     got fuzz_acpi in the same series (driving the duetos_acpi Rust
     crate directly, ≈ 440k/s clean). Both auto-picked up by
     tools/test/fuzz-all.sh. -->
<!-- CDC-ECM + RNDIS bullet retired 2026-06-12: fuzz_cdcecm +
  fuzz_rndis harnesses (host_shim/usbnet_stubs.cpp +
  seeds/gen_{cdcecm,rndis}_seeds.py) landed and found + fixed a
  real u32-wrap heap-OOB write in the rndis.cpp rx deframer.
  Both run multi-million execs clean and are auto-picked up by
  tools/test/fuzz-all.sh. (The class-descriptor +
  HID-report-descriptor walkers under usb_class_desc.cpp +
  hid_descriptor.cpp were already fuzzed via the Rust-backed
  harnesses landed 2026-05-26.)
  Retired bullets — seeded + fuzzed 2026-05-26:
  X.509 (seeds/gen_x509_seeds.py — openssl-subprocess + embedded
  RSA-2048 reference cert + 128-byte truncation seed; fuzz_x509
  ≈ 244k runs/s + 551 new units added past the format gate);
  EDID + CEA-861 (seeds/gen_{edid,cea861}_seeds.py + host_shim/
  edid_stubs.cpp ConsoleWrite no-op stub; fuzz_edid ≈ 407k/s,
  fuzz_cea861 ≈ 511k/s); USB class-descriptor + HID report-
  descriptor (fuzz_usbclass + fuzz_usbhid via the
  usbclass/usbhid Rust rlib + panic=abort staticlib pattern;
  fuzz_usbclass ≈ 1.05M/s, fuzz_usbhid ≈ 639k/s — both clean);
  TLS records/handshake (fuzz_tls + seeds/gen_tls_seeds.py —
  five parsers (TlsPeekRecord / TlsPeekHandshake /
  TlsParseServerHello / TlsParseCertificateLeaf /
  TlsParseServerHelloDone) dispatched by a 1-byte selector;
  6 seeds covering each entry point at ≈ 982k runs/s clean);
  Image decoders (fuzz_bmp / fuzz_tga / fuzz_jpeg / fuzz_png
  harnesses + seeds + duetos_img_meta Rust shim were already
  in tree from prior slices — bullet was stale).
-->
- **Bluetooth HCI/HID** — `kernel/net/bluetooth/hci.h`,
  `hid.h`. Untrusted radio peer.
<!-- Disassembler bullet retired 2026-05-26: fuzz_disasm harness
     + host_shim/disasm_stubs.cpp + seeds/gen_disasm_seeds.py
     landed; fuzz_disasm runs ≈ 50k execs/s clean on the canonical
     five-family seed corpus (prologue / ALU / control / SIMD /
     unknown-as-db). Auto-picked up by tools/test/fuzz-all.sh via
     the established seeds/gen_<name>_seeds.py convention. -->


**Blocks on:** nothing — independent slices, one parser each,
same recipe. Pick the top unstruck bullet, land harness +
(any) fix, strike the bullet in the same commit.

---

## How to graduate an item

When a roadmap item lands:

1. **Delete its entry from this page** in the same commit.
2. Add a [`Design-Decisions`](Design-Decisions.md) entry (one
   per non-trivial commit).
3. Update [`History`](../getting-started/History.md) if the
   landing changes a project-level milestone.
4. Update the owning subsystem wiki page's "Known Limits".

If an item is wrong-sized for a single commit, write a slice plan
into the relevant subsystem page and keep a one-line index
pointer here — **not** a landed-work paragraph.

## Program backlog — ordered (2026-07-28)

The standing work queue, in priority order. Items are ordered by **how much
real software or hardware each unlocks per unit of work**, not by how
interesting they are. Detailed sections for several already exist elsewhere
in this file; this is the running order, not a replacement for them.

Convention: `[dep: N]` means item N should land first. **PROOF** names the
artefact that decides whether it actually works — without one an item is not
done, it is merely written.

### Tier 1 — Win32 compatibility (the first pillar)

1. ~~**SEH + C++ exception handling.**~~ **LANDED 2026-07-26 (T6-05).**
   Acceptance met: `pe-runtime` QEMU profile passes scalar catch,
   class-reference catch, cross-frame destructor unwind, catch-all, TLS,
   SEH, and synchronization with 51/51 boot self-tests. Remaining
   extensions (copy-ctor catch objects, FH4, ESTypeList, rethrow) are
   incremental — the core contract is delivered.
2. ~~**`.rsrc` (PE resource) parser.**~~ **LANDED 2026-07-28.** The
   walker, `FindResource*` / `LoadResource` / `LockResource` /
   `SizeofResource` / `FreeResource` / `EnumResource*` and a real
   `LoadStringW` ship on both bitnesses; `user32!LoadStringW` went from
   282 32-bit SysWOW64 binaries wanting it (82 counting `.exe` only) to
   0. See [`wiki/subsystems/PE-Resources.md`](../subsystems/PE-Resources.md).
   Two consumers were deliberately NOT built, because each needs a sink
   that does not exist — building the decoder first would be dead code:
   - ~~**Icons / cursors / bitmaps**~~ **LANDED 2026-07-29.** `LoadIcon`,
     `LoadCursor`, `LoadImage` are REAL on both bitnesses.
     `SYS_GDI_CREATE_CURSOR_RGBA` (224) takes RGBA pixels + hotspot.
     `duet_res_decode_icon` walks RT_GROUP_ICON -> RT_ICON, decodes
     BIH + bottom-up DIB (32/24/8/4/1bpp) + AND-mask -> BGRA.
     `icon_smoke` PE fixture in the ring3 battery.
   - ~~**Accelerators**~~ **LANDED 2026-07-29.** `LoadAcceleratorsA/W`
     parse `RT_ACCELERATOR` from the PE's `.rsrc` section.
     `TranslateAcceleratorA/W` match VK + modifier state and post
     `WM_COMMAND`. `KeyCode` -> Win32 VK translation table in
     `kernel/subsystems/win32/keycode_vk.h`. `accel_test` PE fixture
     in the ring3 battery.
3. ~~**Side-by-side DLL loading.**~~ **LANDED 2026-07-29.** `Process::sxs_dir`
   tracks the exe directory; `SYS_DLL_LOAD_FROM_PATH` falls through to a
   side-by-side resolver; recursive import resolution + security guard
   scanning of disk-loaded DLLs shipped. BattleBit.exe + UnityPlayer.dll
   (26 MiB, 67 imports) loads and runs. See
   [`PE-Loader.md`](../subsystems/PE-Loader.md).
4. ~~**Dialog manager.**~~ **LANDED 2026-07-29.** Template-driven
   `DialogBoxIndirectParamA/W`, `CreateDialogIndirectParamA/W`, modal loop
   with `EndDialog`, `IsDialogMessage`, `GetDlgItem`, `SetDlgItemTextA/W`,
   `GetDlgItemTextA/W`, `SendDlgItemMessageA/W`, `CheckDlgButton`,
   `IsDlgButtonChecked`. `dialog_smoke` PE fixture in the ring3 battery.
5. ~~**Real COM.**~~ **LANDED 2026-07-29.** Registry-backed CLSID→DLL
   resolution, `CoInitializeEx`, `CoCreateInstance`, `CoRegisterClassObject`,
   `IUnknown`/`QueryInterface`, in-proc servers, apartment model. See
   [`Win32-Surface-Status.md`](Win32-Surface-Status.md#ole32dll).
6. ~~**Delay-load imports.**~~ **LANDED 2026-07-29.** The premise was
   wrong twice over: `__delayLoadHelper2` is linked INTO the image by
   `delayimp.lib`, not provided by the OS, and routing through it would
   have gone through `GetProcAddress`, which deliberately reports a miss
   for no-op thunks. The loader binds directory 13 eagerly through the
   static-import ladder instead — see
   [`PE-Loader.md`](../subsystems/PE-Loader.md#delay-load-imports).
7. ~~**PE TLS callbacks.**~~ **ALREADY LANDED** (T6-01, predates this
   backlog). `SetupStaticTls` copies the `.tls` template, wires
   `TEB.ThreadLocalStoragePointer` and `_tls_index`, and runs
   `AddressOfCallBacks` in ring 3 via a generated trampoline on both
   process and thread attach. Remaining gap is DETACH — see
   [`PE-Loader.md`](../subsystems/PE-Loader.md#tls-static-data-and-callbacks).
8. ~~**SxS / assembly manifests.**~~ **LANDED 2026-07-30.** RT_MANIFEST
   resource parser (`ParseManifestFromPe`), execution level / DPI awareness /
   SxS dependency extraction. Wired into `Process::manifest` at spawn.
9. ~~**Console completeness.**~~ **LANDED 2026-07-29.** Real
   `GetStdHandle`, `WriteConsoleA/W`, `ReadConsoleA/W`,
   `GetConsoleMode`/`SetConsoleMode`, `GetConsoleScreenBufferInfo`,
   `SetConsoleCursorPosition`, `FillConsoleOutputCharacter`,
   `SetConsoleTextAttribute`.
10. ~~**Fibers.**~~ **LANDED 2026-07-29.** Real `ConvertThreadToFiber`,
    `CreateFiber`, `SwitchToFiber`, `DeleteFiber`, `GetFiberData`,
    `GetCurrentFiber`, FLS (`FlsAlloc`/`FlsFree`/`FlsGetValue`/`FlsSetValue`)
    with per-fiber storage + generation counters. `fiber_smoke` PE
    fixture in the ring3 battery.
11. **.NET spike.** [dep: 3, 5 — both cleared] **DEFERRED** by owner
    (2026-07-29) — see the ".NET / CLR hosting" section above. Do NOT
    write a CLR. Determine whether CoreCLR can be hosted as a guest PE.
    **PROOF:** a managed hello-world runs, or a written account of the
    exact blocker.

### Tier 2 — graphics and media

12. ~~**Off-screen surfaces.**~~ **LANDED 2026-07-29.** The premise was
    wrong: memory DCs, compatible bitmaps and BitBlt already existed. What
    was missing was pixel-DATA transfer (`SYS_GDI_SET_DIBITS` /
    `_GET_DIBITS`, 214 / 215) and, more seriously, ownership --- surfaces
    had no owner, no per-process bound, and were never reclaimed at exit.
    Remaining GDI DIB gaps are listed in
    [`Win32-Surface-Status.md`](Win32-Surface-Status.md#gdi32dll).
13. **GDI completeness.** [dep: 12] Paths landed earlier (per-DC
    recorder: Begin/End/Close/Stroke/Fill/StrokeAndFill/Abort/GetPath/
    PathToRegion); regions (exact `CombineRgn` rect-list algebra +
    the clip-selection family) and transfer modes (`SetROP2` via
    `SYS_GDI_SET_ROP2`) landed 2026-08-05. Residue: the 11 R2 codes
    beyond BLACK/NOT/XORPEN/COPYPEN/WHITE (fall back to COPYPEN),
    window-DC ROP2 (only R2_BLACK/R2_WHITE via colour transform),
    clip enforcement for outlines/lines/text (bounding-box reject,
    not per-pixel), path curves + scan-line interior fill,
    `FlattenPath`/`WidenPath`.
15. **D3D9.** Large back catalogue; simpler than 11/12.
16. **D3D11 completeness** and **D3D12** beyond the current thunk layer.
17. **DirectWrite / Direct2D.** [dep: 13]
18. **Vulkan ICD completeness** — real pipelines, render passes, swapchain.
19. **Hardware video decode.**
20. **XAudio2 / WASAPI real mixing.** [dep: 21]
21. **Audio depth** — USB audio class, HDMI/DP audio, per-stream volume,
    resampling.
22. **DirectInput / XInput** bound to real HID devices. Groundwork
    landed 2026-08-05: the `hid_gamepad` driver is wired end-to-end —
    xHCI descriptor parse claims non-boot HID interfaces as gamepad
    candidates, Report-descriptor layout extraction binds confirmed
    Gamepad/Joystick devices into the 4-slot XInput-shaped state
    table, and the poll task injects interrupt-IN reports (host test
    `tests/host/test_hid_gamepad.cpp` + the gamepad arm of
    `XhciDescriptorSelfTest` at boot). Remaining:
    the `SYS_GAMEPAD_STATE` syscall + the userland XInput DLL
    binding.

### Tier 3 — hardware needed to be a daily driver

23. **Power management.** The S3 core LANDED 2026-07-29: real-mode wake
    trampoline at physical 0x9000 (`arch/x86_64/acpi_wakeup.{S,cpp}`),
    CPU architectural save/restore across the power loss, the FACS
    waking-vector handshake, generic `\_Sx` sleep-package decode, and
    the per-driver Suspend/Resume + veto contract in
    `kernel/power/suspend.{h,cpp}`. A full cycle is proven under QEMU +
    SeaBIOS by `tools/test/s3-cycle-smoke.sh`. What remains:
    - `ResumePlatform` re-MAPS MMIO as well as re-programming the
      controllers (LapicInit / IoApicInit / HpetInit each call
      `mm::MapMmio` again). The arena is a bump allocator with no free,
      so every cycle leaks arena and strands cached pointers to the old
      VA; an `s3test=1` boot faults later in the VirtIO probe. Fix by
      splitting a re-program-only entry point out of each Init.
    - NVMe / AHCI / e1000 register `PowerSuspendVeto` at attach, so a
      machine that probed them declines S3. Each needs a quiesce +
      controller re-init pair to become a participant.
    - SMP: `PowerSuspendCheck` refuses with more than one CPU online —
      no AP park/resume path exists.
    - OVMF never re-enters the waking vector (SeaBIOS does), so UEFI S3
      resume is unproven.
    - S0ix is untouched.
24. **CPU frequency scaling — EPP + idle governors.** [PARTIAL — the
    P-state *selection* half LANDED 2026-07-29] Reading (Intel ratios,
    AMD Zen `MSR_PSTATE_DEF` decode, APERF/MPERF effective frequency)
    and *selecting* an operating point are both in tree: Intel HWP
    (`IA32_HWP_REQUEST`) preferred where firmware enabled it, legacy
    `IA32_PERF_CTL` otherwise, AMD `MSR_PSTATE_CTL` index select,
    all behind `cpufreq=tune` + `kCapPowerTune` + a
    platform-advertised window, never voltage, never a syscall. See
    [Power-Management](../drivers/Power-Management.md) "CPU P-state
    Control". What remains:
    - **EPP / energy-performance preference.** The HWP path preserves
      firmware's EPP and never chooses one. Needs its own policy
      rationale before it becomes a knob.
    - **Enabling HWP where firmware left it off.** `IA32_PM_ENABLE`
      bit 0 is write-once until reset, so the decision belongs with
      the EPP work rather than with a single set-the-ratio call.
    - **Idle governors / C-state selection.** Untouched; idle stays at
      firmware default.
    - **Broadcast to all CPUs.** `CpuFreqSetTarget` writes the MSR on
      the calling CPU only; per-core P-state parts keep their other
      cores unchanged.
    - **Hardware validation.** QEMU answers none of these MSRs under
      TCG or KVM, so the write path has never executed. It needs a
      real-silicon first boot.
25. ~~**`ReadMsrSafe`.**~~ LANDED. Extable-guarded `rdmsr` beside the
    existing `wrmsr` template; every MSR consumer now probes instead of
    predicting, and the static vendor+hypervisor gates are gone from
    thermal, cpufreq and RAPL.
26. **Thermal + battery policy.** [dep: 25 — cleared] The CPU
    temperature READ exists for both vendors now (AMD via SMN, still
    unvalidated on hardware). What remains is the policy: periodic
    resampling into the heartbeat, throttle thresholds, and battery
    `_BST`/`_BIF` evaluation.
27. **TPM 2.0 — seal / unseal.** [PARTIAL — the rest of item 27 LANDED]
    The TIS/FIFO transport, presence detection, ACPI TPM2 interface
    check, PCR extend + read, and the hardware RNG are in and verified
    live against `swtpm`; so is the permanent refusal of the identity
    half (EK export, AIKs, quote signing), enforced by a transport
    allow-list plus the absence of any raw passthrough. See
    [`TPM`](../security/TPM.md). What remains is sealing itself: the
    marshalling for `TPM2_CreatePrimary` / `Create` / `Load` / `Unseal`
    and the trial/policy session handling that binds a sealed blob to a
    PCR policy. The command codes are already on the allow-list. When a
    guest-facing seal syscall lands it must be cap-gated and derive key
    material per-application, salted per install, so two applications
    cannot correlate on a shared identifier even locally.
28. **Full-disk encryption.** [dep: 27's seal/unseal] Key sealed to PCR
    state, so no passphrase on every boot.
29. ~~**Measured boot as a LOCAL tripwire.**~~ LANDED. PCR 10/11 carry
    the kernel identity and command line; the composite over PCR 0-7,
    10 and 11 is read back from the chip and compared against a
    baseline pinned with `tpm.baseline=`. A mismatch warns and never
    refuses to boot — refusing would be the lock-out behaviour the
    design set out to avoid. Detection only: nothing signs a PCR set
    and nothing sends one anywhere. Remaining limitation, recorded as a
    `// GAP:` — the baseline shares storage with the thing it measures,
    which needs the writable persistent store to fix properly.
30. **Secure Boot chain verification.**
31. **Bluetooth.** HCI, L2CAP, then HID and A2DP.
32. **Precision touchpad HID** — gestures, palm rejection.
33. **UVC camera.**
34. **Multi-monitor + hotplug**, per-head modeset.
35. **SD/MMC**, **Thunderbolt/USB4**, **more NICs** (2.5G Realtek, Intel
    I225), **fingerprint / sensors**.
36. **Real GPU engine-busy sampling.** AMD `mmGRBM_STATUS` bit 31 is already
    mapped but read ONCE at probe — a single read of a level-triggered bit
    is not a duty cycle; it needs a periodic sampler. Intel: RC6 residency
    or RING head/tail. NVIDIA: `NV_PGRAPH_STATUS`. Virtual adapters must
    report NOT APPLICABLE, never 0%. **PROOF:** unvalidatable in QEMU —
    needs a bare-metal boot.

### Tier 4 — storage and filesystems

37. **Native journaling FS** with checksums; **COW snapshots**.
38. **NTFS write** (read-only today), **ext4 write**.
39. **exFAT cluster-chain growth** — writes are bounded today.
40. **TRIM/discard**, **NVMe namespace management**, **software RAID**.
41. **File-change notification** (`ReadDirectoryChangesW` / inotify).
42. **Memory-mapped file completeness.**
43. **SMB client** — the biggest single interop win on a home network.
44. **Disk quotas**, **NFS client**.

### Tier 5 — networking

45. **TLS 1.3** — a branch exists (X25519 + RSA-PSS done, protocol layer
    remaining); finish and merge it.
46. **IPv6 dual-stack.**
47. **Firewall / packet filter**, **NAT + bridging**.
48. **WireGuard**, **QUIC / HTTP3**, **DNS-over-HTTPS**, **mDNS**.
49. **Wi-Fi depth** — WPA3, roaming, iwlwifi.

### Tier 6 — kernel hardening and quality

50. **WaitQueue detach primitive.** One missing scheduler ABI
    (`WaitQueueBlockLocked`) blocks three filed findings (R1-14
    `regions_lock`, R1-15 PS/2 ring, C4 unkillable blocked threads).
    Building it once retires all three.
51. **Root-cause the intermittent `sync/spinlock` self-deadlock** seen ~1
    boot in 5 during the userland elf-loader OOM self-tests.
52. **CET / shadow stacks**, **per-entry IBRS**, **KCFI**.
53. **NUMA awareness**, **huge pages**, **memory compression**.
54. **io_uring-style async I/O.**
55. **Real-time scheduling class**, **cgroup-style resource limits**.
56. **Checkpoint / restore** of a running process.
57. **Kernel live patching.**
58. **Crash reporting with symbolisation**; **sampling profiler**.

### Tier 7 — the differentiator

59. **PE/ELF interop as a first-class feature.** DuetOS runs both as peers
    on ONE kernel, ONE VFS, ONE TCP stack. A Linux binary piping into a
    Windows binary in the same process tree is something Wine cannot do (no
    Linux kernel ABI) and WSL cannot do natively (two kernels). Most of the
    substrate exists; what is missing is deliberate plumbing and a demo.
60. **Hypervisor.** [dep: 23] Run Linux/Windows guests; `tools/vmm` already
    drives WHP on the host side.
61. **Package manager / installer**, **multi-user + fast switching**,
    **remote desktop**, **accessibility** (screen reader), **i18n**.

### Standing rules for this backlog

- An item is done when its **PROOF** artefact runs, not when it compiles.
- Anything returning a constant carries `// STUB:`; real-but-limited carries
  `// GAP: <what> - <when>`. A present-but-lying export is worse than a
  missing one — `LoadStringW` is deliberately unexported for exactly this
  reason.
- Prefer extending an existing subsystem over adding one.
- Re-run `tools/test/pe-compat-survey.py` after Tier 1 items: it measures
  which real binaries each change actually unblocked, turning "what next"
  into a measurement instead of a guess.
