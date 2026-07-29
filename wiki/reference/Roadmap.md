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

### SMP=8 (4c × 2t) AP-bringup recursive fault under x86_64-debug

- **Symptom:** booting `tools/qemu/run-stress.sh cpu` on
  **x86_64-debug only** with `DUETOS_SMP=8,sockets=1,cores=4,threads=2`
  reproducibly hits a recursive #-fault during the **first AP**'s
  bring-up at ~70 ms after `[arch/smp] starting AP apic_id val=0x1`.
  Captured 2026-05-22; symptom-line in the serial log:

  ```
  [t=97644.875ms] [D] fs/fat32 : ...corrupted bytes... path=""
  [recursive-fault] vec=0x...  rip=0x... — short-circuiting panic dump
  ```

  The vec/rip on the recursive-fault line render mostly as
  spaces / non-printable bytes — the panic-mode SerialWrite is
  bypassing `g_serial_lock`, so the BSP's hex digits and a
  concurrent AP-side writer interleave at the wire level. The
  underlying first fault is therefore lost to corruption.

  **Bound:** x86_64-release at SMP=8 boots clean and runs the
  10s-8-worker stress to `[stress] done` (verdict OK, no
  inversions). x86_64-debug at SMP=4 also boots clean. So the
  AP-bringup storm under KASAN/UBSAN instrumentation noise is
  the trigger — neither SMP=8 alone nor debug alone is enough.
- **Likely shape:** an AP's first timer IRQ enters the trap path
  while KASAN/UBSAN shadow-map machinery is still initialising
  for that AP's stack/IST region, AND `Current()` on that AP is
  the bootstrap sentinel rather than a fully-armed task. The
  UBSAN report path itself takes a lock that races. **Not** the
  GSBASE/lidt root that PR #320 fixed — that one trace-bounds at
  "AP online" and the recursive-fault never reaches it.
- **Reusable harness:** `tools/test/smp-stress-sweep.sh 20 8 5`
  re-triggers the scenario with per-repeat log capture so a
  future investigation can grep `build/x86_64-debug/smp-stress-N.log`
  for the first fault line.
- **Bounded fix landed** (`arch/traps,serial: serialize recursive-fault
  dump through g_serial_lock try-lock`): `HaltOnRecursiveFault` now
  snapshots vec/rip into locals before formatting, pre-formats the
  entire line into a stack buffer, and emits it through
  `SerialWriteNRecursiveFault` — which try-acquires `g_serial_lock`
  (non-blocking) first, falling back to the `PanicEmitTryClaim`
  bounded-spin serializer only if the lock is held (BSP mid-dump).
  The `vec=0x   __  rip=0x   __` interleaving symptom is suppressed.
  Re-run `tools/test/smp-stress-sweep.sh 20 8 5` with this fix in
  tree to read the real first-fault site in the now-clean log.
- **An AP-bringup `Current()` fault WAS found and fixed (2026-07-28)**
  — `sched: install the AP boot sentinel before SchedStartIdle`. The
  clean first-fault log this item was blocked on finally arrived from a
  full-device TCG smoke:

  ```
  SchedEnterOnAp begin cpu_id=1
  SchedCreate: kernel task name="idle-ap1"
  sched/idle : idle task online          <- tail of SchedStartIdle
  [ubsan] tm-detail member-access null-deref ptr=0x0 ty='Task'
  [panic] KASSERT: WaitQueueBlockTimeout on non-Running task cpu=1
  ```

  `SchedEnterOnAp` ran `SchedStartIdle` (which allocates via
  `SchedCreate` -> `KMalloc` and takes locks) BEFORE minting the boot
  sentinel and installing it as `current_task`. A fresh AP's PerCpu is
  memset-zeroed, so `current_task` was **nullptr** for that whole
  window — anything reaching `Current()` got a null `Task`, and
  anything blocking failed the Running-state assert. Moving the
  sentinel ahead of `SchedStartIdle` closes it.

  Note this item's hypothesis was *nearly* right and off by one step:
  it guessed a race involving "a sentinel `Current()`". The sentinel
  was not the problem — the window BEFORE the sentinel existed was.

  Measured over full-device TCG smokes: **0 KASSERTs across 3 boots**
  with the fix, versus the pre-fix control panicking at t≈20 s. Every
  fixed run reached t≈412 s (20x further) and brought up a
  deterministic 3/3/3 APs.

- **Still open — the SMP=8 stress symptom specifically.** The fix above
  was measured against the SMP=4 boot smoke. The recursive `#`-fault
  this item was originally filed for reproduces under
  `tools/qemu/run-stress.sh cpu` at `DUETOS_SMP=8,sockets=1,cores=4,threads=2`,
  which has NOT been re-run since. They plausibly share the root cause
  — both are AP-bringup `Current()` faults — but that is an inference,
  not a measurement. Re-run `tools/test/smp-stress-sweep.sh 20 8 5`
  before closing this item.

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

- **Finding (audit R1-14, high):** `AddressSpace::regions_lock` is
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
  with frame allocation, page-table edits and TLB shootdowns kept
  outside it. `AddressSpaceMapUserPage` allocates while holding
  the current lock, so it cannot simply be converted in place. The
  alternative is to stop compacting — tombstone the dying row and
  reclaim separately — which keeps readers correct without any new
  lock on the read path.
- **Blocks on:** deciding between those two, since it changes an
  mm-core invariant. Not attempted as a drive-by: `address_space.cpp`
  is the highest-blast-radius file in the tree and a partial fix here
  (locking writers only, leaving the spinlock-holding reader
  unsynchronised) would buy very little while looking like a
  resolution.


### PS/2 scan-code ring — two writers to `g_ring_tail` on SMP

- **Finding (audit R1-15, medium):** the scan-code ring is protected
  only by `arch::Cli()` / `Sti()`, and `Ps2KeyboardTryReadChar`
  (`drivers/input/ps2kbd.cpp:841`) has no protection at all. On SMP
  `Cli` masks only the LOCAL CPU, so the IRQ can fire on a peer and
  race the reader regardless.
- **The actual defect is a second writer, not just a missing mask.**
  `g_ring_tail` is documented as the "read cursor (task)", but the IRQ
  producer ALSO advances it on the ring-full path
  (`ps2kbd.cpp:687`, `++g_ring_tail; // discard oldest`). Two
  unsynchronised read-modify-writes to the same cursor lose an update,
  which leaves `head - tail` permanently skewed — so the fullness test
  that drives the drop path is wrong from then on, and the consumer can
  re-read a byte the producer intended to discard.
- **Why a spinlock is not a drop-in.** `Ps2KeyboardRead`
  (`ps2kbd.cpp:740`) calls `WaitQueueBlock(&g_readers)` INSIDE its
  `Cli` region, which is what makes its check-then-sleep atomic against
  the waker. Converting that to a spinlock requires the
  release-and-block primitive `WaitQueueBlockLocked(wq, lock)` — which
  Design-Decisions already records as deliberately deferred and which
  is not exported. Locking only the producer and `TryReadChar` would
  leave the blocking reader racing, i.e. the partial-fix trap.
- **The other option is a design change:** switch the ring-full policy
  from drop-OLDEST to drop-NEWEST. The producer would then only ever
  write `g_ring_head` and the consumer only `g_ring_tail`, making it a
  true single-producer/single-consumer ring that needs no lock at all
  (aligned u64 loads/stores are atomic on x86_64). The cost is the
  behaviour `ps2kbd.cpp:676-680` deliberately chose: dropping the
  oldest keeps key-RELEASE bytes that arrive after a press, which
  matters more than keeping the first press of a burst. Worth noting
  the ring is only full when the consumer is already too slow, so bytes
  are lost either way — the question is which.
- **Blocks on:** picking one of those two. Both are defensible; the
  first is strictly more work and gates on a scheduler-ABI addition,
  the second trades a documented input-handling nicety for a
  lock-free invariant.


### Cancelling an untimed-blocked thread — needs a WaitQueue detach primitive

- **Finding (sweep C4):** `SchedKillByPid` cannot terminate a thread that
  is Blocked. It sets `kill_requested` and returns
  `KillResult::Blocked`, relying on the task's normal producer to wake
  it so it can take the kill path. For a thread on an UNTIMED wait whose
  producer never fires, that wake never comes and the thread is
  effectively unkillable — and `SchedKillByProcess` inherits the problem,
  which is why its sweep is now pass-bounded rather than
  loop-until-empty (a naive retry would spin forever on exactly this).
- **The kernel is already honest about it.** `SchedKillByPid`'s own
  comment states the constraint: "Blocked tasks sit on a WaitQueue
  threaded via `next`. We don't have a safe cross-queue detach primitive
  in v0 — the producer that owns the WaitQueue might be mid-enqueue."
  That is a real hazard, not laziness: detaching a task from a queue
  another CPU may be mid-enqueue on corrupts the list.
- **Fixed already — the half that was lying.** `NtTerminateThread`
  mapped `KillResult::Blocked` to `STATUS_SUCCESS`, so a Win32 caller was
  told a thread had been terminated while it was still running. It now
  returns `STATUS_PENDING`, which is SUCCESS-class (so `NT_SUCCESS()`
  callers are unchanged) but distinguishable by an exact comparison.
  `SchedKillByProcess` likewise now WARNs with a live-task count instead
  of returning a plausible number in silence.
- **What a real fix needs:** a safe detach — either a per-WaitQueue lock
  held across both enqueue and detach, or an epoch/tombstone scheme
  where the killer marks the entry and the owning producer drops it on
  its next pass. The first is the same scheduler-ABI addition that
  `WaitQueueBlockLocked(wq, lock)` needs (see the AddressSpace
  regions_lock and PS/2 ring entries); doing them together is likely
  cheaper than either alone.
- **Blocks on:** that primitive. Deliberately not attempted piecemeal —
  a detach that races an in-flight enqueue trades an unkillable thread
  for a corrupted wait queue.


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

### PE loader — unchecked `AddressSpaceMapUserPage` frame leak

- **Mechanism (confirmed, mirrors a bug already fixed on the ELF
  side 2026-07-28):** `AddressSpaceMapUserPage` returns `void` and
  has three *silent, non-fatal* refusal paths — frame budget
  exhausted, region-table grow OOM, page-table walker OOM
  (`kernel/mm/address_space.cpp:398`, `:426`, `:440`). None of them
  takes ownership of the caller's frame or appends a regions row,
  and `address_space.h:205-208` forbids the caller from
  `FreeFrame`-ing a frame it handed over. `pe_loader.cpp` calls it
  and immediately `guard.Track(va)` without checking, at roughly
  twelve sites: section pages (`:531`), header pages (`:597`), the
  relocation/TLS paths (`:939`, `:979`, `:1084`), the image reserve
  loop (`:2500`), TEB (`:2650`), proc-env (`:2682`),
  KUSER_SHARED_DATA (`:2710`), and the 64- and 32-bit thunks pages
  (`:2749`, `:2752`, `:2782`). Every page past the AS's
  `frame_budget` leaks one 4 KiB frame permanently, `PeLoad` still
  reports success with a half-mapped image, and the bogus `Track`
  rows make the unwind walk call `UnmapUserPage` on VAs with no
  regions row (returns false, reclaims nothing).
- **Fix shape:** the ELF loader's — probe the leaf PTE with
  `AddressSpaceProbePteRaw` (O(1)) after the map; absent ⇒ the map
  was refused ⇒ `FreeFrame` and fail the load. See
  `kernel/loader/elf_loader.cpp` `LoadSegment` for the landed
  pattern.
- **Why it wasn't done in the ELF slice:** twelve sites in a
  ~2800-line TU with several distinct failure-propagation shapes
  (some return `bool`, some are inside `PeLoad` proper). Fixing two
  of twelve would leave a half-consistent loader, which is worse
  than a uniformly-known gap. Wants its own slice.

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

### Multi-monitor / runtime resolution change

- **Today:** single linear framebuffer, mode set at boot via
  Bochs VBE; EDID parser landed, hot-plug detect missing.
- **Blocks on:** per-vendor GPU drivers (Intel/AMD/NVIDIA all
  probe-only), mode-set negotiation.
- **Owner:** `kernel/drivers/gpu/`.

### Brightness — per-vendor register backlight

- **Residual:** per-vendor *register* backlight (Intel/AMD PWM,
  vendor WMI / Fn-key hotkeys) for laptops that do brightness
  outside ACPI `_BCM`; wire the UI brightness control + Fn-key
  events to `AcpiBacklightSet`. (ACPI `_BCL`/`_BQC`/`_BCM` path +
  EC driver landed.)

### Battery + ACPI suspend (residual — shared with ACPI S5)

- **Residual:** S3 / S0ix suspend-to-RAM wake-vector +
  context save/restore. EC `_Qxx` read path
  (`AcpiEcReadQueryByte` / `AcpiEcDispatchPendingQuery`) and
  per-bit `_Lxx`/`_Exx` GPE walking in the `env-monitor` task
  both landed 2026-05-26 — lid-close / AC plug/unplug events
  routed through either EC `_Qxx` or per-GPE method now fire
  the firmware's handler. Battery / AC / lid *state* readable
  via `_LID`/`_PSR`, SCI power-button path, ACPI S5 soft-off
  incl. `_PTS`/`_GTS`, and the GPE `_Qxx` event surface all
  landed. Open work: S3 trampoline + per-driver Suspend/Resume
  callback contract (the harder half, per the research notes).

### Bluetooth, Printer, Webcam

- **Bluetooth residual (SMP-gated frontier):** the connection
  manager — LE scan/connect, SMP pairing/bonding, GATT-HOGP
  service discovery — so a real BT keyboard can associate on its
  own; plus general L2CAP signalling / RFCOMM / SDP for
  non-keyboard profiles. (HCI codec, HID-keyboard upper stack,
  btusb transport, xHCI interrupt-IN primitive landed; invoked
  via `bt probe`.)
- **Printer:** USB printer-class driver + IPP / PostScript /
  raster pipeline.
- **Webcam:** UVC USB-Video class driver.

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

### Winsock async surface

- **Deferred:** Overlapped I/O + IOCP-backed socket reads
  (kernel32's IOCP plumbing exists but isn't wired into the
  socket read path — see **IOCP for sockets (Win32)** below);
  kernel-direct event signaling at the moment of socket activity
  (today's `WSAWaitForMultipleEvents` is a 10 ms polling loop);
  `fWaitAll == TRUE` semantics (current impl returns on first
  ready event). (Synchronous BSD subset + the `WSAEvent*` /
  `WSAEventSelect` / `WSAEnumNetworkEvents` async surface +
  kernel `SocketPollEvents` producer + `WSAAsyncSelect`
  window-message delivery with DLL-side non-blocking emulation
  landed.)

### IOCP for sockets (Win32)

- **Cost:** ~300 LoC for a new `KCompletionPort` kernel object
  (`kernel/ipc/kcompletion.{h,cpp}`) + new sub-ops on
  `SYS_HANDLE_OP`: `kCompPortCreate(concurrency)`,
  `kCompPortAssociate(port, handle, key)`,
  `kCompPortPost(port, key, bytes, ovl)`,
  `kCompPortGet(port, &key, &bytes, &ovl, timeoutMs)`. New socket
  sub-op `kSockOpOverlapped(kind, sock, buf, len, ovl_uptr)`
  returns `WSA_IO_PENDING` and posts completion to the associated
  port.
- **Reference:** Wine `dlls/ws2_32/socket.c` overlapped path +
  `WS_AddCompletion` → `NtRemoveIoCompletion`.
- **Ordering:** `WSAAsyncSelect` shipped (no kernel change);
  IOCP follows when a real overlapped-using PE binary is in test.
- **Owner:** `kernel/ipc/`, `userland/libs/ws2_32/`.

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

### IPv6 dual-stack

- **Cost:** ~3000 LoC + ~15 KB state.
- **Design:** mirror lwIP's `src/core/ipv6/` (smallest correct
  IPv6 reference at ~3000 LoC). Cross-reference OpenBSD
  `sys/netinet6/` for the cleaner protocol layering. Address
  widening: 4-byte → 16-byte union on every `addr_t`; per-socket
  +10 B for AF+V6ONLY+scope+flowinfo; per-TCB +24 B for
  dual-family endpoints; prefix list + default-router list +
  neighbor cache ~6 KB total.
- **Approach:** AF_INET6 as the native type with v4-mapped
  addresses (`::ffff:0:0/96`) bridging. NOT separate AF_INET +
  AF_INET6 codepaths.
- **Required pieces:** NDP (NS/NA), Router Discovery (RS/RA),
  prefix-info → SLAAC, MLD (mandatory for solicited-node
  reception), fragment reassembly (sender-side fragmentation can
  defer to PMTUD-discovered minimum MTU + don't-fragment).
- **Owner:** new `kernel/net/ipv6/` subdirectory; subsystem page
  follows the same shape as `Network-Stack.md`.

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
   `user32_32` / `gdi32_32` STUBs all trace to one missing thing — an
   off-screen surface the compositor's display list has no concept of,
   which blocks memory DCs, bitmaps, blits and DIB sections. Icon and
   cursor resources need a `.rsrc` parser. Fonts need a font pipeline.

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

### Run a real 64-bit application - side-by-side DLL loading (next rung)

**Landed 2026-07-28:** off-the-shelf x86_64 MSVC binaries start. A stock
`cl /MT` build reaches `main()` and exits 0, and System32's `clip.exe`,
`sort.exe` and `timeout.exe` run to an exit code -- `timeout.exe`
returns **1 with no arguments, matching real Windows exactly**. The
blocker was `VirtualProtect` failing on every page outside a
`VirtualAlloc` region (see Design-Decisions, same date); import coverage
was never the issue.

The measured next blocker is **loading a DLL that ships beside the
.exe**. `tools/test/pe-compat-survey.py` puts the Unity launchers on
this dev host (`BattleBit.exe`, `Black Ice.exe`, `Cult Of The Lamb.exe`)
at 98.5% coverage with exactly **one** unresolved import each --
`UnityPlayer.dll!UnityMain`. Every DLL DuetOS can bind is embedded in
the kernel image via the `spawn.cpp` preload set; a PE that imports a
DLL sitting next to it on the volume has no path at all.

What the rung needs:

1. The spawn path must remember the directory the PE was read from, so
   an import miss has somewhere to look. `peexec=` reads a bare 8.3 name
   off FAT32 vol 0 today.
2. A read-DLL-from-volume helper, and recursive import resolution for
   the loaded DLL (its own imports may pull further side-by-side DLLs).
3. The security guard must scan a disk-loaded DLL the way it scans a
   disk-loaded PE -- this is the reviewable signal, since a DLL loaded
   from a guest-writable volume executes in the process's address space.
4. `SYS_DLL_LOAD_FROM_PATH` should share that path so runtime
   `LoadLibrary` of a bundled DLL works too, rather than only the
   `/lib/<name>` ramfs lookup.

Sizing the rung honestly: side-by-side loading is necessary but nowhere
near sufficient for a real game. `UnityPlayer.dll` itself measures 68.6%
coverage with **163** unresolved imports plus three DLLs that do not
exist here at all (`hid.dll`, `imm32.dll`, `opengl32.dll`), and the
bundled `mono-2.0-bdwgc.dll` adds 72 more. The managed assemblies all
import `mscoree.dll`. Expect the ladder above this rung to be import
coverage, then OpenGL, then audio/input -- the same long middle the
PE32 ladder describes.

### GetProcAddress cannot see the kernel thunk page

Bind-time and run-time symbol resolution use **different surfaces**. The
PE import binder resolves against the preloaded DLLs' export tables AND
`Win32ThunksLookup` (the fixed R-X thunk page at `kWin32ThunksVa`).
`SYS_DLL_PROC_ADDRESS` resolves only through
`ProcessResolveDllExportByBase`, i.e. export tables. A symbol DuetOS
genuinely implements, but implements as a thunk rather than a DLL
export, is therefore **invisible to a runtime `GetProcAddress`**.

Measured, not inferred (2026-07-28, stock `vulkaninfo.exe`, with the new
`[dll-load] GetProcAddress miss` diagnostic): 15 misses, of which 13 are
present in `thunks_table.inc` right now -
`InitializeCriticalSectionEx`, `FlsAlloc`, `FlsSetValue`,
`LCMapStringEx`, `CompareStringEx`, `EnumSystemLocalesEx`,
`GetDateFormatEx`, `GetLocaleInfoEx`, `GetTimeFormatEx`,
`GetUserDefaultLocaleName`, `IsValidLocaleName`, `AreFileApisANSI`,
`LocaleNameToLCID`. Only `FlsGetValue2` and `LCIDToLocaleName` are
genuinely absent. The MSVC UCRT caches those NULLs and later calls
through one, giving an access violation at `rip=0`.

**Why this was NOT force-fixed.** The obvious fix - fall back to
`Win32ThunksLookup` on an export-table miss - changes `GetProcAddress`
semantics in a way one boot cannot validate. Many thunks are
*safe-ignore stubs* returning a constant; the loader already emits a
Warn when an IMPORT lands on one, precisely because the caller will
silently misbehave. Applications routinely use
`GetProcAddress(h, "Foo") != NULL` as a **feature/OS-version probe** and
branch on the answer. Handing back a no-op stub converts "this OS lacks
Foo, use the fallback path" into "Foo exists" followed by a silent
no-op - trading a loud failure for a quiet wrong answer.

So the fix needs a policy decision first: return only NON-no-op thunks
(`Win32ThunksLookupKind`'s `out_is_noop` already distinguishes them), or
return all and accept probe breakage. The former is almost certainly
right and is a small change - but it deserves a corpus re-run across all
nine binaries, not a single vulkaninfo boot. Note also that the module
handle must be mapped back to a DLL name for the lookup, and that
`kernelbase.dll` is a declared pure forwarder to `kernel32.dll`, so a
kernelbase handle should consult kernel32's thunks - which is exactly
what its `.def` already does for the exported subset.

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

### Win32 handle lifecycle — teardown + close-dispatch gaps (audited 2026-07-26)

A read-only audit of the PE loader and Win32 handle lifecycle found one
root shape with several symptoms: the handle **bands** are declared
across `kernel/proc/process.h` and the per-type pool modules, but the
two functions that must enumerate them all — `DoFileClose`
(`kernel/subsystems/win32/file_syscall.cpp`) and `ProcessRelease`
(`kernel/proc/process.cpp`) — each carry a hand-maintained list that has
drifted behind the set. Verified against the code, not inferred.

Ranked, with the security one first:

1. **Section handles are never released at process teardown —
   sandbox-reachable, system-wide.** `Section g_pool[kSectionPoolCap]`
   (`subsystems/win32/section.cpp:20`) is a **file-scope global**, 8
   slots shared by every process, and `SYS_SECTION_CREATE` has **no
   entry in `cap_table.def`** — a zero-capability guest PE can call
   `NtCreateSection`. `ProcessRelease` walks `kobj_handles` and
   `win32_dirs[]` only; the sole `SectionRelease` caller is the
   explicit-`CloseHandle` arm. Eight short-lived sandboxed spawns that
   each create one section and exit therefore exhaust the pool **for
   every process on the system until reboot**. This is the reviewable
   signal from CLAUDE.md — a malicious PE doing something a native
   DuetOS process could not. Fix: one release loop in `ProcessRelease`.
2. **Job-object handles cannot be closed by any shipped DLL.**
   `NtClose`/`CloseHandle` always issue syscall 22, and `DoFileClose`'s
   band chain has **no arm for `kJobHandleBase` (0xC00..0xC07)**.
   `SysJobClose` (168) has exactly one caller in the tree — the raw
   dispatcher — and nothing in `userland/` ever issues 168. So the
   spec-correct `NtCreateJobObject` → `NtAssignProcessToJobObject` →
   `NtClose` sequence leaks 100% of the time, and the `ProcessRetain`
   done at assign pins the target `Process` + its `AddressSpace`
   forever. Fix: one arm in `DoFileClose`.
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
4. **`win32_proc_handles[]` is not walked at teardown**, so an app that
   exits without `CloseHandle` on an `OpenProcess` result (normal —
   real Windows auto-closes) pins the target `Process` + `AddressSpace`
   for the life of the kernel. `kCapDebug`-gated. Foreign thread rows
   now retain only immutable TIDs and need no teardown release. Fix:
   one `win32_proc_handles[]` loop in `ProcessRelease`.
5. **Mutex ownership is not force-released when the owning task dies.**
   Only the explicit-`CloseHandle`-while-holding path drops it, so a
   worker killed while holding a mutex leaves `m->owner` a dead `Task*`
   and any sibling thread blocks forever, with no `WAIT_ABANDONED`.
   **Larger refactor** — needs per-task held-lock bookkeeping or a
   task-death hook; the handle table stores type-erased `KObject*`.
6. **`SpawnPeFile` leaks a `Process` on one error path.**
   `spawn.cpp:1419` calls `AddressSpaceRelease(as)` after
   `ProcessCreate` has already taken ownership of `as`; it should be
   `ProcessRelease(proc)`. One line, OOM-gated.

Because 1-4 are the same drift, the durable fix is not four more
hand-edits: give the bands one enumeration both sites share, or add a
static check that every declared `kWin32*Base` / `kJobHandleBase`
appears in both — the same "convert the whitelist into a property test"
move that `tools/test/check-syscall-numbers.py` makes for syscall
literals. Note `kWin32VmapBase` / `kWin32ExtraHeapArenaBase` are VA
bases, not handle bands, and must be excluded.

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

### Chrome tactility (Pass A) — residual polish + Pass A verification

The chrome-tactility plan
(`docs/superpowers/plans/2026-05-24-duetos-chrome-tactility.md`)
landed 23 of its 28 tasks: blend math + atlas-based 9-slice soft
shadow + 7 new Theme fields + per-theme intensity matrix +
runtime override (cmdline + shell) + chrome paint integration
on windows, modals, snap previews, taskbar tabs + strip, menu
panels + the WindowPaintFocusGlow helper. See
[`Compositor`](../subsystems/Compositor.md#chrome-tactility-pass-a)
for the subsystem summary.

The residuals waiting on visual verification or follow-on work:

- **VBox boot verification** (Task 27 step 5 of the plan).
  QEMU verification landed on 2026-05-24: all four
  `*-selftest` PASS sentinels fire on the canonical
  `x86_64-debug-fast` boot, the boot-log-analyzer TACTILITY
  section reports `blend=1 shadow=1 theme-matrix=1 umbrella=1
  probe fires=0`, and `tools/test/tactility-screenshot-matrix.sh
  classic` produces a 2.3 MB 1024×768 PPM at
  `build/shots/classic-debug-fast.ppm`. VBox still wanted per
  the [`vbox-bringup-pr266`](../../docs/...) memory entry —
  LAPIC / GS-base differences from QEMU sometimes catch what
  QEMU doesn't.
- **(VERIFIED 2026-05-24)** HighContrast pixel-diff invariant
  (plan §8.5 step 6). Empirically confirmed via
  `tools/test/hc-invariant-check.sh`: HighContrast captured
  twice under tactility=auto (theme matrix says off) + once
  under tactility=off (runtime override) shows the
  auto-vs-override diff (324 px) is below the inter-boot
  noise floor itself (333 px). The 333 px noise floor is the
  live taskbar widgets — clock display, uptime ticker,
  network-state cell, cursor PS/2-timing anti-aliasing —
  which vary independently of any chrome code. Together with
  the structural argument (HighContrast.tactility_enabled
  = false → ThemeTactilityEffective = false → every
  `*Shadow` site routes through the legacy fallback branch),
  the invariant is closed for this branch.
- **Menu scale-pop animation** (Task 18 full of the plan). The
  menu panel pop from 95% to 100% on open would need a per-
  panel scale factor threaded through `MenuRedraw` + the
  `MenuItemAt` hit-test so the click target stays aligned with
  the painted bounds while the animation runs. Discrete
  refactor; visual verification mandatory.
- **Cursor micro-shadow** (Task 21 of the plan, plan-marked
  stretch). Per-frame cost is the heaviest in the spec —
  cursor moves every PS/2 packet at up to 60 Hz. Also requires
  enlarging the cursor backing-store to cover the shadow halo
  so the shadow region restores when the cursor moves, instead
  of leaving a trail. Defer until soak shows headroom.
- **Per-tab pressed state** (out of plan scope). The taskbar
  per-tab paint reads a CursorPosition-derived hover state but
  the input layer transitions straight from press to dispatch
  without a paint-time pressed bit. An input-state refactor
  that surfaces per-widget pressed-bits would light up the
  press overlay that the chrome-tactility plan describes.
- **Menu row hover wash + force-dirty on flips** (Tasks 18 row-
  wash + 23 of the plan). The existing solid-accent hover-row
  fill in `MenuRedraw` is already a strong affordance; layering
  a tactility wash on top would compound. Task 23's
  force-dirty-on-flip pattern needs `WidgetFlag::*` bit-flip
  call sites that don't exist in this codebase — the current
  bool-state model doesn't have flip points to instrument.
- **WM z-order click bleed-through re-verification.** User reported
  on 2026-05-25 (amber-theme VBox boot, screenshot at 00:59) that
  "apps beneath the ones on top i clicked bleed through." Visible
  bleed in that screenshot predates `7ecfa12c security/guard: pause
  desktop compose while modal prompt is up` by 21 min and is most
  likely the same desktop-compose-vs-guard-prompt race that commit
  fixes. Code inspection of `WindowRaise` + `DesktopCompose` +
  `FramebufferEndCompose` diff scan found the z-order repaint path
  architecturally correct in isolation (gradient marks full-screen
  damage → diff scan finds all changed pixels → blit). Commit
  `e13159be video/wm: force full-screen snapshot invalidation on
  WindowRaise` lands a belt-and-suspenders: when `WindowRaise`
  actually reorders, post a full-screen `FramebufferInvalidateSnapshot`
  so the next `EndCompose` unconditionally flushes shadow→live +
  resyncs the snapshot.
  **Root cause found 2026-07-26 — that guard was a no-op on any
  present-hook backend.** `EndCompose` force-blitted the invalidated
  rects shadow→live and re-synced the snapshot there, then overwrote
  the damage union with the content-diff result (`g_damage = d`, or
  `g_damage.Reset()` on an empty diff) — and the re-sync is exactly
  what makes the diff report those pixels as unchanged. So the forced
  rects were dropped before `FramebufferPresent` ran: on virtio-gpu the
  z-order repaint reached the guest's live surface and never reached
  the host scanout. Same defect stranded a moved cursor's old sprite on
  the host. Fixed by folding the forced rects back into the published
  damage (see [`Graphics-Drivers`](../drivers/Graphics-Drivers.md#forced-invalidation--direct-to-live-writers),
  regression sentinel `tests/host/test_damage_bands.cpp`).
  Re-verify on the next VBox session WITHOUT triggering a guard
  prompt. VBox's default VBoxVGA/VBoxSVGA is a direct framebuffer (no
  present hook), where the blit alone was already sufficient — so if
  bleed is still observable *there*, a distinct second cause remains
  (cursor backing mismatch, a draw path bypassing `MarkDamage`, or a
  paint primitive writing to `g_info.virt` directly during compose).
  On QEMU `-vga virtio` the fix above is the expected cure.

When a residual ships, delete its bullet here and update the
[`Compositor`](../subsystems/Compositor.md) subsystem page's
"Deferred from Pass A" call-out.

### Chrome tactility (Pass B) — residual polish + Pass B verification

The first-impression moments plan
(`docs/superpowers/plans/2026-05-24-duetos-pass-b.md`)
landed all 25 tasks: boot splash with motion + phase ticker, animated
wallpaper with arc rotation / pulse / topo drift, login GUI with
backdrop clock + avatar card + atlas-shadow + focus-glow password
field + sign-in button. See
[`Compositor`](../subsystems/Compositor.md#first-impression-moments-pass-b)
for the subsystem summary.

QEMU verification complete (2026-05-24): all Pass B self-tests fire
(`[splash-selftest] PASS`, `[wallpaper-motion-selftest] PASS`,
`[login-gui-selftest] PASS`, `[pass-b-selftest] PASS`); the
boot-log-analyzer PASS B section reports `splash=1 wallpaper-motion=1
login-gui=1 umbrella=1 probe fires=0`; no Pass A regressions;
soak reports zero wallpaper/splash/login errors, zero real soft-lockup
warnings, zero compositor missed ticks.

The residuals waiting on visual verification:

- **VBox boot verification.** Pairs with the Pass A VBox residual
  above. Same approach: boot the matrix under VirtualBox after QEMU
  verification; LAPIC / GS-base differences from QEMU sometimes catch
  what QEMU doesn't. Run after the Pass A VBox verification is cleared.
- **Screenshot matrix for splash / login surfaces.** The
  `tactility-screenshot-matrix.sh --splash --login --wallpaper`
  invocation from the spec §10 criterion 1 requires QEMU PPM capture
  (`-screendump`), which is infra-limited in the headless WSL dev
  environment. Cleared automatically when VBox visual verification runs
  (the GUI boot produces the visible frames the spec calls for).

Follow-on items surfaced during live VBox testing of Pass B:

- **Mouse-click positioning under headless QEMU rel-mode.**
  `tools/test/qmp-click.sh` ships in two modes — `abs` for display
  setups and `rel` for headless. The rel-mode "snap to origin via
  Δ=-65535 then move by (X, Y)" pattern is reliable for the snap part
  but the move-by-(X,Y) sometimes doesn't fully propagate through the
  PS/2 driver under fast successive calls (observed: cursor stays at
  origin after a click on (400, 400)). Needs a per-call settling
  delay or per-axis ack from the kernel-side PS/2 ringbuffer; for now,
  treat headless QEMU mouse-click as best-effort and re-issue if the
  cursor doesn't land. Abs-mode users (real display, `usb-tablet`)
  are unaffected.

When a residual ships, delete its bullet here and update the
[`Compositor`](../subsystems/Compositor.md) subsystem page's
"Deferred from Pass B" call-out.

### Chrome typography (Pass C) — residual polish + Pass C verification

The typography hierarchy plan
(`docs/superpowers/plans/2026-05-24-duetos-pass-c.md`)
landed all 21 planned tasks plus 5 settings sub-panel migrations + 1
drive-by comment fix (27 commits total). New module
`kernel/drivers/video/chrome_text.{h,cpp}` owns the four-tier
dispatch (Display 72 px / Title 16 px / Body 13 px / Caption 11 px),
with Regular + Bold weights backed by Liberation Sans Regular and a
newly-baked Liberation Sans Bold companion. Boot sentinels
`[chrome-text-selftest] PASS` and `[pass-c-selftest] PASS
(chrome-text=ok)` fire under the `if constexpr (kBootSelfTests)`
umbrella. See
[`Compositor`](../subsystems/Compositor.md#typography-hierarchy-pass-c)
for the subsystem summary.

Per-task verification: every implementation subagent ran a debug
boot smoke after its commit; all 21 tasks reported all three Pass C
sentinels green plus the bold-font load line, with no PANIC / TRIPLE
/ new non-deliberate FAIL. The `pass-c-soak.sh` 30 s rig (Task 19)
PASSed against commit `ad680846`. Full end-to-end acceptance run
(debug + release builds, hosted ctest, soak, screenshot matrix,
clang-format on all touched TUs together) is **deferred — pending
host disk space** at the time of branch wrap (WSL vhdx couldn't grow
on a 29 MB-free C:). Re-run once disk is freed; expected to be clean
based on per-task evidence.

Residuals carried into Pass D / future polish:

- **Bitmap themes collapse Caption to Body at scale 1** (both =
  8 px). Acceptable v0 — bitmap font is single-size; the role split
  is recovered automatically on any TTF theme. Add a 6×8 micro-font
  asset if a bitmap-theme reviewer reports the visual collapse is
  confusing.
- **No italic, no Thin / Medium / Heavy weights.** Intentional v0
  omission. Extend `ChromeTextWeight` + bake the asset when a design
  need lands.
- **VBox boot verification.** Pairs with the Pass A / Pass B VBox
  residuals above — boot the typography matrix under VirtualBox to
  pick up anything QEMU smokes don't. The
  `tactility-screenshot-matrix.sh --typography` rig (Task 18) is
  the canonical surface set (login + lock + wallpaper × 10 themes
  = 30 PPMs) once the host can rebuild the kernel.elf.
- **Avatar monogram is Title Bold** — fits the 40 px circle today.
  If avatar grows above ~40 px or shrinks below ~24 px, the Bold
  Title metric may need a dedicated "hero monogram" role between
  Display and Title.

When a residual ships, delete its bullet here and update the
[`Compositor`](../subsystems/Compositor.md) subsystem page's
"Pass C — Typography Hierarchy" call-out.

### App widgets (Pass D) — residual polish

The app-widgets plan
(`docs/superpowers/plans/2026-05-25-duetos-pass-d.md`)
landed the library at
`kernel/drivers/video/app_widgets/{widget.h,widget_group.h,
app_button.{h,cpp}, app_label.{h,cpp}, app_panel.{h,cpp},
app_divider.{h,cpp}, app_list_row.{h,cpp}, app_toolbar.{h,cpp},
app_input.{h,cpp}, app_scrollbar.{h,cpp}, self_test.{h,cpp}}`
plus 28 per-app migrations and the acceptance scaffolding
(`tools/test/pass-d-soak.sh` 60 s regression guard,
`tactility-screenshot-matrix.sh --apps` mode). Boot sentinels
`[app-widgets-selftest] PASS` and
`[pass-d-selftest] PASS (widgets=ok, apps=28/28)` fire under the
`if constexpr (kBootSelfTests)` umbrella. See
[`AppWidgets`](../subsystems/AppWidgets.md) for the subsystem
reference and
[`Compositor`](../subsystems/Compositor.md#app-widgets-pass-d)
for the integration summary.

Per-task verification: every implementation subagent ran a debug
boot smoke after its commit; all 28 app migrations report their
per-app sentinel green plus both umbrella sentinels, with no
PANIC / TRIPLE / oom-slab-fault. The `pass-d-soak.sh` 60 s rig
PASSes against commit `5dd79097` (28/28 apps green + Pass A/B/C
umbrellas all green + no soft-lockups).

Residuals carried out of Pass D:

- **Apps not migrated** — six `.cpp` files under `kernel/apps/`
  intentionally stay on raw paint (or have no paint surface):
    - `dbg.cpp`, `dbg_core.cpp` — debug overlays must work when
      half the kernel is wedged; raw paint by design.
    - `gfxdemo_modes.cpp`, `gfxdemo_modes_vk.cpp` — the demos
      exercise primitive APIs directly; widget chrome would
      defeat the demonstration.
    - `notes_persist.cpp` — pure data layer; no paint surface.
    - `trash.cpp` — facade module providing Files' trash mode;
      no chrome of its own.
  Don't migrate these without a compelling reason; the carve-out
  rationale is documented in
  [`AppWidgets`](../subsystems/AppWidgets.md#carve-outs).
- **Carve-outs preserved (raw paint regions inside migrated
  apps)** — Files' folder/list grid, Calendar's month/week/day
  cells, Terminal's cell grid, Hexview's byte grid,
  Gfxdemo's content region, Dbg_render's overlay layer all
  paint raw. Each app's `RenderContent()` runs after
  `group.PaintAll(compose)` into the carved-out rect; the
  widget group owns the chrome only. This pattern is the
  recommended shape for future apps with fixed-grid surfaces.
- **VBox visual verification** — pairs with the Pass A / Pass B /
  Pass C VBox residuals above. Boot the
  `tactility-screenshot-matrix.sh --apps` 3 surfaces × 10 themes
  = 30 PPM reference set under VirtualBox to pick up anything
  QEMU smokes don't.
- **Per-app window screenshots deferred to VBox.** The
  `--apps` matrix mode captures three chrome surfaces (login,
  wallpaper, lock) per theme because qmp.sh can't open
  Calculator / Notes / etc. headlessly — QMP key+click driving
  the Start menu isn't implemented (qmp.sh supports
  `screendump` / `powerdown` / `quit` / `status` only). When
  full per-app shots become valuable, either extend qmp.sh
  with a `keys` / `click` subcommand routed through QMP
  `input-send-event`, or capture them manually under VBox.
- **gfxdemo legacy sentinel.** Predates the
  `[<app>-selftest] PASS` convention and emits
  `[gfxdemo] self-test OK (sin LUT, FxMul, PRNG, Mandelbrot,
  chrome)` instead. `pass-d-soak.sh` accepts either form;
  next time gfxdemo gets touched, normalise its emission to
  the standard sentinel and drop the soak's special case.

Potential Pass E items (deferred — none of these are committed):

- **Layout managers** — today every widget gets explicit
  `Rect bounds` set at construction. A `VBox` / `HBox` /
  `Grid` layout manager would compute bounds from constraints
  + content size, eliminating manual coordinate maths.
- **Extended widget set** — `Checkbox`, `Slider`, `Progress`,
  `Tabs`, `Tooltip`, `Spinner`, `RadioGroup`. Each is one
  widget pair following the existing shape.
- **Event-routing hub** — today every app calls
  `group.DispatchEvent(event)` directly from its mouse /
  keyboard reader. A hub that knows about window focus +
  z-order would route automatically (the window manager
  already does this for chrome; widgets could plug in).
- **Animation system** — Pass A's tactility uses
  static shadow textures; an animation hook (interpolate
  state.flags transitions over N ms) would let press / hover
  feel kinetic without each widget hand-rolling it.

When a residual ships, delete its bullet here and update the
[`AppWidgets`](../subsystems/AppWidgets.md) subsystem page.

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

### Suspend-to-RAM (S3 / S0ix)

Consolidated S3 / S0ix wake-vector + context save/restore
residual. The GPE `_Qxx` / `_Lxx` / `_Exx` dispatch half of this
entry landed 2026-05-26 (EC query-byte read +
`env-monitor`-task GPE walker — see "Battery + ACPI suspend"
above). What remains: the trampoline blob below 1 MiB, CPU /
device context save/restore via `kernel/arch/x86_64/acpi_wakeup.{S,cpp}`,
and the per-driver Suspend/Resume callback contract in a new
`kernel/power/` subsystem. Research notes document the FACS
wake-vector handshake, the trampoline mode-transition sequence,
and the device-state save surface. (ACPI S5 soft-off incl.
`_PTS`/`_GTS` in §7 order, reboot chain, and lid/AC/battery
*state* reads all landed — see the Battery row above.)

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
| T5-01 | mm | P1 | Full `STATUS_GUARD_PAGE_VIOLATION` delivery to userland for `PAGE_GUARD` pages — **now unblocked** (T6-02 x64 SEH landed). v0 silently re-arms the guard (the next write succeeds); the reserve/commit split + protection bits + `VirtualQuery` already shipped. | A PE relying on the guard-page exception (not just silent stack-grow) sees `STATUS_GUARD_PAGE_VIOLATION`. |
| T5-03 | mm | P2 | Real KASLR in the UEFI loader (memory-map scan, random 2 MiB-aligned base in a 64 MiB window, boot-info handoff, boot-log report). **Same work as Linux-CVE Class II follow-up.** | Two cold boots show different kernel `.text` load addresses. |
| T6-05 | win32 | complete — 2026-07-26 | MSVC x64 C++ EH now captures the caller's complete aligned `CONTEXT`, validates bounded PE unwind metadata, restores GPR/XMM state, binds by-value and reference catches from the correct HandlerType metadata, and defers catch execution to `TARGET_UNWIND` so crossed-frame destructors run first. The `pe-runtime` QEMU profile passes scalar catch, class-reference catch, cross-frame destructor unwind, catch-all, TLS, SEH, and synchronization with 51/51 boot self-tests. Remaining extensions are non-trivial copy-ctor catch objects, FH4 compressed FuncInfo, ESTypeList, and rethrow. | `cxxeh_pe` prints all four subtest PASS markers, `[cxxeh] RESULT PASS`, and exits 0. |
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

1. **SEH + C++ exception handling.** Every `throw` currently terminates the
   process and `__try/__except` never runs. `ntdll_dispatch.c` already has
   real `RtlUnwindEx`/`RtlVirtualUnwind`; the kernel32 rows point at no-ops
   instead. **PROOF:** a PE that throws and catches, including a destructor
   running during unwind, as a ring3 battery row.
2. **`.rsrc` (PE resource) parser.** Needs no kernel change — every section
   is already mapped. Unblocks `LoadStringW` (82 binaries measured),
   `LoadImageW`, icons, cursors, accelerators, dialog templates.
3. **Side-by-side DLL loading.** A PE importing a DLL shipped beside it has
   no path at all today. The Unity launchers measure 98.5% import coverage
   with exactly ONE unresolved import (`UnityPlayer.dll!UnityMain`). Needs
   exe-directory tracking, recursive import resolution, guard scanning of
   disk-loaded DLLs, and the same path reused by runtime `LoadLibrary`.
4. **Dialog manager.** [dep: 2] Template-driven dialogs, modal loop,
   standard controls.
5. **Real COM.** Registry-backed CLSID to DLL resolution, `IUnknown` /
   `QueryInterface`, apartments, in-proc servers. `ole32.c` is 32 exports in
   one file today. Gates installers, shell integration and most DirectX
   device-creation paths — the largest multiplier left after 1-3.
6. **Delay-load imports.** `ResolveDelayLoadedAPI` / `DelayLoadFailureHook`
   were deliberately skipped once because they need `GetProcAddress`, which
   lives only in the thunk page and is not linkable from kernel32.
7. **PE TLS callbacks.** The TLS directory callback array is never run.
8. **SxS / assembly manifests.** Many installers and MFC apps depend on it.
9. **Console completeness.** Screen buffers, VT sequences, real
   `ReadConsoleInput`.
10. **Fibers.** Real fibers, not the current `Tls*` aliases.
11. **.NET spike.** [dep: 3, 5] Do NOT write a CLR. Determine whether
    CoreCLR can be hosted as a guest PE — that converts a multi-year feature
    into a compatibility problem already being solved. **PROOF:** a managed
    hello-world runs, or a written account of the exact blocker.

### Tier 2 — graphics and media

12. **Off-screen surfaces.** The compositor has no concept of one, which is
    what blocks memory DCs, bitmaps, blits and DIB sections across GDI.
13. **Font pipeline.** Enumeration, fallback, metrics, antialiasing.
14. **GDI completeness.** [dep: 12] Paths, regions, transfer modes.
15. **D3D9.** Large back catalogue; simpler than 11/12.
16. **D3D11 completeness** and **D3D12** beyond the current thunk layer.
17. **DirectWrite / Direct2D.** [dep: 13]
18. **Vulkan ICD completeness** — real pipelines, render passes, swapchain.
19. **Hardware video decode.**
20. **XAudio2 / WASAPI real mixing.** [dep: 21]
21. **Audio depth** — USB audio class, HDMI/DP audio, per-stream volume,
    resampling.
22. **DirectInput / XInput** bound to real HID devices.

### Tier 3 — hardware needed to be a daily driver

23. **Power management.** `kernel/power/` contains only `reboot.cpp`. S3 /
    S0ix suspend-resume and the wake path. ACPI is already parsed. A laptop
    that cannot sleep is not a daily driver.
24. **CPU frequency scaling.** P-states, EPP, idle governors.
25. **`ReadMsrSafe`.** A ~20-line fault-tolerant `rdmsr` mirroring the
    existing `wrmsr` template in `msr_safe.S`. Every MSR consumer currently
    defends with static vendor+hypervisor gating because a bad `rdmsr` is
    unrecoverable. Cheap unlock for AMD CPU temperature on this dev box.
26. **Thermal + battery policy.** [dep: 25]
27. **TPM 2.0 — sealing half only.** Seal / unseal / PCR-measure / hardware
    RNG, and deliberately NO endorsement-key export, NO quote signing, NO
    attestation protocol. Enforced by capability, so a guest PE is
    structurally unable to obtain a stable hardware identifier.
28. **Full-disk encryption.** [dep: 27] Key sealed to PCR state, so no
    passphrase on every boot.
29. **Measured boot as a LOCAL tripwire.** [dep: 27] Detection without
    reporting — the two are separable and we implement only the first.
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
