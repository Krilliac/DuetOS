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

- **Residual:** per-CPU runqueue head/tail live in `cpu::PerCpu`,
  but every mutation still serialises on one global
  `g_sched_lock`. Split it per-CPU so steady-state contention
  drops to local-only `Schedule()` calls; wake paths take the
  target CPU's lock briefly; work-stealing uses the existing
  try-lock primitive (`SpinLockTryAcquire` /
  `SpinLockTryAcquireFor` / `SpinLockTryGuard`,
  `kernel/sync/spinlock.h`) to avoid AB/BA deadlock.
- **Blocks on:** nothing technical — deferred until a profile
  shows contention on `g_sched_lock`. For most workloads the
  global lock is acceptable.
- **Cascading items unlocked when this lands:**
  - Index the lockdep / event-trace / soft-lockup `g_per_cpu`
    arrays by current-CPU ID (currently keyed on `g_per_cpu[0]`
    aliases).
  - SMP-stress versions of the RwLock + SeqLock + KMailbox
    contention self-tests.
  - MLFQ priority bands (the T8-01-followon row) — band-aware
    enqueue/steal becomes a one-slice add-on once the lock is
    per-CPU.
  - Buddy coalescing + per-CPU lock-free allocator fast paths
    (frame warm-pool / slab magazine) — correctness is already
    in place under one global allocator lock; this is the
    scalability follow-on.
  - Move LAPIC-divider + tick-frequency programming out of
    `arch::TimerInit` into `time::TimerConfigure(hz)` once an
    ARM64 / generic-timer backend justifies the abstraction.

### Lockdep held-set must be per-task, not global

- **Residual:** `kernel/sync/lockdep.cpp` keeps the held-class
  stack in a single global array (`g_per_cpu[0]`). Correct for
  spinlocks (can't be held across a context switch) but **wrong
  for sleeping `sched::Mutex`**: two tasks each correctly holding
  a different sleeping mutex across a yield are reported as a
  lock-order inversion (observed: compositor↔fat32, ~40×/boot,
  no real cycle). Per-CPU indexing (the B2 cascading item) does
  not fix this — a task holding a sleeping mutex can resume on a
  different CPU, so the held-set must follow the *task*.
- **Approach:** give each `Task` its own held-stack and swap it
  at the context-switch boundary; spinlock classes stay on a
  per-CPU stack, mutex classes move to the per-task one. Avoid
  threading a `Task*` through every lockdep hook (reintroduces
  the lockdep↔sched recursion the TU header avoids).
- **Attempt 1 reverted (2026-05-17):** the minimal form
  (`LockdepHeldSnapshot` before `ContextSwitch`,
  `LockdepHeldRestore` at the top of `SchedFinishTaskSwitch`)
  was correct on one long boot but a 6-boot determinism sweep
  (`tools/test/boot-determinism-sweep.sh`) caught an
  **intermittent** hard panic on the AP-bring-up path
  (`KASSERT WaitQueueBlock on non-Running task`). Root: the
  restore was inserted *above* the existing not-yet-armed-AP
  guard, so `Current()` deref'd a partial `PerCpu` on a fresh
  AP. (The nearby `[ubsan] tm-detail PerCpu/u32/Task` lines are
  pre-existing benign noise, ~4×/clean boot — not the signal.)
- **Attempt 2 — LANDED (snapshot/restore half):** the per-task
  carry is now wired per the constraints above. `Task` owns
  `lockdep_held[kLockdepHeldMax]` + `lockdep_held_depth`
  (`kernel/sched/sched.cpp`); `ScheduleLockedHandoff` snapshots the
  outgoing task's held set just before `ContextSwitch`;
  `SchedFinishTaskSwitch` restores the resumed task's set *after*
  the fresh-AP `lock_ptr == nullptr` guard, gated on
  `self != nullptr && self->state == TaskState::Running` (exactly
  the attempt-2 design constraint — the held-set now follows the
  *task* across a cross-CPU resume, so the compositor↔fat32 false
  inversion from a sleeping mutex held across a yield no longer
  fires). Fresh tasks are seeded `[kLockClassSched], depth=1` so
  the first `SchedFinishTaskSwitch` pop balances.
- **SMP `release out-of-order` symptom — RESOLVED (2026-05-19):**
  the occasional `sync/spinlock : release out-of-order` line under
  4-CPU churn was NOT caused by the held-stack storage design — it
  was a symptom of the SMP cross-CPU corruption that also drove the
  "SMP task double-run" item (now deleted, fixed in the same
  slice). Root: an AP ran kernel code with a non-kernel GSBASE
  (`LoadGdtForCurrent`'s `mov %gs` zeroed `IA32_GS_BASE` and the
  AP's per-CPU pointer was written *before* that, not after), so
  `cpu::CurrentCpu()` silently returned the BSP slot and the AP
  read/wrote the BSP's `g_per_cpu[0]` held-stack alias (plus
  `current_task` / the `ctxsw_lock_to_release` lock-pass slot).
  Compounded by APs never executing `lidt` (no per-CPU IDTR), which
  triple-faulted them on the first timer tick. Fixes: GSBASE +
  KERNEL_GS_BASE now programmed *after* `LoadGdtForCurrent`;
  `IdtLoadForCurrent()` added to the AP path; `cpu::CurrentCpu()`
  resolves the real CPU by LAPIC ID instead of assuming BSP, with a
  gated `kCurrentCpuGsbaseFallback` probe + count sentinel
  (`OnTimerTick`) so any future swapgs/AP-GS regression is caught.
  Gated by a 6-boot determinism sweep (3/3 APs online, byte-stable,
  zero panic/triple/fallback) + a 6/6-clean `gui-fuzz.sh 18` SMP
  matrix. `g_promote_to_panic` may now be reconsidered.
- **Per-CPU held-stack storage — LANDED (2026-05-22).** The
  global `g_per_cpu[0]` alias is gone. `kLockdepCpuMax =
  acpi::kMaxCpus`, each CPU indexes its own slot via
  `cpu::CurrentCpuIdOrBsp()`, and the re-entry guard
  (`PerCpuHeld::in_lockdep`) moved into the per-CPU struct too.
  `LockdepCriticalSection` reads the slot AFTER `Cli` so a
  migration can't corrupt a peer's slot. The shared edge graph
  + counters use `__atomic_fetch_or` (bit) and `SatAtomicAdd`
  (counters) for cross-CPU safety. Verified with 5/5-clean
  `tools/test/smp-stress-sweep.sh 8 8 5` (release SMP=8) and
  no inversions in the lockdep self-test under the new
  storage layout.
- **Residual (architectural cleanup, no live failure):** the
  spinlock-vs-mutex class split. Today every `LockClass` lives
  in one per-CPU stack; with the per-task `Task::lockdep_held`
  snapshot/restore wired underneath, sleeping-mutex classes
  technically ride the task across a switch via that buffer,
  while spinlock classes are protected by Cli (single CPU at a
  time). The two are not separately tagged at the API. A
  `LockClassSpin` / `LockClassMutex` tag would make the
  separation explicit so an audit can verify a sleeping-mutex
  class never appears on a per-CPU spinlock stack.
- **Blocks on:** a workload that produces a false inversion the
  per-CPU + per-task pair doesn't already absorb. None
  observed since 2026-05-22.

### SMP=8 saturation use-after-free (RIP=0xdededededededede)

- **Symptom:** booting `tools/test/smp-stress-sweep.sh 8 8 5`
  (release SMP=8) intermittently — about 1-2 of every 5 repeats —
  hits a kernel-mode #GP at the freed-poison RIP pattern:

  ```
  [panic-summary] subsystem=arch/traps msg="#GP General protection"
  rip       : 0xdededededededede  [wild: non-canonical ...]
  rbx, rbp, r12, r14, r15 : 0xdededededededede (all freed-poison)
  cs        : 0x08 (ring 0 kernel-code)
  cpu_id    : 0x02
  uptime    : 2.272s since boot
  ```

  The kernel jumped through a freed function pointer
  (`0xDE` = `kHeapFreePoison`, see `kernel/mm/kheap.cpp:39`).
  Several registers carry the same freed-poison pattern,
  indicating the call/jmp went through a struct field that was
  freed-then-poisoned but still referenced.
- **What's known:** the fault site is BEFORE the stress driver's
  workers do meaningful work — it lands just after
  `LOADTEST: spawned 8 / 8` and a few `[sched] {A,B,C} i=...`
  iterations from `SchedDemoWorkerTask`. So the use-after-free is
  on the boot-tail spawn path, NOT in the stress workload itself.
- **Reusable harness:** `tools/test/smp-stress-sweep.sh 8 8 10`
  reproduces at ~20-40% rate. The discovery harness is the
  panic-dump cleanup itself — without the serial-bypass +
  `WriteCurrentTaskLabel` guards that landed in the 2026-05-22
  slice, the RIP rendered as space-mixed bytes and the bug was
  invisible. Future investigation should start with the panic
  dump's kernel-stack trace (the dump prints
  `[fault-stack] stack@... <unreadable>` today because the rsp
  is in `k.stack-arena` but the dump-time AS doesn't have the
  frame faulted in — fix that first to get the call chain).
- **Likely shape:** a kobject / handle-table / iocp-style
  object's callback pointer outliving its owner under SMP. The
  surface-area suspects from the boot tail:
  - HandleTableDrain / ProcessRelease running concurrently with
    a peer that still has a handle in flight
  - `SchedExit` reclaiming a Task whose pointer a peer's
    runqueue still references
  - workpool's `WorkerCtx` freed while a peer worker is
    inside the callback
  Each of these has refcount machinery; the bug is likely a
  missing `KObjectAcquire` on one of the acquire paths.
- **Blocks on:** dumping the stack frames at the fault rsp
  (`tools/qemu/run.sh` can supply a GDB stub via COM2; attach
  with `tools/debug/duetos-gdb-attach.sh` once the fault fires
  and read the call chain). With the call chain visible the
  owning subsystem becomes apparent.

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
- **Bounded fix to land first (before chasing the race):** make
  the recursive-fault dump grab `g_serial_lock` with `try_lock`
  semantics (or take an `IrqFlags` snapshot once per AP) so the
  vec/rip survive the second fault. Without that the loop is
  diagnose-by-corruption. Then re-run the harness with that fix
  in tree to read the real first-fault site.
- **Blocks on:** the serial-bypass cleanup OR a per-CPU panic
  ringbuffer the AP fault path can write to (no serial contention).

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

### KMalloc slab routing + real KASAN

- **Residual:** (1) route small `KMalloc` calls through pre-built
  size-classed slab caches automatically (today opt-in via direct
  `SlabAlloc`); (2) **real KASAN** — shadow-memory mapping,
  compiler-plugin integration, per-access shadow lookup. Big
  lift; deferred until a use-after-free hunt needs it. (Slab
  allocator + freed-object poison landed.)

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
- **Larger refactor (deferred):** split into per-volume mutex +
  per-cache RwLock + lock-free FAT entry cache. Wants its own
  slice once the path-cache fast path + per-CPU scratch are
  measured.
- **Saturation harness:** `tools/test/fat32-concurrent.sh`
  spawns the linux-smoke synfs + win32 PE smokes concurrently
  and captures the boot log. Look for `fs/fat32 : lookup`
  line-rate vs `MutexLock waiter` parking lines as the
  contention signal.
- **Blocks on:** evidence that the path-cache fast path didn't
  close the live livelock corner. If a fat32-concurrent.sh run
  still shows the symptom, the per-CPU scratch + lock-drop
  refactor lands next.

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
   a `.exe` from a real NTFS partition. (NTFS metadata walker
   landed; the read path + NTFS *write* are separate items —
   write is **T7-04** below.)

### Crash-dump persistence — real-hardware verification

- **Residual:** an unforced panic on an installed laptop is the
  last step to graduate this from "shipped" to "lived through it
  once." The encode + transport layers (QEMU debugcon + in-RAM
  minidump + NVMe/AHCI reserved-region + installer
  `kDuetCrashDumpTypeGuid` partition) are all in tree and
  exercised every boot via `DiskPersistSelfTest`.

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
  4-way handshake + per-vendor upload + ring scaffolds all
  landed; 16 self-tests pass.)
- **Unlocks:** Network flyout SSID picker, Settings → Network →
  Wi-Fi tab, captive-portal handler.
- **Owner:** `kernel/drivers/net/wireless/`, `kernel/net/wireless/`.

### USB mouse — high-DPI real-hardware verification

- **Residual:** plug in a high-DPI USB mouse and verify the
  device-supplied HID Report descriptor produces the expected
  12/16-bit X/Y layout, button mask, wheel, and AC-Pan fields on
  real interrupt-IN reports. (Descriptor-driven decoding +
  injector + synthetic self-tests landed.)
- **Owner:** `kernel/drivers/usb/`.

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

- **Residual:** (1) S3 / S0ix suspend-to-RAM wake-vector +
  context save/restore; (2) GPE `_Qxx` AML query-method
  evaluation — the SCI detects + acks a GPE but dispatching the
  firmware's per-GPE `_Qxx` handler (lid-close / AC *event*
  delivery) needs the AML interpreter in process context off the
  woken worker plus an EC `_Qxx` read path (`ec.h` has none).
  Lid/AC *state* is already readable via `_LID`/`_PSR`. (Battery
  / AC / lid via EC + ACPI, SCI power-button path, and ACPI S5
  soft-off incl. `_PTS`/`_GTS` all landed.)

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

## Win32 / NT subsystem

### DirectX real device backends

- **Still gated:** HLSL bytecode execution (the `d3dcompiler.dll`
  frontend emits a DXBC-shaped blob the draw path ignores),
  texture sampling, geometry/hull/domain/compute shaders,
  multi-stream input, Z-buffer, D3D9 fixed-function lighting,
  real GPU command-ring submission.
- **Blocks on:** per-vendor GPU drivers landing real
  command-ring submission; D3D→Vulkan thunk wiring (the Vulkan
  ICD v0 lifecycle landed; the D3D side still returns `E_FAIL`
  and must redirect through the Vulkan path). (D3D9/11/12 COM
  vtables + shared software rasterizer + DXGI swap-chain present
  into compositor windows landed.)

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
  socket read path — see **IOCP consolidation** below);
  kernel-direct event signaling at the moment of socket activity
  (today's `WSAWaitForMultipleEvents` is a 10 ms polling loop);
  `fWaitAll == TRUE` semantics (current impl returns on first
  ready event). (Synchronous BSD subset + the `WSAEvent*` /
  `WSAEventSelect` / `WSAEnumNetworkEvents` async surface +
  kernel `SocketPollEvents` producer landed.)

---

## End-user features

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

### Suspend-to-RAM (S3 / S0ix) + GPE `_Qxx` dispatch

Consolidated single residual shared by the ACPI S5, Battery, and
power-management surfaces: (1) S3 / S0ix wake-vector + context
save/restore; (2) GPE `_Qxx` AML query-method evaluation off the
woken worker + an EC `_Qxx` read path. (ACPI S5 soft-off incl.
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

- **Blocks on:** code-signing infrastructure + A/B kernel-slot
  layout (state machine landed — see **A/B kernel slots** below).

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
| T6-05 | win32 | in progress — fault #1 fixed, fault #2 open | MSVC C++ EH (`__CxxFrameHandler3` + `_CxxThrowException`). Two distinct faults were conflated. **Fault #1 (FIXED 2026-05-18):** vcruntime140→ntdll imports (`NtRaiseException`/`RtlUnwindEx`/`RtlCaptureContext`) bound to a catch-all NO-OP because `kernel/proc/spawn.cpp` resolved each preloaded DLL's imports against only the DLLs loaded *before* it, and ntdll is listed after vcruntime140 in `preload_set[]`. Fixed by an order-independent cross-preload reconciliation pass (re-resolve every preloaded image against the full set once assembled). Verified: those imports now resolve via-dll; zero kernel regressions (120 self-tests pass, seh_try still PASS, boot-log-analyze OK). **Fault #2 (OPEN — real remaining blocker):** `cxxeh_pe` still faults `0xC0000005`. The kernel logs `[win32/seh] faulting rip val=0x23d8` and that value is the **raw trap-frame RIP = an absolute VA** (`seh_dispatch.cpp:196` logs `frame->rip` unmodified). `0x23d8` is a bare RVA inside cxxeh_pe `.rdata` EH-metadata (ThrowInfo/CatchableType, RVA 0x2300–0x2568). **Definitive conclusion: an FH3 transfer jumped to a bare `.rdata` RVA with `image_base` NOT added (or ==0)** — not import resolution, not a struct-layout bug (`catchblock_info`/`cxx_function_descr` x64 layouts verified correct in `vcruntime140.c:193-228`). **Three candidates, in `userland/libs/vcruntime140/vcruntime140.c`:** (a) `cxx_frame_handler` line 455 `funclet = image_base + cb->handler` with `disp->ImageBase` (line 395) wrong/0 — depends on how our ntdll's `RtlLookupFunctionEntry`/dispatcher fills `DISPATCHER_CONTEXT.ImageBase` for a Win32 PE; (b) line 456 `cont = cxx_call_funclet(...)` returning a bad continuation; (c) line 461 `RtlUnwindEx(frame, cont, …)` (our ntdll) mishandling `TargetIp`. **Next slice:** add gated DEBUG output (vcruntime140 must import `kernel32!WriteConsoleA` or a debug syscall — it has no print path today) dumping `disp->ImageBase`, `cb->handler`, `funclet`, `cont` for the first throw; one rebuild+boot identifies which is `0x23d8`. Reproduce with `DUETOS_SMOKE_PROFILE=pe-hello DUETOS_TIMEOUT=120 tools/qemu/run.sh`; grep `ring3-cxxeh-pe` / `[cxxeh] RESULT`. GAPs (post-unblock): copy-ctor catch objects, strict inner-frame dtor ordering, FH4 compressed FuncInfo, ESTypeList, rethrow. | A PE `try { throw 42; } catch(int){}` resumes in the catch and exits 0. |
| T7-04 | fs | P2 | Scoped NTFS write: create, write, truncate, delete, rename with MFT/index/journal/bitmap updates; no compression/encryption/ADS for v0. | PEs can perform basic writes to NTFS volumes. |
| T8-01-followon | sched | P1 | MLFQ priority aging/decay + work-stealing priority behaviour. `Process::win32_priority_class` is wired today; the scheduler ignores it. Rides on the per-CPU `g_sched_lock` split (B2-followup). | A high-priority thread preempts a low-priority thread within one 10 ms tick. |
| T10-04 | build | P2 | Extend hosted `ctest` to mirror the PE-parser contract (Result / string / syscall_error / cvt / text_hash / d3dcompiler / damage_rect / wild_address / disk_path / vfs_resolve / registry_path already wired). PE parser is kernel-only — use the algorithmic-contract pattern (re-state the routine inline, assert canonical cases) as primitives grow self-contained. | Host `ctest` covers Result + PE parser + VFS + registry + string helpers without QEMU. |

---

## Tier-1/2 follow-ups (next-slice integration points)

The kernel-side primitive is in tree for each; what's missing is
the per-call wiring.

### VirtIO — virtio-blk concurrency + IRQ

- **Lands:** (1) IRQ wire-up so consumers don't busy-poll for
  already-serviced I/O; (2) multiple in-flight descriptor chains
  so a second caller isn't fully serialised behind the first
  (depends on IRQ-driven completion first — the poll model
  tracks one chain). (Read/write/flush + per-device serialising
  mutex landed.)

### VirtIO — per-class polish

- **Lands:** virtio-blk concurrency + IRQ (above);
  virtio-console multiport (`VIRTIO_CONSOLE_F_MULTIPORT` +
  control-queue protocol); virtio-balloon inflate/deflate policy
  (the "when do we agree to give up memory?" half — spec
  dispatch is straightforward); virtio-input statusq for LED /
  force-feedback delivery (eventq + EV_REL + EV_ABS already
  landed — virtio-tablet absolute coordinates are converted to
  `MousePacket` deltas at the driver boundary so the unified
  one-source-of-truth pointer API stays intact);
  IRQ wire-up across rng/blk/net/console/balloon/input. (Every
  per-class probe v0 + RX/TX poll tasks landed.)

### IOCP — primitive consolidation

- **Lands:** (1) migrate the legacy
  `kernel/subsystems/win32/iocp_job.{h,cpp}`
  (`SYS_IOCP_CREATE/SET/REMOVE/CLOSE` 159–162) onto the newer
  KObject-shaped `IocpPort` (`kernel/ipc/iocp.{h,cpp}`) so
  per-process storage sits in `kobj_handles` alongside KMutex /
  KEvent — a re-routing patch in the four `SysIocp*` syscalls,
  the shapes are wire-compatible; (2) add `SYS_IOCP_POST`
  (`PostQueuedCompletionStatus`) — a thin Win32-shaped wrapper
  over the existing `IocpTryPost`. (The new KObject primitive +
  blocking `IocpWait` + self-test landed.)

### A/B kernel slots — installer + GRUB cfg

- **Lands:** (1) installer — `CmdInstall` writes the new kernel
  to `SlotKernelPath(Other(active))`, validates, then
  `BeginInstall` + `SaveVia(<fat32-writer>, &state)` so the new
  state persists on the ESP (the FAT32 writer callback is the
  only new code); (2) GRUB cfg — two menuentries, one per slot,
  with the active slot as `set default` and the matching
  `slot=a`/`slot=b` on each `multiboot2` line. (State machine,
  parser/writer, watchdog mark-healthy, callback-based
  persistence helpers landed.)

### PE-compat smoke — per-PE structured pass/fail

- **Lands:** a kernel-side aggregator that counts per-PE PASS
  lines and emits `[pe-compat-smoke] passed=N failed=M
  skipped=K`. Requires every smoke PE to standardise its PASS
  line (`[ring3-<n>-smoke] PASS` / `... FAIL <reason>`) — one
  small per-PE source edit; the aggregator watches the serial
  stream via the klog ring. (Per-API PASS/FAIL + the
  `[pe-compat-smoke] battery complete` anchor landed.)

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

- **DEFLATE / gzip / zip** — `kernel/util/deflate.{h,cpp}`,
  `gzip.h`, `zip.h`. Decompressors are the single richest fuzz
  surface (bit-level Huffman over attacker data, window
  arithmetic, decompression-bomb ratios). Highest priority.
- **ASN.1 / X.509** — `kernel/crypto/asn1.{h,cpp}`,
  `x509.{h,cpp}`. TLV length/recursion parsing of untrusted TLS
  certificates — classic OOB / stack-recursion territory.
- **TLS records/handshake** — `kernel/net/tls.cpp`
  (`TlsPeekRecord`, `TlsParseServerHello`,
  `TlsParseCertificateLeaf`, `TlsPeekHandshake`). Untrusted
  network bytes; feeds the ASN.1/X.509 path.
- **Image decoders** — `kernel/util/jpeg.cpp`, `png` (+
  `deflate`), `tga.h`. Untrusted file bytes; wallpaper / asset
  load path.
- **EDID / CEA-861** — `kernel/drivers/gpu/edid.cpp`,
  `cea861.cpp`. Untrusted monitor-supplied descriptor bytes;
  both already have `*_selftest.cpp` so a harness entrypoint is
  trivial.
- **AML interpreter** — `kernel/acpi/aml.cpp`, `aml_eval.cpp`.
  Firmware-provided bytecode the kernel *executes*; large
  attack surface, heavier harness (needs an ACPI namespace
  stub).
- **USB descriptors** — `kernel/drivers/usb/usb_class_desc.cpp`,
  `hid_descriptor.h`, `cdc_ecm.cpp`, `rndis.cpp`. Device-
  supplied (untrusted peripheral) configuration/HID-report
  descriptors.
- **Bluetooth HCI/HID** — `kernel/net/bluetooth/hci.h`,
  `hid.h`. Untrusted radio peer.
- **Disassembler** — `kernel/debug/disasm.cpp`. Decodes
  arbitrary code bytes on the crash-dump path; a decode bug
  there faults the post-mortem.

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
