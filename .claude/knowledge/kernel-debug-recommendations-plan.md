# Kernel & Debug Design Recommendations Plan

## Status (2026-04-27)

### Landed

| Commit | Effect |
|--------|--------|
| _A1-infra_ (commit `aba75cd`) | `kernel/core/init.{h,cpp}` registry: `Phase` enum (13 phases), `InitcallRegister`, `RunPhase`, `InitSelfTest` (3 phases × 1 callback + bad-arg + failing-callback paths). Self-test wired into `kernel_main` after `FaultDomainSelfTest`. `KERNEL_INITCALL` macro deferred until `_init_array` is invoked at boot — registration is by direct call today. Imperative `kernel_main` body NOT migrated; see plan A1 follow-up. |
| _A4_ (commit `6097eb0`) | `kernel/syscall/cap_gate.{h,cpp}` + `cap_table.def`: 15-row X-macro listing the syscalls whose authorisation reduces to a single static cap (kCapFsWrite/Read, kCapSpawnThread, kCapDebug, kCapInput, kCapNet). `SyscallGate(num, proc)` called by `SyscallDispatch` BEFORE any handler; missing cap → `RecordSandboxDenial(missing)` + `frame->rax = -1`. Self-test walks every row vs synthetic empty/trusted processes plus nullptr-proc + unknown-syscall paths. Existing in-handler `CapSetHas` checks remain (belt-and-braces); follow-up cleanup will remove the redundant ones. |
| _C2_ (commit `1039bfa`) | `kernel/mm/poison.h` central constants + helpers. `kheap` gained a 16-byte trailing red zone (`kHeapTrailerCanaryLo/Hi`) on every allocation; `KFree` verifies before flipping magic and panics with "trailing red-zone canary corrupt" on overrun. Existing leading magic + freed-payload `0xDE` poison stay. `frame_allocator::FreeFrame` and `FreeContiguousFrames` now stamp `kFreedPagePoison` (0xDE) across the full 4 KiB page before returning it to the bitmap. Self-tests extended to (a) verify a fresh allocation's canary, transiently corrupt + restore + re-verify; (b) allocate a frame, scribble, free, re-allocate the same frame, assert all 4 KiB read 0xDE. Slab freed-object poison (`kSlabFreedObjectPoison = 0xCC`) is reserved in `poison.h` for when a slab allocator lands. |
| _B1.1 Mutex_ (pre-existing) | `sched::Mutex` + `sched::Condvar` already implemented in `kernel/sched/sched.{h,cpp}` with FIFO hand-off, `MutexTryLock`, `CondvarWait` / `CondvarSignal` / `CondvarBroadcast` / `CondvarWaitTimeout`. The plan's "extend kernel/sync/" wording is a forward-looking convention; the existing implementation is correct and well-tested, so no migration was performed. New downstream code can use `sched::Mutex` until/unless a re-export layer is added. |
| _B1.2 RwLock_ (commit `cc4d716`) | `kernel/sync/rwlock.{h,cpp}` — multiple-reader / single-writer lock built on `sched::Mutex` + two `Condvar`s (one per role). Writer-preference fairness: new readers block when `waiting_writers > 0` to prevent writer starvation. Full Try/Acquire/Release matrix, RAII guards (`RwLockSharedGuard`, `RwLockExclusiveGuard`). `RwLockSelfTest` exercises every state-machine transition reachable from a single-task boot context (multi-reader, writer-blocks-readers, readers-block-writer, counter-zero invariants); contention paths fire only under SMP, deferred to a follow-up self-test once AP bringup lands. Self-test wired into `kernel_main` after `SchedStartReaper`. |
| _A3-infra_ (commit `2e889f9`) | `kernel/ipc/kobject.{h,cpp}` + `handle_table.{h,cpp}`: `KObject` base (refcount + type tag + destroy callback), `KObjectInit / Acquire / Release / Refcount / TypeName`. Per-process `HandleTable` (64 slots, slot 0 reserved as `kHandleInvalid`) with `Insert / Lookup / Remove / Duplicate / LiveCount / Drain`. Lookup supports type-tag check (or `KObjectType::Invalid` to skip). Duplicate calls `KObjectAcquire` for the destination. Drain calls `KObjectRelease` for every live slot — designed for process tear-down. Both self-tests verify refcount semantics, destroy-on-zero firing exactly once, capacity-overflow returns `OutOfMemory`, and cross-table duplication keeps siblings live. The infrastructure is purely additive — existing per-type Win32 handle arrays on `Process` and the Linux fd table keep working unchanged. |
| _A2-infra_ (commit `3aa495b`) | `kernel/time/clocksource.{h,cpp}` + `timekeeper.{h,cpp}`: `Clocksource` struct (function-pointer vtable: `read_ns`, `resolution_ns`, `monotonic`, `rating`); `ClocksourceRegister / Get / Find / SelectBest / Current / RefreshCurrent`; `time::MonotonicNs()` / `ResolutionNs()` accessors that delegate to the cached current source. HPET registered as the v0 monotonic source (rating 250) so new code can replace inline `HpetReadCounter * period_fs / 1e6` math with one accessor. Self-tests register two synthetic providers (one monotonic rating 100, one non-monotonic rating 200), assert SelectBest skips the non-monotonic, exercise FindByName + bad-arg paths, and verify HPET-backed MonotonicNs strictly advances across a busy-wait. Existing `DoNowNs` / `DoGetTimeFt` etc. are NOT migrated. |
| _D1-infra_ (commit `ed2a2c9`) | `kernel/sync/lockdep.{h,cpp}`: locking-order graph (256 classes × 256 outbound bits = 8 KiB BSS bitset) + 8-deep held-class stack + cycle detection. `LockdepRegisterClass / BeforeAcquire / AfterAcquire / BeforeRelease`; counters `InversionsDetected / EdgesRecorded`. Internal critical section is `pushfq + cli + g_busy` (NOT `sync::SpinLock` — the eventual integration target IS SpinLock and would recurse). Self-test exercises good-order acquire (no inversion), bad-order acquire (B→A after A→B → inversion detected), unclassified-skip path, and held-stack-overflow guard. NOT yet hooked into SpinLock / Mutex / RwLock — production integration is tracked as a follow-up. |
| _A4-followup_ (this commit) | Removed the redundant in-handler `CapSetHas` blocks for every syscall now in `cap_table.def`: `kernel/debug/bp_syscall.cpp` (SYS_BP_INSTALL/REMOVE), `kernel/subsystems/win32/file_syscall.cpp` (SYS_FILE_WRITE/CREATE/RENAME), `kernel/subsystems/win32/thread_syscall.cpp` (SYS_THREAD_CREATE), `kernel/subsystems/win32/dir_syscall.cpp` (SYS_DIR_OPEN), `kernel/subsystems/win32/window_syscall.cpp` (SYS_WIN_GET_KEYSTATE/CURSOR — also dropped the now-dead `InputCapAllowed` deception helper since the gate fires first), and the SYS_STAT + SYS_SOCKET_OP arms in `kernel/syscall/syscall.cpp`. Each handler keeps its `proc == nullptr` safety check and trusts the gate for cap enforcement. `cap_table.def` header comment updated: gate is now the sole authority for every listed row. |
| _A2-followup_ (this commit) | `kernel/syscall/time_syscall.cpp::DoNowNs` now reads `::duetos::time::MonotonicNs()` instead of inlining `HpetReadCounter * period_fs / 1e6`. Drops the `arch/x86_64/hpet.h` include from this TU. Boot ordering already places `time::TimekeeperInit` before any user-mode syscall is dispatchable, so this is a one-line forward with no ordering risk. |
| _B1.3_ (commit `9bf87d3`) | `kernel/sync/seqlock.{h,cpp}` — sequence-counter lock for read-mostly hot data. Even sequence = stable, odd = writer in progress; readers do an optimistic `BeginRead → load payload → EndRead` that retries on conflict without ever taking a lock or disabling IRQs. Writer side is serialised by an inner `SpinLock` and bumps `sequence` even→odd→even across the protected mutation. RAII writer guard (`SeqLockWriteGuard`); reader path is the canonical do/while-retry pattern documented in the header. Self-test covers parity transitions, quiet-lock convergence (no retry), odd-snapshot detection, mid-read writer-completion detection, and the guard. Wired into `kernel_main` after `SpinLockSelfTest`. Contention paths (multi-CPU writer/reader race) only fire under SMP — covered by a follow-up self-test once AP bringup lands. |
| _A4-followup_ (this commit) | `inspect syscalls caps` shell subcommand. Walks every row of `kSyscallCapTable` and writes `[inspect-sc-caps] row nr=N name=SYS_FOO cap=kCapX mask=0x...` to COM1, ending with a summary line. Read-only audit surface that lets an operator confirm the gate's policy without disassembling the dispatcher. Tied into `CmdInspectSyscalls` via `argv[2] == "caps"`; `INSPECT HELP` advertises the new variant. Files: `kernel/shell/shell_debug.cpp`. |
| _D1-followup_ (commit `4624981`) | `LockClass class_id` field on `SpinLock`; `SpinLockAcquire` / `SpinLockRelease` now call `LockdepBefore/AfterAcquire` / `LockdepBeforeRelease`. Untagged locks (default `class_id == kLockClassUnclassified`) bypass with a single compare-and-skip — zero overhead for the long tail. Five canonical class IDs (`kLockClassSched / KObject / KStack / PciConfig / Breakpoints`) declared in `lockdep.h`; `LockdepRegisterCanonicalClasses()` names them at boot so any inversion report prints readable strings. Tagged: `g_sched_lock`, `g_kobject_lock`, `g_kstack_lock`, `g_pci_config_lock`, breakpoints `g_lock`. Mutex / RwLock instrumentation deferred (their tagging story differs slightly — both rely on `sched::Mutex` internally, so naive hooks would double-count). |
| _D1-followup_ (this commit) | Two more global SpinLocks tagged: `cleanroom_trace::g_cleanroom_lock` (kLockClassCleanroomTrace = 0x06) and `net::wifi::g_lock` (kLockClassWifi = 0x07). `LockdepRegisterCanonicalClasses()` names them at boot. Brings the tagged-lock count to 7; the kernel-internal SpinLock graph is now classified end-to-end for everything that runs in the steady-state syscall path. |
| _A2-followup_ (commit `0406381`) | `time::RealtimeFiletime()` + `time::BoottimeNs()` added to `kernel/time/timekeeper.{h,cpp}`. `RealtimeFiletime` samples the CMOS RTC and runs the same Gregorian → 100-ns-since-1601 arithmetic that previously lived inline in `RtcToFileTime`. `BoottimeNs` is a v0 alias for `MonotonicNs` (CLOCK_BOOTTIME == CLOCK_MONOTONIC until suspend/resume exists); a separate accessor so callers that mean "boot time" don't have to be rewritten when the two diverge. `DoGetTimeFt` migrated to `time::RealtimeFiletime()`. `DoGetTimeSt` left in place because SYSTEMTIME's Win32-specific layout doesn't earn a slot in `time/` yet; tracked as a follow-up. `RtcToFileTime` retained in `time_syscall.cpp` for `DoStToFt` (pure ST→FT conversion, no RTC involved). |
| _A3-followup_ (this commit) | Added `::duetos::ipc::HandleTable kobj_handles` field to `core::Process`. Zero-initialised by default — until concrete `KObject` subclasses (`KMutex`, `KEvent`, …) land and route through it, the table stays empty and the existing per-type Win32 arrays remain authoritative. `ProcessRelease` now calls `HandleTableDrain(p->kobj_handles)` as part of teardown so any `KObject` references parked in the table get released cleanly even on abnormal exit. Bringing the unified table physically into `Process` first lets the next slice (concrete subclasses) land without touching every existing Win32 handle path. |
| _D5_ (commit `778ea97`) | `kernel/diag/ubsan.{h,cpp}` — UBSAN klog runtime answering the 14 most-common `__ubsan_handle_*` symbols (overflow / shift / oob / null / alignment / type-mismatch / unreachable / pointer-overflow / divrem / negate / load-invalid / builtin-invalid / nonnull-arg). Each handler emits one structured line `[ubsan] <kind> at <file>:<line>:<col>` via `klog` + serial and returns — visibility, not enforcement. Source-location structs are clang's documented ABI (`compiler-rt/lib/ubsan`). The kernel is NOT yet compiled with `-fsanitize=undefined`, so none of the symbols are reachable from real code today; the self-test (`UbsanSelfTest`) invokes the report path directly to confirm the runtime is linked in. Day a future debug preset turns the compile flag on, the runtime is already there. |
| _D6_ (this commit) | Caller-RIP tagging on every `kheap` allocation. `ChunkHeader::reserved` repurposed to `caller_rip`; `KMalloc` records `__builtin_return_address(0)` (KMalloc has external linkage so the attribution is stable). New `KernelHeapTopAllocators(out, capacity)` walks the heap in chunk-size steps and aggregates live chunks by RIP into a fixed-size table, sorted descending by bytes. New shell command `heap leaks` prints the top 16 RIPs through the embedded symbol table — `bytes count rip=0x... fn+offset`. Cost: 0 bytes overhead in the hot path (the field already existed). The heap walk is on-demand only. |
| _A2-followup_ (this commit) | `time::RealtimeBrokenDown(out)` + `time::BrokenDownTime` (16-byte ABI-compatible with Win32 SYSTEMTIME). `DoGetTimeSt` now samples through `time::RealtimeBrokenDown` instead of inlining the RTC + Zeller's-congruence DOW; the conversion math + a `static_assert` confirm the ABI shape match. The local `SystemTime` struct + `ComputeDayOfWeek` helper in `time_syscall.cpp` stay for `DoStToFt`/`DoFtToSt` (pure ST↔FT conversions, no RTC involved). |
| _D5-followup_ (this commit) | `x86_64-debug-ubsan` CMake preset added (inherits `x86_64-debug` + sets `DUETOS_ENABLE_UBSAN=ON`). New CMake option `DUETOS_ENABLE_UBSAN` adds `-fsanitize=undefined -fno-sanitize-trap=all` + defines `DUETOS_UBSAN=1` on both stage1 + final kernel targets. Daily builds stay on `x86_64-release`; the UBSAN preset is opt-in for runs that want compiler-emitted UB diagnostics resolved through the in-tree runtime. |
| _D1-followup_ (this commit) | `LockClass class_id` field added to `sched::Mutex` (zero = unclassified, default). `MutexLock` / `MutexUnlock` / `MutexTryLock` now call `LockdepBefore/AfterAcquire` and `LockdepBeforeRelease`. Try-lock only feeds the held-stack on the success path so a failed try doesn't record a never-acquired edge. `RwLock` and per-instance Mutex tagging follow in a separate slice; the infrastructure is in place. New shell command `inspect lockdep` prints `inversions=N edges=N` plus the canonical class-ID/name table — read-only triage surface mirroring `inspect syscalls caps`. |
| _D1-followup_ (this commit) | `LockClass class_id` field added to `sync::RwLock`; both shared and exclusive acquire/release paths now call `LockdepBeforeAcquire` / `LockdepAfterAcquire` / `LockdepBeforeRelease`. Try-acquire variants only record the held-edge on the success path. The inner `sched::Mutex` is intentionally NOT classified separately to avoid double-counting every RwLock acquire. Untagged RwLocks stay zero-overhead; per-instance RwLock users (the AddressSpace migration when it lands, etc.) get their tag in the slice that introduces them. |
| _E2_ (this commit) | KPTI / Meltdown investigation produced `.claude/knowledge/kpti-meltdown-investigation-v0.md`. Answer: **no, kernel is currently unmitigated**, but the threat is only material on pre-Cascade-Lake / pre-Zen CPUs that lack `RDCL_NO`. Modern targets (Tiger Lake / Zen 3 +) are inherently safe in silicon, so KPTI lands on a "real machine that needs it enters the test fleet" trigger rather than speculatively. Recommended next step is a 50-line `arch::CpuMitigations::needs_kpti` runtime check that reads `IA32_ARCH_CAPABILITIES.RDCL_NO`; the KPTI implementation itself is gated on that signal. |
| _A4-followup_ (this commit) | Three more rows added to `kSyscallCapTable`: `SYS_READ` (kCapFsRead), `SYS_SPAWN` (kCapFsRead), and `SYS_EXECVE` ((kCapFsRead | kCapSpawnThread) — the table's `(held & required) == required` check enforces multi-bit "all of" semantics). The corresponding in-handler `CapSetHas` / `RecordSandboxDenial` blocks were removed; the gate is now the sole authoritative check for these surfaces. The conditional cap surfaces (SYS_WRITE fd=1, SYS_PROCESS_OPEN foreign-PID, the cross-process VM read/write/protect/section-map family) are correctly left in their handlers — their authorisation depends on runtime arguments, not on the syscall number alone. Self-test in `cap_gate.cpp` already iterates every row, so the new entries are exercised at boot without code changes. |
| _E2-followup_ (this commit) | `kernel/arch/x86_64/cpu_mitigations.{h,cpp}` reads `IA32_ARCH_CAPABILITIES` (MSR 0x10A) gated on CPUID(7).EDX[29], decoding `RDCL_NO` / `MDS_NO` / `SSB_NO` / `TAA_NO` into a `CpuMitigations` struct with `needs_kpti` / `needs_mds_buf` / `needs_ssbd` / `needs_taa_flush` booleans. Probe wired into `kernel_main` immediately after `CpuInfoProbe`. Failure-to-detect paths (no leaf 7, no MSR support) keep every needs_X = true (conservative). One-line boot summary `[cpu] mitigations: ARCH_CAPS=<hex> kpti=<safe/needed> mds=... ssbd=... taa=...`. KPTI implementation itself remains trigger-gated per `.claude/knowledge/kpti-meltdown-investigation-v0.md`; the runtime signal is now in place to branch on. |
| _D6-followup_ (this commit) | `heap leaks watch <secs>` shell mode: take snapshot 1 (top 16 RIPs), sleep N seconds, take snapshot 2, print delta. Each row tagged `+NEW` / `=STBL` / `+GREW` / `-SHRK`. Two-snapshot model fits the shell's blocking command shape; spinning forever would need a background ticker we don't have. Re-uses the existing `KernelHeapTopAllocators` walk + a small `PrintHeapLeakRow` helper extracted from the original `heap leaks` path so both modes share formatting. Ctrl+C aborts the inter-snapshot sleep cleanly. |
| _A1-followup_ (this commit) | Incremental `kernel_main` → `RunPhase` migration: the four utility-primitive self-tests (Result / String / Hexdump / VaRegion) are now `InitcallRegister(Phase::Earlycon, ...)` lambdas, dispatched together by `RunPhase(Phase::Earlycon)`. KLogSelfTest stays at line 295 (it has to come BEFORE multiboot validation — every other line in the boot path uses klog). Slice is observationally a no-op — same callbacks run in the same order, just reached through the registry instead of by direct call. Demonstrates the registration → RunPhase pattern works under boot conditions; future slices can migrate further phases (PhysMem, Paging, Heap, …) one at a time. |
| _B1-followup_ (this commit) | `RwLockContentionSelfTest` + `SeqLockContentionSelfTest`. Both spawn kernel threads via `sched::SchedCreate` to exercise the actual blocking + retry paths on top of the state-machine paths the original self-tests already verify. RwLock test runs two scenarios: (a) main holds exclusive while spawned readers block on `readers_cv` and only acquire after main releases, (b) main holds shared while a spawned writer blocks on `writers_cv` and only acquires after main releases. SeqLock test runs a writer thread doing 200 short Begin/EndWrite cycles in parallel with the calling thread doing canonical retry-loop reads — verifies the reader observes at least one retry, that the `hi == lo + 1` payload invariant survives every successful read, and that both threads make forward progress. Cooperative single-CPU scheduling with `SchedYield` is enough to trigger the contention paths; SMP stress will arrive with B2. Both runs at boot after `SchedStartReaper`. |
| _D5-followup_ (this commit) | UBSAN preset verification end-to-end. Added `UbsanPresetSmoke` to `diag/ubsan.cpp`, conditionally compiled under `DUETOS_UBSAN=1`, that performs a deliberately UB signed-integer addition (`volatile int 0x7FFFFFFE + 0x7FFFFFFE`). Under the `x86_64-debug-ubsan` preset, clang's `-fsanitize=signed-integer-overflow` emits `__ubsan_handle_add_overflow`, which routes through the in-tree runtime and bumps `g_reports`. `UbsanSelfTest` checks the counter advances and prints "preset smoke OK" or a clear failure line. Also added `-fno-sanitize=function` to the UBSAN flag set in `kernel/CMakeLists.txt` — clang's umbrella `-fsanitize=undefined` includes function-type-mismatch CFI checks that need RTTI metadata the kernel deliberately doesn't build, so without this every callback dispatch (sched task entry, IRQ handler, syscall thunk) emitted an unresolved `__ubsan_handle_function_type_mismatch`. Both `x86_64-release` and `x86_64-debug-ubsan` presets now build clean. |
| _A3-followup_ (this commit) | First concrete `KObject` subclass: `KMutex` in `kernel/ipc/kmutex.{h,cpp}`. Embeds `KObject` as the first member (compile-time `static_assert(__builtin_offsetof(KMutex, base) == 0)`), wraps a `sched::Mutex`, tracks owner-task + recursion depth + creation tick. Lifecycle: `KMutexCreate` allocates through kheap + calls `KObjectInit` (refcount = 1); the type's `destroy` callback (`KMutexDestroy`) panics if the lock is still held at refcount=0 and `KFree`s the storage. `KMutexAcquire` / `KMutexRelease` provide a recursive-lock state machine that the future SYS_MUTEX_* migration can sit on top of. `KMutexSelfTest` runs the full HandleTable round-trip — Create → Insert → Lookup (right + wrong type-tag) → recursive acquire/release cycle → Remove → assert lookup-after-remove returns nullptr + LiveCount = 0 + destroy fired. Demonstrates the concrete-subclass + HandleTable pattern works end-to-end. Existing `Process::win32_mutexes` array keeps its own syscall surface; the actual SYS_MUTEX_* migration is a separate, larger slice (Win32 ABI semantics — kWaitObject0 / kWaitTimeout, infinite waits, deadlock-detect callbacks — need careful unwinding from the existing per-type array). |
| _A3-followup_ (this commit) | Second + third concrete `KObject` subclasses: `KEvent` in `kernel/ipc/kevent.{h,cpp}` and `KSemaphore` in `kernel/ipc/ksemaphore.{h,cpp}`. KEvent supports both manual-reset (Set wakes all, stays signaled until Reset) and auto-reset (Set wakes one, atomically clears) semantics — the Win32 / POSIX-condvar equivalents. KSemaphore exposes counted permits with a hard `max_count` cap (Release that would overflow panics; v0 fail-loud over silent corruption). Each subclass: `KObject` embedded as first member, `sched::Mutex + Condvar` for the wait path, `KMalloc`/`KFree` lifecycle, type-specific destroy callback. Self-tests round-trip through HandleTable on the manual-reset event + the (initial=2, max=2) semaphore — Create → Insert → Lookup (right + wrong type-tag) → state-machine cycle → Remove → assert LiveCount=0. KMutex / KEvent / KSemaphore now form the core IPC trio; KMailbox / KWaitable remain reserved KObjectType enumerators. The legacy `Process::win32_events` / `win32_semaphores` arrays keep their own syscall surface — actual SYS_EVENT_* / SYS_SEM_* migration lives with the deferred SYS_MUTEX_* migration as a single Win32-ABI-preserving slice. |
| _D1-followup_ (this commit) | Two more per-instance Mutex users tagged: `kLockClassFat32 = 0x08` for `g_fat32_mutex` (FAT32 driver — serialises every block-IO + path-walk) and `kLockClassCompositor = 0x09` for `g_compositor_mutex` (per-frame widget tree walk + dirty-region accumulation + framebuffer flushes). Each tag explains its acquire-ordering position relative to the existing canonical classes. `LockdepRegisterCanonicalClasses()` names them at boot; lockdep can now report inversions like `compositor -> sched` (which would mean the compositor held its mutex across a scheduler-touching call — a real bug). Brings the named-class roster to 9 entries; further per-instance tags land as new global Mutex / RwLock instances appear. Designated-initializer form `{.owner = nullptr, .waiters = {}, .class_id = X}` keeps `-Wmissing-field-initializers` clean. |
| _A3-followup_ (this commit) | Fourth concrete `KObject` subclass: `KMailbox` in `kernel/ipc/kmailbox.{h,cpp}`. Bounded-FIFO message queue: `KMailboxMessage` is a 32-byte fixed struct (u64 type + 24 bytes payload); the mailbox holds a `KMalloc`'d circular buffer of `capacity` slots. `Post` blocks when full, `Receive` blocks when empty; non-blocking `TryPost` / `TryReceive` variants for caller-decides-overflow patterns. Two condvars (`not_full` / `not_empty`) mean blocked producers and consumers never collide. Destroy frees both the slot buffer and the mailbox itself in the right order. Self-test exercises empty try-receive returns false → post + receive round-trip preserves message → fill to capacity → try-post returns false → drain in FIFO order → HandleTable round-trip with right + wrong type-tag. Brings the IPC primitive set to 4-of-5; KWaitable (multi-object wait abstraction) remains. |
| _D4_ (this commit) | Soft-lockup detector — `kernel/diag/soft_lockup.{h,cpp}`. Distinct from the NMI watchdog: this catches a single task hogging the CPU while the timer IRQ is still firing (NMI watchdog catches the case where the timer IRQ has stopped). Mechanism: `SoftLockupTick(now_ticks, current_tid)` is called from the timer-IRQ tail (after `OnTimerTick`'s scheduler bookkeeping); tracks the most-recently-observed running TID + a counter of consecutive ticks with that TID; if the counter exceeds `kSoftLockupThresholdTicks` (~1 s on the 100 Hz tick), one klog warning fires per streak. Idle / kernel-boot tasks pass TID=0 which the detector ignores. `SoftLockupDisable()` is called from the panic path so a final warning doesn't drown out the crash dump. Self-test drives the state machine with synthesised inputs (idle skip, threshold trigger, rate limit, per-TID reset) — asserts the warnings counter advances by exactly 2 across the full test sequence. |
| _A1-followup_ (this commit) | Continue `kernel_main` → `RunPhase` migration: `Phase::PhysMem` (`FrameAllocatorSelfTest`) and `Phase::Heap` (`KernelHeapSelfTest`) self-tests now run through the registry. The init steps themselves (`FrameAllocatorInit`, `KernelHeapInit`) stay imperative because their inter-dependencies with the multiboot parse + the kernel heap region in linker.ld can't be expressed in phase membership alone — each needs explicit ordering w.r.t. the other. The verification step is the part that fits cleanly into the registry. Same shape as the Earlycon migration: register a lambda adapter, then `RunPhase(Phase::X)`. As more subsystems gain init() functions whose ordering IS expressible through phase membership, the imperative tail shrinks. |
| _A1-followup_ (this commit) | Third A1-followup slice: `Phase::Paging` (`PagingSelfTest`) self-test routes through the registry. `PagingInit` stays imperative — it adopts the boot PML4, enables NXE/SMEP/SMAP, and switches to higher-half — every step has an ordering constraint relative to other init code that phase membership alone can't express. Earlycon + PhysMem + Heap + Paging are now all on the registry; Idt / Apic / Time / Sched / Drivers / Vfs / Userland remain. |
| _D1-followup_ (this commit) | Inversion-promote-to-panic knob: `LockdepSetPromoteToPanic(bool)` + `LockdepPromoteToPanic()` accessors on `sync::lockdep`. When ON, any new inversion in `LockdepBeforeAcquire` calls `core::Panic` instead of just emitting a klog warning. Default off — a kernel boot under instrumentation can still complete with a noisy graph so an operator can collect evidence; CI eventually pins the knob ON. New shell command `lockdep panic on\|off` (admin-gated; an unprivileged caller flipping it ON could weaponise a known existing inversion to crash the box). `inspect lockdep` now prints `panic-on-invert=on/off` alongside the inversions/edges counters. |
| _A2-followup_ (this commit) | TSC clocksource (rating 300, outranks HPET's 250). Registered conditionally on `CpuHasInvariantTsc()` — CPUID 0x80000007 EDX[8] is the in-silicon "TSC doesn't drift across P/C-state" bit. Calibration counts TSC ticks across a 50 ms HPET-derived window; the resulting `g_tsc_freq_hz` lets the read-side convert TSC deltas to ns via a divmod form that avoids `tsc_delta * 1e9` overflowing u64 (which would otherwise happen at ~4.6 s of uptime at 4 GHz). On invariant-TSC silicon `ClocksourceRefreshCurrent` picks TSC; older / hypervisor-emulated CPUs fall back to HPET automatically. Boot log gains a `[time] tsc clocksource registered, freq_hz=N` line on success, `no invariant TSC; staying on HPET` on the fall-through. |
| _A1-followup_ (this commit) | Fourth A1-followup slice: `Phase::Idt` (`TrapsSelfTest`), `Phase::Apic` (`HpetSelfTest`), and `Phase::Time` (`ClocksourceSelfTest` + `TimekeeperSelfTest` + new `TickSelfTest`) self-tests now route through the registry. Earlycon + PhysMem + Heap + Paging + Idt + Apic + Time are all on the registry; only Sched / Drivers / Vfs / Userland remain imperative-only. The pattern is now fully proven across the early/mid boot path. |
| _A2-followup_ (this commit) | Portable scheduler-tick wrapper — `kernel/time/tick.{h,cpp}`. Exposes `time::TickCount()` (forwards to `arch::TimerTicks`), `time::TickHz()` (compile-time constant 100), `time::TickPeriodNs()`, plus `TicksToNs` / `NsToTicks` conversion helpers. Header-defined `constexpr` accessors stay zero-cost; only `TickCount()` is out-of-line. Self-test verifies the tick→ns→tick round-trip is lossless and that `TickHz * TickPeriodNs == 1e9`. Migration of existing `arch::TimerTicks()` call sites to `time::TickCount()` is a tracked follow-up — landing the wrapper first lets the second arch backend (ARM64 generic-timer) drop in cleanly. |
| _D1-followup_ (this commit) | Confirmed all global `sync::SpinLock` / `sync::RwLock` / `sync::SeqLock` instances in the tree now have canonical lockdep class IDs: 7 SpinLocks (sched / kobject / kstack / pci-config / breakpoints / cleanroom-trace / wifi) + 2 sched::Mutex (fat32 / compositor). Per-instance tagging campaign closes — the `audio_server` user mentioned in the original deferred entry doesn't actually have a global mutex (the audio TUs are lockless). Further per-instance tags land as new global lock instances appear; this entry can be considered "done for the v0 surface". |
| _A2-followup_ (this commit) | First call-site migration sweep from `arch::TimerTicks()` to `time::TickCount()`: `kernel/log/klog.cpp` (klog timestamp fallback), `kernel/util/random.cpp` (entropy seeding), `kernel/diag/runtime_checker.cpp` (runaway-CPU detector + scan loop), `kernel/net/stack.cpp` (network NowTicks). klog's tick-to-ms math also moves through `time::TickPeriodNs()` so the conversion no longer hardcodes "10 ms per tick". 4 portable / diagnostic call sites converted; ABI-shaped sites (Win32 mutex_syscall, Linux syscall_time, gfxdemo, custom.cpp) intentionally stay on `arch::TimerTicks` until their syscall surface itself is reviewed. |
| _A1-followup_ (this commit) | Fifth A1-followup slice: `Phase::Sched` self-tests through the registry — `RwLockSelfTest` + `SeqLockContentionSelfTest` + `RwLockContentionSelfTest` + the new `KMailboxContentionSelfTest`. Earlycon + PhysMem + Heap + Paging + Idt + Apic + Time + Sched are now on the registry; only Drivers / Vfs / Userland remain imperative-only. |
| _B1-followup_ (this commit) | KMailbox concurrency stress test — `KMailboxContentionSelfTest`. Spawns 4 producer × 4 consumer kernel tasks racing on a capacity-8 mailbox (small enough that producers actually hit the not_full condvar wait path). Each producer posts 50 messages; consumers TryReceive-with-yield until total received hits 200. Verifies: (a) producers + consumers all complete inside a 10 s budget (1000-tick poll loop), (b) per-producer received count exactly equals posted count (no lost / duplicated messages), (c) per-producer sequence numbers don't regress by more than one slot (multi-consumer races within ±1 are allowed; ≥2 backwards is a real out-of-order delivery and panics). Cooperative single-CPU scheduling is enough to surface a regression in the not_full / not_empty condvar wiring; SMP-stress arrives with B2. |
| _A3-followup_ (this commit) | Fifth and final concrete `KObject` subclass: `KWaitable` in `kernel/ipc/kwaitable.{h,cpp}`. Coordinates "wait until any of N independently-signaled conditions becomes true" (Win32 `WaitForMultipleObjects` shape). v0 design: caller registers up to `kWaitableMaxPredicates = 64` predicate functions (matching Win32's MAXIMUM_WAIT_OBJECTS); `WaitForAny` polls every predicate under the inner mutex, returns the lowest-index ready slot, otherwise blocks on a single condvar. Whoever changes underlying state calls `KWaitableSignal(w)` to broadcast a re-poll. Producers (KEventSet, KMailboxPost, etc.) are NOT modified to auto-notify — that would couple every primitive to every wait abstraction; full Linux-style wait_queue subscription chains land later if a workload demands it. Self-test exercises null-fn rejection, capacity-full path (fresh waitable filled to 64), single + multi-flag wait-for-any (lowest-index wins), and the HandleTable round-trip. Brings IPC primitive set to 5-of-5; KMailbox / KWaitable migration into SYS_* surfaces stays the deferred slice. |
| _A1-followup_ (this commit) | Sixth A1-followup slice: `Phase::Drivers` (`FramebufferSelfTest`) and `Phase::Vfs` (`VfsSelfTest`) self-tests through the registry. The Init steps stay imperative (FramebufferInit needs the multiboot info pointer; RamfsInit lays down the v0 root hierarchy + seed files in a specific order). Earlycon + PhysMem + Heap + Paging + Idt + Apic + Time + Sched + Drivers + Vfs are now all on the registry; only `Phase::Userland` remains imperative. The migration pattern is now applied across every distinct phase in the boot path. |
| _A2-followup_ (this commit) | Second call-site migration sweep — ABI-shaped sites: `kernel/core/panic.cpp` (uptime line in panic dump), `kernel/apps/gfxdemo.cpp` (frame timestamp; conversion now goes through `time::TickHz()` instead of hardcoded `/ 100`), `kernel/subsystems/linux/syscall_time.cpp` (`DoTimes` clock), `kernel/subsystems/win32/custom.cpp` (quarantine release-tick + drain). 4 more call sites converted; remaining: `kernel/syscall/time_syscall.cpp`, `kernel/shell/shell_hardware.cpp`, `kernel/subsystems/win32/mutex_syscall.cpp` (3 sites). Also dropped a small forward-declaration block in custom.cpp that was reaching into `arch::TimerTicks` directly. |
| _A2-followup_ (this commit) | Third and FINAL call-site migration sweep — every remaining `arch::TimerTicks()` use now goes through `time::TickCount()`: `kernel/syscall/time_syscall.cpp` (SYS_PERF_COUNTER backing — also dropped its arch:: forward-decl block + the stale `ComputeDayOfWeek` helper that became dead after the earlier `DoGetTimeSt` migration), `kernel/shell/shell_hardware.cpp` (`cpuid` shell command's TIMER TICKS line), `kernel/subsystems/win32/mutex_syscall.cpp` (Win32 mutex wait-time accounting × 3 sites — also dropped its arch:: forward-decl block), `kernel/diag/diag_decode.cpp` (pre-HPET fallback for the diag timestamp; the `* 10000` constant becomes `* (TickPeriodNs / 1000)` so the conversion is no longer hardcoded). Every consumer now goes through the portable `time::TickCount` wrapper; the day a second arch backend lands, the `arch::TimerTicks` forwarder is the only thing that has to change. |
| _A1-followup_ (this commit) | Seventh and FINAL `kernel_main` → `RunPhase` migration: `Phase::Userland` (`DllLoaderSelfTest` + `Win32CustomSelfTest`) self-tests through the registry. With this slice EVERY phase in the boot sequence — Earlycon / PhysMem / Heap / Paging / Idt / Apic / Time / Sched / Drivers / Vfs / Userland — has at least one self-test routed through the registry; the only remaining imperative tail is one-shot subsystem bring-up that doesn't have a SelfTest function (idle loop, heartbeat thread, etc.). The migration pattern is now fully proven across the boot path. |
| _D2_ (this commit) | Dynamic event tracer — `kernel/diag/event_trace.{h,cpp}`. Lockless single-writer ring of fixed-size 32-byte `EventRecord`s (tick + kind + arg0 + arg1) sized for 4096 entries (128 KiB BSS). Append path: atomic-RMW on the head index claims a slot; payload writes are followed by a compiler barrier and then the kind store, so a reader observing kind != 0 sees a fully-populated record. `EventTraceSnapshot` walks oldest-first into a caller buffer; if it observes a torn slot (kind == 0) it returns the count copied so far. 8 canonical `EventKind`s reserved (syscall enter/exit, sched switch, irq, page fault, mutex acquire/release, custom). Self-test verifies append + snapshot + tick monotonicity + kind-name resolution. The tracer is a passive surface; instrumentation points are added at the call sites that want them, not centrally. |
| _D2-followup_ (this commit) | `tracer dump` shell command (admin-gated through normal dispatch). Walks `EventTraceSnapshot` over the live ring, prints one row per event: `tick=N kind=NAME arg0=H arg1=H`. No filter knob in v0; `tracer kind <K>` lands when an investigation needs it. |
| _E1_ (this commit) | Intel CET probe — `kernel/arch/x86_64/cet.{h,cpp}`. Reads CPUID(7,0).ECX[7] for CET-SS support and CPUID(7,0).EDX[20] for CET-IBT support; stashes both in a global. Boot log gains `[cpu] cet: ss=<supported/absent> ibt=<supported/absent> (enable deferred to E1-followup)`. The actual mitigation enable (writing `IA32_S_CET`, allocating shadow stacks, recompiling with `-fcf-protection=branch`) is gated on the now-landed signal; lands as E1-followup when a workload demands it. |
| _D3_ (this commit) | PMU sample profiler — `kernel/diag/perf_profile.{h,cpp}`. Same ring shape as `event_trace` but for sampled RIPs (16-byte `PerfSample` of {rip, tick}; 4096 entries × 16 B = 64 KiB BSS). `PerfRecord(rip)` is single-fetch_add + 2 stores, designed to be cheap enough to call from inside a PMU NMI handler. Snapshot path matches event_trace's torn-slot gating (rip=0 = "writer in flight"). The actual NMI-driven sampling is NOT wired in this slice — landing the ring + dump first lets the future wiring be a one-line call to `PerfRecord(frame->rip)` from inside the existing NMI watchdog. |
| _B1.4_ (this commit) | Quiescent-state RCU — `kernel/sync/rcu.{h,cpp}`. Read-side `RcuReadLock`/`RcuReadUnlock` are zero-overhead compiler barriers; writers defer tear-down via `RcuCall(cb, arg)` which queues into a 256-slot ring under `arch::Cli`/`arch::Sti`. `RcuTick()` (called from `OnTimerTick`) increments a global tick counter; `RcuReclaim()` walks the queue and invokes any callback whose enqueue-tick is strictly less than the current tick. v0 grace rule: a single tick = a quiescent state (correct on BSP-only boot). Self-test queues a callback, asserts no-fire-before-tick, drives one tick + reclaim, asserts the callback fires exactly once. |
| _D2-followup_ (this commit) | `tracer kind <name>` filter — dumps only events whose kind matches one of the 8 canonical names (syscall-enter / syscall-exit / sched-switch / irq / page-fault / mutex-acquire / mutex-release / custom). Reuses the EventTraceSnapshot path; counts matched events for the operator. |
| _D3-followup_ (this commit) | `perf dump` shell command. Same shape as `tracer dump` but for PerfSnapshot, with each RIP resolved through the embedded symbol table (`util/symbols.h::ResolveAddress`) and printed as `name+0xoffset` — matches `heap leaks`'s formatting. Prints "(no samples; PMU NMI sampling not yet wired)" when the ring is empty, signalling the operator that the storage exists but the sampling source is still inert (D3-followup NMI wiring covers that). |
| _C1_ (this commit) | Memory zones scaffold — `kernel/mm/zone.{h,cpp}`. `Zone` enum (Dma / Dma32 / Normal / Mmio) + `AllocateZoneFrame(zone)` / `FreeZoneFrame(zone, frame)` API + per-zone `ZoneStats` (allocs / frees / oom). v0 forwards every non-Mmio zone request to the global frame allocator; Mmio always returns kNullFrame. The driver-facing API is in place so DMA-needing drivers can call `AllocateZoneFrame(kZoneDma32)` today; once a real per-zone pool exists (C1-followup), those calls start being honoured without any driver-side change. Self-test exercises every zone's allocate/free path + stats counters. |
| _E3_ (this commit) | Per-driver fault-domain extension — `kernel/security/driver_domain.{h,cpp}`. Thin convention layer over `core::FaultDomain*`: `RegisterDriverDomain(name, init, teardown)` adds a registration counter + driver-tag klog; `RestartDriverDomain(name)` resolves the name lookup + invokes `FaultDomainRestart`. Self-test registers a synthetic domain, drives Restart twice, asserts init/teardown counters advance + missing-name lookup returns `NotFound`. Existing drivers are NOT auto-registered — each opts in by calling `RegisterDriverDomain` from its own Init in a future E3-followup slice. |
| _D4-followup_ (this commit) | Soft-lockup detector restructured to per-CPU shape: `g_last_tid` / `g_same_tid_count` / `g_warned_for_tid` collapsed into a `PerCpuState` struct, `g_per_cpu[kSoftLockupCpuMax]` array (capacity 1 in v0 — BSP only). The `g_state` macro aliases `g_per_cpu[0]` so existing single-CPU code paths stay readable. Indexing by the current-CPU ID is the remaining work once SMP per-CPU storage exposes that ID; structural change is purely additive. |
| _A1-followup_ (this commit) | `_init_array` invocation wired at boot. New `.init_array` output section in `kernel/arch/x86_64/linker.ld` (between `.rodata` and `.data`, with `__init_array_start` / `__init_array_end` symbols KEEP'd). New `core::RunInitArray()` walks the range and invokes each function pointer in order. Called from `kernel_main` immediately after `KernelHeapInit` — heap is online for any constructor that allocates, but everything else (paging, IDT, scheduler, drivers) hasn't yet started so a constructor that touches them stays an unsupported pattern. Boot log shows `[init] _init_array: <hex_count> entries`; v0 count is typically 0 because kernel TUs use `constinit`. The `KERNEL_INITCALL` macro itself is the next follow-up — landing the invocation first means no behaviour change today but unblocks the macro work. |
| _B1-followup_ (this commit) | `AddressSpace::regions_lock` field added to `kernel/mm/address_space.h`. `MapUserPage` takes `RwLockExclusiveGuard` across the budget check + PTE write + TLB invalidate + region-table append — a single critical section so the budget check and the table append can never observe each other half-done. Today AS is single-Task and the lock is uncontended; the day a Process becomes multi-threaded (multiple Tasks per AS), this exclusive guard already serialises concurrent map/unmap callers correctly. Lockdep class tagging deferred until a second per-instance RwLock joins the system to compare against. |
| _B1-followup_ (this commit) | `time::ClocksourceCurrent()` / `ClocksourceRefreshCurrent()` now go through a `sync::SeqLock` (`g_current_lock`). v0 the clocksource pointer is the only protected field; an 8-byte pointer load is atomic on x86, so the SeqLock is forward-looking infrastructure for the day clocksource hot-swap publishes more state (e.g. invariant-TSC scaling factors that haven't been stamped into the source struct itself). Read path uses canonical `BeginRead` / `EndRead` retry loop; write path uses `SeqLockWriteGuard`. Single-CPU boot context retries at most once. |
| _A1-followup_ (this commit) | `KERNEL_INITCALL(phase, name, fn)` macro layer over `_init_array`. Macro emits a per-call `__attribute__((constructor))` thunk in an anon namespace; `core::RunInitArray()` invokes the thunk, which forwards to `core::InitcallAutoRegister(phase, name, fn)` → `core::InitcallRegister`. Subsystems can now register from file scope without modifying `kernel_main`; the dispatcher's `RunPhase(phase)` call still has to happen at the right point. The trailing NOTE in init.h that called the macro "intentionally absent rather than stubbed" is now resolved. |
| _D3-followup_ (this commit) | PMU NMI sampling is wired live. `NmiWatchdogHandleNmi` now takes `interrupted_rip` (passed from `traps.cpp`'s `frame->rip`) and calls `diag::PerfRecord(rip)` immediately after confirming the overflow is ours. Each watchdog-NMI now drops a sample into the perf ring; `perf dump` returns real data instead of "(no samples; PMU NMI sampling not yet wired)". The watchdog's existing pet-counter check + counter-reload path stay unchanged; sampling is a single fetch_add + 2 stores added before that work. |
| _D1-followup_ (this commit) | Lockdep held-stack restructured to per-CPU shape: `g_held_stack` / `g_held_depth` collapsed into a `PerCpuHeld` struct, `g_per_cpu[kLockdepCpuMax]` array (capacity 1 in v0). `g_held_stack` / `g_held_depth` macro aliases preserve the existing single-CPU code paths. Same shape as the D4-followup soft-lockup restructuring; indexing by current-CPU ID is the remaining work once SMP exposes that ID. |
| _D2-followup_ (this commit) | Event-trace ring restructured to per-CPU shape: `g_ring` + `g_total` collapsed into a `PerCpuRing` struct, `g_per_cpu[kEventTraceCpuMax]` array (capacity 1 in v0). Macro aliases preserve existing single-CPU code paths. Each future CPU's state stays cache-line independent. Same shape as the D1 / D4 followup restructurings. |
| _A2-followup_ (this commit) | `time::TimerInit()` portable forwarder added to `kernel/time/tick.{h,cpp}`. Calls `arch::TimerInit()` today; the day an ARM64 generic-timer backend lands, this is the call site `kernel_main` keeps using and only the arch implementation changes. `kernel_main` now invokes `duetos::time::TimerInit()` instead of the arch entry point. Remaining work — moving the LAPIC-divider + tick-frequency programming out of `arch::TimerInit` itself — is the new A2-followup. |
| _E3-followup_ (this commit) | First real driver registered as a fault domain: the soft-lockup detector. `SoftLockupEnable()` added (resets per-CPU streak state + flips `g_enabled` back on); `SoftLockupDisable()` already existed. Init/teardown lambdas in `kernel_main` register the pair via `RegisterDriverDomain("soft-lockup", ...)`. `RestartDriverDomain("soft-lockup")` from the shell now drives the detector through a clean disable + re-enable cycle. Other drivers register as their teardown story matures (each needs a real teardown written). |
| _E3-followup_ (this commit) | Second driver registered: lockdep. New `LockdepReset()` clears every per-CPU held-class stack, the edge matrix, the inversion counter, and the promote-to-panic knob; pairs with the existing `LockdepRegisterCanonicalClasses` for the init half of the domain. `RestartDriverDomain("lockdep")` re-baselines the graph after triaging a noisy boot — useful for clean slate before a stress run. |
| _shell_ (this commit) | Two new `inspect` subcommands: `inspect domains` walks every registered fault domain (driver-tagged + hand-registered) and prints id / name / restart count / alive flag to COM1, plus a console summary; `inspect zones` walks the four memory zones and prints per-zone allocs / frees / oom counts. Read-only audit surfaces sit alongside the existing `inspect lockdep` / `inspect syscalls` family. |
| _shell_ (this commit) | New top-level `domain` shell verb: `domain list` (alias for `inspect domains`) + `domain restart <name>` (admin-gated, walks `RestartDriverDomain`). The domain restart path was already callable from C; this exposes it through the shell so an operator can kick a misbehaving subsystem without rebooting. |
| _E3-followup_ (this commit) | Two more drivers registered as fault domains: `event-trace` and `perf`. New `EventTraceReset()` clears every CPU's ring + total counter; new `PerfReset()` does the same for the PMU sample ring. Each registers with a no-op init + the reset as teardown — `domain restart event-trace` / `domain restart perf` re-baselines the relevant ring before a measurement run. Brings the registered driver-domain set to 4 (soft-lockup + lockdep + event-trace + perf). |
| _D7_ (this commit) | GDB remote serial protocol stub scaffolding — `kernel/diag/gdb_stub.{h,cpp}`. Implements the wire-protocol framing (`$packet#csum`), ACK/NAK on checksum, and a small handler table for the commands every GDB session sends on connect: `qSupported` (returns `PacketSize=400`), `?` halt-reason (returns `S05`), `g` register read (returns 16×u64 zeros), `G`/`M`/`H` (returns `OK`), `m` memory read (returns `00`), `k` kill/detach (no reply). Anything else returns the empty packet `$#00` ("unsupported"). Single-byte input via `GdbStubReceiveByte`; output through a caller-supplied sink (`GdbStubSetSink`). Self-test drives synthesised conversations through the parser with a capturing sink, asserts `qSupported` reply contains `PacketSize`, halt-reason contains `S05`, and a deliberately bad-checksum packet emits `-` (NAK) + bumps the bad-csum counter. NOT yet wired to a serial RX IRQ — that's the D7-followup that lets a real GDB session attach. |
| _A3-followup_ (this commit) | Sixth concrete `KObject` subclass: `KFile` in `kernel/ipc/kfile.{h,cpp}`. Wraps an open-file descriptor (vnode pointer + seek pos + open-mode flags). New `KObjectType::File = 6` enumerator + `KObjectTypeName` mapping. v0 lifecycle + HandleTable round-trip self-test only — no I/O surface; the Linux fd-table / Win32 file-handle migrations onto KFile remain the deferred slice. The IPC primitive set is now 6-of-6 (Mutex / Event / Semaphore / Mailbox / Waitable / File). |

### Deferred (in priority order — see "Recommended ordering" below)

- [ ] A4-followup — Extend `kSyscallCapTable` to cover conditional cap surfaces once the conditional logic is collapsed (e.g. SYS_WRITE fd=1)
- [ ] C2-followup — Slab freed-object poison once a slab allocator lands (`kSlabFreedObjectPoison` reserved in `poison.h`)
- [ ] C2-followup — Real KASAN with shadow memory (only after telemetry shows the lite layer misses something)
- [ ] B1-followup — SMP-stress versions of the RwLock + SeqLock + KMailbox contention self-tests (current cooperative-single-CPU forms verify the wakeup paths fire; AP bringup will let real concurrent acquires race on the spinlock cores)
- [ ] A3-followup — Migrate `SYS_MUTEX_CREATE / WAIT / RELEASE` from `Process::win32_mutexes` array onto `KMutex` + `kobj_handles` (Win32 ABI semantics — kWaitObject0 / kWaitTimeout, deadlock-detect callbacks — need careful preservation; out-of-scope for the bare-subclass slice)
- [ ] A3-followup — Migrate the 10+ Win32 per-type handle arrays into the unified `HandleTable`
- [ ] A3-followup — Migrate Linux `LinuxFd` table into `HandleTable` once a `KFile` subclass exists
- [ ] A2-followup — Move the LAPIC-divider math + tick-frequency programming OUT of `arch::TimerInit` into a portable `time::TimerConfigure(hz)` helper once an ARM64 / generic-timer backend justifies the abstraction (current `time::TimerInit` is a forwarder)
- [ ] D1-followup — Index `g_per_cpu` lockdep array by current-CPU ID once SMP per-CPU storage exposes it (state is now structured per-CPU; only the slot-0 alias remains hardcoded)
- [ ] B2 — Per-CPU runqueues + work stealing (real SMP)
- [ ] D1 — Lockdep-lite (locking-order graph)
- [ ] E1-followup — Enable CET mitigations (write `IA32_S_CET` / `IA32_PL0_SSP`, allocate shadow stacks, recompile with `-fcf-protection=branch`); gated on the now-landed `arch::CetGet().ss_supported` / `ibt_supported` signal
- [ ] E2-followup — KPTI implementation itself, gated on the now-landed `arch::CpuMitigations::needs_kpti` signal; only triggered when a needs-kpti machine enters the test fleet (see investigation v0)
- [ ] C1-followup — Real per-zone allocator (current scaffolding forwards every zone request to the global pool; per-zone bitmap + buddy free-lists land when a workload demands DMA / DMA32 isolation)
- [ ] D2-followup — Index `g_per_cpu` event-trace ring array by current-CPU ID once SMP per-CPU storage exposes it (state is now structured per-CPU; only the slot-0 alias remains hardcoded)
- [ ] D7-followup — Wire `GdbStubReceiveByte` into the COM2 serial RX path (parser + canned responses landed; no IRQ source yet)
- [ ] D7-followup — Implement live `g`/`G` register reads + `m`/`M` memory reads against the actual trap frame + extable-protected memory access (currently returns zeros)
- [ ] D4-followup — Index `g_per_cpu` array by current-CPU ID once SMP per-CPU storage exposes it (state is now structured per-CPU; only the slot-0 alias remains hardcoded)
- [ ] E3-followup — Continue registering drivers as fault domains (soft-lockup + lockdep + event-trace + perf landed; framebuffer / pci / nvme / ahci / xhci / e1000 each need a real teardown written)

## Resume prompt

> Read `.claude/knowledge/kernel-debug-recommendations-plan.md`. The "Status"
> table at the top tracks which items have landed. Pick the next unchecked
> item from the "Deferred" list (priority order matches the
> "Recommended ordering" table). Each item's section below names the files
> to touch and an associated verification step — treat those as the
> implementation contract. Mark the item landed in the Status table in the
> same commit as the work itself. A1 (formal init ordering) and A4
> (centralized capability gate) are the cheapest wins; B2 (SMP completion)
> is the largest single piece of work.

---

## Context

Recommendations for the OS itself — kernel internals and debug/diagnostic
surface — explicitly excluding subsystems (Win32 / Linux / graphics / etc.)
and excluding work that's already on the roadmap.

What's already strong in the tree (so this plan does **not** re-recommend
these): breakpoints + DR support, static `KBP_PROBE` sites, `klog` ring
with sinks + `TraceScope`, panic / crash-dump v1 with backtrace + peer-CPU
NMI snapshots, runtime invariant checker (~35 health checks), fault-domain
restartable subsystems, image guard, attack-sim, kernel stack guard pages,
`Result<T,E>`, NMI watchdog, capability bitset on `Process`, ring-3 smoke
harness.

What's structurally thin or missing (the surface this plan covers):

- `kernel/core/` has no real source — init ordering is implicit / scattered.
- `kernel/ipc/` and `kernel/time/` directories don't exist; their concerns
  live half in `arch/x86_64/`, half in `syscall/`.
- `kernel/sync/` ships **only spinlocks** — no mutex, RW lock, seqlock, RCU.
- Frame allocator is **bitmap linear-scan**; no buddy, no zones, no NUMA.
- Held-lock stacks are recorded for panic snapshots but there's no
  locking-order validator (no lockdep-equivalent).
- PMU is used **only** for NMI-watchdog overflow — no sample profiling.
- No KASAN / UBSAN / heap red zones / freed-page poisoning.
- No dynamic tracing (only static `KBP_PROBE` enum sites).
- No soft-lockup detector (NMI watchdog catches a full timer wedge, not a
  single CPU spinning in a kernel path).
- No remote-debug stub (no kgdb-style serial protocol).
- Capability checks are scattered across syscall handlers — no single gate.

Leverage scoring: **H** = high (changes how the kernel is reasoned about),
**M** = medium (large quality-of-life win for one subsystem), **L** =
lower (nice to have).

---

## A. Structural / architectural

### A1. Make `kernel/core/` real — formal init ordering   [H]

Today `kernel/core/` contains only `generated_synxtest_elf.h`. There is no
`kernel/core/init.cpp`, no `panic.cpp` lives in this directory (panic is
elsewhere), and the boot sequence is a hand-ordered list of calls in
`kernel_main`. As subsystems multiply, this hand-ordering becomes the place
where bugs hide ("driver X assumed Y was up, but on this build it wasn't").

Recommend: introduce `kernel/core/init.cpp` with an explicit
`enum class Phase { Earlycon, PhysMem, Paging, Heap, Idt, Apic, Time,
PerCpuBsp, Sched, Smp, Drivers, Vfs, Userland }` and a registration macro
`KERNEL_INITCALL(phase, fn)` that lands callbacks in a fixed-size table at
link time (no allocator at boot). `kernel_main` then becomes a single loop
over phases. Each call returns `Result<void, ErrorCode>`; a failed early
phase panics, a failed late phase marks the corresponding fault domain.

Files: new `kernel/core/init.{h,cpp}`, `kernel/core/panic.cpp` moved here
from its current home, `kernel/arch/x86_64/boot.S` keeps its job (just sets
up the C++ environment and jumps to `kernel_main`).

### A2. Promote `kernel/time/` — clocksource abstraction   [H]

Timekeeping today is split: `kernel/arch/x86_64/timer.{cpp,h}`,
`hpet.{cpp,h}`, `rtc.{cpp,h}`, plus `SYS_GETTIME_FT / SYS_NOW_NS /
SYS_SLEEP_MS` in `kernel/syscall/time_syscall.cpp`. There's no abstraction
that lets a future ARM64 port plug in a different timer, and no central
place that owns wall-clock vs. monotonic vs. boot-time.

Recommend: create `kernel/time/` with `clocksource.h` (an interface:
`u64 read_ns()`, `u64 resolution_ns()`, `bool monotonic()`),
`timekeeper.cpp` (owns CLOCK_MONOTONIC, CLOCK_REALTIME, CLOCK_BOOTTIME),
`timer.cpp` (high-level periodic + one-shot), and `tick.cpp` (the per-CPU
scheduler tick). Existing HPET / TSC / LAPIC code becomes providers that
register themselves via `KERNEL_INITCALL(Phase::Time, ...)`. The syscall
layer becomes a one-line forward to `time::now_ns(clock_id)`.

### A3. Promote `kernel/ipc/` — kernel-object handle table   [H]

Today there's no `kernel/ipc/` directory. Mutexes, events, mailboxes, and
wait-queues are scattered through `kernel/syscall/syscall.cpp` (~110 KB of
mixed dispatch and impl) and `kernel/sched/sched.cpp`. As more syscalls
land this becomes unmaintainable, and the hard rule from CLAUDE.md ("one
TCP stack, one VFS, one registry, one window manager — each reachable from
multiple ABI front-ends, but with one kernel-owned implementation")
implicitly demands the same shape for IPC objects.

Recommend: introduce `kernel/ipc/` with a single per-process **handle
table**, kernel-object base type `KObject` (refcounted, type-tagged), and
concrete subclasses `KMutex`, `KEvent`, `KSemaphore`, `KMailbox`,
`KWaitable`. Native and Win32/NT and Linux ABI front-ends all bottom out at
the same `KObject` set; the handle table is what they translate to/from
their respective ABI handle shapes. This is the single biggest
"refactoring debt that compounds" item — fix it before the table gets any
bigger.

### A4. Centralize the capability gate   [H]

`Process::caps` is the source of truth, but cap checks today are sprinkled
across individual syscall handlers as ad-hoc `if (!(caps & kCapX)) return
-EPERM;` lines. The exploration noted enforcement is incomplete — easy to
forget, hard to audit.

Recommend: a single `SyscallGate(SyscallNumber n, Process* p) ->
Result<void, ErrorCode>` called by the dispatcher *before* any handler
runs, driven by a static const `kSyscallCapTable[N]` (one row per syscall
number, listing the required cap mask). Handlers stop checking caps; the
table is the audit surface. This pairs with A1 (initcall-registered) and
makes the "could a malicious PE/ELF reach this path?" review question into
a one-table grep.

Files: `kernel/syscall/syscall.cpp`, new `kernel/syscall/cap_table.def` (an
X-macro, mirroring the existing `syscall_names.def` style).

---

## B. Concurrency & SMP

### B1. Sync primitives ladder   [H]

`kernel/sync/` ships only `SpinLock`. Everything from waitqueue logic to
process-table mutation either spins (wasting cycles holding IRQs off
across long sections) or rolls a one-off pattern. The "no recursive, no
MCS, no priority inheritance" comment in `spinlock.h:23–33` is honest, but
the absence of any other primitive forces the wrong tool everywhere.

Recommend a four-step ladder:
1. **`Mutex`** (sleeping lock) — uses the existing wait-queue infrastructure
   in `sched/`. Trivial wins: anything in process / VFS / IPC that today
   spins for milliseconds.
2. **`RwLock`** (reader-writer) — the address-space already wants this
   (`AddressSpace` is described as RW-locked but rolls its own).
   Consolidate.
3. **`SeqLock`** — for read-mostly hot data (timekeeper, per-CPU stat
   counters). Cheaper than RwLock when readers vastly outnumber writers.
4. **RCU-lite** — quiescent-state RCU keyed off the scheduler tick. Worth
   it for the IPC handle table (A3) and the driver registry, both of
   which are read on every syscall and written rarely.

File: extend `kernel/sync/` — one TU per primitive, all in the same
directory. Held-lock tracking already exists per CPU
(`kPerCpuMaxHeldLocks`); extend it to record the new primitives so panic
snapshots remain useful.

### B2. Finish SMP — per-CPU runqueues + work stealing   [H]

The scaffolding is there: `arch/x86_64/smp.{cpp,h}`, `ap_trampoline.S`,
the `PerCpu` struct already holds `current_task` + `need_resched` per CPU.
What's missing is the AP bring-up call site, the per-CPU runqueue, and
the load-balancer.

Recommend: a single per-CPU `RunQueue` in `kernel/sched/runqueue.{h,cpp}`,
preserving today's "FIFO inside a priority class" shape (don't introduce
MLFQ yet — keep that for when there's a real workload to tune against).
On `SchedYield` / tick, pick locally; if local empty, steal one task from
the busiest peer (random victim with retry, not full scan, to keep
overhead O(1) on small SMP). Pin the idle task and the `kthreadd`-equivalent
to BSP only.

This unlocks: (a) the existing CPU-per-task affinity field starts meaning
something, (b) the TLB-shootdown path stops being a no-op, (c) the
soft-lockup detector (D4) becomes meaningful (today, with one CPU, "soft
lockup" and "hard lockup" are the same condition).

---

## C. Memory

### C1. Replace bitmap linear-scan with buddy + zones   [M]

`kernel/mm/frame_allocator.cpp` walks a flat bitmap to find a free frame.
That's fine for v0 (it's correct, deterministic, easy to inspect with the
runtime checker), but it scales linearly with RAM size and can't satisfy
contiguous multi-page allocations cheaply (DMA buffers, large pages, the
1 GiB MMIO arena). It also has no notion of "memory below 4 GiB for
legacy DMA" or "memory in NUMA node N".

Recommend: a buddy allocator (orders 0..10, covering 4 KiB..4 MiB) layered
**on top of** the existing bitmap (the bitmap stays as the canonical
truth so the runtime checker continues to work). Split the address space
into zones — `ZONE_DMA` (<16 MiB, only if anything actually needs it),
`ZONE_DMA32` (<4 GiB, for legacy 32-bit DMA), `ZONE_NORMAL` (everything
else), `ZONE_MMIO` (the high-half arena). NUMA nodes are an axis on top of
zones; keep it as a single node until two-socket boxes show up in the
test plan.

File: `kernel/mm/buddy.{h,cpp}` adjacent to the existing allocator;
`AllocateFrame()` becomes a thin wrapper that calls into the buddy.

### C2. Page + heap poisoning, KASAN-lite red zones   [H]

There are no memory-corruption diagnostics today beyond the post-hoc
runtime checker. A heap underrun that overwrites the next slab header
will only be caught when the next allocation trips the invariant scan —
by which point the call stack of the corruption is gone. KASAN proper is
a big lift (shadow memory, compiler instrumentation), but a 90% solution
is cheap.

Recommend three layers, gated on a single `DUETOS_MEM_DEBUG` build flag:
1. **Heap red zones** — `kheap` allocates with a 16-byte canary on each
   side; `free()` checks both. O(1) overhead per alloc/free. Catches
   linear over/underruns immediately, with the freeing call stack live.
2. **Freed-page poison** — when a frame goes back to the allocator, fill
   with `0xDE` (or zero, if cheaper to detect). Catches use-after-free
   reads of stale pages on the next allocation.
3. **Slab freed-object poison** — same idea, fill freed slab objects with
   `0xCC`. When the runtime checker walks a slab and finds a non-`0xCC`
   pattern in a freed slot, fire a HealthIssue.

This is **not** real KASAN (no shadow memory, no compiler-side
instrumentation, no fine-grained access checks), but it eats 90% of the
real bugs at a fraction of the cost. Keep real KASAN as a "later, when we
have a stable allocator" item — don't try both at once.

File: `kernel/mm/kheap.cpp`, `kernel/mm/frame_allocator.cpp`, plus a small
new `kernel/mm/poison.h` with the canary constants and check helpers.

---

## D. Observability & debugging

### D1. Lockdep-lite — locking-order validator   [H]

Held-lock stacks already exist per CPU (`kPerCpuMaxHeldLocks = 8`, used by
the panic snapshot). Today we know **what** locks a CPU holds at panic
time but not whether the order they were acquired in ever conflicts with
how another CPU acquired the same set.

Recommend: build a **locking-order graph** at runtime. Every time a lock
is acquired, record the edge "(any currently-held lock) → (this lock)".
If the graph has ever recorded the reverse edge, you have a potential
deadlock — fire a HealthIssue (don't panic; downgrade to log + flag, the
graph has false positives until lock classes are tagged). When the
graph stabilizes (no new edges for N seconds), promote violations from
"warn" to "panic" via a runtime knob. The graph is bounded — typically
< 200 lock classes in a kernel — so a fixed 256×256 bitset is enough.

This catches the entire class of "works on single CPU, deadlocks at
random under load" bugs, which is otherwise the worst kind of bug to chase
with only post-hoc panic snapshots. Pairs naturally with B1 (more lock
types) and B2 (real SMP).

File: `kernel/sync/lockdep.{h,cpp}`, hooks in each primitive's `Acquire()`.

### D2. Dynamic event tracer (ring) — beyond static `KBP_PROBE`   [M]

`KBP_PROBE` fires on a fixed enum of named sites. That's great for
documented hot spots, but useless for "what did the scheduler do in the
500 ms before this latency spike?" or "show me every page-fault on CPU 3
in the next second".

Recommend: a per-CPU lockless ring of fixed-size `TraceEvent` records
(timestamp, CPU id, event type tag, 4 inline u64 args). Event types are
declared via X-macro (mirrors `syscall_names.def`), each producing a
`TRACE_EVENT(sched_switch, prev_pid, next_pid, reason, 0)` macro. The ring
is cheap enough (10–30 cycles per event) to leave on by default with a
runtime per-event-type bitmask. Decode tooling lives host-side: dump the
ring on demand (new shell command `trace dump`) over the same crash-dump
serial framing.

This is **not** ftrace (no function-graph, no dynamic patching); it is
the tracing primitive you actually need for everyday debugging. ftrace /
kprobes can come later as a strictly bigger superset.

File: `kernel/diag/tracer.{h,cpp}`, plus 30–50 `TRACE_EVENT(...)`
sprinkles in sched, traps, syscall dispatch, paging, IPC.

### D3. PMU sample profiler ("perf record"-equivalent)   [M]

The PMU is already wired up — but only for the NMI watchdog overflow
counter. The rest of the CPU's performance-monitoring capability is
dormant. There's no way today to answer "where is the kernel spending its
cycles?" except by reading code and guessing.

Recommend: a per-CPU PMU sampler that arms a counter (cycles or
retired-instructions) to overflow every N events, and on overflow records
the trapped RIP into a per-CPU ring. A user-space tool (or a shell
command) drains the ring and a host-side script aggregates RIPs into a
flat / call-graph profile via the existing symbol table from
`kernel/util/symbols.cpp`. AMD support is bookkept differently from Intel
but the surface is small (Intel: PerfEvtSel0..3, AMD: PerfCtl0..5).

File: `kernel/arch/x86_64/pmu.{h,cpp}` (new), `kernel/diag/profiler.{h,cpp}`.
Reuses the NMI delivery path that the watchdog already set up.

### D4. Soft-lockup detector + per-CPU heartbeat   [M]

The NMI watchdog detects a fully wedged kernel (timer tick stopped). It
**doesn't** detect "CPU 1 is spinning forever inside a kernel function
with IRQs on but never voluntarily yielding" — that CPU is taking timer
ticks fine, but no useful work is happening.

Recommend: a per-CPU `last_voluntary_schedule_at` timestamp updated on
every `schedule()` / IRQ-return-to-user. A per-CPU watchdog kthread
(woken from the heartbeat that already runs every 5 s) checks each peer:
if `now - last_voluntary_schedule_at > 10 s`, log a soft-lockup warning
with the offending CPU's RIP (sampled via IPI). After 60 s of no
progress, fire a HealthIssue at `Isolate` severity (kill the offending
task if it's user mode; panic if kernel).

This pairs with B2 (per-CPU runqueues) — without real SMP, this detector
has nothing to detect.

File: `kernel/diag/softlockup.{h,cpp}`, hooks into existing `heartbeat.cpp`.

### D5. UBSAN with klog runtime   [L]

UBSAN is essentially free at compile time (`-fsanitize=undefined`) once
you have a runtime that handles the handful of `__ubsan_handle_*` symbols.
The runtime can be ~150 lines: each handler writes one structured klog
line with kind (signed-overflow, oob-array, null-deref, etc.) + source
location, then either continues (default) or panics (knob).

Recommend wiring this up as a debug-build-only feature flag. Cost: 5–10%
size, near-zero runtime hit on the hot path. Catches a class of bugs
(integer overflow in offset math, alignment violations) that the runtime
checker can't see post-hoc.

File: `kernel/diag/ubsan.{h,cpp}` (new), CMake preset
`x86_64-debug-ubsan` adds `-fsanitize=undefined -fno-sanitize-trap=all`.

### D6. Heap leak tracker — caller-RIP tagging   [L]

Today an allocator leak ("we allocated 50 MB of slab objects somewhere
and never freed them") is invisible until the allocator runs out and the
runtime checker fires `OutOfMemory`.

Recommend: tag every `kheap` allocation with the caller's RIP (cheap —
single `__builtin_return_address(0)`). A new shell command
`heap stats` walks the live-allocation table and prints the top 10
RIPs by bytes outstanding, resolved through the symbol table. Cost: 8
bytes per live allocation, no runtime overhead in the hot path.

File: `kernel/mm/kheap.cpp` extension; reuse `kernel/util/symbols.cpp`.

### D7. GDB serial stub (kgdb-equivalent over COM2)   [M]

Crash dumps are great for post-mortem; live debugging is painful (the
shell breakpoint commands are useful but limited to one CPU and require
typing into a target shell that may itself be wedged). A GDB
remote-serial-protocol stub on COM2 (COM1 is already klog) would let any
GDB connect with `target remote /dev/ttyS1` and step the kernel.

The GDB protocol is small (~10 packets handle 90% of debugging:
`g`/`G` registers, `m`/`M` memory, `c`/`s` continue/step, `Z0`/`z0`
breakpoints, `?` halt reason). The breakpoint subsystem already does the
heavy lifting (`kernel/debug/breakpoints.{h,cpp}` has int3 + DR support);
this is just an alternate UI in front of it.

Cost: ~600 lines of C++. Pays back the first time someone needs to debug
SMP corruption in flight.

File: `kernel/debug/gdb_stub.{h,cpp}` (new).

---

## E. Hardening

### E1. Intel CET — shadow stack + IBT   [M]

Stack canaries (`kernel/security/stack_canary.cpp`) catch *some* stack
smashes but only on function exit, only if the canary is between the
target and the buffer. Hardware Control-flow Enforcement Technology (CET)
on every Tiger Lake / Zen 3+ CPU gives you (a) a hardware shadow stack
that the attacker can't write to from C, and (b) Indirect Branch Tracking
that requires every indirect-call target to begin with `endbr64`.

Recommend: enable both, kernel-only first. The shadow stack is a per-task
allocation (one extra page in the task struct) and a few extra MSR
writes on context switch. IBT requires every kernel indirect-call target
to have `endbr64` as its first instruction — a Clang/GCC flag handles
this for compiled C++; the hand-written assembly entry points
(`exceptions.S`, `context_switch.S`) need explicit `endbr64` added.

This complements (does not replace) the canary; canary catches linear
overruns, CET catches ROP/JOP. Both are hardware-cheap.

File: `kernel/arch/x86_64/cet.{h,cpp}` (new), tweaks in `traps.cpp` and
`sched/context_switch.S`. CMake adds `-fcf-protection=full`.

### E2. Verify KPTI / Meltdown mitigation status   [M]

CLAUDE.md lists "W^X enforced, ASLR, stack canaries, control-flow
integrity" as goals, and the runtime checker confirms SMEP/SMAP/NXE bits.
But Meltdown (CVE-2017-5754) needs **kernel page-table isolation** —
separate kernel and user PML4s, switched on every entry/exit. This is
distinct from SMEP/SMAP and isn't in the audit checklist. The
`AddressSpace` model would need a per-process *user-only* PML4 plus a
shared *kernel-only* PML4 swapped in on syscall entry.

Recommend: explicitly verify status; if unmitigated, add it to the
roadmap as a v0.1 hardening item. The CPU report (CPUID leaf for
RDCL_NO) tells us when the host CPU doesn't need the mitigation, so a
runtime check can skip the cost on safe CPUs.

File: investigation in `kernel/arch/x86_64/cpu_features.cpp` (if it
exists; create otherwise), then implementation gated on the result.

### E3. Per-driver fault-domain extension   [L]

`kernel/security/fault_domain.cpp` already has a 16-entry registry of
restartable subsystems. Extend it: every driver registered via the
PCI/USB/etc. enumerators automatically gets a fault domain entry, and a
driver-local fault (segfault inside the driver, hung DMA) restarts that
specific driver instead of panicking the kernel.

Recommend: a `Driver` base class with `Init() / Teardown() / Probe()`
methods that the bus enumerators call, with the fault domain wired up at
registration time. This lands the "every driver must be probed" rule from
CLAUDE.md as a structural enforcement instead of a convention.

File: `kernel/drivers/driver_base.{h,cpp}` (new),
`kernel/security/fault_domain.cpp` extension. Touches every existing
driver registration site — moderate sprawl, high uniformity payoff.

---

## Recommended ordering (leverage × prerequisite chain)

| Order | Item | Theme | Score | Blocks / unblocks |
|------:|------|-------|-------|-------------------|
| 1 | A1 init ordering | Structural | H | Unblocks everything else's registration story |
| 2 | A4 capability gate | Structural | H | Closes a security-correctness gap *now*, before more syscalls land |
| 3 | C2 poison + red zones | Memory | H | Catches heap bugs from this point forward; cheap |
| 4 | B1 sync ladder | Concurrency | H | Unblocks A3 (IPC handle table) and B2 (SMP) |
| 5 | A3 IPC handle table | Structural | H | One-time; the longer it waits, the more code needs rework |
| 6 | A2 kernel/time/ | Structural | H | Modest, but unblocks a clean ARM64 port later |
| 7 | B2 SMP completion | Concurrency | H | Largest single project; do **after** B1 |
| 8 | D1 lockdep-lite | Observability | H | Pairs with B2; the moment SMP is real, you want this on |
| 9 | E1 CET | Hardening | M | Cheap once toolchain flags are set |
| 10 | E2 KPTI verification | Hardening | M | Investigation first; implementation only if needed |
| 11 | C1 buddy + zones | Memory | M | Becomes urgent once DMA drivers land |
| 12 | D2 dynamic tracer | Observability | M | High everyday-debugging value; moderate cost |
| 13 | D7 GDB stub | Observability | M | Pays for itself the first SMP race you debug |
| 14 | D4 soft-lockup | Observability | M | Only meaningful after B2 |
| 15 | D3 PMU sampler | Observability | M | Performance work; not critical until there's something to tune |
| 16 | D6 heap leak tracker | Observability | L | Small, isolated, high audit value |
| 17 | D5 UBSAN | Observability | L | Free with toolchain; runtime is ~150 lines |
| 18 | E3 driver fault domains | Hardening | L | Lands when the driver registry exists |

---

## Verification (per item)

Each item has a corresponding verification harness — none of these should
land without one:

- **A1** — `KERNEL_INITCALL` registration; build a unit test that
  registers three callbacks in different phases and confirms they fire
  in order. On-target: log every initcall name + duration; assert no
  phase reorders across boots.
- **A2** — Add a clocksource self-test in the runtime checker: read
  monotonic twice, assert non-decreasing; cross-check HPET against TSC
  drift over 1 s.
- **A3** — Existing ring-3 smoke harness exercises mutex/event syscalls;
  extend to allocate 10 000 handles, free them, assert table is empty.
- **A4** — `attack_sim` harness already simulates privileged ops without
  the cap; assert every one returns `-EPERM`. Add a fuzzer that calls
  every syscall number with empty caps and confirms `-EPERM` for all
  capped ones.
- **B1** — Per-primitive unit test (acquire/release, contention, RAII
  guard). Plus a stress test: N threads × M iterations on a counter.
- **B2** — Existing scheduler smoke; extend to N CPUs, assert tasks
  migrate, assert work-steal triggers when one CPU is idle.
- **C1** — Allocate every order 0..10, free interleaved, assert
  bitmap-of-truth still consistent. Stress: 1 M alloc/free pairs.
- **C2** — Deliberately overrun a heap allocation; assert canary check
  fires. Use-after-free read; assert poison pattern detected.
- **D1** — Synthetic AB / BA test; assert order graph fires warning.
- **D2** — `trace dump` after a known workload (10 syscalls); assert
  decoded events match expected sequence.
- **D3** — Spin a tight loop in a known function; assert profiler
  attributes >90% of samples to it.
- **D4** — Spin a kernel thread without yielding; assert detector fires
  within 10 s.
- **D5** — Deliberately trigger a signed overflow; assert UBSAN klog
  line.
- **D6** — Allocate without freeing in a known site; assert `heap stats`
  attributes the bytes to that RIP.
- **D7** — Connect GDB, set breakpoint, hit it, inspect registers,
  continue; assert kernel resumes cleanly.
- **E1** — Attack-sim adds a ROP-style indirect call to a non-`endbr64`
  target; assert CPU raises #CP.
- **E2** — Investigation produces a yes/no + a one-paragraph
  justification in `.claude/knowledge/`. If yes: add a Meltdown-style
  test (try to read kernel memory speculatively from ring 3) and
  confirm it fails post-mitigation.
- **E3** — Inject a fault into a registered driver; assert the
  driver-only fault domain restarts and the kernel survives.

---

## What this plan deliberately does **not** include

- Anything in the Win32 / Linux / POSIX subsystems (out of scope for this
  plan).
- Items already on the roadmap or in `.claude/knowledge/`: breakpoints
  phase 2a/3/4, klog overhaul, crash dump v0, attack-sim kernel v1,
  scheduler v0, Result type, kernel stack guards, fault-domain v0.
- Anything in deferred work: ARM64, CI/CD wiring, registry, signals,
  fork/exec on native ABI, 3D graphics path.
- Real KASAN with shadow memory (deliberate — C2 is the 90% solution at
  10% of the cost; do real KASAN later if telemetry shows we need it).
- ftrace / kprobes / eBPF (deliberate — D2 is the everyday-debugging
  primitive; the dynamic-instrumentation tier can come later).
- New native syscalls. Adding syscalls is an ABI commitment per
  CLAUDE.md; this plan is structural and doesn't grow the published
  surface.

