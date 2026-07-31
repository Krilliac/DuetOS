# DuetOS Stability Audit Ledger

Status: active; static and host-side partial verification complete. Full kernel/runtime verification is pending.

## Coverage

- 1,777 tracked kernel/tools sources checked by the include-tracking audit.
- Kernel passes covered architecture/core/CPU, scheduler/synchronization, memory, filesystems, networking, IPC, Linux and Win32 subsystems, drivers, loader, security, diagnostics, applications, shell, web, crypto, time, and utilities.
- Userland passes covered native apps, libc/CRT, Win32 DLL layers, graphics DLLs, networking DLLs, smoke tests, and PE/SEH/TLS fixtures.
- Boot coverage included UEFI source and boot metadata.
- Rust coverage included the 27 workspace crates and their FFI boundaries; hosted `unwrap` uses found were confined to test fixtures.
- Test assets inventoried: host tests and 35 fuzz targets/shims.

## Evidence

- `alloc-null-check-audit.py`: PASS.
- `include-tracked-audit.py`: PASS for 1,777 sources.
- `check-syscall-numbers.py`: 223 enum entries, 112 annotated sites, 274 assertions, 0 errors.
- `invariant-check.sh`: all gating invariants pass.
- `waitqueue-block-lock-audit.py`: 0 unguarded sites; 19 explicitly CLI-only sites; 2 spinlock untimed sites.
- Focused syntax-only compilation and cppcheck passes cover every modified translation unit.
- The address-space map-failure slice covered the production PE/ELF/DLL loaders, Linux `brk`/`mmap`/`mremap`/`munmap`/`mincore`, vDSO and stack growth, Win32 heap/vmap/fiber/thread allocation, and the shared page-table walker. The follow-on `mincore` validation also passed g++ C++23 syntax-only and focused cppcheck checks; the focused runs had no new correctness findings.
- The Linux socket/I/O boundary slice covered `recvmsg`/`accept4` output ownership, socket KFile-attachment failure cleanup, `recvmmsg`/`sendmmsg` address spans, and `readv`/`writev`/`preadv`/`pwritev` iovec arithmetic. The three changed translation units passed g++ C++23 syntax-only and focused cppcheck checks.
- The Linux timer/async timeout slice covered saturating alarm, interval-timer, and POSIX-timer nanosecond conversions/deadline rearming, timespec validation, timer output narrowing, overrun saturation, and `epoll_pwait2` negative/invalid/overflowing timeout handling. Both changed translation units passed g++ C++23 syntax-only and focused cppcheck checks; remaining cppcheck output was pre-existing style/flow guidance in surrounding code.
- A follow-up fd-lifetime review covered `pidfd_getfd`, cross-process Linux fd copying, shared OFD close/dup paths, and Win32 IOCP close/lookup behavior. `pidfd_splice.cpp` and `iocp_syscall.cpp` passed g++ C++23 syntax-only; the known target-fd concurrent-close race and first-duplicate-IOCP-close semantics remain explicitly isolated design gaps pending their owning lifetime contracts.
- Existing host CTest tree: 68 registered tests; 34 passed, 34 were not run because their prebuilt executables are absent. This tree was not rebuilt against the audit commits.
- The address-space transaction follow-up currently passes `git diff --check`, clang-format 18 `--dry-run --Werror`, the targeted allocation-null audit, and focused cppcheck warning/performance/portability analysis. Cppcheck reported no address-space finding; its three messages were pre-existing `util/result.h` performance guidance. The slice has not been compiled or booted under the current resource gate.
- The process-lifetime follow-up currently passes `git diff --check`, clang-format 18 `--dry-run --Werror`, allocation-null and include-tracking audits, the repository invariant gates, and the 12-band Win32 close/teardown coverage check. Expanded focused cppcheck completed with only pre-existing scheduler string-literal bound modeling and shell path-loop warnings; its C parser still stops at an older GNU inline-assembly block in `ntdll_reg.c`. Every Win32 process-handle consumer now resolves a target by taking a transient `Process` reference while the owning slot lock is held; close and final-table drain detach rows under that lock and run `ProcessRelease` afterward. Cross-process memory reads/writes use a one-page address-space transaction-copy primitive instead of retaining an unpinned frame/PTE snapshot. The reaper unlinks a dead task and detaches its Process/AS pointers under the scheduler lifetime lock before any reference drop, and public borrowed PID/TID pointer lookups have been replaced by retained, existence-only, or scheduler-owned by-ID operations. Boot self-tests cover process-handle publication, saturation, retained lookup, close-once behavior, owner-Job drain, idempotence, and exact reference balance. Compilation and runtime verification remain pending under the current resource gate.

## Implemented hardening

Recent audit commits include teardown pinning for socket/IPC/async pools, timeout and overflow saturation, address-space map refusal/partial-table rollback, Linux mapping-span and `mincore` validation, socket boundary failure cleanup, PE-loader map refusal checks, driver/loader range arithmetic, diagnostic formatting safety, filesystem label walks, Linux directory-prefix copying, and explicit userland ABI/CRT contracts.

The current address-space follow-up splits writer serialization into a task-context `sched::Mutex` transaction plus a bounded IRQ-safe structural spinlock. Map prepares region storage and intermediate page-table frames before the structural commit; unmap/protect perform TLB shootdowns and frame retirement after dropping the spinlock; empty user-half table paths are detached transactionally and freed after shootdown; fork copies frames outside the spinlock and now rolls back the whole child on refusal. This removes allocator, page-copy, logging, frame-free, and IPI-wait work from `regions_lock` without making spinlock-context readers sleep.

The process-lifetime follow-up adds a per-process IRQ-safe handle-slot lock and an explicit ownership API: install adopts one caller-held target reference only on success, lookup pins the target before exposing it, close detaches before releasing, and process-exit drain snapshots the whole table before any destructor can run. VM read/write syscalls hold that target reference for the entire operation. Their target-side data path is now a bounded bounce-copy: PTE resolution, user/writable validation, and direct-map dereference all occur while the target address space's mutation transaction excludes concurrent unmap, protect, and remap; caller-side user copying happens outside that transaction.

The same slice closes the surrounding publication edges. Last-task reaping removes scheduler lookup visibility before Process/AS teardown and drains self-owned Jobs without running destructors under the Job lock. Affinity, suspend/resume, and `tgkill(..., 0)` consume immutable TIDs entirely inside scheduler-owned operations rather than carrying a borrowed `Task*`. Job termination accounts against the locked object instead of re-resolving a reusable slot, and Job error logging now occurs after unlocking. SpawnEx installs inherited stdio through a synchronous pre-publication callback; a child cannot run or exit before its initial handle table and standard-handle aliases are complete. The ntdll VM facade chunks requests above 16 KiB, prevalidates whole-range overflow, preserves kernel validation for zero-length calls, aggregates counts, and distinguishes data-path partial copies from later administrative failures.

## Architecture stabilization contract

The repository-wide architecture review is adopted as a dependency-ordered
stabilization program. It is not a simultaneous rewrite. Every extraction uses
a strangler transition: define and test a narrow interface, adapt the current
implementation behind it, move one behavior at a time, compare old and new
behavior, then prohibit the retired dependency from returning.

The non-negotiable boundaries are:

- Native and compatibility APIs remain adapters over one scheduler, VM, object,
  filesystem, socket, graphics, and IPC implementation. A second Win32-shaped
  kernel backend is not acceptable.
- A recovery domain inside the shared kernel address space is not described as
  fault isolation. Only a separate address space, and where applicable an IOMMU
  domain, establishes a containment boundary.
- Syscall handlers receive retained typed objects or immutable identifiers. They
  do not carry borrowed `Process*`, `Task*`, PTE, or handle-slot pointers across
  an unlock, block, copy, teardown, or external call.
- All hostile arithmetic and structure validation occurs at ingress. No
  compatibility shim, parser, or service may rely on silent W+X downgrades,
  alignment repair, truncated identifiers, or partial initialization.
- No allocator, user copy, page copy, TLB-wait, destructor, scheduler call, or
  service callback runs beneath an IRQ-safe pool or metadata spinlock.

### Phase order and exit gates

1. **Correctness and truthfulness.** Finish transactional VM metadata, guarded
   task-owned stacks, generation-safe handles, per-task GUI queues, the truthful
   boot contract, mandatory prerequisites, and generated syscall/security
   inventory. Exit requires sanitizer/model concurrency coverage, stale-handle
   rejection after forced reuse, at least one unmapped guard page per stack, no
   required release-test skips, and explicit policy metadata for every syscall.
2. **Object and process decomposition.** Introduce a small process core plus Job,
   credentials, thread-group, and independently destructible ABI contexts.
   Register files, sections, sockets, pipes, windows, and synchronization objects
   in one reference-driven teardown system. Exit requires no backend, GUI,
   socket, or ABI-specific fields in the core and passing create/duplicate/
   inherit/close/exit properties for every object family.
3. **Generated ABI and IPC.** Make a versioned IDL the source of syscall numbers,
   kernel dispatch, C/Rust stubs, argument validators, authorization, tracing,
   fuzz metadata, and documentation. Add waitable channels/message ports and
   size/version-tagged request structures. Exit requires zero handwritten number
   duplication and reproducible generated compatibility reports.
4. **Service extraction.** Extract `serviced`, then `execd`, `displayd`,
   `registryd`, `netd`, selected filesystem parsers, and suitable driver hosts.
   An extracted service must be restartable with defined client recovery, and
   its crash/fuzz campaign must be unable to corrupt the kernel or stop unrelated
   processes.
5. **GUI compatibility.** Route messages to the owning Task, implement real
   `PostThreadMessage`, broker and filter cross-process delivery, and make
   synchronous cross-thread sends explicit RPC with cancellation, timeout, and
   reentrancy tracking. Exit requires independent queues in one process,
   integrity-safe cross-process behavior, reference message ordering, and
   defined saturation/backpressure.
6. **Boot, build, and packaging separation.** Replace recursive privileged source
   discovery with explicit subsystem targets, ship an initrd or immutable system
   image with a hashed capability manifest, keep applications/fixtures out of the
   production kernel, and require the advertised boot path in release CI.
7. **Measured SMP and performance refinement.** Only after the prior correctness
   gates: add priority inheritance, lower stack budgets, consider per-CPU runqueue
   locks, adopt `SYSCALL/SYSRET`, add IOMMU domains, and optimize IPC/shared
   memory. Each change needs a reproducible contention or latency win without a
   stress regression.

### Decisions frozen for the first implementation waves

- **Boot:** Multiboot2 through GRUB is the supported release contract until the
  direct UEFI loader completes segment loading, `ExitBootServices`, versioned
  `BootInfo`, and kernel handoff in required CI. The partial loader remains an
  experimental path and must not be advertised as complete.
- **Handles:** first make the current bounded tables generation-safe; paged growth
  follows after initialization and teardown can allocate safely. Public PE32
  tokens reserve bit 31 and use nonzero, non-wrapping generations. Generation
  exhaustion retires a slot rather than accepting ABA. Raw lookup is deprecated
  in favor of typed retained lookup.
- **Stacks:** the owning Task holds a non-forgeable address-space reservation
  token for its whole guard/reserve/commit interval. Mapping, demand growth,
  exec, fork, and reaping consume that exact token; a present foreign PTE is a
  hard conflict, never adopted as stack memory.
- **GUI:** a fixed allocation-free queue and its wait queue belong to each Task.
  Receive is transactional: peek a sequence while locked, copy unlocked, then
  commit that exact sequence. `WM_QUIT` cannot be evicted; coalescing is limited
  to explicitly safe high-frequency messages.
- **Execution:** the kernel PE loader first produces and consumes a compact,
  immutable `LoadPlan`. `execd` later owns parsing and dependency policy, while a
  small kernel validator rejects overlap, overflow, W+X, mutable executable
  backing, and an entry point outside executable regions.
- **Service control:** kernel-resident service state is transitional policy, not
  a security boundary. `serviced` owns manifests and restart policy through
  capability-checked IPC; the kernel retains scheduling, mappings, interrupts,
  object rights, and final device/DMA authority.

### Quantitative completion evidence

- One million randomized map/protect/unmap/fork/lookup operations without
  divergence from the reference interval model.
- Zero stale resolutions under forced handle-slot reuse and terminal-generation
  tests.
- Zero object leaks after 10,000 create/duplicate/inherit/close/exit cycles per
  object family.
- One thousand consecutive boots for every required release profile, with no
  missing-prerequisite skip path.
- Complete generated syscall authorization metadata and checked object rights.
- Cross-process GUI fuzzing cannot cause unauthorized close, quit, focus,
  capture, or input changes.
- Service fault injection leaves the kernel and unrelated processes running.
- Compatibility is reported by behavioral fixtures (return and last-error
  values, layouts, ordering, blocking, inheritance, thread-local state,
  cross-process security, and abnormal cleanup), not by export counts.

## Remaining verification

- Full MSVC build and link.
- Rebuilt host test suite for all 68 registered tests.
- QEMU boot, syscall/fuzz/stress campaigns, SMP/S3 paths, and graphical/runtime smoke tests.
- Address-space failure injection at page-table reserve depths 1–3, region-table growth OOM, and fork allocation refusal, with unchanged PTE/ledger/frame counts on failure.
- Multi-vCPU concurrent map/protect/unmap and fork/exec churn, including protection downgrade or unmap while a peer CPU actively runs the same address space.
- Forced-interleaving tests for process-handle lookup versus close/drain, scheduler lookup versus reaping, Job close versus terminate, and child publication versus inherited-handle setup.
- Hardware-dependent storage, networking, GPU, ACPI, and USB paths.
- Static analyzer residuals classified as intentional canary/SEH fixtures, linker/PE image-base contracts, inline-assembly parser limitations, or bounded NUL-terminated pointer contracts; they should be revisited after a target-aware compiler/analyzer run.
- Active-path design risks retained for follow-up: IOCP close currently marks the port closed on the first handle close if duplicate IOCP handles become supported; the current userland `DuplicateHandle` implementation aliases the numeric source handle, and no `NtDuplicateObject`/kernel duplicate dispatch exists for IOCP. `pidfd_getfd` reads a target Linux fd table without a per-process fd lock during concurrent close; the array is directly read by many Linux syscall paths, so adding a lock only at `pidfd_getfd` would not establish an invariant. Both require their owning handle/fd-lifetime contracts before a safe fix.
- `sync::AdaptiveMutex` has an SMP lost-wake window between its owner recheck and wait-queue enqueue. The address-space transaction uses the scheduler's handoff-safe `sched::Mutex`; AdaptiveMutex should not gain new correctness-critical users until its park handshake is coupled to `g_sched_lock` and covered by a forced-interleaving test.
- Address-space read probes still return an unpinned PTE/frame snapshot after releasing `regions_lock`. Cross-process VM read/write no longer use that API, but live Win32 heap, thread setup, stopped-task debugger, runtime DLL loader, and Linux `mremap` helpers must either prove exclusive/pre-publication ownership or migrate to higher-level transaction operations before concurrent unmap/protect is safe. The Linux `mremap` file remains isolated behind its active external claim.
- Fork now stabilizes the mapping structure but does not quiesce sibling writers to mapped memory. A coherent multi-threaded fork needs sibling suspension, write-protected COW, or an explicit rejection contract.
- Win32 `SectionMap` still does not pin its section frames before entering the sleepable AS mapping transaction. Section-handle lookup, W^X state, and per-process view ledgers also need one serialized reserve/publish/retire contract so close/unmap cannot free, alias, or double-release a view in flight.

The post-trace machine preflight recovered to `GO` with 7.1 GiB free RAM,
31.6 GiB commit headroom, zero running builds, and approximately 1.62 GiB of
kernel pool. Builds remain serialized until the active lifetime edits reach a
coherent checkpoint; the elevated pool baseline still makes a reboot advisable
before the prolonged release/QEMU campaigns.
