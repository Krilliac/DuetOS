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

The machine preflight currently reports STOP-level resource pressure, so no build or QEMU process was launched during this audit slice.
