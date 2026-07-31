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

## Implemented hardening

Recent audit commits include teardown pinning for socket/IPC/async pools, timeout and overflow saturation, address-space map refusal/partial-table rollback, Linux mapping-span and `mincore` validation, socket boundary failure cleanup, PE-loader map refusal checks, driver/loader range arithmetic, diagnostic formatting safety, filesystem label walks, Linux directory-prefix copying, and explicit userland ABI/CRT contracts. The latest timer/async hardening code commit is `4d921155`; the branch is clean after the accompanying ledger update.

## Remaining verification

- Full MSVC build and link.
- Rebuilt host test suite for all 68 registered tests.
- QEMU boot, syscall/fuzz/stress campaigns, SMP/S3 paths, and graphical/runtime smoke tests.
- Hardware-dependent storage, networking, GPU, ACPI, and USB paths.
- Static analyzer residuals classified as intentional canary/SEH fixtures, linker/PE image-base contracts, inline-assembly parser limitations, or bounded NUL-terminated pointer contracts; they should be revisited after a target-aware compiler/analyzer run.
- Active-path design risks retained for follow-up: IOCP close currently marks the port closed on the first handle close if duplicate IOCP handles become supported; the current userland `DuplicateHandle` implementation aliases the numeric source handle, and no `NtDuplicateObject`/kernel duplicate dispatch exists for IOCP. `pidfd_getfd` reads a target Linux fd table without a per-process fd lock during concurrent close; the array is directly read by many Linux syscall paths, so adding a lock only at `pidfd_getfd` would not establish an invariant. Both require their owning handle/fd-lifetime contracts before a safe fix.

The machine preflight currently reports STOP-level resource pressure, so no build or QEMU process was launched during this audit slice.
