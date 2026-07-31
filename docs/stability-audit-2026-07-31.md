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
- Existing host CTest tree: 68 registered tests; 34 passed, 34 were not run because their prebuilt executables are absent. This tree was not rebuilt against the audit commits.

## Implemented hardening

Recent audit commits include teardown pinning for socket/IPC/async pools, timeout and overflow saturation, bounds and source-span checks, driver/loader range arithmetic, diagnostic formatting safety, filesystem label walks, Linux directory-prefix copying, and explicit userland ABI/CRT contracts. The current branch is clean at `9aeca2f0`.

## Remaining verification

- Full MSVC build and link.
- Rebuilt host test suite for all 68 registered tests.
- QEMU boot, syscall/fuzz/stress campaigns, SMP/S3 paths, and graphical/runtime smoke tests.
- Hardware-dependent storage, networking, GPU, ACPI, and USB paths.
- Static analyzer residuals classified as intentional canary/SEH fixtures, linker/PE image-base contracts, inline-assembly parser limitations, or bounded NUL-terminated pointer contracts; they should be revisited after a target-aware compiler/analyzer run.
- Active-path design risks retained for follow-up: IOCP close currently marks the port closed on the first handle close if duplicate IOCP handles become supported; the current userland `DuplicateHandle` implementation aliases the numeric source handle, and no `NtDuplicateObject`/kernel duplicate dispatch exists for IOCP. `pidfd_getfd` reads a target Linux fd table without a per-process fd lock during concurrent close; the array is directly read by many Linux syscall paths, so adding a lock only at `pidfd_getfd` would not establish an invariant. Both require their owning handle/fd-lifetime contracts before a safe fix.

The machine preflight currently reports STOP-level resource pressure, so no build or QEMU process was launched during this audit slice.
