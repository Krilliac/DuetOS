# Parallel Work Coordinator

Auto-managed by tools/parallel/claim.sh and release.sh — do not edit by hand.

## Active Sessions

### [DONE] thunk-retirement-wave1
- **Session**: `Codex-thunk-wave1`
- **Branch**: `claude/thunk-retirement-wave1`
- **Files**: `kernel/subsystems/win32/thunks* kernel/loader/pe_loader.cpp kernel/proc/spawn.cpp kernel/CMakeLists.txt userland/libs/kernel32/kernel32_sync.c tools/build/*verify* tools/build/build-kernel32-dll.sh tools/build/gen-fix-patches.py tools/test/fix-patch-roundtrip.sh tests/host/*thunk* tests/host/CMakeLists.txt wiki/reference/Win32-Surface-Status.md wiki/getting-started/History.md wiki/reference/Design-Decisions.md wiki/subsystems/Win32-PE-Subsystem.md`
- **Description**: Retire CreateThread ExitThread and GetExitCodeThread legacy thunks with linked-export verification
- **Claimed**: 2026-07-26T23:30:04Z
- **Status**: COMPLETED @ 2026-07-27T00:31:42Z

### [DONE] thunk-retirement-runtime-test
- **Session**: `Codex-thunk-wave1`
- **Branch**: `claude/thunk-retirement-wave1`
- **Files**: `userland/apps/syscall_stress/* tools/build/build-syscall-stress.sh kernel/CMakeLists.txt`
- **Description**: Add distinguishable-argument FreeLibraryAndExitThread runtime coverage
- **Claimed**: 2026-07-26T23:38:21Z
- **Status**: COMPLETED @ 2026-07-27T00:31:44Z

### [DONE] kernel32-retirement-contract
- **Session**: `Codex-thunk-wave1`
- **Branch**: `claude/thunk-retirement-wave1`
- **Files**: `userland/libs/kernel32/kernel32_internal.h`
- **Description**: Declare cross-TU FreeLibrary contract for FreeLibraryAndExitThread
- **Claimed**: 2026-07-26T23:48:15Z
- **Status**: COMPLETED @ 2026-07-27T00:31:47Z

### [DONE] thunk-retirement-smoke-profile
- **Session**: `Codex-thunk-wave1`
- **Branch**: `claude/thunk-retirement-wave1`
- **Files**: `kernel/test/smoke_profile.h kernel/test/smoke_profile.cpp kernel/proc/ring3_smoke.cpp tools/test/profile-boot-smoke.sh .github/workflows/build.yml`
- **Description**: Add focused emulator-safe PE thread/thunk retirement runtime profile and CI gate
- **Claimed**: 2026-07-26T23:49:28Z
- **Status**: COMPLETED @ 2026-07-27T00:31:48Z

### [DONE] smoke-profile-docs
- **Session**: `Codex-thunk-wave1`
- **Branch**: `claude/thunk-retirement-wave1`
- **Files**: `tools/test/bochs-smoke.sh tools/test/diff-boot-smoke.sh`
- **Description**: Keep cross-hypervisor smoke profile documentation synchronized with pe-threads
- **Claimed**: 2026-07-26T23:53:25Z
- **Status**: COMPLETED @ 2026-07-27T00:31:51Z

### [DONE] parallel-release-safety
- **Session**: `Codex-thunk-wave1`
- **Branch**: `claude/thunk-retirement-wave1`
- **Files**: `tools/parallel/release.sh`
- **Description**: Stage only PARALLEL_WORK.md so releasing a claim cannot absorb fleet work
- **Claimed**: 2026-07-26T23:54:03Z
- **Status**: COMPLETED @ 2026-07-27T00:31:53Z

### [DONE] thunk-retirement-kernel-contract
- **Session**: `Codex-thunk-wave1`
- **Branch**: `claude/thunk-retirement-wave1`
- **Files**: `kernel/syscall/syscall.cpp userland/apps/hello_winapi/hello.c userland/apps/thread2_smoke/thread2_smoke.c`
- **Description**: Correct invalid-handle semantics and make natural-return thread coverage verdict-bearing
- **Claimed**: 2026-07-27T00:06:53Z
- **Status**: COMPLETED @ 2026-07-27T00:31:55Z

### [DONE] thunk-retirement-fix-cycle-profiles
- **Session**: `Codex-thunk-wave1`
- **Branch**: `claude/thunk-retirement-wave1`
- **Files**: `tools/qemu/run-fix-cycle.sh tools/qemu/chain-fix-boots.sh tools/qemu/run.sh`
- **Description**: Keep local fix-cycle profile chains synchronized with pe-threads CI coverage
- **Claimed**: 2026-07-27T00:17:14Z
- **Status**: COMPLETED @ 2026-07-27T00:31:56Z

### [DONE] thunk-retirement-wave2-core
- **Session**: `Codex-thunk-wave2`
- **Branch**: `claude/thunk-retirement-wave2`
- **Files**: `kernel/subsystems/win32/thunk* kernel/loader/pe_loader.cpp kernel/proc/spawn.cpp tools/build/*fix* tools/build/*verify* tests/host/*thunk* tests/host/CMakeLists.txt wiki/reference/Win32-Surface-Status.md wiki/reference/Design-Decisions.md wiki/subsystems/Win32-PE-Subsystem.md wiki/getting-started/History.md`
- **Description**: Retire six exact current-process/thread/error-state x64 thunks through the real verified kernel32 export path
- **Claimed**: 2026-07-27T00:53:14Z
- **Status**: COMPLETED @ 2026-07-27T01:30:11Z

### [DONE] thunk-retirement-wave2-runtime
- **Session**: `Codex-thunk-wave2`
- **Branch**: `claude/thunk-retirement-wave2`
- **Files**: `userland/apps/hello_winapi/hello.c tools/test/profile-boot-smoke.sh tools/test/bochs-smoke.sh`
- **Description**: Add verdict-bearing pseudo-handle ID last-error and via-DLL smoke sentinels
- **Claimed**: 2026-07-27T00:53:16Z
- **Status**: COMPLETED @ 2026-07-27T01:30:14Z

### [DONE] thunk-retirement-wave2-alias-fixture
- **Session**: `Codex-thunk-wave2`
- **Branch**: `claude/thunk-retirement-wave2`
- **Files**: `userland/apps/thunk_alias_smoke/* kernel/CMakeLists.txt kernel/proc/ring3_smoke.cpp tools/build/build-thunk-alias-smoke.sh`
- **Description**: Add kernel32 kernelbase and API-set IAT routing boot coverage for retired imports
- **Claimed**: 2026-07-27T00:53:17Z
- **Status**: COMPLETED @ 2026-07-27T01:30:17Z

### [DONE] thunk-retirement-wave2-timeout
- **Session**: `Codex-thunk-wave2`
- **Branch**: `claude/thunk-retirement-wave2`
- **Files**: `kernel/test/smoke_profile.cpp`
- **Description**: Increase pe-winapi guest timeout for the second mixed-provider PE and worker-thread oracle
- **Claimed**: 2026-07-27T01:08:47Z
- **Status**: COMPLETED @ 2026-07-27T01:30:19Z

### [DONE] thunk-retirement-wave2-apiset-policy
- **Session**: `Codex-thunk-wave2`
- **Branch**: `claude/thunk-retirement-wave2`
- **Files**: `kernel/loader/apiset_static.cpp`
- **Description**: Lock known-host mappings and fabricated-contract rejection for retired API-set aliases
- **Claimed**: 2026-07-27T01:10:30Z
- **Status**: COMPLETED @ 2026-07-27T01:30:21Z

### [ACTIVE] thunk-retirement-wave3-core
- **Session**: `Codex-thunk-wave3`
- **Branch**: `claude/thunk-retirement-wave3`
- **Files**: `kernel/subsystems/win32/thunk* kernel/loader/pe_loader.cpp kernel/proc/spawn.cpp tools/build/*fix* tools/build/*verify* tests/host/*thunk* wiki/reference/Win32-Surface-Status.md wiki/reference/Design-Decisions.md wiki/subsystems/Win32-PE-Subsystem.md wiki/getting-started/History.md`
- **Description**: Retire four verified 32-bit interlocked kernel32 thunks while preserving shared bytecode consumers
- **Claimed**: 2026-07-27T01:48:59Z
- **Status**: IN PROGRESS

### [ACTIVE] thunk-retirement-wave3-alias-fixture
- **Session**: `Codex-thunk-wave3`
- **Branch**: `claude/thunk-retirement-wave3`
- **Files**: `userland/apps/thunk_alias_smoke/* kernel/CMakeLists.txt kernel/proc/ring3_smoke.cpp tools/build/build-thunk-alias-smoke.sh tools/test/profile-boot-smoke.sh tools/test/bochs-smoke.sh`
- **Description**: Extend mixed-provider boot coverage to kernelbase and API-set interlocked aliases
- **Claimed**: 2026-07-27T01:49:00Z
- **Status**: IN PROGRESS

### [ACTIVE] thunk-retirement-wave3-apiset-policy
- **Session**: `Codex-thunk-wave3`
- **Branch**: `claude/thunk-retirement-wave3`
- **Files**: `kernel/loader/apiset_static.cpp`
- **Description**: Pin the interlocked API-set host used by the mixed-provider retirement fixture
- **Claimed**: 2026-07-27T01:53:41Z
- **Status**: IN PROGRESS
