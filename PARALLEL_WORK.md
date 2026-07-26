# Parallel Work Coordinator

Auto-managed by tools/parallel/claim.sh and release.sh — do not edit by hand.

## Active Sessions

### 🟢 thunk-retirement-wave1
- **Session**: `Codex-thunk-wave1`
- **Branch**: `claude/thunk-retirement-wave1`
- **Files**: `kernel/subsystems/win32/thunks* kernel/loader/pe_loader.cpp kernel/proc/spawn.cpp kernel/CMakeLists.txt userland/libs/kernel32/kernel32_sync.c tools/build/*verify* tools/build/build-kernel32-dll.sh tools/build/gen-fix-patches.py tools/test/fix-patch-roundtrip.sh tests/host/*thunk* tests/host/CMakeLists.txt wiki/reference/Win32-Surface-Status.md wiki/getting-started/History.md wiki/reference/Design-Decisions.md wiki/subsystems/Win32-PE-Subsystem.md`
- **Description**: Retire CreateThread ExitThread and GetExitCodeThread legacy thunks with linked-export verification
- **Claimed**: 2026-07-26T23:30:04Z
- **Status**: IN PROGRESS

### 🟢 thunk-retirement-runtime-test
- **Session**: `Codex-thunk-wave1`
- **Branch**: `claude/thunk-retirement-wave1`
- **Files**: `userland/apps/syscall_stress/* tools/build/build-syscall-stress.sh kernel/CMakeLists.txt`
- **Description**: Add distinguishable-argument FreeLibraryAndExitThread runtime coverage
- **Claimed**: 2026-07-26T23:38:21Z
- **Status**: IN PROGRESS

### 🟢 kernel32-retirement-contract
- **Session**: `Codex-thunk-wave1`
- **Branch**: `claude/thunk-retirement-wave1`
- **Files**: `userland/libs/kernel32/kernel32_internal.h`
- **Description**: Declare cross-TU FreeLibrary contract for FreeLibraryAndExitThread
- **Claimed**: 2026-07-26T23:48:15Z
- **Status**: IN PROGRESS
