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

### [DONE] thunk-retirement-wave3-core
- **Session**: `Codex-thunk-wave3`
- **Branch**: `claude/thunk-retirement-wave3`
- **Files**: `kernel/subsystems/win32/thunk* kernel/loader/pe_loader.cpp kernel/proc/spawn.cpp tools/build/*fix* tools/build/*verify* tests/host/*thunk* wiki/reference/Win32-Surface-Status.md wiki/reference/Design-Decisions.md wiki/subsystems/Win32-PE-Subsystem.md wiki/getting-started/History.md`
- **Description**: Retire four verified 32-bit interlocked kernel32 thunks while preserving shared bytecode consumers
- **Claimed**: 2026-07-27T01:48:59Z
- **Status**: COMPLETED @ 2026-07-27T01:59:36Z

### [DONE] thunk-retirement-wave3-alias-fixture
- **Session**: `Codex-thunk-wave3`
- **Branch**: `claude/thunk-retirement-wave3`
- **Files**: `userland/apps/thunk_alias_smoke/* kernel/CMakeLists.txt kernel/proc/ring3_smoke.cpp tools/build/build-thunk-alias-smoke.sh tools/test/profile-boot-smoke.sh tools/test/bochs-smoke.sh`
- **Description**: Extend mixed-provider boot coverage to kernelbase and API-set interlocked aliases
- **Claimed**: 2026-07-27T01:49:00Z
- **Status**: COMPLETED @ 2026-07-27T01:59:38Z

### [DONE] thunk-retirement-wave3-apiset-policy
- **Session**: `Codex-thunk-wave3`
- **Branch**: `claude/thunk-retirement-wave3`
- **Files**: `kernel/loader/apiset_static.cpp`
- **Description**: Pin the interlocked API-set host used by the mixed-provider retirement fixture
- **Claimed**: 2026-07-27T01:53:41Z
- **Status**: COMPLETED @ 2026-07-27T01:59:40Z

### [DONE] thunk-retirement-wave4-core
- **Session**: `Codex-thunk-wave4`
- **Branch**: `claude/thunk-retirement-wave4`
- **Files**: `kernel/subsystems/win32/thunk* tools/build/*fix* tools/build/*verify* tests/host/*thunk* wiki/reference/Win32-Surface-Status.md wiki/reference/Design-Decisions.md wiki/subsystems/Win32-PE-Subsystem.md wiki/getting-started/History.md`
- **Description**: Retire four verified timing kernel32 thunks while preserving shared and PE32 consumers
- **Claimed**: 2026-07-27T02:18:38Z
- **Status**: COMPLETED @ 2026-07-27T02:33:54Z

### [DONE] thunk-retirement-wave4-alias-fixture
- **Session**: `Codex-thunk-wave4`
- **Branch**: `claude/thunk-retirement-wave4`
- **Files**: `userland/apps/thunk_alias_smoke/* kernel/proc/ring3_smoke.cpp tools/build/build-thunk-alias-smoke.sh tools/test/profile-boot-smoke.sh tools/test/bochs-smoke.sh`
- **Description**: Extend mixed-provider boot coverage to kernelbase profile and sysinfo timing aliases
- **Claimed**: 2026-07-27T02:18:40Z
- **Status**: COMPLETED @ 2026-07-27T02:33:57Z

### [DONE] thunk-retirement-wave4-apiset-policy
- **Session**: `Codex-thunk-wave4`
- **Branch**: `claude/thunk-retirement-wave4`
- **Files**: `kernel/loader/apiset_static.cpp`
- **Description**: Pin profile and sysinfo API-set hosts used by the retirement fixture
- **Claimed**: 2026-07-27T02:18:42Z
- **Status**: COMPLETED @ 2026-07-27T02:33:59Z

### [DONE] thunk-retirement-wave5-core
- **Session**: `Codex-thunk-wave5`
- **Branch**: `claude/thunk-retirement-wave5`
- **Files**: `kernel/subsystems/win32/thunk* tools/build/*fix* tools/build/*verify* tests/host/*thunk* wiki/reference/Win32-Surface-Status.md wiki/reference/Design-Decisions.md wiki/subsystems/Win32-PE-Subsystem.md wiki/getting-started/History.md`
- **Description**: Retire four verified core interlocked kernel32 and kernelbase rows while preserving vcruntime shared bytecode
- **Claimed**: 2026-07-27T02:53:01Z
- **Status**: COMPLETED @ 2026-07-27T03:09:08Z

### [DONE] thunk-retirement-wave5-alias-fixture
- **Session**: `Codex-thunk-wave5`
- **Branch**: `claude/thunk-retirement-wave5`
- **Files**: `userland/apps/thunk_alias_smoke/* kernel/proc/ring3_smoke.cpp tools/build/build-thunk-alias-smoke.sh tools/test/profile-boot-smoke.sh tools/test/bochs-smoke.sh`
- **Description**: Extend mixed-provider boot coverage to core interlocked aliases semantics and width canaries
- **Claimed**: 2026-07-27T02:53:03Z
- **Status**: COMPLETED @ 2026-07-27T03:09:10Z

### [DONE] thunk-retirement-wave5-interlock-smoke
- **Session**: `Codex-thunk-wave5`
- **Branch**: `claude/thunk-retirement-wave5`
- **Files**: `userland/apps/interlock_smoke/* tools/build/build-interlock-smoke.sh`
- **Description**: Make legacy interlock smoke failures terminal instead of printing unconditional PASS
- **Claimed**: 2026-07-27T02:53:04Z
- **Status**: COMPLETED @ 2026-07-27T03:09:12Z

### [DONE] thunk-retirement-wave6-core
- **Session**: `Codex-thunk-wave6`
- **Branch**: `claude/thunk-retirement-wave6`
- **Files**: `kernel/subsystems/win32/thunk* tools/build/*fix* tools/build/*verify* tests/host/*thunk* wiki/reference/Win32-Surface-Status.md wiki/reference/Design-Decisions.md wiki/subsystems/Win32-PE-Subsystem.md wiki/getting-started/History.md`
- **Description**: Retire four verified TLS kernel32 and kernelbase rows while preserving FLS shared bytecode
- **Claimed**: 2026-07-27T03:31:42Z
- **Status**: COMPLETED @ 2026-07-27T03:56:47Z

### [DONE] thunk-retirement-wave6-alias-fixture
- **Session**: `Codex-thunk-wave6`
- **Branch**: `claude/thunk-retirement-wave6`
- **Files**: `userland/apps/thunk_alias_smoke/* kernel/proc/ring3_smoke.cpp tools/build/build-thunk-alias-smoke.sh tools/test/profile-boot-smoke.sh tools/test/bochs-smoke.sh`
- **Description**: Extend mixed-provider boot coverage to TLS API-set and kernelbase semantics with cross-thread isolation
- **Claimed**: 2026-07-27T03:31:44Z
- **Status**: COMPLETED @ 2026-07-27T03:56:50Z

### [DONE] thunk-retirement-wave6-tls-smoke
- **Session**: `Codex-thunk-wave6`
- **Branch**: `claude/thunk-retirement-wave6`
- **Files**: `userland/apps/tls_smoke/* tools/build/build-tls-smoke.sh`
- **Description**: Make TLS smoke failures terminal and require full real-DLL verdict
- **Claimed**: 2026-07-27T03:31:45Z
- **Status**: COMPLETED @ 2026-07-27T03:56:52Z

### [DONE] thunk-retirement-wave6-tls-runtime
- **Session**: `Codex-thunk-wave6`
- **Branch**: `claude/thunk-retirement-wave6`
- **Files**: `userland/libs/kernel32/kernel32_sync.c kernel/subsystems/win32/tls_syscall.cpp kernel/proc/process.h kernel/sched/sched.h kernel/sched/sched.cpp`
- **Description**: Harden TLS LastError, SMP allocation, and slot generation semantics used by retired real DLL exports
- **Claimed**: 2026-07-27T03:35:44Z
- **Status**: COMPLETED @ 2026-07-27T03:56:55Z

### [DONE] thunk-retirement-wave6-tls-init
- **Session**: `Codex-thunk-wave6`
- **Branch**: `claude/thunk-retirement-wave6`
- **Files**: `kernel/proc/process.cpp`
- **Description**: Initialize TLS slot generations after replacing process-global value storage
- **Claimed**: 2026-07-27T03:45:44Z
- **Status**: COMPLETED @ 2026-07-27T03:56:57Z

### [DONE] thunk-retirement-wave6-abi-docs
- **Session**: `Codex-thunk-wave6`
- **Branch**: `claude/thunk-retirement-wave6`
- **Files**: `kernel/syscall/syscall.h kernel/subsystems/win32/tls_syscall.h`
- **Description**: Synchronize TLS syscall and runtime contracts with per-task generation and LastError behavior
- **Claimed**: 2026-07-27T03:54:07Z
- **Status**: COMPLETED @ 2026-07-27T03:56:59Z

### [DONE] kernel-thread-wait-fix
- **Session**: `Codex-wave6-thread-wait-fix`
- **Branch**: `claude/kernel-thread-wait-fix`
- **Files**: `kernel/syscall/syscall.cpp`
- **Description**: No description provided
- **Claimed**: 2026-07-27T04:57:08Z
- **Status**: COMPLETED @ 2026-07-27T05:18:41Z

### [DONE] kernel-thread-lifecycle
- **Session**: `Codex-wave6-thread-wait-fix`
- **Branch**: `claude/kernel-thread-wait-fix`
- **Files**: `kernel/subsystems/win32/thread_syscall.cpp`
- **Description**: No description provided
- **Claimed**: 2026-07-27T04:57:34Z
- **Status**: COMPLETED @ 2026-07-27T05:19:26Z

### [DONE] kernel-thread-close
- **Session**: `Codex-wave6-thread-wait-fix`
- **Branch**: `claude/kernel-thread-wait-fix`
- **Files**: `kernel/subsystems/win32/file_syscall.cpp`
- **Description**: No description provided
- **Claimed**: 2026-07-27T04:57:39Z
- **Status**: COMPLETED @ 2026-07-27T05:19:56Z

### [DONE] kernel-thread-state
- **Session**: `Codex-wave6-thread-wait-fix`
- **Branch**: `claude/kernel-thread-wait-fix`
- **Files**: `kernel/proc/process.cpp`
- **Description**: kernel/proc/process.h
- **Claimed**: 2026-07-27T04:57:44Z
- **Status**: COMPLETED @ 2026-07-27T05:20:27Z

### [DONE] kernel-thread-regression
- **Session**: `Codex-wave6-thread-wait-fix`
- **Branch**: `claude/kernel-thread-wait-fix`
- **Files**: `userland/apps/thunk_alias_smoke/thunk_alias_smoke.c`
- **Description**: No description provided
- **Claimed**: 2026-07-27T04:57:49Z
- **Status**: COMPLETED @ 2026-07-27T05:20:57Z

### [DONE] kernel-thread-doc
- **Session**: `Codex-wave6-thread-wait-fix`
- **Branch**: `claude/kernel-thread-wait-fix`
- **Files**: `wiki/reference/Roadmap.md`
- **Description**: No description provided
- **Claimed**: 2026-07-27T04:57:54Z
- **Status**: COMPLETED @ 2026-07-27T05:21:27Z

### [DONE] kernel-thread-state-header
- **Session**: `Codex-wave6-thread-wait-fix`
- **Branch**: `claude/kernel-thread-wait-fix`
- **Files**: `kernel/proc/process.h`
- **Description**: No description provided
- **Claimed**: 2026-07-27T04:58:04Z
- **Status**: COMPLETED @ 2026-07-27T05:21:57Z

### [DONE] kernel-thread-diagnostics
- **Session**: `Codex-wave6-thread-wait-fix`
- **Branch**: `claude/kernel-thread-wait-fix`
- **Files**: `kernel/diag/leak_detector.cpp`
- **Description**: No description provided
- **Claimed**: 2026-07-27T05:02:28Z
- **Status**: COMPLETED @ 2026-07-27T05:22:24Z

### [DONE] kernel-thread-deferred-sched
- **Session**: `Codex-wave6-thread-wait-fix`
- **Branch**: `claude/kernel-thread-wait-fix`
- **Files**: `kernel/sched/sched.cpp`
- **Description**: No description provided
- **Claimed**: 2026-07-27T05:05:52Z
- **Status**: COMPLETED @ 2026-07-27T05:22:34Z

### [DONE] kernel-thread-deferred-api
- **Session**: `Codex-wave6-thread-wait-fix`
- **Branch**: `claude/kernel-thread-wait-fix`
- **Files**: `kernel/sched/sched.h`
- **Description**: No description provided
- **Claimed**: 2026-07-27T05:06:09Z
- **Status**: COMPLETED @ 2026-07-27T05:23:04Z

### [DONE] thread-handle-tid-state
- **Session**: `Codex-thread-handle-tid-isolation`
- **Branch**: `claude/thread-handle-tid-isolation`
- **Files**: `kernel/proc/process.h`
- **Description**: No description provided
- **Claimed**: 2026-07-27T05:46:29Z
- **Status**: COMPLETED @ 2026-07-27T06:39:37Z

### [DONE] thread-handle-tid-scheduler
- **Session**: `Codex-thread-handle-tid-isolation`
- **Branch**: `claude/thread-handle-tid-isolation`
- **Files**: `kernel/sched/sched.h`
- **Description**: No description provided
- **Claimed**: 2026-07-27T05:46:47Z
- **Status**: COMPLETED @ 2026-07-27T06:39:40Z

### [DONE] thread-handle-tid-syscalls
- **Session**: `Codex-thread-handle-tid-isolation`
- **Branch**: `claude/thread-handle-tid-isolation`
- **Files**: `kernel/syscall/syscall.cpp`
- **Description**: Resolve
- **Claimed**: 2026-07-27T05:46:52Z
- **Status**: COMPLETED @ 2026-07-27T06:39:43Z

### [DONE] thread-handle-tid-close
- **Session**: `Codex-thread-handle-tid-isolation`
- **Branch**: `claude/thread-handle-tid-isolation`
- **Files**: `kernel/subsystems/win32/file_syscall.cpp`
- **Description**: Serialize
- **Claimed**: 2026-07-27T05:46:57Z
- **Status**: COMPLETED @ 2026-07-27T06:39:45Z

### [DONE] thread-handle-tid-create
- **Session**: `Codex-thread-handle-tid-isolation`
- **Branch**: `claude/thread-handle-tid-isolation`
- **Files**: `kernel/subsystems/win32/thread_syscall.cpp`
- **Description**: Publish
- **Claimed**: 2026-07-27T05:47:02Z
- **Status**: COMPLETED @ 2026-07-27T06:39:47Z

### [DONE] thread-handle-tid-regression
- **Session**: `Codex-thread-handle-tid-isolation`
- **Branch**: `claude/thread-handle-tid-isolation`
- **Files**: `userland/apps/thread2_smoke`
- **Description**: No description provided
- **Claimed**: 2026-07-27T05:47:07Z
- **Status**: COMPLETED @ 2026-07-27T06:39:50Z

### [DONE] thread-handle-tid-doc
- **Session**: `Codex-thread-handle-tid-isolation`
- **Branch**: `claude/thread-handle-tid-isolation`
- **Files**: `wiki/reference/Roadmap.md`
- **Description**: Track
- **Claimed**: 2026-07-27T05:47:12Z
- **Status**: COMPLETED @ 2026-07-27T06:39:52Z

### [DONE] thread-handle-tid-state-impl
- **Session**: `Codex-thread-handle-tid-isolation`
- **Branch**: `claude/thread-handle-tid-isolation`
- **Files**: `kernel/proc/process.cpp`
- **Description**: Implement_TID_based_thread_handle_state
- **Claimed**: 2026-07-27T05:47:26Z
- **Status**: COMPLETED @ 2026-07-27T06:39:55Z

### [DONE] thread-handle-tid-scheduler-impl
- **Session**: `Codex-thread-handle-tid-isolation`
- **Branch**: `claude/thread-handle-tid-isolation`
- **Files**: `kernel/sched/sched.cpp`
- **Description**: Implement_scheduler_owned_by_TID_operations
- **Claimed**: 2026-07-27T05:47:32Z
- **Status**: COMPLETED @ 2026-07-27T06:39:57Z

### [DONE] thread-handle-tid-regression3
- **Session**: `Codex-thread-handle-tid-isolation`
- **Branch**: `claude/thread-handle-tid-isolation`
- **Files**: `userland/apps/thread3_smoke`
- **Description**: Foreign_stale_handle_and_context_quiescence_regressions
- **Claimed**: 2026-07-27T05:47:37Z
- **Status**: COMPLETED @ 2026-07-27T06:39:59Z

### [DONE] thread-handle-tid-diagnostics
- **Session**: `Codex-thread-handle-tid-isolation`
- **Branch**: `claude/thread-handle-tid-isolation`
- **Files**: `kernel/diag/leak_detector.cpp`
- **Description**: serialize_thread_handle_diagnostics
- **Claimed**: 2026-07-27T05:49:34Z
- **Status**: COMPLETED @ 2026-07-27T06:40:02Z

### [DONE] thread-handle-tid-apc
- **Session**: `Nathan-47566`
- **Branch**: `claude/thread-handle-tid-isolation`
- **Files**: `kernel/subsystems/win32/apc_syscall.cpp`
- **Description**: Resolve APC same-process TID authorization entirely under scheduler lifetime lock
- **Claimed**: 2026-07-27T06:00:03Z
- **Status**: COMPLETED @ 2026-07-27T06:40:04Z

### [DONE] thread-handle-tid-profile-core
- **Session**: `Nathan-48040`
- **Branch**: `claude/thread-handle-tid-isolation`
- **Files**: `kernel/proc/ring3_smoke.cpp`
- **Description**: Run thread3 TID and context regression in focused pe-threads profile
- **Claimed**: 2026-07-27T06:14:29Z
- **Status**: COMPLETED @ 2026-07-27T06:40:06Z

### [DONE] thread-handle-tid-profile-api
- **Session**: `Nathan-48053`
- **Branch**: `claude/thread-handle-tid-isolation`
- **Files**: `kernel/test/smoke_profile.h`
- **Description**: Document thread3 coverage in pe-threads profile
- **Claimed**: 2026-07-27T06:14:31Z
- **Status**: COMPLETED @ 2026-07-27T06:40:09Z

### [DONE] thread-handle-tid-profile-qemu
- **Session**: `Nathan-48066`
- **Branch**: `claude/thread-handle-tid-isolation`
- **Files**: `tools/test/profile-boot-smoke.sh`
- **Description**: Require thread3 isolation sentinels in QEMU
- **Claimed**: 2026-07-27T06:14:32Z
- **Status**: COMPLETED @ 2026-07-27T06:40:11Z

### [DONE] thread-handle-tid-profile-bochs
- **Session**: `Nathan-48079`
- **Branch**: `claude/thread-handle-tid-isolation`
- **Files**: `tools/test/bochs-smoke.sh`
- **Description**: Require thread3 isolation sentinels in Bochs
- **Claimed**: 2026-07-27T06:14:34Z
- **Status**: COMPLETED @ 2026-07-27T06:40:14Z

### [DONE] thread-handle-tid-profile-timing
- **Session**: `Nathan-48094`
- **Branch**: `claude/thread-handle-tid-isolation`
- **Files**: `kernel/test/smoke_profile.cpp`
- **Description**: Keep pe-threads timing documentation synchronized with four PE fixtures
- **Claimed**: 2026-07-27T06:15:47Z
- **Status**: COMPLETED @ 2026-07-27T06:40:16Z

### [DONE] thread-handle-tid-doc-sync
- **Session**: `Codex-thread-handle-tid-isolation`
- **Branch**: `claude/thread-handle-tid-isolation`
- **Files**: `wiki/getting-started/History.md wiki/subsystems/Win32-PE-Subsystem.md .github/workflows/build.yml`
- **Description**: Synchronize thread3 profile coverage and fixed-duration CI contract
- **Claimed**: 2026-07-27T06:29:54Z
- **Status**: COMPLETED @ 2026-07-27T06:40:19Z

### [ACTIVE] thread-handle-tid-regression-debug
- **Session**: `Codex-thread-handle-tid-isolation`
- **Branch**: `claude/thread-handle-tid-isolation`
- **Files**: `userland/apps/thread3_smoke/thread3_smoke.c`
- **Description**: Expose foreign-handle lifecycle stage verdicts in runtime smoke
- **Claimed**: 2026-07-27T06:48:49Z
- **Status**: IN PROGRESS
