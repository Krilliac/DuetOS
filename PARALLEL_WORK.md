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

### [DONE] thread-handle-tid-regression-debug
- **Session**: `Codex-thread-handle-tid-isolation`
- **Branch**: `claude/thread-handle-tid-isolation`
- **Files**: `userland/apps/thread3_smoke/thread3_smoke.c`
- **Description**: Expose foreign-handle lifecycle stage verdicts in runtime smoke
- **Claimed**: 2026-07-27T06:48:49Z
- **Status**: COMPLETED @ 2026-07-27T06:49:17Z

### [DONE] thread-handle-tid-abi-fix
- **Session**: `Codex-thread-handle-tid-isolation`
- **Branch**: `claude/thread-handle-tid-isolation`
- **Files**: `userland/apps/thread3_smoke/thread3_smoke.c kernel/syscall/syscall.h`
- **Description**: Correct SYS_THREAD_OPEN fixture number and synchronize TID-only handle contract
- **Claimed**: 2026-07-27T06:51:16Z
- **Status**: COMPLETED @ 2026-07-27T06:52:05Z
### 🟢 linux-mm-wx-hardening
- **Session**: `Nathan-8`
- **Branch**: `claude/linux-mmap-wx-hardening`
- **Files**: `kernel/subsystems/linux/syscall_mm.cpp kernel/subsystems/linux/mm_protection_policy.h kernel/subsystems/linux/extra_syscalls.cpp kernel/subsystems/linux/syscall_internal.h tests/host/test_linux_mm_policy.cpp tests/host/CMakeLists.txt wiki/security/WX-Enforcement.md wiki/reference/Design-Decisions.md`
- **Description**: Enforce Linux mmap and mprotect W^X policy and make mseal failure truthful
- **Claimed**: 2026-07-26T12:30:06Z
- **Status**: IN PROGRESS

### [DONE] ci-red-main-repair
- **Session**: `Nathan-616`
- **Branch**: `claude/ci-red-main-repair`
- **Files**: `Codex-CI-red-main`
- **Description**: kernel/subsystems/win32/registry.cpp kernel/loader/pe_loader.cpp kernel/proc/ring3_smoke.cpp userland/apps/accel_test/hello.c userland/apps/console4_smoke/console4_smoke.c userland/apps/dialog_smoke/dialog_smoke.c userland/apps/guard_smoke/guard_smoke.c userland/libs/advapi32/advapi32.c userland/libs/comtest/comtest.c userland/libs/gdi32/gdi32.c userland/libs/kernel32/kernel32_fiber.c userland/libs/ole32/ole32.c tools/build/build-accel-test.sh tests/host/test_thunk_retirement_policy.cpp tools/build/test_verify_pe_exports.py
- **Claimed**: 2026-07-30T23:59:25Z
- **Status**: COMPLETED @ 2026-07-31T00:04:51Z

### [DONE] ci-red-main-repair-files
- **Session**: `Nathan-545`
- **Branch**: `claude/ci-red-main-repair`
- **Files**: `kernel/subsystems/win32/registry.cpp kernel/loader/pe_loader.cpp kernel/proc/ring3_smoke.cpp userland/apps/accel_test/hello.c userland/apps/console4_smoke/console4_smoke.c userland/apps/dialog_smoke/dialog_smoke.c userland/apps/guard_smoke/guard_smoke.c userland/libs/advapi32/advapi32.c userland/libs/comtest/comtest.c userland/libs/gdi32/gdi32.c userland/libs/kernel32/kernel32_fiber.c userland/libs/ole32/ole32.c tools/build/build-accel-test.sh tests/host/test_thunk_retirement_policy.cpp tools/build/test_verify_pe_exports.py`
- **Description**: Repair current main CI format executable-bit and export-test drift discovered while validating handoff PRs
- **Claimed**: 2026-07-31T00:00:20Z
- **Status**: COMPLETED @ 2026-07-31T00:04:37Z

### [DONE] ci-red-main-sched-format
- **Session**: `Codex-CI-red-main`
- **Branch**: `claude/ci-red-main-repair`
- **Files**: `kernel/sched/sched.cpp kernel/sched/sched.h`
- **Description**: Format already-landed scheduler fiber additions so current main passes full-tree clang-format
- **Claimed**: 2026-07-31T00:02:37Z
- **Status**: COMPLETED @ 2026-07-31T00:04:44Z

### [DONE] drsh-wire-attack-rebased
- **Session**: `Codex-DRSH-recovery-rebase`
- **Branch**: `claude/drsh-attack-campaign-2026-07-30`
- **Files**: `kernel/net/drsh/* kernel/net/tcp* kernel/net/socket* kernel/CMakeLists.txt kernel/core/boot_bringup.cpp tools/qemu/run.sh tools/security/drsh_* wiki/networking/DRSH-Remote-Access.md`
- **Description**: Re-record completed DRSH wire attack slice after rebasing onto repaired main
- **Claimed**: 2026-07-31T00:24:23Z
- **Status**: COMPLETED @ 2026-07-31T00:24:28Z

### [DONE] aurora-sample-gadgets-post-drsh
- **Session**: `Codex-Aurora-gadgets-post-drsh`
- **Branch**: `claude/aurora-sample-gadgets`
- **Files**: `kernel/drivers/video/desktop_gadgets.cpp kernel/drivers/video/desktop_gadgets.h kernel/drivers/video/taskbar.cpp kernel/sched/sched.cpp kernel/sched/sched.h wiki/subsystems/Compositor.md wiki/reference/Roadmap.md wiki/reference/Design-Decisions.md`
- **Description**: Re-record completed Aurora sample stats gadgets slice after rebasing onto DRSH-merged main
- **Claimed**: 2026-07-31T00:51:53Z
- **Status**: COMPLETED @ 2026-07-31T00:51:58Z

### [DONE] drsh-agent-host
- **Session**: `Codex-drsh-agent-host-2026-07-30`
- **Branch**: `claude/drsh-agent-host`
- **Files**: `tools/security/drsh_host.py tools/security/drsh_agent.py tools/qemu/run.sh wiki/networking/DRSH-Remote-Access.md`
- **Description**: Host a throwaway DuetOS QEMU and dispatch real authenticated DRSH agent workers; keep separate from protocol/OS attack scripts.
- **Claimed**: 2026-07-31T04:37:53Z
- **Status**: COMPLETED @ 2026-07-31T04:56:36Z

### [DONE] drsh-concurrent-access
- **Session**: `Nathan-1422`
- **Branch**: `claude/drsh-agent-host`
- **Files**: `kernel/net/drsh/drsh.h kernel/net/drsh/drsh_internal.h kernel/net/drsh/drsh_server.cpp kernel/net/drsh/drsh_transport.cpp kernel/shell/shell_drsh.cpp tools/qemu/run.sh tools/security/drsh_host.py wiki/networking/DRSH-Remote-Access.md`
- **Description**: Concurrent DRSH sessions with explicit local-only or external access policy
- **Claimed**: 2026-07-31T05:17:53Z
- **Status**: COMPLETED @ 2026-07-31T05:40:34Z

### [DONE] drsh-concurrent-access-boot
- **Session**: `Nathan-655`
- **Branch**: `claude/drsh-agent-host`
- **Files**: `kernel/core/boot_bringup.cpp`
- **Description**: Enable external peer policy only for the explicit DRSH test autostart fixture
- **Claimed**: 2026-07-31T05:23:38Z
- **Status**: COMPLETED @ 2026-07-31T05:41:09Z

### [DONE] gpu-amd-pm4
- **Session**: `Nathan-131`
- **Branch**: `claude/gpu-amd-pm4-20260731`
- **Files**: `kernel/drivers/gpu/amd_gpu.h kernel/drivers/gpu/amd_gpu.cpp kernel/drivers/gpu/amd_gpu_cmds.h kernel/drivers/gpu/amd_cp_ucode.cpp kernel/drivers/gpu/amd_cp_ucode.h wiki/drivers/Graphics-Drivers.md wiki/reference/GPU-Implementation-Notes.md wiki/reference/Roadmap.md`
- **Description**: AMD GFX9 PM4 write-data readback probe after CP microcode load
- **Claimed**: 2026-07-31T05:49:50Z
- **Status**: COMPLETED @ 2026-07-31T06:04:13Z

### [DONE] gpu-amd-psp-status
- **Session**: `Nathan-1936`
- **Branch**: `claude/gpu-amd-psp-status-20260731`
- **Files**: `kernel/drivers/gpu/amd_gpu.cpp kernel/drivers/gpu/amd_gpu.h kernel/drivers/gpu/amd_gpu_cmds.cpp kernel/drivers/gpu/amd_gpu_cmds.h kernel/drivers/gpu/amd_cp_ucode.cpp kernel/drivers/gpu/amd_cp_ucode.h kernel/drivers/gpu/amd_gfx_fw.cpp kernel/drivers/gpu/amd_gfx_fw.h`
- **Description**: AMD generation-specific capability/status selftest after merged PM4; PSP/GFX11 or VM groundwork with explicit fallback
- **Claimed**: 2026-07-31T06:28:35Z
- **Status**: COMPLETED @ 2026-07-31T06:35:45Z

### [DONE] gpu-intel-blt-capability
- **Session**: `Nathan-280`
- **Branch**: `claude/gpu-intel-blt-gdi-20260731`
- **Files**: `kernel/drivers/gpu/intel_gpu.h kernel/drivers/gpu/intel_gpu.cpp kernel/drivers/gpu/intel_gpu_cmds.h kernel/drivers/gpu/intel_gpu_cmds.cpp`
- **Description**: Publish explicit Intel BLT capability after the existing real-hardware offscreen probe; keep GDI/compositor wiring deferred until surface mapping and submission serialization contracts exist
- **Claimed**: 2026-07-31T06:34:21Z
- **Status**: COMPLETED @ 2026-07-31T06:37:48Z

### [DONE] gpu-amd-vm-pte
- **Session**: `Nathan-782`
- **Branch**: `claude/gpu-amd-vm-20260731`
- **Files**: `kernel/drivers/gpu/amd_gpu_vm.h kernel/drivers/gpu/amd_gpu_vm.cpp`
- **Description**: AMD GFX9-GFX11 VM PTE encoding and reject-path selftests; no MMIO or firmware upload
- **Claimed**: 2026-07-31T07:24:07Z
- **Status**: COMPLETED @ 2026-07-31T07:26:46Z

### [DONE] gpu-nvidia-gsp-ring
- **Session**: `Nathan-859`
- **Branch**: `claude/gpu-nvidia-gsp-ring-20260731`
- **Files**: `kernel/drivers/gpu/nvidia_gpu.h kernel/drivers/gpu/nvidia_gpu.cpp kernel/drivers/gpu/nvidia_gsp_fw.h kernel/drivers/gpu/nvidia_gsp_fw.cpp`
- **Description**: Bounded GSP RPC ring model with structural overflow and corruption selftests; no PFIFO/PGRAPH writes
- **Claimed**: 2026-07-31T07:25:58Z
- **Status**: COMPLETED @ 2026-07-31T07:31:13Z

### [DONE] gpu-intel-t403
- **Session**: `Nathan-806`
- **Branch**: `claude/gpu-intel-t403-20260731`
- **Files**: `kernel/drivers/gpu/intel_gpu.cpp kernel/drivers/gpu/intel_gpu.h kernel/drivers/gpu/intel_gpu_cmds.h kernel/drivers/video/framebuffer.cpp tests/host/test_intel_blt.cpp tests/host/CMakeLists.txt`
- **Description**: Route eligible GDI solid fills through the verified Intel BLT engine on the owned compose surface with validation, serialization, and CPU fallback
- **Claimed**: 2026-07-31T07:24:16Z
- **Status**: COMPLETED @ 2026-07-31T07:37:50Z

### [DONE] gpu-intel-t403
- **Session**: `Nathan-1458`
- **Branch**: `claude/gpu-intel-t403-20260731`
- **Files**: `kernel/drivers/gpu/intel_gpu.cpp kernel/drivers/gpu/intel_gpu.h kernel/drivers/gpu/intel_gpu_cmds.cpp kernel/drivers/gpu/intel_gpu_cmds.h kernel/drivers/video/framebuffer.cpp tests/host/test_intel_blt.cpp tests/host/CMakeLists.txt`
- **Description**: Route eligible GDI solid fills through the verified Intel BLT engine on the owned compose surface with validation, serialization, and CPU fallback
- **Claimed**: 2026-07-31T07:28:08Z
- **Status**: COMPLETED @ 2026-07-31T07:37:50Z

### [DONE] gpu-intel-t403
- **Session**: `Nathan-1837`
- **Branch**: `claude/gpu-intel-t403-20260731`
- **Files**: `kernel/drivers/gpu/intel_gpu.cpp kernel/drivers/gpu/intel_gpu.h kernel/drivers/gpu/intel_gpu_cmds.cpp kernel/drivers/gpu/intel_gpu_cmds.h kernel/drivers/video/framebuffer.cpp tests/host/test_intel_blt.cpp tests/host/CMakeLists.txt wiki/drivers/Graphics-Drivers.md`
- **Description**: Route eligible GDI solid fills through the verified Intel BLT engine on the owned compose surface with validation, serialization, and CPU fallback
- **Claimed**: 2026-07-31T07:32:14Z
- **Status**: COMPLETED @ 2026-07-31T07:37:50Z

### [DONE] gpu-virtio-resource-lifecycle
- **Session**: `Nathan-1526`
- **Branch**: `claude/gpu-virtio-feature-slice-20260731`
- **Files**: `kernel/drivers/gpu/virtio_gpu.cpp kernel/drivers/gpu/virtio_gpu.h`
- **Description**: Complete one QEMU-testable Virtio-GPU resource lifecycle or scanout feature with bounded queue/DMA behavior
- **Claimed**: 2026-07-31T07:23:57Z
- **Status**: COMPLETED @ 2026-07-31T07:30:48Z

### [DONE] mm-address-space-transactions
- **Session**: `Nathan-1058`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/mm/address_space.cpp kernel/mm/address_space.h docs/stability-audit-2026-07-31.md wiki/reference/Roadmap.md`
- **Description**: Split VM mutation serialization from IRQ-safe structural snapshots; keep alloc/free/TLB IPI outside regions spinlock
- **Claimed**: 2026-07-31T13:20:39Z
- **Status**: COMPLETED @ 2026-07-31T13:44:10Z

### [ACTIVE] vm-process-lifetime
- **Session**: `Nathan-221`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/mm/address_space.cpp kernel/mm/address_space.h kernel/proc/process.cpp kernel/proc/process.h kernel/syscall/syscall.cpp kernel/subsystems/win32/file_syscall.cpp kernel/subsystems/win32/job_syscall.cpp docs/stability-audit-2026-07-31.md wiki/reference/Roadmap.md`
- **Description**: Retain process-handle targets and copy cross-AS memory under address-space mutation lifetime
- **Claimed**: 2026-07-31T13:58:27Z
- **Status**: IN PROGRESS

### [ACTIVE] vm-process-exit-drain
- **Session**: `Nathan-221`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/sched/sched.cpp kernel/subsystems/win32/job_syscall.h`
- **Description**: Drain owner jobs at last-task exit without releasing members under the pool lock
- **Claimed**: 2026-07-31T14:17:02Z
- **Status**: IN PROGRESS

### [ACTIVE] vm-process-abi
- **Session**: `Nathan-221`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/syscall/syscall.h userland/libs/ntdll/ntdll_reg.c wiki/specifications/Syscall-ABI.md`
- **Description**: Make capped cross-process VM calls chunked and partial-copy status truthful
- **Claimed**: 2026-07-31T14:17:15Z
- **Status**: IN PROGRESS

### [ACTIVE] vm-process-lookup-callers
- **Session**: `Nathan-221`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/subsystems/win32/spawn_syscall.cpp kernel/apps/dbg_core.cpp kernel/diag/gdb_monitor_read.cpp kernel/diag/leak_detector.cpp kernel/shell/shell_exec.cpp`
- **Description**: Replace borrowed scheduler Process pointers at dereferencing callers and serialize diagnostics
- **Claimed**: 2026-07-31T14:17:25Z
- **Status**: IN PROGRESS

### [ACTIVE] vm-process-exit-test
- **Session**: `Nathan-221`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/core/boot_bringup.cpp`
- **Description**: Run owner-job exit-drain reference-balance selftest before user tasks
- **Claimed**: 2026-07-31T14:18:14Z
- **Status**: IN PROGRESS

### [ACTIVE] vm-process-lookup-api
- **Session**: `Nathan-221`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/sched/sched.h kernel/subsystems/linux/syscall_async_io.cpp kernel/subsystems/linux/syscall_proc.cpp kernel/subsystems/linux/pidfd_splice.cpp`
- **Description**: Retire borrowed Process pointer lookup in favor of retained ownership or boolean existence queries
- **Claimed**: 2026-07-31T14:24:02Z
- **Status**: IN PROGRESS

### [ACTIVE] task-lookup-lifetime
- **Session**: `Nathan-2012`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/subsystems/linux/syscall_sched.cpp`
- **Description**: No description provided
- **Claimed**: 2026-07-31T14:35:52Z
- **Status**: IN PROGRESS

### [ACTIVE] task-lookup-shell
- **Session**: `Nathan-29`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/shell/shell_process.cpp`
- **Description**: Retire
- **Claimed**: 2026-07-31T14:36:08Z
- **Status**: IN PROGRESS

### [ACTIVE] spawn-prepublish-core
- **Session**: `Nathan-953`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/proc/spawn.cpp`
- **Description**: Prepare
- **Claimed**: 2026-07-31T14:43:47Z
- **Status**: IN PROGRESS

### [ACTIVE] spawn-prepublish-api
- **Session**: `Nathan-705`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/proc/spawn.h`
- **Description**: Expose
- **Claimed**: 2026-07-31T14:44:00Z
- **Status**: IN PROGRESS

### [ACTIVE] win32-file-handle-lifetime
- **Session**: `Nathan-1508`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/fs/file_route.cpp kernel/fs/file_route.h kernel/subsystems/linux/syscall_pipe.cpp kernel/subsystems/linux/syscall_pipe.h kernel/subsystems/win32/pipe_syscall.cpp kernel/subsystems/win32/named_pipe_syscall.cpp`
- **Description**: Serialize reserve publish inherit and detach for Win32 file handles
- **Claimed**: 2026-07-31T14:56:08Z
- **Status**: IN PROGRESS

### [DONE] host-msvc-assert-portability
- **Session**: `Nathan-221`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/util/debug_assert.h`
- **Description**: Make debug assertion branch hints portable to MSVC-hosted tests
- **Claimed**: 2026-07-31T15:33:50Z
- **Status**: COMPLETED @ 2026-07-31T16:44:29Z

### [DONE] host-msvc-panic-portability
- **Session**: `Nathan-221`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/core/panic.h`
- **Description**: Make cold-path annotations portable to MSVC-hosted tests
- **Claimed**: 2026-07-31T15:36:01Z
- **Status**: COMPLETED @ 2026-07-31T16:44:31Z

### [DONE] host-msvc-saturating
- **Session**: `Nathan-221`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/util/saturating.h tests/host/test_shadow_atlas.cpp`
- **Description**: Make saturating telemetry and constant-condition tests portable to MSVC
- **Claimed**: 2026-07-31T15:37:07Z
- **Status**: COMPLETED @ 2026-07-31T16:44:33Z

### [ACTIVE] win32-job-userland-ingress
- **Session**: `Codex-job-userland`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `userland/libs/kernel32/kernel32_io.c userland/libs/ntdll/ntdll_token.c userland/libs/ntdll/ntdll.c userland/libs/ntdll/ntdll_rtl.c userland/libs/ntdll/ntdll_internal.h tools/build/build-kernel32-dll.sh userland/apps/jobobj_smoke/jobobj_smoke.c`
- **Description**: Wire real kernel32 and ntdll Job lifecycle ingress with verdict-bearing smoke coverage
- **Claimed**: 2026-07-31T15:53:38Z
- **Status**: IN PROGRESS

### [ACTIVE] win32-file-opaque-userland
- **Session**: `Nathan-892`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `userland/libs/ucrtbase/ucrtbase.c userland/libs/msvcrt/msvcrt.c userland/apps/pe32_rich/pe32_rich.c`
- **Description**: Accept opaque generation-tagged Win32 file handles in CRT and PE32 fixture
- **Claimed**: 2026-07-31T15:56:35Z
- **Status**: IN PROGRESS

### [ACTIVE] task-affinity-publication
- **Session**: `Codex-scheduler-exit-lifetime`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/sched/workpool.cpp kernel/shell/shell_bench.cpp`
- **Description**: Migrate post-publication raw Task affinity callers to scheduler-owned TID operations
- **Claimed**: 2026-07-31T15:58:01Z
- **Status**: IN PROGRESS

### [ACTIVE] win32-file-opaque-pe32-classifier
- **Session**: `Nathan-1940`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `userland/libs/kernel32_32/kernel32_32_internal.h`
- **Description**: Classify PE32 opaque generation-tagged file handles without truncation
- **Claimed**: 2026-07-31T15:58:33Z
- **Status**: IN PROGRESS

### [ACTIVE] win32-section-transaction
- **Session**: `Nathan-1547`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/subsystems/win32/section.cpp kernel/subsystems/win32/section.h`
- **Description**: Make Section generation refs views and borrowed-range map/unmap transactional
- **Claimed**: 2026-07-31T15:58:41Z
- **Status**: IN PROGRESS

### [ACTIVE] task-user-stack-lifetime
- **Session**: `Codex-scheduler-exit-lifetime`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/proc/user_stack.cpp kernel/proc/user_stack.h kernel/subsystems/win32/thread_syscall.cpp tests/host/test_user_stack.cpp`
- **Description**: Move guarded user-stack growth and reclamation ownership from Process to Task
- **Claimed**: 2026-07-31T16:18:01Z
- **Status**: IN PROGRESS

### [ACTIVE] win32-file-opaque-pe32-comments
- **Session**: `Nathan-1554`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `userland/libs/kernel32_32/kernel32_32.c userland/libs/kernel32_32/kernel32_32_fs.c`
- **Description**: Synchronize PE32 file-handle comments with opaque generation-tagged ABI
- **Claimed**: 2026-07-31T16:19:59Z
- **Status**: IN PROGRESS

### [ACTIVE] win32-section-userland-type
- **Session**: `Nathan-1762`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `userland/libs/ntdll/ntdll_info.c`
- **Description**: Recognize opaque generation-tagged Section handles in NtQueryObject
- **Claimed**: 2026-07-31T16:23:53Z
- **Status**: IN PROGRESS

### [ACTIVE] proc-job-core-service
- **Session**: `Codex-job-core-service`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/proc/job.h`
- **Description**: No description provided
- **Claimed**: 2026-07-31T16:24:29Z
- **Status**: IN PROGRESS

### [ACTIVE] proc-job-core-source
- **Session**: `Codex-job-core-service`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/proc/job.cpp`
- **Description**: No description provided
- **Claimed**: 2026-07-31T16:24:48Z
- **Status**: IN PROGRESS

### [ACTIVE] proc-job-win32-header
- **Session**: `Codex-job-core-service`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/subsystems/win32/job_syscall.h`
- **Description**: No description provided
- **Claimed**: 2026-07-31T16:24:50Z
- **Status**: IN PROGRESS

### [ACTIVE] proc-job-win32-adapter
- **Session**: `Codex-job-core-service`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/subsystems/win32/job_syscall.cpp`
- **Description**: No description provided
- **Claimed**: 2026-07-31T16:24:52Z
- **Status**: IN PROGRESS

### [DONE] docs-sync-dry-run
- **Session**: `Nathan-221`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `docs/sync-wiki.sh`
- **Description**: Make wiki drift check operate on an isolated copy and never mutate the worktree
- **Claimed**: 2026-07-31T16:32:01Z
- **Status**: COMPLETED @ 2026-07-31T16:37:31Z

### [DONE] win32-section-mmap-cursor
- **Session**: `Nathan-1221`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/subsystems/linux/syscall_mm.cpp kernel/subsystems/linux/syscall_clone.cpp`
- **Description**: Make automatic mmap range allocation atomic across Linux, VM, and Section callers
- **Claimed**: 2026-07-31T16:51:11Z
- **Status**: COMPLETED @ 2026-07-31T16:51:42Z

### [ACTIVE] win32-section-fork-cursor
- **Session**: `Nathan-86`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/subsystems/linux/syscall_clone.cpp`
- **Description**: Snapshot the shared mmap cursor atomically when forking a Process
- **Claimed**: 2026-07-31T16:51:58Z
- **Status**: IN PROGRESS

### [ACTIVE] stack-reservation-loader
- **Session**: `Codex-scheduler-exit-lifetime`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/loader/pe_loader.cpp`
- **Description**: No description provided
- **Claimed**: 2026-07-31T16:52:30Z
- **Status**: IN PROGRESS

### [ACTIVE] stack-reservation-loader-api
- **Session**: `Codex-scheduler-exit-lifetime`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/loader/pe_loader.h`
- **Description**: primary-stack-token-result-contract
- **Claimed**: 2026-07-31T16:52:37Z
- **Status**: IN PROGRESS

### [ACTIVE] named-pipe-registry-reservation
- **Session**: `Nathan-offline-1744`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/ipc/named_pipes.cpp kernel/ipc/named_pipes.h`
- **Description**: Release the registry-owned opposite pipe end exactly once across connected server close (offline claim; remote publication pending)
- **Claimed**: 2026-07-31T17:02:55Z
- **Status**: IN PROGRESS

### [ACTIVE] service-runtime-transactions
- **Session**: `Codex-root-service-lifetime`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/core/service.cpp kernel/core/service.h`
- **Description**: Serialize service lifecycle with reserve-execute-commit tokens and no scheduler or loader calls under the runtime lock (offline claim; remote publication pending)
- **Claimed**: 2026-07-31T17:08:41Z
- **Status**: IN PROGRESS

### [ACTIVE] rust-build-truth
- **Session**: `Codex-rust-build-truth`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/rust/CMakeLists.txt cmake/DuetOSRust.cmake tools/test/check-rust-ffi.py wiki/tooling/Rust-Subsystems.md`
- **Description**: Derive aggregate Rust build dependencies from the workspace and fail closed on Rust FFI inventory drift (offline claim; remote publication pending)
- **Claimed**: 2026-07-31T17:17:23Z
- **Status**: IN PROGRESS

### [ACTIVE] kobject-handle-v2
- **Session**: `Codex-kobject-handle-v2`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/ipc/handle_table.h`
- **Description**: No description provided
- **Claimed**: 2026-07-31T18:24:07Z
- **Status**: IN PROGRESS

### [ACTIVE] kobject-handle-v2-callers
- **Session**: `Codex-kobject-handle-v2`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/ipc/handle_table.cpp kernel/ipc/handle_table_selftest.cpp kernel/ipc/kobject.h kernel/ipc/kobject.cpp kernel/ipc/kevent.cpp kernel/ipc/kfile.cpp kernel/ipc/kmailbox.cpp kernel/ipc/kmutex.cpp kernel/ipc/ksemaphore.cpp kernel/ipc/kwaitable.cpp kernel/ipc/named_kobjects.cpp kernel/subsystems/win32/kobject_handle.h kernel/subsystems/win32/mutex_syscall.cpp kernel/subsystems/win32/mutex_syscall.h kernel/subsystems/win32/event_syscall.cpp kernel/subsystems/win32/event_syscall.h kernel/subsystems/win32/semaphore_syscall.cpp kernel/subsystems/win32/semaphore_syscall.h kernel/subsystems/win32/iocp_syscall.cpp kernel/subsystems/win32/iocp_syscall.h kernel/subsystems/win32/named_kobj_syscall.cpp kernel/subsystems/win32/named_kobj_syscall.h userland/libs/kernel32/kernel32_sync.c userland/libs/kernel32_32/kernel32_32_sync.c userland/libs/ntdll/ntdll_facades.c`
- **Description**: Generation-safe fixed-capacity opaque handles and checked KObject retention
- **Claimed**: 2026-07-31T18:24:27Z
- **Status**: IN PROGRESS

### [ACTIVE] gui-task-message-v2
- **Session**: `Codex-gui-task-queue`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/drivers/video/gui_message_queue.cpp`
- **Description**: No description provided
- **Claimed**: 2026-07-31T18:40:04Z
- **Status**: IN PROGRESS

### [ACTIVE] gui-task-message-v2-surface
- **Session**: `Codex-gui-task-queue`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/drivers/video/gui_message_queue.h kernel/drivers/video/widget.cpp kernel/drivers/video/widget.h kernel/subsystems/win32/window_syscall.cpp kernel/subsystems/win32/window_syscall.h userland/libs/user32/user32.c userland/libs/user32_32/user32_32.c wiki/subsystems/Compositor.md`
- **Description**: Per-Task transactional GUI queues and generation-safe HWND identity
- **Claimed**: 2026-07-31T18:40:21Z
- **Status**: IN PROGRESS

### [ACTIVE] gui-task-message-v2-pe32-thread
- **Session**: `Codex-gui-task-queue`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `userland/libs/user32_32/user32_32_dlg.c`
- **Description**: Route PE32 thread messages to kernel Task queues
- **Claimed**: 2026-07-31T18:41:42Z
- **Status**: IN PROGRESS

### [ACTIVE] gui-task-message-v2-gdi-identity
- **Session**: `Codex-gui-task-queue`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/subsystems/win32/gdi_objects.cpp kernel/subsystems/win32/gdi_objects.h`
- **Description**: Keep window HDC state keyed by generation-safe HWND identity
- **Claimed**: 2026-07-31T18:44:01Z
- **Status**: IN PROGRESS

### [ACTIVE] proc-resource-domain
- **Session**: `Codex-resource-domain`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/proc/resource_domain.h kernel/proc/resource_domain.cpp`
- **Description**: Generation-safe spawn-tree Section object and frame quota domains with exact final-ref charge tokens
- **Claimed**: 2026-07-31T19:00:55Z
- **Status**: IN PROGRESS

### [ACTIVE] kobject-handle-v2-thunk
- **Session**: `Nathan-1281`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/subsystems/win32/thunks_bytecode.inc`
- **Description**: Make
- **Claimed**: 2026-07-31T19:14:31Z
- **Status**: IN PROGRESS

### [ACTIVE] ipc-message-abi
- **Session**: `Codex-ipc-message-abi`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/ipc/message_abi.h`
- **Description**: No description provided
- **Claimed**: 2026-07-31T19:31:37Z
- **Status**: IN PROGRESS

### [ACTIVE] ipc-message-abi-source
- **Session**: `Codex-ipc-message-abi`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/ipc/message_abi.cpp`
- **Description**: Versioned service message validator implementation
- **Claimed**: 2026-07-31T19:32:03Z
- **Status**: IN PROGRESS

### [ACTIVE] ipc-message-abi-test
- **Session**: `Codex-ipc-message-abi`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `tests/host/test_message_abi.cpp`
- **Description**: Hostile-input and compatibility vectors for message ABI
- **Claimed**: 2026-07-31T19:32:04Z
- **Status**: IN PROGRESS

### [ACTIVE] ipc-message-abi-host-build
- **Session**: `Codex-ipc-message-abi`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `tests/host/CMakeLists.txt`
- **Description**: Register message ABI host test
- **Claimed**: 2026-07-31T19:32:04Z
- **Status**: IN PROGRESS

### [ACTIVE] boot-truth-docs
- **Session**: `Codex-gui-task-queue`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `README.md`
- **Description**: No description provided
- **Claimed**: 2026-07-31T19:37:26Z
- **Status**: IN PROGRESS

### [ACTIVE] boot-truth-wiki
- **Session**: `Codex-gui-task-queue`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `CLAUDE.md wiki/kernel/Boot.md wiki/kernel/UEFI-Loader.md wiki/getting-started/Getting-Started.md wiki/tooling/Build-System.md wiki/tooling/Running-on-VMs.md wiki/tooling/QEMU-Smoke.md wiki/reference/Daily-Driver-Readiness.md wiki/security/Linux-CVE-Audit.md`
- **Description**: Align maintainer and wiki boot claims with required GRUB plus Multiboot2 release contract and experimental direct UEFI status
- **Claimed**: 2026-07-31T19:37:39Z
- **Status**: IN PROGRESS

### [ACTIVE] boot-release-gate
- **Session**: `Codex-gui-task-queue`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `CMakeLists.txt boot/grub/grub.cfg tools/test/ctest-boot-smoke.sh .github/workflows/release.yml`
- **Description**: Require the GRUB plus Multiboot2 smoke before publication and fail closed on missing prerequisites or timeouts
- **Claimed**: 2026-07-31T19:37:47Z
- **Status**: IN PROGRESS

### [ACTIVE] immutable-load-plan
- **Session**: `Codex-kobject-handle-v2`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/loader/load_plan.h kernel/loader/load_plan.cpp tests/host/test_load_plan.cpp`
- **Description**: Versioned immutable executable load plan with allocation-free hostile-input validation
- **Claimed**: 2026-07-31T19:40:18Z
- **Status**: IN PROGRESS

### [ACTIVE] boot-truth-faq
- **Session**: `Codex-gui-task-queue`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `wiki/getting-started/FAQ.md`
- **Description**: Remove the remaining newcomer-facing claim that conflates GRUB and the experimental direct UEFI loader
- **Claimed**: 2026-07-31T19:43:36Z
- **Status**: IN PROGRESS

### [ACTIVE] boot-installer-truth
- **Session**: `Codex-gui-task-queue`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/shell/shell_storage.cpp kernel/fs/installer.cpp kernel/fs/installer.h`
- **Description**: Make installer output and comments state that embedded direct UEFI bytes are layout preparation, not a bootable installation
- **Claimed**: 2026-07-31T19:44:43Z
- **Status**: IN PROGRESS

### [ACTIVE] ipc-versioned-payload
- **Session**: `Codex-ipc-message-abi`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/ipc/versioned_payload.h kernel/ipc/versioned_payload.cpp tests/host/test_versioned_payload.cpp`
- **Description**: Allocation-free size/version-tagged payload validation and transactional encoding for generated IPC contracts
- **Claimed**: 2026-07-31T19:47:53Z
- **Status**: IN PROGRESS

### [DONE] native-syscall-idl
- **Session**: `Nathan-427`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `abi/native_syscalls.json tools/build/gen-native-syscall-abi.py tools/test/check-native-syscall-idl.py kernel/syscall/syscall_idl_generated.def userland/libc/include/duet/syscall_numbers_generated.h docs/native-syscall-policy.json docs/native-syscall-policy.md`
- **Description**: Versioned syscall IDL migration source plus generated names, policy, userland constants, fuzz/tracing metadata, and drift checks
- **Claimed**: 2026-07-31T19:52:02Z
- **Status**: COMPLETED @ 2026-07-31T20:04:28Z

### [DONE] native-syscall-names-source
- **Session**: `Nathan-1522`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/syscall/syscall_names.def`
- **Description**: Generate the complete diagnostic name table from the versioned native syscall IDL and close current 38-row inventory gap
- **Claimed**: 2026-07-31T19:56:41Z
- **Status**: COMPLETED @ 2026-07-31T20:04:31Z

### [ACTIVE] native-syscall-idl-tests
- **Session**: `Nathan-1754`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `tools/test/test-native-syscall-idl.py`
- **Description**: Hostile-schema and deterministic-output regression tests for the native syscall IDL generator
- **Claimed**: 2026-07-31T19:58:16Z
- **Status**: IN PROGRESS

### [ACTIVE] native-libc-syscall-idl
- **Session**: `Nathan-237`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `userland/libc/include/duet/syscall.h`
- **Description**: Replace duplicated native libc syscall numbers with the generated IDL header while preserving documented wrappers and socket operation constants
- **Claimed**: 2026-07-31T19:59:16Z
- **Status**: IN PROGRESS

### [ACTIVE] native-syscall-cap-policy
- **Session**: `Nathan-239`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/syscall/cap_table.def`
- **Description**: Generate the authoritative static capability gate rows from the versioned native syscall IDL
- **Claimed**: 2026-07-31T19:59:47Z
- **Status**: IN PROGRESS

### [ACTIVE] ipc-message-ring
- **Session**: `Codex-ipc-message-abi`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/ipc/message_ring.h kernel/ipc/message_ring.cpp tests/host/test_message_ring.cpp`
- **Description**: Caller-storage bounded validated message ring with explicit backpressure and transactional sequence-exact receive
- **Claimed**: 2026-07-31T20:00:08Z
- **Status**: IN PROGRESS

### [ACTIVE] native-syscall-idl-gates
- **Session**: `Nathan-990`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `tools/build/regenerate-syscall-artifacts.sh tools/dev/invariant-check.sh`
- **Description**: Regenerate and gate native syscall IDL artifacts in the existing repository static-analysis workflow
- **Claimed**: 2026-07-31T20:00:48Z
- **Status**: IN PROGRESS
