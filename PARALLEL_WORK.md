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
### [DONE] linux-mm-wx-hardening
- **Session**: `Nathan-8`
- **Branch**: `claude/linux-mmap-wx-hardening`
- **Files**: `kernel/subsystems/linux/syscall_mm.cpp kernel/subsystems/linux/mm_protection_policy.h kernel/subsystems/linux/extra_syscalls.cpp kernel/subsystems/linux/syscall_internal.h tests/host/test_linux_mm_policy.cpp tests/host/CMakeLists.txt wiki/security/WX-Enforcement.md wiki/reference/Design-Decisions.md`
- **Description**: Enforce Linux mmap and mprotect W^X policy and make mseal failure truthful
- **Claimed**: 2026-07-26T12:30:06Z
- **Status**: COMPLETED @ 2026-08-01T14:59:25Z

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

### [DONE] gpu-intel-t403-retry-1458
- **Session**: `Nathan-806`
- **Branch**: `claude/gpu-intel-t403-20260731`
- **Files**: `kernel/drivers/gpu/intel_gpu.cpp kernel/drivers/gpu/intel_gpu.h kernel/drivers/gpu/intel_gpu_cmds.h kernel/drivers/video/framebuffer.cpp tests/host/test_intel_blt.cpp tests/host/CMakeLists.txt`
- **Description**: Route eligible GDI solid fills through the verified Intel BLT engine on the owned compose surface with validation, serialization, and CPU fallback
- **Claimed**: 2026-07-31T07:24:16Z
- **Status**: COMPLETED @ 2026-07-31T07:37:50Z

### [DONE] gpu-intel-t403-final-1837
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

### [DONE] vm-process-lifetime
- **Session**: `Nathan-221`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/mm/address_space.cpp kernel/mm/address_space.h kernel/proc/process.cpp kernel/proc/process.h kernel/syscall/syscall.cpp kernel/subsystems/win32/file_syscall.cpp kernel/subsystems/win32/job_syscall.cpp docs/stability-audit-2026-07-31.md wiki/reference/Roadmap.md`
- **Description**: Retain process-handle targets and copy cross-AS memory under address-space mutation lifetime
- **Claimed**: 2026-07-31T13:58:27Z
- **Status**: COMPLETED @ 2026-08-01T03:09:57Z

### [DONE] vm-process-exit-drain
- **Session**: `Nathan-221`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/sched/sched.cpp kernel/subsystems/win32/job_syscall.h`
- **Description**: Drain owner jobs at last-task exit without releasing members under the pool lock
- **Claimed**: 2026-07-31T14:17:02Z
- **Status**: COMPLETED @ 2026-08-01T03:09:59Z

### [DONE] vm-process-abi
- **Session**: `Nathan-221`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/syscall/syscall.h userland/libs/ntdll/ntdll_reg.c wiki/specifications/Syscall-ABI.md`
- **Description**: Make capped cross-process VM calls chunked and partial-copy status truthful
- **Claimed**: 2026-07-31T14:17:15Z
- **Status**: COMPLETED @ 2026-08-01T03:10:02Z

### [DONE] vm-process-lookup-callers
- **Session**: `Nathan-221`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/subsystems/win32/spawn_syscall.cpp kernel/apps/dbg_core.cpp kernel/diag/gdb_monitor_read.cpp kernel/diag/leak_detector.cpp kernel/shell/shell_exec.cpp`
- **Description**: Replace borrowed scheduler Process pointers at dereferencing callers and serialize diagnostics
- **Claimed**: 2026-07-31T14:17:25Z
- **Status**: COMPLETED @ 2026-08-01T03:10:05Z

### [DONE] vm-process-exit-test
- **Session**: `Nathan-221`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/core/boot_bringup.cpp`
- **Description**: Run owner-job exit-drain reference-balance selftest before user tasks
- **Claimed**: 2026-07-31T14:18:14Z
- **Status**: COMPLETED @ 2026-08-01T03:10:08Z

### [DONE] vm-process-lookup-api
- **Session**: `Nathan-221`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/sched/sched.h kernel/subsystems/linux/syscall_async_io.cpp kernel/subsystems/linux/syscall_proc.cpp kernel/subsystems/linux/pidfd_splice.cpp`
- **Description**: Retire borrowed Process pointer lookup in favor of retained ownership or boolean existence queries
- **Claimed**: 2026-07-31T14:24:02Z
- **Status**: COMPLETED @ 2026-08-01T03:10:14Z

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

### [DONE] win32-job-userland-ingress
- **Session**: `Codex-job-userland`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `userland/libs/kernel32/kernel32_io.c userland/libs/ntdll/ntdll_token.c userland/libs/ntdll/ntdll.c userland/libs/ntdll/ntdll_rtl.c userland/libs/ntdll/ntdll_internal.h tools/build/build-kernel32-dll.sh userland/apps/jobobj_smoke/jobobj_smoke.c`
- **Description**: Wire real kernel32 and ntdll Job lifecycle ingress with verdict-bearing smoke coverage
- **Claimed**: 2026-07-31T15:53:38Z
- **Status**: COMPLETED @ 2026-08-01T18:58:56Z

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

### [DONE] task-user-stack-lifetime
- **Session**: `Codex-scheduler-exit-lifetime`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/proc/user_stack.cpp kernel/proc/user_stack.h kernel/subsystems/win32/thread_syscall.cpp tests/host/test_user_stack.cpp`
- **Description**: Move guarded user-stack growth and reclamation ownership from Process to Task
- **Claimed**: 2026-07-31T16:18:01Z
- **Status**: COMPLETED @ 2026-08-01T10:29:28Z

### [ACTIVE] win32-file-opaque-pe32-comments
- **Session**: `Nathan-1554`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `userland/libs/kernel32_32/kernel32_32.c userland/libs/kernel32_32/kernel32_32_fs.c`
- **Description**: Synchronize PE32 file-handle comments with opaque generation-tagged ABI
- **Claimed**: 2026-07-31T16:19:59Z
- **Status**: IN PROGRESS

### [DONE] win32-section-userland-type
- **Session**: `Nathan-1762`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `userland/libs/ntdll/ntdll_info.c`
- **Description**: Recognize opaque generation-tagged Section handles in NtQueryObject
- **Claimed**: 2026-07-31T16:23:53Z
- **Status**: COMPLETED @ 2026-08-01T13:24:01Z

### [DONE] proc-job-core-service
- **Session**: `Codex-job-core-service`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/proc/job.h`
- **Description**: No description provided
- **Claimed**: 2026-07-31T16:24:29Z
- **Status**: COMPLETED @ 2026-08-01T18:58:59Z

### [DONE] proc-job-core-source
- **Session**: `Codex-job-core-service`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/proc/job.cpp`
- **Description**: No description provided
- **Claimed**: 2026-07-31T16:24:48Z
- **Status**: COMPLETED @ 2026-08-01T18:59:02Z

### [DONE] proc-job-win32-header
- **Session**: `Codex-job-core-service`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/subsystems/win32/job_syscall.h`
- **Description**: No description provided
- **Claimed**: 2026-07-31T16:24:50Z
- **Status**: COMPLETED @ 2026-08-01T18:59:04Z

### [DONE] proc-job-win32-adapter
- **Session**: `Codex-job-core-service`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/subsystems/win32/job_syscall.cpp`
- **Description**: No description provided
- **Claimed**: 2026-07-31T16:24:52Z
- **Status**: COMPLETED @ 2026-08-01T18:59:07Z

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

### [DONE] win32-section-fork-cursor
- **Session**: `Nathan-86`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/subsystems/linux/syscall_clone.cpp`
- **Description**: Snapshot the shared mmap cursor atomically when forking a Process
- **Claimed**: 2026-07-31T16:51:58Z
- **Status**: COMPLETED @ 2026-08-01T10:29:30Z

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

### [DONE] service-runtime-transactions
- **Session**: `Codex-root-service-lifetime`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/core/service.cpp kernel/core/service.h`
- **Description**: Serialize service lifecycle with reserve-execute-commit tokens and no scheduler or loader calls under the runtime lock (offline claim; remote publication pending)
- **Claimed**: 2026-07-31T17:08:41Z
- **Status**: COMPLETED @ 2026-08-01T15:00:46Z

### [DONE] rust-build-truth
- **Session**: `Codex-rust-build-truth`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/rust/CMakeLists.txt cmake/DuetOSRust.cmake tools/test/check-rust-ffi.py wiki/tooling/Rust-Subsystems.md`
- **Description**: Derive aggregate Rust build dependencies from the workspace and fail closed on Rust FFI inventory drift (offline claim; remote publication pending)
- **Claimed**: 2026-07-31T17:17:23Z
- **Status**: COMPLETED @ 2026-08-01T18:16:35Z

### [ACTIVE] kobject-handle-v2
- **Session**: `Codex-kobject-handle-v2`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/ipc/handle_table.h`
- **Description**: No description provided
- **Claimed**: 2026-07-31T18:24:07Z
- **Status**: IN PROGRESS

### [DONE] kobject-handle-v2-callers
- **Session**: `Codex-kobject-handle-v2`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/ipc/handle_table.cpp kernel/ipc/handle_table_selftest.cpp kernel/ipc/kobject.h kernel/ipc/kobject.cpp kernel/ipc/kevent.cpp kernel/ipc/kfile.cpp kernel/ipc/kmailbox.cpp kernel/ipc/kmutex.cpp kernel/ipc/ksemaphore.cpp kernel/ipc/kwaitable.cpp kernel/ipc/named_kobjects.cpp kernel/subsystems/win32/kobject_handle.h kernel/subsystems/win32/mutex_syscall.cpp kernel/subsystems/win32/mutex_syscall.h kernel/subsystems/win32/event_syscall.cpp kernel/subsystems/win32/event_syscall.h kernel/subsystems/win32/semaphore_syscall.cpp kernel/subsystems/win32/semaphore_syscall.h kernel/subsystems/win32/iocp_syscall.cpp kernel/subsystems/win32/iocp_syscall.h kernel/subsystems/win32/named_kobj_syscall.cpp kernel/subsystems/win32/named_kobj_syscall.h userland/libs/kernel32/kernel32_sync.c userland/libs/kernel32_32/kernel32_32_sync.c userland/libs/ntdll/ntdll_facades.c`
- **Description**: Generation-safe fixed-capacity opaque handles and checked KObject retention
- **Claimed**: 2026-07-31T18:24:27Z
- **Status**: COMPLETED @ 2026-08-02T04:52:55Z

### [DONE] gui-task-message-v2
- **Session**: `Codex-gui-task-queue`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/drivers/video/gui_message_queue.cpp`
- **Description**: No description provided
- **Claimed**: 2026-07-31T18:40:04Z
- **Status**: COMPLETED @ 2026-08-01T04:31:16Z

### [DONE] gui-task-message-v2-surface
- **Session**: `Codex-gui-task-queue`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/drivers/video/gui_message_queue.h kernel/drivers/video/widget.cpp kernel/drivers/video/widget.h kernel/subsystems/win32/window_syscall.cpp kernel/subsystems/win32/window_syscall.h userland/libs/user32/user32.c userland/libs/user32_32/user32_32.c wiki/subsystems/Compositor.md`
- **Description**: Per-Task transactional GUI queues and generation-safe HWND identity
- **Claimed**: 2026-07-31T18:40:21Z
- **Status**: COMPLETED @ 2026-08-01T04:31:17Z

### [DONE] gui-task-message-v2-pe32-thread
- **Session**: `Codex-gui-task-queue`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `userland/libs/user32_32/user32_32_dlg.c`
- **Description**: Route PE32 thread messages to kernel Task queues
- **Claimed**: 2026-07-31T18:41:42Z
- **Status**: COMPLETED @ 2026-08-01T04:31:19Z

### [DONE] gui-task-message-v2-gdi-identity
- **Session**: `Codex-gui-task-queue`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/subsystems/win32/gdi_objects.cpp kernel/subsystems/win32/gdi_objects.h`
- **Description**: Keep window HDC state keyed by generation-safe HWND identity
- **Claimed**: 2026-07-31T18:44:01Z
- **Status**: COMPLETED @ 2026-08-01T04:31:21Z

### [DONE] proc-resource-domain
- **Session**: `Codex-resource-domain`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/proc/resource_domain.h kernel/proc/resource_domain.cpp`
- **Description**: Generation-safe spawn-tree Section object and frame quota domains with exact final-ref charge tokens
- **Claimed**: 2026-07-31T19:00:55Z
- **Status**: COMPLETED @ 2026-08-01T03:00:59Z

### [ACTIVE] kobject-handle-v2-thunk
- **Session**: `Nathan-1281`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/subsystems/win32/thunks_bytecode.inc`
- **Description**: Make
- **Claimed**: 2026-07-31T19:14:31Z
- **Status**: IN PROGRESS

### [DONE] ipc-message-abi
- **Session**: `Codex-ipc-message-abi`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/ipc/message_abi.h`
- **Description**: No description provided
- **Claimed**: 2026-07-31T19:31:37Z
- **Status**: COMPLETED @ 2026-08-01T00:22:22Z

### [DONE] ipc-message-abi-source
- **Session**: `Codex-ipc-message-abi`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/ipc/message_abi.cpp`
- **Description**: Versioned service message validator implementation
- **Claimed**: 2026-07-31T19:32:03Z
- **Status**: COMPLETED @ 2026-08-01T00:22:24Z

### [DONE] ipc-message-abi-test
- **Session**: `Codex-ipc-message-abi`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `tests/host/test_message_abi.cpp`
- **Description**: Hostile-input and compatibility vectors for message ABI
- **Claimed**: 2026-07-31T19:32:04Z
- **Status**: COMPLETED @ 2026-08-01T00:22:27Z

### [DONE] ipc-message-abi-host-build
- **Session**: `Codex-ipc-message-abi`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `tests/host/CMakeLists.txt`
- **Description**: Register message ABI host test
- **Claimed**: 2026-07-31T19:32:04Z
- **Status**: COMPLETED @ 2026-08-01T00:22:29Z

### [DONE] boot-truth-docs
- **Session**: `Codex-gui-task-queue`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `README.md`
- **Description**: No description provided
- **Claimed**: 2026-07-31T19:37:26Z
- **Status**: COMPLETED @ 2026-08-01T04:31:24Z

### [DONE] boot-truth-wiki
- **Session**: `Codex-gui-task-queue`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `CLAUDE.md wiki/kernel/Boot.md wiki/kernel/UEFI-Loader.md wiki/getting-started/Getting-Started.md wiki/tooling/Build-System.md wiki/tooling/Running-on-VMs.md wiki/tooling/QEMU-Smoke.md wiki/reference/Daily-Driver-Readiness.md wiki/security/Linux-CVE-Audit.md`
- **Description**: Align maintainer and wiki boot claims with required GRUB plus Multiboot2 release contract and experimental direct UEFI status
- **Claimed**: 2026-07-31T19:37:39Z
- **Status**: COMPLETED @ 2026-08-01T04:31:31Z

### [DONE] boot-release-gate
- **Session**: `Codex-gui-task-queue`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `CMakeLists.txt boot/grub/grub.cfg tools/test/ctest-boot-smoke.sh .github/workflows/release.yml`
- **Description**: Require the GRUB plus Multiboot2 smoke before publication and fail closed on missing prerequisites or timeouts
- **Claimed**: 2026-07-31T19:37:47Z
- **Status**: COMPLETED @ 2026-08-01T04:31:33Z

### [DONE] immutable-load-plan
- **Session**: `Codex-kobject-handle-v2`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/loader/load_plan.h kernel/loader/load_plan.cpp tests/host/test_load_plan.cpp`
- **Description**: Versioned immutable executable load plan with allocation-free hostile-input validation
- **Claimed**: 2026-07-31T19:40:18Z
- **Status**: COMPLETED @ 2026-08-02T09:44:43Z

### [DONE] boot-truth-faq
- **Session**: `Codex-gui-task-queue`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `wiki/getting-started/FAQ.md`
- **Description**: Remove the remaining newcomer-facing claim that conflates GRUB and the experimental direct UEFI loader
- **Claimed**: 2026-07-31T19:43:36Z
- **Status**: COMPLETED @ 2026-08-01T04:31:35Z

### [DONE] boot-installer-truth
- **Session**: `Codex-gui-task-queue`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/shell/shell_storage.cpp kernel/fs/installer.cpp kernel/fs/installer.h`
- **Description**: Make installer output and comments state that embedded direct UEFI bytes are layout preparation, not a bootable installation
- **Claimed**: 2026-07-31T19:44:43Z
- **Status**: COMPLETED @ 2026-08-01T04:31:37Z

### [DONE] ipc-versioned-payload
- **Session**: `Codex-ipc-message-abi`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/ipc/versioned_payload.h kernel/ipc/versioned_payload.cpp tests/host/test_versioned_payload.cpp`
- **Description**: Allocation-free size/version-tagged payload validation and transactional encoding for generated IPC contracts
- **Claimed**: 2026-07-31T19:47:53Z
- **Status**: COMPLETED @ 2026-08-01T03:04:06Z

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

### [DONE] native-syscall-idl-tests
- **Session**: `Nathan-1754`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `tools/test/test-native-syscall-idl.py`
- **Description**: Hostile-schema and deterministic-output regression tests for the native syscall IDL generator
- **Claimed**: 2026-07-31T19:58:16Z
- **Status**: COMPLETED @ 2026-07-31T20:04:33Z

### [DONE] native-libc-syscall-idl
- **Session**: `Nathan-237`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `userland/libc/include/duet/syscall.h`
- **Description**: Replace duplicated native libc syscall numbers with the generated IDL header while preserving documented wrappers and socket operation constants
- **Claimed**: 2026-07-31T19:59:16Z
- **Status**: COMPLETED @ 2026-07-31T20:04:35Z

### [DONE] native-syscall-cap-policy
- **Session**: `Nathan-239`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/syscall/cap_table.def`
- **Description**: Generate the authoritative static capability gate rows from the versioned native syscall IDL
- **Claimed**: 2026-07-31T19:59:47Z
- **Status**: COMPLETED @ 2026-07-31T20:04:36Z

### [DONE] ipc-message-ring
- **Session**: `Codex-ipc-message-abi`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/ipc/message_ring.h kernel/ipc/message_ring.cpp tests/host/test_message_ring.cpp`
- **Description**: Caller-storage bounded validated message ring with explicit backpressure and transactional sequence-exact receive
- **Claimed**: 2026-07-31T20:00:08Z
- **Status**: COMPLETED @ 2026-08-01T03:03:33Z

### [DONE] native-syscall-idl-gates
- **Session**: `Nathan-990`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `tools/build/regenerate-syscall-artifacts.sh tools/dev/invariant-check.sh`
- **Description**: Regenerate and gate native syscall IDL artifacts in the existing repository static-analysis workflow
- **Claimed**: 2026-07-31T20:00:48Z
- **Status**: COMPLETED @ 2026-07-31T20:04:38Z

### [DONE] socket-alloc-transaction
- **Session**: `Nathan-1456`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/net/socket.cpp`
- **Description**: Atomic socket slot reservation across BSP preemption and SMP allocation races
- **Claimed**: 2026-07-31T20:08:21Z
- **Status**: COMPLETED @ 2026-08-02T04:09:57Z

### [DONE] rust-ffi-hard-ingress
- **Session**: `Nathan-1340`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/acpi/acpi_rust/src/lib.rs kernel/arch/x86_64/smbios_rust/src/lib.rs kernel/drivers/pci/caps_rust/src/lib.rs kernel/drivers/usb/class_rust/src/lib.rs kernel/drivers/usb/hid_rust/src/lib.rs kernel/drivers/usb/msc_scsi_rust/src/lib.rs kernel/fs/duetfs/src/ffi.rs kernel/fs/exfat_rust/src/lib.rs kernel/fs/ext4_rust/src/lib.rs kernel/fs/ntfs_rust/src/lib.rs kernel/loader/exec_meta_rust/src/lib.rs kernel/mm/multiboot2_rust/src/lib.rs kernel/net/hci_rust/src/lib.rs kernel/net/parsers_rust/src/lib.rs kernel/net/tls_rust/src/lib.rs kernel/net/wifi80211_rust/src/lib.rs kernel/util/img_meta_rust/src/lib.rs`
- **Description**: Make raw-pointer exports explicitly unsafe and bind raw-derived references to call-local scopes
- **Claimed**: 2026-07-31T20:10:15Z
- **Status**: COMPLETED @ 2026-07-31T20:35:21Z

### [DONE] resource-domain-host-properties
- **Session**: `Codex-resource-domain`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `tests/host/test_resource_domain.cpp`
- **Description**: Host ownership quota generation and concurrent charge-release properties for ResourceDomain
- **Claimed**: 2026-07-31T20:18:14Z
- **Status**: COMPLETED @ 2026-08-01T03:01:32Z

### [DONE] load-image-staging
- **Session**: `Nathan-1074`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/loader/load_image.h kernel/loader/load_image.cpp tests/host/test_load_image.cpp`
- **Description**: Loader-private staging package with sealed LoadPlan backing and transactional ownership map
- **Claimed**: 2026-07-31T20:19:16Z
- **Status**: COMPLETED @ 2026-08-02T03:55:58Z

### [DONE] ipc-message-port
- **Session**: `Codex-resource-domain`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/ipc/kmessage_port.h kernel/ipc/kmessage_port.cpp tests/host/test_kmessage_port.cpp`
- **Description**: Generation-safe waitable MessagePort KObject atop validated MessageRing
- **Claimed**: 2026-07-31T20:34:40Z
- **Status**: COMPLETED @ 2026-08-01T03:03:48Z

### [DONE] gui-window-side-tables
- **Session**: `Codex-gui-task-queue`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/core/boot_tasks.cpp kernel/core/menu_dispatch.cpp kernel/core/menu_dispatch.h kernel/drivers/video/menu.cpp kernel/drivers/video/menu.h`
- **Description**: Generation-tagged gesture and window-menu contexts with stale-generation cancellation
- **Claimed**: 2026-07-31T20:43:31Z
- **Status**: COMPLETED @ 2026-08-01T04:31:39Z

### [ACTIVE] host-msvc-d3dcompiler
- **Session**: `Nathan-610`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `tests/host/test_d3dcompiler.cpp`
- **Description**: Guard
- **Claimed**: 2026-07-31T20:58:17Z
- **Status**: IN PROGRESS

### [ACTIVE] host-msvc-production-portability
- **Session**: `Nathan-1176`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/debug/probes.h`
- **Description**: No description provided
- **Claimed**: 2026-07-31T21:14:35Z
- **Status**: IN PROGRESS

### [ACTIVE] host-msvc-render-stats
- **Session**: `Nathan-1882`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/drivers/video/render_stats.cpp`
- **Description**: Rename
- **Claimed**: 2026-07-31T21:14:42Z
- **Status**: IN PROGRESS

### [DONE] exec-admission
- **Session**: `Codex-exec-admission`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/loader/exec_admission.h kernel/loader/exec_admission.cpp tests/host/test_exec_admission.cpp`
- **Description**: Allocation-free frozen executable-plan admission seam with exact prepare consume cancel identity
- **Claimed**: 2026-07-31T21:15:59Z
- **Status**: COMPLETED @ 2026-08-02T05:52:59Z

### [ACTIVE] host-msvc-kernel32-nls-test
- **Session**: `Nathan-1841`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `tests/host/test_kernel32_nls.cpp`
- **Description**: Map
- **Claimed**: 2026-07-31T21:17:07Z
- **Status**: IN PROGRESS

### [DONE] proc-credentials-api
- **Session**: `Nathan-1200`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/proc/credentials.h`
- **Description**: Immutable
- **Claimed**: 2026-07-31T21:21:30Z
- **Status**: COMPLETED @ 2026-08-02T08:07:50Z

### [DONE] proc-credentials-core
- **Session**: `Nathan-418`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/proc/credentials.cpp`
- **Description**: Fixed-pool
- **Claimed**: 2026-07-31T21:21:31Z
- **Status**: COMPLETED @ 2026-08-02T08:07:57Z

### [DONE] proc-credentials-host
- **Session**: `Nathan-383`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `tests/host/test_credentials.cpp`
- **Description**: Credential
- **Claimed**: 2026-07-31T21:21:32Z
- **Status**: COMPLETED @ 2026-08-02T08:08:05Z

### [ACTIVE] gui-message-queue-host-properties
- **Session**: `Nathan-601`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `tests/host/test_gui_message_queue.cpp`
- **Description**: Host production queue properties, deterministic concurrency, sanitizer gate
- **Claimed**: 2026-07-31T21:29:27Z
- **Status**: IN PROGRESS

### [ACTIVE] gui-message-policy
- **Session**: `Nathan-1665`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/drivers/video/gui_message_policy.h kernel/drivers/video/gui_message_policy.cpp tests/host/test_gui_message_policy.cpp`
- **Description**: Pure bounded cross-process GUI broker authorization policy and host properties
- **Claimed**: 2026-07-31T21:37:46Z
- **Status**: IN PROGRESS

### [DONE] Codex-exec-admission
- **Session**: `Nathan-1477`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `execd-protocol`
- **Description**: kernel/loader/execd_protocol.h
- **Claimed**: 2026-07-31T21:38:56Z
- **Status**: COMPLETED @ 2026-07-31T21:39:16Z

### [ACTIVE] execd-protocol
- **Session**: `Nathan-1607`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/loader/execd_protocol.h`
- **Description**: No description provided
- **Claimed**: 2026-07-31T21:39:18Z
- **Status**: IN PROGRESS

### [ACTIVE] execd-protocol-source
- **Session**: `Nathan-922`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/loader/execd_protocol.cpp`
- **Description**: Transport-neutral
- **Claimed**: 2026-07-31T21:39:33Z
- **Status**: IN PROGRESS

### [ACTIVE] execd-protocol-test
- **Session**: `Nathan-945`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `tests/host/test_execd_protocol.cpp`
- **Description**: Hostile
- **Claimed**: 2026-07-31T21:39:40Z
- **Status**: IN PROGRESS

### [DONE] proc-thread-group-api
- **Session**: `Nathan-963`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/proc/thread_group.h`
- **Description**: Opaque
- **Claimed**: 2026-07-31T21:41:56Z
- **Status**: COMPLETED @ 2026-08-02T09:46:01Z

### [DONE] proc-thread-group-core
- **Session**: `Nathan-2031`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/proc/thread_group.cpp`
- **Description**: Allocation-free
- **Claimed**: 2026-07-31T21:42:01Z
- **Status**: COMPLETED @ 2026-08-02T09:46:13Z

### [DONE] proc-thread-group-host
- **Session**: `Nathan-535`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `tests/host/test_thread_group.cpp`
- **Description**: ThreadGroup
- **Claimed**: 2026-07-31T21:42:06Z
- **Status**: COMPLETED @ 2026-08-02T09:46:26Z

### [ACTIVE] gui-broker-protocol
- **Session**: `Nathan-1592`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/drivers/video/gui_broker_protocol.h kernel/drivers/video/gui_broker_protocol.cpp tests/host/test_gui_broker_protocol.cpp`
- **Description**: Versioned transport-independent GUI broker wire contract and hostile host vectors
- **Claimed**: 2026-07-31T21:49:13Z
- **Status**: IN PROGRESS

### [ACTIVE] process-decomposition-map
- **Session**: `Nathan-1684`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `docs/process-decomposition-2026-07-31.md`
- **Description**: Implementation-grade
- **Claimed**: 2026-07-31T21:55:32Z
- **Status**: IN PROGRESS

### [DONE] ipc-object-transfer
- **Session**: `Nathan-1481`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/ipc/object_transfer.h`
- **Description**: Endpoint-owned
- **Claimed**: 2026-07-31T22:01:39Z
- **Status**: COMPLETED @ 2026-08-02T07:09:27Z

### [DONE] ipc-object-transfer-source
- **Session**: `Nathan-840`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/ipc/object_transfer.cpp`
- **Description**: Object
- **Claimed**: 2026-07-31T22:01:49Z
- **Status**: COMPLETED @ 2026-08-02T07:09:34Z

### [DONE] ipc-object-transfer-test
- **Session**: `Nathan-1467`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `tests/host/test_object_transfer.cpp`
- **Description**: Hostile
- **Claimed**: 2026-07-31T22:01:58Z
- **Status**: COMPLETED @ 2026-08-02T07:09:41Z

### [ACTIVE] service-publication-state
- **Session**: `Nathan-1202`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/core/service_transition.h`
- **Description**: No description provided
- **Claimed**: 2026-07-31T22:02:34Z
- **Status**: IN PROGRESS

### [ACTIVE] service-publication-state-source
- **Session**: `Nathan-700`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/core/service_transition.cpp`
- **Description**: Service_transition_source
- **Claimed**: 2026-07-31T22:02:49Z
- **Status**: IN PROGRESS

### [ACTIVE] service-publication-state-test
- **Session**: `Nathan-682`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `tests/host/test_service_transition.cpp`
- **Description**: Service_transition_host_properties
- **Claimed**: 2026-07-31T22:02:50Z
- **Status**: IN PROGRESS

### [ACTIVE] serviced-protocol-api
- **Session**: `Nathan-331`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/core/serviced_protocol.h`
- **Description**: Capability_checked_serviced_wire_api
- **Claimed**: 2026-07-31T22:10:55Z
- **Status**: IN PROGRESS

### [ACTIVE] serviced-protocol-source
- **Session**: `Nathan-344`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/core/serviced_protocol.cpp`
- **Description**: Transport_neutral_serviced_wire_validation
- **Claimed**: 2026-07-31T22:10:56Z
- **Status**: IN PROGRESS

### [ACTIVE] serviced-protocol-test
- **Session**: `Nathan-313`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `tests/host/test_serviced_protocol.cpp`
- **Description**: Hostile_serviced_protocol_vectors
- **Claimed**: 2026-07-31T22:10:57Z
- **Status**: IN PROGRESS

### [ACTIVE] service-extraction-map
- **Session**: `Nathan-455`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `docs/service-extraction-2026-07-31.md`
- **Description**: Implementation-grade serviced to execd displayd registryd netd extraction architecture map
- **Claimed**: 2026-07-31T22:16:14Z
- **Status**: IN PROGRESS

### [ACTIVE] gui-send-transaction
- **Session**: `Nathan-960`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/drivers/video/gui_send_transaction.h kernel/drivers/video/gui_send_transaction.cpp tests/host/test_gui_send_transaction.cpp`
- **Description**: Generation-safe synchronous GUI SendMessage transaction table and hostile host vectors
- **Claimed**: 2026-07-31T22:22:40Z
- **Status**: IN PROGRESS

### [DONE] service-manifest-api
- **Session**: `Nathan-1113`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/core/service_manifest.h`
- **Description**: Immutable bounded service manifest byte contract
- **Claimed**: 2026-07-31T22:25:38Z
- **Status**: COMPLETED @ 2026-07-31T23:32:44Z

### [DONE] service-manifest-source
- **Session**: `Nathan-1039`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/core/service_manifest.cpp`
- **Description**: Canonical LE decoder and trusted authority narrowing
- **Claimed**: 2026-07-31T22:25:43Z
- **Status**: COMPLETED @ 2026-07-31T23:32:50Z

### [DONE] service-manifest-test
- **Session**: `Nathan-1381`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `tests/host/test_service_manifest.cpp`
- **Description**: Hostile deterministic DAG and authority tests
- **Claimed**: 2026-07-31T22:25:50Z
- **Status**: COMPLETED @ 2026-07-31T23:32:59Z

### [DONE] ipc-endpoint-request-ledger
- **Session**: `Nathan-1761`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/ipc/endpoint_request_ledger.h kernel/ipc/endpoint_request_ledger.cpp tests/host/test_endpoint_request_ledger.cpp`
- **Description**: Caller-locked fixed-capacity exact endpoint epoch and request lifecycle ledger
- **Claimed**: 2026-07-31T23:02:15Z
- **Status**: COMPLETED @ 2026-07-31T23:15:03Z

### [DONE] service-lifecycle-broker
- **Session**: `Codex-root-lifecycle`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/core/service_lifecycle_broker.h`
- **Description**: No description provided
- **Claimed**: 2026-07-31T23:06:33Z
- **Status**: COMPLETED @ 2026-08-01T00:07:22Z

### [DONE] native-syscall-policy-json
- **Session**: `Nathan-663`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `tools/build/gen-native-syscall-abi.py tools/test/test-native-syscall-idl.py docs/native-syscall-policy.json`
- **Description**: Generate canonical machine-readable native syscall policy JSON with deterministic drift coverage
- **Claimed**: 2026-07-31T23:06:45Z
- **Status**: COMPLETED @ 2026-08-02T03:14:42Z

### [DONE] service-lifecycle-broker-source
- **Session**: `Codex-root-lifecycle`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/core/service_lifecycle_broker.cpp`
- **Description**: Lifecycle
- **Claimed**: 2026-07-31T23:06:48Z
- **Status**: COMPLETED @ 2026-08-01T00:07:33Z

### [DONE] service-lifecycle-broker-test
- **Session**: `Codex-root-lifecycle`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `tests/host/test_service_lifecycle_broker.cpp`
- **Description**: Lifecycle
- **Claimed**: 2026-07-31T23:06:50Z
- **Status**: COMPLETED @ 2026-08-01T00:07:39Z

### [DONE] native-syscall-dispatch-bijection
- **Session**: `Nathan-1412`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `tools/test/native-syscall-dispatch-bijection.py tools/test/test-native-syscall-dispatch-bijection.py`
- **Description**: Bounded native syscall IDL enum dispatch bijection and migration classification gate
- **Claimed**: 2026-07-31T23:16:05Z
- **Status**: COMPLETED @ 2026-07-31T23:26:49Z

### [ACTIVE] gui-send-service-foundation
- **Session**: `Codex-gui-send-service`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/drivers/video/gui_send_service.h kernel/drivers/video/gui_send_service.cpp tests/host/test_gui_send_service.cpp`
- **Description**: Non-hot-reloadable same-process synchronous GUI send service foundation
- **Claimed**: 2026-07-31T23:18:57Z
- **Status**: IN PROGRESS

### [DONE] service-lifecycle-lockdep
- **Session**: `Nathan-1167`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/sync/lockdep.h kernel/sync/lockdep.cpp`
- **Description**: Register scheduler-to-service lifecycle broker lock ordering
- **Claimed**: 2026-07-31T23:21:50Z
- **Status**: COMPLETED @ 2026-08-01T00:07:46Z

### [DONE] rust-ffi-signature-parity
- **Session**: `Nathan-1196`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `tools/test/check-rust-ffi-signatures.py tools/test/test-rust-ffi-signatures.py`
- **Description**: Bounded canonical C/Rust FFI arity type pointer-depth and constness parity gate
- **Claimed**: 2026-07-31T23:40:31Z
- **Status**: COMPLETED @ 2026-07-31T23:46:59Z

### [DONE] service-manifest-authority-replay
- **Session**: `Nathan-1892`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/core/service_manifest.h kernel/core/service_manifest.cpp tests/host/test_service_manifest.cpp`
- **Description**: Expose pure native document against retained authority validation for lifecycle broker anti-forgery
- **Claimed**: 2026-07-31T23:45:31Z
- **Status**: COMPLETED @ 2026-08-01T00:06:20Z

### [ACTIVE] gui-send-lockdep
- **Session**: `Codex-gui-send-service`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/sync/lockdep.h`
- **Description**: No description provided
- **Claimed**: 2026-08-01T00:14:07Z
- **Status**: IN PROGRESS

### [ACTIVE] gui-send-lockdep-registration
- **Session**: `Codex-gui-send-service`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/sync/lockdep.cpp`
- **Description**: Register GUI send lock classes
- **Claimed**: 2026-08-01T00:14:23Z
- **Status**: IN PROGRESS

### [DONE] rust-ffi-bounded-signature-walk
- **Session**: `Codex-rust-ffi-scan`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `tools/test/check-rust-ffi-signatures.py tools/test/test-rust-ffi-signatures.py`
- **Description**: Single-pass bounded prunable Rust FFI signature inventory and hostile traversal tests
- **Claimed**: 2026-08-01T00:36:35Z
- **Status**: COMPLETED @ 2026-08-01T18:16:38Z

### [DONE] ipc-channel-core-codex-20260801
- **Session**: `Nathan-1571`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/ipc/channel_core.h`
- **Description**: No description provided
- **Claimed**: 2026-08-01T02:53:15Z
- **Status**: COMPLETED @ 2026-08-01T02:54:13Z

### [DONE] ipc-channel-core-codex-20260801-exact
- **Session**: `Codex-channel-core-20260801`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/ipc/channel_core.h kernel/ipc/channel_core.cpp tests/host/test_channel_core.cpp`
- **Description**: Internal generation-safe paired channel owner primitive
- **Claimed**: 2026-08-01T02:54:16Z
- **Status**: COMPLETED @ 2026-08-01T05:16:41Z

### [DONE] proc-resource-channel-charge-20260801
- **Session**: `Codex-resource-channel-charge-20260801`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/proc/resource_domain.h kernel/proc/resource_domain.cpp tests/host/test_resource_domain_channel.cpp`
- **Description**: Generation-safe ResourceDomain channel charge authority
- **Claimed**: 2026-08-01T03:02:15Z
- **Status**: COMPLETED @ 2026-08-01T18:56:20Z

### [DONE] ipc-message-ring-port-p2-coverage
- **Session**: `Codex-gui-task-queue`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/ipc/message_ring.h kernel/ipc/message_ring.cpp tests/host/test_message_ring.cpp kernel/ipc/kmessage_port.h kernel/ipc/kmessage_port.cpp tests/host/test_kmessage_port.cpp`
- **Description**: Deterministic reservation-exhaustion and close-during-copy host coverage
- **Claimed**: 2026-08-01T03:07:43Z
- **Status**: COMPLETED @ 2026-08-01T04:31:47Z

### [DONE] vm-exec-reaper-transaction-20260801
- **Session**: `Codex-vm-exec-reaper-20260801`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/sched/sched.cpp kernel/sched/sched.h kernel/syscall/syscall.cpp kernel/proc/process.cpp kernel/proc/process.h`
- **Description**: Serialize exec with dead-task stack drain and reject live borrowed mappings
- **Claimed**: 2026-08-01T03:19:44Z
- **Status**: COMPLETED @ 2026-08-01T14:18:41Z

### [DONE] core-service-directory-20260801
- **Session**: `Codex-service-directory-20260801`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/core/service_directory.h kernel/core/service_directory.cpp tests/host/test_service_directory.cpp`
- **Description**: Bounded generation-safe internal service directory
- **Claimed**: 2026-08-01T03:27:54Z
- **Status**: COMPLETED @ 2026-08-01T04:53:20Z

### [DONE] boot-verdict-verifier
- **Session**: `Codex-gui-task-queue`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `tools/test/verify-boot-verdict.py tools/test/test-verify-boot-verdict.py`
- **Description**: Bounded machine-readable exact SMP boot-report completion and exit-class verifier with hostile tests
- **Claimed**: 2026-08-01T03:29:56Z
- **Status**: COMPLETED @ 2026-08-01T04:31:49Z

### [DONE] smoke-profile-smp-producer
- **Session**: `Codex-gui-task-queue`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/core/main.cpp`
- **Description**: Move smoke profile termination after SMP and Userland phases so exact CPU verdicts are producible
- **Claimed**: 2026-08-01T03:44:11Z
- **Status**: COMPLETED @ 2026-08-01T04:31:51Z

### [DONE] vm-sysv-attach-transaction-20260801
- **Session**: `Codex-process-section-audit`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/subsystems/linux/sysv_ipc.cpp`
- **Description**: Serialize SysV SHM attach rows with Process VM transaction and exact borrowed-range publication
- **Claimed**: 2026-08-01T03:44:51Z
- **Status**: COMPLETED @ 2026-08-01T04:39:28Z

### [DONE] smoke-profile-smp-order-test
- **Session**: `Codex-gui-task-queue`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `tools/test/test-smoke-profile-order.py`
- **Description**: Semantic structural guard for target spawn SMP topology IPI Userland smoke termination ordering
- **Claimed**: 2026-08-01T03:46:14Z
- **Status**: COMPLETED @ 2026-08-01T04:31:53Z

### [DONE] authorization-context-foundation-20260801
- **Session**: `Codex-root-authorization-20260801`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/proc/authorization_context.h kernel/proc/authorization_context.cpp tests/host/test_authorization_context.cpp`
- **Description**: Standalone generation-safe DuetOS authorization authority and enforcement accounting service
- **Claimed**: 2026-08-01T03:56:03Z
- **Status**: COMPLETED @ 2026-08-01T04:29:48Z

### [DONE] gui-broker-protocol-reply-layout
- **Session**: `Codex-gui-task-queue`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/drivers/video/gui_broker_protocol.h kernel/drivers/video/gui_broker_protocol.cpp tests/host/test_gui_broker_protocol.cpp`
- **Description**: Adopt stale broker claim and repair reply sequence wire offset with hostile vectors
- **Claimed**: 2026-08-01T04:13:46Z
- **Status**: COMPLETED @ 2026-08-01T04:31:55Z

### [DONE] boot-verdict-integration
- **Session**: `Codex-boot-verdict-integration`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `tools/test/profile-boot-smoke.sh`
- **Description**: No description provided
- **Claimed**: 2026-08-01T04:33:38Z
- **Status**: COMPLETED @ 2026-08-01T04:50:12Z

### [DONE] boot-verdict-integration-ctest
- **Session**: `Codex-boot-verdict-integration`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `tools/test/ctest-boot-smoke.sh`
- **Description**: strict_boot_verdict_in_ctest_runner
- **Claimed**: 2026-08-01T04:33:50Z
- **Status**: COMPLETED @ 2026-08-01T04:50:14Z

### [DONE] boot-verdict-integration-ci
- **Session**: `Codex-boot-verdict-integration`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `.github/workflows/build.yml`
- **Description**: exact_2_and_4_vcpu_machine_verdict_CI
- **Claimed**: 2026-08-01T04:33:51Z
- **Status**: COMPLETED @ 2026-08-01T04:50:16Z

### [DONE] boot-verdict-integration-host-test
- **Session**: `Codex-boot-verdict-integration`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `tools/test/test-profile-boot-verdict-integration.py`
- **Description**: hostile_runner_wiring_and_exact_2_4_cpu_contracts
- **Claimed**: 2026-08-01T04:36:19Z
- **Status**: COMPLETED @ 2026-08-01T04:50:19Z

### [DONE] Codex-boot-order-crash
- **Session**: `Nathan-1516`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/core/boot_bringup.cpp tools/test/test-service-boot-order.py`
- **Description**: Move user service launch behind scheduler initialization and guard boot source ordering
- **Claimed**: 2026-08-01T04:43:11Z
- **Status**: COMPLETED @ 2026-08-01T05:04:25Z

### [DONE] authorization-context-audit-source-20260801
- **Session**: `Nathan-1525`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/proc/authorization_context.h`
- **Description**: No description provided
- **Claimed**: 2026-08-01T04:45:20Z
- **Status**: COMPLETED @ 2026-08-01T04:46:05Z

### [DONE] authorization-context-audit-full-20260801
- **Session**: `Nathan-1836`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/proc/authorization_context.h`
- **Description**: kernel/proc/authorization_context.cpp
- **Claimed**: 2026-08-01T04:46:13Z
- **Status**: COMPLETED @ 2026-08-01T04:46:39Z

### [DONE] authorization-context-audit-20260801
- **Session**: `Nathan-639`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/proc/authorization_context.h,kernel/proc/authorization_context.cpp,tests/host/test_authorization_context.cpp`
- **Description**: independent_authorization_context_audit_and_replay_watermark_hostile_coverage
- **Claimed**: 2026-08-01T04:46:47Z
- **Status**: COMPLETED @ 2026-08-01T04:50:02Z

### [DONE] service-directory-cleanup-20260801
- **Session**: `Codex-service-cleanup-repair`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/core/service_directory.h`
- **Description**: No description provided
- **Claimed**: 2026-08-01T04:53:29Z
- **Status**: COMPLETED @ 2026-08-01T04:53:45Z

### [DONE] service-directory-cleanup-20260801-v2
- **Session**: `Codex-service-cleanup-repair`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/core/service_directory.h kernel/core/service_directory.cpp tests/host/test_service_directory.cpp`
- **Description**: Deliver detached request cleanup exactly once outside locks across busy and batch close paths
- **Claimed**: 2026-08-01T04:53:58Z
- **Status**: COMPLETED @ 2026-08-01T05:07:21Z

### [DONE] host-cmake-registry-20260801
- **Session**: `Codex-host-cmake-registry-20260801`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `tests/host/CMakeLists.txt`
- **Description**: Register
- **Claimed**: 2026-08-01T04:54:20Z
- **Status**: COMPLETED @ 2026-08-01T05:10:18Z

### [DONE] Codex-boot-order-crash-main
- **Session**: `Nathan-1764`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/core/main.cpp`
- **Description**: Launch managed user services only after the Userland phase completes
- **Claimed**: 2026-08-01T04:56:32Z
- **Status**: COMPLETED @ 2026-08-01T05:04:34Z

### [DONE] boot-order-ci-registration-20260801
- **Session**: `Codex-boot-order-ci-20260801`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `.github/workflows/build.yml`
- **Description**: Register service boot-order semantic guard in required CI harness
- **Claimed**: 2026-08-01T05:10:36Z
- **Status**: COMPLETED @ 2026-08-01T05:11:12Z

### [DONE] initcall-capacity-20260801
- **Session**: `Nathan-1192`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/core/init.h`
- **Description**: Raise
- **Claimed**: 2026-08-01T05:15:57Z
- **Status**: COMPLETED @ 2026-08-01T05:22:04Z

### [DONE] channel-service-epoch-drain-20260801
- **Session**: `Codex-channel-service-epoch-repair`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/ipc/channel_core.h kernel/ipc/channel_core.cpp tests/host/test_channel_core.cpp kernel/core/service_directory.h kernel/core/service_directory.cpp tests/host/test_service_directory.cpp`
- **Description**: Expected-epoch atomic drain gate and stale-wrapper teardown coverage
- **Claimed**: 2026-08-01T05:16:51Z
- **Status**: COMPLETED @ 2026-08-01T05:25:35Z

### [DONE] strict-panic-verifier-20260801
- **Session**: `Nathan-1028`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `tools/test/verify-boot-verdict.py tools/test/test-verify-boot-verdict.py`
- **Description**: Narrow panic forbidden signatures to real terminal sentinels and add benign classifier regression
- **Claimed**: 2026-08-01T05:23:16Z
- **Status**: COMPLETED @ 2026-08-01T05:27:15Z

### [DONE] strict-crash-banner-verifier-20260801
- **Session**: `Nathan-990`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `tools/test/verify-boot-verdict.py tools/test/test-verify-boot-verdict.py`
- **Description**: Match actual DuetOS crash dump sentinel and accept benign minidump reservation prose
- **Claimed**: 2026-08-01T05:38:17Z
- **Status**: COMPLETED @ 2026-08-01T05:44:47Z

### [DONE] smp-ap-handshake-20260801
- **Session**: `Codex-smp-ap-handshake-20260801`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/arch/x86_64/smp.cpp`
- **Description**: No description provided
- **Claimed**: 2026-08-01T05:53:53Z
- **Status**: COMPLETED @ 2026-08-01T06:21:44Z

### [DONE] smp-ap-trampoline-20260801
- **Session**: `Codex-smp-ap-handshake-20260801`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/arch/x86_64/ap_trampoline.S`
- **Description**: Attempt-specific trampoline readiness publication
- **Claimed**: 2026-08-01T05:54:09Z
- **Status**: COMPLETED @ 2026-08-01T06:21:50Z

### [DONE] smp-ap-handshake-test-20260801
- **Session**: `Codex-smp-ap-handshake-20260801`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `tools/test/test-smp-ap-handshake.py`
- **Description**: Deterministic generation-slot handshake and source-layout regression
- **Claimed**: 2026-08-01T06:08:52Z
- **Status**: COMPLETED @ 2026-08-01T06:21:56Z

### [DONE] mm-tlb-confirmed-20260801
- **Session**: `Codex-tlb-confirmed-20260801`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/mm/paging.cpp kernel/mm/kstack.cpp tools/test/test-tlb-shootdown-contract.py`
- **Description**: Confirmed per-target TLB delivery and unmap-before-shootdown-before-frame-free ordering
- **Claimed**: 2026-08-01T06:09:42Z
- **Status**: COMPLETED @ 2026-08-01T06:26:59Z

### [DONE] mm-tlb-confirmed-header-20260801
- **Session**: `Codex-tlb-confirmed-20260801`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/mm/paging.h`
- **Description**: Declare confirmed kernel-range peer TLB invalidation barrier
- **Claimed**: 2026-08-01T06:11:49Z
- **Status**: COMPLETED @ 2026-08-01T06:27:06Z

### [DONE] mm-tlb-kstack-contract-header-20260801
- **Session**: `Codex-tlb-confirmed-20260801`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/mm/kstack.h`
- **Description**: Synchronize kernel-stack reclamation ordering contract
- **Claimed**: 2026-08-01T06:13:47Z
- **Status**: COMPLETED @ 2026-08-01T06:27:13Z

### [DONE] smp-ap-docs-ci-20260801
- **Session**: `Codex-smp-docs-ci-20260801`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/arch/x86_64/smp.h`
- **Description**: No description provided
- **Claimed**: 2026-08-01T06:24:21Z
- **Status**: COMPLETED @ 2026-08-01T06:29:40Z

### [DONE] smp-ap-docs-ci-shared-20260801
- **Session**: `Codex-smp-docs-ci-20260801`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/cpu/topology.h`
- **Description**: No description provided
- **Claimed**: 2026-08-01T06:24:42Z
- **Status**: COMPLETED @ 2026-08-01T06:29:42Z

### [DONE] smp-ap-docs-boot-20260801
- **Session**: `Codex-smp-docs-ci-20260801`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/core/boot_bringup.cpp`
- **Description**: synchronize_AP_admission_boot_comment
- **Claimed**: 2026-08-01T06:24:51Z
- **Status**: COMPLETED @ 2026-08-01T06:29:45Z

### [DONE] smp-ap-ci-registration-20260801
- **Session**: `Codex-smp-docs-ci-20260801`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `.github/workflows/build.yml`
- **Description**: register_AP_handshake_static_test
- **Claimed**: 2026-08-01T06:24:52Z
- **Status**: COMPLETED @ 2026-08-01T06:29:48Z

### [DONE] adaptive-mutex-lifetime-20260801
- **Session**: `Nathan-1927`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/sync/adaptive_mutex.cpp kernel/sync/adaptive_mutex.h`
- **Description**: Replace raw Task owner compatibility mutex with scheduler-owned lifetime-safe mutex wrapper
- **Claimed**: 2026-08-01T06:41:50Z
- **Status**: COMPLETED @ 2026-08-01T07:01:21Z

### [DONE] adaptive-mutex-lifetime-auditfix-20260801
- **Session**: `Nathan-1460`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/sync/adaptive_mutex.cpp kernel/sync/adaptive_mutex.h`
- **Description**: Finalize audited publication ordering and deterministic SMP selftest
- **Claimed**: 2026-08-01T07:04:02Z
- **Status**: COMPLETED @ 2026-08-01T07:04:09Z

### [DONE] mm-user-tlb-reclaim-20260801
- **Session**: `Nathan-584`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/mm/address_space.cpp`
- **Description**: No description provided
- **Claimed**: 2026-08-01T08:57:13Z
- **Status**: COMPLETED @ 2026-08-01T09:13:48Z

### [DONE] task-cancellation-boundaries-20260801
- **Session**: `Nathan-1271`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/arch/x86_64/traps.cpp`
- **Description**: No description provided
- **Claimed**: 2026-08-01T08:57:19Z
- **Status**: COMPLETED @ 2026-08-01T12:34:57Z

### [ACTIVE] task-cancellation-usermode-20260801
- **Session**: `Nathan-1721`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/arch/x86_64/usermode.S`
- **Description**: bootstrap-cancellation-boundary
- **Claimed**: 2026-08-01T08:57:31Z
- **Status**: IN PROGRESS

### [ACTIVE] task-cancellation-linux-dispatch-20260801
- **Session**: `Nathan-906`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/subsystems/linux/syscall.cpp`
- **Description**: linux-dispatch-cancellation-boundary
- **Claimed**: 2026-08-01T08:57:32Z
- **Status**: IN PROGRESS

### [DONE] task-cancel-contract-test-20260801
- **Session**: `Nathan-1315`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `tools/test/test-task-cancellation-contract.py`
- **Description**: Structural regression guard for cooperative task cancellation boundaries
- **Claimed**: 2026-08-01T08:57:35Z
- **Status**: COMPLETED @ 2026-08-01T09:07:12Z

### [DONE] adaptive-mutex-docs-20260801
- **Session**: `Nathan-1299`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `wiki/kernel/Synchronization.md`
- **Description**: No description provided
- **Claimed**: 2026-08-01T08:57:35Z
- **Status**: COMPLETED @ 2026-08-01T09:01:32Z

### [DONE] mm-user-tlb-reclaim-header-20260801
- **Session**: `Nathan-1098`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/mm/address_space.h`
- **Description**: Confirmed user address-space TLB reclaim API contract
- **Claimed**: 2026-08-01T08:57:37Z
- **Status**: COMPLETED @ 2026-08-01T09:13:56Z

### [DONE] mm-user-tlb-reclaim-test-20260801
- **Session**: `Nathan-910`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `tools/test/test-user-tlb-reclaim-contract.py`
- **Description**: Focused confirmed user TLB reclaim structural coverage
- **Claimed**: 2026-08-01T08:57:43Z
- **Status**: COMPLETED @ 2026-08-01T09:14:04Z

### [DONE] adaptive-mutex-boot-doc-20260801
- **Session**: `Nathan-1182`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/core/boot_bringup.cpp`
- **Description**: synchronize_adaptive_mutex_boot_selftest_comment
- **Claimed**: 2026-08-01T08:57:57Z
- **Status**: COMPLETED @ 2026-08-01T09:01:34Z

### [DONE] exit-helper-unwind-20260801
- **Session**: `Codex-exit-helper-unwind`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/subsystems/linux/syscall_proc.cpp`
- **Description**: No description provided
- **Claimed**: 2026-08-01T09:03:46Z
- **Status**: COMPLETED @ 2026-08-01T09:07:25Z

### [DONE] exit-helper-unwind-sig-20260801
- **Session**: `Codex-exit-helper-unwind`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/subsystems/linux/syscall_sig.cpp`
- **Description**: No description provided
- **Claimed**: 2026-08-01T09:04:05Z
- **Status**: COMPLETED @ 2026-08-01T09:07:34Z

### [DONE] exit-helper-unwind-fiber-20260801
- **Session**: `Codex-exit-helper-unwind`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/subsystems/win32/fiber_syscall.cpp`
- **Description**: No description provided
- **Claimed**: 2026-08-01T09:04:05Z
- **Status**: COMPLETED @ 2026-08-01T09:07:42Z

### [DONE] hardening-ci-registration-20260801
- **Session**: `Nathan-739`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `.github/workflows/build.yml`
- **Description**: Register task cancellation and user TLB reclaim structural tests
- **Claimed**: 2026-08-01T09:16:33Z
- **Status**: COMPLETED @ 2026-08-01T09:20:37Z

### [DONE] hardening-roadmap-sync-20260801
- **Session**: `Nathan-205`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `wiki/reference/Roadmap.md`
- **Description**: Retire stale adaptive mutex and user TLB reclamation roadmap text
- **Claimed**: 2026-08-01T09:16:40Z
- **Status**: COMPLETED @ 2026-08-01T09:20:45Z

### [DONE] task-cancel-contract-test-fix-20260801
- **Session**: `Nathan-480`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `tools/test/test-task-cancellation-contract.py`
- **Description**: Align cancellation structural guard with helper-based atomic implementation
- **Claimed**: 2026-08-01T09:17:09Z
- **Status**: COMPLETED @ 2026-08-01T09:19:00Z

### [ACTIVE] reaper-tlb-if-contract-20260801
- **Session**: `Nathan-1850`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `tools/test/test-tlb-shootdown-contract.py`
- **Description**: Guard reaper interrupt enable before confirmed kernel-stack TLB reclamation
- **Claimed**: 2026-08-01T09:35:53Z
- **Status**: IN PROGRESS

### [DONE] process-task-publication-contract-20260801
- **Session**: `Nathan-1594`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `tools/test/test-process-task-publication-contract.py`
- **Description**: Red-first
- **Claimed**: 2026-08-01T09:40:42Z
- **Status**: COMPLETED @ 2026-08-01T09:56:05Z

### [ACTIVE] scheduler-resume-if-contract-20260801
- **Session**: `Nathan-1407`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/sched/context_switch.S`
- **Description**: Restore resumed task interrupt state across scheduler lock handoff
- **Claimed**: 2026-08-01T09:51:38Z
- **Status**: IN PROGRESS

### [DONE] scheduler-resume-if-percpu-doc-20260801
- **Session**: `Nathan-555`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/cpu/percpu.h`
- **Description**: Document source RFLAGS breadcrumb versus resumed-task lock release state
- **Claimed**: 2026-08-01T09:52:29Z
- **Status**: COMPLETED @ 2026-08-01T12:35:01Z

### [DONE] kmutex-cancellation-contract-20260801
- **Session**: `Codex-kmutex-contract-test`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `tools/test/test-kmutex-cancellation-contract.py`
- **Description**: Red-first
- **Claimed**: 2026-08-01T10:04:27Z
- **Status**: COMPLETED @ 2026-08-01T10:26:35Z

### [ACTIVE] receipt-callers-20260801
- **Session**: `Nathan-1909`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/core/main.cpp kernel/diag/hung_task.cpp kernel/diag/stress_driver.cpp kernel/security/gui_fuzz.cpp kernel/sync/adaptive_mutex.cpp`
- **Description**: Migrate unclaimed scheduler create callers from raw Task pointers to immutable TaskCreateResult receipts
- **Claimed**: 2026-08-01T10:26:53Z
- **Status**: IN PROGRESS

### [DONE] task-receipt-user-callers-20260801
- **Session**: `Codex-root-lifecycle-20260801`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/subsystems/win32/thread_syscall.cpp kernel/subsystems/linux/syscall_clone.cpp tests/fuzz/host_shim/net_stubs.cpp tests/fuzz/host_shim/usbnet_stubs.cpp`
- **Description**: Migrate public Task creation callers to immutable receipts and fix fork ownership
- **Claimed**: 2026-08-01T10:29:41Z
- **Status**: COMPLETED @ 2026-08-01T14:33:54Z

### [DONE] task-receipt-loadtest-20260801
- **Session**: `Nathan-986`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/shell/shell_loadtest.cpp`
- **Description**: Migrate load-test worker creation to immutable TaskCreateResult receipt
- **Claimed**: 2026-08-01T10:31:36Z
- **Status**: COMPLETED @ 2026-08-01T10:32:03Z

### [ACTIVE] task-receipt-loadtest-root-20260801
- **Session**: `Codex-root-lifecycle-20260801`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/shell/shell_loadtest.cpp`
- **Description**: Migrate loadtest task creation to immutable receipt
- **Claimed**: 2026-08-01T10:32:10Z
- **Status**: IN PROGRESS

### [ACTIVE] process-task-publication-atomic-compile-20260801
- **Session**: `Codex-root-lifecycle-20260801`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `tools/test/test-process-task-publication-contract.py`
- **Description**: Accept compiler-valid underlying atomic access for enum lifecycle state
- **Claimed**: 2026-08-01T10:35:06Z
- **Status**: IN PROGRESS

### [DONE] boot-manifest-package-20260801
- **Session**: `Codex-boot-manifest-package`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `config/services.toml tools/build/gen-service-manifest.py kernel/core/boot_service_manifest_data.h tools/test/test-gen-service-manifest.py`
- **Description**: Deterministic staged ServiceManifest v1 package and hostile generator tests without boot activation
- **Claimed**: 2026-08-01T11:16:39Z
- **Status**: COMPLETED @ 2026-08-01T16:12:51Z

### [DONE] gdb-monitor-stop-snapshots-20260801
- **Session**: `Codex-root-gdb-monitor-20260801`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/diag/gdb_monitor.h kernel/diag/gdb_monitor.cpp kernel/diag/gdb_monitor_read.cpp kernel/sched/sched.h kernel/sched/sched.cpp tools/test/test-gdb-monitor-stop-safety-contract.py`
- **Description**: Bounded no-wait qRcmd snapshots and incomplete-rendezvous gating
- **Claimed**: 2026-08-01T12:34:33Z
- **Status**: COMPLETED @ 2026-08-01T12:52:27Z

### [DONE] gdb-stop-rendezvous-20260801
- **Session**: `Nathan-1693`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/cpu/percpu.h`
- **Description**: No description provided
- **Claimed**: 2026-08-01T12:35:33Z
- **Status**: COMPLETED @ 2026-08-01T12:52:29Z

### [DONE] gdb-stop-rendezvous-arch-20260801
- **Session**: `Nathan-475`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/arch/x86_64/smp.h kernel/arch/x86_64/smp.cpp kernel/arch/x86_64/traps.cpp`
- **Description**: Generation-safe bounded GDB NMI rendezvous
- **Claimed**: 2026-08-01T12:36:06Z
- **Status**: COMPLETED @ 2026-08-01T12:52:32Z

### [DONE] gdb-stop-rendezvous-server-20260801
- **Session**: `Nathan-381`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/diag/gdb_server.cpp`
- **Description**: Wait for rendezvous and gate peer register writes
- **Claimed**: 2026-08-01T12:36:07Z
- **Status**: COMPLETED @ 2026-08-01T12:52:34Z

### [DONE] gdb-stop-rendezvous-test-20260801
- **Session**: `Nathan-1374`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `tools/test/test-gdb-stop-rendezvous-contract.py`
- **Description**: Focused generation rendezvous source contract
- **Claimed**: 2026-08-01T12:36:09Z
- **Status**: COMPLETED @ 2026-08-01T12:52:36Z

### [DONE] linux-fd-transaction-core
- **Session**: `Codex-linux-fd-transaction-core`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/proc/process.h kernel/proc/process.cpp kernel/ipc/handle_table.h kernel/ipc/handle_table.cpp tools/test/test-linux-fd-transaction-contract.py`
- **Description**: SMP-linearizable Linux fd core receipts and failure-atomic handle replacement
- **Claimed**: 2026-08-01T12:37:44Z
- **Status**: COMPLETED @ 2026-08-01T12:53:25Z

### [DONE] gdb-monitor-atomic-controls-20260801
- **Session**: `Codex-root-gdb-monitor-20260801`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/debug/probes.cpp kernel/diag/kdbg.cpp`
- **Description**: Atomic qRcmd control state safe across NMI stop/resume
- **Claimed**: 2026-08-01T12:48:59Z
- **Status**: COMPLETED @ 2026-08-01T12:52:39Z

### [DONE] kmutex-cancel-abandon-20260801
- **Session**: `Nathan-1522`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/ipc/kmutex.h`
- **Description**: No description provided
- **Claimed**: 2026-08-01T12:56:04Z
- **Status**: COMPLETED @ 2026-08-01T13:23:35Z

### [DONE] kmutex-cancel-abandon-impl-20260801
- **Session**: `Nathan-1726`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/ipc/kmutex.cpp,kernel/subsystems/win32/mutex_syscall.cpp,kernel/subsystems/win32/file_syscall.cpp,kernel/sched/sched.h,kernel/sched/sched.cpp,tools/test/test-kmutex-cancellation-contract.py,tools/test/test-task-cancellation-contract.py`
- **Description**: cooperative-cancellation-safe-KMutex-abandonment
- **Claimed**: 2026-08-01T12:56:42Z
- **Status**: COMPLETED @ 2026-08-01T13:23:43Z

### [DONE] fable-epoll-fd-identity-20260801
- **Session**: `Fable-epoll-fd-identity`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/subsystems/linux/syscall_async_io.cpp tools/test/test-epoll-fd-identity-contract.py`
- **Description**: Migrate epoll watches to strong fd receipt identity
- **Claimed**: 2026-08-01T13:00:02Z
- **Status**: COMPLETED @ 2026-08-01T15:37:37Z

### [DONE] fable-pidfd-getfd-identity-20260801
- **Session**: `Fable-pidfd-getfd-identity`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/subsystems/linux/pidfd_splice.cpp tools/test/test-pidfd-strong-identity-contract.py kernel/subsystems/linux/syscall_internal.h`
- **Description**: Migrate pidfd operations and getfd export import to strong fd receipts
- **Claimed**: 2026-08-01T13:00:03Z
- **Status**: COMPLETED @ 2026-08-01T16:01:22Z

### [DONE] ci-structural-contract-registry-20260801
- **Session**: `Nathan-1352`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `.github/workflows/build.yml`
- **Description**: Register
- **Claimed**: 2026-08-01T13:02:42Z
- **Status**: COMPLETED @ 2026-08-01T13:05:17Z

### [DONE] runtime-access-contract-sync-20260801
- **Session**: `Nathan-1961`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `tools/test/test-process-runtime-access-contract.py`
- **Description**: Align
- **Claimed**: 2026-08-01T13:06:15Z
- **Status**: COMPLETED @ 2026-08-01T13:10:46Z

### [DONE] gdb-percpu-generation-init-20260801
- **Session**: `Codex-root-gdb-percpu-init`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/cpu/percpu.cpp`
- **Description**: Initialize generation-based GDB freeze fields after rendezvous migration
- **Claimed**: 2026-08-01T13:08:49Z
- **Status**: COMPLETED @ 2026-08-01T13:12:26Z

### [DONE] ci-process-runtime-contract-registry-20260801
- **Session**: `Nathan-118`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `.github/workflows/build.yml`
- **Description**: Register
- **Claimed**: 2026-08-01T13:12:35Z
- **Status**: COMPLETED @ 2026-08-01T13:13:02Z

### [DONE] process-handle-generation-20260801
- **Session**: `Nathan-151`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/proc/process.h`
- **Description**: No description provided
- **Claimed**: 2026-08-01T13:16:07Z
- **Status**: COMPLETED @ 2026-08-01T13:32:52Z

### [DONE] linux-fd-io-transaction-migration
- **Session**: `Nathan-1410`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/subsystems/linux/syscall_fd.cpp`
- **Description**: No description provided
- **Claimed**: 2026-08-01T13:16:22Z
- **Status**: COMPLETED @ 2026-08-01T13:17:06Z

### [DONE] process-handle-generation-impl-20260801
- **Session**: `Nathan-1647`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/proc/process.cpp`
- **Description**: Opaque
- **Claimed**: 2026-08-01T13:16:40Z
- **Status**: COMPLETED @ 2026-08-01T13:32:55Z

### [DONE] process-handle-generation-test-20260801
- **Session**: `Nathan-65`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `tools/test/test-process-handle-generation-contract.py`
- **Description**: Generation-safe
- **Claimed**: 2026-08-01T13:16:45Z
- **Status**: COMPLETED @ 2026-08-01T13:32:58Z

### [DONE] linux-fd-io-migration
- **Session**: `Nathan-458`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/subsystems/linux/syscall_fd.cpp,kernel/subsystems/linux/syscall_file.cpp,kernel/subsystems/linux/syscall_io.cpp,kernel/subsystems/linux/syscall_pipe.cpp`
- **Description**: transactional-fd-receipt-migration
- **Claimed**: 2026-08-01T13:17:09Z
- **Status**: COMPLETED @ 2026-08-01T14:09:52Z

### [DONE] handle-band-helper-dispatch-20260801
- **Session**: `Nathan-884`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `tools/test/check-handle-bands.py`
- **Description**: Recognize
- **Claimed**: 2026-08-01T13:24:20Z
- **Status**: COMPLETED @ 2026-08-01T13:33:04Z

### [DONE] process-handle-generation-user-classifier-20260801
- **Session**: `Nathan-1433`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `userland/libs/ntdll/ntdll_info.c`
- **Description**: Classify
- **Claimed**: 2026-08-01T13:24:32Z
- **Status**: COMPLETED @ 2026-08-01T13:33:01Z

### [DONE] ci-kmutex-fd-core-contracts-20260801
- **Session**: `Nathan-874`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `.github/workflows/build.yml`
- **Description**: Register
- **Claimed**: 2026-08-01T13:24:57Z
- **Status**: COMPLETED @ 2026-08-01T13:25:28Z

### [DONE] linux-fd-async-pools-20260801
- **Session**: `Nathan-1384`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/subsystems/linux/fanotify.cpp`
- **Description**: No description provided
- **Claimed**: 2026-08-01T13:26:33Z
- **Status**: COMPLETED @ 2026-08-01T13:58:51Z

### [DONE] linux-fd-async-pools-rest-20260801
- **Session**: `Nathan-1697`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/subsystems/linux/inotify.cpp,kernel/subsystems/linux/msg_queues.cpp,kernel/subsystems/linux/extra_syscalls.cpp,tools/test/test-linux-fd-async-pools-contract.py`
- **Description**: Migrate
- **Claimed**: 2026-08-01T13:26:49Z
- **Status**: COMPLETED @ 2026-08-01T13:58:53Z

### [DONE] linux-fd-io-contract
- **Session**: `Nathan-746`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `tools/test/test-linux-fd-io-transaction-contract.py`
- **Description**: forbid-raw-fd-slots-and-require-explicit-receipt-cleanup
- **Claimed**: 2026-08-01T13:28:07Z
- **Status**: COMPLETED @ 2026-08-01T14:09:54Z

### [DONE] linux-fd-receipt-extension-20260801
- **Session**: `Codex-linux-fd-receipt-extension`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/proc/process.h`
- **Description**: No description provided
- **Claimed**: 2026-08-01T13:34:15Z
- **Status**: COMPLETED @ 2026-08-01T13:55:22Z

### [DONE] linux-fd-receipt-extension-impl-20260801
- **Session**: `Codex-linux-fd-receipt-extension`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/proc/process.cpp`
- **Description**: Receipt
- **Claimed**: 2026-08-01T13:34:27Z
- **Status**: COMPLETED @ 2026-08-01T13:55:29Z

### [DONE] linux-fd-receipt-extension-test-20260801
- **Session**: `Codex-linux-fd-receipt-extension`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `tools/test/test-linux-fd-receipt-extension-contract.py`
- **Description**: receipt-extension-hostile-contract
- **Claimed**: 2026-08-01T13:34:42Z
- **Status**: COMPLETED @ 2026-08-01T13:55:36Z

### [DONE] address-space-region-sync-20260801
- **Session**: `Nathan-1830`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/mm/address_space.h`
- **Description**: No description provided
- **Claimed**: 2026-08-01T13:59:01Z
- **Status**: COMPLETED @ 2026-08-01T14:19:54Z

### [DONE] address-space-region-sync-impl-20260801
- **Session**: `Nathan-1390`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/mm/address_space.cpp`
- **Description**: structural-region-table-read-synchronization
- **Claimed**: 2026-08-01T13:59:17Z
- **Status**: COMPLETED @ 2026-08-01T14:19:58Z

### [DONE] address-space-region-sync-test-20260801
- **Session**: `Nathan-1969`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `tools/test/test-address-space-region-sync-contract.py`
- **Description**: hostile-structural-region-table-contract
- **Claimed**: 2026-08-01T13:59:19Z
- **Status**: COMPLETED @ 2026-08-01T14:20:02Z

### [DONE] linux-fd-post-close-commit-20260801
- **Session**: `Codex-linux-fd-post-close-commit`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/proc/process.h,kernel/proc/process.cpp,tools/test/test-linux-fd-receipt-extension-contract.py`
- **Description**: Allow retained guarded OFD metadata commit after source fd close without touching replacement slot
- **Claimed**: 2026-08-01T14:06:46Z
- **Status**: COMPLETED @ 2026-08-01T14:20:59Z

### [DONE] address-space-region-sync-panic-20260801
- **Session**: `Nathan-1069`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/core/panic.cpp`
- **Description**: panic-safe-fail-fast-region-summary-snapshot
- **Claimed**: 2026-08-01T14:07:21Z
- **Status**: COMPLETED @ 2026-08-01T14:21:04Z

### [DONE] fable-gui-wait-sequence-20260801
- **Session**: `Nathan-1026`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/drivers/video/gui_message_queue.h`
- **Description**: No description provided
- **Claimed**: 2026-08-01T14:09:26Z
- **Status**: COMPLETED @ 2026-08-01T14:51:38Z

### [DONE] fable-gui-wait-sequence-surface-20260801
- **Session**: `Nathan-532`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/drivers/video/gui_message_queue.cpp kernel/drivers/video/widget.h kernel/drivers/video/widget.cpp kernel/subsystems/win32/window_syscall.cpp tools/test/test-gui-message-wait-sequence-contract.py wiki/subsystems/Compositor.md`
- **Description**: Close GetMessage lost-wake window with scheduler-owned mutation sequence
- **Claimed**: 2026-08-01T14:09:55Z
- **Status**: COMPLETED @ 2026-08-01T14:51:41Z

### [DONE] linux-fd-residual-receipts-20260801
- **Session**: `Nathan-330`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/subsystems/linux/syscall_xattr.cpp,kernel/subsystems/linux/syscall_path.cpp,kernel/subsystems/linux/syscall_fs_mut.cpp,kernel/subsystems/linux/syscall_misc.cpp,kernel/subsystems/linux/syscall_socket.cpp,kernel/subsystems/linux/syscall_stub.cpp,tools/test/test-linux-fd-residual-receipt-contract.py`
- **Description**: Migrate remaining unclaimed Linux fd-slot syscall paths to stable receipt and OFD guard ownership
- **Claimed**: 2026-08-01T14:12:46Z
- **Status**: COMPLETED @ 2026-08-01T14:51:27Z

### [DONE] linux-fd-poll-ready-declaration-20260801
- **Session**: `Nathan-440`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/subsystems/linux/syscall_async_io.h`
- **Description**: Align epoll readiness declaration with retained Linux fd receipt and migrate poll caller
- **Claimed**: 2026-08-01T14:16:39Z
- **Status**: COMPLETED @ 2026-08-01T14:51:29Z

### [DONE] cancellable-waits-20260801
- **Session**: `Codex-cancellable-waits-20260801`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/sched/sched.h,kernel/sched/sched.cpp,tools/test/test-cancellable-wait-contract.py`
- **Description**: Add result-bearing cancellable WaitQueue and Condvar primitives; truthful deferred cancellation diagnostics
- **Claimed**: 2026-08-01T14:19:07Z
- **Status**: COMPLETED @ 2026-08-01T14:35:53Z

### [DONE] fable-ap-bootstrap-guard-20260801
- **Session**: `Codex-root-ap-stack`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/arch/x86_64/smp.cpp kernel/mm/kstack.h tools/test/test-ap-bootstrap-stack-contract.py`
- **Description**: Move live AP bootstrap contexts onto the guarded kernel-stack arena and retire stale scope documentation
- **Claimed**: 2026-08-01T14:20:00Z
- **Status**: COMPLETED @ 2026-08-01T14:51:43Z

### [DONE] address-space-region-sync-panic-comment-20260801
- **Session**: `Nathan-440`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/core/panic.cpp`
- **Description**: Correct panic region-summary comment grammar
- **Claimed**: 2026-08-01T14:21:58Z
- **Status**: COMPLETED @ 2026-08-01T14:22:20Z

### [DONE] fable-targeted-contract-ci-20260801
- **Session**: `Codex-root-ci-contracts`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `.github/workflows/build.yml`
- **Description**: Register integrated Fable-targeted hostile structural contracts in authoritative CI
- **Claimed**: 2026-08-01T14:26:06Z
- **Status**: COMPLETED @ 2026-08-02T06:55:08Z

### [DONE] linux-fd-fork-inheritance-caller-20260801
- **Session**: `Nathan-1452`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/subsystems/linux/syscall_clone.cpp`
- **Description**: Consume failure-atomic dirfd-filtered Linux fd inheritance and remove raw fork cleanup scan
- **Claimed**: 2026-08-01T14:34:32Z
- **Status**: COMPLETED @ 2026-08-01T14:51:32Z

### [DONE] linux-fd-inherit-retained-refresh-20260801
- **Session**: `Codex-linux-fd-inherit-retained-refresh-20260801`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/proc/process.h,kernel/proc/process.cpp,tools/test/test-linux-fd-receipt-extension-contract.py`
- **Description**: Make Linux fd inheritance failure-atomic and state-11 safe; add guarded retained-regular OFD refresh
- **Claimed**: 2026-08-01T14:36:07Z
- **Status**: COMPLETED @ 2026-08-01T14:48:59Z

### [DONE] vm-breakpoint-frame-access-20260801
- **Session**: `Nathan-210`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/debug/breakpoints.cpp`
- **Description**: No description provided
- **Claimed**: 2026-08-01T14:41:50Z
- **Status**: COMPLETED @ 2026-08-01T14:48:03Z

### [DONE] vm-breakpoint-frame-access-test-20260801
- **Session**: `Nathan-1187`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `tools/test/test-breakpoint-address-space-read-contract.py`
- **Description**: hostile-structural-frame-lifetime-contract
- **Claimed**: 2026-08-01T14:42:09Z
- **Status**: COMPLETED @ 2026-08-01T14:48:18Z

### [DONE] vm-breakpoint-frame-access-header-20260801
- **Session**: `Nathan-1188`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/debug/breakpoints.h`
- **Description**: breakpoint-read-contract-doc
- **Claimed**: 2026-08-01T14:42:09Z
- **Status**: COMPLETED @ 2026-08-01T14:48:10Z

### [DONE] linux-fd-inherit-legacy-contract-20260801
- **Session**: `Codex-linux-fd-inherit-legacy-contract-20260801`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `tools/test/test-linux-fd-transaction-contract.py`
- **Description**: Update legacy fd transaction contract for result-bearing atomic inheritance
- **Claimed**: 2026-08-01T14:42:29Z
- **Status**: COMPLETED @ 2026-08-01T14:49:07Z

### [DONE] cancellable-waits-held-contract-followup-20260801
- **Session**: `Nathan-955`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/sched/sched.cpp`
- **Description**: No description provided
- **Claimed**: 2026-08-01T14:43:31Z
- **Status**: COMPLETED @ 2026-08-01T14:53:06Z

### [DONE] cancellable-waits-format-followup-20260801
- **Session**: `Nathan-775`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/sched/sched.h,tools/test/test-cancellable-wait-contract.py`
- **Description**: cancellable-wait-header-and-contract-format
- **Claimed**: 2026-08-01T14:45:23Z
- **Status**: COMPLETED @ 2026-08-01T14:53:08Z

### [DONE] pidfd-runtime-contract-refresh-20260801
- **Session**: `Nathan-1721`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `tools/test/test-process-runtime-access-contract.py`
- **Description**: refresh-pidfd-runtime-order-for-transactional-export
- **Claimed**: 2026-08-01T14:48:14Z
- **Status**: COMPLETED @ 2026-08-01T14:51:35Z

### [DONE] linux-cwd-sync-20260801
- **Session**: `Codex-linux-cwd-sync-20260801`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/proc/process.h,kernel/proc/process.cpp,tools/test/test-linux-cwd-sync-contract.py`
- **Description**: Process-owned synchronized Linux cwd snapshot and replacement contract
- **Claimed**: 2026-08-01T14:50:20Z
- **Status**: COMPLETED @ 2026-08-01T15:04:23Z

### [DONE] win32-heap-vm-safety-20260801
- **Session**: `Codex-win32-heap-vm-safety`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/subsystems/win32/heap.cpp,kernel/subsystems/win32/heap.h,tools/test/test-win32-heap-vm-safety-contract.py`
- **Description**: Serialize process heap metadata and route all heap user-memory access through locked AddressSpace copy APIs
- **Claimed**: 2026-08-01T14:51:37Z
- **Status**: COMPLETED @ 2026-08-01T15:12:02Z

### [DONE] adaptive-mutex-doc-sync-20260801
- **Session**: `Nathan-687`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/sched/sched.h`
- **Description**: No description provided
- **Claimed**: 2026-08-01T14:55:26Z
- **Status**: COMPLETED @ 2026-08-01T14:58:56Z

### [DONE] adaptive-mutex-doc-sync-rest-20260801
- **Session**: `Nathan-1973`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/sched/sched.cpp,kernel/core/boot_bringup.cpp,wiki/kernel/Synchronization.md`
- **Description**: Reconcile remaining AdaptiveMutex comments and synchronization documentation
- **Claimed**: 2026-08-01T14:55:46Z
- **Status**: COMPLETED @ 2026-08-01T14:58:49Z

### [DONE] linux-cwd-callers-20260801
- **Session**: `Codex-linux-cwd-callers-20260801`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/subsystems/linux/syscall_path.cpp`
- **Description**: Migrate chdir fchdir and getcwd to coherent process cwd snapshot replacement APIs
- **Claimed**: 2026-08-01T14:57:24Z
- **Status**: COMPLETED @ 2026-08-01T15:04:39Z

### [DONE] linux-mmap-vm-receipts-20260801
- **Session**: `Nathan-1906`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/subsystems/linux/syscall_mm.cpp`
- **Description**: No description provided
- **Claimed**: 2026-08-01T15:00:35Z
- **Status**: COMPLETED @ 2026-08-01T15:22:51Z

### [DONE] linux-cwd-internal-doc-20260801
- **Session**: `Codex-linux-cwd-internal-doc-20260801`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/subsystems/linux/syscall_internal.h`
- **Description**: Synchronize Linux CWD internal documentation with process snapshot replacement API
- **Claimed**: 2026-08-01T15:00:39Z
- **Status**: COMPLETED @ 2026-08-01T15:04:48Z

### [DONE] linux-mmap-vm-receipts-test-20260801
- **Session**: `Nathan-319`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `tools/test/test-linux-mmap-vm-receipt-contract.py`
- **Description**: mmap-and-mremap-hostile-structural-contract
- **Claimed**: 2026-08-01T15:00:52Z
- **Status**: COMPLETED @ 2026-08-01T15:22:49Z

### [DONE] service-scheduler-publication-gate-20260801
- **Session**: `Nathan-1888`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/sched/sched.cpp,kernel/core/service.cpp,tools/test/test-service-publication-gate-contract.py`
- **Description**: scheduler-lock-service-commit-and-unpublished-task-rollback
- **Claimed**: 2026-08-01T15:00:59Z
- **Status**: COMPLETED @ 2026-08-01T15:26:09Z

### [DONE] win32-heap-process-lock-20260801
- **Session**: `Codex-win32-heap-vm-safety`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/proc/process.h,kernel/proc/process.cpp`
- **Description**: Add and initialize process-owned sleeping mutex for Win32 default and secondary heap metadata
- **Claimed**: 2026-08-01T15:04:58Z
- **Status**: COMPLETED @ 2026-08-01T15:11:59Z

### [DONE] service-scheduler-publication-doc-20260801
- **Session**: `Nathan-376`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/core/service.h`
- **Description**: document-scheduler-atomic-first-task-publication
- **Claimed**: 2026-08-01T15:05:58Z
- **Status**: COMPLETED @ 2026-08-01T15:26:12Z

### [DONE] dbg-scan-coherence-20260801
- **Session**: `Codex-dbg-scan-coherence-20260801`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/apps/dbg_core.cpp,tools/test/test-dbg-core-scan-coherence-contract.py`
- **Description**: Mutation-coherent pointer-free debugger region scan with explicit cap truncation diagnostics
- **Claimed**: 2026-08-01T15:08:54Z
- **Status**: COMPLETED @ 2026-08-01T15:16:05Z

### [DONE] process-key-publication-gate-20260801
- **Session**: `Nathan-ProcessKey-20260801`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/proc/process.h,kernel/proc/process.cpp`
- **Description**: Non-wrapping
- **Claimed**: 2026-08-01T15:12:47Z
- **Status**: COMPLETED @ 2026-08-01T15:26:04Z

### [DONE] win32-thread-tls-vm-receipts-20260801
- **Session**: `Nathan-1548`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/subsystems/win32/thread_syscall.cpp,tools/test/test-win32-thread-tls-vm-safety-contract.py`
- **Description**: Migrate Win32 thread and TLS user-memory access to address-space lifetime-safe copy APIs
- **Claimed**: 2026-08-01T15:17:58Z
- **Status**: COMPLETED @ 2026-08-01T15:30:30Z

### [DONE] process-key-structural-test-compat-20260801
- **Session**: `Nathan-ProcessKey-Tests-20260801`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `tools/test/test-process-task-publication-contract.py,tools/test/test-linux-child-relation-contract.py,tools/test/test-linux-fd-transaction-contract.py`
- **Description**: Make
- **Claimed**: 2026-08-01T15:24:47Z
- **Status**: COMPLETED @ 2026-08-01T15:26:06Z

### [DONE] loader-image-patch-vm-receipts-20260801
- **Session**: `Nathan-1959`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/loader/image_patch.h,kernel/loader/dll_loader.cpp,tools/test/test-loader-image-patch-vm-receipt-contract.py`
- **Description**: Classify
- **Claimed**: 2026-08-01T15:25:10Z
- **Status**: COMPLETED @ 2026-08-01T15:50:40Z

### [DONE] linux-vm-range-transaction-20260801
- **Session**: `Nathan-LinuxVmRange-20260801`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/mm/address_space.h,kernel/mm/address_space.cpp,kernel/subsystems/linux/syscall_mm.cpp,tools/test/test-linux-mmap-vm-receipt-contract.py`
- **Description**: Serialize
- **Claimed**: 2026-08-01T15:29:52Z
- **Status**: COMPLETED @ 2026-08-01T15:48:32Z

### [DONE] linux-timerfd-signalfd-receipts-20260801
- **Session**: `Codex-linux-timerfd-signalfd-receipts`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/subsystems/linux/syscall_async_io.cpp,tools/test/test-linux-timer-signalfd-receipt-contract.py`
- **Description**: Atomic timerfd/signalfd publication, exact retained receipt operations, and epoll strong identity comparison
- **Claimed**: 2026-08-01T15:37:39Z
- **Status**: COMPLETED @ 2026-08-01T15:53:54Z

### [DONE] service-object-package-20260801
- **Session**: `Nathan-1283`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/core/service_object_package.h,kernel/core/service_object_package.cpp,tests/host/test_service_object_package.cpp,tests/host/CMakeLists.txt`
- **Description**: Immutable
- **Claimed**: 2026-08-01T15:40:27Z
- **Status**: COMPLETED @ 2026-08-01T16:07:55Z

### [DONE] service-manifest-transfer-uniqueness-20260801
- **Session**: `Nathan-1001`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/core/service_manifest.h,kernel/core/service_manifest.cpp,tests/host/test_service_manifest.cpp`
- **Description**: Reject
- **Claimed**: 2026-08-01T15:41:33Z
- **Status**: COMPLETED @ 2026-08-01T16:07:49Z

### [DONE] linux-async-ready-doc-20260801
- **Session**: `Codex-linux-timerfd-signalfd-receipts`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/subsystems/linux/syscall_async_io.h`
- **Description**: Synchronize retained readiness and signalfd behavior contract comments
- **Claimed**: 2026-08-01T15:44:15Z
- **Status**: COMPLETED @ 2026-08-01T15:54:00Z

### [DONE] linux-signalfd-poll-owner-20260801
- **Session**: `Codex-linux-timerfd-signalfd-receipts`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/subsystems/linux/syscall_misc.cpp`
- **Description**: Pass explicit current Process into retained fd readiness for signalfd pending-state evaluation
- **Claimed**: 2026-08-01T15:46:05Z
- **Status**: COMPLETED @ 2026-08-01T15:54:09Z

### [DONE] linux-epoll-exact-identity-contract-20260801
- **Session**: `Codex-linux-timerfd-signalfd-receipts`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `tools/test/test-epoll-fd-identity-contract.py`
- **Description**: Update epoll structural contract for helper-encapsulated exact KFile/OFD identity matching
- **Claimed**: 2026-08-01T15:48:36Z
- **Status**: COMPLETED @ 2026-08-01T15:54:15Z

### [DONE] loader-image-patch-rollback-doc-20260801
- **Session**: `Nathan-1678`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/loader/dll_loader.h`
- **Description**: Synchronize
- **Claimed**: 2026-08-01T15:49:37Z
- **Status**: COMPLETED @ 2026-08-01T15:50:25Z

### [DONE] linux-fd-generation-exhaustion-20260801
- **Session**: `Nathan-LinuxFdGeneration-20260801`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/proc/process.h,kernel/proc/process.cpp,tools/test/test-linux-fd-generation-exhaustion-contract.py`
- **Description**: Retire
- **Claimed**: 2026-08-01T15:51:53Z
- **Status**: COMPLETED @ 2026-08-01T15:59:06Z

### [DONE] cancellation-unwind-safety-20260801
- **Session**: `Nathan-138`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/sched/sched.h,kernel/sched/sched.cpp,kernel/ipc/kmutex.h,kernel/ipc/kmutex.cpp,tools/test/test-task-cancellation-contract.py,tools/test/test-cancellable-wait-contract.py,tools/test/test-kmutex-cancellation-contract.py,wiki/kernel/Scheduler.md,wiki/kernel/Synchronization.md`
- **Description**: Close
- **Claimed**: 2026-08-01T16:03:16Z
- **Status**: COMPLETED @ 2026-08-01T17:55:24Z

### [DONE] rust-ingress-hardening-20260801
- **Session**: `Nathan-1547`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `cmake/DuetOSRust.cmake,kernel/rust/CMakeLists.txt,tools/test/check-rust-ffi.py,tools/test/check-rust-ffi-signatures.py,tools/test/test-rust-ffi-signatures.py,kernel/fs/duetfs/src/ffi.rs,kernel/fs/duetfs/src/crypto.rs,kernel/fs/duetfs/src/compress.rs,kernel/fs/duetfs/include/duetfs.h,tools/test/test-rust-ingress-hardening-contract.py`
- **Description**: Audit
- **Claimed**: 2026-08-01T16:05:47Z
- **Status**: COMPLETED @ 2026-08-01T18:16:27Z

### [DONE] rust-ingress-allocator-20260801
- **Session**: `Nathan-623`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/fs/duetfs/src/kheap_alloc.rs,kernel/fs/duetfs/src/lib.rs`
- **Description**: Harden
- **Claimed**: 2026-08-01T16:07:36Z
- **Status**: COMPLETED @ 2026-08-01T18:16:30Z

### [DONE] linux-signal-pending-sync-20260801
- **Session**: `Codex-linux-signal-pending-sync`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/proc/process.h,kernel/proc/process.cpp,kernel/subsystems/linux/syscall_sig.cpp,kernel/subsystems/linux/signal_deliver.cpp,kernel/subsystems/linux/syscall_timer.cpp,kernel/subsystems/linux/syscall_async_io.cpp,tools/test/test-linux-signal-pending-sync-contract.py`
- **Description**: Atomic process-pending signal publication and exact claimant drain across signal, timer, handler, signalfd, and epoll paths
- **Claimed**: 2026-08-01T16:13:22Z
- **Status**: COMPLETED @ 2026-08-01T16:28:20Z

### [DONE] service-artifact-pipeline-20260801
- **Session**: `Nathan-1353`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/CMakeLists.txt,tools/build/gen-service-manifest.py,tools/test/test-gen-service-manifest.py,userland/native-apps/serviced/serviced.c,userland/native-apps/execd/execd.c,userland/native-apps/displayd/displayd.c,userland/native-apps/registryd/registryd.c`
- **Description**: Deterministic freestanding service artifacts and bounded build-tree manifest/package binding with activation disabled
- **Claimed**: 2026-08-01T16:17:20Z
- **Status**: COMPLETED @ 2026-08-01T16:51:13Z

### [DONE] linux-signal-pending-sync-test-20260801
- **Session**: `Codex-linux-signal-pending-sync`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `tools/test/test-linux-timer-signalfd-receipt-contract.py`
- **Description**: Update retained async readiness contract for centralized atomic pending-signal accessor
- **Claimed**: 2026-08-01T16:18:29Z
- **Status**: COMPLETED @ 2026-08-01T16:28:11Z

### [DONE] job-member-process-exit-glue-20260801
- **Session**: `Codex-job-cycle-break`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/proc/process.cpp,tools/test/test-process-runtime-access-contract.py,tools/test/test-process-task-publication-contract.py`
- **Description**: Replace
- **Claimed**: 2026-08-01T16:33:23Z
- **Status**: COMPLETED @ 2026-08-01T18:59:10Z

### [DONE] job-member-completion-contract-20260801
- **Session**: `Codex-job-cycle-break`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `tools/test/test-job-member-completion-contract.py`
- **Description**: Enforce
- **Claimed**: 2026-08-01T16:43:28Z
- **Status**: COMPLETED @ 2026-08-01T18:59:12Z

### [DONE] linux-exit-unwind-20260801
- **Session**: `Codex-linux-exit-unwind`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/subsystems/linux/syscall.cpp,kernel/subsystems/linux/syscall.h,kernel/subsystems/translation/translate.cpp,tools/test/test-linux-exit-unwind-contract.py`
- **Description**: Make Linux and NT translated exit requests return through cooperative cancellation guards without false noreturn or foreign frame abandonment
- **Claimed**: 2026-08-01T16:48:47Z
- **Status**: COMPLETED @ 2026-08-01T16:56:26Z

### [DONE] ipc-wait-cancellation-20260801
- **Session**: `Codex-ipc-wait-cancellation`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/ipc/kevent.h,kernel/ipc/kevent.cpp,kernel/ipc/ksemaphore.h,kernel/ipc/ksemaphore.cpp,kernel/ipc/kmailbox.h,kernel/ipc/kmailbox.cpp,kernel/ipc/kwaitable.h,kernel/ipc/kwaitable.cpp,kernel/subsystems/win32/event_syscall.h,kernel/subsystems/win32/event_syscall.cpp,kernel/subsystems/win32/semaphore_syscall.h,kernel/subsystems/win32/semaphore_syscall.cpp,kernel/shell/shell_bench.cpp,tools/test/test-ipc-wait-cancellation-contract.py,wiki/kernel/IPC.md`
- **Description**: Migrate
- **Claimed**: 2026-08-01T16:57:47Z
- **Status**: COMPLETED @ 2026-08-01T17:25:58Z

### [DONE] job-userland-ingress-contract-20260801
- **Session**: `Codex-job-cycle-break`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `tools/test/test-job-userland-ingress-contract.py`
- **Description**: Hostile
- **Claimed**: 2026-08-01T16:58:46Z
- **Status**: COMPLETED @ 2026-08-01T17:05:23Z

### [DONE] job-file-close-doc-20260801
- **Session**: `Codex-job-cycle-break`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/subsystems/win32/file_syscall.cpp`
- **Description**: Synchronize
- **Claimed**: 2026-08-01T17:02:59Z
- **Status**: COMPLETED @ 2026-08-01T17:05:26Z

### [DONE] service-elf-load-image-20260801
- **Session**: `Nathan-294`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/loader/elf_load_image.h kernel/loader/elf_load_image.cpp tests/host/test_elf_load_image.cpp tests/host/CMakeLists.txt tools/test/test-service-elf-load-image-contract.py wiki/kernel/Loader.md`
- **Description**: Stage exact ELF bytes through production parser into sealed LoadImage/LoadPlan without publishing a Process
- **Claimed**: 2026-08-01T17:19:06Z
- **Status**: COMPLETED @ 2026-08-01T17:30:14Z

### [DONE] ipc-residual-wait-cancellation-20260801
- **Session**: `Nathan-467`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/ipc/iocp.h,kernel/ipc/iocp.cpp,kernel/subsystems/win32/iocp_syscall.cpp,kernel/ipc/kmessage_port.h,kernel/ipc/kmessage_port.cpp,tools/test/test-ipc-residual-wait-cancellation-contract.py`
- **Description**: Migrate IOCP and message-port waits to explicit cancellation-safe outcomes with deadline and lifetime contracts
- **Claimed**: 2026-08-01T17:23:26Z
- **Status**: COMPLETED @ 2026-08-01T17:55:26Z

### [DONE] service-manifest-authority-binding-20260801
- **Session**: `Nathan-640`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `config/service-authority.toml config/services.toml tools/build/gen-service-manifest.py tools/test/test-gen-service-manifest.py kernel/CMakeLists.txt`
- **Description**: Bind generated artifact package to a separately trusted build authority while keeping bootstrap plans and activation disabled
- **Claimed**: 2026-08-01T17:31:11Z
- **Status**: COMPLETED @ 2026-08-01T17:43:31Z

### [DONE] service-runtime-staging-20260801
- **Session**: `Nathan-186`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/core/service_bootstrap_stage.h,kernel/core/service_bootstrap_stage.cpp,tests/host/test_service_bootstrap_stage.cpp,tools/test/test-service-bootstrap-stage-contract.py,wiki/kernel/Service-Bootstrap.md,kernel/CMakeLists.txt,tests/host/CMakeLists.txt`
- **Description**: Initialize authority-bound service package, mint typed stable backing identities, stage ELF LoadImages, and consume through ExecAdmission without activation
- **Claimed**: 2026-08-01T17:45:11Z
- **Status**: COMPLETED @ 2026-08-01T18:55:45Z

### [DONE] rust-ingress-node-validation-20260801
- **Session**: `Nathan-RustNode-20260801`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/fs/duetfs/src/format.rs,kernel/fs/duetfs/src/fs.rs,kernel/fs/duetfs/src/fsck.rs,kernel/fs/duetfs/src/ops_dir.rs`
- **Description**: Centralize validated normal node reads while preserving bounded raw fsck diagnostics
- **Claimed**: 2026-08-01T17:52:28Z
- **Status**: COMPLETED @ 2026-08-01T18:16:33Z

### [ACTIVE] cancellation-smp-runtime-oracle-20260801
- **Session**: `Codex-cancellation-smp-oracle`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/test/cancellation_smp_oracle.h,kernel/test/cancellation_smp_oracle.cpp,kernel/test/smoke_profile.h,kernel/test/smoke_profile.cpp,tools/test/profile-boot-smoke.sh,tools/test/test-cancellation-smp-oracle-contract.py,wiki/tooling/QEMU-Smoke.md`
- **Description**: Deterministic
- **Claimed**: 2026-08-01T18:02:35Z
- **Status**: IN PROGRESS

### [DONE] gdb-capability-snapshot-20260801
- **Session**: `Codex-job-cycle-break`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/proc/process.h,kernel/diag/gdb_monitor_read.cpp`
- **Description**: Expose bounded no-wait effective capability snapshot for stop-loop diagnostics without direct Process authority access
- **Claimed**: 2026-08-01T18:28:04Z
- **Status**: COMPLETED @ 2026-08-01T18:37:17Z

### [DONE] gdb-capability-snapshot-contract-20260801
- **Session**: `Codex-job-cycle-break`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `tools/test/test-gdb-monitor-stop-safety-contract.py`
- **Description**: Require capability stop-loop reader to use process-owned no-wait snapshot helper
- **Claimed**: 2026-08-01T18:29:19Z
- **Status**: COMPLETED @ 2026-08-01T18:37:20Z

### [DONE] service-bootstrap-activation-20260801
- **Session**: `Nathan-ServiceActivate-20260801`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/core/service_bootstrap_stage.h kernel/core/service_bootstrap_stage.cpp kernel/core/service_bootstrap_activation.h kernel/core/service_bootstrap_activation.cpp tests/host/test_service_bootstrap_stage.cpp tests/host/test_service_bootstrap_activation.cpp tools/test/test-service-bootstrap-stage-contract.py tools/test/test-service-bootstrap-activation-contract.py wiki/kernel/Service-Bootstrap.md kernel/proc/resource_domain.h kernel/proc/resource_domain.cpp tests/host/test_resource_domain.cpp kernel/CMakeLists.txt tests/host/CMakeLists.txt`
- **Description**: Compiled-but-dormant one-shot authority-bound service activation transaction
- **Claimed**: 2026-08-01T18:57:44Z
- **Status**: COMPLETED @ 2026-08-01T19:56:29Z

### [DONE] job-scheduler-linearization-repair-20260801
- **Session**: `Codex-JobLinearization-20260801`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/proc/job.h,kernel/proc/job.cpp,kernel/sched/sched.h,kernel/sched/sched.cpp,kernel/proc/process.h,kernel/proc/process.cpp,kernel/subsystems/win32/job_syscall.cpp,kernel/syscall/syscall.cpp,tools/test/test-job-member-completion-contract.py,tools/test/test-job-scheduler-linearization-contract.py,tools/test/test-process-task-publication-contract.py,tools/test/test-task-cancellation-contract.py`
- **Description**: Scheduler-linearized Job assignment inheritance termination exit-code and retirement repair
- **Claimed**: 2026-08-01T19:00:22Z
- **Status**: COMPLETED @ 2026-08-01T19:41:11Z

### [DONE] job-userland-runtime-proof-20260801
- **Session**: `Codex-JobUserlandProof-20260801`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `userland/libs/kernel32/kernel32_sync.c,userland/apps/jobobj_smoke/*,tools/build/build-kernel32-dll.sh,tools/test/test-job-userland-ingress-contract.py,tools/test/test-job-runtime-proof-contract.py,wiki/reference/Win32-Surface-Status.md,wiki/specifications/Syscall-ABI.md,wiki/kernel/Scheduler.md`
- **Description**: Real
- **Claimed**: 2026-08-01T19:01:50Z
- **Status**: COMPLETED @ 2026-08-01T19:41:14Z

### [DONE] service-lifecycle-dependency-reserve-20260801
- **Session**: `Nathan-ServiceActivate-20260801`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/core/service_lifecycle_broker.h kernel/core/service_lifecycle_broker.cpp tests/host/test_service_lifecycle_broker.cpp`
- **Description**: Atomically require exact manifest dependencies Running while reserving a service start
- **Claimed**: 2026-08-01T19:06:16Z
- **Status**: COMPLETED @ 2026-08-01T19:56:32Z

### [DONE] job-ntdll-query-export-fix-20260801
- **Session**: `Codex-JobUserlandProof-20260801`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `tools/build/build-ntdll-dll.sh`
- **Description**: Remove
- **Claimed**: 2026-08-01T19:24:39Z
- **Status**: COMPLETED @ 2026-08-01T19:41:16Z

### [DONE] linux-pipe-wait-cancellation-20260801
- **Session**: `Nathan-538`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/subsystems/linux/syscall_pipe.cpp tools/test/test-linux-pipe-wait-cancellation-contract.py`
- **Description**: Cancellation-safe sequence-linearized Linux pipe eventfd splice and tee waits
- **Claimed**: 2026-08-01T19:26:06Z
- **Status**: COMPLETED @ 2026-08-01T19:41:25Z

### [DONE] linux-exit-code-ticket-20260801
- **Session**: `Nathan-1332`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/subsystems/linux/syscall_proc.cpp tools/test/test-linux-exit-unwind-contract.py`
- **Description**: Bind Linux exit status into the combined scheduler cancellation ticket
- **Claimed**: 2026-08-01T19:32:54Z
- **Status**: COMPLETED @ 2026-08-01T19:41:28Z

### [DONE] scheduler-sleep-exit-boundary-20260801
- **Session**: `Nathan-287`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/sched/sched.h,kernel/sched/sched.cpp,tools/test/test-task-cancellation-contract.py`
- **Description**: Close kill-before-sleep race and constrain process-backed terminal exits to cooperative boundaries
- **Claimed**: 2026-08-01T19:42:11Z
- **Status**: COMPLETED @ 2026-08-01T20:07:00Z

### [DONE] user-wait-cancellation-20260801
- **Session**: `Codex-UserWaitCancellation-20260801`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/proc/process.cpp,kernel/proc/process.h,kernel/subsystems/win32/thread_syscall.cpp,kernel/subsystems/win32/thread_syscall.h,kernel/syscall/syscall.cpp,tools/test/test-process-child-wait-cancellation-contract.py,tools/test/test-win32-thread-wait-cancellation-contract.py`
- **Description**: Sequence-linearized
- **Claimed**: 2026-08-01T19:43:51Z
- **Status**: COMPLETED @ 2026-08-01T20:07:03Z

### [DONE] handle-table-publication-reservation-20260801
- **Session**: `Codex-HandlePublication-20260801`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/ipc/handle_table.h,kernel/ipc/handle_table.cpp,kernel/ipc/handle_table_selftest.cpp,tools/test/test-handle-publication-reservation-contract.py`
- **Description**: Unpublished exact handle reservation publish abort and drain transaction
- **Claimed**: 2026-08-01T19:43:55Z
- **Status**: COMPLETED @ 2026-08-01T20:04:53Z

### [DONE] linux-child-wait-cancel-status-20260801
- **Session**: `Codex-UserWaitCancellation-20260801`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/subsystems/linux/syscall_stub.cpp`
- **Description**: Propagate
- **Claimed**: 2026-08-01T19:44:20Z
- **Status**: COMPLETED @ 2026-08-01T20:07:05Z

### [DONE] service-endpoint-kobject-tag-20260801
- **Session**: `Codex-HandlePublication-20260801`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/ipc/kobject.h`
- **Description**: Append stable ServiceEndpoint KObject tag for authenticated channel handles
- **Claimed**: 2026-08-01T19:56:57Z
- **Status**: COMPLETED @ 2026-08-01T20:04:55Z

### [DONE] service-endpoint-kobject-name-20260801
- **Session**: `Codex-HandlePublication-20260801`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/ipc/kobject.cpp`
- **Description**: Expose stable diagnostic name for ServiceEndpoint KObject tag
- **Claimed**: 2026-08-01T19:58:04Z
- **Status**: COMPLETED @ 2026-08-01T20:04:58Z

### [DONE] service-endpoint-publication-20260801
- **Session**: `Nathan-ServiceActivate-20260801`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/core/service_endpoint.h kernel/core/service_endpoint.cpp kernel/core/service_directory.h kernel/core/service_directory.cpp tests/host/test_service_endpoint.cpp tests/host/test_service_directory.cpp tools/test/test-service-endpoint-contract.py`
- **Description**: Authenticated ServiceEndpoint ownership and failure-atomic directory/handle publication
- **Claimed**: 2026-08-01T20:00:58Z
- **Status**: COMPLETED @ 2026-08-01T21:18:09Z

### [DONE] linux-sysv-ipc-wait-cancellation-20260801
- **Session**: `Nathan-565`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/subsystems/linux/msg_queues.cpp,tools/test/test-linux-sysv-ipc-wait-cancellation-contract.py`
- **Description**: Sequence-linearized cancellable SysV message-queue and semaphore blocking waits with removal and ABA safety
- **Claimed**: 2026-08-01T20:09:41Z
- **Status**: COMPLETED @ 2026-08-01T20:50:41Z

### [DONE] win32-directory-address-wait-cancellation-20260801
- **Session**: `Codex-root-win32wait`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/subsystems/win32/dir_syscall.cpp,kernel/subsystems/win32/waitaddr_syscall.cpp,tools/test/test-win32-directory-address-wait-cancellation-contract.py`
- **Description**: Sequence-linearized
- **Claimed**: 2026-08-01T20:10:29Z
- **Status**: COMPLETED @ 2026-08-01T20:23:16Z

### [DONE] linux-sysv-sem-wait-cancellation-20260801
- **Session**: `Nathan-720`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/subsystems/linux/sysv_ipc.cpp,kernel/subsystems/linux/syscall_internal.h`
- **Description**: Cancellation-safe sequence-linearized SysV semop and semtimedop waits with removal and saturation safety
- **Claimed**: 2026-08-01T20:10:43Z
- **Status**: COMPLETED @ 2026-08-01T20:50:44Z

### [DONE] linux-notify-aio-wait-cancel-20260801
- **Session**: `Codex-LinuxNotifyAioCancel-20260801`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/subsystems/linux/fanotify.cpp,kernel/subsystems/linux/inotify.cpp,kernel/subsystems/linux/syscall_async_io.cpp,kernel/subsystems/linux/pidfd_splice.cpp,tools/test/test-linux-notify-aio-wait-cancellation-contract.py`
- **Description**: Sequence-linearized cancellable notification timerfd epoll and pidfd waits with close timeout and ABA contracts
- **Claimed**: 2026-08-01T20:11:36Z
- **Status**: COMPLETED @ 2026-08-01T20:47:23Z

### [DONE] linux-notify-aio-nonblock-ingress-20260801
- **Session**: `Codex-LinuxNotifyAioCancel-20260801`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/subsystems/linux/fanotify.h,kernel/subsystems/linux/inotify.h,kernel/subsystems/linux/syscall_async_io.h,kernel/subsystems/linux/syscall_io.cpp`
- **Description**: Snapshot exact retained OFD O_NONBLOCK state and pass it into cancellable read helpers without holding guards across waits
- **Claimed**: 2026-08-01T20:14:03Z
- **Status**: COMPLETED @ 2026-08-01T20:47:34Z

### [DONE] linux-signal-wait-sequence-20260801
- **Session**: `Codex-LinuxNotifyAioCancel-20260801`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/proc/process.h,kernel/proc/process.cpp`
- **Description**: Persistent saturating signal event sequence for ABA-safe signalfd cancellation waits
- **Claimed**: 2026-08-01T20:18:35Z
- **Status**: COMPLETED @ 2026-08-01T20:47:47Z

### [DONE] linux-fd-async-pools-wait-contract-20260801
- **Session**: `Nathan-828`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `tools/test/test-linux-fd-async-pools-contract.py`
- **Description**: Update exact POSIX MQ receipt lifetime contract for cancellable waits without subsystem pins
- **Claimed**: 2026-08-01T20:31:38Z
- **Status**: COMPLETED @ 2026-08-01T20:48:42Z

### [DONE] service-exit-observer-20260801
- **Session**: `Codex-ServiceExitObserver-20260801`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/core/service_exit_observer.h,kernel/core/service_exit_observer.cpp,tests/host/test_service_exit_observer.cpp,tools/test/test-service-exit-observer-contract.py`
- **Description**: Fixed-capacity publication-reserved exact ProcessKey service-exit event queue with dequeue acknowledgement
- **Claimed**: 2026-08-01T20:34:10Z
- **Status**: COMPLETED @ 2026-08-01T20:48:45Z

### [DONE] service-exit-observer-build-20260801
- **Session**: `Codex-ServiceExitObserverBuild-20260801`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `tests/host/CMakeLists.txt`
- **Description**: Register hosted service exit observer test after endpoint CMake handoff
- **Claimed**: 2026-08-01T20:43:03Z
- **Status**: COMPLETED @ 2026-08-01T20:48:47Z

### [DONE] service-handle-table-host-atomic-20260801
- **Session**: `Nathan-2`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/ipc/handle_table.cpp`
- **Description**: Add
- **Claimed**: 2026-08-01T20:44:37Z
- **Status**: COMPLETED @ 2026-08-01T20:50:47Z

### [DONE] service-exit-observer-integration-20260801
- **Session**: `Nathan-937`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/core/service_bootstrap_activation.h,kernel/core/service_bootstrap_activation.cpp,kernel/proc/process.cpp,tests/host/test_service_bootstrap_activation.cpp,tools/test/test-service-bootstrap-activation-contract.py`
- **Description**: Integrate exact service exit observer reservation binding rollback and post-Exited publication without runnable-before-registration races
- **Claimed**: 2026-08-01T20:50:06Z
- **Status**: COMPLETED @ 2026-08-01T20:50:49Z

### [DONE] linux-sysv-ipc-id-generation-20260801
- **Session**: `Nathan-1201`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/subsystems/linux/msg_queues.cpp,kernel/subsystems/linux/sysv_ipc.cpp,kernel/subsystems/linux/syscall_internal.h,tools/test/test-linux-sysv-ipc-id-generation-contract.py`
- **Description**: Generation-bearing stale-safe positive Linux SysV message semaphore and shared-memory identifiers with hostile reuse and saturation contracts
- **Claimed**: 2026-08-01T20:53:44Z
- **Status**: COMPLETED @ 2026-08-01T21:12:26Z

### [DONE] service-exit-observer-activation-build-20260801
- **Session**: `Nathan-1710`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `tests/host/CMakeLists.txt`
- **Description**: Link
- **Claimed**: 2026-08-01T21:03:49Z
- **Status**: COMPLETED @ 2026-08-01T21:18:02Z

### [DONE] linux-sysv-ipc-id-generation-wait-contract-20260801
- **Session**: `Nathan-1201`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `tools/test/test-linux-sysv-ipc-wait-cancellation-contract.py`
- **Description**: Synchronize prior SysV wait contract with generation-bearing exact public IDs without weakening cancellation semantics
- **Claimed**: 2026-08-01T21:05:53Z
- **Status**: COMPLETED @ 2026-08-01T21:18:06Z

### [DONE] service-runtime-owner-20260801
- **Session**: `Nathan-1400`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/core/service_runtime.h,kernel/core/service_runtime.cpp,tools/test/test-service-runtime-owner-contract.py`
- **Description**: Static
- **Claimed**: 2026-08-01T21:06:00Z
- **Status**: COMPLETED @ 2026-08-01T21:18:14Z

### [DONE] service-endpoint-publication-doc-20260801
- **Session**: `Nathan-539`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `wiki/kernel/Service-Bootstrap.md`
- **Description**: Document
- **Claimed**: 2026-08-01T21:09:51Z
- **Status**: COMPLETED @ 2026-08-01T21:18:18Z

### [DONE] process-authority-wiring-20260801
- **Session**: `Codex-ProcessAuthority-20260801`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/proc/process.h,kernel/proc/process.cpp,kernel/proc/credentials.h,kernel/proc/credentials.cpp,kernel/proc/authorization_context.h,kernel/proc/authorization_context.cpp,kernel/sched/sched.cpp,kernel/syscall/cap_gate.cpp,kernel/security/broker.cpp,kernel/security/grace.cpp,kernel/security/grace.h,kernel/security/attack_sim.cpp,kernel/shell/shell_security.cpp,kernel/apps/dbg_core.cpp,kernel/diag/leak_detector.cpp,kernel/syscall/syscall.cpp,kernel/subsystems/linux/syscall_clone.cpp,kernel/subsystems/linux/syscall_misc.cpp,kernel/subsystems/linux/syscall_time.cpp,kernel/subsystems/win32/spawn_syscall.cpp,kernel/subsystems/win32/token_syscall.cpp,tests/host/test_credentials.cpp,tests/host/test_authorization_context.cpp,tools/test/test-process-authority-wiring-contract.py`
- **Description**: Wire
- **Claimed**: 2026-08-01T21:15:21Z
- **Status**: COMPLETED @ 2026-08-01T22:11:48Z

### [DONE] service-runtime-owner-build-20260801
- **Session**: `Codex-ServiceRuntimeBuild-20260801`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/CMakeLists.txt`
- **Description**: Register static service runtime owner in production kernel source graph
- **Claimed**: 2026-08-01T21:18:53Z
- **Status**: COMPLETED @ 2026-08-01T21:19:39Z

### [DONE] serviced-supervisor-20260801
- **Session**: `Codex-ServicedSupervisor-20260801`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `userland/native-apps/serviced/supervisor.h userland/native-apps/serviced/supervisor.c tests/host/test_serviced_supervisor.cpp tools/test/test-serviced-supervisor-contract.py tests/host/CMakeLists.txt`
- **Description**: Fixed-capacity serviced policy state machine with exact lifecycle replay restart reconciliation and command dedup
- **Claimed**: 2026-08-01T21:25:02Z
- **Status**: COMPLETED @ 2026-08-01T22:22:08Z

### [DONE] process-authority-direct-callers-20260801
- **Session**: `Codex-ProcessAuthority-20260801`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/subsystems/win32/file_syscall.cpp,kernel/subsystems/linux/syscall.cpp`
- **Description**: Migrate
- **Claimed**: 2026-08-01T21:25:48Z
- **Status**: COMPLETED @ 2026-08-01T22:11:57Z

### [DONE] serviced-supervisor-private-20260801
- **Session**: `Codex-ServicedSupervisor-20260801`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `userland/native-apps/serviced/supervisor_internal.h`
- **Description**: Private fixed-layout storage for opaque serviced supervisor object
- **Claimed**: 2026-08-01T21:34:41Z
- **Status**: COMPLETED @ 2026-08-01T22:22:17Z

### [DONE] service-runtime-owner-doc-20260801
- **Session**: `Codex-ServiceRuntimeDoc-20260801`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `wiki/kernel/Service-Bootstrap.md`
- **Description**: Document static runtime ownership, exact identity inspection, and live-boot boundary
- **Claimed**: 2026-08-01T21:36:03Z
- **Status**: COMPLETED @ 2026-08-01T22:58:27Z

### [DONE] serviced-supervisor-policy-20260801
- **Session**: `Codex-ServicedSupervisor-20260801`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `userland/native-apps/serviced/supervisor_policy.c`
- **Description**: Private serviced event command reconciliation and restart policy implementation
- **Claimed**: 2026-08-01T21:37:45Z
- **Status**: COMPLETED @ 2026-08-01T22:22:24Z

### [DONE] service-bootstrap-live-20260801
- **Session**: `Nathan-161`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/core/service_bootstrap_live.h,kernel/core/service_bootstrap_live.cpp,kernel/core/boot_bringup.cpp,tools/test/test-service-bootstrap-live-contract.py`
- **Description**: Wire fixed-capacity generated service staging and runtime owner into boot without activating services
- **Claimed**: 2026-08-01T21:42:44Z
- **Status**: COMPLETED @ 2026-08-01T22:14:40Z

### [DONE] service-directory-close-adapter-20260801
- **Session**: `Codex-ServiceDirectoryClose-20260801`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/core/service_directory.h,kernel/core/service_directory.cpp,tests/host/test_service_directory.cpp,tools/test/test-service-endpoint-contract.py`
- **Description**: Bind normal server handle close to exact accepted-channel ownership release without endpoint metadata leaks
- **Claimed**: 2026-08-01T21:44:58Z
- **Status**: COMPLETED @ 2026-08-01T22:09:34Z

### [DONE] serviced-supervisor-policy-split-20260801
- **Session**: `Codex-ServicedSupervisor-20260801`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `userland/native-apps/serviced/supervisor_reconcile.c userland/native-apps/serviced/supervisor_event.c userland/native-apps/serviced/supervisor_command.c`
- **Description**: Split serviced reconciliation ordered-event and command-dedup policy TUs
- **Claimed**: 2026-08-01T21:47:45Z
- **Status**: COMPLETED @ 2026-08-01T22:22:31Z

### [DONE] service-bootstrap-live-build-20260801
- **Session**: `Nathan-944`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/CMakeLists.txt`
- **Description**: Register the live service bootstrap anchor in both kernel stages
- **Claimed**: 2026-08-01T21:55:18Z
- **Status**: COMPLETED @ 2026-08-01T21:56:41Z

### [DONE] win32-service-endpoint-close-20260801
- **Session**: `Codex-ServiceEndpointClose-20260801`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/subsystems/win32/file_syscall.cpp,tools/test/test-win32-service-endpoint-close-contract.py`
- **Description**: Wire
- **Claimed**: 2026-08-01T22:15:39Z
- **Status**: COMPLETED @ 2026-08-01T22:30:15Z

### [DONE] service-endpoint-request-lifecycle-20260801
- **Session**: `Codex-ServiceRequestLifecycle-20260801`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/ipc/channel_core.h,kernel/ipc/channel_core.cpp,kernel/core/service_endpoint.h,kernel/core/service_endpoint.cpp,tests/host/test_channel_core.cpp,tests/host/test_service_endpoint.cpp,tools/test/test-service-endpoint-request-lifecycle-contract.py`
- **Description**: Pinned
- **Claimed**: 2026-08-01T22:16:32Z
- **Status**: COMPLETED @ 2026-08-01T22:58:18Z

### [DONE] registryd-store-20260801
- **Session**: `Nathan-1239`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `userland/native-apps/registryd/registry_store.h,userland/native-apps/registryd/registry_store.c,userland/native-apps/registryd/registry_persistence.c,tests/host/test_registryd_store.cpp,tools/test/test-registryd-store-contract.py`
- **Description**: Allocation-free registry store with canonical snapshot and WAL recovery
- **Claimed**: 2026-08-01T22:18:13Z
- **Status**: COMPLETED @ 2026-08-01T22:58:31Z

### [DONE] execd-worker-engine-20260801
- **Session**: `Nathan-1915`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `userland/native-apps/execd/worker.h,userland/native-apps/execd/worker_internal.h,userland/native-apps/execd/worker.c,userland/native-apps/execd/worker_request.c,tests/host/test_execd_worker.cpp,tools/test/test-execd-worker-contract.py`
- **Description**: Fixed-capacity authenticated generation-safe execd request worker engine with cancellation reply commit peer close and drain
- **Claimed**: 2026-08-01T22:30:59Z
- **Status**: COMPLETED @ 2026-08-01T23:03:52Z

### [DONE] registryd-store-split-20260801
- **Session**: `Nathan-1463`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `userland/native-apps/registryd/registry_store_internal.h,userland/native-apps/registryd/registry_validate.c,userland/native-apps/registryd/registry_recovery.c`
- **Description**: Split registryd canonical validation and recovery codecs below bloat thresholds
- **Claimed**: 2026-08-01T22:50:16Z
- **Status**: COMPLETED @ 2026-08-01T23:06:46Z

### [DONE] displayd-engine-20260801
- **Session**: `Nathan-715`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `userland/native-apps/displayd/display_engine.h,userland/native-apps/displayd/display_engine_internal.h,userland/native-apps/displayd/display_engine.c,userland/native-apps/displayd/display_engine_request.c,tests/host/test_displayd_engine.cpp,tools/test/test-displayd-engine-contract.py`
- **Description**: Fixed-capacity
- **Claimed**: 2026-08-01T23:00:56Z
- **Status**: COMPLETED @ 2026-08-02T00:02:38Z

### [ACTIVE] driver-id-watch-hardening-20260801
- **Session**: `Codex-DriverIntegration-20260801`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/drivers/net/nic_ids.h,kernel/drivers/net/net.h,kernel/drivers/net/net.cpp,kernel/drivers/net/iwlwifi.cpp,kernel/drivers/net/rtl88xx.cpp,kernel/drivers/net/bcm43xx.cpp,kernel/drivers/net/mt76.cpp,kernel/drivers/net/wireless_watch.h,kernel/drivers/net/wireless_watch.cpp,tests/host/test_nic_ids.cpp,tests/host/test_wireless_watch.cpp,tools/test/test-nic-id-classification-contract.py,tools/test/test-wireless-watch-lifecycle-contract.py,tools/test/ctest-boot-smoke.sh,wiki/drivers/Networking-Drivers.md,wiki/reference/Design-Decisions.md`
- **Description**: Audit and integrate Fable NIC PCI-ID safety plus race-free wireless watcher teardown
- **Claimed**: 2026-08-01T23:05:29Z
- **Status**: IN PROGRESS

### [ACTIVE] netd-socket-engine-20260801
- **Session**: `Codex-NetdSocketEngine-20260801`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `userland/native-apps/netd/socket_engine.h,userland/native-apps/netd/socket_engine_internal.h,userland/native-apps/netd/socket_engine.c,userland/native-apps/netd/socket_engine_request.c,tests/host/test_netd_socket_engine.cpp,tools/test/test-netd-socket-engine-contract.py`
- **Description**: Fixed-capacity authenticated netd socket Open Close transaction engine with fail-closed transport attachment and exact drain cleanup
- **Claimed**: 2026-08-01T23:13:18Z
- **Status**: IN PROGRESS

### [ACTIVE] netd-socket-engine-split-20260801
- **Session**: `Codex-NetdSocketEngine-20260801`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `userland/native-apps/netd/socket_engine_validate.c,userland/native-apps/netd/socket_engine_lifecycle.c`
- **Description**: Split netd socket engine invariant validation from close reply and drain lifecycle below bloat thresholds
- **Claimed**: 2026-08-01T23:26:59Z
- **Status**: IN PROGRESS

### [DONE] displayd-engine-split-20260801
- **Session**: `Codex-DisplaydEngine-20260801`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `userland/native-apps/displayd/display_engine_validate.c userland/native-apps/displayd/display_engine_event.c`
- **Description**: Mechanical anti-bloat split of validated displayd engine
- **Claimed**: 2026-08-01T23:50:40Z
- **Status**: COMPLETED @ 2026-08-02T00:02:35Z

### [DONE] service-driver-test-build-integration-20260801
- **Session**: `Nathan-1437`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `tests/host/CMakeLists.txt,.github/workflows/build.yml`
- **Description**: Register completed service engines and NIC safety contracts in hosted build and CI
- **Claimed**: 2026-08-02T00:09:14Z
- **Status**: COMPLETED @ 2026-08-02T06:55:16Z

### [DONE] net-stack-restart-20260801
- **Session**: `Codex-NetStackRestart-20260801`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/net/stack.h,kernel/net/stack.cpp,tests/host/test_net_stack_restart.cpp,tools/test/test-net-stack-restart-contract.py`
- **Description**: Generation-safe
- **Claimed**: 2026-08-02T00:20:14Z
- **Status**: COMPLETED @ 2026-08-02T00:57:35Z

### [DONE] net-mt7921-contract
- **Session**: `Codex-MT7921Contract-20260801`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/drivers/net/mt7921_contract.h,kernel/drivers/net/mt7921_contract.cpp,tests/host/test_mt7921_contract.cpp,tools/test/test-mt7921-contract.py`
- **Description**: Clean-room exact MT7921 PCI contract, bounded firmware/MCU/ring validation, and fail-closed bring-up state machine
- **Claimed**: 2026-08-02T00:43:55Z
- **Status**: COMPLETED @ 2026-08-02T01:24:42Z

### [DONE] net-stack-tcp-generation-20260801
- **Session**: `Codex-NetTcpGeneration-20260801`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/net/stack.h,kernel/net/stack.cpp,kernel/net/tcp.h,kernel/net/tcp_internal.h,kernel/net/tcp.cpp,kernel/net/tcp_segment.cpp,tests/host/test_net_stack_restart.cpp,tools/test/test-net-stack-restart-contract.py`
- **Description**: Generation-bearing
- **Claimed**: 2026-08-02T00:58:26Z
- **Status**: COMPLETED @ 2026-08-02T01:58:26Z

### [DONE] net-stack-tcp-generation-selftest-20260801
- **Session**: `Codex-NetTcpGeneration-20260801`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/net/tcp_selftest.cpp`
- **Description**: Update
- **Claimed**: 2026-08-02T01:02:31Z
- **Status**: COMPLETED @ 2026-08-02T01:58:37Z

### [DONE] pci-bar-sizing-20260801
- **Session**: `Nathan-952`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/drivers/pci/pci.h,kernel/drivers/pci/pci.cpp,tests/host/test_pci_bar_probe.cpp,tools/test/test-pci-bar-sizing-contract.py`
- **Description**: Serialized decode-safe 32/64-bit PCI BAR sizing transaction with hostile host contract tests
- **Claimed**: 2026-08-02T01:04:54Z
- **Status**: COMPLETED @ 2026-08-02T01:25:42Z

### [ACTIVE] net-registry-snapshot-20260801
- **Session**: `Codex-NetRegistry-20260801`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/diag/telemetry.cpp,kernel/net/wireless/inventory.cpp,kernel/drivers/video/netpanel.cpp,kernel/shell/shell_network.cpp,kernel/shell/shell_hardware.cpp,kernel/drivers/net/nic_telemetry.cpp,tests/fuzz/host_shim/net_stubs.cpp,tools/test/test-net-registry-lifecycle-contract.py`
- **Description**: Lock-protected NIC registry lifecycle with copy-out snapshots and fail-closed restart state
- **Claimed**: 2026-08-02T01:06:09Z
- **Status**: IN PROGRESS

### [DONE] pci-endpoint-identity-20260801
- **Session**: `Nathan-1003`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/drivers/pci/pci.h,kernel/drivers/pci/pci.cpp,tests/host/test_pci_endpoint_identity.cpp,tools/test/test-pci-endpoint-identity-contract.py`
- **Description**: Cached endpoint-only revision programming-interface and subsystem identity with hostile decode coverage
- **Claimed**: 2026-08-02T01:26:34Z
- **Status**: COMPLETED @ 2026-08-02T01:52:48Z

### [DONE] net-mt7921-fixedmap-20260801
- **Session**: `Fable-MT7921Slice-20260801`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/drivers/net/mt7921_contract.h,kernel/drivers/net/mt7921_contract.cpp,tests/host/test_mt7921_contract.cpp,tools/test/test-mt7921-contract.py`
- **Description**: Exact fixed/L1 register-map planner and stricter bring-up resource contract for MT7921
- **Claimed**: 2026-08-02T01:34:16Z
- **Status**: COMPLETED @ 2026-08-02T02:09:05Z

### [DONE] pcnet-restart-20260801
- **Session**: `Codex-PcnetRestart-20260801`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/drivers/net/pcnet.h,kernel/drivers/net/pcnet.cpp,tests/host/test_pcnet_restart.cpp,tools/test/test-pcnet-restart-contract.py`
- **Description**: Restart-safe AMD PCnet exact binding worker operation DMA and PCI teardown contract
- **Claimed**: 2026-08-02T01:56:49Z
- **Status**: COMPLETED @ 2026-08-02T02:20:42Z

### [DONE] net-stack-udp-receipt-20260801
- **Session**: `Codex-NetUdpReceipt-20260801`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/net/socket.cpp,kernel/net/socket.h,tests/host/test_net_stack_restart.cpp,tools/test/test-net-stack-restart-contract.py`
- **Description**: Exact UDP interface receipts, restart isolation, and bounded stream-socket stale-state reconciliation
- **Claimed**: 2026-08-02T02:00:12Z
- **Status**: COMPLETED @ 2026-08-02T02:43:31Z

### [DONE] structural-contract-drift-20260802
- **Session**: `Codex-StructuralDrift-20260802`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `tools/test/test-gdb-monitor-stop-safety-contract.py,tools/test/test-process-runtime-access-contract.py,tools/test/test-service-bootstrap-stage-contract.py`
- **Description**: Repair structural tests after authorization, scheduler-linearized Job exit, and service-doc wording migrations
- **Claimed**: 2026-08-02T02:01:20Z
- **Status**: COMPLETED @ 2026-08-02T02:05:34Z

### [DONE] mt7921-fixedmap-integration-20260802
- **Session**: `Codex-MT7921Integration-20260802`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/drivers/net/mt7921_contract.h,kernel/drivers/net/mt7921_contract.cpp,tests/host/test_mt7921_contract.cpp,tools/test/test-mt7921-contract.py`
- **Description**: Audit and integrate Fable exact fixed/L1 register mapping and generation-bound planning
- **Claimed**: 2026-08-02T02:09:09Z
- **Status**: COMPLETED @ 2026-08-02T02:20:45Z

### [DONE] service-artifact-engine-link-20260802
- **Session**: `Codex-ServiceArtifactWiring-20260802`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/CMakeLists.txt,userland/native-apps/serviced/serviced.c,userland/native-apps/execd/execd.c,userland/native-apps/displayd/displayd.c`
- **Description**: Link serviced execd displayd production artifacts with their completed policy engines and park safely until authenticated userland endpoint ingress exists
- **Claimed**: 2026-08-02T02:19:45Z
- **Status**: COMPLETED @ 2026-08-02T02:47:02Z

### [DONE] virtio-net-restart-20260802
- **Session**: `Codex-VirtioNetRestart-20260802`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/drivers/virtio/virtio_net.cpp,kernel/drivers/virtio/virtio_net.h,tests/host/test_virtio_net_restart.cpp,tools/test/test-virtio-net-restart-contract.py`
- **Description**: Exact-generation virtio-net binding with operation pins worker retirement and fail-closed queue teardown
- **Claimed**: 2026-08-02T02:23:08Z
- **Status**: COMPLETED @ 2026-08-02T03:08:17Z

### [DONE] browser-smoke-ci-20260802
- **Session**: `Codex-BrowserSmokeCI-20260802`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `tools/test/test-browser-smoke-profile-contract.py,wiki/reference/Smoke-Test-Suite.md`
- **Description**: Wire existing browser smoke profile into runner and CI with exact runtime markers and correct docs
- **Claimed**: 2026-08-02T02:23:54Z
- **Status**: COMPLETED @ 2026-08-02T02:26:48Z

### [DONE] service-bootstrap-qemu-verdict-20260802
- **Session**: `Codex-ServiceBootstrapVerdict-20260802`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `tools/test/test-service-bootstrap-live-contract.py`
- **Description**: Make every QEMU profile require the live service package and runtime anchor
- **Claimed**: 2026-08-02T02:27:51Z
- **Status**: COMPLETED @ 2026-08-02T02:29:03Z

### [DONE] host-sanitizer-ci-20260802
- **Session**: `Codex-HostSanitizerCI-20260802`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `tests/fuzz/host_shim/sync/spinlock.h,tools/test/test-host-sanitizer-ci-contract.py`
- **Description**: Make
- **Claimed**: 2026-08-02T02:33:59Z
- **Status**: COMPLETED @ 2026-08-02T06:25:02Z

### [DONE] ntdll-vm-abi-20260802
- **Session**: `Codex-NtdllVmAbi-20260802`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `userland/libs/ntdll/ntdll.c,tools/test/test-ntdll-vm-abi-contract.py`
- **Description**: Correct
- **Claimed**: 2026-08-02T02:40:13Z
- **Status**: COMPLETED @ 2026-08-02T02:42:08Z

### [DONE] net-protocol-state-smp-20260802
- **Session**: `Nathan-848`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/net/stack.h,kernel/net/stack.cpp,tests/host/test_net_protocol_state_smp.cpp,tools/test/test-net-protocol-state-sync-contract.py,wiki/networking/Network-Stack.md`
- **Description**: IRQ-safe ARP UDP DNS NTP DHCP state with generation-revalidated snapshot commit and hostile hosted concurrency coverage
- **Claimed**: 2026-08-02T02:47:10Z
- **Status**: COMPLETED @ 2026-08-02T05:37:03Z

### [DONE] service-package-ci-20260802
- **Session**: `Codex-ServicePackageCI-20260802`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `tools/test/test-service-package-ci-contract.py`
- **Description**: Require
- **Claimed**: 2026-08-02T02:54:27Z
- **Status**: COMPLETED @ 2026-08-02T03:02:21Z

### [DONE] release-publisher-singleton-20260802
- **Session**: `Codex-ReleasePublisherSingleton-20260802`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `.github/workflows/release.yml,wiki/tooling/Build-System.md,wiki/getting-started/Architecture-Overview.md,wiki/reference/Design-Decisions.md,tools/test/test-release-publisher-singleton-contract.py`
- **Description**: Make build.yml the sole main-push rolling-release publisher while preserving tag and manual release entrypoints
- **Claimed**: 2026-08-02T03:13:05Z
- **Status**: COMPLETED @ 2026-08-02T03:22:29Z

### [DONE] service-endpoint-ingress-20260802
- **Session**: `Codex-ServiceEndpointIngress-20260802`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `abi/native_syscalls.json kernel/syscall/cap_table.def kernel/syscall/syscall_idl_generated.def userland/libc/include/duet/syscall_numbers_generated.h docs/native-syscall-policy.json docs/native-syscall-policy.md kernel/syscall/syscall.h kernel/syscall/syscall.cpp kernel/syscall/service_endpoint_ingress.h kernel/syscall/service_endpoint_ingress.cpp userland/libc/include/duet/service_endpoint.h userland/libc/src/syscall.c kernel/proc/process.cpp tests/host/test_service_endpoint_ingress.cpp tools/test/test-service-endpoint-ingress-contract.py`
- **Description**: Authenticated versioned native-userland ServiceEndpoint accept receive reply-ack and typed object-transfer ingress with process-bound receipts
- **Claimed**: 2026-08-02T03:15:30Z
- **Status**: COMPLETED @ 2026-08-02T05:35:59Z

### [DONE] parallel-claim-safety-20260802
- **Session**: `Codex-ParallelClaimSafety-20260802`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `tools/parallel/claim.sh,tools/parallel/status.sh,tools/parallel/release.sh,tools/parallel/claims_guard.py,tools/test/test-parallel-claim-safety.py,CLAUDE_PARALLEL.md`
- **Description**: Serialize coordinator mutation and fail closed on scope ambiguity sync and publication errors
- **Claimed**: 2026-08-02T03:24:07Z
- **Status**: COMPLETED @ 2026-08-02T03:55:01Z

### [DONE] service-endpoint-ingress-names-20260802
- **Session**: `Codex-ServiceEndpointIngress-20260802`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/syscall/syscall_names.def`
- **Description**: Register SYS_SERVICE_ENDPOINT_OP in the canonical generated syscall name table
- **Claimed**: 2026-08-02T03:36:09Z
- **Status**: COMPLETED @ 2026-08-02T06:50:30Z

### [DONE] root-clang-idl-gate-fixes-20260802
- **Session**: `Nathan-169`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `tests/host/test_load_image.cpp,tools/test/test-native-syscall-idl.py,tools/test/test-native-syscall-dispatch-bijection.py`
- **Description**: Repair Clang dead-helper gate and synchronize syscall 227 generated-count expectations
- **Claimed**: 2026-08-02T03:56:12Z
- **Status**: COMPLETED @ 2026-08-02T04:11:55Z

### [DONE] root-authorization-host-clang-gate-20260802
- **Session**: `Nathan-795`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `tests/host/test_authorization_context.cpp`
- **Description**: Initialize complete hostile authorization snapshot under Clang Werror
- **Claimed**: 2026-08-02T03:57:58Z
- **Status**: COMPLETED @ 2026-08-02T04:12:10Z

### [DONE] root-service-manifest-host-clang-gate-20260802
- **Session**: `Nathan-337`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `tests/host/test_service_manifest.cpp`
- **Description**: Remove dead manifest fixture offsets rejected by Clang Werror
- **Claimed**: 2026-08-02T04:00:19Z
- **Status**: COMPLETED @ 2026-08-02T04:12:22Z

### [DONE] root-arp-copyout-callers-20260802
- **Session**: `Nathan-175`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/net/socket.cpp`
- **Description**: Migrate legacy ARP pointer caller to lock-safe copy-out API
- **Claimed**: 2026-08-02T04:10:09Z
- **Status**: COMPLETED @ 2026-08-02T04:16:57Z

### [DONE] service-publication-directory-join-20260802
- **Session**: `Nathan-265`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/core/service_bootstrap_activation.h,kernel/core/service_bootstrap_activation.cpp,kernel/core/service_lifecycle_broker.h,kernel/core/service_lifecycle_broker.cpp,kernel/core/service_runtime.h,kernel/core/service_runtime.cpp,kernel/core/service_directory.h,kernel/core/service_directory.cpp,tests/host/test_service_bootstrap_activation.cpp,tests/host/test_service_publication_directory.cpp,tools/test/test-service-publication-directory-contract.py`
- **Description**: Atomically publish lifecycle exit observer and ServiceDirectory identity at first Task publication with exact rollback
- **Claimed**: 2026-08-02T04:14:16Z
- **Status**: COMPLETED @ 2026-08-02T06:13:19Z

### [DONE] root-arp-copyout-contract-join-20260802
- **Session**: `Nathan-998`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `tools/test/test-net-stack-restart-contract.py`
- **Description**: Update restart structural oracle for lock-safe ARP copy-out caller
- **Claimed**: 2026-08-02T04:15:11Z
- **Status**: COMPLETED @ 2026-08-02T04:17:18Z

### [DONE] parallel-workflow-doc-sync-20260802
- **Session**: `Nathan-1813`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `CLAUDE.md`
- **Description**: Synchronize project workflow docs with fail-closed coordinator and normal-push semantics
- **Claimed**: 2026-08-02T04:18:31Z
- **Status**: COMPLETED @ 2026-08-02T04:19:25Z

### [DONE] channel-core-deferred-drain-20260802
- **Session**: `Nathan-1834`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/ipc/channel_core.h,kernel/ipc/channel_core.cpp,tests/host/test_channel_core.cpp,tests/host/test_service_endpoint.cpp`
- **Description**: Defer
- **Claimed**: 2026-08-02T04:28:38Z
- **Status**: COMPLETED @ 2026-08-02T05:23:49Z

### [DONE] address-space-write-lease-20260802
- **Session**: `Nathan-918`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/mm/address_space.h,kernel/mm/address_space.cpp,tools/test/test-address-space-write-lease-contract.py`
- **Description**: Generation-safe bounded write lease that pins exact user mappings across irreversible syscall operations without holding VM locks
- **Claimed**: 2026-08-02T04:34:36Z
- **Status**: COMPLETED @ 2026-08-02T05:23:41Z

### [DONE] service-endpoint-drain-handoff-20260802
- **Session**: `Nathan-1618`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/core/service_endpoint.cpp`
- **Description**: Lost-wakeup-proof drain-driver retry handoff for last operation release
- **Claimed**: 2026-08-02T04:41:10Z
- **Status**: COMPLETED @ 2026-08-02T05:23:56Z

### [DONE] service-endpoint-drain-handoff-header-20260802
- **Session**: `Nathan-1083`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/core/service_endpoint.h`
- **Description**: Durable drain retry request bit for active-driver handoff
- **Claimed**: 2026-08-02T04:41:45Z
- **Status**: COMPLETED @ 2026-08-02T05:24:03Z

### [DONE] net-stack-boot-order-20260802
- **Session**: `Nathan-1089`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/core/boot_bringup.cpp,tools/test/test-net-stack-boot-order-contract.py`
- **Description**: Initialize
- **Claimed**: 2026-08-02T04:42:49Z
- **Status**: COMPLETED @ 2026-08-02T04:57:46Z

### [DONE] service-endpoint-handle-rights-20260802
- **Session**: `Nathan-933`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/ipc/handle_table.cpp,kernel/ipc/handle_table_selftest.cpp`
- **Description**: Remove generic Duplicate and Transfer rights from ServiceEndpoint handles and prove mint paths fail closed
- **Claimed**: 2026-08-02T04:53:17Z
- **Status**: COMPLETED @ 2026-08-02T05:06:16Z

### [DONE] net-protocol-state-smp-p0-20260802
- **Session**: `Nathan-596`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/net/firewall.h,kernel/net/firewall.cpp,kernel/net/ipv6.h,kernel/net/ipv6.cpp`
- **Description**: IRQ-safe
- **Claimed**: 2026-08-02T04:58:15Z
- **Status**: COMPLETED @ 2026-08-02T05:22:05Z

### [DONE] net-protocol-state-smp-fixtures-20260802
- **Session**: `Nathan-1403`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `tests/host/net_protocol_state_smp_frames.h`
- **Description**: Bounded
- **Claimed**: 2026-08-02T05:03:30Z
- **Status**: COMPLETED @ 2026-08-02T05:22:16Z

### [DONE] service-process-endpoint-teardown-20260802
- **Session**: `Nathan-265`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `tests/host/test_service_process_endpoint_teardown.cpp,tools/test/test-service-process-endpoint-teardown-contract.py`
- **Description**: ProcessKey-aware accepted ServiceEndpoint owner release before raw Process HandleTable drain with durable bounded Busy retry
- **Claimed**: 2026-08-02T05:04:26Z
- **Status**: COMPLETED @ 2026-08-02T06:12:50Z

### [DONE] root-service-endpoint-contract-drift-20260802
- **Session**: `Codex-Root-EndpointContract-20260802`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `tools/test/test-service-endpoint-contract.py`
- **Description**: Repair
- **Claimed**: 2026-08-02T05:38:22Z
- **Status**: COMPLETED @ 2026-08-02T05:39:49Z

### [DONE] service-stage-restage-20260802
- **Session**: `Nathan-1615`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/core/service_bootstrap_stage.h,kernel/core/service_bootstrap_stage.cpp,tests/host/test_service_bootstrap_stage.cpp,tools/test/test-service-bootstrap-stage-contract.py`
- **Description**: Restart
- **Claimed**: 2026-08-02T05:39:13Z
- **Status**: COMPLETED @ 2026-08-02T07:09:08Z

### [DONE] service-deferred-endpoint-reaper-20260802
- **Session**: `Nathan-826`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/proc/process.cpp,kernel/sched/sched.cpp`
- **Description**: Transfer
- **Claimed**: 2026-08-02T05:40:34Z
- **Status**: COMPLETED @ 2026-08-02T06:13:06Z

### [DONE] service-endpoint-route-authority-20260802
- **Session**: `Nathan-914`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/core/service_endpoint.h,kernel/core/service_endpoint.cpp,tests/host/test_service_endpoint.cpp,tests/host/test_service_directory.cpp,tools/test/test-service-endpoint-contract.py,tools/test/test-service-endpoint-request-lifecycle-contract.py`
- **Description**: Migrate fixed 48-byte protocol route authority and add exact role-safe received-request rejection
- **Claimed**: 2026-08-02T05:42:08Z
- **Status**: COMPLETED @ 2026-08-02T06:50:43Z

### [DONE] service-endpoint-connect-send-ingress-20260802
- **Session**: `Nathan-984`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/syscall/service_endpoint_ingress.cpp,userland/libc/include/duet/service_endpoint.h,tests/host/test_service_endpoint_ingress.cpp,tools/test/test-service-endpoint-ingress-contract.py`
- **Description**: Enforce exact protocol routes and add CONNECT and SEND_REQUEST operations with failure-atomic settlement
- **Claimed**: 2026-08-02T05:42:19Z
- **Status**: COMPLETED @ 2026-08-02T06:50:58Z

### [DONE] service-stage-load-image-reset-20260802
- **Session**: `Nathan-1080`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/loader/load_image.h,kernel/loader/load_image.cpp,tests/host/test_load_image.cpp`
- **Description**: Loader-owned
- **Claimed**: 2026-08-02T05:50:36Z
- **Status**: COMPLETED @ 2026-08-02T07:09:14Z

### [DONE] service-stage-exec-admission-reset-20260802
- **Session**: `Nathan-1368`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/loader/exec_admission.h,kernel/loader/exec_admission.cpp,tests/host/test_exec_admission.cpp`
- **Description**: Quiescent
- **Claimed**: 2026-08-02T05:53:41Z
- **Status**: COMPLETED @ 2026-08-02T07:09:21Z

### [DONE] service-protocol-policy-20260802
- **Session**: `Codex-ServiceEndpointDataplane-20260802`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/core/service_protocol_policy.h,kernel/core/service_protocol_policy.cpp,tests/host/test_service_protocol_policy.cpp,tools/test/test-service-protocol-policy-contract.py`
- **Description**: Add trusted manifest keyed route policy resolver with fail-closed capability intersection and authority mint tests
- **Claimed**: 2026-08-02T05:54:44Z
- **Status**: COMPLETED @ 2026-08-02T06:51:10Z

### [DONE] service-endpoint-connect-send-ingress-state-20260802
- **Session**: `Codex-ServiceEndpointDataplane-20260802`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/syscall/service_endpoint_ingress.h`
- **Description**: Add trusted resource-domain snapshot and durable connect rollback authority state
- **Claimed**: 2026-08-02T05:59:40Z
- **Status**: COMPLETED @ 2026-08-02T06:51:25Z

### [DONE] service-joint-readiness-20260802
- **Session**: `Nathan-1443`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/core/service_lifecycle_broker.h,kernel/core/service_lifecycle_broker.cpp,kernel/core/service_directory.h,kernel/core/service_directory.cpp,kernel/core/service_bootstrap_activation.h,kernel/core/service_bootstrap_activation.cpp,tests/host/test_service_bootstrap_activation.cpp,tests/host/test_service_publication_directory.cpp,tests/host/test_service_lifecycle_broker.cpp,tools/test/test-service-publication-directory-contract.py,tools/test/test-service-bootstrap-activation-contract.py`
- **Description**: Atomic broker-directory service readiness transaction with CONNECT admission gate and dependency truth
- **Claimed**: 2026-08-02T06:13:44Z
- **Status**: COMPLETED @ 2026-08-02T06:50:50Z

### [DONE] host-sanitizer-ci-finish-20260802
- **Session**: `Codex-HostSanitizerCIFinish-20260802`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `tests/fuzz/host_shim/sync/spinlock.h,tools/test/test-host-sanitizer-ci-contract.py`
- **Description**: Commit independently validated TSan-visible hosted spinlock and CI structural contract after stale-claim recovery
- **Claimed**: 2026-08-02T06:25:42Z
- **Status**: COMPLETED @ 2026-08-02T06:26:12Z

### [DONE] service-exit-reap-ledger-20260802
- **Session**: `Fable-ServiceExitReapLedger-20260802`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/core/service_exit_reap_ledger.h,kernel/core/service_exit_reap_ledger.cpp,tests/host/test_service_exit_reap_ledger.cpp,tools/test/test-service-exit-reap-ledger-contract.py`
- **Description**: Fixed-capacity allocation-free exit reap ledger between exit observer, lifecycle broker ObserveExit, directory OwnerCrashed, and later SYS_SERVICE_CONTROL delivery/ACK plane
- **Claimed**: 2026-08-02T06:27:41Z
- **Status**: COMPLETED @ 2026-08-02T08:47:42Z

### [DONE] displayd-dormant-contract-drift-20260802
- **Session**: `Codex-DisplaydContractDrift-20260802`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `tools/test/test-displayd-engine-contract.py`
- **Description**: Repair stale dormant displayd entrypoint assertion after artifact engine link while preserving authenticated-ingress boundary
- **Claimed**: 2026-08-02T06:32:10Z
- **Status**: COMPLETED @ 2026-08-02T06:32:49Z

### [DONE] service-object-package-lifecycle-link-20260802
- **Session**: `Codex-ServiceObjectPackageLink-20260802`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `tests/host/test_service_object_package.cpp`
- **Description**: Provide exact hosted directory stubs required by lifecycle broker linkage in the focused service object package target
- **Claimed**: 2026-08-02T06:36:13Z
- **Status**: COMPLETED @ 2026-08-02T06:39:43Z

### [DONE] service-object-package-joint-ready-stub-20260802
- **Session**: `Codex-ServiceObjectPackageJointReady-20260802`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `tests/host/test_service_object_package.cpp`
- **Description**: Update focused lifecycle host stub to final race-free ServiceDirectoryCommitJointReady signature
- **Claimed**: 2026-08-02T06:42:59Z
- **Status**: COMPLETED @ 2026-08-02T06:43:49Z

### [DONE] service-process-teardown-readiness-drift-20260802
- **Session**: `Codex-ProcessTeardownReadiness-20260802`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `tests/host/test_service_process_endpoint_teardown.cpp`
- **Description**: Update completed ProcessKey endpoint teardown fixture for explicit joint directory readiness before Connect
- **Claimed**: 2026-08-02T06:49:18Z
- **Status**: COMPLETED @ 2026-08-02T06:50:16Z

### [DONE] service-bootstrap-live-ready-oracle-20260802
- **Session**: `Codex-BootstrapLiveReadyOracle-20260802`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `tools/test/test-service-bootstrap-live-contract.py`
- **Description**: Track final public and internal joint-readiness symbols in the dormant live-bootstrap forbidden-call oracle
- **Claimed**: 2026-08-02T06:50:38Z
- **Status**: COMPLETED @ 2026-08-02T06:51:06Z

### [DONE] service-live-restage-banks-20260802
- **Session**: `Codex-ServiceLiveRestageBanks-20260802`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/core/service_bootstrap_live.h,kernel/core/service_bootstrap_live.cpp,tools/test/test-service-bootstrap-live-contract.py,tests/host/test_service_bootstrap_live.cpp`
- **Description**: Provision restart-safe fixed two-bank live service staging owner with failure-atomic inactive-bank restage seam and hostile hosted coverage
- **Claimed**: 2026-08-02T06:52:53Z
- **Status**: COMPLETED @ 2026-08-02T07:23:22Z

### [DONE] service-control-syscall-20260802
- **Session**: `Codex-ServiceControlSyscall-20260802`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `abi/native_syscalls.json,kernel/syscall/cap_table.def,kernel/syscall/syscall_idl_generated.def,kernel/syscall/syscall_names.def,userland/libc/include/duet/syscall_numbers_generated.h,docs/native-syscall-policy.json,docs/native-syscall-policy.md,kernel/syscall/syscall.h,kernel/syscall/syscall.cpp,userland/libc/src/syscall.c,userland/libc/include/duet/service_control.h,kernel/syscall/service_control_ingress.h,kernel/syscall/service_control_ingress.cpp,kernel/proc/process.h,tests/host/test_service_control_ingress.cpp,tools/test/test-service-control-ingress-contract.py`
- **Description**: Dedicated versioned native service-control ABI 228 with exact self and supervisor authority and typed platform adapters
- **Claimed**: 2026-08-02T06:55:57Z
- **Status**: COMPLETED @ 2026-08-02T07:53:25Z

### [DONE] service-control-cap-name-20260802
- **Session**: `Codex-ServiceControlSyscall-20260802`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/proc/process.cpp`
- **Description**: Register the dedicated service-control capability name and self-test without widening service manifest v1
- **Claimed**: 2026-08-02T07:00:37Z
- **Status**: COMPLETED @ 2026-08-02T07:53:32Z

### [DONE] fuzz-pe-vm-reservation-shim-20260802
- **Session**: `Codex-Root-FuzzPeVmShim-20260802`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `tests/fuzz/host_shim/pe_stubs.cpp`
- **Description**: Keep PE fuzz host shim synchronized with reservation-backed loader VM API
- **Claimed**: 2026-08-02T07:01:40Z
- **Status**: COMPLETED @ 2026-08-02T07:04:13Z

### [DONE] service-manifest-format-integration-20260802
- **Session**: `Codex-Root-FormatManifest-20260802`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/core/service_manifest.cpp,kernel/core/service_manifest.h`
- **Description**: Integrate duplicate transfer identity contract and satisfy branch clang-format gate
- **Claimed**: 2026-08-02T07:06:33Z
- **Status**: COMPLETED @ 2026-08-02T07:08:26Z

### [DONE] ipc-object-transfer-integration-20260802
- **Session**: `Nathan-139`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/ipc/object_transfer.h,kernel/ipc/object_transfer.cpp,tests/host/test_object_transfer.cpp`
- **Description**: Audit
- **Claimed**: 2026-08-02T07:13:12Z
- **Status**: COMPLETED @ 2026-08-02T07:36:17Z

### [DONE] registryd-store-integration-20260802
- **Session**: `Nathan-1336`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `userland/native-apps/registryd/registry_store.h,userland/native-apps/registryd/registry_store.c,userland/native-apps/registryd/registry_persistence.c,tests/host/test_registryd_store.cpp,tools/test/test-registryd-store-contract.py`
- **Description**: Audit and finish uncommitted registryd store slice (bounded, WAL replay hardening)
- **Claimed**: 2026-08-02T07:15:37Z
- **Status**: COMPLETED @ 2026-08-02T08:07:22Z

### [DONE] service-control-idl-counts-20260802
- **Session**: `Codex-ServiceControlSyscall-20260802`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `tools/test/test-native-syscall-idl.py,tools/test/test-native-syscall-dispatch-bijection.py`
- **Description**: Advance native syscall IDL and dispatch bijection cardinality for dedicated SYS_SERVICE_CONTROL 228
- **Claimed**: 2026-08-02T07:20:25Z
- **Status**: COMPLETED @ 2026-08-02T07:53:38Z

### [DONE] service-control-manifest-policy-20260802
- **Session**: `Codex-ServiceControlSyscall-20260802`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/core/service_manifest.h,kernel/core/service_manifest.cpp,config/services.toml,config/service-authority.toml,tools/build/gen-service-manifest.py,tools/test/test-gen-service-manifest.py,kernel/core/boot_service_manifest_data.h`
- **Description**: Deliberately extend ServiceManifest v1 capability policy for kCapServiceControl and grant it only to serviced
- **Claimed**: 2026-08-02T07:23:59Z
- **Status**: COMPLETED @ 2026-08-02T07:53:44Z

### [DONE] resource-domain-integration-20260802
- **Session**: `Nathan-1326`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/proc/resource_domain.h,kernel/proc/resource_domain.cpp,tests/host/test_resource_domain.cpp`
- **Description**: Audit and integrate generation-safe resource-domain lifetime and exact Section frame charging
- **Claimed**: 2026-08-02T07:25:50Z
- **Status**: COMPLETED @ 2026-08-02T07:37:02Z

### [DONE] service-foundation-dependency-integration-20260802
- **Session**: `Nathan-234`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/core/service_exit_observer.h,kernel/core/service_exit_observer.cpp,tests/host/test_service_exit_observer.cpp,tools/test/test-service-exit-observer-contract.py,kernel/core/service_object_package.h,kernel/core/service_object_package.cpp,tests/host/test_service_object_package.cpp,kernel/core/service_runtime.h,kernel/core/service_runtime.cpp,tools/test/test-service-runtime-owner-contract.py,kernel/CMakeLists.txt,tests/host/CMakeLists.txt`
- **Description**: Publish service exit observer object package runtime owner and exact production and hosted build graph
- **Claimed**: 2026-08-02T08:04:40Z
- **Status**: COMPLETED @ 2026-08-02T08:21:59Z

### [DONE] process-authority-foundation-integration-20260802
- **Session**: `Nathan-18`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/proc/credentials.h,kernel/proc/credentials.cpp,kernel/proc/authorization_context.h,kernel/proc/authorization_context.cpp,tests/host/test_credentials.cpp,tests/host/test_authorization_context.cpp`
- **Description**: Audit and finish uncommitted generation-safe Credentials and AuthorizationContext foundations: immutable snapshots, nonwrapping generations, replay watermark, hostile/concurrent tests
- **Claimed**: 2026-08-02T08:10:12Z
- **Status**: COMPLETED @ 2026-08-02T08:48:47Z

### [ACTIVE] service-exit-reap-ledger-fix-20260802
- **Session**: `Codex-ServiceExitReapFix-20260802`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/core/service_exit_reap_ledger.h,kernel/core/service_exit_reap_ledger.cpp,tests/host/test_service_exit_reap_ledger.cpp,tools/test/test-service-exit-reap-ledger-contract.py`
- **Description**: Repair
- **Claimed**: 2026-08-02T08:48:00Z
- **Status**: IN PROGRESS

### [DONE] ipc-foundation-publish-20260802
- **Session**: `Codex-IPCFoundationPublish-20260802`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/ipc/channel_core.h,kernel/ipc/channel_core.cpp,tests/host/test_channel_core.cpp,kernel/ipc/message_ring.h,kernel/ipc/message_ring.cpp,tests/host/test_message_ring.cpp,kernel/ipc/versioned_payload.h,kernel/ipc/versioned_payload.cpp,tests/host/test_versioned_payload.cpp`
- **Description**: Audit and publish released IPC channel message ring and versioned payload foundation closure
- **Claimed**: 2026-08-02T08:50:35Z
- **Status**: COMPLETED @ 2026-08-02T08:58:57Z

### [DONE] process-authority-foundation-publish-20260802
- **Session**: `Codex-ProcessAuthorityPublish-20260802`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/proc/credentials.h,kernel/proc/credentials.cpp,kernel/proc/authorization_context.h,kernel/proc/authorization_context.cpp,tests/host/test_credentials.cpp,tests/host/test_authorization_context.cpp`
- **Description**: Audit, harden, independently verify, and publish the released process authority foundation
- **Claimed**: 2026-08-02T08:51:11Z
- **Status**: COMPLETED @ 2026-08-02T08:56:45Z

### [DONE] daemon-source-publish-20260802
- **Session**: `Codex-DaemonSourcePublish-20260802`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `userland/native-apps/displayd/display_engine.c,userland/native-apps/displayd/display_engine.h,userland/native-apps/displayd/display_engine_event.c,userland/native-apps/displayd/display_engine_internal.h,userland/native-apps/displayd/display_engine_request.c,userland/native-apps/displayd/display_engine_validate.c,userland/native-apps/displayd/displayd.c,userland/native-apps/execd/execd.c,userland/native-apps/execd/worker.c,userland/native-apps/execd/worker.h,userland/native-apps/execd/worker_internal.h,userland/native-apps/execd/worker_request.c,userland/native-apps/registryd/registry_recovery.c,userland/native-apps/registryd/registry_store_internal.h,userland/native-apps/registryd/registry_validate.c,userland/native-apps/registryd/registryd.c,userland/native-apps/serviced/serviced.c,userland/native-apps/serviced/supervisor.c,userland/native-apps/serviced/supervisor.h,userland/native-apps/serviced/supervisor_command.c,userland/native-apps/serviced/supervisor_event.c,userland/native-apps/serviced/supervisor_internal.h,userland/native-apps/serviced/supervisor_policy.c,userland/native-apps/serviced/supervisor_reconcile.c,tests/host/test_displayd_engine.cpp,tests/host/test_execd_worker.cpp,tests/host/test_serviced_supervisor.cpp,tools/test/test-execd-worker-contract.py,tools/test/test-serviced-supervisor-contract.py`
- **Description**: Publish
- **Claimed**: 2026-08-02T08:51:13Z
- **Status**: COMPLETED @ 2026-08-02T09:01:41Z

### [DONE] service-control-platform-adapter-20260802
- **Session**: `Codex-ServiceControlPlatform-20260802`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/core/service_control_platform.h,kernel/core/service_control_platform.cpp,tests/host/test_service_control_platform.cpp,tools/test/test-service-control-platform-contract.py`
- **Description**: Typed service-control platform adapter over live activation/lifecycle/restage/exact reap ledger
- **Claimed**: 2026-08-02T09:00:48Z
- **Status**: COMPLETED @ 2026-08-02T09:35:44Z

### [DONE] elf-load-image-publish-20260802
- **Session**: `Codex-ELFLoadImagePublish-20260802`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/loader/elf_load_image.h,kernel/loader/elf_load_image.cpp,tests/host/test_elf_load_image.cpp,tools/test/test-service-elf-load-image-contract.py`
- **Description**: Audit and publish hostile-input-safe immutable ELF load-image closure
- **Claimed**: 2026-08-02T09:01:11Z
- **Status**: COMPLETED @ 2026-08-02T09:11:29Z

### [DONE] service-control-event-sequence-abi-20260802
- **Session**: `Codex-ServiceControlPlatform-20260802`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `userland/libc/include/duet/service_control.h,kernel/syscall/service_control_ingress.h,kernel/syscall/service_control_ingress.cpp,tests/host/test_service_control_ingress.cpp,tools/test/test-service-control-ingress-contract.py`
- **Description**: Separate exact exit event sequence from public acknowledgement token while preserving service-control v1 ABI size
- **Claimed**: 2026-08-02T09:12:14Z
- **Status**: COMPLETED @ 2026-08-02T09:35:37Z

### [DONE] immutable-load-plan-recovery-20260802
- **Session**: `Codex-ImmutableLoadPlan-Recovery-20260802`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/loader/load_plan.h`
- **Description**: No description provided
- **Claimed**: 2026-08-02T09:44:58Z
- **Status**: COMPLETED @ 2026-08-02T09:45:30Z

### [DONE] immutable-load-plan-recovery-20260802b
- **Session**: `Codex-ImmutableLoadPlan-Recovery-20260802`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/loader/load_plan.h,kernel/loader/load_plan.cpp,tests/host/test_load_plan.cpp`
- **Description**: Audit and publish immutable hostile-input load-plan authority
- **Claimed**: 2026-08-02T09:45:41Z
- **Status**: COMPLETED @ 2026-08-02T09:54:11Z

### [ACTIVE] proc-thread-group-closure-20260802
- **Session**: `Codex-ThreadGroupClosure-20260802`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/proc/thread_group.h,kernel/proc/thread_group.cpp,tests/host/test_thread_group.cpp,tools/test/test-thread-group-contract.py`
- **Description**: Audit
- **Claimed**: 2026-08-02T09:47:59Z
- **Status**: IN PROGRESS
