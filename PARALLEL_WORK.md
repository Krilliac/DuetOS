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

### [ACTIVE] immutable-load-plan
- **Session**: `Codex-kobject-handle-v2`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/loader/load_plan.h kernel/loader/load_plan.cpp tests/host/test_load_plan.cpp`
- **Description**: Versioned immutable executable load plan with allocation-free hostile-input validation
- **Claimed**: 2026-07-31T19:40:18Z
- **Status**: IN PROGRESS

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

### [ACTIVE] socket-alloc-transaction
- **Session**: `Nathan-1456`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/net/socket.cpp`
- **Description**: Atomic socket slot reservation across BSP preemption and SMP allocation races
- **Claimed**: 2026-07-31T20:08:21Z
- **Status**: IN PROGRESS

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

### [ACTIVE] load-image-staging
- **Session**: `Nathan-1074`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/loader/load_image.h kernel/loader/load_image.cpp tests/host/test_load_image.cpp`
- **Description**: Loader-private staging package with sealed LoadPlan backing and transactional ownership map
- **Claimed**: 2026-07-31T20:19:16Z
- **Status**: IN PROGRESS

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

### [ACTIVE] exec-admission
- **Session**: `Codex-exec-admission`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/loader/exec_admission.h kernel/loader/exec_admission.cpp tests/host/test_exec_admission.cpp`
- **Description**: Allocation-free frozen executable-plan admission seam with exact prepare consume cancel identity
- **Claimed**: 2026-07-31T21:15:59Z
- **Status**: IN PROGRESS

### [ACTIVE] host-msvc-kernel32-nls-test
- **Session**: `Nathan-1841`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `tests/host/test_kernel32_nls.cpp`
- **Description**: Map
- **Claimed**: 2026-07-31T21:17:07Z
- **Status**: IN PROGRESS

### [ACTIVE] proc-credentials-api
- **Session**: `Nathan-1200`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/proc/credentials.h`
- **Description**: Immutable
- **Claimed**: 2026-07-31T21:21:30Z
- **Status**: IN PROGRESS

### [ACTIVE] proc-credentials-core
- **Session**: `Nathan-418`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/proc/credentials.cpp`
- **Description**: Fixed-pool
- **Claimed**: 2026-07-31T21:21:31Z
- **Status**: IN PROGRESS

### [ACTIVE] proc-credentials-host
- **Session**: `Nathan-383`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `tests/host/test_credentials.cpp`
- **Description**: Credential
- **Claimed**: 2026-07-31T21:21:32Z
- **Status**: IN PROGRESS

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

### [ACTIVE] proc-thread-group-api
- **Session**: `Nathan-963`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/proc/thread_group.h`
- **Description**: Opaque
- **Claimed**: 2026-07-31T21:41:56Z
- **Status**: IN PROGRESS

### [ACTIVE] proc-thread-group-core
- **Session**: `Nathan-2031`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/proc/thread_group.cpp`
- **Description**: Allocation-free
- **Claimed**: 2026-07-31T21:42:01Z
- **Status**: IN PROGRESS

### [ACTIVE] proc-thread-group-host
- **Session**: `Nathan-535`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `tests/host/test_thread_group.cpp`
- **Description**: ThreadGroup
- **Claimed**: 2026-07-31T21:42:06Z
- **Status**: IN PROGRESS

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

### [ACTIVE] ipc-object-transfer
- **Session**: `Nathan-1481`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/ipc/object_transfer.h`
- **Description**: Endpoint-owned
- **Claimed**: 2026-07-31T22:01:39Z
- **Status**: IN PROGRESS

### [ACTIVE] ipc-object-transfer-source
- **Session**: `Nathan-840`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/ipc/object_transfer.cpp`
- **Description**: Object
- **Claimed**: 2026-07-31T22:01:49Z
- **Status**: IN PROGRESS

### [ACTIVE] ipc-object-transfer-test
- **Session**: `Nathan-1467`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `tests/host/test_object_transfer.cpp`
- **Description**: Hostile
- **Claimed**: 2026-07-31T22:01:58Z
- **Status**: IN PROGRESS

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

### [ACTIVE] native-syscall-policy-json
- **Session**: `Nathan-663`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `tools/build/gen-native-syscall-abi.py tools/test/test-native-syscall-idl.py docs/native-syscall-policy.json`
- **Description**: Generate canonical machine-readable native syscall policy JSON with deterministic drift coverage
- **Claimed**: 2026-07-31T23:06:45Z
- **Status**: IN PROGRESS

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

### [ACTIVE] rust-ffi-bounded-signature-walk
- **Session**: `Codex-rust-ffi-scan`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `tools/test/check-rust-ffi-signatures.py tools/test/test-rust-ffi-signatures.py`
- **Description**: Single-pass bounded prunable Rust FFI signature inventory and hostile traversal tests
- **Claimed**: 2026-08-01T00:36:35Z
- **Status**: IN PROGRESS

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

### [ACTIVE] proc-resource-channel-charge-20260801
- **Session**: `Codex-resource-channel-charge-20260801`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/proc/resource_domain.h kernel/proc/resource_domain.cpp tests/host/test_resource_domain_channel.cpp`
- **Description**: Generation-safe ResourceDomain channel charge authority
- **Claimed**: 2026-08-01T03:02:15Z
- **Status**: IN PROGRESS

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

### [DONE] authorization-context-audit-20260801
- **Session**: `Nathan-1525`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/proc/authorization_context.h`
- **Description**: No description provided
- **Claimed**: 2026-08-01T04:45:20Z
- **Status**: COMPLETED @ 2026-08-01T04:46:05Z

### [DONE] authorization-context-audit-20260801
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

### [ACTIVE] task-receipt-loadtest-20260801
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

### [ACTIVE] boot-manifest-package-20260801
- **Session**: `Codex-boot-manifest-package`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `config/services.toml tools/build/gen-service-manifest.py kernel/core/boot_service_manifest_data.h tools/test/test-gen-service-manifest.py`
- **Description**: Deterministic staged ServiceManifest v1 package and hostile generator tests without boot activation
- **Claimed**: 2026-08-01T11:16:39Z
- **Status**: IN PROGRESS

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

### [DONE] linux-fd-io-migration
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

### [ACTIVE] fable-targeted-contract-ci-20260801
- **Session**: `Codex-root-ci-contracts`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `.github/workflows/build.yml`
- **Description**: Register integrated Fable-targeted hostile structural contracts in authoritative CI
- **Claimed**: 2026-08-01T14:26:06Z
- **Status**: IN PROGRESS

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

### [ACTIVE] cancellation-unwind-safety-20260801
- **Session**: `Nathan-138`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/sched/sched.h,kernel/sched/sched.cpp,kernel/ipc/kmutex.h,kernel/ipc/kmutex.cpp,tools/test/test-task-cancellation-contract.py,tools/test/test-cancellable-wait-contract.py,tools/test/test-kmutex-cancellation-contract.py,wiki/kernel/Scheduler.md,wiki/kernel/Synchronization.md`
- **Description**: Close
- **Claimed**: 2026-08-01T16:03:16Z
- **Status**: IN PROGRESS

### [ACTIVE] rust-ingress-hardening-20260801
- **Session**: `Nathan-1547`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `cmake/DuetOSRust.cmake,kernel/rust/CMakeLists.txt,tools/test/check-rust-ffi.py,tools/test/check-rust-ffi-signatures.py,tools/test/test-rust-ffi-signatures.py,kernel/fs/duetfs/src/ffi.rs,kernel/fs/duetfs/src/crypto.rs,kernel/fs/duetfs/src/compress.rs,kernel/fs/duetfs/include/duetfs.h,tools/test/test-rust-ingress-hardening-contract.py`
- **Description**: Audit
- **Claimed**: 2026-08-01T16:05:47Z
- **Status**: IN PROGRESS

### [ACTIVE] rust-ingress-allocator-20260801
- **Session**: `Nathan-623`
- **Branch**: `claude/audit-ps2-spsc-20260731`
- **Files**: `kernel/fs/duetfs/src/kheap_alloc.rs,kernel/fs/duetfs/src/lib.rs`
- **Description**: Harden
- **Claimed**: 2026-08-01T16:07:36Z
- **Status**: IN PROGRESS
