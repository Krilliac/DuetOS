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
- **Status**: COMPLETED @ 2026-09-20T11:12:20Z

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

### [DONE] pe32-named-resources
- **Session**: `Nathan-3364`
- **Branch**: `claude/pe32-named-resources-20260813`
- **Files**: `userland/libs/user32_32/user32_32_misc.c`
- **Description**: No description provided
- **Claimed**: 2026-08-13T13:59:54Z
- **Status**: COMPLETED @ 2026-08-13T14:03:08Z

### [ACTIVE] codex-duetos-campaign
- **Session**: `Codex-DuetOS-Campaign-20260920`
- **Branch**: `codex/campaign-integration-20260920`
- **Files**: `.github/workflows/build.yml,CLAUDE.md,CLAUDE_PARALLEL.md,tools/parallel/*,kernel/drivers/video/*,kernel/drivers/net/*,kernel/net/drsh/*,kernel/CMakeLists.txt,tests/host/*,tools/qemu/run.sh,tools/test/*,tools/security/*,tools/image/*,wiki/_Sidebar.md,wiki/subsystems/UI-Toolkit.md,wiki/networking/DRSH-Remote-Access.md,wiki/drivers/*,wiki/reference/*,wiki/tooling/*,docs/plans/*`
- **Description**: Integrate audited UI QEMU PE DRSH removable-media and RTL8125 campaign work
- **Claimed**: 2026-09-20T11:14:23Z
- **Status**: IN PROGRESS

### [DONE] codex-duetos-storage-doc-drift
- **Session**: `Codex-DuetOS-Campaign-20260920`
- **Branch**: `codex/campaign-integration-20260920`
- **Files**: `kernel/drivers/storage/nvme.cpp`
- **Description**: Synchronize crash-dump safety documentation with fail-closed storage code
- **Claimed**: 2026-09-20T11:37:18Z
- **Status**: COMPLETED @ 2026-09-20T14:42:40Z

### [DONE] codex-duetos-static-network
- **Session**: `Codex-DuetOS-Campaign-20260920`
- **Branch**: `codex/campaign-integration-20260920`
- **Files**: `kernel/net/stack.cpp,kernel/net/stack.h,kernel/net/static_ipv4_config.h,kernel/net/ipv4_parse.h,kernel/core/boot_bringup.cpp,kernel/shell/shell_network.cpp`
- **Description**: Add generic boot-configured static IPv4 state for isolated bare-metal control
- **Claimed**: 2026-09-20T12:26:34Z
- **Status**: COMPLETED @ 2026-09-20T14:41:35Z

### [DONE] codex-duetos-static-network-consumers
- **Session**: `Codex-DuetOS-Campaign-20260920`
- **Branch**: `codex/campaign-integration-20260920`
- **Files**: `kernel/apps/browser.cpp,kernel/syscall/syscall.cpp`
- **Description**: Make browser DNS and socket network-info consume static IPv4 state
- **Claimed**: 2026-09-20T12:45:44Z
- **Status**: COMPLETED @ 2026-09-20T14:41:41Z

### [DONE] codex-duetos-static-network-abi
- **Session**: `Codex-DuetOS-Campaign-20260920`
- **Branch**: `codex/campaign-integration-20260920`
- **Files**: `kernel/syscall/syscall.h,userland/libs/iphlpapi/iphlpapi.c`
- **Description**: Expose active static or DHCP IPv4 configuration through the existing network-info ABI
- **Claimed**: 2026-09-20T12:46:53Z
- **Status**: COMPLETED @ 2026-09-20T14:41:46Z

### [DONE] codex-duetos-static-network-surfaces
- **Session**: `Codex-DuetOS-Campaign-20260920`
- **Branch**: `codex/campaign-integration-20260920`
- **Files**: `kernel/shell/shell_wget.cpp,kernel/apps/settings_datetime.cpp,kernel/apps/netstatus.cpp`
- **Description**: Route remaining DNS NTP wget and status surfaces through active IPv4 configuration
- **Claimed**: 2026-09-20T13:08:28Z
- **Status**: COMPLETED @ 2026-09-20T14:41:50Z

### [DONE] codex-duetos-static-socket-routing
- **Session**: `Codex-DuetOS-Campaign-20260920`
- **Branch**: `codex/campaign-integration-20260920`
- **Files**: `kernel/net/socket.cpp`
- **Description**: Select the active static or DHCP interface for TCP and UDP sockets
- **Claimed**: 2026-09-20T13:13:47Z
- **Status**: COMPLETED @ 2026-09-20T14:41:54Z

### [DONE] codex-duetos-static-routing-l2
- **Session**: `DESKTOP-950K3EI-233`
- **Branch**: `codex/campaign-integration-20260920`
- **Files**: `kernel/net/tcp.cpp,kernel/net/net_smoke.cpp`
- **Description**: Resolve TCP and forced smoke traffic through configured static IPv4 routes
- **Claimed**: 2026-09-20T13:47:08Z
- **Status**: COMPLETED @ 2026-09-20T14:41:58Z

### [DONE] codex-duetos-static-routing-l2-api
- **Session**: `DESKTOP-950K3EI-1030`
- **Branch**: `codex/campaign-integration-20260920`
- **Files**: `kernel/net/net_smoke.h`
- **Description**: Synchronize the live network smoke API contract with static or DHCP routes
- **Claimed**: 2026-09-20T13:51:58Z
- **Status**: COMPLETED @ 2026-09-20T14:42:02Z

### [DONE] codex-duetos-wiki-autosync
- **Session**: `DESKTOP-950K3EI-549`
- **Branch**: `codex/campaign-integration-20260920`
- **Files**: `wiki/Home.md,wiki/subsystems/Win32-DLLs.md,wiki/specifications/Syscall-ABI.md`
- **Description**: Refresh generated wiki inventories after the integrated networking slice
- **Claimed**: 2026-09-20T13:58:55Z
- **Status**: COMPLETED @ 2026-09-20T14:42:09Z

### [DONE] codex-duetos-syscall-doc-sync
- **Session**: `DESKTOP-950K3EI-1055`
- **Branch**: `codex/campaign-integration-20260920`
- **Files**: `docs/sync-wiki.sh,tools/build/gen-syscall-doc.py`
- **Description**: Preserve curated syscall ABI cells while adding newly generated rows
- **Claimed**: 2026-09-20T14:07:17Z
- **Status**: COMPLETED @ 2026-09-20T14:42:13Z

### [DONE] codex-duetos-ole32-warning
- **Session**: `DESKTOP-950K3EI-1123`
- **Branch**: `codex/campaign-integration-20260920`
- **Files**: `userland/libs/ole32/ole32.c`
- **Description**: Remove dead duplicate CLSID constants surfaced by the clean Node-test build
- **Claimed**: 2026-09-20T14:21:38Z
- **Status**: COMPLETED @ 2026-09-20T14:42:18Z

### [DONE] codex-duetos-storage-safety
- **Session**: `DESKTOP-950K3EI-902`
- **Branch**: `codex/campaign-integration-20260920`
- **Files**: `kernel/fs/installer.cpp,kernel/fs/mount.cpp,kernel/fs/fat32_write.cpp,kernel/fs/fat32_selftest.cpp,wiki/filesystem/FAT32.md,wiki/filesystem/Mount-Registry.md`
- **Description**: Fix FAT32 mount identity and fail-closed write arithmetic before metadata mutation
- **Claimed**: 2026-09-20T15:15:27Z
- **Status**: COMPLETED @ 2026-09-20T15:55:16Z

### [DONE] codex-duetos-storage-bounds-header
- **Session**: `DESKTOP-950K3EI-1373`
- **Branch**: `codex/campaign-integration-20260920`
- **Files**: `kernel/fs/fat32_write_bounds.h`
- **Description**: Add checked FAT32 write-range helper used by production and hosted tests
- **Claimed**: 2026-09-20T15:17:13Z
- **Status**: COMPLETED @ 2026-09-20T15:55:31Z

### [DONE] codex-duetos-storage-doc-sync
- **Session**: `DESKTOP-950K3EI-757`
- **Branch**: `codex/campaign-integration-20260920`
- **Files**: `wiki/filesystem/VFS.md,wiki/security/Hardware-Safety.md`
- **Description**: Synchronize VFS and hardware-safety docs with bounded FAT32 growth semantics
- **Claimed**: 2026-09-20T15:53:43Z
- **Status**: COMPLETED @ 2026-09-20T15:55:39Z

### [DONE] codex-duetos-runtime-dll-iat
- **Session**: `DESKTOP-950K3EI-558`
- **Branch**: `codex/campaign-integration-20260920`
- **Files**: `kernel/syscall/syscall.cpp,kernel/proc/spawn.cpp,userland/libs/runtime_import/*,tools/build/build-runtime-import-dll.sh,userland/apps/module_smoke/module_smoke.c,wiki/subsystems/PE-Loader.md`
- **Description**: Bind runtime-loaded DLL imports before publication and prove an imported export
- **Claimed**: 2026-09-20T15:59:15Z
- **Status**: COMPLETED @ 2026-09-20T17:07:18Z

### [DONE] codex-duetos-runtime-dll-fixture
- **Session**: `DESKTOP-950K3EI-534`
- **Branch**: `codex/campaign-integration-20260920`
- **Files**: `userland/libs/customdll2/customdll2.c,tools/build/build-customdll2.sh`
- **Description**: Make runtime LoadLibrary fixture import kernel32 and expose a verdict export
- **Claimed**: 2026-09-20T16:00:29Z
- **Status**: COMPLETED @ 2026-09-20T17:07:27Z

### [DONE] codex-duetos-runtime-dll-loader-api
- **Session**: `DESKTOP-950K3EI-187`
- **Branch**: `codex/campaign-integration-20260920`
- **Files**: `kernel/loader/pe_loader.cpp,kernel/loader/pe_loader.h`
- **Description**: Pass the actual mapped base into runtime import binding so ASLR-loaded DLLs patch their own IAT correctly
- **Claimed**: 2026-09-20T16:31:37Z
- **Status**: COMPLETED @ 2026-09-20T17:07:33Z

### [DONE] codex-duetos-runtime-dll-sxs-api
- **Session**: `DESKTOP-950K3EI-1192`
- **Branch**: `codex/campaign-integration-20260920`
- **Files**: `kernel/loader/sxs_dll.cpp`
- **Description**: Pass the actual mapped base through the side-by-side DLL import resolver call
- **Claimed**: 2026-09-20T16:35:25Z
- **Status**: COMPLETED @ 2026-09-20T17:07:38Z

### [DONE] codex-duetos-telemetry-selftest-stability
- **Session**: `DESKTOP-950K3EI-1681`
- **Branch**: `codex/campaign-integration-20260920`
- **Files**: `kernel/diag/telemetry.cpp`
- **Description**: Make the CPU usage short-window self-test deterministic under slow or contended VMs
- **Claimed**: 2026-09-20T16:43:44Z
- **Status**: COMPLETED @ 2026-09-20T17:07:42Z

### [DONE] codex-duetos-session-safe-save
- **Session**: `DESKTOP-950K3EI-898`
- **Branch**: `codex/campaign-integration-20260920`
- **Files**: `kernel/core/session_restore.cpp,kernel/core/session_restore.h`
- **Description**: Preserve the last good session config when staging or replacement fails
- **Claimed**: 2026-09-20T17:12:58Z
- **Status**: COMPLETED @ 2026-09-20T17:51:48Z

### [DONE] codex-duetos-fat32-safe-replace
- **Session**: `DESKTOP-950K3EI-180`
- **Branch**: `codex/campaign-integration-20260920`
- **Files**: `kernel/fs/fat32_create.cpp,kernel/fs/fat32.h,kernel/fs/fat32_selftest.cpp`
- **Description**: Add verified stage-first FAT32 replacement with recovery-file semantics
- **Claimed**: 2026-09-20T17:13:03Z
- **Status**: COMPLETED @ 2026-09-20T17:51:52Z

### [DONE] codex-duetos-session-safe-save-docs
- **Session**: `DESKTOP-950K3EI-1814`
- **Branch**: `codex/campaign-integration-20260920`
- **Files**: `wiki/filesystem/FAT32.md`
- **Description**: Document verified stage-first replacement and SESSION.TMP recovery semantics
- **Claimed**: 2026-09-20T17:35:30Z
- **Status**: COMPLETED @ 2026-09-20T17:51:57Z

### [DONE] codex-duetos-exclusive-stdin-focus
- **Session**: `DESKTOP-950K3EI-433`
- **Branch**: `codex/campaign-integration-20260920`
- **Files**: `kernel/core/boot_tasks.cpp,kernel/proc/process.cpp,kernel/proc/process.h`
- **Description**: Route cooked keyboard input to exactly one live foreground consumer
- **Claimed**: 2026-09-20T17:53:56Z
- **Status**: COMPLETED @ 2026-09-20T18:28:28Z

### [DONE] codex-duetos-createprocess-cmdline
- **Session**: `DESKTOP-950K3EI-281`
- **Branch**: `codex/campaign-integration-20260920`
- **Files**: `userland/libs/kernel32/kernel32_fs.c`
- **Description**: Parse quoted and unquoted CreateProcess command lines into bounded executable paths
- **Claimed**: 2026-09-20T18:29:57Z
- **Status**: COMPLETED @ 2026-09-20T18:52:31Z

### [DONE] codex-duetos-createprocess-parser-header
- **Session**: `DESKTOP-950K3EI-376`
- **Branch**: `codex/campaign-integration-20260920`
- **Files**: `userland/libs/kernel32/createprocess_cmdline.h`
- **Description**: Add a shared bounded parser for CreateProcess executable selection
- **Claimed**: 2026-09-20T18:30:39Z
- **Status**: COMPLETED @ 2026-09-20T18:52:35Z

### [DONE] codex-duetos-pe-winapi-budget
- **Session**: `DESKTOP-950K3EI-1287`
- **Branch**: `codex/campaign-integration-20260920`
- **Files**: `kernel/test/smoke_profile.cpp`
- **Description**: Give the comprehensive pe-winapi smoke enough deterministic time under full TCG instrumentation
- **Claimed**: 2026-09-20T18:52:46Z
- **Status**: COMPLETED @ 2026-09-20T19:08:02Z

### [DONE] codex-duetos-pe-winapi-stress-tail
- **Session**: `DESKTOP-950K3EI-1979`
- **Branch**: `codex/campaign-integration-20260920`
- **Files**: `userland/apps/hello_winapi/hello.c`
- **Description**: Diagnose and make the comprehensive Win32 stress tail complete deterministically
- **Claimed**: 2026-09-20T19:03:02Z
- **Status**: COMPLETED @ 2026-09-20T19:08:10Z

### [DONE] codex-duetos-sched-as-admission
- **Session**: `DESKTOP-950K3EI-1983`
- **Branch**: `codex/campaign-integration-20260920`
- **Files**: `kernel/sched/sched.cpp`
- **Description**: Serialize user-task address-space admission with process teardown
- **Claimed**: 2026-09-20T19:12:34Z
- **Status**: COMPLETED @ 2026-09-20T19:42:15Z

### [DONE] codex-duetos-fat32-empty-write
- **Session**: `DESKTOP-950K3EI-537`
- **Branch**: `codex/campaign-integration-20260920`
- **Files**: `kernel/fs/fat32_write.cpp,kernel/fs/fat32_selftest.cpp,kernel/fs/file_route.cpp`
- **Description**: Support native writes and growth from clusterless empty FAT32 files
- **Claimed**: 2026-09-20T19:42:34Z
- **Status**: COMPLETED @ 2026-09-20T20:38:05Z

### [DONE] codex-duetos-win32-close-lifecycle
- **Session**: `DESKTOP-950K3EI-257`
- **Branch**: `codex/campaign-integration-20260920`
- **Files**: `kernel/core/boot_tasks.cpp,userland/libs/user32/user32.c,userland/libs/user32_32/user32_32.c,userland/libs/user32_32/user32_32_internal.h,userland/apps/pe32_window/pe32_window.c`
- **Description**: Route Alt+F4 through WM_CLOSE and implement default Win32 destroy lifecycle
- **Claimed**: 2026-09-20T20:38:18Z
- **Status**: COMPLETED @ 2026-09-20T21:13:47Z

### [DONE] codex-duetos-overlapped-result
- **Session**: `DESKTOP-950K3EI-203`
- **Branch**: `codex/campaign-integration-20260920`
- **Files**: `userland/libs/kernel32/kernel32_io.c,userland/libs/ntdll/ntdll_rtl.c,tools/build/build-kernel32-dll.sh,kernel/subsystems/win32/thunks_table.inc,kernel/subsystems/win32/thunk_retirement_wave1.inc,userland/libs/kernelbase/kernelbase.def,userland/apps/iocp_overlapped_smoke/iocp_overlapped_smoke.c,kernel/proc/ring3_smoke.cpp`
- **Description**: Replace fake overlapped-result success with real x64 completion semantics and live CI coverage
- **Claimed**: 2026-09-20T21:13:57Z
- **Status**: COMPLETED @ 2026-09-20T22:46:02Z

### [DONE] codex-duetos-critical-gsbase-fallback
- **Session**: `DESKTOP-950K3EI-1487`
- **Branch**: `codex/campaign-integration-20260920`
- **Files**: `kernel/cpu/critical.cpp,kernel/cpu/critical.h`
- **Description**: Prevent critical counter updates from bypassing CurrentCpu stale-GS recovery
- **Claimed**: 2026-09-20T22:46:31Z
- **Status**: COMPLETED @ 2026-09-20T23:29:12Z

### [ACTIVE] codex-duetos-critical-gsbase-contract
- **Session**: `DESKTOP-950K3EI-443`
- **Branch**: `codex/campaign-integration-20260920`
- **Files**: `kernel/cpu/percpu.h`
- **Description**: Keep PerCpu critical-counter ownership documentation aligned with stale-GS recovery
- **Claimed**: 2026-09-20T23:00:16Z
- **Status**: IN PROGRESS
