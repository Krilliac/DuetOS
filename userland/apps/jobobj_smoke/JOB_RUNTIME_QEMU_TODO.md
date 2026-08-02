# Job child runtime profile TODO (not a passing test)

The shipped `jobobj_smoke` is an embedded, single-process fixture. Its PASS
verdict covers only behavior it executes: class-0 process-exit queries,
self-assignment, fixed and partial Job queries, last-handle membership
persistence, empty-Job termination, and stale-handle rejection.

It does **not** prove live-child termination, process-slot reuse, or inherited
membership. No shipped smoke verdict may claim those cases until a dedicated
kernel/QEMU profile stages separately named controller and worker images.

## Required runtime profile

1. Stage `jobobj_controller.exe`, `jobobj_idle.exe`, `jobobj_worker.exe`, and
   `jobobj_grandchild.exe` at paths that `CreateProcess` can reopen.
2. Keep the controller outside every tested Job. Spawn `jobobj_idle.exe`, obtain
   a real retained Process handle, assign it to one Job, call
   `TerminateJobObject(job, 0x4A4F42)`, and require `GetExitCodeProcess` to
   report exactly `0x4A4F42` after the child exits.
3. Reuse one still-open Job for at least 33 sequential idle children. Assign and
   terminate each child individually, wait for its real exit, close its Process
   handle, and prove assignment 33 succeeds. This is the runtime guard against
   a fixed 32-slot table retaining exited members forever.
4. Have an assigned `jobobj_worker.exe` create `jobobj_grandchild.exe`. Query
   `JobObjectBasicProcessIdList` until both exact PIDs are active, terminate the
   Job, and verify the requested exit code through retained handles for both
   processes. This is the default child/grandchild inheritance proof.
5. Repeat close-versus-exit and terminate-versus-exit cases under 2-vCPU and
   4-vCPU QEMU profiles. A timeout, missing verdict, or surviving child fails
   the profile.

Only that profile may emit `[jobobj-runtime-profile] PASS`, and only after every
case above has completed. Missing helper images must be a SKIP/no-verdict, never
a PASS.

## Current harness blockers (2026-08-01)

- `CreateProcessA/W` stores the spawn syscall's PID in `PROCESS_INFORMATION.hProcess`
  rather than returning a generation-valid Process handle.
- `kernel32!OpenProcess` currently returns the current-process pseudo-handle for
  every PID, so it cannot repair the child handle in user mode.
- `WaitForSingleObject` does not dispatch Process handles and would report an
  unknown handle as pseudo-signaled. The profile needs a real Process wait or a
  bounded `GetExitCodeProcess` poll over a retained handle.
- The built-in smoke battery executes an embedded image that has no filesystem
  path from which it can create a second copy or a separately named worker.

The kernel/QEMU profile therefore needs its own staging and verdict integration
claim. Adding dormant child code or a source-shape assertion to the embedded
fixture is not an acceptable substitute.
