# Subsystem isolation — v0

**Type:** Decision + Audit checklist
**Status:** Active
**Last updated:** 2026-04-27
**Cross-refs:** CLAUDE.md → "Subsystem isolation (DO NOT VIOLATE)";
README.md → "Subsystem isolation rule" callout.

## The rule

DuetOS hosts two guest ABIs — Win32/NT (for PE binaries) and Linux
(for ELF binaries). Both are **facades for executing those binaries**.
They are NOT auxiliary kernels, not co-equals to DuetOS-native logic,
and not free to drive the system on their own authority.

The DuetOS kernel — its capability set, scheduler, address-space
ledger, FS mediation, IPC, and timer infrastructure — is the **single
authority** on every effect a guest binary can have on the system.
NT and Linux thunks translate ABI shapes only; the kernel's gate
sites enforce policy.

The reviewable signal: **"could a malicious PE / ELF use this path
to do something a native DuetOS process couldn't?"** If yes, the
gate is wrong, not the workload.

## Concrete rules

1. **Every subsystem-driven mutation of DuetOS state goes through a
   kernel-mediated, cap-gated SYS_\* syscall.** No exceptions. A
   Win32 PE that wants to write a file calls `SYS_FILE_WRITE`
   (cap-gated on `kCapFsWrite`). A Linux binary that wants to
   spawn a thread calls `SYS_THREAD_CREATE` (cap-gated on
   `kCapSpawnThread`). The NT or Linux thunk in
   `kernel/subsystems/{win32,linux}/` cannot skip the gate by
   reaching into kernel internals directly.

2. **Auth, privilege, and capability are kernel-owned.** `Process::caps`
   (the `kCap*` bitset in `kernel/proc/process.h`) is the source of
   truth for what a process is allowed to do. Any Win32-shaped
   privilege surface — NtAdjustPrivilegesToken, SeDebugPrivilege,
   integrity levels, ACLs, NtOpenProcessToken handles — is a
   **probe-satisfying facade**. It records nothing in DuetOS's
   actual security model; the kernel's cap gates are what gate.
   The same applies to Linux uid/gid: `getuid()` returns 0, but
   that means nothing — actual access control is the cap set.

3. **Userland DLLs (`userland/libs/*`) are freestanding.** They do
   NOT include kernel headers. They do NOT assume kernel internals.
   They issue syscalls and trust the kernel's return. The build
   contract is that ntdll.c, kernel32.c, advapi32.c, etc. compile
   against a freestanding C target with no DuetOS-kernel includes
   visible.

4. **In-kernel subsystem code routes through public kernel APIs.**
   Files under `kernel/subsystems/win32/` and
   `kernel/subsystems/linux/` may call:
   - `mm::AddressSpaceMapUserPage` / `mm::AddressSpaceProtectUserPage`
     / `mm::CopyToUser` / `mm::CopyFromUser`
   - `sched::SchedCreateUser` / `sched::SchedKillByPid`
     / `sched::WaitQueueBlock`
   - `fs::routing::OpenForProcess` / `fs::routing::ReadForProcess`
     / etc.
   - `core::CapSetHas` / `core::RecordSandboxDenial`

   They MAY NOT mutate `regions[]` arrays, runqueue link pointers,
   `Process::caps` bitsets, or any other kernel-internal data
   structure directly. If a subsystem needs an effect the kernel
   doesn't expose, the kernel grows a new public API — the
   subsystem doesn't reach in.

5. **No subsystem-to-subsystem coupling.** Win32 code doesn't call
   into Linux code; Linux code doesn't call into Win32. Both call
   the kernel. The kernel may call into either via well-defined
   entry points (e.g. PE loader → win32 thunk emission), but the
   data flow is hierarchical: kernel ↔ each subsystem, never
   subsystem ↔ subsystem.

6. **One source of truth per resource.** One TCP stack lives in
   `kernel/net/`. One VFS in `kernel/fs/`. One registry in
   `kernel/subsystems/win32/registry.cpp` (because that's where
   the static tree lives — but the data is kernel-resident and
   kernel-owned; the Win32 thunks just read it). One window
   manager. Each is reachable from multiple ABI front-ends but
   has one kernel-owned implementation.

## Audit checklist (run before merging anything that touches a
subsystem TU or a userland DLL)

For each new or modified syscall handler in
`kernel/subsystems/*/syscall_*.cpp` or `kernel/syscall/syscall.cpp`:

- [ ] **Does this mutation require a capability check?** If the
      handler writes to FS, registry, another process's AS, or any
      shared resource, it MUST `core::CapSetHas(proc->caps, kCapXxx)`
      before proceeding. Self-process operations (writing to your
      own AS, reading your own FDs) don't need a gate; cross-
      process or cross-resource operations do.

- [ ] **Does the handler mutate kernel-internal state directly?**
      If it touches `regions[]`, runqueue links, `caps`, or any
      private struct field, that's a violation — the API surface
      should be a public kernel function.

- [ ] **Does the userland thunk depend on kernel internals?**
      Check the `#include` list — kernel headers in a
      `userland/libs/*` file is a violation.

- [ ] **Could a malicious guest use this path to bypass a kernel
      gate?** Walk the path mentally: PE issues NT call → ntdll
      thunk → SYS_* → kernel handler. At each step, ask "what
      stops a hostile caller from going around this?" The
      stopping mechanism must live in the kernel, not in the
      ntdll thunk.

For any new thunk in `userland/libs/ntdll/ntdll.c` or sibling
DLLs:

- [ ] **Does it issue a syscall, or does it return a constant?**
      Both are valid (constant returners are facades for probe-
      satisfying surfaces — see token family). What's NOT valid
      is a thunk that *acts* on DuetOS state from userland — a
      userland DLL can't open files behind the kernel's back, can't
      spawn threads without going through SYS_THREAD_CREATE, can't
      install signal handlers in another process.

- [ ] **If it's a constant returner, is it documented as a
      facade?** Comment header should say "v0 has no [auth/named-
      objects/registry-children/etc.] machinery; this stub
      satisfies callers that probe the surface but does not
      actually [grant privileges / open named objects /
      enumerate keys]."

## Known facade surfaces (intentional, documented)

These thunks DELIBERATELY return canned data instead of doing real
work, because the underlying kernel facility doesn't exist in v0.
They're documented as facades so an audit doesn't flag them:

| Thunk | What it returns | Why it's not a violation |
|---|---|---|
| `NtOpenProcessToken` / `Ex` | constant handle 0xA00 | No auth model; the kernel's `kCap*` is the real gate. The token is a probe surface. |
| `NtQueryInformationToken` (TokenUser, TokenIntegrityLevel) | static SIDs | Same. PE callers probe; nothing in DuetOS gates on the answer. |
| `NtAdjustPrivilegesToken` | success no-op | No privilege model. `kCapDebug` etc. is what actually gates cross-process inspection. |
| `NtOpenMutant` / `NtOpenEvent` | STATUS_OBJECT_NAME_NOT_FOUND | No named-object table yet. The Create* thunks DO work; only the Open-by-name path is a facade. |
| `NtFsControlFile` / `NtDeviceIoControlFile` | STATUS_NOT_IMPLEMENTED | No IOCTL framework. Explicit NotImpl is the right answer; callers fall back. |
| `NtFlushBuffersFile` | success no-op | No write cache; flush has nothing to do. |

If you add a new facade thunk, document it here. If you find an
**undocumented** thunk that returns a constant, audit it — it
might be a violation pretending to be a facade.

## Known gate sites (where the kernel actually enforces)

These are the kernel-side syscall handlers that gate guest behaviour
on `kCap*`. New handlers should follow the same pattern:

| Syscall | Gate |
|---|---|
| `SYS_FILE_OPEN`, `SYS_STAT`, `SYS_FILE_QUERY_ATTRIBUTES` | `kCapFsRead` |
| `SYS_FILE_WRITE`, `SYS_FILE_CREATE`, `SYS_FILE_UNLINK`, `SYS_FILE_RENAME` | `kCapFsWrite` |
| `SYS_REGISTRY` (kOpSetValue, kOpDeleteValue) | `kCapFsWrite` (registry mutation) |
| `SYS_THREAD_CREATE`, Linux `clone()` | `kCapSpawnThread` |
| `SYS_THREAD_OPEN`, `SYS_PROCESS_OPEN`, `SYS_PROCESS_VM_READ/WRITE/QUERY`, `SYS_THREAD_GET/SET_CONTEXT`, `SYS_THREAD_SUSPEND/RESUME`, `SYS_VM_ALLOCATE/FREE/PROTECT` (foreign target) | `kCapDebug` |
| Linux BSD-socket family (when sockets land) | `kCapNet` |
| `SYS_WIN_GET_KEYSTATE`, `SYS_WIN_GET_CURSOR` | `kCapInput` |
| Cross-process `SYS_PROCESS_TERMINATE`, `SYS_THREAD_TERMINATE` (foreign) | `kCapDebug` |

When adding a new SYS_*, decide which `kCap*` gates it (or whether
it's a self-process operation that needs no gate). When in doubt,
err on the side of gating.

## Violation history

Tracked here so the same mistake doesn't land twice:

| Date | Commit | Violation | Fix |
|---|---|---|---|
| 2026-04-27 | `0caf60f` (introduced) → fix in this slice | `SYS_REGISTRY` op `kOpSetValue` / `kOpDeleteValue` were not cap-gated. Any sandboxed PE could mutate the kernel-side registry sidecar. | Add `core::CapSetHas(proc->caps, core::kCapFsWrite)` check at the top of `DoSetValue` + `DoDeleteValue` before any sidecar mutation. Record sandbox denial on miss. |
