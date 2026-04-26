# VFS namespace + per-process root — v0

**Type:** Observation
**Status:** Active
**Last updated:** 2026-04-20

## What

A minimal read-only in-kernel VFS (`kernel/fs/`) with two seeded
ramfs trees:

- **Trusted root** — `/etc/version`, `/bin/hello` (multi-level tree).
- **Sandbox root** — `/welcome.txt` only.

`core::Process` gained a `root` pointer. Path resolution
(`fs::VfsLookup(root, path, max)`) starts at the caller-supplied
root. There is NO ambient global root — a process's reachable
namespace is exactly the subtree below `Process::root`.

## Jail guarantees

1. **".." is rejected.** Not "resolved relative to root" — refused
   outright. A jail that allows ".." breaks the moment its root is
   embedded inside a larger tree. `VfsLookup(trusted, "/etc/..")`
   returns nullptr. The kernel self-test panics if this ever regresses.
2. **No per-process cwd.** Every path is root-relative. Both
   "/foo/bar" and "foo/bar" resolve identically against `Process::root`.
3. **Empty components tolerated.** "//etc//version" is normalised,
   not rejected, so the sandbox fingerprint doesn't leak via the
   strict-mode error.
4. **Walk-through-file rejected.** Can't `cd` into a regular file.

## SYS_STAT (syscall 4)

- `rdi` = user pointer to NUL-terminated path.
- `rsi` = user pointer to u64 output slot (file size).
- Returns 0 on success, -1 on any failure.
- Gated on `kCapFsRead`. Sandboxed processes with empty caps are
  denied before the path is even copied from user memory.
- Paths are bounced onto the kernel stack via `CopyFromUser`, then
  force-terminated — a user pointer to an unterminated buffer
  can't trick `VfsLookup` into wandering.
- Path is resolved against `CurrentProcess()->root` — the jail
  composes with the cap check.

## Kernel self-test (boot-gated)

`kernel_main` runs a VFS self-test immediately after `PagingInit`
+ `RamfsInit`. It asserts:

- Positive lookups hit for every trusted/sandbox path.
- Sandbox root's `VfsLookup("/etc/version")` returns nullptr.
  Named "JAIL BROKEN" in the panic message.
- `/etc/..` returns nullptr.

Boot halts if any of these regress. Strong guardrail against
future refactors that accidentally widen the namespace.

## Files

- `kernel/fs/ramfs.{h,cpp}` — tree nodes in `.rodata`, two seeded
  trees, accessors for both roots.
- `kernel/fs/vfs.{h,cpp}` — `VfsLookup` + internal `FindChild`,
  `StrEqN`.
- `kernel/core/process.{h,cpp}` — `Process::root`, `ProcessCreate`
  now takes `root`, `kCapFsRead` added.
- `kernel/core/syscall.{h,cpp}` — `SYS_STAT = 4`.
- `kernel/proc/ring3_smoke.cpp` — trusted tasks use trusted root,
  sandbox task uses sandbox root.
- `kernel/core/main.cpp` — `RamfsInit` + the self-test block.

## Next bites

1. **SYS_READ / SYS_OPEN.** Today user code can only learn existence
   + size via `SYS_STAT`. A real file-reading syscall (with caps +
   jail composition) is the natural next step.
2. **Sandbox user payload that probes jail-escape.** The existing
   user payload is the same 31 bytes for every task — it issues
   SYS_WRITE + SYS_YIELD + SYS_EXIT. Custom per-task payloads
   (one that tries `stat("/etc/version")` from the sandbox to
   show the deny) make the jail story visible in the boot log at
   the user-mode level, not just the kernel self-test level.
3. **Mount points.** Today each Process picks one of two hardcoded
   roots. Real processes should mount a composition (overlay,
   bind mounts). That's a deeper design push — defer until a
   second FS backend exists.
4. **Writable ramfs for /tmp.** The tree is read-only today. A
   per-process writable `/tmp` that's torn down with the process
   is a common sandbox idiom and small to add.
5. **A "files" cap table.** SYS_STAT is coarsely gated by
   `kCapFsRead` + `Process::root`. A real cap system would let a
   process receive a handle to one specific node (capability = a
   tagged pointer) rather than ambient permission to stat
   anywhere in its root. Promote when a real userland asks for
   file descriptors.
