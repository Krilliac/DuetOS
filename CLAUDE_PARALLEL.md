# Parallel Session Protocol

## MANDATORY — read before touching any files

DuetOS may be worked on by several concurrent Claude Code sessions at once.
Follow this protocol every session, no exceptions. The scripts in
`tools/parallel/` automate the bookkeeping; the shared coordinator file
`PARALLEL_WORK.md` (tracked at the repo root) is the source of truth for who
owns what.

> **Visibility note.** Coordination only works if every session sees the same
> coordinator. `claim.sh`/`release.sh` rebase on `origin/main` first so claims
> that have merged are visible. A claim that lives only on an un-pushed session
> branch is invisible to others — when in doubt, check with the other session
> rather than assuming a file is free.

---

## On session start

**Step 1 — Check active sessions:**
```bash
tools/parallel/status.sh
```
Read the output. Identify what's claimed and by whom, and note the conflict check.

**Step 2 — Claim your subsystem before editing anything:**
```bash
tools/parallel/claim.sh <subsystem-name> "<files/dirs>" "<brief description>"
```
Examples:
```bash
tools/parallel/claim.sh win32-com    "subsystems/win32/ole32/*" "COM/IDispatch base"
tools/parallel/claim.sh vfs          "kernel/fs/*"              "VFS + path resolution"
tools/parallel/claim.sh net-tcp      "kernel/net/*"            "TCP/IP stack"
tools/parallel/claim.sh sched        "kernel/sched/*"          "MLFQ runqueue work-stealing"
```

This will:
- Rebase your branch on the latest `origin/main`.
- Warn you if your target files are already claimed.
- Keep you on your `claude/*` session branch (or create `claude/<subsystem>`).
- Register your claim in `PARALLEL_WORK.md` and commit it.

**Step 3 — Verify no conflicts before proceeding.**
If `claim.sh` warned about an existing claim, stop and coordinate with the
other session.

---

## During work

- **Stay in your claimed directory/files.** Do not touch files outside your scope.
- **Commit frequently** — every logical unit of work, not one giant commit.
- **If you need a file owned by another session**, ask before touching it.
  Coordinate via `status.sh`; update the coordinator if ownership transfers.
- **Do not edit `PARALLEL_WORK.md` by hand** — use the scripts.
- **Honour DuetOS isolation rules** (see `CLAUDE.md` → Subsystem Isolation).
  A claim grants editing ownership, not a licence to bypass cap-gating.

---

## On session complete

```bash
# Push the session branch only (a human or another session does the merge):
tools/parallel/release.sh <subsystem>

# Push AND merge into main (explicit opt-in):
tools/parallel/release.sh <subsystem> --merge
```

Use `--merge` only when **all** of these hold:
- Your subsystem has no dependency on in-progress work from another session.
- CI is green on your branch.
- DuetOS's "never push to main without explicit permission" bar is met — the
  `--merge` flag *is* that explicit opt-in, so do not pass it casually.

---

## Conflict resolution

If two sessions edited the same file:
1. Do **not** blind force-push over the other session's work.
2. Scope the delta: `git diff origin/main...HEAD`.
3. If the other session merged first, rebase: `git rebase origin/main`.
4. Resolve conflicts, `git add` the files, then re-run `release.sh`.

`release.sh` pushes with `--force-with-lease`, which refuses to clobber commits
you haven't seen — if it rejects the push, fetch and rebase before retrying.

---

## File-ownership cheatsheet (DuetOS layout)

| Subsystem    | Path                      | Notes                                          |
|--------------|---------------------------|------------------------------------------------|
| win32-loader | `subsystems/win32/loader/`| PE/COFF loader, imports, relocations, TLS      |
| win32-ntdll  | `subsystems/win32/ntdll/` | NT syscall surface                             |
| win32-com    | `subsystems/win32/ole32/` | IUnknown, IDispatch, CoCreateInstance          |
| win32-gdi    | `subsystems/win32/gdi32/` | GDI software path                              |
| userland-dll | `userland/libs/*`         | Freestanding Win32 DLLs (one DLL per claim)    |
| vfs          | `kernel/fs/`              | VFS, path resolution, FS backends              |
| net          | `kernel/net/`             | TCP/IP, UDP, ICMP, ARP                         |
| sched        | `kernel/sched/`           | Scheduler, runqueues, threads                  |
| mm           | `kernel/mm/`              | Frame allocator, paging, slab, address spaces  |
| gpu          | `drivers/gpu/`            | Intel/AMD/NVIDIA GPU drivers                   |
| kernel-core  | `kernel/core/`, `kernel/arch/` | **High conflict risk — coordinate explicitly** |
| build        | `CMakeLists.txt`, `cmake/`, `CMakePresets.json` | **Shared — coordinate before editing** |

> Cross-cutting roots — `kernel/core/`, `kernel/arch/`, the build files, and any
> shared header pulled in tree-wide — are high-conflict. If another session is
> active, either wait or stage the change in a subsystem-local spot and promote
> it during integration.

---

## Quick reference

```bash
tools/parallel/status.sh                          # See all active/completed sessions
tools/parallel/claim.sh <sub> "<files>" "<desc>"  # Claim before starting
tools/parallel/release.sh <sub>                   # Release when done (push branch)
tools/parallel/release.sh <sub> --merge           # Release and merge to main
```
