# Parallel Session Protocol

## MANDATORY — read before touching any files

DuetOS may be worked on by several concurrent Claude Code sessions at once.
Follow this protocol every session, no exceptions. The scripts in
`tools/parallel/` automate the bookkeeping; the shared coordinator file
`PARALLEL_WORK.md` (tracked at the repo root) is the source of truth for who
owns what.

> **Visibility note.** A successful claim is not local bookkeeping:
> `claim.sh` makes a signed coordinator-only commit, performs a normal
> (non-force) push of the current `claude/*` branch, and verifies that the
> remote branch head is exactly that commit before reporting success. The
> scripts never auto-rebase a dirty integration tree. They fetch the current
> remote session branch and fail if it is not already an ancestor of `HEAD`;
> reconcile that divergence explicitly before retrying.

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
- Require that you already be on the intended `claude/*` session branch.
- Permit unrelated implementation files to remain dirty, but require
  `PARALLEL_WORK.md` itself to be clean.
- Normalize comma/whitespace-delimited scopes and reject intersections with
  active exact paths, parent/child directories, or conservative glob matches.
- Reject duplicate subsystem IDs noninteractively.
- Register the claim, make a signed coordinator-only commit, push normally,
  and verify the exact remote head.

**Step 3 — Verify publication before proceeding.**
Only the `Claimed and published:` verdict grants ownership. A conflict, dirty
coordinator, remote divergence, commit failure, push rejection, or remote-head
mismatch is a hard failure; there is no interactive "continue anyway" path.

`status.sh` uses the same parser and overlap engine. It exits nonzero when it
finds duplicate IDs, malformed entries, an `[ACTIVE]` header paired with a
completed status, or intersecting active scopes. Contradictory entries are
treated as active for ownership safety until repaired.

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

Both release modes require a clean coordinator, select exactly one consistent
active entry, make a signed coordinator-only commit, push without force, and
verify the remote head. Unrelated dirty files are allowed for ordinary release.
`--merge` additionally requires a completely clean worktree/index, a local
`main` exactly equal to freshly fetched `origin/main`, and a session branch that
can fast-forward `main`; any stale, ahead, divergent, or non-fast-forward state
is refused.

## Coordinator lock and failure recovery

Claim, status, and release share an atomic directory lock under the Git common
directory (`duetos-parallel-coordinator.lock`). This serializes every worktree
of one clone, rather than placing a lock inside only one worktree. Lock metadata
records a random token, operation, hostname, shell PID, and timestamp. The
default wait is 15 seconds and stale threshold is 600 seconds; tests or unusual
operations may override these with `DUETOS_PARALLEL_LOCK_TIMEOUT` and
`DUETOS_PARALLEL_LOCK_STALE_AFTER`. A same-host lock is recovered only after
the threshold and a dead holder PID; a cross-host lock cannot be liveness-
probed and is recoverable only after the threshold.

Do not delete the lock directory by hand merely because an operation is slow.
If a Git commit or push fails, the script reports failure and releases the
lock, but the attempted coordinator edit or local signed commit may remain for
forensics. Inspect `git status`, local `HEAD`, and the exact remote branch head;
then either publish the valid local commit or deliberately restore only
`PARALLEL_WORK.md`. Never treat absence of a success verdict as ownership.

The lock cannot serialize independent clones because they have different Git
common directories. If those clones publish to the **same** remote integration
branch, the fetched-ancestor preflight plus normal push is the final race
boundary: at most one competing push advances that branch, and the loser fails
without a success verdict. Clones publishing different session branches still
have independent coordinator histories and can make mutually invisible claims;
closing that residual requires a repository-wide claim service or forcing all
claims through one protected integration ref. Coordinate out of band until one
of those exists.

---

## Conflict resolution

If two sessions edited the same file:
1. Do **not** blind force-push over the other session's work.
2. Scope the delta: `git diff origin/main...HEAD`.
3. If the other session published first, fetch and reconcile explicitly; do
   not ask the coordinator script to auto-rebase a dirty tree.
4. Resolve conflicts, stage the files, and commit the resolved implementation
   with `git commit -s`. Re-run `release.sh` only after that commit succeeds;
   the release helper intentionally commits only its `PARALLEL_WORK.md` record.

`claim.sh` and `release.sh` use normal pushes only. If a push rejects, the
remote moved or policy rejected the update; inspect and reconcile rather than
rewriting remote history.

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
