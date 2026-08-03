# Inter-Process Communication (IPC)

> **Audience:** Kernel hackers, ABI thunk authors
>
> **Execution context:** Kernel — process context primarily; refcount
> and handle-table operations are spinlock-protected and safe from any
> context that doesn't sleep
>
> **Maturity:** v0 — KObject base + handle table + concrete primitives
> (Mutex / Event / Semaphore / Mailbox / Waitable / File / IOCP) live;
> named-kobject + named-pipe namespaces wired

## Overview

DuetOS's IPC is **capability- and handle-based**. Every kernel-side
IPC primitive derives from a refcounted, type-tagged base
(`KObject`); every process gets a private 64-slot handle table that
maps an opaque `Handle` (u32) to a `KObject*`. ABI front-ends (Win32
NT, Linux POSIX, native) translate their own handle shapes
(`HANDLE`, `int fd`, …) to and from `Handle` — the kernel-internal
name for an IPC object is its `KObject*` plus its handle in the
owning process's table.

This is the design plank that lets the kernel be hybrid: microkernel-
shaped IPC objects keep the surface auditable, while monolithic
drivers keep their hot paths.

## When to Read This Page

- Adding a new ABI-shared primitive (the next "thing" that maps to
  both a Win32 `HANDLE` and a Linux `fd`).
- Migrating an open-coded per-type handle array on `Process` onto
  the unified handle table.
- Reviewing a slice that touches refcounts, handle duplication, or
  cross-process object sharing.
- Investigating an `inspect ipc` report that doesn't match what a
  process should hold.

## Architecture

```
ABI syscall (SYS_MUTEX_CREATE / SYS_EVENT_WAIT / SYS_NAMED_PIPE_OPEN …)
        ↓
HandleTableLookupRef(table, h, expected_type)     — refcounted lookup
        ↓
KMutex / KEvent / KSemaphore / KMailbox / KWaitable / KMessagePort / KFile / IocpPort
        ↓
KObject base (refcount + type tag + destroy callback)
        ↓
g_kobject_lock (spinlock)                          — global refcount lock
```

A handle's lifetime is independent of its underlying KObject's
lifetime: closing the last handle releases the table's reference;
the KObject is destroyed only when *all* references drop, including
those held by named-kobject registrations and in-flight blocking
syscalls.

## Concrete Kernel Objects

| Type            | File                                                 | Maps to (Win32 / POSIX)                                  | What it gives you                                                            |
|-----------------|------------------------------------------------------|----------------------------------------------------------|------------------------------------------------------------------------------|
| `KMutex`        | [`ipc/kmutex.h`](../../kernel/ipc/kmutex.h)          | `CreateMutex` / `pthread_mutex_t`                        | Reentrant lock; owner-aware release; wait-queue blocks on contention.        |
| `KEvent`        | [`ipc/kevent.h`](../../kernel/ipc/kevent.h)          | `CreateEvent` / eventfd                                  | Binary signal, manual-reset or auto-reset; Wait / Set / Reset.               |
| `KSemaphore`    | [`ipc/ksemaphore.h`](../../kernel/ipc/ksemaphore.h)  | `CreateSemaphore` / POSIX `sem_t`                        | Counting semaphore; `Acquire` blocks, `Release(n)` broadcasts once and count admits at most n waiters. |
| `KMailbox`      | [`ipc/kmailbox.h`](../../kernel/ipc/kmailbox.h)      | `PostThreadMessage` / POSIX message queues               | Bounded FIFO of 32-byte typed messages; `not_full`/`not_empty` condvars.     |
| `KWaitable`     | [`ipc/kwaitable.h`](../../kernel/ipc/kwaitable.h)    | `WaitForMultipleObjects`                                 | Composite "wait on any of N predicates"; up to 64 predicates per Waitable.   |
| `KMessagePort`  | [`ipc/kmessage_port.h`](../../kernel/ipc/kmessage_port.h) | Native framed message channel                         | Fixed-storage message ring with a level-triggered readable wait.              |
| `KFile`         | [`ipc/kfile.h`](../../kernel/ipc/kfile.h)            | NT file handle / POSIX `fd`                              | Open-file abstraction; per-kind release callback routes destroy → fd-pool.   |
| `IocpPort`      | [`ipc/iocp.h`](../../kernel/ipc/iocp.h)              | `CreateIoCompletionPort` / `GetQueuedCompletionStatus`   | Fixed-capacity I/O completion ring with retained-handle blocking removal.    |

Every concrete type embeds `KObject base` as its **first member** so
a `KObject*` from the handle table can be `reinterpret_cast`'d back
to the concrete type after a `KObjectType` check.

## Handle Table

[`handle_table.h`](../../kernel/ipc/handle_table.h) exposes a small
surface:

- `HandleTableInsert(table, obj)` — takes ownership of the caller's
  reference (no extra `KObjectAcquire`).
- `HandleTableLookup(table, h, type)` — non-refcounting lookup;
  pointer is only valid until the next `HandleTableRemove` on the
  same slot.
- `HandleTableLookupRef(table, h, type)` — refcounted lookup; pairs
  with `KObjectRelease`. Use this in any syscall that blocks (Wait /
  Acquire / Receive) so a parallel close can't free the object out
  from under you.
- `HandleTableRemove(table, h)` — closes the handle; calls
  `KObjectRelease`.
- `HandleTableDuplicate(src, dst, h)` — cross-process duplication,
  acquires the destination side under canonical lock order (lower
  table address first).
- `HandleTableDrain(table)` — used by process tear-down to release
  every live handle.

`kHandleInvalid = 0` is reserved so a zeroed `HandleTable` is in the
"all-empty" state and any code that mistakenly treats `0` as valid
hits the invalid-handle return path.

Capacity is **fixed at 64 slots per process**
(`kHandleTableCapacity`). Bumping the limit is a one-line change;
the "10 000-handle stress test" item on the
[Roadmap](../reference/Roadmap.md) is gated on a real workload
demanding it.

## Named Namespaces

Two namespaces let processes find each other's objects by name —
matching the Win32 contract where `CreateMutexW(NULL, FALSE, L"Global\\Foo")`
in process A and `OpenMutexW` in process B must return handles to the
same kernel object.

### Named kernel objects ([`named_kobjects.h`](../../kernel/ipc/named_kobjects.h))

- 32-slot, single-spinlock, type-aware table mapping
  `(KObjectType, name) → KObject*`.
- `NamedKObjectRegister` takes a reference on behalf of the table.
- `NamedKObjectFind` returns a fresh reference the caller is
  responsible for (typically handed straight to a `HandleTable`).
- LRU eviction on capacity; no permission gating yet, no
  hierarchical `Global\` vs `Local\` distinction yet.

### Named pipes ([`named_pipes.h`](../../kernel/ipc/named_pipes.h))

- Translates `\\.\pipe\<name>` registrations to a slot in the
  kernel pipe pool (`kernel/subsystems/linux/syscall_pipe.cpp`),
  reusing the existing pipe primitive for the data path.
- One instance per name in v0; duplex access rejected at the
  syscall boundary (would need two pool slots).
- Server-side close clears the registry entry so future
  `CreateFile` opens on the same name miss cleanly.
- **Registry ownership is per-handle and non-transferable.** Only
  the `Win32FileHandle` that `CreateNamedPipe` stamped carries a
  `named_pipe_registry_slot`; every other reference to the same
  pipe (a client open, a handle inherited across `CreateProcess`)
  is an ordinary pipe-pool end. A second owner would run the whole
  teardown — unregistering a name whose server is still serving,
  and dropping the opposite-end reservation the server still needs.
- **Closes are identity-checked, not index-checked.** The registry
  hands back a `(slot, generation)` pair; `FindFreeSlot` returns
  the lowest free index, so a torn-down slot is recycled by the
  very next `CreateNamedPipe`. `NamedPipeOnServerClose` ignores any
  pair whose generation has moved on — a bare slot index alone is
  never safe to act on. Pinned by the `aba-replay` leg of
  `NamedPipeSelfTest`.

## Syscall Surface

Each primitive has a matching syscall band; numbers are fixed in
[`syscall/syscall_names.def`](../../kernel/syscall/syscall_names.def).
Adding a syscall is an ABI change — review the contract in
[`specifications/Syscall-ABI.md`](../specifications/Syscall-ABI.md).

| Object        | Syscall band         | Notes                                                        |
|---------------|----------------------|--------------------------------------------------------------|
| `KMutex`      | `SYS_MUTEX_*` (25–27)| Create / Wait / Release; reentrant; FIFO wakeup via wait-queue. |
| `KEvent`      | `SYS_EVENT_*` (30–33)| Create / Set / Reset / Wait; manual-reset vs. auto-reset.    |
| `KWaitable`   | `SYS_WAIT_MULTI` (48)| Wait on multiple events / mutexes / semaphores.              |
| `KSemaphore`  | `SYS_SEM_*` (51–53)  | Create / Release / Wait.                                     |
| Named pipes   | `SYS_NAMED_PIPE_*` (202–203) | Create on server side; Open on client side.           |
| `KFile`       | (no direct syscall)  | Backing object for POSIX `fd` and NT file handle migrations. |
| `IocpPort`    | `SYS_IOCP_*` (159–162), `SYS_IOCP_POST` (213) | Create / post / cancellable remove / close. |

## Capability / Privilege Surface

IPC objects themselves are not gated by capability — anyone can
create a `KMutex`. **Cross-process reach** is gated:

- `HandleTableDuplicate` requires `kCapDuplicateHandle` on the
  duplicating process (kernel-mediated; ABI front-ends consult
  `ProcessHasCap` before they call it).
- `NamedKObjectFind` is currently ungated — a documented residual
  on [`security/Capabilities.md`](../security/Capabilities.md). Any
  process can probe any registered name. Real workloads can rely on
  `Global\<random>` names until the gate lands.

Crossing the ABI does **not** widen the surface. Win32
`NtDuplicateHandle` and Linux `dup`/`dup2` both reach
`HandleTableDuplicate` after their thunks translate the handle
shape.

## Refcount Semantics

```
KObjectInit(obj, type, destroy)          refcount = 1, caller owns
HandleTableInsert(table, obj)            table takes the +1 (no extra acquire)
HandleTableDuplicate(src, dst, h)        KObjectAcquire (refcount += 1)
HandleTableRemove(table, h)              KObjectRelease (refcount -= 1; destroy if 0)
NamedKObjectRegister(type, name, obj)    KObjectAcquire on register; release on evict
HandleTableLookupRef(table, h, type)     KObjectAcquire; caller must KObjectRelease
```

`destroy` runs **outside** the spinlock — concrete types free their
backing storage (KMalloc'd mailbox ring, KEvent struct, pool slot
release for KFile) at this point. A `destroy` that needs to call
`KObjectRelease` on another object must defer the work to a
fault-domain helper, not recurse.

## Threading & Locking Model

- **Refcount lock**: a single global spinlock (`g_kobject_lock` in
  `kobject.cpp`) wraps every `Acquire` / `Release`. v0 chose the
  global form for auditability; if SMP profiling shows contention,
  the obvious upgrade is a per-object atomic counter.
- **Handle-table lock**: each `HandleTable` carries its own
  `SpinLock`. Cross-process duplicate takes both locks in canonical
  address order to avoid the symmetric-deadlock pair.
- **Object-internal locks**: each primitive owns its own mutex /
  condvar pair (KMutex's `wait_queue`, KMailbox's `not_full` /
  `not_empty`, KSemaphore's `cond`). Use the object API; do **not**
  reach past the public functions to touch internal state.

### Cooperative cancellation at blocking objects

`KMutex`, `KEvent`, `KSemaphore`, `KMailbox`, `KWaitable`, `KMessagePort`,
and `IocpPort` expose
result-bearing waits. Their blocked paths use the scheduler's cancellable
mutex/condvar operations and never terminate another task's live kernel
frame. On `Cancelled`, the scheduler first reacquires the object's companion
mutex and the object unwinds guarded state before unlocking. Each self-pinning
object then drops its explicit wait pin before returning. IOCP also supports a
stack-local boot-test form, and message-port operations use a caller-owned
lifetime contract, so their retained syscall/handle lookup instead spans the
wait and is dropped immediately after the result returns.

The result types intentionally cannot blur cancellation into a normal outcome:

- event and semaphore waits distinguish signaled/acquired, timed out,
  cancelled, and failure;
- mailbox post/receive return completed, cancelled, or failure, and a cancelled
  receive does not modify its output buffer;
- wait-for-any returns `{status,index}`, with a non-ready result carrying
  `kWaitableInvalidIndex` rather than a plausible predicate index;
- IOCP removal distinguishes dequeued, timed out, closed, cancelled, and
  failure; its finite path computes one wrap-safe deadline, and only dequeued
  writes the completion output. The Win32 adapter fail-fast probes every
  stable output range before blocking/dequeue, but those snapshots are not
  page pins, so the later fault-recoverable copies still handle a racing unmap;
- message-port readable wait returns `Cancelled` without consuming a frame.
  Its hosted-test branch deliberately keeps `std::condition_variable` behavior.

Win32 event, semaphore, and IOCP adapters translate a cancelled wait to `-1` only as
an internal unwind sentinel. The syscall dispatcher's outer cancellation guard
terminates the task after all lookup references and dispatcher-local guards
have unwound, before ring 3 can observe that sentinel. Native or Linux adapters
must preserve the same rule when they expose these objects: return an explicit
cancellation/EINTR-shaped result to the dispatcher and let its outer boundary
finalize the current task.

Per-object self-tests (`KObjectSelfTest`, `HandleTableSelfTest`,
`KMutexSelfTest`, …) run from boot before any user code and panic
the kernel on invariant violation. If you add a new concrete type,
add its self-test to the boot list — it pays for itself the first
time a refactor introduces a regression.

## Shell / Diagnostic Surface

- `inspect ipc` (`shell_debug.cpp::CmdInspectIpc`) — lists every
  known `KObjectType` and its name. A future slice will extend this
  to live counts per type (refcount sum across the handle table).
- Per-object self-tests are not user-callable but emit a serial
  `PASS` line during boot; absence is a failure signal.

## Known Limits / GAPs / STUBs

- **IOCP is consolidated onto `IocpPort` + `kobj_handles`.** The
  `SYS_IOCP_CREATE/SET/REMOVE/CLOSE` syscalls (159–162) route
  through the KObject-shaped `IocpPort`
  (`kernel/subsystems/win32/iocp_syscall.cpp`) — handles are
  `0xB00 + slot`, per-process, reclaimed by handle-table drain at
  teardown; the legacy 8-port global pool (`iocp_job.cpp`) is
  deleted. `SYS_IOCP_POST` (213) is the Win32-shaped
  `PostQueuedCompletionStatus` wrapper over `IocpTryPost`,
  exported from ntdll. Remaining GAP: kernel32's
  `CreateIoCompletionPort` / `GetQueuedCompletionStatus` /
  `PostQueuedCompletionStatus` still service an in-process v0 ring
  (0x8000-range handles) — re-routing them onto the kernel ports
  (and the `OVERLAPPED`-completion delivery for real async file
  I/O) is the follow-up consolidation slice.
- **Named-kobject permission gating** is unimplemented; see
  [`security/Capabilities.md`](../security/Capabilities.md).
- **Per-process handle-table capacity is 64.** Workloads that need
  thousands of handles need the `kHandleTableCapacity` bump and a
  matching stress test before it can land.
- **Hierarchical named-pipe paths** (`Global\` vs `Local\` prefix
  semantics) flatten into a single table.
- **Named pipes**: PIPE_ACCESS_DUPLEX, PIPE_TYPE_MESSAGE framing,
  and async `ConnectNamedPipe` are all sub-GAPs documented inline
  in [`named_pipes.h`](../../kernel/ipc/named_pipes.h).
- **KFile per-instance seek lock** is not yet present; callers that
  share an fd across threads must serialise externally.

## Related Pages

- [Synchronization](Synchronization.md) — the underlying spinlock /
  mutex / wait-queue primitives.
- [Process Model](Process-Model.md) — where `HandleTable` lives on
  `Process`.
- [Capabilities](../security/Capabilities.md) — gate definitions
  (`kCapDuplicateHandle`, etc.).
- [Subsystem Isolation](Subsystem-Isolation.md) — why ABI front-ends
  must route through the kernel handle table rather than mutating
  state directly.
- [Sandboxing](../security/Sandboxing.md) — capability profiles that
  remove `kCapDuplicateHandle` from untrusted PEs.
- [Syscall ABI](../specifications/Syscall-ABI.md) — fixed numbers
  for the IPC syscall bands.
