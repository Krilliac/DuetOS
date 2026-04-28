# KMalloc-zero-init pattern — every kernel struct with embedded sync primitives must memset before use

**Last updated:** 2026-04-28
**Type:** Pattern + Issue
**Status:** Active

## Description

KMalloc returns memory still carrying whatever was last in it — including the
freed-page poison `kFreedPagePoison = 0xDE` from the C2 frame-allocator patch.
A subsequent caller that explicitly assigns *most* fields but leaves any
embedded sub-structure unset reads back garbage. When that sub-structure is a
`sync::SpinLock`, the lock's `locked` word reads `0xdededede` (≠ 0) and
`SpinLockAcquire` busy-spins forever waiting for the lock to "free" — even
though no one ever held it.

## Symptoms (qemu-smoke matrix, 2026-04-28)

The qemu-smoke profile-matrix redesign exposed this in
`Process::kobj_handles` (a `HandleTable` containing a `SpinLock`):

  * Every non-bringup profile (pe-hello, pe-winapi, pe-winkill, ring3, linux)
    timed out at exactly the 480s wall budget with no `[smoke] complete`
    sentinel and no panic. Bringup passed because it spawns no Process and
    never reaches `ProcessRelease`.
  * Localised by adding `arch::SerialWrite` checkpoints around
    `AddressSpaceRelease` and `ProcessRelease` — the kernel got past
    `[proc] release: post-CleanupProcess` and never reached
    `[proc] release: post-HandleTableDrain`.
  * `HandleTableDrain` does `sync::SpinLockGuard guard(table.lock);` —
    `SpinLockAcquire` saw `locked = 0xdededede` and spun forever.

## Fix

`memset(p, 0, sizeof(...))` immediately after the KMalloc, BEFORE any
explicit field assignment. The explicit assignments still set fields to
their non-zero values; the memset just guarantees every field NOT covered
by an explicit assignment starts from a clean zero.

## Existing instances of the pattern

  * `kernel/mm/address_space.cpp:236` — AddressSpaceCreate. Comment cites
    `Mutex.waiters.tail reads back as 0xdededededededede ... and #GPs`.
    Existed before the C2 patch landed — the fix preceded the rest.
  * `kernel/proc/process.cpp:46` — ProcessCreate (this commit, `d9cfeb7`).
    Same root cause.
  * `kernel/sched/sched.cpp:592, :647` — Task struct in SchedInit's
    boot_task allocation and SchedCreateInternal's per-task allocation
    (commit `91bd728`). Same root cause.

## Audit checklist

When adding a new KMalloc'd struct:

1. Does the struct embed any of: `sync::SpinLock`, `sync::Mutex`,
   `sync::WaitQueue`, `ipc::HandleTable`, `ipc::KObject` pointer table,
   linked-list pointers (`next`, `prev`, etc.)?
2. Does the struct have nullable / "set-only-if-needed" pointer fields
   that the consumer dereferences without an explicit-zero check?
3. Does the consumer have a destructor / cleanup path that walks
   embedded tables (drain, release, free)?

If any answer is "yes": add `memset(p, 0, sizeof(*p))` right after the
KMalloc. The cost is one ~9 KB memset on a path that only runs at
process-create / task-create time; the benefit is unconditional safety
against the next freed-page-poison-related bug.

## Why explicit assignments don't suffice

The pre-fix ProcessCreate set ~30 fields explicitly, including many
`= 0` assignments for counters (`win32_iat_miss_count = 0` etc.). The
`Process` struct as of 2026-04-28 has ~120 fields totalling ~9 KB. The
gap between "fields covered by explicit assignment" and "fields the
struct contains" is what holds the poison. Every time a new field is
added without a corresponding assignment in ProcessCreate, the bug
re-grows.

Memset is the dependable boundary: regardless of how many fields are
added, the post-memset state is "zero everywhere unless explicitly
overridden". Anything depending on zero-init (lock unlocked, pointer
null, counter zero, flag false) gets that state for free.

## Related: stack-allocated structs

Stack-allocated structs are NOT covered by this pattern — they get
initialised via the compiler's value-init / `{}` syntax. The bug only
applies to heap-allocated structs whose constructor is "manual
assignment after KMalloc". Local lambdas, `static` variables in BSS,
and struct literals are all fine.
