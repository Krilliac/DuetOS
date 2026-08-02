#pragma once

#include "ipc/kobject.h"
#include "sched/sched.h"
#include "util/result.h"
#include "util/types.h"

/*
 * DuetOS — I/O completion port (IOCP) scaffold.
 *
 * Win32's `CreateIoCompletionPort` returns a HANDLE that other
 * I/O handles can be associated with; on each completion the
 * kernel posts an `OVERLAPPED*` + `completion_key` + bytes-
 * transferred to the port. `GetQueuedCompletionStatus` blocks
 * until one arrives. The whole point is decoupling the
 * issuing-thread from the I/O-completing-thread — modern Win32
 * server code (winsock, ReadFile, ConnectNamedPipe, …) leans
 * on this hard.
 *
 * The kernel primitive is a typed fixed-capacity completion ring
 * guarded by a scheduler Mutex + Condvar. The `SYS_IOCP_*` surface
 * maps NtCreate/Set/RemoveIoCompletion onto this object through the
 * unified HandleTable; kernel32 facade consolidation remains a
 * separate compatibility slice.
 *
 * Why scaffold instead of a full implementation:
 * - The kernel-side queue is reusable: any subsystem that wants
 *   a completion-style event sink can hang off it without
 *   reinventing the FIFO.
 * - Wiring it into the existing file/socket syscall surface is
 *   per-call work; the scaffold gives those slices a stable
 *   target to integrate against.
 * - `OVERLAPPED` lifetime is user-controlled; the Win32-side
 *   ABI needs careful design (the OVERLAPPED struct lives in
 *   the issuing process's address space, the kernel can't
 *   touch it directly — needs user copy on completion delivery).
 *   That design lands with the syscall surface, not here.
 *
 * Context: kernel. Queue storage is inline in the IocpPort, so the
 * post path is allocation-free and object lifetime is governed by
 * a KObject reference (or by the stack-local boot-self-test owner).
 */

namespace duetos::ipc
{

struct IocpCompletion
{
    // Win32 OVERLAPPED* in the issuing process's address space.
    // Kept as an opaque u64 here — the kernel does not deref it;
    // the user-mode IOCP consumer does.
    u64 overlapped_user_va;

    // Win32 ULONG_PTR completion_key — caller-defined, opaque to
    // the kernel.
    u64 completion_key;

    // Bytes transferred. For non-I/O completions
    // (PostQueuedCompletionStatus from user mode), the caller
    // picks whatever it wants.
    u64 bytes_transferred;

    // Status code. 0 == STATUS_SUCCESS. Non-zero values map to
    // NTSTATUS shapes (e.g. STATUS_END_OF_FILE 0xC0000011 for an
    // EOF-on-read completion).
    u32 ntstatus;

    u8 _pad[4];
};

struct IocpPort
{
    /// MUST be the first member — `KObject*` ↔ `IocpPort*` cast
    /// shape for `HandleTable` round-trips. Empty when the port
    /// is exercised through the legacy `IocpInit` path (boot
    /// self-test); populated via `IocpCreate` for handle-table
    /// callers.
    KObject base;

    /// Producer / consumer serialisation. Every ring mutation
    /// (post, pop, close) acquires this mutex; the condvar pairs
    /// with it for blocking-wait — drops the mutex, parks on
    /// `not_empty`, re-acquires on wake. Zero-init is the empty
    /// state; no explicit init needed.
    sched::Mutex inner;
    sched::Condvar not_empty;

    // Fixed-cap inline ring. v0 doesn't need a heap-allocated
    // variable-depth queue — every realistic Win32 IOCP user
    // pulls completions fast enough that 32 in-flight is
    // sufficient. A real workload that fills the queue gets a
    // STATUS_TOO_MANY_OPENED_FILES back through `IocpTryPost`,
    // which the caller can surface to user mode.
    static constexpr u32 kCapacity = 32;
    IocpCompletion slots[kCapacity];
    u32 head;              // Next post slot.
    u32 tail;              // Next pop slot.
    u32 count;             // 0..kCapacity.
    u32 association_count; // # of file handles associated, for diag.
    /// True after `IocpClose` ran. `IocpWait` wakes blocked
    /// consumers when this flips and returns `Closed` from then on.
    /// The current Win32 ABI keeps its legacy no-packet mapping;
    /// the object API does not conflate close with timeout.
    bool closed;
    u8 _pad[7];
};

/// Sentinel `timeout_ticks` argument for `IocpWait`: "block
/// indefinitely until a completion arrives or the port is
/// closed". Matches Win32 `INFINITE` for GetQueuedCompletionStatus.
inline constexpr u64 kIocpTimeoutInfinite = ~u64{0};

/// Result-bearing blocking dequeue. Only `Dequeued` commits a ring
/// mutation or writes the caller's completion output.
enum class IocpWaitResult : u8
{
    Dequeued,
    TimedOut,
    Closed,
    Cancelled,
    Failed,
};

/// Initialise the fixed ring and its scheduler synchronization fields.
/// A quiescent port may be re-used after `Close` by initializing it again.
void IocpInit(IocpPort* port);

/// Post a completion. Non-blocking; returns false if the queue
/// is full (caller decides whether to drop, retry, or surface
/// the failure to user mode as STATUS_TOO_MANY_OPENED_FILES /
/// similar). Memory-safe from any kernel context.
bool IocpTryPost(IocpPort* port, const IocpCompletion& c);

/// Drain one completion from the queue (FIFO). Returns false if
/// no completion is available. Non-blocking; pairs with
/// `IocpWait` for the blocking variant a `GetQueuedCompletionStatus`
/// thunk consumes.
bool IocpTryPop(IocpPort* port, IocpCompletion* out);

/// Block until a completion arrives, then drain one (FIFO).
/// `timeout_ticks`:
///   - `0`            — behaves exactly like `IocpTryPop` (probe
///                      and return).
///   - `kIocpTimeoutInfinite` — wait indefinitely.
///   - any other      — wait at most `timeout_ticks` scheduler
///                      timer ticks (one tick = 10 ms at 100 Hz).
/// Returns `Dequeued` iff a completion was popped into `*out`; every
/// other result leaves `*out` unchanged. Cooperative cancellation is
/// distinct from timeout/close and returns only after the companion
/// mutex has been reacquired and unlocked. The caller must keep the
/// port alive for the full call: this API also supports stack-local
/// ports initialized by `IocpInit`, so it cannot take a KObject pin.
IocpWaitResult IocpWait(IocpPort* port, IocpCompletion* out, u64 timeout_ticks);

/// Tear down a port — drains the queue, zeroes the association
/// count. Safe to call on an already-clean port. Does NOT free
/// the port's storage — use `IocpRelease` for the heap-allocated
/// path that came out of `IocpCreate`.
void IocpClose(IocpPort* port);

/// Allocate a fresh IocpPort on the kernel heap, wired up as a
/// `KObjectType::Iocp`. Returns the new object with refcount = 1;
/// the caller hands it to `HandleTableInsert` which takes that
/// reference. The destroy callback frees the storage on last
/// release. Returns `Err{ErrorCode::OutOfMemory}` on heap
/// exhaustion. Safe from any kernel context once kheap is online.
::duetos::core::Result<IocpPort*> IocpCreate();

/// Boot-time self-test. Posts a small batch of completions,
/// drains them, asserts FIFO order + no leaks. Panics on any
/// invariant violation.
void IocpSelfTest();

} // namespace duetos::ipc
