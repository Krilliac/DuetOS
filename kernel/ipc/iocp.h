#pragma once

#include "ipc/kobject.h"
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
 * v0 (this header): the kernel-side primitive — a typed
 * completion queue. Implemented as a thin wrapper over KMailbox,
 * which already provides the FIFO + blocking-wait infrastructure
 * (`kernel/ipc/kmailbox.h`). The Win32 ABI surface
 * (`CreateIoCompletionPort` / `GetQueuedCompletionStatus` /
 * `PostQueuedCompletionStatus`) is GAP — it lands in a future
 * slice and goes through SYS_IOCP_* syscalls that map to these
 * primitives.
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
 * Context: kernel. The wrapper holds a KMailbox by value, so
 * lifetime tracks the embedding struct (handle-table slot, in
 * the real implementation). Allocation-free post path: callers
 * pass the completion record by value.
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
};

/// Initialise an IOCP port. Calls through to `KMailboxInit`
/// with a completion-record-shaped slot size and a v0 fixed
/// depth. Idempotent on the same port — a port may be reused
/// after `Close` clears it.
void IocpInit(IocpPort* port);

/// Post a completion. Non-blocking; returns false if the queue
/// is full (caller decides whether to drop, retry, or surface
/// the failure to user mode as STATUS_TOO_MANY_OPENED_FILES /
/// similar). Memory-safe from any kernel context.
bool IocpTryPost(IocpPort* port, const IocpCompletion& c);

/// Drain one completion from the queue (FIFO). Returns false if
/// no completion is available. Non-blocking; the blocking
/// `Wait` variant lands when the syscall surface integrates
/// with the scheduler's sleep paths.
bool IocpTryPop(IocpPort* port, IocpCompletion* out);

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
