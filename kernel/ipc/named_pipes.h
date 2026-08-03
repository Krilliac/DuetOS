#pragma once

#include "util/types.h"

/*
 * DuetOS — Win32 named-pipe namespace.
 *
 * Win32 contract (subset honoured by v0):
 *
 *   server: HANDLE h = CreateNamedPipeW(L"\\\\.\\pipe\\foo",
 *               PIPE_ACCESS_INBOUND,  // or PIPE_ACCESS_OUTBOUND
 *               PIPE_TYPE_BYTE | PIPE_WAIT,
 *               1,  // max instances (only 1 supported in v0)
 *               4096, 4096, 0, NULL);
 *
 *   client: HANDLE h = CreateFileW(L"\\\\.\\pipe\\foo", ...);
 *
 * The two handles read/write a shared 4 KiB ring backed by the
 * existing kernel pipe pool (kernel/subsystems/linux/syscall_pipe.cpp).
 * This file owns only the name → pool-slot mapping. The pipe pool
 * already supplies blocking reads/writes + EOF/EPIPE on opposite-
 * end close.
 *
 * V0 limitations (documented; deliberate):
 *   - One instance per name. CreateNamedPipe with the same name
 *     twice fails with ERROR_PIPE_BUSY-equivalent (-1).
 *   - PIPE_ACCESS_DUPLEX is rejected at the syscall boundary
 *     (requires two pool slots — sub-GAP).
 *   - PIPE_TYPE_MESSAGE is silently accepted; reads behave like
 *     PIPE_TYPE_BYTE (no message framing — sub-GAP).
 *   - ConnectNamedPipe is a synchronous no-op that succeeds; the
 *     client can connect at any time after CreateNamedPipe
 *     returns (no overlapped wait — sub-GAP).
 *   - No security descriptor / ACL enforcement; any process can
 *     open any registered name.
 *
 * Lifetime: the registry entry maps name → pool_idx. The pipe
 * pool's read_refs / write_refs track end lifetime. When the
 * server-side handle closes, the kernel calls
 * NamedPipeOnServerClose(slot, generation) which:
 *   - releases the registry-owned opposite-end reservation exactly once
 *   - clears the registry entry so future clients can't find it
 * Every client takes a fresh opposite-end retain. Client handles do not own
 * the registry reservation; they are ordinary pipe-pool ends managed by
 * CloseForProcess.
 */

namespace duetos::ipc
{

constexpr u32 kNamedPipeSlots = 16;
constexpr u32 kNamedPipeMaxNameLen = 64;

/// Server side of CreateNamedPipe. Records the (name, pool_idx,
/// server_is_writer) tuple. Caller has already allocated the
/// pipe pool slot.
///
/// Writes the claimed slot's generation to `*out_generation` on
/// success; the caller must keep it alongside the slot index and
/// hand both back to NamedPipeOnServerClose. `out_generation` is
/// mandatory — a null pointer is refused, because a caller with no
/// generation cannot close its registration safely.
///
/// Returns the registry slot index (>= 0) on success, -1 if the
/// table is full or the name is already registered.
i32 NamedPipeRegisterServer(const char* name, u32 pool_idx, bool server_is_writer, u32* out_generation);

/// Client side of CreateFile against `\\.\pipe\NAME`. Looks up an
/// existing registration and atomically takes a fresh retain on the opposite
/// end while the exact registry entry is still locked. On success, writes
/// (pool_idx, server_is_writer) to the out pointers and transfers that retain
/// to the caller. The registry keeps ownership of the original PipeAlloc
/// reference until exact server close.
///
/// Returns true on hit, false on miss / not-yet-registered.
bool NamedPipeConnectClient(const char* name, u32* out_pool_idx, bool* out_server_is_writer);

/// Server-side close hook. Called from the file-close path when a
/// Win32FileHandle with `named_pipe_registry_slot >= 0` is closed.
/// Clears the registry entry so future clients cannot find it, then drops the
/// registry-owned opposite-end reservation exactly once. A connected client's
/// independently retained reference remains live.
///
/// `generation` is the value NamedPipeRegisterServer handed back for
/// THIS registration; the call is a no-op unless the slot still
/// holds it. That identity check is what makes a stale pair safe:
/// a bare slot index is NOT safe on its own, because FindFreeSlot
/// hands out the lowest free index and an unrelated CreateNamedPipe
/// recycles a torn-down slot immediately.
///
/// No-op when `slot >= kNamedPipeSlots`, when the slot is free, or
/// when the slot's generation has moved on.
void NamedPipeOnServerClose(i32 slot, u32 generation);

/// Boot-time self-test — register / lookup / lifecycle drift checks.
void NamedPipeSelfTest();

} // namespace duetos::ipc
