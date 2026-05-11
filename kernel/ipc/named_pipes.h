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
 * NamedPipeOnServerClose(pool_idx) which:
 *   - releases the registry's reservation for the opposite end
 *     if no client ever connected (avoids leaking the pool slot)
 *   - clears the registry entry so future clients can't find it
 * Client handles do not touch the registry; they're just
 * ordinary pipe-pool ends managed by CloseForProcess.
 */

namespace duetos::ipc
{

constexpr u32 kNamedPipeSlots = 16;
constexpr u32 kNamedPipeMaxNameLen = 64;

/// Server side of CreateNamedPipe. Records the (name, pool_idx,
/// server_is_writer) tuple. Caller has already allocated the
/// pipe pool slot.
///
/// Returns the registry slot index (>= 0) on success, -1 if the
/// table is full or the name is already registered.
i32 NamedPipeRegisterServer(const char* name, u32 pool_idx, bool server_is_writer);

/// Client side of CreateFile against `\\.\pipe\NAME`. Looks up an
/// existing registration. If found, marks the client as connected
/// (so the server-close path stops worrying about the unused
/// reservation) and writes (pool_idx, server_is_writer) to the
/// out pointers.
///
/// Returns true on hit, false on miss / not-yet-registered.
bool NamedPipeConnectClient(const char* name, u32* out_pool_idx, bool* out_server_is_writer);

/// Server-side close hook. Called from the file-close path when a
/// Win32FileHandle with `named_pipe_registry_slot >= 0` is closed.
/// Drops the unused opposite-end reservation if no client connected,
/// and clears the registry entry so future clients can't find it.
///
/// Safe to call with `slot >= kNamedPipeSlots` or with a slot that
/// no longer matches any registration — no-op in those cases.
void NamedPipeOnServerClose(i32 slot);

/// Boot-time self-test — register / lookup / lifecycle drift checks.
void NamedPipeSelfTest();

} // namespace duetos::ipc
