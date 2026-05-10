#pragma once

/*
 * Win32 / Linux subprocess spawn entry point. Backs
 * kernel32.CreateProcessA / CreateProcessW + (eventually)
 * NtCreateUserProcess once ProcessParameters parsing lands.
 *
 * SYS_PROCESS_SPAWN signature:
 *   rdi = const char* user_path  (NUL-terminated; "/disk/<idx>/<rest>")
 *   rsi = u64 flags              (reserved; 0)
 * Returns the new process's PID on success, -1 on failure.
 *
 * Cap-gated on kCapSpawnThread.
 */

#include "util/types.h"

namespace duetos::subsystems::win32
{

i64 SysProcessSpawn(u64 user_path, u64 flags);

/*
 * SYS_PROCESS_SPAWN_EX — extended spawn carrying inheritable
 * stdio handles. See syscall.h for the contract. The bundle
 * pointer (rdx) may be 0 — equivalent to SYS_PROCESS_SPAWN
 * with no inheritance. Each non-zero handle in the bundle is
 * resolved against the caller's win32_handles table; the
 * kernel materialises a matching child-side handle that
 * shares the same backing pipe / file before the child's
 * first ring-3 instruction runs.
 *
 * Inheritance restrictions:
 *   - Pipe-backed handles share their kernel pipe pool slot
 *     with the child; the child takes a fresh refcount on the
 *     end (so the parent can CloseHandle without tearing
 *     the child's view down).
 *   - File-backed (Fat32 / Ramfs / DuetFs) handles are
 *     duplicated by value — the child gets a fresh handle
 *     pointing at the same node with cursor=0.
 *   - Any non-pipe / non-file kind in the bundle aborts the
 *     spawn with -1.
 */
i64 SysProcessSpawnEx(u64 user_path, u64 flags, u64 user_stdio_bundle);

} // namespace duetos::subsystems::win32
