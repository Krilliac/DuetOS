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

} // namespace duetos::subsystems::win32
