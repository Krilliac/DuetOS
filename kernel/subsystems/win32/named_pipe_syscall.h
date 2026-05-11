#pragma once

#include "arch/x86_64/traps.h"

/*
 * SYS_NAMED_PIPE_CREATE / SYS_NAMED_PIPE_OPEN — Win32 named-pipe
 * server + client paths. Backs kernel32!CreateNamedPipeA/W and
 * the "\\.\pipe\NAME" prefix branch of kernel32!CreateFileW.
 *
 * See ipc/named_pipes.h for the registry contract and the
 * syscall.h ABI block for the argument layout.
 */

namespace duetos::subsystems::win32
{

void DoNamedPipeCreate(arch::TrapFrame* frame);
void DoNamedPipeOpen(arch::TrapFrame* frame);

} // namespace duetos::subsystems::win32
