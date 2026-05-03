#pragma once

/*
 * Serial-input pump — public interface.
 *
 * Boots a kernel task that polls COM1 and feeds the same shell API
 * the PS/2 keyboard reader uses. With this thread running, a host
 * terminal connected via QEMU's `-serial stdio` is an interactive
 * console: the operator types commands, the kernel shell parses
 * and dispatches them, output lands back on the same COM1 stream.
 *
 * Initialization: call SerialInputStart() once after ShellInit and
 * after the scheduler is online. The function spawns a single
 * "serial-input" kernel task and returns immediately. The task
 * runs forever — no shutdown path.
 *
 * Subsystem isolation: the input pump lives in core/. It never
 * routes bytes into the Win32 or Linux subsystems. Userland stdin
 * focus stays driven off the PS/2 path in core/main.cpp; a future
 * slice can wire serial-input to the same focus pump if a CI flow
 * needs a userland binary to read stdin from the host terminal.
 */

namespace duetos::core
{

void SerialInputStart();

} // namespace duetos::core
