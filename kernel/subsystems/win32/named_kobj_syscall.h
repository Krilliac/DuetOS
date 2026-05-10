#pragma once

/*
 * Win32 named-kobject syscall handler — backs
 * Create{Mutex,Event,Semaphore} when given a non-NULL name and
 * Open{Mutex,Event,Semaphore} on the open-only path. See
 * SYS_NAMED_KOBJ_OPEN_OR_CREATE (185) in kernel/syscall/syscall.h
 * for the ABI.
 *
 * The handler routes through the kernel-resident named table
 * (kernel/ipc/named_kobjects.h). On a name-table miss it
 * allocates a fresh kobject of the requested type, registers
 * the name, and inserts the kobject into the calling process's
 * handle table. On a hit it inserts the existing kobject (with
 * a fresh refcount) into the caller's table — both processes
 * end up holding handles to the same kernel object.
 */

namespace duetos::arch
{
struct TrapFrame;
}

namespace duetos::subsystems::win32
{

void DoNamedKObjOpenOrCreate(arch::TrapFrame* frame);

} // namespace duetos::subsystems::win32
