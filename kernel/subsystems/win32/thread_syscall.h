#pragma once

/*
 * Win32 thread-creation syscall handler — backs CreateThread
 * (batch ~47). Spawns a new sched::Task sharing the caller's
 * Process + AddressSpace + cap set.
 *
 *   SYS_THREAD_CREATE (45) — cap-gated on kCapSpawnThread.
 */

namespace customos::arch
{
struct TrapFrame;
}

namespace customos::subsystems::win32
{

void DoThreadCreate(arch::TrapFrame* frame);

/// Ring-3 entry point for a thread Task. SchedCreateUser
/// launches the Task with this as the ring-0 entry; it reads
/// the thread-specific (start_va, param, stack_top) from the
/// heap-allocated ThreadDesc pointed at by the Task's `arg`.
/// After the usual TssSetRsp0 / CR3 is already current / set
/// user_gs_base, iretq's into ring 3 at `start_va` with
/// `param` in rcx (Win32 x64 calling convention).
[[noreturn]] void Ring3ThreadEntry(void* arg);

} // namespace customos::subsystems::win32
