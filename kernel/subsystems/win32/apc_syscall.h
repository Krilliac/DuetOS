#pragma once

/*
 * Kernel-resident APC queue syscalls — backs Win32 QueueUserAPC,
 * ntdll!NtQueueApcThread, and the alertable-wait drain path.
 *
 * The user-space queue in `userland/libs/kernel32/kernel32.c` is
 * a fast path for self-targeting APCs in single-threaded code.
 * The kernel queue here is the source of truth for cross-thread
 * same-process delivery: a peer thread queues to a target tid,
 * the target's alertable-wait poll calls SYS_DRAIN_USER_APC, and
 * the (pfn, data) pair surfaces in user mode for invocation.
 *
 * Cross-process delivery is GAP today: SYS_QUEUE_USER_APC rejects
 * tids whose owning Process is not the caller's. NtQueueApcThread
 * with a foreign thread handle gets the same -1 return; consumers
 * fall back to whatever "best effort" the user-space queue
 * provides.
 */

namespace duetos::arch
{
struct TrapFrame;
}

namespace duetos::subsystems::win32
{

/// SYS_QUEUE_USER_APC handler. See syscall.h for the contract.
void DoQueueUserApc(arch::TrapFrame* frame);

/// SYS_DRAIN_USER_APC handler. See syscall.h for the contract.
void DoDrainUserApc(arch::TrapFrame* frame);

} // namespace duetos::subsystems::win32
