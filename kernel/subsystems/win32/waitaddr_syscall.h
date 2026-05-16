#pragma once

/*
 * DuetOS — Win32 address-keyed wait (WaitOnAddress / WakeByAddress).
 *
 * The kernel half of the futex-shaped primitive V8 / Chrome build
 * their SRW locks and condition variables on. A task parks on the
 * hash bucket of a user VA after confirming the watched word still
 * holds the expected value; a waker wakes the bucket. Bucket
 * collisions degrade to spurious wakeups (callers re-check), never
 * lost wakeups.
 *
 * Context: kernel syscall handlers, called from the native syscall
 * dispatcher on the faulting task's kernel stack.
 */

namespace duetos::arch
{
struct TrapFrame;
}

namespace duetos::subsystems::win32
{

/// SYS_WAIT_ON_ADDRESS. rdi=user VA, rsi=expected value (low
/// `size` bytes), rdx=size (1/2/4/8), r10=timeout ms (0xFFFFFFFF
/// infinite). Sets frame->rax = 1 (woken or value already
/// differed — caller must re-check) or 0 (timed out).
void DoWaitOnAddress(arch::TrapFrame* frame);

/// SYS_WAKE_BY_ADDRESS. rdi=user VA, rsi=0 single / 1 all. Wakes
/// the address's hash bucket. frame->rax = 0.
void DoWakeByAddress(arch::TrapFrame* frame);

} // namespace duetos::subsystems::win32
