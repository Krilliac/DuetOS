#pragma once

/*
 * CustomOS ring-3 smoke task — v0.
 *
 * Boot-time demonstration that the kernel can transition to ring 3 and
 * that a user-mode task coexists with kernel-mode workers. Spawns a
 * dedicated scheduler thread that:
 *
 *   1. allocates one physical frame for the user code page,
 *   2. allocates one physical frame for the user stack,
 *   3. maps both into the low-half canonical user virtual range with
 *      the U/S bit set,
 *   4. plants a 4-byte payload into the code page: `pause; jmp short -4`
 *      — an interruptible, non-faulting infinite loop,
 *   5. publishes its kernel stack top to the TSS's RSP0 slot so the
 *      next user→kernel transition lands safely,
 *   6. iretq's into ring 3 and never returns to kernel mode except via
 *      preempting interrupts.
 *
 * Success evidence: boot log shows the spawn line, other workers
 * (heartbeat, keyboard reader, idle) keep running — which would be
 * impossible if the ring-3 entry corrupted the CPU state. A future
 * slice will add a syscall gate and the user task will exit cleanly.
 *
 * Context: kernel. Call exactly once after SchedInit + the standard
 * driver bring-up sequence (paging is required — MapPage is the
 * mechanism that flips the U/S bit on the user pages).
 */

namespace customos::core
{

void StartRing3SmokeTask();

} // namespace customos::core
