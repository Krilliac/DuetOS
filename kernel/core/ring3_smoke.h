#pragma once

#include "types.h"

// Forward-declares to keep this header lightweight.
namespace customos::fs { struct RamfsNode; }
namespace customos::core { struct CapSet; }

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

/// Spawn one ring-3 task on demand, dispatched by `kind`.
/// Returns true if `kind` matched a known spawner, false if
/// the user passed an unknown name. Each spawn call creates
/// a fresh Process + AddressSpace — the ring-3 payload, caps,
/// and ramfs root depend on the kind. Known kinds:
///
///   hello    Trusted, prints "Hello from ring 3!", exits.
///   sandbox  Empty caps + sandbox root; SYS_WRITE denied.
///   jail     Writes into its own RX page → killed on #PF.
///   nx       Jumps into its own NX stack → killed on #PF.
///   hog      Infinite loop → killed by tick-budget.
///   hostile  Retries denied SYS_WRITE → killed by denial ceiling.
///   dropcaps Trusted task that voluntarily drops its caps.
///   priv     Issues `cli` from ring 3 → #GP (CPL > IOPL).
///   badint   Issues `int 0x81` → gate-not-present → task-kill.
///   kread    Reads kernel-half VA → #PF (U/S mismatch) → kill.
///   ptrfuzz  Trusted task; SYS_WRITE with 4 wild user pointers.
///            Each must return -1; control print confirms survival.
///
/// All spawned tasks are reaped cleanly through the normal
/// scheduler path; the shell command returns immediately
/// without waiting for completion.
bool SpawnOnDemand(const char* kind);

/// Entry trampoline for every ring-3 task created via
/// SchedCreateUser. Reads user_code_va / user_stack_va from
/// CurrentProcess(), publishes the kernel stack top to the
/// TSS, and iretqs into ring 3. Exposed so non-ring3 callers
/// (shell `exec`, SYS_SPAWN handler) can hand it to
/// SchedCreateUser.
[[noreturn]] void Ring3UserEntry(void* arg);

/// Load an ELF64 image into a fresh AddressSpace, wrap it in a
/// Process with the given caps + namespace root + budgets, and
/// queue a ring-3 task for it via SchedCreateUser. Returns the
/// new pid on success, or 0 on any failure (invalid ELF, OOM,
/// ProcessCreate failure). On failure, any partial state is
/// cleaned up through AddressSpaceRelease.
u64 SpawnElfFile(const char* name, const u8* elf_bytes, u64 elf_len, CapSet caps,
                 const fs::RamfsNode* root, u64 frame_budget, u64 tick_budget);

} // namespace customos::core
