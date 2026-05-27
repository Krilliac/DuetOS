#pragma once

#include "util/types.h"

/*
 * DuetOS — single-instruction per-CPU access via the GS segment override.
 *
 * The kernel keeps each CPU's `PerCpu` struct in `IA32_GS_BASE`. A
 * read of `cpu::CurrentCpu()->field` therefore costs an indirect load
 * through GSBASE. For hot, single-word counters (frame-allocator stats,
 * scheduler tick counts, soft-IRQ pending masks) the compiler can't
 * collapse that into the single `mov %gs:imm, %reg` instruction the
 * Linux `this_cpu_*` macros emit on x86_64 — so we provide the wrappers
 * here.
 *
 * Usage:
 *
 *     using duetos::cpu::PerCpu;
 *     constexpr u64 kOff = DUETOS_THIS_CPU_OFFSET(PerCpu, sched_tasks_live);
 *     arch::ThisCpuInc64(kOff);          // incq %gs:offset(...)
 *     u64 v = arch::ThisCpuRead64<u64>(kOff);
 *
 * Safety:
 *
 *   1. ONLY valid for fields whose single writer is the owning CPU.
 *      Cross-CPU reads of a this_cpu field need READ_ONCE-style
 *      semantics plus explicit summation — see `cpu::PercpuCounter`
 *      for read-mostly counters where the slop bound matters.
 *
 *   2. The caller must guarantee no migration between the offset
 *      compute and the GS-relative access. Spinlock-held, IRQ-off,
 *      preempt-off, or scheduler-pinned contexts are all safe.
 *
 *   3. GSBASE must be a kernel-canonical PerCpu pointer. Inside the
 *      ring3 → ring0 swapgs window (a few instructions in
 *      syscall_entry / int 0x80 entry stub) GSBASE still holds the
 *      user value — these macros must NOT be used there. They are
 *      safe everywhere a normal `cpu::CurrentCpu()` call is safe.
 *
 * The asm itself is one instruction in every helper below: a single
 * `mov` / `inc` / `add` with the `%gs:` segment override. The "r"
 * (register) constraint on `offset` keeps the offset in a register so
 * we don't need to materialise an immediate at every call site, and
 * GCC/Clang both fold a constexpr offset into a `lea` + the single
 * `mov` (or, when the offset fits an addressing-mode 32-bit
 * displacement and the constraint admits it, directly into the
 * displacement of the GS-relative memory operand).
 */

namespace duetos::arch
{

/// Compute the byte offset of `field` in `type`. Encoded by the call
/// site at compile time and passed to the ThisCpu* helpers below.
#define DUETOS_THIS_CPU_OFFSET(type, field) (static_cast<duetos::u64>(__builtin_offsetof(type, field)))

/// Read a u64 field of the current CPU's PerCpu struct.
/// Emits a single `mov %gs:(%reg), %reg` instruction.
template <typename T> inline T ThisCpuRead64(u64 offset)
{
    static_assert(sizeof(T) == 8, "ThisCpuRead64 is for u64-width fields only");
    u64 value;
    asm volatile("movq %%gs:(%1), %0" : "=r"(value) : "r"(offset) : "memory");
    return static_cast<T>(value);
}

/// Write a u64 field of the current CPU's PerCpu struct.
/// Emits a single `mov %reg, %gs:(%reg)` instruction.
inline void ThisCpuWrite64(u64 offset, u64 value)
{
    asm volatile("movq %0, %%gs:(%1)" : : "r"(value), "r"(offset) : "memory");
}

/// Atomic-on-this-CPU increment of a u64 field. Single
/// `incq %gs:(%reg)` — no LOCK prefix needed: by contract this field
/// is written only by the owning CPU, and `incq` is a single retired
/// uop so it can't tear against a same-CPU IRQ.
inline void ThisCpuInc64(u64 offset)
{
    asm volatile("incq %%gs:(%0)" : : "r"(offset) : "memory");
}

/// Atomic-on-this-CPU add of `n` to a u64 field. Single
/// `addq %imm/reg, %gs:(%reg)` instruction.
inline void ThisCpuAdd64(u64 offset, u64 n)
{
    asm volatile("addq %0, %%gs:(%1)" : : "ri"(n), "r"(offset) : "memory");
}

/// Boot self-test. Increments a dedicated counter slot in the BSP's
/// PerCpu struct via the ThisCpu* macros and verifies the read-back.
/// Called from `BootBringupKernelServices` after `PerCpuInitBsp`.
void ThisCpuOpsSelfTest();

} // namespace duetos::arch
