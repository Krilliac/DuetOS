#pragma once

#include "../../core/types.h"

/*
 * CustomOS ring-3 transition — v0.
 *
 * One-way iretq-based user-mode entry. The caller has already:
 *   1) mapped a user-accessible code page at `user_rip` (kPageUser + exec),
 *   2) mapped a user-accessible stack page and picked `user_rsp` inside it,
 *   3) set the TSS's RSP0 to the TOP of a valid kernel stack for this task
 *      (via arch::TssSetRsp0) — that stack is where the CPU will deliver
 *      the next interrupt/trap taken from ring 3.
 *
 * `EnterUserMode` builds an iretq frame (ss / rsp / rflags / cs / rip) and
 * transfers control to ring 3. The RFLAGS value enables IF (0x202), so the
 * next timer tick can preempt the user code.
 *
 * The function is marked `[[noreturn]]`: a ring-3 task returns to the
 * kernel only via a trap or an interrupt, never via this path. When
 * syscalls land this file will grow a `ReturnToUserMode` counterpart that
 * consumes a trap frame instead of a pair of scalars.
 *
 * Context: kernel. Safe to call from task context ONLY; IRQ context has no
 * meaningful "enter user mode" semantics.
 */

namespace customos::arch
{

// Implemented in usermode.S; the unmangled name is what the .S file
// exports. Wrapping it behind a C++-visible namespaced identifier
// would require a trampoline shim, and this is the only symbol from
// usermode.S that anyone calls.
extern "C" [[noreturn]] void EnterUserMode(u64 user_rip, u64 user_rsp);

} // namespace customos::arch
