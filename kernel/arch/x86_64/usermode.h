#pragma once

#include "util/types.h"

/*
 * DuetOS ring-3 transition — v0.
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

namespace duetos::arch
{

// Implemented in usermode.S; the unmangled name is what the .S file
// exports. Wrapping it behind a C++-visible namespaced identifier
// would require a trampoline shim, and this is the only symbol from
// usermode.S that anyone calls.
extern "C" [[noreturn]] void EnterUserMode(u64 user_rip, u64 user_rsp);

// PE variant: same contract as EnterUserMode, but also sets the
// user's GS base to `user_gs_base` before iretq. Used for Win32
// PE tasks so that `mov rax, gs:[0x30]` (TEB self-pointer) and
// other TEB reads resolve into a valid TEB page instead of
// faulting against linear address 0x30. `user_gs_base` of 0 is
// legal (makes this equivalent to the 2-arg form).
extern "C" [[noreturn]] void EnterUserModeWithGs(u64 user_rip, u64 user_rsp, u64 user_gs_base);

// Thread-entry variant: identical to EnterUserModeWithGs but loads
// `user_rcx` into RCX before iretq instead of zero-scrubbing it.
// Used by SYS_THREAD_CREATE: Win32 x64 calling convention passes
// the thread's "param" argument in RCX, so the entry point of a
// thread started via CreateThread sees it there on first
// instruction. Everything else (segment selector hygiene, GSBASE
// setup via MSR, RFLAGS.IF=1) is identical to the 3-arg form.
extern "C" [[noreturn]] void EnterUserModeThread(u64 user_rip, u64 user_rsp, u64 user_gs_base, u64 user_rcx);

} // namespace duetos::arch
