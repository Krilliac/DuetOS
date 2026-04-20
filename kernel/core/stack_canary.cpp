#include "panic.h"
#include "types.h"

/*
 * CustomOS stack-canary runtime support.
 *
 * The compiler emits, in every protected function's prologue:
 *     mov  <cookie>, __stack_chk_guard
 *     mov  <cookie>, [rbp - N]       ; stash on stack
 * and in the epilogue:
 *     mov  <saved>, [rbp - N]
 *     cmp  <saved>, __stack_chk_guard
 *     jne  __stack_chk_fail
 *
 * We provide the two symbols the codegen references:
 *   - __stack_chk_guard: a 64-bit cookie constant.
 *   - __stack_chk_fail:  a [[noreturn]] function that panics.
 *
 * The cookie is a compile-time constant today. That's adequate for
 * catching accidental stack overflows (buffer overruns, wild
 * writes) — the bug's error is random, not targeted at a specific
 * cookie value. A boot-time randomisation from the TSC would
 * harden against an attacker who can probe the kernel image
 * (information disclosure → cookie predictable across reboots).
 * Deferred until such a leak vector exists; the current bit count
 * of "guessing a 64-bit value on the first try" is already
 * 1-in-2^64.
 *
 * Context: kernel. Both symbols are referenced from every
 * protected function; keep them in .data (for the guard) and
 * .text (for the fail) so normal linking resolves them.
 */

namespace
{
// Constant for today. See rationale above.
constexpr customos::u64 kCanarySeed = 0x0123456789ABCDEFULL;
} // namespace

extern "C"
{

// Must match the symbol the compiler emits references to. Size is
// platform pointer size; u64 on x86-64.
__attribute__((used)) customos::u64 __stack_chk_guard = kCanarySeed;

// Called by compiler-generated epilogue code when the stashed cookie
// doesn't match __stack_chk_guard at function return. That means
// SOMETHING between the prologue and the epilogue scribbled on the
// stack past the locals — a buffer overflow, a wild pointer store
// bouncing into the stack, etc. The cookie hasn't been checked
// against anything unpredictable here, so reaching this function
// is unambiguous "kernel memory has been corrupted; halt now."
//
// Must be [[noreturn]]. Must NOT itself have a stack canary (the
// stack is already corrupt and we'd loop forever). Mark with
// no_stack_protector so the compiler omits the epilogue check on
// this function specifically.
[[noreturn]] __attribute__((no_stack_protector)) void __stack_chk_fail()
{
    customos::core::Panic("security/stack", "stack canary corrupted — overflow detected");
}

} // extern "C"
