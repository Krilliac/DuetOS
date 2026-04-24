#include "panic.h"
#include "stack_canary.h"
#include "types.h"

/*
 * DuetOS stack-canary runtime support.
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
 * The cookie starts at a boot-constant seed (used by every
 * function call from kernel_main until RandomizeStackCanary is
 * invoked). Once the entropy pool is up, RandomizeStackCanary
 * replaces the cookie with a per-boot RDSEED/RDRAND value, so
 * across reboots the cookie is unpredictable — an attacker who
 * leaks the kernel image no longer has the canary on a platter.
 *
 * Critical constraint: RandomizeStackCanary and any function
 * currently on the stack when it runs MUST be compiled with
 * `no_stack_protector`. Otherwise the cookie update happens
 * between that caller's prologue (stashed old cookie) and
 * epilogue (compares against new cookie) — FAIL. `kernel_main`
 * never returns (enters the scheduler loop), so it's naturally
 * exempt; `RandomizeStackCanary` itself needs the attribute.
 *
 * Context: kernel. Both symbols are referenced from every
 * protected function; keep them in .data (for the guard) and
 * .text (for the fail) so normal linking resolves them.
 */

namespace
{
// Boot-time seed used until RandomizeStackCanary lands. Any
// overflow that trips the canary before that point produces a
// predictable kernel-panic (the seed is a compile-time
// constant) but catches the corruption just the same.
constexpr duetos::u64 kCanaryBootSeed = 0x0123456789ABCDEFULL;
} // namespace

extern "C"
{

    // Must match the symbol the compiler emits references to. Size is
    // platform pointer size; u64 on x86-64.
    __attribute__((used)) duetos::u64 __stack_chk_guard = kCanaryBootSeed;

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
        duetos::core::Panic("security/stack", "stack canary corrupted — overflow detected");
    }

} // extern "C"

namespace duetos::core
{

// Replace the boot-constant canary with a real entropy value.
// MUST be called from a function-chain that won't unwind —
// every function currently on the stack stashed the OLD cookie
// at its prologue and would fail the epilogue check if we
// replace the guard and they subsequently return. `kernel_main`
// never returns (enters the scheduler), so it's a safe caller.
//
// The function itself is `no_stack_protector`. We also avoid
// any callee that might be protected: rather than calling
// `RandomU64`, we inline RDSEED / RDRAND / RDTSC. That keeps
// RandomizeStackCanary self-contained — no intermediate
// stack frame can stash the old cookie and later check against
// the new one.
//
// Interrupt-safety: callers invoke this BEFORE any IDT is
// installed and BEFORE `sti` runs, so there's no possibility
// of an IRQ handler being mid-flight with an OLD-cookie
// stash pending verification.
__attribute__((no_stack_protector)) void RandomizeStackCanary()
{
    duetos::u64 fresh = 0;
    unsigned char cf = 0;

    // Try RDSEED up to 32 times. Falls through to RDRAND if the
    // hardware doesn't have RDSEED or retries are exhausted.
    for (int i = 0; i < 32; ++i)
    {
        asm volatile("rdseed %0; setc %1" : "=r"(fresh), "=r"(cf));
        if (cf)
            break;
    }
    if (!cf)
    {
        for (int i = 0; i < 10; ++i)
        {
            asm volatile("rdrand %0; setc %1" : "=r"(fresh), "=r"(cf));
            if (cf)
                break;
        }
    }
    if (!cf)
    {
        // Last resort: TSC. Not cryptographic but still per-boot
        // unique — an attacker who reads the disk image can't
        // predict when we booted.
        duetos::u32 lo = 0;
        duetos::u32 hi = 0;
        asm volatile("rdtsc" : "=a"(lo), "=d"(hi));
        fresh = (duetos::u64(hi) << 32) | lo;
    }
    // Keep at least one non-NUL byte — a canary of all zeros
    // would still panic on corruption but looks suspicious in
    // a dump.
    __stack_chk_guard = fresh | 1ULL;
}

} // namespace duetos::core
