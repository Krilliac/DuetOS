/*
 * userland/libs/common/duet32_syscall.h
 *
 * The i386 (PE32) `int $0x80` syscall trampolines, shared by every
 * `_32` companion DLL under userland/libs. Freestanding: no libc, no
 * kernel headers. The only contract with the kernel is the syscall
 * number + argument shape documented in kernel/syscall/syscall.h.
 *
 * Native 32-bit syscall ABI (mirrors Linux i386 because that is the
 * register set the i386 architecture exposes):
 *     int $0x80
 *     eax = syscall number
 *     ebx = arg1, ecx = arg2, edx = arg3, esi = arg4, edi = arg5, ebp = arg6
 *     eax = return value on exit
 *
 * The kernel's isr_common detects a 32-bit caller via CS=0x3B in the
 * trap frame and remaps these into the SysV AMD64 slots the C++
 * SyscallDispatch expects — see kernel/arch/x86_64/exceptions.S,
 * which moves (ebx,ecx,edx,esi,edi,ebp) -> (rdi,rsi,rdx,r10,r8,r9).
 *
 * ABI NOTE (matters for every signed argument): the remap moves the
 * 32-bit source slots into the 64-bit target slots verbatim, and the
 * CPU zero-extended each 32-bit register write on the user side. A
 * negative 32-bit argument therefore arrives at the C++ dispatcher as
 * a large positive u64 — it is NOT sign-extended. Handlers that read
 * a coordinate back with `static_cast<i32>(frame->rsi)` recover the
 * negative value correctly (truncation undoes the zero-extension);
 * handlers that compare the u64 against a bound do not. Callers that
 * need signed semantics against a bounds-checking handler must
 * resolve the value to a non-negative absolute quantity in the DLL
 * before issuing the syscall. See kernel32_32_fs.c::SetFilePointer.
 */

#ifndef DUETOS_COMMON_DUET32_SYSCALL_H
#define DUETOS_COMMON_DUET32_SYSCALL_H

/* No-arg syscall trampoline: eax = nr. */
static inline int duet_syscall0(int nr)
{
    int rv;
    __asm__ volatile("int $0x80" : "=a"(rv) : "a"(nr) : "memory");
    return rv;
}

/* Single-arg syscall trampoline: eax = nr, ebx = arg1. */
static inline int duet_syscall1(int nr, unsigned a1)
{
    int rv;
    __asm__ volatile("int $0x80" : "=a"(rv) : "a"(nr), "b"(a1) : "memory");
    return rv;
}

/* Two-arg syscall trampoline: eax = nr, ebx = arg1, ecx = arg2. */
static inline int duet_syscall2(int nr, unsigned a1, unsigned a2)
{
    int rv;
    __asm__ volatile("int $0x80" : "=a"(rv) : "a"(nr), "b"(a1), "c"(a2) : "memory");
    return rv;
}

/* Three-arg syscall trampoline: eax = nr, ebx = arg1, ecx = arg2,
 * edx = arg3. The kernel's isr_common remaps (ebx,ecx,edx) ->
 * (rdi,rsi,rdx) for the C++ dispatcher. */
static inline int duet_syscall3(int nr, unsigned a1, unsigned a2, unsigned a3)
{
    int rv;
    __asm__ volatile("int $0x80" : "=a"(rv) : "a"(nr), "b"(a1), "c"(a2), "d"(a3) : "memory");
    return rv;
}

/* Four-arg syscall trampoline: adds esi = arg4, which the remap
 * moves into r10 — the SysV slot the C++ dispatcher reads for a
 * fourth argument. */
static inline int duet_syscall4(int nr, unsigned a1, unsigned a2, unsigned a3, unsigned a4)
{
    int rv;
    __asm__ volatile("int $0x80" : "=a"(rv) : "a"(nr), "b"(a1), "c"(a2), "d"(a3), "S"(a4) : "memory");
    return rv;
}

/* Five-arg syscall trampoline: adds edi = arg5 -> r8. Needed by
 * SYS_WIN_CREATE (x, y, w, h, title). */
static inline int duet_syscall5(int nr, unsigned a1, unsigned a2, unsigned a3, unsigned a4, unsigned a5)
{
    int rv;
    __asm__ volatile("int $0x80" : "=a"(rv) : "a"(nr), "b"(a1), "c"(a2), "d"(a3), "S"(a4), "D"(a5) : "memory");
    return rv;
}

/* Six-arg syscall trampoline: arg6 travels in ebp -> r9. Needed by
 * the SYS_GDI_* primitives (hwnd, x, y, w, h, colour).
 *
 * ebp cannot be named as an asm operand constraint — the compiler
 * reserves it whenever a frame pointer is live — so the value is
 * swapped in around the trap with a pair of register-register
 * `xchg`s. `xchg` (rather than the push/mov/pop the Linux i386
 * headers use) deliberately leaves esp untouched: a push would
 * shift any esp-relative memory operand the compiler picked for
 * the remaining inputs by 4 bytes.
 */
static inline int duet_syscall6(int nr, unsigned a1, unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6)
{
    int rv;
    unsigned scratch6 = a6;
    __asm__ volatile("xchg %%ebp, %[a6]\n\t"
                     "int $0x80\n\t"
                     "xchg %%ebp, %[a6]"
                     : "=a"(rv), [a6] "+r"(scratch6)
                     : "a"(nr), "b"(a1), "c"(a2), "d"(a3), "S"(a4), "D"(a5)
                     : "memory");
    return rv;
}

#endif /* DUETOS_COMMON_DUET32_SYSCALL_H */
