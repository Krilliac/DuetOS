/*
 * userland/libs/kernel32_32/kernel32_32_internal.h
 *
 * Shared plumbing for the i386 (PE32) kernel32 companion DLL —
 * the Win32 scalar typedefs plus the `int $0x80` syscall
 * trampolines. Included by every kernel32_32 TU; nothing here is
 * exported.
 *
 * Freestanding: no libc, no kernel headers. The only contract with
 * the kernel is the syscall number + argument shape documented in
 * kernel/syscall/syscall.h.
 *
 * Native 32-bit syscall ABI (mirrors Linux i386 because that's the
 * register set the i386 architecture exposes):
 *     int $0x80
 *     eax = syscall number
 *     ebx = arg1, ecx = arg2, edx = arg3, esi = arg4, edi = arg5, ebp = arg6
 *     eax = return value on exit
 *
 * The kernel's isr_common detects a 32-bit caller via CS=0x3B in the
 * trap frame and remaps these into the SysV AMD64 slots the C++
 * SyscallDispatch expects — see kernel/arch/x86_64/exceptions.S.
 *
 * ABI NOTE (matters for every signed argument): the remap moves the
 * 32-bit source slots into the 64-bit target slots verbatim, and the
 * CPU zero-extended each 32-bit register write on the user side. A
 * negative 32-bit argument therefore arrives at the C++ dispatcher as
 * a large positive u64 — it is NOT sign-extended. Callers that need
 * signed semantics (e.g. a backwards SetFilePointer) must resolve the
 * value to a non-negative absolute quantity in the DLL before issuing
 * the syscall. See kernel32_32_fs.c::SetFilePointer.
 */

#ifndef DUETOS_KERNEL32_32_INTERNAL_H
#define DUETOS_KERNEL32_32_INTERNAL_H

typedef unsigned int DWORD;
typedef unsigned int UINT;
typedef int BOOL;
typedef void* HANDLE;
typedef unsigned short wchar_t16;

#define WIN32_NORETURN __attribute__((noreturn))

/* Win32-shaped kernel file handles are Process::kWin32HandleBase +
 * slot_idx, i.e. the closed range [0x100, 0x10F]. SYS_FILE_OPEN /
 * SYS_FILE_CREATE plant them; SYS_FILE_{READ,WRITE,SEEK,FSTAT,CLOSE}
 * consume them. Everything outside the band is a pseudo-handle
 * (std handles, GetCurrentProcess, ...) and must not be routed to
 * the file syscalls. */
#define DUET32_FILE_HANDLE_MIN 0x100u
#define DUET32_FILE_HANDLE_MAX 0x110u /* exclusive */

static inline int Duet32IsFileHandle(HANDLE h)
{
    const unsigned raw = (unsigned)(unsigned long)h;
    return raw >= DUET32_FILE_HANDLE_MIN && raw < DUET32_FILE_HANDLE_MAX;
}

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
 * edx = arg3. Linux i386 ABI; the kernel's isr_common remaps
 * (ebx,ecx,edx) -> (rdi,rsi,rdx) for the C++ dispatcher. */
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

#endif /* DUETOS_KERNEL32_32_INTERNAL_H */
