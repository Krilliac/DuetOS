/*
 * userland/libs/kernel32_32/kernel32_32_internal.h
 *
 * Shared plumbing for the i386 (PE32) kernel32 companion DLL — the
 * Win32 scalar typedefs plus the kernel file-handle band predicate.
 * Included by every kernel32_32 TU; nothing here is exported.
 *
 * The `int $0x80` trampolines every `_32` DLL issues syscalls through
 * live in userland/libs/common/duet32_syscall.h, including the ABI
 * note on how the kernel remaps the i386 argument registers and why
 * negative arguments are NOT sign-extended on the way in.
 *
 * Freestanding: no libc, no kernel headers. The only contract with
 * the kernel is the syscall number + argument shape documented in
 * kernel/syscall/syscall.h.
 */

#ifndef DUETOS_KERNEL32_32_INTERNAL_H
#define DUETOS_KERNEL32_32_INTERNAL_H

#include "../common/duet32_syscall.h"

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

#endif /* DUETOS_KERNEL32_32_INTERNAL_H */
