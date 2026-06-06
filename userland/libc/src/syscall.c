/*
 * DuetOS — userland syscall trampolines, v0.
 *
 * Each function packs its arguments into the int 0x80 ABI and
 * issues the trap. The compiler is free to inline these (they're
 * tiny) but they're declared as plain extern functions so unit
 * testing can link a different impl into a host build later.
 */

#include "duet/syscall.h"
#include "string.h"
#include "unistd.h"

#define DUET_USER_TRAP_UNREACHABLE()                                                                                   \
    do                                                                                                                 \
    {                                                                                                                  \
        __asm__ volatile("ud2" ::: "memory");                                                                          \
        __builtin_unreachable();                                                                                       \
    } while (0)

ssize_t write(int fd, const void* buf, size_t len)
{
    long rv;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"(DUET_SYS_WRITE), "D"((long)fd), "S"(buf), "d"((long)len)
                     : "memory", "rcx", "r11");
    return (ssize_t)rv;
}

ssize_t read(int fd, void* buf, size_t len)
{
    /* Only fd == STDIN_FILENO is wired in v0. Other fds map onto
     * the kernel's path-based SYS_READ family which has a
     * different ABI shape (path + buffer + cap, no fd) — calling
     * those with a numeric fd would faultily reinterpret the
     * value as a path pointer. Return -1 cleanly for now; a real
     * fd-based file read syscall lands when a userland binary
     * needs to drain a non-stdin handle. */
    if (fd != STDIN_FILENO)
        return -1;
    long rv;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"(DUET_SYS_STDIN_READ), "D"(buf), "S"((long)len)
                     : "memory", "rcx", "r11");
    return (ssize_t)rv;
}

int getpid(void)
{
    long rv;
    __asm__ volatile("int $0x80" : "=a"(rv) : "a"(DUET_SYS_GETPID) : "rcx", "r11");
    return (int)rv;
}

void exit(int code)
{
    __asm__ volatile("int $0x80" ::"a"(DUET_SYS_EXIT), "D"((long)code) : "rcx", "r11");
    DUET_USER_TRAP_UNREACHABLE();
}

long duet_socket_op(long op, long a1, long a2, long a3, long a4, long a5)
{
    /* Six-arg int 0x80 ABI: arg3/4/5 land in r10/r8/r9 (Linux-shaped).
     * Mirrors ws2_32.dll's ws2_op trampoline so native binaries and
     * Win32 PEs drive the one kernel socket pool through identical
     * register packing. */
    long rv;
    __asm__ volatile("mov %5, %%r10\n\t"
                     "mov %6, %%r8\n\t"
                     "mov %7, %%r9\n\t"
                     "int $0x80"
                     : "=a"(rv)
                     : "a"((long)DUET_SYS_SOCKET_OP), "D"(op), "S"(a1), "d"(a2), "r"(a3), "r"(a4), "r"(a5)
                     : "r10", "r8", "r9", "rcx", "r11", "memory");
    return rv;
}

/* String helpers — implemented in userland/libc/src/string.S
 * (memcpy, memmove, memset, strlen, strcmp). The asm versions use
 * `rep movsb` / `rep stosb` which the silicon optimises into a
 * single microcoded operation on Ivy Bridge and later (the ERMS
 * feature), beating any C byte loop by ~4x on aligned bulk copies
 * and matching it on small ones. */
