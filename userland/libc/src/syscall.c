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
    __builtin_unreachable();
}

/* String helpers. Inline implementations — every userland binary
 * gets these for free without a separate libc archive. */

size_t strlen(const char* s)
{
    size_t n = 0;
    while (s[n])
        ++n;
    return n;
}

void* memset(void* dst, int c, size_t n)
{
    unsigned char* p = (unsigned char*)dst;
    unsigned char v = (unsigned char)c;
    for (size_t i = 0; i < n; ++i)
        p[i] = v;
    return dst;
}

void* memcpy(void* dst, const void* src, size_t n)
{
    unsigned char* d = (unsigned char*)dst;
    const unsigned char* s = (const unsigned char*)src;
    for (size_t i = 0; i < n; ++i)
        d[i] = s[i];
    return dst;
}

int strcmp(const char* a, const char* b)
{
    while (*a && *a == *b)
    {
        ++a;
        ++b;
    }
    return (int)(unsigned char)*a - (int)(unsigned char)*b;
}
