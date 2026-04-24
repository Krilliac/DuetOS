/*
 * userland/apps/hello_pe/hello.c
 *
 * The first DuetOS userland program shipped as a real
 * Windows PE/COFF executable, compiled by clang + lld-link
 * on the host and embedded into the boot image as
 * /bin/hello.exe.
 *
 * Freestanding: no libc, no Windows DLLs, no imports. The
 * compiled PE's Import Directory is empty. The entry point
 * talks to the DuetOS native syscall ABI directly:
 *
 *     int 0x80
 *     rax = syscall number   (0 = SYS_EXIT, 2 = SYS_WRITE)
 *     rdi, rsi, rdx          = args
 *
 * This is a stepping stone toward a real Win32 subsystem. The
 * point right now is: does the kernel's PE loader correctly
 * parse DOS + NT headers, map sections with the right flags,
 * and jump to AddressOfEntryPoint? If it does, this program
 * prints one line and exits cleanly.
 *
 * A follow-up slice will introduce an ntdll.dll shim that
 * forwards NtWriteFile / NtTerminateProcess to these same
 * native syscalls, at which point hello.c can be rewritten
 * as `int main() { puts(...); return 0; }` linked against a
 * real msvcrt-equivalent.
 *
 * Build (host): see tools/build-hello-pe.sh.
 */

typedef long long i64;

static inline i64 sys_write(i64 fd, const char* buf, i64 len)
{
    i64 ret;
    __asm__ volatile("int $0x80" : "=a"(ret) : "a"((i64)2), "D"(fd), "S"(buf), "d"(len) : "memory");
    return ret;
}

static inline void sys_exit(i64 code)
{
    __asm__ volatile("int $0x80" : : "a"((i64)0), "D"(code) : "memory");
    __builtin_unreachable();
}

static const char kMsg[] = "[hello-pe] Hello from a PE executable!\n";
#define kMsgLen ((i64)(sizeof(kMsg) - 1))

void _start(void)
{
    sys_write(1, kMsg, kMsgLen);
    sys_exit(0);
}
