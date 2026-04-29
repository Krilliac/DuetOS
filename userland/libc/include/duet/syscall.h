#pragma once

/*
 * DuetOS — userland-side syscall numbers + raw int 0x80 ABI.
 *
 * Mirrors the kernel-side `enum SyscallNumber` in
 * `kernel/syscall/syscall.h`. Every userland binary that issues
 * syscalls (the v0 shell, future native init, eventual coreutils
 * shims) consumes this header.
 *
 * Calling convention:
 *   eax = syscall number
 *   rdi, rsi, rdx, r10, r8, r9 = arg0..5
 *   int 0x80
 *   rax = return value (negative on error: -ENOSYS, -EFAULT, ...)
 *
 * Identical shape to the Linux x86_64 syscall ABI for argument
 * registers. Different from Linux's `syscall` instruction (we use
 * `int 0x80` so the kernel side doesn't need MSR_LSTAR / SCE).
 */

#define DUET_SYS_EXIT 0
#define DUET_SYS_GETPID 1
#define DUET_SYS_WRITE 2
#define DUET_SYS_READ 3
