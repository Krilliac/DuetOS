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

/* SYS_STDIN_READ — drain cooked ASCII bytes from the calling
 * process's per-process stdin ring. Backs `read(STDIN_FILENO,
 * buf, len)`. Blocks until at least one byte is available.
 * Distinct from the kernel's path-based SYS_READ (= 5), which
 * takes a NUL-terminated ASCII path pointer in rdi rather than
 * a file descriptor + buffer. */
#define DUET_SYS_STDIN_READ 171

/* SYS_SOCKET_OP — the kernel's multiplexed BSD-socket entry point
 * (kernel/syscall/syscall.h SYS_SOCKET_OP = 153). Native binaries
 * reach the same kernel socket pool the Win32 ws2_32.dll uses. The
 * op selector goes in arg0 (rdi); the rest are op-specific. Cap-gated
 * on kCapNet. See duet/socket.h for typed wrappers. */
#define DUET_SYS_SOCKET_OP 153

#define DUET_SOCKOP_CREATE 1
#define DUET_SOCKOP_BIND 2
#define DUET_SOCKOP_CONNECT 3
#define DUET_SOCKOP_LISTEN 4
#define DUET_SOCKOP_ACCEPT 5
#define DUET_SOCKOP_SENDTO 6
#define DUET_SOCKOP_RECVFROM 7
#define DUET_SOCKOP_SHUTDOWN 8
#define DUET_SOCKOP_CLOSE 9

/* Six-arg raw trampoline for SYS_SOCKET_OP (arg3 -> r10, arg4 -> r8,
 * arg5 -> r9). Implemented in userland/libc/src/syscall.c. Returns
 * the kernel result: >= 0 on success, negative -errno on failure. */
long duet_socket_op(long op, long a1, long a2, long a3, long a4, long a5);

/* Native syscall ABI errno values returned as negative rax payloads.
 * Keep these in sync with kernel/syscall/error.h. */
#define DUET_EPERM 1
#define DUET_ENOENT 2
#define DUET_EIO 5
#define DUET_EBADF 9
#define DUET_EAGAIN 11
#define DUET_ENOMEM 12
#define DUET_EACCES 13
#define DUET_EFAULT 14
#define DUET_EBUSY 16
#define DUET_EEXIST 17
#define DUET_ENODEV 19
#define DUET_EINVAL 22
#define DUET_ERANGE 34
#define DUET_ENOSYS 38
#define DUET_EOVERFLOW 75
#define DUET_EOPNOTSUPP 95
#define DUET_ETIMEDOUT 110
