#pragma once

/*
 * DuetOS — userland POSIX-ish `unistd.h`, v0.
 *
 * Minimal subset of POSIX every userland binary in the tree needs.
 * Backed by `userland/libc/src/syscall.c` which routes to the
 * kernel via `int 0x80`.
 */

#include <stddef.h>

typedef long ssize_t;

ssize_t write(int fd, const void* buf, size_t len);
ssize_t read(int fd, void* buf, size_t len);
void exit(int code);
int getpid(void);

/* Standard fd numbers. Match POSIX so existing C habits work. */
#define STDIN_FILENO 0
#define STDOUT_FILENO 1
#define STDERR_FILENO 2
