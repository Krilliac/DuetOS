#pragma once

/*
 * DuetOS — userland `stdio.h`, v0.
 *
 * Lightweight printing helpers shared by every native ELF app
 * (the Phase-1 shell + everything in `userland/native-apps/`).
 * Backed by `userland/libc/src/stdio.c`. Routes everything to
 * SYS_WRITE on STDOUT_FILENO via the existing `write()` shim.
 *
 * Not a full ISO C `stdio` — there's no `FILE*`, no buffered
 * I/O, no `fopen`/`fclose`. When a native app needs a real file
 * descriptor, the kernel-side path syscalls (SYS_FILE_OPEN /
 * SYS_FILE_READ / SYS_FILE_WRITE) are reachable from
 * `<duet/syscall.h>` directly.
 */

#include <stddef.h>

/* Write a NUL-terminated string to stdout. Returns the number
 * of bytes actually written; 0 on a write failure. */
size_t puts_str(const char* s);

/* Write a single character to stdout. Returns 1 on success. */
size_t puts_char(char c);

/* Print a base-10 representation of a signed long. Returns the
 * number of bytes written. */
size_t print_int(long v);

/* Print a hex representation of an unsigned long. `width` pads
 * with leading zeros to the nominated width (cap 16); pass 0
 * for "no padding". A `0x` prefix is emitted unless `width == 0`
 * and `v == 0`. */
size_t print_hex(unsigned long v, unsigned width);

/* Print a NUL-terminated string followed by a newline. */
size_t println(const char* s);

/* `printf`-style helper covering the format-specifier subset
 * v0 native apps need: `%s`, `%c`, `%d`, `%ld`, `%u`, `%lu`,
 * `%x`, `%lx`, `%p`, `%%`. No width specifiers, no precision,
 * no floating point — those are deferred. Returns total bytes
 * written. */
size_t print_fmt(const char* fmt, ...);
