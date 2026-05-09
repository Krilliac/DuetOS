#pragma once

/*
 * DuetOS — userland `string.h`, v0.
 * Implementations in `userland/libc/src/string.S` — hand-written
 * `rep movsb` / `rep stosb` based on the SysV AMD64 ABI.
 */

#include <stddef.h>

size_t strlen(const char* s);
void* memset(void* dst, int c, size_t n);
void* memcpy(void* dst, const void* src, size_t n);
void* memmove(void* dst, const void* src, size_t n);
int strcmp(const char* a, const char* b);
