#pragma once

/*
 * DuetOS — userland `setjmp.h`, v0.
 * Implementations in `userland/libc/src/setjmp.S`.
 *
 * `jmp_buf` holds the eight 8-byte slots setjmp.S writes:
 * rbx, rbp, r12-r15, rsp, rip. Volatile GPRs are not preserved —
 * setjmp / longjmp follow the ISO C contract, not the
 * make-everything-survive contract some libcs offer.
 */

typedef unsigned long long jmp_buf[8];

#ifdef __cplusplus
extern "C"
{
#endif

    int setjmp(jmp_buf env);
    __attribute__((noreturn)) void longjmp(jmp_buf env, int val);

#ifdef __cplusplus
}
#endif
