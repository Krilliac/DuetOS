/*
 * userland/libs/kernel32_32/kernel32_32_qpc.h
 *
 * The QueryPerformanceCounter epoch extension used by the i386
 * (PE32) kernel32 companion. Freestanding: no libc, no kernel
 * headers, no syscalls — pure arithmetic on values the caller
 * supplies, so tests/host/test_kernel32_32_time.cpp can pin it
 * directly.
 *
 * Why this exists at all
 * ---------------------
 * SYS_NOW_NS (18) returns nanoseconds-since-boot in rax — a full
 * 64-bit value. The i386 syscall path cannot carry it: the kernel's
 * un-remap in kernel/arch/x86_64/exceptions.S restores the user's
 * edi/esi and leaves edx holding the caller's own arg3, so a 32-bit
 * caller only ever observes eax. A PE32 kernel32 therefore sees the
 * LOW 32 BITS of the nanosecond counter, which wraps every
 * 2^32 ns ~= 4.295 seconds.
 *
 * Handing that raw value back as QueryPerformanceCounter would break
 * the one property every caller depends on — monotonicity. Elapsed
 * deltas would go negative roughly every four seconds.
 *
 * Duet32QpcExtend rebuilds the high half in user space: it remembers
 * the previous low word and bumps an epoch counter every time the
 * new low word is below the old one. The result is strictly
 * non-decreasing, and exact whenever the caller polls more often
 * than the wrap period. That keeps the 64-bit sibling's contract
 * (userland/libs/kernel32/kernel32_sync.c: QPC counts nanoseconds,
 * QueryPerformanceFrequency reports 1 GHz) intact on i386.
 *
 * GAP: a process that lets more than ~4.295 s of wall time pass
 * between two QueryPerformanceCounter calls skips one or more wrap
 * epochs, and every later reading is short by 4.295 s per missed
 * wrap. The sequence stays monotonic, so deltas across the gap are
 * merely too small, never negative. Revisit if a syscall that
 * returns the full 64-bit tick through an out-pointer lands (the
 * SYS_GETTIME_ST / SYS_ST_TO_FT pair is the model).
 */

#ifndef DUETOS_KERNEL32_32_QPC_H
#define DUETOS_KERNEL32_32_QPC_H

/* Caller-owned extension state. Zero-initialised state is valid and
 * starts the sequence at whatever low word the first sample carries;
 * QPC is only ever meaningful as a difference, so a non-zero origin
 * is harmless. */
typedef struct
{
    unsigned int last_low; /* previous sample's low 32 bits */
    unsigned int epoch;    /* count of observed wraps */
} Duet32QpcState;

/* Fold `now_low` into `st` and return the extended 64-bit count.
 * Not reentrant — the caller serialises access (kernel32_32_time.c
 * holds a spinlock across the call). */
static inline unsigned long long Duet32QpcExtend(Duet32QpcState* st, unsigned int now_low)
{
    if (st == (Duet32QpcState*)0)
        return (unsigned long long)now_low;
    /* A low word below the previous one can only mean the 32-bit
     * counter rolled over: SYS_NOW_NS is monotonic in the kernel.
     * Equality is not a wrap — two calls inside the same nanosecond
     * must report the same value, not jump a whole epoch. */
    if (now_low < st->last_low)
        ++st->epoch;
    st->last_low = now_low;
    return ((unsigned long long)st->epoch << 32) | (unsigned long long)now_low;
}

#endif /* DUETOS_KERNEL32_32_QPC_H */
