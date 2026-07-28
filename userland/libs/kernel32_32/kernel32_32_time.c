/*
 * userland/libs/kernel32_32/kernel32_32_time.c
 *
 * Wall-clock and performance-counter exports for the i386 (PE32)
 * kernel32 companion. Mirrors userland/libs/kernel32/kernel32_sync.c
 * (the x86_64 sibling) in contract — QueryPerformanceCounter counts
 * nanoseconds and QueryPerformanceFrequency reports 1 GHz — but not
 * in mechanism, because the i386 syscall return path is 32 bits wide.
 *
 * Two 64-bit values have to cross that boundary here:
 *
 *   FILETIME. The x86_64 sibling reads SYS_GETTIME_FT (17), which
 *   returns the whole 100 ns tick count in rax. A 32-bit caller
 *   would see only the low half — a FILETIME that wraps every ~7.16
 *   minutes and decodes to a nonsense calendar date. Instead we use
 *   the pair the kernel provides for exactly this shape:
 *   SYS_GETTIME_ST (40) fills a caller-owned 16-byte SYSTEMTIME and
 *   SYS_ST_TO_FT (41) converts it into a caller-owned FILETIME. Both
 *   move their payload through user pointers, so the full 64 bits
 *   survive.
 *
 *   Performance counter. SYS_NOW_NS (18) has no out-pointer form, so
 *   the low 32 bits are all we get and the epoch is rebuilt in user
 *   space — see kernel32_32_qpc.h for the reconstruction and its
 *   documented limit.
 *
 * SYSTEMTIME (8 WORDs) and FILETIME (2 DWORDs) have identical layout
 * on i386 and x86_64, so neither struct needs an i386-specific shape.
 */

#include "kernel32_32_internal.h"
#include "kernel32_32_qpc.h"

/* ------------------------------------------------------------------
 * Wall clock
 * ------------------------------------------------------------------ */

/* SYSTEMTIME — 8 WORDs, 16 bytes. Same on i386 and x86_64. */
typedef struct
{
    unsigned short wYear;
    unsigned short wMonth;
    unsigned short wDayOfWeek;
    unsigned short wDay;
    unsigned short wHour;
    unsigned short wMinute;
    unsigned short wSecond;
    unsigned short wMilliseconds;
} DUET32_SYSTEMTIME;

/* FILETIME — 2 DWORDs, 8 bytes. Same on i386 and x86_64. */
typedef struct
{
    DWORD dwLowDateTime;
    DWORD dwHighDateTime;
} DUET32_FILETIME;

__declspec(dllexport) void __stdcall GetSystemTime(DUET32_SYSTEMTIME* lpSystemTime)
{
    if (lpSystemTime == (DUET32_SYSTEMTIME*)0)
        return;
    if (duet_syscall1(40 /* SYS_GETTIME_ST */, (unsigned)(unsigned long)lpSystemTime) != 0)
    {
        /* EFAULT — leave a zeroed struct rather than whatever the
         * caller's stack happened to hold. */
        unsigned char* p = (unsigned char*)lpSystemTime;
        for (int i = 0; i < 16; ++i)
            p[i] = 0;
    }
}

__declspec(dllexport) void __stdcall GetSystemTimeAsFileTime(DUET32_FILETIME* lpSystemTimeAsFileTime)
{
    if (lpSystemTimeAsFileTime == (DUET32_FILETIME*)0)
        return;
    lpSystemTimeAsFileTime->dwLowDateTime = 0;
    lpSystemTimeAsFileTime->dwHighDateTime = 0;

    DUET32_SYSTEMTIME st;
    if (duet_syscall1(40 /* SYS_GETTIME_ST */, (unsigned)(unsigned long)&st) != 0)
        return;
    duet_syscall2(41 /* SYS_ST_TO_FT */, (unsigned)(unsigned long)&st, (unsigned)(unsigned long)lpSystemTimeAsFileTime);
}

/* ------------------------------------------------------------------
 * Performance counter
 * ------------------------------------------------------------------ */

/* The epoch state is process-wide, so concurrent QPC callers have to
 * be serialised or two threads racing across a wrap could each bump
 * the epoch. A 32-bit test-and-set is enough: the critical section is
 * three loads and two stores, and SYS_YIELD keeps a loser from
 * burning its slice. */
static Duet32QpcState g_qpc_state;
static volatile int g_qpc_lock;

__declspec(dllexport) BOOL __stdcall QueryPerformanceCounter(DUET32_FILETIME* lpPerformanceCount)
{
    const unsigned now_low = (unsigned)duet_syscall0(18 /* SYS_NOW_NS */);

    int expected = 0;
    while (!__atomic_compare_exchange_n(&g_qpc_lock, &expected, 1, 0, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED))
    {
        expected = 0;
        duet_syscall0(3 /* SYS_YIELD */);
    }
    const unsigned long long extended = Duet32QpcExtend(&g_qpc_state, now_low);
    __atomic_store_n(&g_qpc_lock, 0, __ATOMIC_RELEASE);

    /* LARGE_INTEGER is two DWORDs on i386 — same 8-byte footprint as
     * FILETIME, so the struct is reused rather than duplicated. */
    if (lpPerformanceCount != (DUET32_FILETIME*)0)
    {
        lpPerformanceCount->dwLowDateTime = (DWORD)(extended & 0xFFFFFFFFu);
        lpPerformanceCount->dwHighDateTime = (DWORD)(extended >> 32);
    }
    return 1;
}

__declspec(dllexport) BOOL __stdcall QueryPerformanceFrequency(DUET32_FILETIME* lpFrequency)
{
    /* 1 GHz — pairs with QPC's nanosecond return so a difference
     * divided by the frequency yields seconds. Identical to the
     * x86_64 sibling's answer. */
    if (lpFrequency != (DUET32_FILETIME*)0)
    {
        lpFrequency->dwLowDateTime = 1000000000u;
        lpFrequency->dwHighDateTime = 0;
    }
    return 1;
}
