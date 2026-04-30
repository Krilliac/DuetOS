/*
 * interlock_smoke — exercise lock-free atomic primitives.
 *
 * Probes the InterlockedXxx family every multi-threaded Win32
 * program uses for refcounts, lock-free queues, etc.:
 *   InterlockedIncrement / InterlockedDecrement
 *   InterlockedExchange
 *   InterlockedCompareExchange / InterlockedCompareExchange64
 *   InterlockedExchangeAdd
 *   InterlockedAnd / InterlockedOr / InterlockedXor
 *   _ReadWriteBarrier (intrinsic — no test, just compiles)
 *
 * Single-threaded test: verifies the value-update semantics,
 * not the lock-freedom. mt-test belongs in thread_stress.
 */
#include <windows.h>

static void Out(const char* s)
{
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD n = 0;
    DWORD len = 0;
    while (s[len] != '\0')
        ++len;
    WriteConsoleA(h, s, len, &n, 0);
}

void __cdecl mainCRTStartup(void)
{
    Out("[interlock_smoke] starting\r\n");

    LONG x = 10;
    LONG r = InterlockedIncrement(&x);
    Out("[interlock_smoke] InterlockedIncrement   = ");
    Out(r == 11 && x == 11 ? "PASS\r\n" : "FAIL\r\n");

    r = InterlockedDecrement(&x);
    Out("[interlock_smoke] InterlockedDecrement   = ");
    Out(r == 10 && x == 10 ? "PASS\r\n" : "FAIL\r\n");

    LONG prev = InterlockedExchange(&x, 99);
    Out("[interlock_smoke] InterlockedExchange    = ");
    Out(prev == 10 && x == 99 ? "PASS\r\n" : "FAIL\r\n");

    /* CompareExchange: x=99, expected 99 → swap to 7 */
    prev = InterlockedCompareExchange(&x, 7, 99);
    Out("[interlock_smoke] InterlockedCmpXchg hit = ");
    Out(prev == 99 && x == 7 ? "PASS\r\n" : "FAIL\r\n");

    /* CompareExchange: expected mismatch — should not change */
    prev = InterlockedCompareExchange(&x, 100, 999);
    Out("[interlock_smoke] InterlockedCmpXchg miss= ");
    Out(prev == 7 && x == 7 ? "PASS\r\n" : "FAIL\r\n");

    /* ExchangeAdd. */
    prev = InterlockedExchangeAdd(&x, 5);
    Out("[interlock_smoke] InterlockedExchangeAdd = ");
    Out(prev == 7 && x == 12 ? "PASS\r\n" : "FAIL\r\n");

    /* InterlockedCompareExchange64. */
    LONG64 y = 0x1000000000ULL;
    LONG64 p64 = InterlockedCompareExchange64(&y, 0x2000000000LL, 0x1000000000LL);
    Out("[interlock_smoke] InterlockedCmpXchg64   = ");
    Out(p64 == 0x1000000000LL && y == 0x2000000000LL ? "PASS\r\n" : "FAIL\r\n");

    Out("[interlock_smoke] done\r\n");
    ExitProcess(0);
}
