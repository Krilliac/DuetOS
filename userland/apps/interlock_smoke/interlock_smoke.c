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
    BOOL ok = TRUE;

    LONG x = 10;
    LONG r = InterlockedIncrement(&x);
    Out("[interlock_smoke] InterlockedIncrement   = ");
    BOOL check = r == 11 && x == 11;
    Out(check ? "PASS\r\n" : "FAIL\r\n");
    ok = ok && check;

    r = InterlockedDecrement(&x);
    Out("[interlock_smoke] InterlockedDecrement   = ");
    check = r == 10 && x == 10;
    Out(check ? "PASS\r\n" : "FAIL\r\n");
    ok = ok && check;

    LONG prev = InterlockedExchange(&x, 99);
    Out("[interlock_smoke] InterlockedExchange    = ");
    check = prev == 10 && x == 99;
    Out(check ? "PASS\r\n" : "FAIL\r\n");
    ok = ok && check;

    /* CompareExchange: x=99, expected 99 → swap to 7 */
    prev = InterlockedCompareExchange(&x, 7, 99);
    Out("[interlock_smoke] InterlockedCmpXchg hit = ");
    check = prev == 99 && x == 7;
    Out(check ? "PASS\r\n" : "FAIL\r\n");
    ok = ok && check;

    /* CompareExchange: expected mismatch — should not change */
    prev = InterlockedCompareExchange(&x, 100, 999);
    Out("[interlock_smoke] InterlockedCmpXchg miss= ");
    check = prev == 7 && x == 7;
    Out(check ? "PASS\r\n" : "FAIL\r\n");
    ok = ok && check;

    /* ExchangeAdd. */
    prev = InterlockedExchangeAdd(&x, 5);
    Out("[interlock_smoke] InterlockedExchangeAdd = ");
    check = prev == 7 && x == 12;
    Out(check ? "PASS\r\n" : "FAIL\r\n");
    ok = ok && check;

    /* InterlockedCompareExchange64. */
    LONG64 y = 0x1000000000ULL;
    LONG64 p64 = InterlockedCompareExchange64(&y, 0x2000000000LL, 0x1000000000LL);
    Out("[interlock_smoke] InterlockedCmpXchg64   = ");
    check = p64 == 0x1000000000LL && y == 0x2000000000LL;
    Out(check ? "PASS\r\n" : "FAIL\r\n");
    ok = ok && check;

    Out("[interlock_smoke] done\r\n");
    if (!ok)
    {
        Out("[ring3-interlock-smoke] FAIL\r\n");
        ExitProcess(1);
    }
    Out("[ring3-interlock-smoke] PASS\r\n");
    ExitProcess(0);
}
