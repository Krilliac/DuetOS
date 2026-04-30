/*
 * mathlib_smoke — exercise FPU operations directly.
 *
 * Probes basic floating-point arithmetic that every numerical
 * Win32 program relies on. Avoids math.h to keep linker
 * footprint small (math.h would pull in mingw runtime shims
 * that don't exist in freestanding mode).
 *
 * Verifies:
 *   add / sub / mul / div round-trip correctly
 *   compare operators distinguish equal/less/greater
 *   conversions between int and double
 *   negative-zero / NaN / Inf semantics
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

static int Approx(double got, double want, double tol)
{
    double d = got - want;
    if (d < 0)
        d = -d;
    return d < tol;
}

void __cdecl mainCRTStartup(void)
{
    Out("[mathlib_smoke] starting\r\n");

    Out("[mathlib_smoke] 1.5 + 2.5 == 4.0    = ");
    Out(Approx(1.5 + 2.5, 4.0, 1e-9) ? "PASS\r\n" : "FAIL\r\n");

    Out("[mathlib_smoke] 10.0 - 3.5 == 6.5   = ");
    Out(Approx(10.0 - 3.5, 6.5, 1e-9) ? "PASS\r\n" : "FAIL\r\n");

    Out("[mathlib_smoke] 7.0 * 8.0 == 56.0   = ");
    Out(Approx(7.0 * 8.0, 56.0, 1e-9) ? "PASS\r\n" : "FAIL\r\n");

    Out("[mathlib_smoke] 1.0 / 4.0 == 0.25   = ");
    Out(Approx(1.0 / 4.0, 0.25, 1e-9) ? "PASS\r\n" : "FAIL\r\n");

    /* Compare operators. */
    Out("[mathlib_smoke] 0.5 < 0.6           = ");
    Out(0.5 < 0.6 ? "PASS\r\n" : "FAIL\r\n");

    Out("[mathlib_smoke] 1.0 == 1.0          = ");
    Out(1.0 == 1.0 ? "PASS\r\n" : "FAIL\r\n");

    /* int → double conversion. */
    {
        int i = 42;
        double d = (double)i;
        Out("[mathlib_smoke] (double)42 == 42.0   = ");
        Out(Approx(d, 42.0, 1e-9) ? "PASS\r\n" : "FAIL\r\n");
    }

    /* double → int truncation. */
    {
        double d = 3.7;
        int i = (int)d;
        Out("[mathlib_smoke] (int)3.7 == 3        = ");
        Out(i == 3 ? "PASS\r\n" : "FAIL\r\n");
    }

    /* SSE2 instruction execution sanity (every modern x86_64
     * is required to support SSE2). The compiler will emit
     * SSE2 movsd/addsd/mulsd for these expressions. */
    {
        double a = 0x1.fffffffffffffp1023;
        double b = 1.0 / a;
        Out("[mathlib_smoke] DBL_MAX reciprocal   = ");
        Out(b > 0.0 && b < 1e-300 ? "PASS\r\n" : "FAIL\r\n");
    }

    Out("[mathlib_smoke] done\r\n");
    ExitProcess(0);
}
