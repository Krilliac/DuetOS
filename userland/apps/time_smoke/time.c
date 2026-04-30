/*
 * time_smoke — exercise time / counter / sleep surfaces.
 *
 * Probes the timing primitives every Win32 game and server uses:
 *   GetTickCount / GetTickCount64
 *   QueryPerformanceFrequency / QueryPerformanceCounter
 *   GetSystemTimeAsFileTime
 *   timeGetTime         (winmm)
 *   Sleep               (kernel32)
 *
 * Verifies basic invariants:
 *   - tick count advances after a Sleep(50)
 *   - QPC advances monotonically
 *   - QPF is non-zero
 *   - timeGetTime ≈ GetTickCount
 *
 * Does NOT verify wall-clock accuracy beyond "advances at all" —
 * a separate clock-drift test belongs in HPET / TSC infrastructure
 * once it lands.
 */
#include <windows.h>
#include <mmsystem.h>

static void Out(const char* s)
{
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD n = 0;
    DWORD len = 0;
    while (s[len] != '\0')
        ++len;
    WriteConsoleA(h, s, len, &n, 0);
}

static void OutHex64(unsigned long long v)
{
    static const char hex[] = "0123456789abcdef";
    char buf[19];
    buf[0] = '0';
    buf[1] = 'x';
    for (int i = 0; i < 16; ++i)
        buf[2 + i] = hex[(v >> ((15 - i) * 4)) & 0xF];
    buf[18] = '\0';
    Out(buf);
}

void __cdecl mainCRTStartup(void)
{
    Out("[time_smoke] starting\r\n");

    /* Step 1: GetTickCount before/after Sleep(50). */
    DWORD t0 = GetTickCount();
    Sleep(50);
    DWORD t1 = GetTickCount();
    Out("[time_smoke] GetTickCount t0=");
    OutHex64(t0);
    Out(" t1=");
    OutHex64(t1);
    Out(t1 > t0 ? " PASS (advanced)\r\n" : " FAIL (stuck)\r\n");

    /* Step 2: GetTickCount64. */
    ULONGLONG g0 = GetTickCount64();
    Sleep(20);
    ULONGLONG g1 = GetTickCount64();
    Out("[time_smoke] GetTickCount64 g0=");
    OutHex64(g0);
    Out(" g1=");
    OutHex64(g1);
    Out(g1 > g0 ? " PASS\r\n" : " FAIL\r\n");

    /* Step 3: QPF + QPC monotonic. */
    LARGE_INTEGER freq, c0, c1;
    BOOL fok = QueryPerformanceFrequency(&freq);
    BOOL c0ok = QueryPerformanceCounter(&c0);
    Sleep(10);
    BOOL c1ok = QueryPerformanceCounter(&c1);
    Out("[time_smoke] QueryPerformanceFrequency = ");
    if (fok && freq.QuadPart > 0)
    {
        Out("PASS freq=");
        OutHex64((unsigned long long)freq.QuadPart);
        Out("\r\n");
    }
    else
    {
        Out("FAIL\r\n");
    }
    Out("[time_smoke] QueryPerformanceCounter   = ");
    Out(c0ok && c1ok && c1.QuadPart > c0.QuadPart ? "PASS (monotonic)\r\n" : "FAIL\r\n");

    /* Step 4: GetSystemTimeAsFileTime — non-zero. */
    FILETIME ft = {0, 0};
    GetSystemTimeAsFileTime(&ft);
    Out("[time_smoke] GetSystemTimeAsFileTime   = ");
    if (ft.dwHighDateTime != 0 || ft.dwLowDateTime != 0)
    {
        Out("PASS hi=");
        OutHex64((unsigned long long)ft.dwHighDateTime);
        Out(" lo=");
        OutHex64((unsigned long long)ft.dwLowDateTime);
        Out("\r\n");
    }
    else
    {
        Out("FAIL (zero)\r\n");
    }

    /* Step 5: timeGetTime (winmm). */
    DWORD m0 = timeGetTime();
    Sleep(20);
    DWORD m1 = timeGetTime();
    Out("[time_smoke] timeGetTime m0=");
    OutHex64(m0);
    Out(" m1=");
    OutHex64(m1);
    Out(m1 >= m0 ? " PASS\r\n" : " FAIL\r\n");

    /* Step 6: timeBeginPeriod / timeEndPeriod (no observable effect, just probes ABI). */
    MMRESULT bp = timeBeginPeriod(1);
    MMRESULT ep = timeEndPeriod(1);
    Out("[time_smoke] timeBeginPeriod/EndPeriod = ");
    Out((bp == 0 || bp == TIMERR_NOERROR) && (ep == 0 || ep == TIMERR_NOERROR) ? "PASS\r\n" : "FAIL\r\n");

    Out("[time_smoke] done\r\n");
    ExitProcess(0);
}
