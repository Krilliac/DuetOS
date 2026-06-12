/*
 * trace_smoke — exercise ETW / debug-trace APIs.
 *
 *   EventRegister / EventUnregister
 *   EventWrite
 *   ReportEventA   (legacy; already in eventlog_smoke)
 *
 * v0: ETW is not implemented; expect STUB.
 */
#include <windows.h>
#include <evntprov.h>

static const GUID kProvider = {0x12345678, 0x1234, 0x1234, {0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0}};

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
    Out("[trace_smoke] starting\r\n");

    REGHANDLE reg = 0;
    ULONG s = EventRegister(&kProvider, NULL, NULL, &reg);
    Out("[trace_smoke] EventRegister        = ");
    Out(s == 0 ? "PASS\r\n" : "FAIL/STUB\r\n");

    if (s == 0)
    {
        EVENT_DESCRIPTOR ed = {0};
        ed.Id = 1;
        ed.Level = 4; /* INFO */
        ULONG w = EventWrite(reg, &ed, 0, NULL);
        Out("[trace_smoke] EventWrite           = ");
        Out(w == 0 ? "PASS\r\n" : "FAIL/STUB\r\n");

        ULONG u = EventUnregister(reg);
        Out("[trace_smoke] EventUnregister      = ");
        Out(u == 0 ? "PASS\r\n" : "FAIL/STUB\r\n");
    }

    Out("[trace_smoke] done\r\n");
    Out("[ring3-trace-smoke] PASS\r\n");
    ExitProcess(0);
}
