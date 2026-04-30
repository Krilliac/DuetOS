/*
 * dbghelp_smoke — exercise dbghelp / debug-utility APIs.
 *
 * Probes the surface every Windows crash reporter / profiler /
 * debugger uses for stack walking and symbol lookup:
 *   SymInitialize / SymCleanup
 *   SymSetOptions / SymGetOptions
 *   StackWalk64 (skipped — needs a CONTEXT we'd have to fabricate)
 *   UnDecorateSymbolName
 *   MiniDumpWriteDump (skipped — would create a 50MB+ file)
 *
 * Most of these are likely STUB today; the value is the boot
 * transcript showing exactly which calls return success vs.
 * which return E_NOTIMPL / 0.
 */
#include <windows.h>
#include <dbghelp.h>

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
    Out("[dbghelp_smoke] starting\r\n");

    /* SymInitialize — TRUE if started OK. */
    BOOL ok = SymInitialize(GetCurrentProcess(), NULL, FALSE);
    Out("[dbghelp_smoke] SymInitialize         = ");
    Out(ok ? "PASS\r\n" : "FAIL/STUB\r\n");

    /* SymGetOptions / SymSetOptions round-trip. */
    {
        DWORD opts = SymGetOptions();
        Out("[dbghelp_smoke] SymGetOptions         = ");
        Out("PASS (returned)\r\n");
        DWORD prev = SymSetOptions(opts | SYMOPT_DEFERRED_LOADS);
        Out("[dbghelp_smoke] SymSetOptions         = ");
        Out(prev == opts ? "PASS (round-trip)\r\n" : "FAIL\r\n");
    }

    /* UnDecorateSymbolName — even a noop returning input length
     * counts as PASS. */
    {
        char out_buf[64] = {0};
        DWORD n = UnDecorateSymbolName("?foo@@YAXXZ", out_buf, sizeof(out_buf), UNDNAME_COMPLETE);
        Out("[dbghelp_smoke] UnDecorateSymbolName  = ");
        Out(n > 0 ? "PASS\r\n" : "FAIL/STUB\r\n");
    }

    /* SymCleanup. */
    {
        BOOL c = SymCleanup(GetCurrentProcess());
        Out("[dbghelp_smoke] SymCleanup            = ");
        Out(c ? "PASS\r\n" : "FAIL\r\n");
    }

    Out("[dbghelp_smoke] done\r\n");
    ExitProcess(0);
}
