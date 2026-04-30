/*
 * wow64_smoke — exercise Wow64 / arch-detection APIs.
 *
 * Even on a native x86_64-only system, every Win32 PE that
 * cares about installer logic touches these:
 *   IsWow64Process / IsWow64Process2
 *   GetNativeSystemInfo
 *   IsProcessorFeaturePresent
 *   GetSystemFirmwareTable
 *   ImageNtHeader  (skipped — needs valid PE base)
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
    Out("[wow64_smoke] starting\r\n");

    BOOL is_wow = TRUE;
    BOOL ok = IsWow64Process(GetCurrentProcess(), &is_wow);
    Out("[wow64_smoke] IsWow64Process       = ");
    Out(ok && !is_wow ? "PASS (FALSE, native)\r\n" : "FAIL/STUB\r\n");

    /* IsWow64Process2 (Win10+). */
    {
        USHORT proc = 0, native = 0;
        BOOL ok2 = IsWow64Process2(GetCurrentProcess(), &proc, &native);
        Out("[wow64_smoke] IsWow64Process2      = ");
        if (ok2)
        {
            Out("PASS native=0x");
            char hex[8];
            const char* h = "0123456789abcdef";
            for (int i = 3; i >= 0; --i)
                hex[3 - i] = h[(native >> (i * 4)) & 0xF];
            hex[4] = '\0';
            Out(hex);
            Out("\r\n");
        }
        else
        {
            Out("FAIL/STUB\r\n");
        }
    }

    /* GetNativeSystemInfo — should match GetSystemInfo on native. */
    {
        SYSTEM_INFO si = {0};
        GetNativeSystemInfo(&si);
        Out("[wow64_smoke] GetNativeSystemInfo  = ");
        Out(si.wProcessorArchitecture == 9 /*PROCESSOR_ARCHITECTURE_AMD64*/ ? "PASS (AMD64)\r\n" : "FAIL/STUB\r\n");
    }

    /* IsProcessorFeaturePresent — SSE2 should be present on x86_64. */
    {
        BOOL sse2 = IsProcessorFeaturePresent(PF_XMMI64_INSTRUCTIONS_AVAILABLE);
        Out("[wow64_smoke] IsProcessorFeaturePresent(SSE2) = ");
        Out(sse2 ? "PASS\r\n" : "FAIL/STUB\r\n");
    }

    Out("[wow64_smoke] done\r\n");
    ExitProcess(0);
}
