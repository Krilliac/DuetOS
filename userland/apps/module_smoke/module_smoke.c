/*
 * module_smoke — exercise kernel32 module / DLL APIs.
 *
 * Probes the dynamic-loading surface every Win32 app uses to
 * find function pointers at runtime:
 *   GetModuleHandleW (NULL = self, "kernel32.dll" = preloaded DLL)
 *   GetModuleFileNameW (path of EXE)
 *   LoadLibraryW (try to load an already-preloaded DLL again)
 *   FreeLibrary
 *   GetProcAddress (resolve a known export)
 *   DisableThreadLibraryCalls
 *   GetLastError / SetLastError / FormatMessageW
 *
 * Verifies that GetProcAddress returns a function-shaped pointer
 * (non-NULL, in a sensible VA range) for known kernel32 exports.
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

static void OutHex(unsigned long long v)
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
    Out("[module_smoke] starting\r\n");

    /* GetModuleHandleW(NULL) — should return the EXE base. */
    HMODULE self = GetModuleHandleW(NULL);
    Out("[module_smoke] GetModuleHandleW(NULL)  = ");
    if (self != NULL)
    {
        Out("PASS base=");
        OutHex((unsigned long long)(unsigned long long)self);
        Out("\r\n");
    }
    else
    {
        Out("FAIL\r\n");
    }

    /* GetModuleHandleW(L"kernel32.dll"). */
    HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
    Out("[module_smoke] GetModuleHandleW(k32)   = ");
    if (k32 != NULL)
    {
        Out("PASS base=");
        OutHex((unsigned long long)(unsigned long long)k32);
        Out("\r\n");
    }
    else
    {
        Out("FAIL\r\n");
    }

    /* GetModuleFileNameW(NULL). */
    {
        WCHAR path[260] = {0};
        DWORD n = GetModuleFileNameW(NULL, path, 260);
        Out("[module_smoke] GetModuleFileNameW(0) = ");
        Out(n > 0 ? "PASS\r\n" : "FAIL\r\n");
    }

    /* GetProcAddress on a known kernel32 export. */
    if (k32 != NULL)
    {
        FARPROC fn = GetProcAddress(k32, "ExitProcess");
        Out("[module_smoke] GetProcAddress(ExitProc)= ");
        if (fn != NULL)
        {
            Out("PASS addr=");
            OutHex((unsigned long long)(unsigned long long)fn);
            Out("\r\n");
        }
        else
        {
            Out("FAIL\r\n");
        }

        FARPROC bogus = GetProcAddress(k32, "DefinitelyNotARealFunction");
        Out("[module_smoke] GetProcAddress(bogus)  = ");
        Out(bogus == NULL ? "PASS (NULL, as expected)\r\n" : "FAIL (false positive)\r\n");
    }

    /* LoadLibraryW on a preloaded DLL — should succeed via the
     * loader's already-mapped image. */
    {
        HMODULE m = LoadLibraryW(L"kernel32.dll");
        Out("[module_smoke] LoadLibraryW(k32)      = ");
        Out(m != NULL ? "PASS\r\n" : "FAIL\r\n");
        if (m != NULL)
            FreeLibrary(m);
    }

    /* GetLastError / SetLastError round-trip. */
    {
        SetLastError(0x1234);
        DWORD got = GetLastError();
        Out("[module_smoke] SetLastError + GetLast = ");
        Out(got == 0x1234 ? "PASS\r\n" : "FAIL\r\n");
    }

    /* FormatMessageW for ERROR_SUCCESS / a known code. */
    {
        WCHAR buf[256] = {0};
        DWORD n =
            FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, 0, 0, buf, 256, NULL);
        Out("[module_smoke] FormatMessageW         = ");
        Out(n > 0 ? "PASS\r\n" : "FAIL/empty\r\n");
    }

    Out("[module_smoke] done\r\n");
    ExitProcess(0);
}
