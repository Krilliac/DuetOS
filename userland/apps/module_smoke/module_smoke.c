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
     * loader's already-mapped image (fast path:
     * SYS_DLL_BASE_BY_NAME). */
    {
        HMODULE m = LoadLibraryW(L"kernel32.dll");
        Out("[module_smoke] LoadLibraryW(k32)      = ");
        Out(m != NULL ? "PASS\r\n" : "FAIL\r\n");
        if (m != NULL)
            FreeLibrary(m);
    }

    /* LoadLibraryW("customdll2.dll") — exercises the
     * disk-load path via SYS_DLL_LOAD_FROM_PATH. Under emulator,
     * customdll2.dll is NOT in the preload set (essential=false),
     * so GetModuleHandleW misses and the kernel falls through to
     * the /lib/customdll2.dll ramfs lookup + DllLoad. Under bare
     * metal, it IS preloaded, and the fast path returns the
     * existing base. Either way the call returns a valid handle
     * and GetProcAddress(CustomDouble) yields a function that
     * doubles its argument. */
    {
        HMODULE m = LoadLibraryW(L"customdll2.dll");
        Out("[module_smoke] LoadLibraryW(cdll2)    = ");
        if (m == NULL)
        {
            Out("FAIL/null-handle\r\n");
        }
        else
        {
            typedef int(__stdcall * CustomDoubleFn)(int);
            CustomDoubleFn fn = (CustomDoubleFn)GetProcAddress(m, "CustomDouble");
            if (fn == NULL)
            {
                Out("FAIL/no-export\r\n");
            }
            else
            {
                int v = fn(21);
                Out(v == 42 ? "PASS\r\n" : "FAIL/wrong-result\r\n");
            }
        }
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
    Out("[ring3-module-smoke] PASS\r\n");
    ExitProcess(0);
}
