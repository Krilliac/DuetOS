/*
 * process_smoke — exercise kernel32 process / environment APIs.
 *
 * Probes the per-process state surface every Win32 app reads:
 *   GetCurrentProcess / GetCurrentProcessId
 *   GetCurrentThreadId
 *   GetCommandLineA / GetCommandLineW
 *   GetEnvironmentStringsW (block of L-strings, double-null term)
 *   GetEnvironmentVariableW (single var lookup)
 *   GetSystemInfo
 *   GetVersionExW (legacy version)
 *   GetComputerNameW
 *   GetSystemDirectoryW / GetWindowsDirectoryW
 *
 * Each call is checked for sane return value; for IDs we just
 * verify they're non-zero (process 0 is the kernel, so a userland
 * PE should always see > 0).
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
    Out("[process_smoke] starting\r\n");

    HANDLE proc = GetCurrentProcess();
    Out("[process_smoke] GetCurrentProcess     = ");
    Out(proc != NULL ? "PASS\r\n" : "FAIL\r\n");

    DWORD pid = GetCurrentProcessId();
    Out("[process_smoke] GetCurrentProcessId   = ");
    if (pid != 0)
    {
        Out("PASS pid=");
        OutHex((unsigned long long)pid);
        Out("\r\n");
    }
    else
    {
        Out("FAIL\r\n");
    }

    DWORD tid = GetCurrentThreadId();
    Out("[process_smoke] GetCurrentThreadId    = ");
    if (tid != 0)
    {
        Out("PASS tid=");
        OutHex((unsigned long long)tid);
        Out("\r\n");
    }
    else
    {
        Out("FAIL\r\n");
    }

    LPSTR cmd = GetCommandLineA();
    Out("[process_smoke] GetCommandLineA       = ");
    if (cmd != NULL && cmd[0] != '\0')
    {
        Out("PASS \"");
        Out(cmd);
        Out("\"\r\n");
    }
    else
    {
        Out("FAIL\r\n");
    }

    LPWSTR cmdw = GetCommandLineW();
    Out("[process_smoke] GetCommandLineW       = ");
    Out(cmdw != NULL && cmdw[0] != 0 ? "PASS\r\n" : "FAIL\r\n");

    /* GetEnvironmentVariableW — typically PATH or USERNAME. */
    {
        WCHAR vbuf[64] = {0};
        DWORD got = GetEnvironmentVariableW(L"PATH", vbuf, 64);
        Out("[process_smoke] GetEnvironmentVar PATH = ");
        Out(got > 0 ? "PASS\r\n" : "FAIL/empty\r\n");
    }

    /* GetEnvironmentStringsW — block. */
    {
        LPWCH env = GetEnvironmentStringsW();
        Out("[process_smoke] GetEnvironmentStringsW = ");
        Out(env != NULL ? "PASS\r\n" : "FAIL\r\n");
        if (env != NULL)
            FreeEnvironmentStringsW(env);
    }

    /* GetSystemInfo. */
    {
        SYSTEM_INFO si = {0};
        GetSystemInfo(&si);
        Out("[process_smoke] GetSystemInfo         = ");
        if (si.dwPageSize > 0 && si.dwNumberOfProcessors > 0)
        {
            Out("PASS pgsz=");
            OutHex((unsigned long long)si.dwPageSize);
            Out(" cpus=");
            OutHex((unsigned long long)si.dwNumberOfProcessors);
            Out("\r\n");
        }
        else
        {
            Out("FAIL\r\n");
        }
    }

    /* GetVersionExW. */
    {
        OSVERSIONINFOW vi = {0};
        vi.dwOSVersionInfoSize = sizeof(vi);
        BOOL ok = GetVersionExW(&vi);
        Out("[process_smoke] GetVersionExW         = ");
        if (ok)
        {
            Out("PASS major=");
            OutHex((unsigned long long)vi.dwMajorVersion);
            Out(" minor=");
            OutHex((unsigned long long)vi.dwMinorVersion);
            Out("\r\n");
        }
        else
        {
            Out("FAIL\r\n");
        }
    }

    /* GetComputerNameW. */
    {
        WCHAR name[64] = {0};
        DWORD sz = 64;
        BOOL ok = GetComputerNameW(name, &sz);
        Out("[process_smoke] GetComputerNameW      = ");
        Out(ok && sz > 0 ? "PASS\r\n" : "FAIL\r\n");
    }

    /* GetSystemDirectoryW / GetWindowsDirectoryW. */
    {
        WCHAR dir[260] = {0};
        UINT n = GetSystemDirectoryW(dir, 260);
        Out("[process_smoke] GetSystemDirectoryW   = ");
        Out(n > 0 ? "PASS\r\n" : "FAIL\r\n");
    }
    {
        WCHAR dir[260] = {0};
        UINT n = GetWindowsDirectoryW(dir, 260);
        Out("[process_smoke] GetWindowsDirectoryW  = ");
        Out(n > 0 ? "PASS\r\n" : "FAIL\r\n");
    }

    Out("[process_smoke] done\r\n");
    ExitProcess(0);
}
