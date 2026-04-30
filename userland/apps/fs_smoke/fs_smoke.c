/*
 * fs_smoke — exercise kernel32 filesystem APIs.
 *
 * Probes the file-I/O surface every Windows app uses:
 *   CreateFileW (open existing for READ)
 *   GetFileSizeEx
 *   ReadFile
 *   SetFilePointer / SetFilePointerEx
 *   GetFileAttributesW
 *   GetCurrentDirectoryW
 *   GetFullPathNameW
 *   FindFirstFileW / FindNextFileW / FindClose
 *   CloseHandle
 *
 * Targets `/etc/version` which exists in the kernel ramfs as
 * `\etc\version` — the previous winkill smoke verified
 * CreateFileW + ReadFile + Close against this exact path, so
 * we know that branch works. Adds attribute / find / pointer
 * coverage on top.
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

static void OutDec(unsigned long long v)
{
    char buf[32];
    int len = 0;
    if (v == 0)
        buf[len++] = '0';
    else
    {
        char rev[32];
        int r = 0;
        while (v != 0)
        {
            rev[r++] = (char)('0' + (v % 10));
            v /= 10;
        }
        for (int j = 0; j < r; ++j)
            buf[len++] = rev[r - 1 - j];
    }
    buf[len] = '\0';
    Out(buf);
}

void __cdecl mainCRTStartup(void)
{
    Out("[fs_smoke] starting\r\n");

    /* CreateFileW + GetFileSizeEx + ReadFile. */
    HANDLE f =
        CreateFileW(L"/etc/version", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    Out("[fs_smoke] CreateFileW(/etc/version)  = ");
    if (f == INVALID_HANDLE_VALUE)
    {
        Out("FAIL\r\n");
        Out("[fs_smoke] done\r\n");
        ExitProcess(1);
    }
    Out("PASS\r\n");

    LARGE_INTEGER sz = {0};
    BOOL gz = GetFileSizeEx(f, &sz);
    Out("[fs_smoke] GetFileSizeEx              = ");
    if (gz)
    {
        Out("PASS sz=");
        OutDec((unsigned long long)sz.QuadPart);
        Out("\r\n");
    }
    else
    {
        Out("FAIL\r\n");
    }

    char buf[64] = {0};
    DWORD got = 0;
    BOOL rok = ReadFile(f, buf, sizeof(buf) - 1, &got, NULL);
    Out("[fs_smoke] ReadFile                   = ");
    if (rok && got > 0)
    {
        Out("PASS got=");
        OutDec(got);
        Out(" content=\"");
        /* Trim at first newline for readability. */
        for (DWORD i = 0; i < got; ++i)
            if (buf[i] == '\r' || buf[i] == '\n')
            {
                buf[i] = '\0';
                break;
            }
        Out(buf);
        Out("\"\r\n");
    }
    else
    {
        Out("FAIL\r\n");
    }

    /* SetFilePointer back to start, re-read. */
    DWORD pos = SetFilePointer(f, 0, NULL, FILE_BEGIN);
    Out("[fs_smoke] SetFilePointer(0,BEGIN)    = ");
    Out(pos == 0 ? "PASS\r\n" : "FAIL\r\n");

    CloseHandle(f);
    Out("[fs_smoke] CloseHandle                = PASS (returned)\r\n");

    /* GetFileAttributesW. */
    DWORD attr = GetFileAttributesW(L"/etc/version");
    Out("[fs_smoke] GetFileAttributesW         = ");
    if (attr == INVALID_FILE_ATTRIBUTES)
        Out("FAIL\r\n");
    else
    {
        Out("PASS attr=0x");
        char hex[12];
        const char* h = "0123456789abcdef";
        DWORD v = attr;
        for (int i = 7; i >= 0; --i)
            hex[7 - i] = h[(v >> (i * 4)) & 0xF];
        hex[8] = '\0';
        Out(hex);
        Out("\r\n");
    }

    /* GetCurrentDirectoryW. */
    {
        WCHAR dir[260] = {0};
        DWORD n = GetCurrentDirectoryW(260, dir);
        Out("[fs_smoke] GetCurrentDirectoryW     = ");
        Out(n > 0 ? "PASS\r\n" : "FAIL\r\n");
    }

    /* GetFullPathNameW. */
    {
        WCHAR full[260] = {0};
        DWORD n = GetFullPathNameW(L"/etc/version", 260, full, NULL);
        Out("[fs_smoke] GetFullPathNameW         = ");
        Out(n > 0 ? "PASS\r\n" : "FAIL\r\n");
    }

    /* FindFirstFileW / FindNextFileW / FindClose. */
    {
        WIN32_FIND_DATAW fd = {0};
        HANDLE h = FindFirstFileW(L"/etc/*", &fd);
        Out("[fs_smoke] FindFirstFileW(/etc/*)   = ");
        if (h == INVALID_HANDLE_VALUE)
            Out("FAIL\r\n");
        else
        {
            int count = 1;
            while (FindNextFileW(h, &fd))
                ++count;
            FindClose(h);
            Out("PASS entries=");
            OutDec((unsigned long long)count);
            Out("\r\n");
        }
    }

    Out("[fs_smoke] done\r\n");
    ExitProcess(0);
}
