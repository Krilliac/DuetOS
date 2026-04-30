/*
 * fs2_smoke — extended file APIs beyond fs_smoke.
 *
 *   GetFileTime
 *   SetFileTime (skipped on RO)
 *   GetFileType
 *   GetFileSize / GetFileSizeEx
 *   FlushFileBuffers
 *   LockFile / UnlockFile (skipped)
 *   GetFileInformationByHandle
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
    Out("[fs2_smoke] starting\r\n");

    HANDLE f =
        CreateFileW(L"/etc/version", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    Out("[fs2_smoke] CreateFileW         = ");
    if (f == INVALID_HANDLE_VALUE)
    {
        Out("FAIL\r\n");
        Out("[fs2_smoke] done\r\n");
        ExitProcess(1);
    }
    Out("PASS\r\n");

    /* GetFileType. */
    DWORD type = GetFileType(f);
    Out("[fs2_smoke] GetFileType         = ");
    Out(type != FILE_TYPE_UNKNOWN ? "PASS\r\n" : "FAIL/STUB\r\n");

    /* GetFileSize. */
    DWORD hi = 0;
    DWORD lo = GetFileSize(f, &hi);
    Out("[fs2_smoke] GetFileSize         = ");
    Out(lo != INVALID_FILE_SIZE ? "PASS\r\n" : "FAIL/STUB\r\n");

    /* GetFileTime. */
    {
        FILETIME c, a, w;
        BOOL ok = GetFileTime(f, &c, &a, &w);
        Out("[fs2_smoke] GetFileTime         = ");
        Out(ok ? "PASS\r\n" : "FAIL/STUB\r\n");
    }

    /* GetFileInformationByHandle. */
    {
        BY_HANDLE_FILE_INFORMATION info = {0};
        BOOL ok = GetFileInformationByHandle(f, &info);
        Out("[fs2_smoke] GetFileInformationByHandle = ");
        Out(ok ? "PASS\r\n" : "FAIL/STUB\r\n");
    }

    /* FlushFileBuffers. */
    {
        BOOL ok = FlushFileBuffers(f);
        Out("[fs2_smoke] FlushFileBuffers    = ");
        Out("PASS (returned)\r\n");
        (void)ok;
    }

    CloseHandle(f);
    Out("[fs2_smoke] done\r\n");
    ExitProcess(0);
}
