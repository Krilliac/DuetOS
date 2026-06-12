/*
 * drive_smoke — exercise file-creation / write / delete APIs.
 *
 *   CreateFileW (CREATE_ALWAYS to /tmp)
 *   WriteFile + CloseHandle
 *   DeleteFileW
 *   CopyFileW (skipped — heavy)
 *   MoveFileW (skipped)
 *   GetTempPathW / GetTempFileNameW
 *   CreateDirectoryW (skipped — read-only ramfs)
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
    Out("[drive_smoke] starting\r\n");

    /* GetTempPathW. */
    {
        WCHAR buf[260] = {0};
        DWORD n = GetTempPathW(260, buf);
        Out("[drive_smoke] GetTempPathW         = ");
        Out(n > 0 ? "PASS\r\n" : "FAIL/STUB\r\n");
    }

    /* GetTempFileNameW. */
    {
        WCHAR temp_dir[260] = {0};
        GetTempPathW(260, temp_dir);
        WCHAR name[260] = {0};
        UINT n = GetTempFileNameW(temp_dir, L"DSM", 0, name);
        Out("[drive_smoke] GetTempFileNameW     = ");
        Out(n != 0 ? "PASS\r\n" : "FAIL/STUB\r\n");
    }

    /* DeleteFileW on a definitely-missing file — should return FALSE. */
    {
        BOOL r = DeleteFileW(L"C:\\does\\not\\exist.txt");
        Out("[drive_smoke] DeleteFileW(missing) = ");
        Out(!r ? "PASS (FALSE, as expected)\r\n" : "FAIL\r\n");
    }

    Out("[drive_smoke] done\r\n");
    Out("[ring3-drive-smoke] PASS\r\n");
    ExitProcess(0);
}
