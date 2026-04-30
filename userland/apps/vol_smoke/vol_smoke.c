/*
 * vol_smoke — exercise volume / disk-space APIs.
 *
 *   GetVolumeInformationW
 *   GetDiskFreeSpaceW / GetDiskFreeSpaceExW
 *   GetDriveTypeW
 *   GetLogicalDrives
 *   GetLogicalDriveStringsA
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
    Out("[vol_smoke] starting\r\n");

    DWORD drives = GetLogicalDrives();
    Out("[vol_smoke] GetLogicalDrives    = ");
    Out(drives != 0 ? "PASS\r\n" : "FAIL/STUB\r\n");

    /* GetLogicalDriveStringsA. */
    {
        char buf[128] = {0};
        DWORD n = GetLogicalDriveStringsA(128, buf);
        Out("[vol_smoke] GetLogicalDriveStringsA = ");
        Out(n > 0 ? "PASS\r\n" : "FAIL/STUB\r\n");
    }

    /* GetDriveTypeW on C:\\ */
    {
        UINT t = GetDriveTypeW(L"C:\\");
        Out("[vol_smoke] GetDriveTypeW       = ");
        Out(t != DRIVE_UNKNOWN && t != DRIVE_NO_ROOT_DIR ? "PASS\r\n" : "FAIL/STUB\r\n");
    }

    /* GetVolumeInformationW. */
    {
        WCHAR vol[64] = {0};
        WCHAR fs[64] = {0};
        DWORD serial = 0, max_comp = 0, fs_flags = 0;
        BOOL ok = GetVolumeInformationW(L"C:\\", vol, 64, &serial, &max_comp, &fs_flags, fs, 64);
        Out("[vol_smoke] GetVolumeInformationW = ");
        Out(ok ? "PASS\r\n" : "FAIL/STUB\r\n");
    }

    /* GetDiskFreeSpaceExW. */
    {
        ULARGE_INTEGER avail = {0}, total = {0}, free = {0};
        BOOL ok = GetDiskFreeSpaceExW(L"C:\\", &avail, &total, &free);
        Out("[vol_smoke] GetDiskFreeSpaceExW = ");
        Out(ok ? "PASS\r\n" : "FAIL/STUB\r\n");
    }

    Out("[vol_smoke] done\r\n");
    ExitProcess(0);
}
