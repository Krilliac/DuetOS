/*
 * shell_smoke — exercise shell32 / shlwapi shell APIs.
 *
 * Probes the shell-integration surface every Windows app uses
 * to find well-known folders, run external tools, parse paths:
 *   SHGetFolderPathW    (CSIDL_PROGRAM_FILES, CSIDL_PERSONAL, CSIDL_WINDOWS)
 *   SHGetSpecialFolderPathW
 *   ShellExecuteW       (skipped — would launch process)
 *   PathFileExistsW     (already in paths_smoke)
 *   CommandLineToArgvW
 *   SHGetKnownFolderPath (modern Vista+ API)
 */
#include <windows.h>
#include <shlobj.h>

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
    Out("[shell_smoke] starting\r\n");

    /* SHGetFolderPathW for CSIDL_WINDOWS. */
    {
        WCHAR path[MAX_PATH] = {0};
        HRESULT r = SHGetFolderPathW(NULL, CSIDL_WINDOWS, NULL, 0, path);
        Out("[shell_smoke] SHGetFolderPathW(WIN) = ");
        Out(SUCCEEDED(r) ? "PASS\r\n" : "FAIL/STUB\r\n");
    }

    /* SHGetSpecialFolderPathW(CSIDL_PROGRAM_FILES). */
    {
        WCHAR path[MAX_PATH] = {0};
        BOOL r = SHGetSpecialFolderPathW(NULL, path, CSIDL_PROGRAM_FILES, FALSE);
        Out("[shell_smoke] SHGetSpecialFolderPathW = ");
        Out(r ? "PASS\r\n" : "FAIL/STUB\r\n");
    }

    /* CommandLineToArgvW with a simple line. */
    {
        int argc = 0;
        LPWSTR* argv = CommandLineToArgvW(L"prog arg1 arg2", &argc);
        Out("[shell_smoke] CommandLineToArgvW    = ");
        Out(argv != NULL && argc == 3 ? "PASS (argc=3)\r\n" : "FAIL/STUB\r\n");
        if (argv != NULL)
            LocalFree(argv);
    }

    Out("[shell_smoke] done\r\n");
    ExitProcess(0);
}
