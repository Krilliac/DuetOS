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

/* Print a UTF-16 path as ASCII-fast (every char fits because all our
 * canonical paths are ASCII). Truncates at MAX_PATH. */
static void OutW(const WCHAR* w)
{
    char buf[MAX_PATH + 1];
    int i = 0;
    for (; i < MAX_PATH && w[i]; ++i)
        buf[i] = (char)w[i];
    buf[i] = 0;
    Out(buf);
}

/* Compare a wide-string path against an ASCII reference. */
static int wstreq_a(const WCHAR* w, const char* a)
{
    int i = 0;
    for (;; ++i)
    {
        if ((char)w[i] != a[i])
            return 0;
        if (a[i] == 0)
            return 1;
    }
}

void __cdecl mainCRTStartup(void)
{
    Out("[shell_smoke] starting\r\n");

    /* SHGetFolderPathW for CSIDL_WINDOWS. */
    {
        WCHAR path[MAX_PATH] = {0};
        HRESULT r = SHGetFolderPathW(NULL, CSIDL_WINDOWS, NULL, 0, path);
        Out("[shell_smoke] SHGetFolderPathW(WIN) = ");
        if (SUCCEEDED(r))
        {
            Out(wstreq_a(path, "X:\\Windows") ? "PASS " : "FAIL ");
            OutW(path);
            Out("\r\n");
        }
        else
        {
            Out("FAIL/STUB\r\n");
        }
    }

    /* SHGetFolderPathW(CSIDL_APPDATA) — the slice that the
     * surface-status doc explicitly calls out. */
    {
        WCHAR path[MAX_PATH] = {0};
        HRESULT r = SHGetFolderPathW(NULL, CSIDL_APPDATA, NULL, 0, path);
        Out("[shell_smoke] SHGetFolderPathW(APPDATA) = ");
        if (SUCCEEDED(r))
        {
            Out(wstreq_a(path, "X:\\Users\\duetos\\AppData\\Roaming") ? "PASS " : "FAIL ");
            OutW(path);
            Out("\r\n");
        }
        else
        {
            Out("FAIL/STUB\r\n");
        }
    }

    /* CSIDL_LOCAL_APPDATA must produce a distinct path. */
    {
        WCHAR path[MAX_PATH] = {0};
        HRESULT r = SHGetFolderPathW(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, path);
        Out("[shell_smoke] SHGetFolderPathW(LOCAL_APPDATA) = ");
        if (SUCCEEDED(r))
        {
            Out(wstreq_a(path, "X:\\Users\\duetos\\AppData\\Local") ? "PASS " : "FAIL ");
            OutW(path);
            Out("\r\n");
        }
        else
        {
            Out("FAIL/STUB\r\n");
        }
    }

    /* SHGetSpecialFolderPathW(CSIDL_PROGRAM_FILES). */
    {
        WCHAR path[MAX_PATH] = {0};
        BOOL r = SHGetSpecialFolderPathW(NULL, path, CSIDL_PROGRAM_FILES, FALSE);
        Out("[shell_smoke] SHGetSpecialFolderPathW(PROGRAM_FILES) = ");
        if (r)
        {
            Out(wstreq_a(path, "X:\\Program Files") ? "PASS " : "FAIL ");
            OutW(path);
            Out("\r\n");
        }
        else
        {
            Out("FAIL/STUB\r\n");
        }
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
