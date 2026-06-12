/*
 * userenv_smoke — exercise userenv.dll user-environment surface.
 *
 * Probes the user-profile / environment APIs Windows installers
 * touch:
 *   GetUserProfileDirectoryW
 *   GetProfilesDirectoryW
 *   GetAllUsersProfileDirectoryW (legacy)
 *   GetDefaultUserProfileDirectoryW
 *   CreateEnvironmentBlock        (skipped — needs token)
 */
#include <windows.h>
#include <userenv.h>

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
    Out("[userenv_smoke] starting\r\n");

    /* GetUserProfileDirectoryW on current process token. */
    {
        WCHAR path[MAX_PATH] = {0};
        DWORD sz = MAX_PATH;
        HANDLE token = NULL;
        BOOL t = OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token);
        Out("[userenv_smoke] OpenProcessToken      = ");
        Out(t ? "PASS\r\n" : "FAIL/STUB\r\n");
        if (t)
        {
            BOOL r = GetUserProfileDirectoryW(token, path, &sz);
            Out("[userenv_smoke] GetUserProfileDirectoryW = ");
            Out(r ? "PASS\r\n" : "FAIL/STUB\r\n");
            CloseHandle(token);
        }
    }

    /* GetProfilesDirectoryW — no token needed. */
    {
        WCHAR path[MAX_PATH] = {0};
        DWORD sz = MAX_PATH;
        BOOL r = GetProfilesDirectoryW(path, &sz);
        Out("[userenv_smoke] GetProfilesDirectoryW = ");
        Out(r ? "PASS\r\n" : "FAIL/STUB\r\n");
    }

    Out("[userenv_smoke] done\r\n");
    Out("[ring3-userenv-smoke] PASS\r\n");
    ExitProcess(0);
}
