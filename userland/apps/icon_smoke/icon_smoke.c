/*
 * icon_smoke — PE32 (i386) test image for the icon / cursor resource
 * loading rung. Has a genuine .rsrc section with a 16x16 icon compiled
 * by windres, and exercises LoadIconW, LoadCursorW and LoadImageW to
 * prove the real RT_GROUP_ICON -> RT_ICON decode path works end-to-end
 * from ring 3 via the IAT.
 *
 * What each step proves:
 *
 *   1. LoadIconW(NULL, IDI_APPLICATION) returns non-NULL (system icon).
 *   2. LoadIconW(hInst, MAKEINTRESOURCE(1)) returns non-NULL (PE icon).
 *   3. LoadCursorW(NULL, IDC_ARROW) returns non-NULL (system cursor).
 *   4. LoadImageW(NULL, IDI_APPLICATION, IMAGE_ICON, 0, 0, 0) returns
 *      non-NULL (LoadImage dispatch).
 *
 * Built with i686-w64-mingw32-gcc + i686-w64-mingw32-windres,
 * freestanding, entry mainCRTStartup.
 */

typedef void* HANDLE;
typedef unsigned long DWORD;
typedef unsigned int UINT;
typedef int BOOL;
typedef int INT;
typedef unsigned short WCHAR;

#define STD_OUTPUT_HANDLE ((DWORD) - 11)
#define MAKEINTRESOURCEW(i) ((const WCHAR*)(unsigned long)(unsigned short)(i))
#define IDI_APPLICATION MAKEINTRESOURCEW(32512)
#define IDC_ARROW MAKEINTRESOURCEW(32512)
#define IMAGE_ICON 1

/* kernel32 */
__declspec(dllimport) void __stdcall ExitProcess(unsigned);
__declspec(dllimport) HANDLE __stdcall GetStdHandle(DWORD);
__declspec(dllimport) BOOL __stdcall WriteConsoleA(HANDLE, const void*, DWORD, DWORD*, void*);
__declspec(dllimport) HANDLE __stdcall GetModuleHandleW(const WCHAR*);

/* user32 */
__declspec(dllimport) HANDLE __stdcall LoadIconW(HANDLE, const WCHAR*);
__declspec(dllimport) HANDLE __stdcall LoadCursorW(HANDLE, const WCHAR*);
__declspec(dllimport) HANDLE __stdcall LoadImageW(HANDLE, const WCHAR*, UINT, int, int, UINT);

static int g_failures = 0;

static void Out(const char* s)
{
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD n = 0;
    DWORD len = 0;
    while (s[len] != '\0')
        ++len;
    WriteConsoleA(h, s, len, &n, 0);
}

static void Check(const char* what, int ok)
{
    Out("[icon_smoke] ");
    Out(what);
    Out(ok ? " = PASS\r\n" : " = FAIL\r\n");
    if (!ok)
        ++g_failures;
}

void __cdecl mainCRTStartup(void)
{
    HANDLE me = GetModuleHandleW(0);

    Out("[icon_smoke] starting\r\n");

    /* 1. System icon. */
    {
        HANDLE h = LoadIconW(0, IDI_APPLICATION);
        Check("LoadIconW(sys)      ", h != 0);
    }

    /* 2. PE icon (id 1 from icon_smoke.rc). */
    {
        HANDLE h = LoadIconW(me, MAKEINTRESOURCEW(1));
        Check("LoadIconW(pe)       ", h != 0);
    }

    /* 3. System cursor. */
    {
        HANDLE h = LoadCursorW(0, IDC_ARROW);
        Check("LoadCursorW(sys)    ", h != 0);
    }

    /* 4. LoadImageW dispatch for IMAGE_ICON. */
    {
        HANDLE h = LoadImageW(0, IDI_APPLICATION, IMAGE_ICON, 0, 0, 0);
        Check("LoadImageW(icon)    ", h != 0);
    }

    if (g_failures == 0)
        Out("[ring3-icon-smoke] PASS\r\n");
    else
        Out("[ring3-icon-smoke] FAIL icon checks did not all pass\r\n");
    ExitProcess(g_failures == 0 ? 0x42 : 1);
}
