/*
 * userland/apps/windowed_hello/hello.c
 *
 * First DuetOS userland program that creates a real window on
 * the kernel compositor via user32!CreateWindowExA. Proves the
 * windowing v0 slice works end-to-end:
 *   1. PE loader maps the binary.
 *   2. Import resolver binds CreateWindowExA / ShowWindow /
 *      MessageBoxA / Sleep / ExitProcess to their translator
 *      DLL exports (user32.dll, kernel32.dll).
 *   3. user32!CreateWindowExA issues SYS_WIN_CREATE (58) which
 *      WindowRegisters the rect in the kernel compositor.
 *   4. ShowWindow issues SYS_WIN_SHOW (60) which raises +
 *      composes — the window appears on screen at the next
 *      paint.
 *   5. MessageBoxA issues SYS_WIN_MSGBOX (61) which logs the
 *      text + caption to the serial console.
 *   6. Sleep parks the process so the window stays on-screen
 *      long enough for the screenshot script to capture it.
 *   7. ExitProcess(0x57) leaves a distinct exit code so the
 *      boot log makes clear which fixture printed what.
 *
 * Expected serial-log signature:
 *   [msgbox] pid=... caption="Windowed Hello" text="Running on DuetOS!"
 *   [win] create pid=... hwnd=N rect=(x,y WxH) title="Windowed Hello"
 *   [I] sys : exit rc val=0x57
 */

typedef void* HANDLE;
typedef unsigned int DWORD;
typedef unsigned int UINT;
typedef int BOOL;

#define CW_USEDEFAULT ((int)0x80000000)
#define SW_SHOW 5
#define WS_OVERLAPPEDWINDOW 0x00CF0000u

__declspec(dllimport) HANDLE __stdcall CreateWindowExA(DWORD dwExStyle, const char* lpClassName,
                                                       const char* lpWindowName, DWORD dwStyle, int x, int y,
                                                       int nWidth, int nHeight, HANDLE hWndParent, HANDLE hMenu,
                                                       HANDLE hInstance, void* lpParam);
__declspec(dllimport) BOOL __stdcall ShowWindow(HANDLE hWnd, int nCmdShow);
__declspec(dllimport) int __stdcall MessageBoxA(HANDLE hWnd, const char* lpText, const char* lpCaption, UINT uType);
__declspec(dllimport) void __stdcall Sleep(DWORD dwMilliseconds);
__declspec(dllimport) void __stdcall ExitProcess(unsigned int uExitCode);

void mainCRTStartup(void)
{
    /* Emit a [msgbox] record first so the serial log carries a
     * "we got here" marker before anything can go wrong in the
     * compositor path. */
    MessageBoxA(0, "Running on DuetOS!", "Windowed Hello", 0);

    /* Create a window. Fixed geometry (not CW_USEDEFAULT) so the
     * result is visually deterministic in the screenshot. */
    HANDLE hwnd = CreateWindowExA(0, "DuetWindow", "WINDOWED HELLO", WS_OVERLAPPEDWINDOW,
                                  /* x */ 500,
                                  /* y */ 400,
                                  /* w */ 420,
                                  /* h */ 220,
                                  /* parent */ 0,
                                  /* menu */ 0,
                                  /* hinstance */ 0,
                                  /* lpparam */ 0);

    /* Map it onto the compositor. v0's ShowWindow unconditionally
     * raises + composes, so this also forces the first visible
     * paint. */
    if (hwnd)
    {
        ShowWindow(hwnd, SW_SHOW);
    }

    /* Park for long enough that the screenshot script's settle
     * window (DUETOS_SETTLE=5s default) captures the window on
     * screen. After that we exit cleanly with a distinctive
     * exit code. */
    Sleep(20000);

    ExitProcess(0x57);
}
