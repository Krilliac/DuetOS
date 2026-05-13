/*
 * userland/libs/user32_32/user32_32.c
 *
 * Freestanding DuetOS user32.dll (i386 / PE32 variant). v0 contains
 * safe-ignore stubs for the most-imported user32 exports a typical
 * Win32 GUI PE32 references. Every function:
 *   - returns 0 (or a benign sentinel) — caller's error path runs
 *   - has __stdcall so the callee pops the right number of args
 *
 * Real implementations land slice-by-slice as the GUI subsystem
 * grows a 32-bit story.
 *
 * Built as PE32 (Machine=0x014C, OptHdrMagic=0x10B). Export Directory
 * Name field = "user32.dll" (from /out: basename).
 */

typedef unsigned int DWORD;
typedef unsigned int UINT;
typedef int INT;
typedef int BOOL;
typedef void* HANDLE;
typedef HANDLE HWND;
typedef HANDLE HDC;
typedef HANDLE HMENU;
typedef HANDLE HICON;
typedef HANDLE HCURSOR;
typedef HANDLE HINSTANCE;
typedef unsigned long ULONG_PTR;
typedef long LONG;
typedef short SHORT;
typedef unsigned short USHORT;
typedef unsigned short wchar_t16;
typedef int LRESULT;
typedef unsigned LPARAM;
typedef unsigned WPARAM;

/* Minimal stub macro: __stdcall fn that takes any args and returns 0. */
#define USER32_STUB_DEF(name, ret_t, ...)                                                                              \
    __declspec(dllexport) ret_t __stdcall name(__VA_ARGS__)                                                            \
    {                                                                                                                  \
        return (ret_t)0;                                                                                               \
    }

/* Window lifecycle (return INVALID_HANDLE_VALUE sentinel where a
 * NULL HWND would crash the caller). */
__declspec(dllexport) HWND __stdcall CreateWindowExA(DWORD a, const char* b, const char* c, DWORD d, int e, int f,
                                                     int g, int h, HWND i, HMENU j, HINSTANCE k, void* l)
{
    (void)a;
    (void)b;
    (void)c;
    (void)d;
    (void)e;
    (void)f;
    (void)g;
    (void)h;
    (void)i;
    (void)j;
    (void)k;
    (void)l;
    return (HWND)0;
}

__declspec(dllexport) HWND __stdcall CreateWindowExW(DWORD a, const wchar_t16* b, const wchar_t16* c, DWORD d, int e,
                                                     int f, int g, int h, HWND i, HMENU j, HINSTANCE k, void* l)
{
    (void)a;
    (void)b;
    (void)c;
    (void)d;
    (void)e;
    (void)f;
    (void)g;
    (void)h;
    (void)i;
    (void)j;
    (void)k;
    (void)l;
    return (HWND)0;
}

__declspec(dllexport) BOOL __stdcall DestroyWindow(HWND h)
{
    (void)h;
    return 1;
}

__declspec(dllexport) BOOL __stdcall ShowWindow(HWND h, INT n)
{
    (void)h;
    (void)n;
    return 1;
}

__declspec(dllexport) BOOL __stdcall UpdateWindow(HWND h)
{
    (void)h;
    return 1;
}

/* Message-loop stubs. PeekMessage returning FALSE means "no message"
 * which keeps the caller's loop quiet. GetMessage returning 0 (= WM_QUIT)
 * cleanly exits the message loop. */
__declspec(dllexport) BOOL __stdcall PeekMessageA(void* lpMsg, HWND hWnd, UINT a, UINT b, UINT remove)
{
    (void)lpMsg;
    (void)hWnd;
    (void)a;
    (void)b;
    (void)remove;
    return 0;
}

__declspec(dllexport) BOOL __stdcall PeekMessageW(void* lpMsg, HWND hWnd, UINT a, UINT b, UINT remove)
{
    return PeekMessageA(lpMsg, hWnd, a, b, remove);
}

__declspec(dllexport) BOOL __stdcall GetMessageA(void* lpMsg, HWND hWnd, UINT a, UINT b)
{
    (void)lpMsg;
    (void)hWnd;
    (void)a;
    (void)b;
    return 0;
}

__declspec(dllexport) BOOL __stdcall GetMessageW(void* lpMsg, HWND hWnd, UINT a, UINT b)
{
    return GetMessageA(lpMsg, hWnd, a, b);
}

__declspec(dllexport) BOOL __stdcall TranslateMessage(const void* lpMsg)
{
    (void)lpMsg;
    return 0;
}

__declspec(dllexport) LRESULT __stdcall DispatchMessageA(const void* lpMsg)
{
    (void)lpMsg;
    return 0;
}

__declspec(dllexport) LRESULT __stdcall DispatchMessageW(const void* lpMsg)
{
    return DispatchMessageA(lpMsg);
}

__declspec(dllexport) void __stdcall PostQuitMessage(int code)
{
    (void)code;
}

__declspec(dllexport) BOOL __stdcall PostMessageA(HWND a, UINT b, WPARAM c, LPARAM d)
{
    (void)a;
    (void)b;
    (void)c;
    (void)d;
    return 0;
}

__declspec(dllexport) BOOL __stdcall PostMessageW(HWND a, UINT b, WPARAM c, LPARAM d)
{
    return PostMessageA(a, b, c, d);
}

__declspec(dllexport) LRESULT __stdcall SendMessageA(HWND a, UINT b, WPARAM c, LPARAM d)
{
    (void)a;
    (void)b;
    (void)c;
    (void)d;
    return 0;
}

__declspec(dllexport) LRESULT __stdcall SendMessageW(HWND a, UINT b, WPARAM c, LPARAM d)
{
    return SendMessageA(a, b, c, d);
}

/* Default window procs: return 0. */
__declspec(dllexport) LRESULT __stdcall DefWindowProcA(HWND a, UINT b, WPARAM c, LPARAM d)
{
    (void)a;
    (void)b;
    (void)c;
    (void)d;
    return 0;
}

__declspec(dllexport) LRESULT __stdcall DefWindowProcW(HWND a, UINT b, WPARAM c, LPARAM d)
{
    return DefWindowProcA(a, b, c, d);
}

/* Class registration. Return non-zero atom so RegisterClass doesn't
 * appear to fail. */
__declspec(dllexport) USHORT __stdcall RegisterClassA(const void* lpWndClass)
{
    (void)lpWndClass;
    return 1;
}

__declspec(dllexport) USHORT __stdcall RegisterClassW(const void* lpWndClass)
{
    return RegisterClassA(lpWndClass);
}

__declspec(dllexport) USHORT __stdcall RegisterClassExA(const void* lpWndClass)
{
    return RegisterClassA(lpWndClass);
}

__declspec(dllexport) USHORT __stdcall RegisterClassExW(const void* lpWndClass)
{
    return RegisterClassA(lpWndClass);
}

__declspec(dllexport) BOOL __stdcall UnregisterClassA(const char* lpClassName, HINSTANCE hInst)
{
    (void)lpClassName;
    (void)hInst;
    return 1;
}

__declspec(dllexport) BOOL __stdcall UnregisterClassW(const wchar_t16* lpClassName, HINSTANCE hInst)
{
    (void)lpClassName;
    (void)hInst;
    return 1;
}

/* MessageBox returns IDOK (1). */
__declspec(dllexport) int __stdcall MessageBoxA(HWND owner, const char* text, const char* caption, UINT type)
{
    (void)owner;
    (void)text;
    (void)caption;
    (void)type;
    return 1; /* IDOK */
}

__declspec(dllexport) int __stdcall MessageBoxW(HWND owner, const wchar_t16* text, const wchar_t16* caption, UINT type)
{
    (void)owner;
    (void)text;
    (void)caption;
    (void)type;
    return 1;
}

/* Resource loaders return non-null sentinel handles. */
__declspec(dllexport) HICON __stdcall LoadIconA(HINSTANCE h, const char* n)
{
    (void)h;
    (void)n;
    return (HICON)1;
}

__declspec(dllexport) HICON __stdcall LoadIconW(HINSTANCE h, const wchar_t16* n)
{
    (void)h;
    (void)n;
    return (HICON)1;
}

__declspec(dllexport) HCURSOR __stdcall LoadCursorA(HINSTANCE h, const char* n)
{
    (void)h;
    (void)n;
    return (HCURSOR)2;
}

__declspec(dllexport) HCURSOR __stdcall LoadCursorW(HINSTANCE h, const wchar_t16* n)
{
    (void)h;
    (void)n;
    return (HCURSOR)2;
}

/* GetDC / ReleaseDC. v0: sentinel HDC. */
__declspec(dllexport) HDC __stdcall GetDC(HWND h)
{
    (void)h;
    return (HDC)0;
}

__declspec(dllexport) int __stdcall ReleaseDC(HWND h, HDC dc)
{
    (void)h;
    (void)dc;
    return 1;
}

/* Window rects. Zero everything. */
__declspec(dllexport) BOOL __stdcall GetClientRect(HWND h, void* lpRect)
{
    (void)h;
    if (lpRect)
    {
        unsigned char* p = (unsigned char*)lpRect;
        for (int i = 0; i < 16; ++i)
            p[i] = 0;
    }
    return 1;
}

__declspec(dllexport) BOOL __stdcall GetWindowRect(HWND h, void* lpRect)
{
    return GetClientRect(h, lpRect);
}

__declspec(dllexport) HWND __stdcall GetDesktopWindow(void)
{
    return (HWND)0x10001;
}

/* Common safe-ignore shims. */
__declspec(dllexport) int __stdcall GetSystemMetrics(int idx)
{
    /* v0 reports a fake 1024x768 desktop and reasonable defaults
     * for the most-queried metrics. */
    switch (idx)
    {
    case 0:
        return 1024; /* SM_CXSCREEN */
    case 1:
        return 768; /* SM_CYSCREEN */
    case 32:
        return 8; /* SM_CXFRAME */
    case 33:
        return 8; /* SM_CYFRAME */
    default:
        return 0;
    }
}

__declspec(dllexport) BOOL __stdcall InvalidateRect(HWND h, const void* lpRect, BOOL bErase)
{
    (void)h;
    (void)lpRect;
    (void)bErase;
    return 1;
}

__declspec(dllexport) BOOL __stdcall ValidateRect(HWND h, const void* lpRect)
{
    (void)h;
    (void)lpRect;
    return 1;
}

__declspec(dllexport) BOOL __stdcall ScreenToClient(HWND h, void* pt)
{
    (void)h;
    (void)pt;
    return 1;
}

__declspec(dllexport) BOOL __stdcall ClientToScreen(HWND h, void* pt)
{
    (void)h;
    (void)pt;
    return 1;
}

/* Caret stubs. */
__declspec(dllexport) BOOL __stdcall CreateCaret(HWND h, HANDLE bmp, int w, int hgt)
{
    (void)h;
    (void)bmp;
    (void)w;
    (void)hgt;
    return 1;
}

__declspec(dllexport) BOOL __stdcall DestroyCaret(void)
{
    return 1;
}

__declspec(dllexport) BOOL __stdcall SetCaretPos(int x, int y)
{
    (void)x;
    (void)y;
    return 1;
}

__declspec(dllexport) BOOL __stdcall ShowCaret(HWND h)
{
    (void)h;
    return 1;
}

__declspec(dllexport) BOOL __stdcall HideCaret(HWND h)
{
    (void)h;
    return 1;
}

__declspec(dllexport) UINT __stdcall GetCaretBlinkTime(void)
{
    return 500;
}

__declspec(dllexport) BOOL __stdcall SetCaretBlinkTime(UINT msec)
{
    (void)msec;
    return 1;
}

/* Paint stubs. BeginPaint/EndPaint pair: BeginPaint returns a fake HDC,
 * EndPaint is a no-op. */
__declspec(dllexport) HDC __stdcall BeginPaint(HWND h, void* ps)
{
    (void)h;
    (void)ps;
    return (HDC)0;
}

__declspec(dllexport) BOOL __stdcall EndPaint(HWND h, const void* ps)
{
    (void)h;
    (void)ps;
    return 1;
}

/* Clipboard stubs. */
__declspec(dllexport) BOOL __stdcall OpenClipboard(HWND h)
{
    (void)h;
    return 0;
}

__declspec(dllexport) BOOL __stdcall CloseClipboard(void)
{
    return 0;
}

__declspec(dllexport) HANDLE __stdcall GetClipboardData(UINT fmt)
{
    (void)fmt;
    return 0;
}

__declspec(dllexport) HANDLE __stdcall SetClipboardData(UINT fmt, HANDLE data)
{
    (void)fmt;
    (void)data;
    return 0;
}

__declspec(dllexport) BOOL __stdcall EmptyClipboard(void)
{
    return 1;
}

/* Cursor / window-focus stubs. */
__declspec(dllexport) BOOL __stdcall SetCursorPos(int x, int y)
{
    (void)x;
    (void)y;
    return 1;
}

__declspec(dllexport) HCURSOR __stdcall SetCursor(HCURSOR hcur)
{
    (void)hcur;
    return 0;
}

__declspec(dllexport) HWND __stdcall GetFocus(void)
{
    return 0;
}

__declspec(dllexport) HWND __stdcall SetFocus(HWND h)
{
    (void)h;
    return 0;
}

__declspec(dllexport) HWND __stdcall GetActiveWindow(void)
{
    return 0;
}

__declspec(dllexport) HWND __stdcall SetActiveWindow(HWND h)
{
    (void)h;
    return 0;
}

__declspec(dllexport) HWND __stdcall GetForegroundWindow(void)
{
    return 0;
}

__declspec(dllexport) BOOL __stdcall SetForegroundWindow(HWND h)
{
    (void)h;
    return 1;
}
