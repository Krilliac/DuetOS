/*
 * userland/libs/user32/user32.c — 73 window-manager stubs.
 *
 * Windows programs that are console-only but import user32 for
 * MessageBox or GetSystemMetrics typically NULL-check and fall
 * back. v0 reports "no window / no input / no clipboard" for
 * everything.
 *
 * Critical quirk:
 *   - GetMessage / PeekMessage MUST NOT return a random
 *     positive value — callers loop on truthy. We return 0 for
 *     GetMessage (WM_QUIT) and FALSE for PeekMessage.
 *   - DefWindowProcA/W returns 0 (caller accepts).
 *   - PostQuitMessage is a no-op.
 */

typedef int            BOOL;
typedef unsigned int   UINT;
typedef unsigned int   DWORD;
typedef unsigned long long LRESULT;
typedef unsigned long long WPARAM;
typedef unsigned long long LPARAM;
typedef unsigned short wchar_t16;
typedef void*          HANDLE;

/* --- Message pump --- */

__declspec(dllexport) LRESULT CallWindowProcA(void* proc, HANDLE h, UINT msg, WPARAM w, LPARAM l)
{
    (void) proc; (void) h; (void) msg; (void) w; (void) l;
    return 0;
}
__declspec(dllexport) LRESULT CallWindowProcW(void* proc, HANDLE h, UINT msg, WPARAM w, LPARAM l)
{ (void) proc; (void) h; (void) msg; (void) w; (void) l; return 0; }
__declspec(dllexport) LRESULT DefWindowProcA(HANDLE h, UINT msg, WPARAM w, LPARAM l)
{ (void) h; (void) msg; (void) w; (void) l; return 0; }
__declspec(dllexport) LRESULT DefWindowProcW(HANDLE h, UINT msg, WPARAM w, LPARAM l)
{ (void) h; (void) msg; (void) w; (void) l; return 0; }

/* Message pump — GetMessage returns 0 (quit); PeekMessage returns FALSE (no messages). */
__declspec(dllexport) BOOL GetMessageA(void* msg, HANDLE h, UINT min, UINT max)
{ (void) msg; (void) h; (void) min; (void) max; return 0; }
__declspec(dllexport) BOOL GetMessageW(void* msg, HANDLE h, UINT min, UINT max)
{ (void) msg; (void) h; (void) min; (void) max; return 0; }
__declspec(dllexport) BOOL PeekMessageA(void* msg, HANDLE h, UINT min, UINT max, UINT flags)
{ (void) msg; (void) h; (void) min; (void) max; (void) flags; return 0; }
__declspec(dllexport) BOOL PeekMessageW(void* msg, HANDLE h, UINT min, UINT max, UINT flags)
{ (void) msg; (void) h; (void) min; (void) max; (void) flags; return 0; }
__declspec(dllexport) LRESULT DispatchMessageA(const void* msg) { (void) msg; return 0; }
__declspec(dllexport) LRESULT DispatchMessageW(const void* msg) { (void) msg; return 0; }
__declspec(dllexport) BOOL TranslateMessage(const void* msg) { (void) msg; return 0; }
__declspec(dllexport) BOOL TranslateAcceleratorA(HANDLE h, HANDLE accel, void* msg)
{ (void) h; (void) accel; (void) msg; return 0; }
__declspec(dllexport) BOOL TranslateAcceleratorW(HANDLE h, HANDLE accel, void* msg)
{ (void) h; (void) accel; (void) msg; return 0; }
__declspec(dllexport) void PostQuitMessage(int code) { (void) code; }
__declspec(dllexport) BOOL PostMessageA(HANDLE h, UINT msg, WPARAM w, LPARAM l)
{ (void) h; (void) msg; (void) w; (void) l; return 1; }
__declspec(dllexport) BOOL PostMessageW(HANDLE h, UINT msg, WPARAM w, LPARAM l)
{ (void) h; (void) msg; (void) w; (void) l; return 1; }
__declspec(dllexport) BOOL PostThreadMessageA(DWORD tid, UINT msg, WPARAM w, LPARAM l)
{ (void) tid; (void) msg; (void) w; (void) l; return 1; }
__declspec(dllexport) BOOL PostThreadMessageW(DWORD tid, UINT msg, WPARAM w, LPARAM l)
{ (void) tid; (void) msg; (void) w; (void) l; return 1; }
__declspec(dllexport) LRESULT SendMessageA(HANDLE h, UINT msg, WPARAM w, LPARAM l)
{ (void) h; (void) msg; (void) w; (void) l; return 0; }
__declspec(dllexport) LRESULT SendMessageW(HANDLE h, UINT msg, WPARAM w, LPARAM l)
{ (void) h; (void) msg; (void) w; (void) l; return 0; }

/* --- Window creation / destruction --- */
__declspec(dllexport) HANDLE CreateWindowExA(DWORD ex, const char* cls, const char* name, DWORD style, int x, int y,
                                             int w, int h, HANDLE parent, HANDLE menu, HANDLE hInst, void* param)
{ (void) ex; (void) cls; (void) name; (void) style; (void) x; (void) y; (void) w; (void) h;
  (void) parent; (void) menu; (void) hInst; (void) param; return (HANDLE) 0; }
__declspec(dllexport) HANDLE CreateWindowExW(DWORD ex, const wchar_t16* cls, const wchar_t16* name, DWORD style,
                                             int x, int y, int w, int h, HANDLE parent, HANDLE menu, HANDLE hInst,
                                             void* param)
{ (void) ex; (void) cls; (void) name; (void) style; (void) x; (void) y; (void) w; (void) h;
  (void) parent; (void) menu; (void) hInst; (void) param; return (HANDLE) 0; }
__declspec(dllexport) BOOL DestroyWindow(HANDLE h) { (void) h; return 1; }
__declspec(dllexport) BOOL ShowWindow(HANDLE h, int cmd) { (void) h; (void) cmd; return 0; }
__declspec(dllexport) BOOL UpdateWindow(HANDLE h) { (void) h; return 1; }
__declspec(dllexport) BOOL InvalidateRect(HANDLE h, const void* r, BOOL erase) { (void) h; (void) r; (void) erase; return 1; }
__declspec(dllexport) BOOL MoveWindow(HANDLE h, int x, int y, int w, int ht, BOOL repaint)
{ (void) h; (void) x; (void) y; (void) w; (void) ht; (void) repaint; return 1; }
__declspec(dllexport) BOOL SetWindowPos(HANDLE h, HANDLE after, int x, int y, int w, int ht, UINT flags)
{ (void) h; (void) after; (void) x; (void) y; (void) w; (void) ht; (void) flags; return 1; }
__declspec(dllexport) BOOL IsWindow(HANDLE h) { (void) h; return 0; }
__declspec(dllexport) HANDLE GetActiveWindow(void) { return (HANDLE) 0; }
__declspec(dllexport) HANDLE GetForegroundWindow(void) { return (HANDLE) 0; }
__declspec(dllexport) HANDLE GetDesktopWindow(void) { return (HANDLE) 0; }
__declspec(dllexport) BOOL GetClientRect(HANDLE h, void* r)
{
    (void) h;
    if (r) { unsigned char* b = (unsigned char*) r; for (int i = 0; i < 16; ++i) b[i] = 0; }
    return 1;
}
__declspec(dllexport) BOOL GetWindowRect(HANDLE h, void* r) { return GetClientRect(h, r); }
__declspec(dllexport) HANDLE GetProcessWindowStation(void) { return (HANDLE) 0; }

/* --- Class registration --- */
typedef unsigned short ATOM;
__declspec(dllexport) ATOM RegisterClassA(const void* wc) { (void) wc; return 1; }
__declspec(dllexport) ATOM RegisterClassW(const void* wc) { (void) wc; return 1; }
__declspec(dllexport) ATOM RegisterClassExA(const void* wcex) { (void) wcex; return 1; }
__declspec(dllexport) ATOM RegisterClassExW(const void* wcex) { (void) wcex; return 1; }
__declspec(dllexport) BOOL UnregisterClassA(const char* name, HANDLE hInst) { (void) name; (void) hInst; return 1; }
__declspec(dllexport) BOOL UnregisterClassW(const wchar_t16* name, HANDLE hInst) { (void) name; (void) hInst; return 1; }

/* --- MessageBox --- */
#define IDOK 1

__declspec(dllexport) int MessageBoxA(HANDLE h, const char* text, const char* caption, UINT type)
{ (void) h; (void) text; (void) caption; (void) type; return IDOK; }
__declspec(dllexport) int MessageBoxW(HANDLE h, const wchar_t16* text, const wchar_t16* caption, UINT type)
{ (void) h; (void) text; (void) caption; (void) type; return IDOK; }
__declspec(dllexport) int MessageBoxExA(HANDLE h, const char* text, const char* caption, UINT type, unsigned short lang)
{ (void) h; (void) text; (void) caption; (void) type; (void) lang; return IDOK; }
__declspec(dllexport) int MessageBoxExW(HANDLE h, const wchar_t16* text, const wchar_t16* caption, UINT type, unsigned short lang)
{ (void) h; (void) text; (void) caption; (void) type; (void) lang; return IDOK; }

/* --- Load* family --- */
__declspec(dllexport) HANDLE LoadAcceleratorsA(HANDLE h, const char* name) { (void) h; (void) name; return (HANDLE) 0; }
__declspec(dllexport) HANDLE LoadAcceleratorsW(HANDLE h, const wchar_t16* name) { (void) h; (void) name; return (HANDLE) 0; }
__declspec(dllexport) HANDLE LoadBitmapA(HANDLE h, const char* name) { (void) h; (void) name; return (HANDLE) 0; }
__declspec(dllexport) HANDLE LoadBitmapW(HANDLE h, const wchar_t16* name) { (void) h; (void) name; return (HANDLE) 0; }
__declspec(dllexport) HANDLE LoadCursorA(HANDLE h, const char* name) { (void) h; (void) name; return (HANDLE) 1; }
__declspec(dllexport) HANDLE LoadCursorW(HANDLE h, const wchar_t16* name) { (void) h; (void) name; return (HANDLE) 1; }
__declspec(dllexport) HANDLE LoadIconA(HANDLE h, const char* name) { (void) h; (void) name; return (HANDLE) 1; }
__declspec(dllexport) HANDLE LoadIconW(HANDLE h, const wchar_t16* name) { (void) h; (void) name; return (HANDLE) 1; }
__declspec(dllexport) HANDLE LoadImageA(HANDLE h, const char* name, UINT t, int w, int ht, UINT flags)
{ (void) h; (void) name; (void) t; (void) w; (void) ht; (void) flags; return (HANDLE) 0; }
__declspec(dllexport) HANDLE LoadImageW(HANDLE h, const wchar_t16* name, UINT t, int w, int ht, UINT flags)
{ (void) h; (void) name; (void) t; (void) w; (void) ht; (void) flags; return (HANDLE) 0; }
__declspec(dllexport) HANDLE LoadMenuA(HANDLE h, const char* name) { (void) h; (void) name; return (HANDLE) 0; }
__declspec(dllexport) HANDLE LoadMenuW(HANDLE h, const wchar_t16* name) { (void) h; (void) name; return (HANDLE) 0; }
__declspec(dllexport) int LoadStringA(HANDLE h, UINT id, char* buf, int len)
{ (void) h; (void) id; if (buf && len > 0) buf[0] = 0; return 0; }
__declspec(dllexport) int LoadStringW(HANDLE h, UINT id, wchar_t16* buf, int len)
{ (void) h; (void) id; if (buf && len > 0) buf[0] = 0; return 0; }

/* --- Cursor / clipboard --- */
__declspec(dllexport) BOOL ClipCursor(const void* r) { (void) r; return 1; }
__declspec(dllexport) BOOL GetCursorPos(void* p)
{
    if (p) { int* i = (int*) p; i[0] = 0; i[1] = 0; }
    return 1;
}
__declspec(dllexport) BOOL SetCursorPos(int x, int y) { (void) x; (void) y; return 1; }
__declspec(dllexport) HANDLE SetCursor(HANDLE h) { (void) h; return (HANDLE) 0; }
__declspec(dllexport) int ShowCursor(BOOL show) { (void) show; return 0; }
__declspec(dllexport) BOOL OpenClipboard(HANDLE owner) { (void) owner; return 0; }
__declspec(dllexport) BOOL CloseClipboard(void) { return 1; }
__declspec(dllexport) BOOL EmptyClipboard(void) { return 1; }
__declspec(dllexport) HANDLE GetClipboardData(UINT fmt) { (void) fmt; return (HANDLE) 0; }
__declspec(dllexport) HANDLE SetClipboardData(UINT fmt, HANDLE h) { (void) fmt; (void) h; return (HANDLE) 0; }

/* --- Char helpers --- */
__declspec(dllexport) wchar_t16* CharLowerW(wchar_t16* s)
{
    if (!s) return s;
    for (wchar_t16* p = s; *p; ++p)
        if (*p >= 'A' && *p <= 'Z') *p = (wchar_t16) (*p + ('a' - 'A'));
    return s;
}
__declspec(dllexport) wchar_t16* CharUpperW(wchar_t16* s)
{
    if (!s) return s;
    for (wchar_t16* p = s; *p; ++p)
        if (*p >= 'a' && *p <= 'z') *p = (wchar_t16) (*p - ('a' - 'A'));
    return s;
}

/* --- System metrics --- */
__declspec(dllexport) int GetSystemMetrics(int index)
{
    /* Return 0 for everything — caller either uses the value
     * directly (fine, 0 is "sensible default") or checks != 0. */
    (void) index;
    return 0;
}
__declspec(dllexport) DWORD GetSysColor(int index) { (void) index; return 0xFFFFFFu; /* white */ }
