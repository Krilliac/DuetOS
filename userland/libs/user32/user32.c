/*
 * userland/libs/user32/user32.c — 73 window-manager stubs, with
 * the core create/destroy/show/message-box family bridged to the
 * kernel compositor via SYS_WIN_* (58..61) as of the windowing
 * v0 slice. Message pump (GetMessage / PeekMessage / DispatchMessage)
 * is still a synthetic-WM_QUIT stub — per-window event queues
 * land in a later slice.
 *
 * Critical quirks:
 *   - GetMessage / PeekMessage MUST NOT return a random
 *     positive value — callers loop on truthy. We return 0 for
 *     GetMessage (WM_QUIT) and FALSE for PeekMessage.
 *   - DefWindowProcA/W returns 0 (caller accepts).
 *   - PostQuitMessage is a no-op.
 *   - CreateWindowExA/W now returns a real compositor-backed HWND
 *     so ShowWindow actually paints a window. HWND is a biased
 *     compositor index (+1) so 0 still means failure.
 */

typedef int BOOL;
typedef unsigned int UINT;
typedef unsigned int DWORD;
typedef unsigned long long LRESULT;
typedef unsigned long long WPARAM;
typedef unsigned long long LPARAM;
typedef unsigned short wchar_t16;
typedef void* HANDLE;

/* Syscall numbers duplicated from kernel/core/syscall.h — keeping
 * the two in sync is a manual discipline shared with every other
 * DLL here. Compile-time drift is caught by the stubs' runtime
 * behaviour diverging from spec. */
#define SYS_WIN_CREATE 58
#define SYS_WIN_DESTROY 59
#define SYS_WIN_SHOW 60
#define SYS_WIN_MSGBOX 61

#define WIN_TITLE_MAX 64

/* Translate a UTF-16 title into a fixed ASCII buffer. Non-ASCII
 * code units become '?'. Buffer is always NUL-terminated. Caller
 * owns the buffer; length cap matches kernel-side kWinTitleMax. */
static void win32_w_to_ascii(const wchar_t16* src, char* dst, unsigned cap)
{
    unsigned i = 0;
    if (cap == 0)
    {
        return;
    }
    if (src)
    {
        for (; i < cap - 1 && src[i] != 0; ++i)
        {
            wchar_t16 c = src[i];
            dst[i] = (c > 0 && c < 0x7F) ? (char)c : '?';
        }
    }
    dst[i] = '\0';
}

/* --- Message pump --- */

__declspec(dllexport) LRESULT CallWindowProcA(void* proc, HANDLE h, UINT msg, WPARAM w, LPARAM l)
{
    (void)proc;
    (void)h;
    (void)msg;
    (void)w;
    (void)l;
    return 0;
}
__declspec(dllexport) LRESULT CallWindowProcW(void* proc, HANDLE h, UINT msg, WPARAM w, LPARAM l)
{
    (void)proc;
    (void)h;
    (void)msg;
    (void)w;
    (void)l;
    return 0;
}
__declspec(dllexport) LRESULT DefWindowProcA(HANDLE h, UINT msg, WPARAM w, LPARAM l)
{
    (void)h;
    (void)msg;
    (void)w;
    (void)l;
    return 0;
}
__declspec(dllexport) LRESULT DefWindowProcW(HANDLE h, UINT msg, WPARAM w, LPARAM l)
{
    (void)h;
    (void)msg;
    (void)w;
    (void)l;
    return 0;
}

/* Message pump — GetMessage returns 0 (quit); PeekMessage returns FALSE (no messages). */
__declspec(dllexport) BOOL GetMessageA(void* msg, HANDLE h, UINT min, UINT max)
{
    (void)msg;
    (void)h;
    (void)min;
    (void)max;
    return 0;
}
__declspec(dllexport) BOOL GetMessageW(void* msg, HANDLE h, UINT min, UINT max)
{
    (void)msg;
    (void)h;
    (void)min;
    (void)max;
    return 0;
}
__declspec(dllexport) BOOL PeekMessageA(void* msg, HANDLE h, UINT min, UINT max, UINT flags)
{
    (void)msg;
    (void)h;
    (void)min;
    (void)max;
    (void)flags;
    return 0;
}
__declspec(dllexport) BOOL PeekMessageW(void* msg, HANDLE h, UINT min, UINT max, UINT flags)
{
    (void)msg;
    (void)h;
    (void)min;
    (void)max;
    (void)flags;
    return 0;
}
__declspec(dllexport) LRESULT DispatchMessageA(const void* msg)
{
    (void)msg;
    return 0;
}
__declspec(dllexport) LRESULT DispatchMessageW(const void* msg)
{
    (void)msg;
    return 0;
}
__declspec(dllexport) BOOL TranslateMessage(const void* msg)
{
    (void)msg;
    return 0;
}
__declspec(dllexport) BOOL TranslateAcceleratorA(HANDLE h, HANDLE accel, void* msg)
{
    (void)h;
    (void)accel;
    (void)msg;
    return 0;
}
__declspec(dllexport) BOOL TranslateAcceleratorW(HANDLE h, HANDLE accel, void* msg)
{
    (void)h;
    (void)accel;
    (void)msg;
    return 0;
}
__declspec(dllexport) void PostQuitMessage(int code)
{
    (void)code;
}
__declspec(dllexport) BOOL PostMessageA(HANDLE h, UINT msg, WPARAM w, LPARAM l)
{
    (void)h;
    (void)msg;
    (void)w;
    (void)l;
    return 1;
}
__declspec(dllexport) BOOL PostMessageW(HANDLE h, UINT msg, WPARAM w, LPARAM l)
{
    (void)h;
    (void)msg;
    (void)w;
    (void)l;
    return 1;
}
__declspec(dllexport) BOOL PostThreadMessageA(DWORD tid, UINT msg, WPARAM w, LPARAM l)
{
    (void)tid;
    (void)msg;
    (void)w;
    (void)l;
    return 1;
}
__declspec(dllexport) BOOL PostThreadMessageW(DWORD tid, UINT msg, WPARAM w, LPARAM l)
{
    (void)tid;
    (void)msg;
    (void)w;
    (void)l;
    return 1;
}
__declspec(dllexport) LRESULT SendMessageA(HANDLE h, UINT msg, WPARAM w, LPARAM l)
{
    (void)h;
    (void)msg;
    (void)w;
    (void)l;
    return 0;
}
__declspec(dllexport) LRESULT SendMessageW(HANDLE h, UINT msg, WPARAM w, LPARAM l)
{
    (void)h;
    (void)msg;
    (void)w;
    (void)l;
    return 0;
}

/* --- Window creation / destruction --- */

/* Shared core for A and W variants. `title` is an ASCII pointer
 * (caller-owned, NUL-terminated); width/height are clamped by
 * the kernel. Returns a biased compositor handle (or 0). */
static HANDLE win32_create_window_core(int x, int y, int w, int h, const char* title)
{
    /* Coerce signed Win32 ints (possibly CW_USEDEFAULT = (int)0x80000000)
     * into u32 — the kernel clamps negatives-as-huge-u32 against the
     * framebuffer. No point splitting the signed branch here. */
    long long lx = (unsigned int)x;
    long long ly = (unsigned int)y;
    long long lw = (unsigned int)w;
    long long lh = (unsigned int)h;
    long long lt = (long long)(unsigned long long)title;

    register long long r10_h asm("r10") = lh;
    register long long r8_t asm("r8") = lt;
    long long rv;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"((long long)SYS_WIN_CREATE), "D"(lx), "S"(ly), "d"(lw), "r"(r10_h), "r"(r8_t)
                     : "memory");
    return (HANDLE)(unsigned long long)rv;
}

__declspec(dllexport) HANDLE CreateWindowExA(DWORD ex, const char* cls, const char* name, DWORD style, int x, int y,
                                             int w, int h, HANDLE parent, HANDLE menu, HANDLE hInst, void* param)
{
    (void)ex;
    (void)cls;
    (void)style;
    (void)parent;
    (void)menu;
    (void)hInst;
    (void)param;
    return win32_create_window_core(x, y, w, h, name);
}

__declspec(dllexport) HANDLE CreateWindowExW(DWORD ex, const wchar_t16* cls, const wchar_t16* name, DWORD style, int x,
                                             int y, int w, int h, HANDLE parent, HANDLE menu, HANDLE hInst, void* param)
{
    (void)ex;
    (void)cls;
    (void)style;
    (void)parent;
    (void)menu;
    (void)hInst;
    (void)param;
    char title[WIN_TITLE_MAX];
    win32_w_to_ascii(name, title, WIN_TITLE_MAX);
    return win32_create_window_core(x, y, w, h, title);
}

__declspec(dllexport) BOOL DestroyWindow(HANDLE h)
{
    long long rv;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"((long long)SYS_WIN_DESTROY), "D"((long long)(unsigned long long)h)
                     : "memory");
    return rv ? 1 : 0;
}

__declspec(dllexport) BOOL ShowWindow(HANDLE h, int cmd)
{
    long long discard;
    __asm__ volatile("int $0x80"
                     : "=a"(discard)
                     : "a"((long long)SYS_WIN_SHOW), "D"((long long)(unsigned long long)h), "S"((long long)cmd)
                     : "memory");
    /* Win32 ShowWindow returns the PREVIOUS visibility state —
     * FALSE means "was not previously visible". We don't track
     * that yet; every call reports FALSE. Callers that branch on
     * the value are virtually always using it as "was it already
     * shown?", so FALSE is the safe under-reporting answer. */
    return 0;
}
__declspec(dllexport) BOOL UpdateWindow(HANDLE h)
{
    (void)h;
    return 1;
}
__declspec(dllexport) BOOL InvalidateRect(HANDLE h, const void* r, BOOL erase)
{
    (void)h;
    (void)r;
    (void)erase;
    return 1;
}
__declspec(dllexport) BOOL MoveWindow(HANDLE h, int x, int y, int w, int ht, BOOL repaint)
{
    (void)h;
    (void)x;
    (void)y;
    (void)w;
    (void)ht;
    (void)repaint;
    return 1;
}
__declspec(dllexport) BOOL SetWindowPos(HANDLE h, HANDLE after, int x, int y, int w, int ht, UINT flags)
{
    (void)h;
    (void)after;
    (void)x;
    (void)y;
    (void)w;
    (void)ht;
    (void)flags;
    return 1;
}
__declspec(dllexport) BOOL IsWindow(HANDLE h)
{
    (void)h;
    return 0;
}
__declspec(dllexport) HANDLE GetActiveWindow(void)
{
    return (HANDLE)0;
}
__declspec(dllexport) HANDLE GetForegroundWindow(void)
{
    return (HANDLE)0;
}
__declspec(dllexport) HANDLE GetDesktopWindow(void)
{
    return (HANDLE)0;
}
__declspec(dllexport) BOOL GetClientRect(HANDLE h, void* r)
{
    (void)h;
    if (r)
    {
        unsigned char* b = (unsigned char*)r;
        for (int i = 0; i < 16; ++i)
            b[i] = 0;
    }
    return 1;
}
__declspec(dllexport) BOOL GetWindowRect(HANDLE h, void* r)
{
    return GetClientRect(h, r);
}
__declspec(dllexport) HANDLE GetProcessWindowStation(void)
{
    return (HANDLE)0;
}

/* --- Class registration --- */
typedef unsigned short ATOM;
__declspec(dllexport) ATOM RegisterClassA(const void* wc)
{
    (void)wc;
    return 1;
}
__declspec(dllexport) ATOM RegisterClassW(const void* wc)
{
    (void)wc;
    return 1;
}
__declspec(dllexport) ATOM RegisterClassExA(const void* wcex)
{
    (void)wcex;
    return 1;
}
__declspec(dllexport) ATOM RegisterClassExW(const void* wcex)
{
    (void)wcex;
    return 1;
}
__declspec(dllexport) BOOL UnregisterClassA(const char* name, HANDLE hInst)
{
    (void)name;
    (void)hInst;
    return 1;
}
__declspec(dllexport) BOOL UnregisterClassW(const wchar_t16* name, HANDLE hInst)
{
    (void)name;
    (void)hInst;
    return 1;
}

/* --- MessageBox --- */
#define IDOK 1
#define WIN_MSGBOX_TEXT_MAX 256

static int win32_msgbox_core(const char* text, const char* caption)
{
    long long rv;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"((long long)SYS_WIN_MSGBOX), "D"((long long)(unsigned long long)text),
                       "S"((long long)(unsigned long long)caption)
                     : "memory");
    return (int)rv;
}

__declspec(dllexport) int MessageBoxA(HANDLE h, const char* text, const char* caption, UINT type)
{
    (void)h;
    (void)type;
    (void)win32_msgbox_core(text, caption);
    return IDOK;
}
__declspec(dllexport) int MessageBoxW(HANDLE h, const wchar_t16* text, const wchar_t16* caption, UINT type)
{
    (void)h;
    (void)type;
    char t_ascii[WIN_MSGBOX_TEXT_MAX];
    char c_ascii[WIN_TITLE_MAX];
    win32_w_to_ascii(text, t_ascii, WIN_MSGBOX_TEXT_MAX);
    win32_w_to_ascii(caption, c_ascii, WIN_TITLE_MAX);
    (void)win32_msgbox_core(t_ascii, c_ascii);
    return IDOK;
}
__declspec(dllexport) int MessageBoxExA(HANDLE h, const char* text, const char* caption, UINT type, unsigned short lang)
{
    (void)lang;
    return MessageBoxA(h, text, caption, type);
}
__declspec(dllexport) int MessageBoxExW(HANDLE h, const wchar_t16* text, const wchar_t16* caption, UINT type,
                                        unsigned short lang)
{
    (void)lang;
    return MessageBoxW(h, text, caption, type);
}

/* --- Load* family --- */
__declspec(dllexport) HANDLE LoadAcceleratorsA(HANDLE h, const char* name)
{
    (void)h;
    (void)name;
    return (HANDLE)0;
}
__declspec(dllexport) HANDLE LoadAcceleratorsW(HANDLE h, const wchar_t16* name)
{
    (void)h;
    (void)name;
    return (HANDLE)0;
}
__declspec(dllexport) HANDLE LoadBitmapA(HANDLE h, const char* name)
{
    (void)h;
    (void)name;
    return (HANDLE)0;
}
__declspec(dllexport) HANDLE LoadBitmapW(HANDLE h, const wchar_t16* name)
{
    (void)h;
    (void)name;
    return (HANDLE)0;
}
__declspec(dllexport) HANDLE LoadCursorA(HANDLE h, const char* name)
{
    (void)h;
    (void)name;
    return (HANDLE)1;
}
__declspec(dllexport) HANDLE LoadCursorW(HANDLE h, const wchar_t16* name)
{
    (void)h;
    (void)name;
    return (HANDLE)1;
}
__declspec(dllexport) HANDLE LoadIconA(HANDLE h, const char* name)
{
    (void)h;
    (void)name;
    return (HANDLE)1;
}
__declspec(dllexport) HANDLE LoadIconW(HANDLE h, const wchar_t16* name)
{
    (void)h;
    (void)name;
    return (HANDLE)1;
}
__declspec(dllexport) HANDLE LoadImageA(HANDLE h, const char* name, UINT t, int w, int ht, UINT flags)
{
    (void)h;
    (void)name;
    (void)t;
    (void)w;
    (void)ht;
    (void)flags;
    return (HANDLE)0;
}
__declspec(dllexport) HANDLE LoadImageW(HANDLE h, const wchar_t16* name, UINT t, int w, int ht, UINT flags)
{
    (void)h;
    (void)name;
    (void)t;
    (void)w;
    (void)ht;
    (void)flags;
    return (HANDLE)0;
}
__declspec(dllexport) HANDLE LoadMenuA(HANDLE h, const char* name)
{
    (void)h;
    (void)name;
    return (HANDLE)0;
}
__declspec(dllexport) HANDLE LoadMenuW(HANDLE h, const wchar_t16* name)
{
    (void)h;
    (void)name;
    return (HANDLE)0;
}
__declspec(dllexport) int LoadStringA(HANDLE h, UINT id, char* buf, int len)
{
    (void)h;
    (void)id;
    if (buf && len > 0)
        buf[0] = 0;
    return 0;
}
__declspec(dllexport) int LoadStringW(HANDLE h, UINT id, wchar_t16* buf, int len)
{
    (void)h;
    (void)id;
    if (buf && len > 0)
        buf[0] = 0;
    return 0;
}

/* --- Cursor / clipboard --- */
__declspec(dllexport) BOOL ClipCursor(const void* r)
{
    (void)r;
    return 1;
}
__declspec(dllexport) BOOL GetCursorPos(void* p)
{
    if (p)
    {
        int* i = (int*)p;
        i[0] = 0;
        i[1] = 0;
    }
    return 1;
}
__declspec(dllexport) BOOL SetCursorPos(int x, int y)
{
    (void)x;
    (void)y;
    return 1;
}
__declspec(dllexport) HANDLE SetCursor(HANDLE h)
{
    (void)h;
    return (HANDLE)0;
}
__declspec(dllexport) int ShowCursor(BOOL show)
{
    (void)show;
    return 0;
}
__declspec(dllexport) BOOL OpenClipboard(HANDLE owner)
{
    (void)owner;
    return 0;
}
__declspec(dllexport) BOOL CloseClipboard(void)
{
    return 1;
}
__declspec(dllexport) BOOL EmptyClipboard(void)
{
    return 1;
}
__declspec(dllexport) HANDLE GetClipboardData(UINT fmt)
{
    (void)fmt;
    return (HANDLE)0;
}
__declspec(dllexport) HANDLE SetClipboardData(UINT fmt, HANDLE h)
{
    (void)fmt;
    (void)h;
    return (HANDLE)0;
}

/* --- Char helpers --- */
__declspec(dllexport) wchar_t16* CharLowerW(wchar_t16* s)
{
    if (!s)
        return s;
    for (wchar_t16* p = s; *p; ++p)
        if (*p >= 'A' && *p <= 'Z')
            *p = (wchar_t16)(*p + ('a' - 'A'));
    return s;
}
__declspec(dllexport) wchar_t16* CharUpperW(wchar_t16* s)
{
    if (!s)
        return s;
    for (wchar_t16* p = s; *p; ++p)
        if (*p >= 'a' && *p <= 'z')
            *p = (wchar_t16)(*p - ('a' - 'A'));
    return s;
}

/* --- System metrics --- */
__declspec(dllexport) int GetSystemMetrics(int index)
{
    /* Return 0 for everything — caller either uses the value
     * directly (fine, 0 is "sensible default") or checks != 0. */
    (void)index;
    return 0;
}
__declspec(dllexport) DWORD GetSysColor(int index)
{
    (void)index;
    return 0xFFFFFFu; /* white */
}
