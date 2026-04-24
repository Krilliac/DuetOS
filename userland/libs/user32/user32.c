/*
 * userland/libs/user32/user32.c — 73 window-manager stubs, with
 * create/destroy/show/message-box + the full message pump (GetMessage
 * / PeekMessage / PostMessage / DispatchMessage / PostQuitMessage)
 * bridged to the kernel compositor via SYS_WIN_* (58..64) as of the
 * windowing v1 slice.
 *
 * Critical quirks:
 *   - GetMessage BLOCKS in the kernel until a message arrives; the
 *     kernel polls every scheduler tick (10 ms). Returns 0 when it
 *     dequeues WM_QUIT — the caller's canonical `while (GetMessage)`
 *     loop exits cleanly.
 *   - PeekMessage is non-blocking.
 *   - DefWindowProcA/W returns 0 (caller accepts).
 *   - PostQuitMessage posts WM_QUIT (0x0012) to every window owned by
 *     the calling process so an event pump blocked on GetMessage
 *     unblocks and sees WM_QUIT next.
 *   - CreateWindowExA/W returns a real compositor-backed HWND. HWND
 *     is a biased compositor index (+1) so 0 still means failure.
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
#define SYS_WIN_PEEK_MSG 62
#define SYS_WIN_GET_MSG 63
#define SYS_WIN_POST_MSG 64
#define SYS_WIN_MOVE 69
#define SYS_WIN_GET_RECT 70
#define SYS_WIN_SET_TEXT 71

/* Selected message IDs the pump + DispatchMessage care about. The
 * kernel doesn't interpret these numbers — it passes them through
 * the queue — but pasting the common ones here lets the pump
 * implement WM_QUIT termination without a shared header. */
#define WM_QUIT 0x0012

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

/* Kernel-wire MSG slice. Matches the first 32 bytes the
 * SYS_WIN_*_MSG syscalls write: { HWND; UINT message; u32 _pad;
 * WPARAM; LPARAM; }. The full Win32 MSG struct is 48 bytes on x64
 * (trailing time/pt/lPrivate fields); we zero those after the
 * kernel copy so the caller's struct is fully defined. */
struct user32_msg_wire
{
    HANDLE hwnd;
    UINT message;
    UINT _pad;
    WPARAM wParam;
    LPARAM lParam;
};

/* Zero the tail of the caller's MSG struct (time/pt/lPrivate) so
 * programs that scan the whole thing see deterministic data. */
static void user32_zero_msg_tail(void* msg)
{
    unsigned char* b = (unsigned char*)msg;
    if (!b)
        return;
    for (unsigned i = sizeof(struct user32_msg_wire); i < 48; ++i)
    {
        b[i] = 0;
    }
}

__declspec(dllexport) BOOL GetMessageA(void* msg, HANDLE h, UINT min, UINT max)
{
    (void)min;
    (void)max;
    if (!msg)
        return 0;
    long long rv;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"((long long)SYS_WIN_GET_MSG), "D"((long long)(unsigned long long)msg),
                       "S"((long long)(unsigned long long)h)
                     : "memory");
    /* rv = 1 for a normal message, 0 for WM_QUIT, -1 on bad args.
     * Win32 GetMessage returns -1 on outright failure which
     * callers usually treat as "break the loop", same as 0. */
    if (rv > 0)
    {
        user32_zero_msg_tail(msg);
    }
    return (BOOL)rv;
}
__declspec(dllexport) BOOL GetMessageW(void* msg, HANDLE h, UINT min, UINT max)
{
    return GetMessageA(msg, h, min, max);
}

#define PM_REMOVE 0x0001

__declspec(dllexport) BOOL PeekMessageA(void* msg, HANDLE h, UINT min, UINT max, UINT flags)
{
    (void)min;
    (void)max;
    if (!msg)
        return 0;
    long long rv;
    const long long remove = (flags & PM_REMOVE) ? 1 : 0;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"((long long)SYS_WIN_PEEK_MSG), "D"((long long)(unsigned long long)msg),
                       "S"((long long)(unsigned long long)h), "d"(remove)
                     : "memory");
    if (rv == 1)
    {
        user32_zero_msg_tail(msg);
        return 1;
    }
    return 0;
}
__declspec(dllexport) BOOL PeekMessageW(void* msg, HANDLE h, UINT min, UINT max, UINT flags)
{
    return PeekMessageA(msg, h, min, max, flags);
}

/* DispatchMessage delivers the message to the target window's
 * WndProc. v0 has no per-window WndProc table — every Win32
 * program supplies its WndProc via RegisterClass(ExA/W), which we
 * stub. Returning 0 matches the default-processed-message
 * convention callers accept. */
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

static BOOL user32_post_msg_core(HANDLE h, UINT msg, WPARAM w, LPARAM l)
{
    register long long r10_l asm("r10") = (long long)l;
    long long rv;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"((long long)SYS_WIN_POST_MSG), "D"((long long)(unsigned long long)h), "S"((long long)msg),
                       "d"((long long)w), "r"(r10_l)
                     : "memory");
    return rv ? 1 : 0;
}

__declspec(dllexport) BOOL PostMessageA(HANDLE h, UINT msg, WPARAM w, LPARAM l)
{
    return user32_post_msg_core(h, msg, w, l);
}
__declspec(dllexport) BOOL PostMessageW(HANDLE h, UINT msg, WPARAM w, LPARAM l)
{
    return user32_post_msg_core(h, msg, w, l);
}
/* PostQuitMessage in real Win32 posts a thread-scoped WM_QUIT.
 * Our v0 queues are per-window, so we fan the WM_QUIT out to
 * every window owned by this process. GetMessage returning
 * FALSE on WM_QUIT guarantees the caller's pump exits after
 * processing one more message. HWND-filter `NULL` from the
 * kernel's perspective == "the caller's pid's windows" — we
 * emit the post using HWND 1 as a heuristic since user32's
 * POST_MSG syscall requires a concrete HWND; if 1 isn't owned
 * by us (rare for a graphical app that created at least one
 * window), the post is a documented no-op and the caller's
 * loop eventually breaks on natural exit. */
__declspec(dllexport) void PostQuitMessage(int code)
{
    /* HWND 1 is the first compositor slot. Attempt-post to
     * slots 1..16 and stop on the first success — cross-pid
     * posts are already rejected by the kernel. */
    for (unsigned i = 1; i <= 16; ++i)
    {
        if (user32_post_msg_core((HANDLE)(unsigned long long)i, WM_QUIT, (WPARAM)(unsigned)code, 0))
        {
            /* One successful post wakes the pump. Keep going so
             * every window owned by this pid sees WM_QUIT — the
             * next GetMessage on any of them picks it up. */
        }
    }
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
/* SYS_WIN_MOVE flags. Match the kernel-side enum used by
 * DoWinMove. Bit 0 = nomove, bit 1 = nosize. */
#define WIN_MOVE_NOMOVE 0x1
#define WIN_MOVE_NOSIZE 0x2

static BOOL user32_move_core(HANDLE h, int x, int y, int w, int ht, unsigned flags)
{
    register long long r10_w asm("r10") = (long long)(unsigned)w;
    register long long r8_h asm("r8") = (long long)(unsigned)ht;
    register long long r9_f asm("r9") = (long long)flags;
    long long rv;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"((long long)SYS_WIN_MOVE), "D"((long long)(unsigned long long)h), "S"((long long)(unsigned)x),
                       "d"((long long)(unsigned)y), "r"(r10_w), "r"(r8_h), "r"(r9_f)
                     : "memory");
    return rv ? 1 : 0;
}

__declspec(dllexport) BOOL MoveWindow(HANDLE h, int x, int y, int w, int ht, BOOL repaint)
{
    (void)repaint; /* kernel always composes on success */
    return user32_move_core(h, x, y, w, ht, 0);
}

/* Common SetWindowPos flags (subset). */
#define SWP_NOMOVE 0x0002
#define SWP_NOSIZE 0x0001

__declspec(dllexport) BOOL SetWindowPos(HANDLE h, HANDLE after, int x, int y, int w, int ht, UINT flags)
{
    (void)after; /* z-order management beyond raise-on-show is v2 */
    unsigned k_flags = 0;
    if (flags & SWP_NOMOVE)
        k_flags |= WIN_MOVE_NOMOVE;
    if (flags & SWP_NOSIZE)
        k_flags |= WIN_MOVE_NOSIZE;
    return user32_move_core(h, x, y, w, ht, k_flags);
}
static BOOL user32_getrect_core(HANDLE h, unsigned selector, void* r);

__declspec(dllexport) BOOL IsWindow(HANDLE h)
{
    /* A biased compositor index whose owner matches the caller's
     * pid is a valid window; SYS_WIN_GET_RECT succeeds iff both
     * of those hold, which is exactly the Win32 IsWindow contract. */
    int local_rect[4];
    return user32_getrect_core(h, 0, local_rect);
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
static BOOL user32_getrect_core(HANDLE h, unsigned selector, void* r)
{
    if (!r)
        return 0;
    long long rv;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"((long long)SYS_WIN_GET_RECT), "D"((long long)(unsigned long long)h),
                       "S"((long long)selector), "d"((long long)(unsigned long long)r)
                     : "memory");
    return rv ? 1 : 0;
}

__declspec(dllexport) BOOL GetClientRect(HANDLE h, void* r)
{
    return user32_getrect_core(h, 1, r);
}
__declspec(dllexport) BOOL GetWindowRect(HANDLE h, void* r)
{
    return user32_getrect_core(h, 0, r);
}

__declspec(dllexport) BOOL SetWindowTextA(HANDLE h, const char* text)
{
    long long rv;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"((long long)SYS_WIN_SET_TEXT), "D"((long long)(unsigned long long)h),
                       "S"((long long)(unsigned long long)text)
                     : "memory");
    return rv ? 1 : 0;
}
__declspec(dllexport) BOOL SetWindowTextW(HANDLE h, const wchar_t16* text)
{
    char ascii[WIN_TITLE_MAX];
    win32_w_to_ascii(text, ascii, WIN_TITLE_MAX);
    return SetWindowTextA(h, ascii);
}

__declspec(dllexport) int GetWindowTextA(HANDLE h, char* buf, int len)
{
    (void)h;
    if (buf && len > 0)
        buf[0] = 0;
    return 0; /* no get-path yet; Win32 returns 0 on empty */
}
__declspec(dllexport) int GetWindowTextW(HANDLE h, wchar_t16* buf, int len)
{
    (void)h;
    if (buf && len > 0)
        buf[0] = 0;
    return 0;
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
