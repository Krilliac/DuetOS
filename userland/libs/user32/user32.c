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
#define SYS_WIN_TIMER_SET 72
#define SYS_WIN_TIMER_KILL 73
#define SYS_WIN_GET_KEYSTATE 77
#define SYS_WIN_GET_CURSOR 78
#define SYS_WIN_SET_CURSOR 79
#define SYS_WIN_SET_CAPTURE 80
#define SYS_WIN_RELEASE_CAPTURE 81
#define SYS_WIN_GET_CAPTURE 82
#define SYS_WIN_CLIP_SET_TEXT 83
#define SYS_WIN_CLIP_GET_TEXT 84
#define SYS_WIN_GET_LONG 85
#define SYS_WIN_SET_LONG 86
#define SYS_WIN_INVALIDATE 87
#define SYS_WIN_VALIDATE 88
#define SYS_WIN_GET_ACTIVE 89
#define SYS_WIN_SET_ACTIVE 90
#define SYS_WIN_GET_METRIC 91
#define SYS_WIN_ENUM 92
#define SYS_WIN_FIND 93
#define SYS_WIN_SET_PARENT 94
#define SYS_WIN_GET_PARENT 95
#define SYS_WIN_GET_RELATED 96
#define SYS_WIN_SET_FOCUS 97
#define SYS_WIN_GET_FOCUS 98
#define SYS_WIN_CARET 99
#define SYS_WIN_BEEP 100

/* WNDCLASS storage indices for SYS_WIN_SET/GET_LONG. */
#define GWLP_WNDPROC 0
#define GWLP_USERDATA 1
/* Slot 2 = style (GWL_STYLE -16), slot 3 = exstyle (GWL_EXSTYLE -20). */
#define USER32_LONG_STYLE 2
#define USER32_LONG_EXSTYLE 3

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

/* WndProc dispatch — the class table that RegisterClass* fills
 * in lives here in user32; the kernel stores the per-window
 * WNDPROC pointer in GWLP_WNDPROC (SYS_WIN_GET_LONG index 0)
 * so every CreateWindow call copies its class's WNDPROC into
 * the window's long slot. DispatchMessage pulls the WNDPROC
 * back out and invokes it with the x64 __stdcall ABI. */

typedef LRESULT(__stdcall* WNDPROC)(HANDLE hwnd, UINT msg, WPARAM w, LPARAM l);

#define USER32_CLASS_CAP 32

struct user32_wndclass
{
    char name[64];
    WNDPROC wndproc;
    int in_use;
};
static struct user32_wndclass s_classes[USER32_CLASS_CAP];

static void user32_strcpy_ascii(char* dst, unsigned cap, const char* src)
{
    unsigned i = 0;
    if (src)
    {
        for (; i + 1 < cap && src[i]; ++i)
            dst[i] = src[i];
    }
    dst[i] = '\0';
}
static int user32_strieq(const char* a, const char* b, unsigned cap)
{
    for (unsigned i = 0; i < cap; ++i)
    {
        char ca = a[i], cb = b[i];
        if (ca >= 'A' && ca <= 'Z')
            ca = (char)(ca + ('a' - 'A'));
        if (cb >= 'A' && cb <= 'Z')
            cb = (char)(cb + ('a' - 'A'));
        if (ca != cb)
            return 0;
        if (ca == 0)
            return 1;
    }
    return 1;
}

/* Register (or update) a class record. Returns 1 on success. */
static int user32_class_register(const char* name, WNDPROC proc)
{
    if (!name)
        return 0;
    for (unsigned i = 0; i < USER32_CLASS_CAP; ++i)
    {
        if (s_classes[i].in_use && user32_strieq(s_classes[i].name, name, 64))
        {
            s_classes[i].wndproc = proc;
            return 1;
        }
    }
    for (unsigned i = 0; i < USER32_CLASS_CAP; ++i)
    {
        if (!s_classes[i].in_use)
        {
            user32_strcpy_ascii(s_classes[i].name, 64, name);
            s_classes[i].wndproc = proc;
            s_classes[i].in_use = 1;
            return 1;
        }
    }
    return 0; /* table full */
}

static WNDPROC user32_class_lookup(const char* name)
{
    if (!name)
        return 0;
    for (unsigned i = 0; i < USER32_CLASS_CAP; ++i)
    {
        if (s_classes[i].in_use && user32_strieq(s_classes[i].name, name, 64))
        {
            return s_classes[i].wndproc;
        }
    }
    return 0;
}

/* DispatchMessage pulls the WNDPROC from the window's
 * GWLP_WNDPROC long slot and invokes it. If no WNDPROC is
 * registered, fall through to DefWindowProcA (returns 0). */
static LRESULT user32_dispatch_core(const void* msg_any)
{
    if (!msg_any)
        return 0;
    const struct user32_msg_wire* m = (const struct user32_msg_wire*)msg_any;
    long long rv;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"((long long)SYS_WIN_GET_LONG), "D"((long long)(unsigned long long)m->hwnd),
                       "S"((long long)GWLP_WNDPROC)
                     : "memory");
    WNDPROC proc = (WNDPROC)(unsigned long long)rv;
    if (!proc)
        return 0;
    return proc(m->hwnd, m->message, m->wParam, m->lParam);
}

__declspec(dllexport) LRESULT DispatchMessageA(const void* msg)
{
    return user32_dispatch_core(msg);
}
__declspec(dllexport) LRESULT DispatchMessageW(const void* msg)
{
    return user32_dispatch_core(msg);
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
/* SendMessage is synchronous — it must return the WndProc's
 * result. v1 implements this by pulling the target's WNDPROC
 * out of GWLP_WNDPROC and calling it directly. Cross-process
 * SendMessage returns 0 because SYS_WIN_GET_LONG refuses the
 * read when the HWND is owned by a different pid. */
static LRESULT user32_send_core(HANDLE h, UINT msg, WPARAM w, LPARAM l)
{
    long long rv;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"((long long)SYS_WIN_GET_LONG), "D"((long long)(unsigned long long)h),
                       "S"((long long)GWLP_WNDPROC)
                     : "memory");
    void* proc_raw = (void*)(unsigned long long)rv;
    if (!proc_raw)
        return 0;
    LRESULT(__stdcall * proc)(HANDLE, UINT, WPARAM, LPARAM) = proc_raw;
    return proc(h, msg, w, l);
}
__declspec(dllexport) LRESULT SendMessageA(HANDLE h, UINT msg, WPARAM w, LPARAM l)
{
    return user32_send_core(h, msg, w, l);
}
__declspec(dllexport) LRESULT SendMessageW(HANDLE h, UINT msg, WPARAM w, LPARAM l)
{
    return user32_send_core(h, msg, w, l);
}
/* SendNotifyMessage is Win32's "async to other threads but sync
 * to self" API. v1 collapses to synchronous send. */
__declspec(dllexport) BOOL SendNotifyMessageA(HANDLE h, UINT msg, WPARAM w, LPARAM l)
{
    (void)user32_send_core(h, msg, w, l);
    return 1;
}
__declspec(dllexport) BOOL SendNotifyMessageW(HANDLE h, UINT msg, WPARAM w, LPARAM l)
{
    (void)user32_send_core(h, msg, w, l);
    return 1;
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

/* Install the registered class's WNDPROC into the freshly-
 * created window's GWLP_WNDPROC slot so DispatchMessage can
 * recover it. No-op if the class has no registered proc. */
static void user32_install_wndproc(HANDLE hwnd, const char* class_name)
{
    if (!hwnd || !class_name)
        return;
    WNDPROC proc = user32_class_lookup(class_name);
    if (!proc)
        return;
    long long rv;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"((long long)SYS_WIN_SET_LONG), "D"((long long)(unsigned long long)hwnd),
                       "S"((long long)GWLP_WNDPROC), "d"((long long)(unsigned long long)proc)
                     : "memory");
    (void)rv;
}

/* Forward decls so user32_install_create_state can use them
 * before the full definitions appear below. */
__declspec(dllexport) long long SetWindowLongPtrA(HANDLE h, int index, long long value);
__declspec(dllexport) HANDLE SetParent(HANDLE child, HANDLE parent);

/* Capture the style + ex-style + parent into the kernel's
 * per-window long slots right after create. */
static void user32_install_create_state(HANDLE hwnd, DWORD style, DWORD ex, HANDLE parent)
{
    if (!hwnd)
        return;
    /* SetWindowLongPtr with the Win32 -16 / -20 indices remaps
     * to our slot 2/3. */
    SetWindowLongPtrA(hwnd, -16 /* GWL_STYLE */, (long long)(unsigned)style);
    SetWindowLongPtrA(hwnd, -20 /* GWL_EXSTYLE */, (long long)(unsigned)ex);
    if (parent)
    {
        (void)SetParent(hwnd, parent);
    }
}

__declspec(dllexport) HANDLE CreateWindowExA(DWORD ex, const char* cls, const char* name, DWORD style, int x, int y,
                                             int w, int h, HANDLE parent, HANDLE menu, HANDLE hInst, void* param)
{
    (void)menu;
    (void)hInst;
    (void)param;
    HANDLE hwnd = win32_create_window_core(x, y, w, h, name);
    user32_install_wndproc(hwnd, cls);
    user32_install_create_state(hwnd, style, ex, parent);
    return hwnd;
}

__declspec(dllexport) HANDLE CreateWindowExW(DWORD ex, const wchar_t16* cls, const wchar_t16* name, DWORD style, int x,
                                             int y, int w, int h, HANDLE parent, HANDLE menu, HANDLE hInst, void* param)
{
    (void)menu;
    (void)hInst;
    (void)param;
    char title[WIN_TITLE_MAX];
    char class_a[WIN_TITLE_MAX];
    win32_w_to_ascii(name, title, WIN_TITLE_MAX);
    win32_w_to_ascii(cls, class_a, WIN_TITLE_MAX);
    HANDLE hwnd = win32_create_window_core(x, y, w, h, title);
    user32_install_wndproc(hwnd, class_a);
    user32_install_create_state(hwnd, style, ex, parent);
    return hwnd;
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
    /* No-op beyond InvalidateRect: the kernel's paint drain
     * runs right after Invalidate, so by the time the pump
     * returns, WM_PAINT is already queued. */
    (void)h;
    return 1;
}
__declspec(dllexport) BOOL InvalidateRect(HANDLE h, const void* r, BOOL erase)
{
    (void)r; /* whole-client dirty only in v1 */
    long long rv;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"((long long)SYS_WIN_INVALIDATE), "D"((long long)(unsigned long long)h), "S"((long long)erase)
                     : "memory");
    return rv ? 1 : 0;
}
__declspec(dllexport) BOOL ValidateRect(HANDLE h, const void* r)
{
    (void)r;
    long long rv;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"((long long)SYS_WIN_VALIDATE), "D"((long long)(unsigned long long)h)
                     : "memory");
    return rv ? 1 : 0;
}

/* BeginPaint / EndPaint — PAINTSTRUCT = { HDC hdc; BOOL fErase;
 * RECT rcPaint; BOOL fRestore; BOOL fIncUpdate; BYTE rgbReserved[32]; }
 * sizeof ~= 72 on x64. We only write the first three fields; the
 * rest is left untouched (typical callers don't inspect them). */
typedef struct
{
    HANDLE hdc;
    BOOL fErase;
    int left, top, right, bottom;
    BOOL fRestore;
    BOOL fIncUpdate;
    unsigned char rgbReserved[32];
} PAINTSTRUCT;

__declspec(dllexport) HANDLE BeginPaint(HANDLE hwnd, void* ps)
{
    /* GetDC gives an HDC tagged with the HWND, so a subsequent
     * FillRect/TextOut dispatches correctly. BeginPaint is
     * expected to return the HDC; cache in the PAINTSTRUCT so
     * EndPaint can release. */
    /* Encode HDC_TAG same way gdi32 does; user32 doesn't have
     * gdi32 symbols, but the encoding is stable ABI. */
    const unsigned long long GDI_TAG = 0xDC00000000ULL;
    HANDLE hdc = (HANDLE)((unsigned long long)hwnd | GDI_TAG);
    if (ps)
    {
        PAINTSTRUCT* p = (PAINTSTRUCT*)ps;
        p->hdc = hdc;
        p->fErase = 1;
        /* Invalid rect = whole client in v1. Fill with a best-
         * effort client rect from SYS_WIN_GET_RECT. */
        int rect[4] = {0, 0, 0, 0};
        long long rv;
        __asm__ volatile("int $0x80"
                         : "=a"(rv)
                         : "a"((long long)SYS_WIN_GET_RECT), "D"((long long)(unsigned long long)hwnd),
                           "S"((long long)1 /* client */), "d"((long long)(unsigned long long)rect)
                         : "memory");
        (void)rv;
        p->left = rect[0];
        p->top = rect[1];
        p->right = rect[2];
        p->bottom = rect[3];
        p->fRestore = 0;
        p->fIncUpdate = 0;
    }
    /* Clear the dirty bit now — the caller promises to paint. */
    ValidateRect(hwnd, 0);
    return hdc;
}
__declspec(dllexport) BOOL EndPaint(HANDLE hwnd, const void* ps)
{
    (void)hwnd;
    (void)ps;
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
    long long rv;
    __asm__ volatile("int $0x80" : "=a"(rv) : "a"((long long)SYS_WIN_GET_ACTIVE) : "memory");
    return (HANDLE)(unsigned long long)rv;
}
__declspec(dllexport) HANDLE GetForegroundWindow(void)
{
    return GetActiveWindow();
}
__declspec(dllexport) HANDLE SetActiveWindow(HANDLE h)
{
    long long rv;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"((long long)SYS_WIN_SET_ACTIVE), "D"((long long)(unsigned long long)h)
                     : "memory");
    return (HANDLE)(unsigned long long)rv;
}
__declspec(dllexport) BOOL SetForegroundWindow(HANDLE h)
{
    return SetActiveWindow(h) ? 1 : 0;
}
__declspec(dllexport) HANDLE GetDesktopWindow(void)
{
    /* v1: no true desktop HWND — return biased handle 0 (== 1
     * in HWND space) as a sentinel the caller can pass into
     * GetClientRect to fetch the screen dimensions. */
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

/* WNDCLASSA layout: {
 *   UINT style; WNDPROC lpfnWndProc; int cbClsExtra; int cbWndExtra;
 *   HINSTANCE hInstance; HICON hIcon; HCURSOR hCursor;
 *   HBRUSH hbrBackground; LPCSTR lpszMenuName; LPCSTR lpszClassName; }
 * Total sizeof = 40 on MSVC x64 (4 + 8 + 4 + 4 + 8 + 8 + 8 + 8 + 8 + 8 = 68, rounded).
 * WNDCLASSEXA has cbSize prepended + hIconSm appended. */
struct user32_wndclass_a
{
    UINT style;
    WNDPROC lpfnWndProc;
    int cbClsExtra;
    int cbWndExtra;
    HANDLE hInstance;
    HANDLE hIcon;
    HANDLE hCursor;
    HANDLE hbrBackground;
    const char* lpszMenuName;
    const char* lpszClassName;
};
struct user32_wndclassex_a
{
    UINT cbSize;
    UINT style;
    WNDPROC lpfnWndProc;
    int cbClsExtra;
    int cbWndExtra;
    HANDLE hInstance;
    HANDLE hIcon;
    HANDLE hCursor;
    HANDLE hbrBackground;
    const char* lpszMenuName;
    const char* lpszClassName;
    HANDLE hIconSm;
};

__declspec(dllexport) ATOM RegisterClassA(const void* wc)
{
    if (!wc)
        return 0;
    const struct user32_wndclass_a* c = (const struct user32_wndclass_a*)wc;
    if (!c->lpszClassName)
        return 0;
    return user32_class_register(c->lpszClassName, c->lpfnWndProc) ? 1 : 0;
}
__declspec(dllexport) ATOM RegisterClassW(const void* wc)
{
    /* Can't inspect wide names safely without flattening; v1
     * accepts and stores with a synthetic name so CreateWindowExW
     * still succeeds (callers typically pair RegisterClassW with
     * CreateWindowExW using the same pointer). */
    if (!wc)
        return 0;
    const struct user32_wndclass_a* c = (const struct user32_wndclass_a*)wc;
    char dummy[16];
    dummy[0] = 'W';
    dummy[1] = '-';
    /* Embed low 14 bits of the WNDPROC pointer so different
     * classes with distinct procs stay distinct. */
    unsigned long long v = (unsigned long long)c->lpfnWndProc;
    for (int i = 0; i < 13; ++i)
    {
        dummy[2 + i] = (char)('a' + ((v >> (i * 4)) & 0xF));
    }
    dummy[15] = '\0';
    return user32_class_register(dummy, c->lpfnWndProc) ? 1 : 0;
}
__declspec(dllexport) ATOM RegisterClassExA(const void* wcex)
{
    if (!wcex)
        return 0;
    const struct user32_wndclassex_a* c = (const struct user32_wndclassex_a*)wcex;
    if (!c->lpszClassName)
        return 0;
    return user32_class_register(c->lpszClassName, c->lpfnWndProc) ? 1 : 0;
}
__declspec(dllexport) ATOM RegisterClassExW(const void* wcex)
{
    return RegisterClassW(wcex); /* shape identical in the v1 bridge */
}
__declspec(dllexport) BOOL UnregisterClassA(const char* name, HANDLE hInst)
{
    (void)hInst;
    if (!name)
        return 0;
    for (unsigned i = 0; i < USER32_CLASS_CAP; ++i)
    {
        if (s_classes[i].in_use && user32_strieq(s_classes[i].name, name, 64))
        {
            s_classes[i].in_use = 0;
            s_classes[i].wndproc = 0;
            return 1;
        }
    }
    return 0;
}
__declspec(dllexport) BOOL UnregisterClassW(const wchar_t16* name, HANDLE hInst)
{
    (void)name;
    (void)hInst;
    return 1;
}

/* --- MessageBox --- */
/* Win32 MessageBox button IDs. */
#define IDOK 1
#define IDCANCEL 2
#define IDABORT 3
#define IDRETRY 4
#define IDIGNORE 5
#define IDYES 6
#define IDNO 7
/* MessageBox uType low 4 bits select the button set. */
#define MB_OK 0x0
#define MB_OKCANCEL 0x1
#define MB_ABORTRETRYIGNORE 0x2
#define MB_YESNOCANCEL 0x3
#define MB_YESNO 0x4
#define MB_RETRYCANCEL 0x5

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

/* Map uType to a sensible default return code. No modal UI in
 * v1 — the MessageBox serial-logs the text and returns a
 * button ID that matches Win32's "default button" convention:
 *   MB_OK            → IDOK
 *   MB_OKCANCEL      → IDOK (user clicked OK)
 *   MB_YESNO         → IDYES
 *   MB_YESNOCANCEL   → IDYES
 *   MB_RETRYCANCEL   → IDRETRY
 *   MB_ABORTRETRYIGNORE → IDRETRY */
static int user32_msgbox_result(UINT type)
{
    switch (type & 0xF)
    {
    case MB_OKCANCEL:
        return IDOK;
    case MB_YESNO:
    case MB_YESNOCANCEL:
        return IDYES;
    case MB_RETRYCANCEL:
        return IDRETRY;
    case MB_ABORTRETRYIGNORE:
        return IDRETRY;
    case MB_OK:
    default:
        return IDOK;
    }
}

__declspec(dllexport) int MessageBoxA(HANDLE h, const char* text, const char* caption, UINT type)
{
    (void)h;
    (void)win32_msgbox_core(text, caption);
    return user32_msgbox_result(type);
}
__declspec(dllexport) int MessageBoxW(HANDLE h, const wchar_t16* text, const wchar_t16* caption, UINT type)
{
    (void)h;
    char t_ascii[WIN_MSGBOX_TEXT_MAX];
    char c_ascii[WIN_TITLE_MAX];
    win32_w_to_ascii(text, t_ascii, WIN_MSGBOX_TEXT_MAX);
    win32_w_to_ascii(caption, c_ascii, WIN_TITLE_MAX);
    (void)win32_msgbox_core(t_ascii, c_ascii);
    return user32_msgbox_result(type);
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
    if (!p)
        return 0;
    long long rv;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"((long long)SYS_WIN_GET_CURSOR), "D"((long long)(unsigned long long)p)
                     : "memory");
    return rv ? 1 : 0;
}
__declspec(dllexport) BOOL SetCursorPos(int x, int y)
{
    long long rv;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"((long long)SYS_WIN_SET_CURSOR), "D"((long long)(unsigned)x), "S"((long long)(unsigned)y)
                     : "memory");
    return rv ? 1 : 0;
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

/* --- Clipboard --- */
/* v1: Win32's OpenClipboard / Close / Empty pattern is
 * effectively stateless — we don't reference-count owners, so
 * Open always "succeeds" and Empty wipes the text. Only the
 * CF_TEXT format is bridged; other formats return null. */
#define CF_TEXT 1

__declspec(dllexport) BOOL OpenClipboard(HANDLE owner)
{
    (void)owner;
    return 1;
}
__declspec(dllexport) BOOL CloseClipboard(void)
{
    return 1;
}
__declspec(dllexport) BOOL EmptyClipboard(void)
{
    long long rv;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"((long long)SYS_WIN_CLIP_SET_TEXT), "D"((long long)(unsigned long long)"")
                     : "memory");
    (void)rv;
    return 1;
}
/* GetClipboardData returns an HGLOBAL that points at a buffer
 * the caller can read. v1 synthesises a thread-local 1-KiB
 * buffer and fills it from the kernel's copy; callers are
 * expected to copy out before any subsequent GetClipboardData
 * call (matches Win32's "don't free this handle" convention). */
static char s_clipboard_shadow[1024];
__declspec(dllexport) HANDLE GetClipboardData(UINT fmt)
{
    if (fmt != CF_TEXT)
        return (HANDLE)0;
    long long rv;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"((long long)SYS_WIN_CLIP_GET_TEXT), "D"((long long)(unsigned long long)s_clipboard_shadow),
                       "S"((long long)sizeof(s_clipboard_shadow))
                     : "memory");
    (void)rv;
    /* Always return the shadow — empty clipboard reads as an
     * empty C string, which most callers handle via strlen. */
    return (HANDLE)s_clipboard_shadow;
}
__declspec(dllexport) HANDLE SetClipboardData(UINT fmt, HANDLE h)
{
    if (fmt != CF_TEXT || !h)
        return (HANDLE)0;
    long long rv;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"((long long)SYS_WIN_CLIP_SET_TEXT), "D"((long long)(unsigned long long)h)
                     : "memory");
    (void)rv;
    return h;
}

/* --- Keyboard state --- */
__declspec(dllexport) short GetKeyState(int vk)
{
    long long rv;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"((long long)SYS_WIN_GET_KEYSTATE), "D"((long long)(unsigned)vk)
                     : "memory");
    return (short)rv;
}
__declspec(dllexport) short GetAsyncKeyState(int vk)
{
    return GetKeyState(vk);
}

/* --- Mouse capture --- */
__declspec(dllexport) HANDLE SetCapture(HANDLE h)
{
    long long rv;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"((long long)SYS_WIN_SET_CAPTURE), "D"((long long)(unsigned long long)h)
                     : "memory");
    return (HANDLE)(unsigned long long)rv;
}
__declspec(dllexport) BOOL ReleaseCapture(void)
{
    long long rv;
    __asm__ volatile("int $0x80" : "=a"(rv) : "a"((long long)SYS_WIN_RELEASE_CAPTURE) : "memory");
    return rv ? 1 : 0;
}
__declspec(dllexport) HANDLE GetCapture(void)
{
    long long rv;
    __asm__ volatile("int $0x80" : "=a"(rv) : "a"((long long)SYS_WIN_GET_CAPTURE) : "memory");
    return (HANDLE)(unsigned long long)rv;
}

/* --- Timers --- */
/* UINT_PTR on x64 is 64-bit; v1 collapses to u32 in the kernel
 * table which is enough for any reasonable SetTimer caller. */
__declspec(dllexport) unsigned long long SetTimer(HANDLE h, unsigned long long id, UINT elapse, void* cb)
{
    (void)cb; /* no timer-callback dispatch; WM_TIMER only */
    long long rv;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"((long long)SYS_WIN_TIMER_SET), "D"((long long)(unsigned long long)h), "S"((long long)id),
                       "d"((long long)elapse)
                     : "memory");
    return (unsigned long long)rv;
}
__declspec(dllexport) BOOL KillTimer(HANDLE h, unsigned long long id)
{
    long long rv;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"((long long)SYS_WIN_TIMER_KILL), "D"((long long)(unsigned long long)h), "S"((long long)id)
                     : "memory");
    return rv ? 1 : 0;
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
    long long rv;
    __asm__ volatile("int $0x80" : "=a"(rv) : "a"((long long)SYS_WIN_GET_METRIC), "D"((long long)index) : "memory");
    return (int)rv;
}
/* GetSysColor — return a stable per-index colour. The kernel
 * publishes the canonical palette via SYS_GDI_GET_SYS_COLOR
 * (=127); use that so apps that paint with COLOR_WINDOWTEXT /
 * COLOR_BTNFACE / COLOR_HIGHLIGHT see distinct colours instead
 * of always-white. Falls back to white on out-of-range. */
__declspec(dllexport) DWORD GetSysColor(int index)
{
    long long rv;
    __asm__ volatile("int $0x80" : "=a"(rv) : "a"((long long)127), "D"((long long)index) : "memory");
    if (rv == 0 && index != 0 && index != 8)
    {
        /* SYS_GDI_GET_SYS_COLOR returned 0 for an unknown index;
         * Win32 returns 0 too — match it. */
        return (DWORD)rv;
    }
    return (DWORD)rv;
}

/* --- Window longs ---
 * Win32 exposes GWL_STYLE=-16, GWL_EXSTYLE=-20, GWLP_WNDPROC=-4,
 * GWLP_USERDATA=-21; our kernel uses positive slot indices 0..3.
 * Both naming conventions work: the raw slot index (0..3) is
 * passed through, a recognised negative constant is remapped to
 * the matching slot, anything else falls through to 0.
 */
static int user32_slot_from_index(int index)
{
    if (index >= 0 && index < 4)
        return index;
    switch (index)
    {
    case -4:
        return 0; /* GWLP_WNDPROC */
    case -21:
        return 1; /* GWLP_USERDATA */
    case -16:
        return USER32_LONG_STYLE;
    case -20:
        return USER32_LONG_EXSTYLE;
    default:
        return 4; /* out-of-range → syscall returns 0 */
    }
}

__declspec(dllexport) long long GetWindowLongPtrA(HANDLE h, int index)
{
    const int slot = user32_slot_from_index(index);
    long long rv;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"((long long)SYS_WIN_GET_LONG), "D"((long long)(unsigned long long)h), "S"((long long)slot)
                     : "memory");
    return rv;
}
__declspec(dllexport) long long GetWindowLongPtrW(HANDLE h, int index)
{
    return GetWindowLongPtrA(h, index);
}
__declspec(dllexport) long long SetWindowLongPtrA(HANDLE h, int index, long long value)
{
    const int slot = user32_slot_from_index(index);
    long long rv;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"((long long)SYS_WIN_SET_LONG), "D"((long long)(unsigned long long)h), "S"((long long)slot),
                       "d"(value)
                     : "memory");
    return rv;
}
__declspec(dllexport) long long SetWindowLongPtrW(HANDLE h, int index, long long value)
{
    return SetWindowLongPtrA(h, index, value);
}
/* GetWindowLongA / SetWindowLongA: same syscall, truncated to 32
 * bits on the way in and out. */
__declspec(dllexport) long GetWindowLongA(HANDLE h, int index)
{
    return (long)GetWindowLongPtrA(h, index);
}
__declspec(dllexport) long GetWindowLongW(HANDLE h, int index)
{
    return (long)GetWindowLongPtrA(h, index);
}
__declspec(dllexport) long SetWindowLongA(HANDLE h, int index, long value)
{
    return (long)SetWindowLongPtrA(h, index, (long long)value);
}
__declspec(dllexport) long SetWindowLongW(HANDLE h, int index, long value)
{
    return (long)SetWindowLongPtrA(h, index, (long long)value);
}

/* --- Enumeration + find --- */
typedef BOOL(__stdcall* WNDENUMPROC)(HANDLE hwnd, LPARAM lparam);

__declspec(dllexport) BOOL EnumWindows(WNDENUMPROC proc, LPARAM lparam)
{
    if (!proc)
        return 0;
    unsigned long long buf[32];
    long long rv;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"((long long)SYS_WIN_ENUM), "D"((long long)(unsigned long long)buf),
                       "S"((long long)(sizeof(buf) / sizeof(buf[0])))
                     : "memory");
    const unsigned n = (unsigned)rv;
    for (unsigned i = 0; i < n; ++i)
    {
        if (!proc((HANDLE)buf[i], lparam))
            break; /* Win32 EnumWindows stops on FALSE */
    }
    return 1;
}

__declspec(dllexport) HANDLE FindWindowA(const char* cls, const char* name)
{
    (void)cls; /* v1: match by title only */
    if (!name)
        return (HANDLE)0;
    long long rv;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"((long long)SYS_WIN_FIND), "D"((long long)(unsigned long long)name)
                     : "memory");
    return (HANDLE)(unsigned long long)rv;
}
__declspec(dllexport) HANDLE FindWindowW(const wchar_t16* cls, const wchar_t16* name)
{
    (void)cls;
    if (!name)
        return (HANDLE)0;
    char ascii[WIN_TITLE_MAX];
    win32_w_to_ascii(name, ascii, WIN_TITLE_MAX);
    return FindWindowA(0, ascii);
}
__declspec(dllexport) HANDLE FindWindowExA(HANDLE parent, HANDLE after, const char* cls, const char* name)
{
    (void)parent;
    (void)after;
    return FindWindowA(cls, name);
}
__declspec(dllexport) HANDLE FindWindowExW(HANDLE parent, HANDLE after, const wchar_t16* cls, const wchar_t16* name)
{
    (void)parent;
    (void)after;
    return FindWindowW(cls, name);
}

/* --- Screen <-> client coord conversion --- */
/* Both compute the window's top-left in screen coords from
 * SYS_WIN_GET_RECT with selector 0, then add the 2-px border +
 * 22-px title offset. Client-side translation; no new syscall. */
typedef struct
{
    int x;
    int y;
} user32_POINT;

static BOOL user32_convert(HANDLE hwnd, void* pt, int to_client)
{
    if (!pt)
        return 0;
    int rect[4] = {0, 0, 0, 0};
    long long rv;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"((long long)SYS_WIN_GET_RECT), "D"((long long)(unsigned long long)hwnd),
                       "S"((long long)0 /* window rect */), "d"((long long)(unsigned long long)rect)
                     : "memory");
    if (!rv)
        return 0;
    user32_POINT* p = (user32_POINT*)pt;
    const int origin_x = rect[0] + 2;
    const int origin_y = rect[1] + 2 + 22;
    if (to_client)
    {
        p->x -= origin_x;
        p->y -= origin_y;
    }
    else
    {
        p->x += origin_x;
        p->y += origin_y;
    }
    return 1;
}

__declspec(dllexport) BOOL ScreenToClient(HANDLE hwnd, void* pt)
{
    return user32_convert(hwnd, pt, 1);
}
__declspec(dllexport) BOOL ClientToScreen(HANDLE hwnd, void* pt)
{
    return user32_convert(hwnd, pt, 0);
}

/* --- Parent / child --- */
__declspec(dllexport) HANDLE SetParent(HANDLE child, HANDLE parent)
{
    long long rv;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"((long long)SYS_WIN_SET_PARENT), "D"((long long)(unsigned long long)child),
                       "S"((long long)(unsigned long long)parent)
                     : "memory");
    return (HANDLE)(unsigned long long)rv;
}
__declspec(dllexport) HANDLE GetParent(HANDLE h)
{
    long long rv;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"((long long)SYS_WIN_GET_PARENT), "D"((long long)(unsigned long long)h)
                     : "memory");
    return (HANDLE)(unsigned long long)rv;
}
__declspec(dllexport) HANDLE GetWindow(HANDLE h, UINT cmd)
{
    /* Win32 GW_HWNDNEXT=2, GW_HWNDPREV=3, GW_HWNDFIRST=0,
     * GW_HWNDLAST=1, GW_CHILD=5, GW_OWNER=4. Kernel enum uses
     * 0=Next, 1=Prev, 2=First, 3=Last, 4=Child, 5=Owner. Remap: */
    unsigned rel;
    switch (cmd)
    {
    case 2:
        rel = 0;
        break; /* NEXT */
    case 3:
        rel = 1;
        break; /* PREV */
    case 0:
        rel = 2;
        break; /* FIRST */
    case 1:
        rel = 3;
        break; /* LAST */
    case 5:
        rel = 4;
        break; /* CHILD */
    case 4:
        rel = 5;
        break; /* OWNER */
    default:
        return (HANDLE)0;
    }
    long long rv;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"((long long)SYS_WIN_GET_RELATED), "D"((long long)(unsigned long long)h), "S"((long long)rel)
                     : "memory");
    return (HANDLE)(unsigned long long)rv;
}

/* --- Focus --- */
__declspec(dllexport) HANDLE SetFocus(HANDLE h)
{
    long long rv;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"((long long)SYS_WIN_SET_FOCUS), "D"((long long)(unsigned long long)h)
                     : "memory");
    return (HANDLE)(unsigned long long)rv;
}
__declspec(dllexport) HANDLE GetFocus(void)
{
    long long rv;
    __asm__ volatile("int $0x80" : "=a"(rv) : "a"((long long)SYS_WIN_GET_FOCUS) : "memory");
    return (HANDLE)(unsigned long long)rv;
}

/* --- Caret --- */
static BOOL user32_caret_op(unsigned op, long long arg1, long long arg2, long long arg3)
{
    register long long r10_a3 asm("r10") = arg3;
    long long rv;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"((long long)SYS_WIN_CARET), "D"((long long)op), "S"(arg1), "d"(arg2), "r"(r10_a3)
                     : "memory");
    return rv ? 1 : 0;
}
__declspec(dllexport) BOOL CreateCaret(HANDLE hwnd, HANDLE bitmap, int width, int height)
{
    (void)bitmap;
    return user32_caret_op(0, (long long)(unsigned)width, (long long)(unsigned)height,
                           (long long)(unsigned long long)hwnd);
}
__declspec(dllexport) BOOL DestroyCaret(void)
{
    return user32_caret_op(1, 0, 0, 0);
}
__declspec(dllexport) BOOL SetCaretPos(int x, int y)
{
    return user32_caret_op(2, (long long)(unsigned)x, (long long)(unsigned)y, 0);
}
__declspec(dllexport) BOOL ShowCaret(HANDLE hwnd)
{
    (void)hwnd;
    return user32_caret_op(3, 0, 0, 0);
}
__declspec(dllexport) BOOL HideCaret(HANDLE hwnd)
{
    (void)hwnd;
    return user32_caret_op(4, 0, 0, 0);
}
__declspec(dllexport) UINT GetCaretBlinkTime(void)
{
    /* Win32 returns the full period in ms. v1 caret blinks
     * with the 1 Hz ui-ticker, so period = 1000 ms. */
    return 1000;
}
__declspec(dllexport) BOOL SetCaretBlinkTime(UINT period)
{
    (void)period;
    return 1;
}

/* --- MessageBeep / Beep --- */
__declspec(dllexport) BOOL MessageBeep(UINT type)
{
    /* Win32 MessageBeep(type) plays the system sound associated
     * with type; in v1 we always beep at 800Hz for 100ms. */
    (void)type;
    long long rv;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"((long long)SYS_WIN_BEEP), "D"((long long)0 /* default freq */),
                       "S"((long long)0 /* default dur */)
                     : "memory");
    return rv ? 1 : 0;
}
__declspec(dllexport) BOOL Beep(DWORD freq, DWORD dur)
{
    long long rv;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"((long long)SYS_WIN_BEEP), "D"((long long)freq), "S"((long long)dur)
                     : "memory");
    return rv ? 1 : 0;
}

/* GWL_STYLE / GWL_EXSTYLE remap is handled inside
 * user32_slot_from_index (shared with GetWindowLongPtrA); no
 * separate wrappers needed here. */
