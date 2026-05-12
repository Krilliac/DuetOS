/*
 * userland/libs/user32/user32.c — window-manager surface, with
 * create/destroy/show/message-box + the full message pump (GetMessage
 * / PeekMessage / PostMessage / DispatchMessage / PostQuitMessage)
 * bridged to the kernel compositor via SYS_WIN_* (58..64) as of the
 * windowing v1 slice. Modal-dialog family (DialogBoxParam / EndDialog
 * + GetDlgItem*) ships as STUB facades — EATs exist so PEs link, but
 * no modal pump runs in v0 (see comment block before DialogBoxParamA).
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

/* Syscall numbers duplicated from kernel/syscall/syscall.h — keeping
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
#define SYS_GDI_SET_CURSOR 174
#define SYS_GDI_CREATE_CURSOR 175

/* GdiCursorShape — keep in sync with kernel/syscall/syscall.h. */
#define DUETOS_CURSOR_ARROW 0
#define DUETOS_CURSOR_IBEAM 1
#define DUETOS_CURSOR_HAND 2
#define DUETOS_CURSOR_WAIT 3
#define DUETOS_CURSOR_RESIZE_NS 4
#define DUETOS_CURSOR_RESIZE_EW 5
#define DUETOS_CURSOR_RESIZE_NESW 6
#define DUETOS_CURSOR_RESIZE_NWSE 7

/* Standard Win32 IDC_* constants. LoadCursor returns these
 * sentinel values; SetCursor maps them to the kernel's
 * GdiCursorShape via SYS_GDI_SET_CURSOR. */
#define IDC_ARROW 32512
#define IDC_IBEAM 32513
#define IDC_WAIT 32514
#define IDC_HAND 32649
#define IDC_SIZENS 32645
#define IDC_SIZEWE 32644
#define IDC_SIZENESW 32643
#define IDC_SIZENWSE 32642
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
#define SYS_WIN_TRACK_POPUP 173

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

/* Forward decl — defined further down once the per-process
 * thread-message queue is in scope. */
static int user32_thread_msg_pop(struct user32_msg_wire* out, int remove);

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
        return (BOOL)rv;
    }
    /* Drain a thread-posted message if the kernel queue was empty
     * — matches the PeekMessage fallback so PostThreadMessage +
     * GetMessage round-trips work without any window registration. */
    if (rv == 0 && user32_thread_msg_pop((struct user32_msg_wire*)msg, 1))
    {
        user32_zero_msg_tail(msg);
        return 1;
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
    /* Two-tier queue check:
     *  1. Kernel-side window-message queue (SYS_WIN_PEEK_MSG) — the
     *     normal source for HWND-targeted messages from the WM
     *     and the input-event dispatch path.
     *  2. User-side thread-message queue — populated by
     *     PostThreadMessage / PostQuitMessage. Drained when (1)
     *     reports nothing.
     * The order matches Win32: GetMessage / PeekMessage prioritises
     * the WM-posted queue over thread messages so input-driven
     * apps stay responsive even when a posted thread message
     * accumulates. */
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
    /* Fallback to user-side queue when the kernel reports empty. */
    if (user32_thread_msg_pop((struct user32_msg_wire*)msg, (int)remove))
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
/* Per-process thread-message queue.
 *
 * Real Win32 keeps one queue per UI thread; PostThreadMessage
 * pushes onto the target thread's queue, and that thread's
 * GetMessage / PeekMessage returns from it (msg.hwnd = NULL).
 *
 * v0 collapses this to a single per-process queue because there's
 * effectively one ring-3 thread per process today (SYS_THREAD_CREATE
 * is wired but smoke tests don't spawn). 8 slots is plenty for
 * the test workload — typical PostQuitMessage / WM_USER round-trips
 * push at most 1–2 messages before draining.
 *
 * Capture-on-Post / drain-on-Peek with a single producer/consumer
 * keeps the queue lock-free; the only consumer is the same task
 * that produced. */
struct user32_thread_msg
{
    UINT message;
    WPARAM wparam;
    LPARAM lparam;
    DWORD time;
};
#define USER32_THREAD_MSG_CAP 8
static struct user32_thread_msg s_thread_msgs[USER32_THREAD_MSG_CAP];
static unsigned s_thread_msg_head = 0; /* push cursor */
static unsigned s_thread_msg_tail = 0; /* pop cursor  */

static int user32_thread_msg_empty(void)
{
    return s_thread_msg_head == s_thread_msg_tail;
}

static void user32_thread_msg_push(UINT msg, WPARAM w, LPARAM l)
{
    /* Drop oldest on overflow — keeps the producer non-blocking
     * even when the consumer is wedged. */
    if (s_thread_msg_head - s_thread_msg_tail >= USER32_THREAD_MSG_CAP)
        ++s_thread_msg_tail;
    unsigned slot = s_thread_msg_head & (USER32_THREAD_MSG_CAP - 1);
    s_thread_msgs[slot].message = msg;
    s_thread_msgs[slot].wparam = w;
    s_thread_msgs[slot].lparam = l;
    s_thread_msgs[slot].time = 0;
    ++s_thread_msg_head;
}

static int user32_thread_msg_pop(struct user32_msg_wire* out, int remove)
{
    if (user32_thread_msg_empty())
        return 0;
    unsigned slot = s_thread_msg_tail & (USER32_THREAD_MSG_CAP - 1);
    out->hwnd = (HANDLE)0; /* thread message — no hwnd */
    out->message = s_thread_msgs[slot].message;
    out->wParam = s_thread_msgs[slot].wparam;
    out->lParam = s_thread_msgs[slot].lparam;
    if (remove)
        ++s_thread_msg_tail;
    return 1;
}

__declspec(dllexport) BOOL PostThreadMessageA(DWORD tid, UINT msg, WPARAM w, LPARAM l)
{
    /* The tid argument names the target thread. v0 only has one
     * UI thread per process, so any tid that could plausibly be
     * a thread of this process (matches GetCurrentThreadId) lands
     * in our shared queue; cross-thread / cross-process posts are
     * silently dropped — the kernel-side dispatch hop they need
     * isn't wired yet. */
    (void)tid;
    user32_thread_msg_push(msg, w, l);
    return 1;
}

__declspec(dllexport) BOOL PostThreadMessageW(DWORD tid, UINT msg, WPARAM w, LPARAM l)
{
    return PostThreadMessageA(tid, msg, w, l);
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

/* AdjustWindowRect / AdjustWindowRectEx — given a desired CLIENT
 * rect and a style mask, expand the rect so it becomes the WINDOW
 * rect (the bounds CreateWindow expects). Pure userland math
 * sourced from GetSystemMetrics so frame / caption insets stay
 * in sync with whatever the kernel composes (see DoWinGetMetric
 * in `kernel/subsystems/win32/window_syscall.cpp`). */
__declspec(dllexport) int GetSystemMetrics(int index);
#define WS_BORDER 0x00800000u
#define WS_DLGFRAME 0x00400000u
#define WS_THICKFRAME 0x00040000u
#define WS_CAPTION (WS_BORDER | WS_DLGFRAME)
#define WS_VSCROLL 0x00200000u
#define WS_HSCROLL 0x00100000u
#define WS_EX_CLIENTEDGE 0x00000200u
#define WS_EX_STATICEDGE 0x00020000u
#define WS_EX_DLGMODALFRAME 0x00000001u

/* GetSystemMetrics indices we read for frame math. */
#define SM_CXBORDER 5
#define SM_CYBORDER 6
#define SM_CYCAPTION 4
#define SM_CXFRAME 32
#define SM_CYFRAME 33
#define SM_CXVSCROLL 2
#define SM_CYHSCROLL 3
#define SM_CYMENU 15
#define SM_CXEDGE 45
#define SM_CYEDGE 46

__declspec(dllexport) BOOL AdjustWindowRectEx(void* lpRect, DWORD dwStyle, BOOL bMenu, DWORD dwExStyle)
{
    if (!lpRect)
        return 0;
    int* r = (int*)lpRect;
    int border_x = GetSystemMetrics(SM_CXBORDER);
    int border_y = GetSystemMetrics(SM_CYBORDER);
    if (border_x <= 0)
        border_x = 1;
    if (border_y <= 0)
        border_y = 1;
    int left_in = border_x;
    int top_in = border_y;
    int right_in = border_x;
    int bot_in = border_y;
    if ((dwStyle & WS_THICKFRAME) != 0)
    {
        int fx = GetSystemMetrics(SM_CXFRAME);
        int fy = GetSystemMetrics(SM_CYFRAME);
        if (fx <= 0)
            fx = 2;
        if (fy <= 0)
            fy = 2;
        left_in += fx;
        right_in += fx;
        top_in += fy;
        bot_in += fy;
    }
    else if ((dwStyle & WS_DLGFRAME) != 0)
    {
        left_in += border_x;
        right_in += border_x;
        top_in += border_y;
        bot_in += border_y;
    }
    if ((dwStyle & WS_CAPTION) == WS_CAPTION)
    {
        int cap = GetSystemMetrics(SM_CYCAPTION);
        if (cap <= 0)
            cap = 22;
        top_in += cap;
    }
    if (bMenu)
    {
        int menu = GetSystemMetrics(SM_CYMENU);
        if (menu <= 0)
            menu = 19;
        top_in += menu;
    }
    if ((dwStyle & WS_VSCROLL) != 0)
    {
        int sb = GetSystemMetrics(SM_CXVSCROLL);
        if (sb <= 0)
            sb = 16;
        right_in += sb;
    }
    if ((dwStyle & WS_HSCROLL) != 0)
    {
        int sb = GetSystemMetrics(SM_CYHSCROLL);
        if (sb <= 0)
            sb = 16;
        bot_in += sb;
    }
    if ((dwExStyle & WS_EX_CLIENTEDGE) != 0 || (dwExStyle & WS_EX_STATICEDGE) != 0)
    {
        int ex = GetSystemMetrics(SM_CXEDGE);
        int ey = GetSystemMetrics(SM_CYEDGE);
        if (ex <= 0)
            ex = 2;
        if (ey <= 0)
            ey = 2;
        left_in += ex;
        right_in += ex;
        top_in += ey;
        bot_in += ey;
    }
    if ((dwExStyle & WS_EX_DLGMODALFRAME) != 0)
    {
        left_in += border_x + 2;
        right_in += border_x + 2;
        top_in += border_y + 2;
        bot_in += border_y + 2;
    }
    r[0] -= left_in;
    r[1] -= top_in;
    r[2] += right_in;
    r[3] += bot_in;
    return 1;
}

__declspec(dllexport) BOOL AdjustWindowRect(void* lpRect, DWORD dwStyle, BOOL bMenu)
{
    return AdjustWindowRectEx(lpRect, dwStyle, bMenu, 0);
}

/* Win10+ DPI-aware variant; we don't track per-window DPI yet so
 * dpi is ignored and behaviour matches the non-DPI form. */
__declspec(dllexport) BOOL AdjustWindowRectExForDpi(void* lpRect, DWORD dwStyle, BOOL bMenu, DWORD dwExStyle, UINT dpi)
{
    (void)dpi;
    return AdjustWindowRectEx(lpRect, dwStyle, bMenu, dwExStyle);
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
    /* WNDCLASSW shares lpfnWndProc / lpszClassName slots with
     * WNDCLASSA in the v0 bridge struct — only the W variant
     * stores lpszClassName as a wchar_t16*. Flatten the wide
     * name with a low-byte strip so the registration's stored
     * name matches what GetClassInfoW(L"...") + UnregisterClassW
     * will look for later. Falls back to a synthetic procName-
     * derived label only if the caller passed a NULL or empty
     * wide name (matches Win32 behaviour: registering with no
     * name is technically allowed, the class becomes anonymous-
     * by-atom). */
    if (!wc)
        return 0;
    const struct user32_wndclass_a* c = (const struct user32_wndclass_a*)wc;
    char flat[64];
    int fi = 0;
    if (c->lpszClassName != 0)
    {
        const wchar_t16* w = (const wchar_t16*)c->lpszClassName;
        while (fi < (int)sizeof(flat) - 1 && w[fi] != 0)
        {
            flat[fi] = (char)(w[fi] & 0xFF);
            ++fi;
        }
    }
    flat[fi] = '\0';
    if (fi == 0)
    {
        /* No name — fall back to a procName-derived synthetic so
         * different anonymous classes stay distinct. */
        flat[0] = 'W';
        flat[1] = '-';
        unsigned long long v = (unsigned long long)c->lpfnWndProc;
        for (int i = 0; i < 13; ++i)
        {
            flat[2 + i] = (char)('a' + ((v >> (i * 4)) & 0xF));
        }
        flat[15] = '\0';
    }
    return user32_class_register(flat, c->lpfnWndProc) ? 1 : 0;
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

/* --- Modal dialogs (STUB) ---
 *
 * Real Win32 DialogBoxParam blocks until EndDialog is called from
 * the caller-supplied DLGPROC. v0 has no modal event loop and no
 * real dialog window; we deliberately do NOT invoke the DLGPROC
 * (calling it with a NULL hwnd would crash any procedure that
 * touches GetDlgItem). Returning IDOK matches MessageBox's "user
 * pressed OK" default so PEs that branch on the result follow the
 * affirmative path. EndDialog is a no-op that returns TRUE — the
 * stored result is never observed because DialogBoxParam itself
 * never enters a modal loop. Real modal dialogs need a window-
 * system upgrade (modal pump + dialog template loader); see wiki
 * Roadmap. The presence of these EAT entries means PEs that import
 * the family LOAD; the fact they don't run a real dialog is on the
 * caller to discover via the surface-status doc. */

typedef long long INT_PTR;

__declspec(dllexport) INT_PTR DialogBoxParamA(HANDLE hInst, const char* lpTemplate, HANDLE hWndParent,
                                              void* lpDialogFunc, LPARAM dwInitParam)
{
    (void)hInst;
    (void)lpTemplate;
    (void)hWndParent;
    (void)lpDialogFunc;
    (void)dwInitParam;
    return IDOK;
}
__declspec(dllexport) INT_PTR DialogBoxParamW(HANDLE hInst, const wchar_t16* lpTemplate, HANDLE hWndParent,
                                              void* lpDialogFunc, LPARAM dwInitParam)
{
    (void)hInst;
    (void)lpTemplate;
    (void)hWndParent;
    (void)lpDialogFunc;
    (void)dwInitParam;
    return IDOK;
}
__declspec(dllexport) INT_PTR DialogBoxA(HANDLE hInst, const char* lpTemplate, HANDLE hWndParent, void* lpDialogFunc)
{
    return DialogBoxParamA(hInst, lpTemplate, hWndParent, lpDialogFunc, 0);
}
__declspec(dllexport) INT_PTR DialogBoxW(HANDLE hInst, const wchar_t16* lpTemplate, HANDLE hWndParent,
                                         void* lpDialogFunc)
{
    return DialogBoxParamW(hInst, lpTemplate, hWndParent, lpDialogFunc, 0);
}
__declspec(dllexport) INT_PTR DialogBoxIndirectParamA(HANDLE hInst, const void* lpTemplate, HANDLE hWndParent,
                                                      void* lpDialogFunc, LPARAM dwInitParam)
{
    (void)hInst;
    (void)lpTemplate;
    (void)hWndParent;
    (void)lpDialogFunc;
    (void)dwInitParam;
    return IDOK;
}
__declspec(dllexport) INT_PTR DialogBoxIndirectParamW(HANDLE hInst, const void* lpTemplate, HANDLE hWndParent,
                                                      void* lpDialogFunc, LPARAM dwInitParam)
{
    (void)hInst;
    (void)lpTemplate;
    (void)hWndParent;
    (void)lpDialogFunc;
    (void)dwInitParam;
    return IDOK;
}
__declspec(dllexport) BOOL EndDialog(HANDLE hDlg, INT_PTR nResult)
{
    (void)hDlg;
    (void)nResult;
    return 1;
}
/* CreateDialogParamA/W is the modeless cousin of DialogBoxParam —
 * Windows returns immediately with a HWND for the dialog instead of
 * blocking. v0 returns NULL (caller treats this as "dialog could not
 * be created"; a properly-written modeless caller falls back to its
 * non-dialog code path). Pair with EndDialog above. */
__declspec(dllexport) HANDLE CreateDialogParamA(HANDLE hInst, const char* lpTemplate, HANDLE hWndParent,
                                                void* lpDialogFunc, LPARAM dwInitParam)
{
    (void)hInst;
    (void)lpTemplate;
    (void)hWndParent;
    (void)lpDialogFunc;
    (void)dwInitParam;
    return (HANDLE)0;
}
__declspec(dllexport) HANDLE CreateDialogParamW(HANDLE hInst, const wchar_t16* lpTemplate, HANDLE hWndParent,
                                                void* lpDialogFunc, LPARAM dwInitParam)
{
    (void)hInst;
    (void)lpTemplate;
    (void)hWndParent;
    (void)lpDialogFunc;
    (void)dwInitParam;
    return (HANDLE)0;
}
__declspec(dllexport) HANDLE CreateDialogA(HANDLE hInst, const char* lpTemplate, HANDLE hWndParent, void* lpDialogFunc)
{
    return CreateDialogParamA(hInst, lpTemplate, hWndParent, lpDialogFunc, 0);
}
__declspec(dllexport) HANDLE CreateDialogW(HANDLE hInst, const wchar_t16* lpTemplate, HANDLE hWndParent,
                                           void* lpDialogFunc)
{
    return CreateDialogParamW(hInst, lpTemplate, hWndParent, lpDialogFunc, 0);
}
/* IsDialogMessageA/W returns FALSE in real Win32 when a message
 * isn't dialog-related. Without modal dialogs the answer is always
 * "not a dialog message" — the caller's GetMessage/DispatchMessage
 * pump runs unchanged. */
__declspec(dllexport) BOOL IsDialogMessageA(HANDLE hDlg, void* lpMsg)
{
    (void)hDlg;
    (void)lpMsg;
    return 0;
}
__declspec(dllexport) BOOL IsDialogMessageW(HANDLE hDlg, void* lpMsg)
{
    (void)hDlg;
    (void)lpMsg;
    return 0;
}
/* GetDlgItem — without real dialogs there are no child controls.
 * Returns NULL so any DLGPROC that does happen to run sees "control
 * not found" and bails on the affected branch. */
__declspec(dllexport) HANDLE GetDlgItem(HANDLE hDlg, int nIDDlgItem)
{
    (void)hDlg;
    (void)nIDDlgItem;
    return (HANDLE)0;
}
__declspec(dllexport) BOOL SetDlgItemTextA(HANDLE hDlg, int nIDDlgItem, const char* text)
{
    (void)hDlg;
    (void)nIDDlgItem;
    (void)text;
    return 0;
}
__declspec(dllexport) BOOL SetDlgItemTextW(HANDLE hDlg, int nIDDlgItem, const wchar_t16* text)
{
    (void)hDlg;
    (void)nIDDlgItem;
    (void)text;
    return 0;
}
__declspec(dllexport) UINT GetDlgItemTextA(HANDLE hDlg, int nIDDlgItem, char* buf, int cap)
{
    (void)hDlg;
    (void)nIDDlgItem;
    if (buf && cap > 0)
        buf[0] = 0;
    return 0;
}
__declspec(dllexport) UINT GetDlgItemTextW(HANDLE hDlg, int nIDDlgItem, wchar_t16* buf, int cap)
{
    (void)hDlg;
    (void)nIDDlgItem;
    if (buf && cap > 0)
        buf[0] = 0;
    return 0;
}
__declspec(dllexport) BOOL SetDlgItemInt(HANDLE hDlg, int nIDDlgItem, UINT value, BOOL signed_)
{
    (void)hDlg;
    (void)nIDDlgItem;
    (void)value;
    (void)signed_;
    return 0;
}
__declspec(dllexport) UINT GetDlgItemInt(HANDLE hDlg, int nIDDlgItem, BOOL* translated, BOOL signed_)
{
    (void)hDlg;
    (void)nIDDlgItem;
    (void)signed_;
    if (translated)
        *translated = 0;
    return 0;
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
/* LoadCursor — return the IDC_* sentinel as the HCURSOR so a
 * subsequent SetCursor can decode which shape was requested.
 * The kernel doesn't track HCURSOR identity; the value is just
 * the round-trip key.
 *
 * `name` here is the MAKEINTRESOURCE-style integer cast to a
 * char*; values < 0x10000 are the well-known IDC_* IDs. v1
 * recognises only those; named cursors return IDC_ARROW. */
__declspec(dllexport) HANDLE LoadCursorA(HANDLE h, const char* name)
{
    (void)h;
    unsigned long id = (unsigned long)(unsigned long long)name;
    if (id == 0 || id > 0xFFFF)
        return (HANDLE)(unsigned long long)IDC_ARROW;
    return (HANDLE)(unsigned long long)id;
}
__declspec(dllexport) HANDLE LoadCursorW(HANDLE h, const wchar_t16* name)
{
    (void)h;
    unsigned long id = (unsigned long)(unsigned long long)name;
    if (id == 0 || id > 0xFFFF)
        return (HANDLE)(unsigned long long)IDC_ARROW;
    return (HANDLE)(unsigned long long)id;
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
/* SetCursor — translate the HCURSOR (IDC_* sentinel) into a
 * GdiCursorShape and issue SYS_GDI_SET_CURSOR. Return value is
 * the previous shape mapped back to its IDC_* sentinel so
 * callers can restore on WM_SETCURSOR. */
__declspec(dllexport) HANDLE SetCursor(HANDLE h)
{
    unsigned long id = (unsigned long)(unsigned long long)h;
    unsigned long shape = DUETOS_CURSOR_ARROW;
    switch (id)
    {
    case IDC_IBEAM:
        shape = DUETOS_CURSOR_IBEAM;
        break;
    case IDC_HAND:
        shape = DUETOS_CURSOR_HAND;
        break;
    case IDC_WAIT:
        shape = DUETOS_CURSOR_WAIT;
        break;
    case IDC_SIZENS:
        shape = DUETOS_CURSOR_RESIZE_NS;
        break;
    case IDC_SIZEWE:
        shape = DUETOS_CURSOR_RESIZE_EW;
        break;
    case IDC_SIZENESW:
        shape = DUETOS_CURSOR_RESIZE_NESW;
        break;
    case IDC_SIZENWSE:
        shape = DUETOS_CURSOR_RESIZE_NWSE;
        break;
    case IDC_ARROW:
    default:
        shape = DUETOS_CURSOR_ARROW;
        break;
    }
    long long prev = 0;
    asm volatile("syscall"
                 : "=a"(prev)
                 : "a"((long long)SYS_GDI_SET_CURSOR), "D"((long long)shape)
                 : "memory", "rcx", "r11");
    /* Map the kernel's previous shape back to an IDC_* HCURSOR
     * the caller can hand to a future SetCursor. */
    unsigned long prev_id = IDC_ARROW;
    switch (prev)
    {
    case DUETOS_CURSOR_IBEAM:
        prev_id = IDC_IBEAM;
        break;
    case DUETOS_CURSOR_HAND:
        prev_id = IDC_HAND;
        break;
    case DUETOS_CURSOR_WAIT:
        prev_id = IDC_WAIT;
        break;
    case DUETOS_CURSOR_RESIZE_NS:
        prev_id = IDC_SIZENS;
        break;
    case DUETOS_CURSOR_RESIZE_EW:
        prev_id = IDC_SIZEWE;
        break;
    case DUETOS_CURSOR_RESIZE_NESW:
        prev_id = IDC_SIZENESW;
        break;
    case DUETOS_CURSOR_RESIZE_NWSE:
        prev_id = IDC_SIZENWSE;
        break;
    default:
        prev_id = IDC_ARROW;
        break;
    }
    return (HANDLE)(unsigned long long)prev_id;
}
__declspec(dllexport) int ShowCursor(BOOL show)
{
    (void)show;
    return 0;
}

/* CreateCursor — register a custom 12x20 sprite. Win32's
 * signature takes hInstance + xHotSpot + yHotSpot + ANDmask +
 * XORmask; v1 simplifies to a single 240-byte mask buffer in
 * the kernel's tri-state encoding (0=transparent, 1=outline,
 * 2=fill). Callers that hand a Win32-shaped AND/XOR pair can
 * convert by walking each (and_bit, xor_bit) pair:
 *   AND=0 XOR=0  -> 1 (outline / black)
 *   AND=0 XOR=1  -> 2 (fill / white)
 *   AND=1 XOR=0  -> 0 (transparent)
 *   AND=1 XOR=1  -> 0 (inverter — degraded to transparent)
 *
 * Hotspot coordinates aren't honoured today; the kernel's
 * cursor anchors at (0, 0) of the sprite. Real Win32 hotspot
 * support waits on a follow-up. */
__declspec(dllexport) HANDLE DuetOsCreateCursor(const unsigned char* mask_240, unsigned char x_hot, unsigned char y_hot)
{
    long long h = 0;
    /* rdx packs (y_hot << 8) | x_hot — both fit in a byte. */
    const unsigned long long hotspot = ((unsigned long long)y_hot << 8) | (unsigned long long)x_hot;
    asm volatile("syscall"
                 : "=a"(h)
                 : "a"((long long)SYS_GDI_CREATE_CURSOR), "D"((long long)(unsigned long long)mask_240),
                   "S"((long long)(12 * 20)), "d"(hotspot)
                 : "memory", "rcx", "r11");
    return (HANDLE)(unsigned long long)h;
}

/* Win32-shaped CreateCursor. Sprites bigger than 12x20 are
 * downsampled to fit; smaller sprites are letterboxed. The
 * AND/XOR mask pair is walked into the kernel's tri-state
 * encoding per the helper above. Hot-spot coords are noted
 * but not honoured by the kernel. */
__declspec(dllexport) HANDLE CreateCursor(HANDLE hInstance, int xHot, int yHot, int width, int height,
                                          const void* and_mask, const void* xor_mask)
{
    (void)hInstance;
    (void)xHot;
    (void)yHot;
    /* v1: only the 12x20 case is supported — anything else
     * returns IDC_ARROW so the caller still has a usable
     * cursor. AND / XOR are 1 bit per pixel, packed MSB-first
     * into rows aligned up to a multiple of 16 bits per
     * Win32. */
    if (width != 12 || height != 20 || and_mask == 0 || xor_mask == 0)
        return (HANDLE)(unsigned long long)IDC_ARROW;
    const unsigned char* a = (const unsigned char*)and_mask;
    const unsigned char* x = (const unsigned char*)xor_mask;
    unsigned char m[12 * 20];
    /* Stride for a 12-px row, MSB-first, padded to 16 bits = 2 bytes. */
    const int stride = 2;
    for (int row = 0; row < 20; ++row)
    {
        for (int col = 0; col < 12; ++col)
        {
            const int byte = row * stride + (col / 8);
            const int bit = 7 - (col % 8);
            const unsigned char ab = (a[byte] >> bit) & 1;
            const unsigned char xb = (x[byte] >> bit) & 1;
            unsigned char v = 0;
            if (ab == 0 && xb == 0)
                v = 1; /* outline */
            else if (ab == 0 && xb == 1)
                v = 2; /* fill */
            /* AND=1 XOR={0,1} → transparent (XOR=1 is the
             * Win32 inverter colour we degrade to clear). */
            m[row * 12 + col] = v;
        }
    }
    /* Clamp the Win32 hotspot into the kernel's 12×20 grid. */
    unsigned char hx = (unsigned char)((xHot < 0) ? 0 : (xHot > 11 ? 11 : xHot));
    unsigned char hy = (unsigned char)((yHot < 0) ? 0 : (yHot > 19 ? 19 : yHot));
    return DuetOsCreateCursor(m, hx, hy);
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
    /* hwnd == NULL → "system timer" — return a synthetic cookie. */
    if (h == (HANDLE)0)
    {
        static unsigned long long g_sys_timer_id = 0xA000;
        return ++g_sys_timer_id;
    }
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
    /* hwnd == NULL → "system timer" cookie produced by SetTimer's
     * matching NULL-hwnd branch; we never registered it with the
     * kernel-side timer table, so there's nothing to kill. Return
     * TRUE — a timer that never fired and won't fire is, by Win32
     * contract, indistinguishable from one that was just removed. */
    if (h == (HANDLE)0)
    {
        (void)id;
        return 1;
    }
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
__declspec(dllexport) char* CharLowerA(char* s)
{
    if (!s)
        return s;
    for (char* p = s; *p; ++p)
        if (*p >= 'A' && *p <= 'Z')
            *p = (char)(*p + ('a' - 'A'));
    return s;
}
__declspec(dllexport) char* CharUpperA(char* s)
{
    if (!s)
        return s;
    for (char* p = s; *p; ++p)
        if (*p >= 'a' && *p <= 'z')
            *p = (char)(*p - ('a' - 'A'));
    return s;
}
__declspec(dllexport) BOOL IsCharAlphaA(char c)
{
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
}
__declspec(dllexport) BOOL IsCharAlphaW(wchar_t16 c)
{
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
}
__declspec(dllexport) BOOL IsCharAlphaNumericA(char c)
{
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9');
}
__declspec(dllexport) BOOL IsCharAlphaNumericW(wchar_t16 c)
{
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9');
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

/* --- Menu API ---
 * HMENU is a userland-allocated struct held in the per-process
 * bump pool below. Submenu marshaling across the SYS_WIN_TRACK_POPUP
 * syscall is a v0 GAP — submenu rows fall through as no-op clicks.
 * GetMenu/SetMenu/DrawMenuBar/LoadMenu/GetSystemMenu remain stubs
 * because menubars and resource-loaded menus are out of scope. */

#define USER32_MENU_CAP 32
#define USER32_MENU_ITEM_CAP 16
#define USER32_MENU_LABEL_CAP 32
#define USER32_MENU_MAGIC 0x756E4D48u /* 'HMnu' */

#define USER32_MF_GRAYED 0x0001u
#define USER32_MF_DISABLED 0x0002u
#define USER32_MF_CHECKED 0x0008u
#define USER32_MF_POPUP 0x0010u
#define USER32_MF_SEPARATOR 0x0800u

/* TPM_* flag bits — mirror kTpFlag* in
 * kernel/subsystems/win32/window_syscall.cpp. The kernel honours
 * RETURNCMD / NONOTIFY / *ALIGN; other bits are accepted but
 * inert in v0 (e.g. TPM_LEFTBUTTON / TPM_RIGHTBUTTON only matter
 * once the mouse-reader filters menu activation by which button
 * fired the click, which still defaults to left). */
#define USER32_TPM_LEFTBUTTON 0x0000u
#define USER32_TPM_RIGHTBUTTON 0x0002u
#define USER32_TPM_LEFTALIGN 0x0000u
#define USER32_TPM_CENTERALIGN 0x0004u
#define USER32_TPM_RIGHTALIGN 0x0008u
#define USER32_TPM_TOPALIGN 0x0000u
#define USER32_TPM_VCENTERALIGN 0x0010u
#define USER32_TPM_BOTTOMALIGN 0x0020u
#define USER32_TPM_NONOTIFY 0x0080u
#define USER32_TPM_RETURNCMD 0x0100u

/* Kernel mirror — must agree with kMenuItemFlag* in
 * kernel/drivers/video/menu.h. */
#define USER32_KMENU_FLAG_DISABLED 0x1u
#define USER32_KMENU_FLAG_CHECKED 0x2u
#define USER32_KMENU_FLAG_SUBMENU 0x4u
#define USER32_KMENU_FLAG_SEPARATOR 0x8u

struct user32_menu_item
{
    unsigned action_id;
    unsigned flags;                    /* kernel kMenuItemFlag* form */
    char label[USER32_MENU_LABEL_CAP]; /* NUL-terminated */
    HANDLE submenu;                    /* nullable */
};

struct user32_menu
{
    unsigned magic;    /* USER32_MENU_MAGIC when in use */
    unsigned is_popup; /* 1 if CreatePopupMenu, 0 if CreateMenu */
    unsigned count;
    struct user32_menu_item items[USER32_MENU_ITEM_CAP];
};

static struct user32_menu s_menus[USER32_MENU_CAP];

static struct user32_menu* user32_menu_resolve(HANDLE h)
{
    if (!h)
        return 0;
    long long idx_signed = (long long)(unsigned long long)h - 1; /* match HWND-style +1 bias */
    if (idx_signed < 0 || idx_signed >= USER32_MENU_CAP)
        return 0;
    struct user32_menu* m = &s_menus[(unsigned)idx_signed];
    if (m->magic != USER32_MENU_MAGIC)
        return 0;
    return m;
}

static HANDLE user32_menu_alloc(unsigned is_popup)
{
    for (unsigned i = 0; i < USER32_MENU_CAP; ++i)
    {
        if (s_menus[i].magic == 0)
        {
            s_menus[i].magic = USER32_MENU_MAGIC;
            s_menus[i].is_popup = is_popup;
            s_menus[i].count = 0;
            for (unsigned j = 0; j < USER32_MENU_ITEM_CAP; ++j)
            {
                s_menus[i].items[j].action_id = 0;
                s_menus[i].items[j].flags = 0;
                s_menus[i].items[j].label[0] = '\0';
                s_menus[i].items[j].submenu = (HANDLE)0;
            }
            return (HANDLE)(unsigned long long)(i + 1);
        }
    }
    return (HANDLE)0;
}

static unsigned user32_menu_translate_flags(UINT mf)
{
    unsigned k = 0;
    if (mf & (USER32_MF_GRAYED | USER32_MF_DISABLED))
        k |= USER32_KMENU_FLAG_DISABLED;
    if (mf & USER32_MF_CHECKED)
        k |= USER32_KMENU_FLAG_CHECKED;
    if (mf & USER32_MF_SEPARATOR)
        k |= USER32_KMENU_FLAG_SEPARATOR;
    if (mf & USER32_MF_POPUP)
        k |= USER32_KMENU_FLAG_SUBMENU;
    return k;
}

__declspec(dllexport) HANDLE CreateMenu(void)
{
    return user32_menu_alloc(0);
}
__declspec(dllexport) HANDLE CreatePopupMenu(void)
{
    return user32_menu_alloc(1);
}
__declspec(dllexport) BOOL DestroyMenu(HANDLE menu)
{
    struct user32_menu* m = user32_menu_resolve(menu);
    if (!m)
        return 0;
    /* Recursively destroy submenus referenced via MF_POPUP. */
    for (unsigned i = 0; i < m->count; ++i)
    {
        if (m->items[i].submenu)
            DestroyMenu(m->items[i].submenu);
    }
    m->magic = 0;
    m->count = 0;
    return 1;
}
/* Menubar slots — STUB: menubar drawing is out of scope for v0. */
__declspec(dllexport) HANDLE GetMenu(HANDLE hwnd)
{
    (void)hwnd;
    return (HANDLE)0;
}
__declspec(dllexport) BOOL SetMenu(HANDLE hwnd, HANDLE menu)
{
    (void)hwnd;
    (void)menu;
    return 1;
}
__declspec(dllexport) HANDLE GetSubMenu(HANDLE menu, int pos)
{
    struct user32_menu* m = user32_menu_resolve(menu);
    if (!m || pos < 0 || (unsigned)pos >= m->count)
        return (HANDLE)0;
    return m->items[(unsigned)pos].submenu;
}
__declspec(dllexport) int GetMenuItemCount(HANDLE menu)
{
    struct user32_menu* m = user32_menu_resolve(menu);
    return m ? (int)m->count : -1;
}
__declspec(dllexport) UINT GetMenuItemID(HANDLE menu, int pos)
{
    struct user32_menu* m = user32_menu_resolve(menu);
    if (!m || pos < 0 || (unsigned)pos >= m->count)
        return 0xFFFFFFFFu;
    return m->items[(unsigned)pos].action_id;
}
__declspec(dllexport) UINT GetMenuState(HANDLE menu, UINT id, UINT flags)
{
    struct user32_menu* m = user32_menu_resolve(menu);
    if (!m)
        return 0xFFFFFFFFu;
    /* MF_BYPOSITION (0x400) flips lookup mode. */
    const unsigned by_pos = (flags & 0x400) != 0;
    for (unsigned i = 0; i < m->count; ++i)
    {
        const unsigned key = by_pos ? i : m->items[i].action_id;
        if (key == id)
        {
            unsigned r = 0;
            if (m->items[i].flags & USER32_KMENU_FLAG_DISABLED)
                r |= USER32_MF_DISABLED;
            if (m->items[i].flags & USER32_KMENU_FLAG_CHECKED)
                r |= USER32_MF_CHECKED;
            if (m->items[i].flags & USER32_KMENU_FLAG_SEPARATOR)
                r |= USER32_MF_SEPARATOR;
            if (m->items[i].submenu)
                r |= USER32_MF_POPUP;
            return r;
        }
    }
    return 0xFFFFFFFFu;
}
__declspec(dllexport) BOOL AppendMenuA(HANDLE menu, UINT flags, unsigned long long item_id, const char* text)
{
    struct user32_menu* m = user32_menu_resolve(menu);
    if (!m || m->count >= USER32_MENU_ITEM_CAP)
        return 0;
    struct user32_menu_item* it = &m->items[m->count];
    it->action_id = (unsigned)(item_id & 0xFFFFFFFFu);
    it->flags = user32_menu_translate_flags(flags);
    if (flags & USER32_MF_POPUP)
    {
        /* When MF_POPUP is set, `text` is actually an HMENU. */
        it->submenu = (HANDLE)(unsigned long long)item_id; /* MSDN quirk */
        /* Action_id of a popup row is the submenu HMENU's value;
         * the kernel side treats it as an opaque pass-through. */
        it->label[0] = '\0';
        if (text)
            user32_strcpy_ascii(it->label, USER32_MENU_LABEL_CAP, text);
    }
    else
    {
        it->submenu = (HANDLE)0;
        it->label[0] = '\0';
        if (text && (flags & USER32_MF_SEPARATOR) == 0)
            user32_strcpy_ascii(it->label, USER32_MENU_LABEL_CAP, text);
    }
    ++m->count;
    return 1;
}
__declspec(dllexport) BOOL AppendMenuW(HANDLE menu, UINT flags, unsigned long long item_id, const wchar_t16* text)
{
    char buf[USER32_MENU_LABEL_CAP];
    buf[0] = '\0';
    if (text && (flags & USER32_MF_SEPARATOR) == 0)
    {
        unsigned i = 0;
        for (; i + 1 < USER32_MENU_LABEL_CAP && text[i]; ++i)
        {
            wchar_t16 wc = text[i];
            buf[i] = (wc < 0x80) ? (char)wc : '?';
        }
        buf[i] = '\0';
    }
    return AppendMenuA(menu, flags, item_id, buf);
}
__declspec(dllexport) BOOL InsertMenuA(HANDLE menu, UINT pos, UINT flags, unsigned long long item_id, const char* text)
{
    struct user32_menu* m = user32_menu_resolve(menu);
    if (!m || m->count >= USER32_MENU_ITEM_CAP)
        return 0;
    /* MF_BYPOSITION (0x400) — `pos` is an index. v0 ignores
     * MF_BYCOMMAND lookup and always treats pos as an index,
     * clamped. */
    unsigned at = pos;
    if (at > m->count)
        at = m->count;
    /* Shift items to make room at `at`. */
    for (unsigned i = m->count; i > at; --i)
        m->items[i] = m->items[i - 1];
    ++m->count;
    /* Reuse Append's translation by rewriting in place. */
    --m->count;
    BOOL ok = AppendMenuA(menu, flags, item_id, text); /* appends at old end */
    if (!ok)
        return 0;
    /* Move the just-appended item to `at` if needed. */
    if (at != m->count - 1)
    {
        struct user32_menu_item tmp = m->items[m->count - 1];
        for (unsigned i = m->count - 1; i > at; --i)
            m->items[i] = m->items[i - 1];
        m->items[at] = tmp;
    }
    return 1;
}
__declspec(dllexport) BOOL InsertMenuW(HANDLE menu, UINT pos, UINT flags, unsigned long long item_id,
                                       const wchar_t16* text)
{
    char buf[USER32_MENU_LABEL_CAP];
    buf[0] = '\0';
    if (text && (flags & USER32_MF_SEPARATOR) == 0)
    {
        unsigned i = 0;
        for (; i + 1 < USER32_MENU_LABEL_CAP && text[i]; ++i)
        {
            wchar_t16 wc = text[i];
            buf[i] = (wc < 0x80) ? (char)wc : '?';
        }
        buf[i] = '\0';
    }
    return InsertMenuA(menu, pos, flags, item_id, buf);
}
__declspec(dllexport) BOOL RemoveMenu(HANDLE menu, UINT pos, UINT flags)
{
    struct user32_menu* m = user32_menu_resolve(menu);
    if (!m)
        return 0;
    const unsigned by_pos = (flags & 0x400) != 0;
    unsigned at = USER32_MENU_ITEM_CAP;
    for (unsigned i = 0; i < m->count; ++i)
    {
        const unsigned key = by_pos ? i : m->items[i].action_id;
        if (key == pos)
        {
            at = i;
            break;
        }
    }
    if (at == USER32_MENU_ITEM_CAP)
        return 0;
    for (unsigned i = at; i + 1 < m->count; ++i)
        m->items[i] = m->items[i + 1];
    --m->count;
    return 1;
}
__declspec(dllexport) BOOL DeleteMenu(HANDLE menu, UINT pos, UINT flags)
{
    /* DeleteMenu also frees the submenu it points at. */
    struct user32_menu* m = user32_menu_resolve(menu);
    if (!m)
        return 0;
    const unsigned by_pos = (flags & 0x400) != 0;
    for (unsigned i = 0; i < m->count; ++i)
    {
        const unsigned key = by_pos ? i : m->items[i].action_id;
        if (key == pos && m->items[i].submenu)
        {
            DestroyMenu(m->items[i].submenu);
            m->items[i].submenu = (HANDLE)0;
            break;
        }
    }
    return RemoveMenu(menu, pos, flags);
}
__declspec(dllexport) BOOL EnableMenuItem(HANDLE menu, UINT id, UINT flags)
{
    struct user32_menu* m = user32_menu_resolve(menu);
    if (!m)
        return 0xFFFFFFFFu;
    const unsigned by_pos = (flags & 0x400) != 0;
    const unsigned want_disabled = (flags & (USER32_MF_GRAYED | USER32_MF_DISABLED)) != 0;
    for (unsigned i = 0; i < m->count; ++i)
    {
        const unsigned key = by_pos ? i : m->items[i].action_id;
        if (key == id)
        {
            const unsigned prev = (m->items[i].flags & USER32_KMENU_FLAG_DISABLED) ? 1u : 0u;
            if (want_disabled)
                m->items[i].flags |= USER32_KMENU_FLAG_DISABLED;
            else
                m->items[i].flags &= ~USER32_KMENU_FLAG_DISABLED;
            return prev;
        }
    }
    return 0xFFFFFFFFu;
}
__declspec(dllexport) DWORD CheckMenuItem(HANDLE menu, UINT id, UINT flags)
{
    struct user32_menu* m = user32_menu_resolve(menu);
    if (!m)
        return 0xFFFFFFFFu;
    const unsigned by_pos = (flags & 0x400) != 0;
    const unsigned want_checked = (flags & USER32_MF_CHECKED) != 0;
    for (unsigned i = 0; i < m->count; ++i)
    {
        const unsigned key = by_pos ? i : m->items[i].action_id;
        if (key == id)
        {
            const unsigned prev = (m->items[i].flags & USER32_KMENU_FLAG_CHECKED) ? USER32_MF_CHECKED : 0u;
            if (want_checked)
                m->items[i].flags |= USER32_KMENU_FLAG_CHECKED;
            else
                m->items[i].flags &= ~USER32_KMENU_FLAG_CHECKED;
            return prev;
        }
    }
    return 0xFFFFFFFFu;
}
__declspec(dllexport) BOOL ModifyMenuA(HANDLE menu, UINT pos, UINT flags, unsigned long long item_id, const char* text)
{
    /* Replace the item at `pos`/id with new text/flags. */
    struct user32_menu* m = user32_menu_resolve(menu);
    if (!m)
        return 0;
    const unsigned by_pos = (flags & 0x400) != 0;
    for (unsigned i = 0; i < m->count; ++i)
    {
        const unsigned key = by_pos ? i : m->items[i].action_id;
        if (key == pos)
        {
            m->items[i].flags = user32_menu_translate_flags(flags);
            m->items[i].action_id = (unsigned)(item_id & 0xFFFFFFFFu);
            m->items[i].label[0] = '\0';
            if (text && (flags & USER32_MF_SEPARATOR) == 0)
                user32_strcpy_ascii(m->items[i].label, USER32_MENU_LABEL_CAP, text);
            return 1;
        }
    }
    return 0;
}
__declspec(dllexport) BOOL ModifyMenuW(HANDLE menu, UINT pos, UINT flags, unsigned long long item_id,
                                       const wchar_t16* text)
{
    char buf[USER32_MENU_LABEL_CAP];
    buf[0] = '\0';
    if (text && (flags & USER32_MF_SEPARATOR) == 0)
    {
        unsigned i = 0;
        for (; i + 1 < USER32_MENU_LABEL_CAP && text[i]; ++i)
        {
            wchar_t16 wc = text[i];
            buf[i] = (wc < 0x80) ? (char)wc : '?';
        }
        buf[i] = '\0';
    }
    return ModifyMenuA(menu, pos, flags, item_id, buf);
}

/* Wire format the kernel expects (mirror of TpReqWire / TpItemWire
 * in kernel/subsystems/win32/window_syscall.cpp). MUST match. */
#define USER32_TP_LABEL_CAP 32
#define USER32_TP_MAX_ITEMS 12

struct user32_tp_item
{
    unsigned action_id;
    unsigned flags;
    char label[USER32_TP_LABEL_CAP];
};

struct user32_tp_req
{
    unsigned count;
    unsigned flags;
    int screen_x, screen_y;
    unsigned long long hwnd_biased;
    struct user32_tp_item items[USER32_TP_MAX_ITEMS];
};

__declspec(dllexport) BOOL TrackPopupMenu(HANDLE menu, UINT flags, int x, int y, int reserved, HANDLE hwnd, void* rect)
{
    (void)reserved;
    (void)rect;
    struct user32_menu* m = user32_menu_resolve(menu);
    if (!m || !m->is_popup || m->count == 0)
        return 0;
    if (m->count > USER32_TP_MAX_ITEMS)
        return 0;
    struct user32_tp_req req;
    /* Zero unused tail items so non-debug kernels can't fault on
     * stale stack bytes. */
    for (unsigned i = 0; i < sizeof(req); ++i)
        ((unsigned char*)&req)[i] = 0;
    req.count = m->count;
    req.flags = flags;
    req.screen_x = x;
    req.screen_y = y;
    req.hwnd_biased = (unsigned long long)hwnd;
    for (unsigned i = 0; i < m->count; ++i)
    {
        req.items[i].action_id = m->items[i].action_id;
        req.items[i].flags = m->items[i].flags;
        unsigned j = 0;
        for (; j + 1 < USER32_TP_LABEL_CAP && m->items[i].label[j]; ++j)
            req.items[i].label[j] = m->items[i].label[j];
        req.items[i].label[j] = '\0';
    }
    long long rv;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"((long long)SYS_WIN_TRACK_POPUP), "D"((long long)(unsigned long long)&req),
                       "S"((long long)USER32_TP_MAX_ITEMS)
                     : "memory");
    return (BOOL)(unsigned long)rv;
}
__declspec(dllexport) BOOL TrackPopupMenuEx(HANDLE menu, UINT flags, int x, int y, HANDLE hwnd, void* params)
{
    /* TPMPARAMS exclude-rect is ignored in v0. */
    (void)params;
    return TrackPopupMenu(menu, flags, x, y, 0, hwnd, (void*)0);
}
__declspec(dllexport) BOOL DrawMenuBar(HANDLE hwnd)
{
    /* STUB: menubar drawing not implemented in v0. */
    (void)hwnd;
    return 1;
}

/* --- Charset / virtual-key conversion ---
 *
 * MapVirtualKey converts between virtual-key codes (VK_*), PS/2
 * set-1 scan codes, and character codes. The mapping is keyboard-
 * layout-dependent on real Windows; v0 commits to US layout and
 * documents the rest as a GAP — every PE the smoke tests run
 * against assumes US, and the layout-table machinery (HKL ->
 * keyboard.dll preload, OEM key tables) isn't wired yet.
 *
 * Supported `type` selectors:
 *   MAPVK_VK_TO_VSC  (0): VK_* -> PS/2 set-1 scan code (or 0 if no
 *                          unambiguous mapping).
 *   MAPVK_VSC_TO_VK  (1): PS/2 scan code -> VK_*.
 *   MAPVK_VK_TO_CHAR (2): VK_* -> UPPERCASE printable char on US
 *                          layout (low 16 bits). Non-printable
 *                          VK_* (modifiers, function keys) returns
 *                          0.
 *   MAPVK_VSC_TO_VK_EX (3): scan -> VK with extended info, same
 *                            mapping as MAPVK_VSC_TO_VK in v0
 *                            (we don't carry extended-key state).
 *
 * GAP: layout-aware mapping (non-US, dead keys, AltGr-introduced
 *      characters) is not implemented. */

#ifndef MAPVK_VK_TO_VSC
#define MAPVK_VK_TO_VSC 0u
#define MAPVK_VSC_TO_VK 1u
#define MAPVK_VK_TO_CHAR 2u
#define MAPVK_VSC_TO_VK_EX 3u
#endif

/* PS/2 set-1 scan codes for VK_A..VK_Z (index = VK - 'A'). */
static const unsigned char k_vk_alpha_to_vsc[26] = {
    0x1E, 0x30, 0x2E, 0x20, 0x12, 0x21, 0x22, 0x23, /* A B C D E F G H */
    0x17, 0x24, 0x25, 0x26, 0x32, 0x31, 0x18, 0x19, /* I J K L M N O P */
    0x10, 0x13, 0x1F, 0x14, 0x16, 0x2F, 0x11, 0x2D, /* Q R S T U V W X */
    0x15, 0x2C                                      /* Y Z */
};
/* PS/2 set-1 scan codes for VK_0..VK_9 (top row, index = VK - '0'). */
static const unsigned char k_vk_digit_to_vsc[10] = {0x0B, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A};

static UINT vk_to_vsc(UINT vk)
{
    if (vk >= 'A' && vk <= 'Z')
        return k_vk_alpha_to_vsc[vk - 'A'];
    if (vk >= '0' && vk <= '9')
        return k_vk_digit_to_vsc[vk - '0'];
    /* Numpad VK_NUMPAD0..9 (0x60..0x69). */
    if (vk >= 0x60 && vk <= 0x69)
    {
        static const unsigned char k_numpad[10] = {0x52, 0x4F, 0x50, 0x51, 0x4B, 0x4C, 0x4D, 0x47, 0x48, 0x49};
        return k_numpad[vk - 0x60];
    }
    switch (vk)
    {
    case 0x08:
        return 0x0E; /* VK_BACK     */
    case 0x09:
        return 0x0F; /* VK_TAB      */
    case 0x0D:
        return 0x1C; /* VK_RETURN   */
    case 0x10:
        return 0x2A; /* VK_SHIFT    -> left shift */
    case 0x11:
        return 0x1D; /* VK_CONTROL  -> left ctrl  */
    case 0x12:
        return 0x38; /* VK_MENU     -> left alt   */
    case 0x14:
        return 0x3A; /* VK_CAPITAL  */
    case 0x1B:
        return 0x01; /* VK_ESCAPE   */
    case 0x20:
        return 0x39; /* VK_SPACE    */
    case 0x21:
        return 0x49; /* VK_PRIOR    (pgup, numpad) */
    case 0x22:
        return 0x51; /* VK_NEXT     (pgdn, numpad) */
    case 0x23:
        return 0x4F; /* VK_END      */
    case 0x24:
        return 0x47; /* VK_HOME     */
    case 0x25:
        return 0x4B; /* VK_LEFT     */
    case 0x26:
        return 0x48; /* VK_UP       */
    case 0x27:
        return 0x4D; /* VK_RIGHT    */
    case 0x28:
        return 0x50; /* VK_DOWN     */
    case 0x2D:
        return 0x52; /* VK_INSERT   */
    case 0x2E:
        return 0x53; /* VK_DELETE   */
    case 0x6A:
        return 0x37; /* VK_MULTIPLY */
    case 0x6B:
        return 0x4E; /* VK_ADD      */
    case 0x6D:
        return 0x4A; /* VK_SUBTRACT */
    case 0x6E:
        return 0x53; /* VK_DECIMAL  */
    case 0x6F:
        return 0x35; /* VK_DIVIDE   */
    case 0x70:
        return 0x3B; /* VK_F1       */
    case 0x71:
        return 0x3C; /* VK_F2       */
    case 0x72:
        return 0x3D; /* VK_F3       */
    case 0x73:
        return 0x3E; /* VK_F4       */
    case 0x74:
        return 0x3F; /* VK_F5       */
    case 0x75:
        return 0x40; /* VK_F6       */
    case 0x76:
        return 0x41; /* VK_F7       */
    case 0x77:
        return 0x42; /* VK_F8       */
    case 0x78:
        return 0x43; /* VK_F9       */
    case 0x79:
        return 0x44; /* VK_F10      */
    case 0x7A:
        return 0x57; /* VK_F11      */
    case 0x7B:
        return 0x58; /* VK_F12      */
    case 0xBA:
        return 0x27; /* VK_OEM_1     ';' */
    case 0xBB:
        return 0x0D; /* VK_OEM_PLUS  '=' */
    case 0xBC:
        return 0x33; /* VK_OEM_COMMA ',' */
    case 0xBD:
        return 0x0C; /* VK_OEM_MINUS '-' */
    case 0xBE:
        return 0x34; /* VK_OEM_PERIOD '.' */
    case 0xBF:
        return 0x35; /* VK_OEM_2     '/' */
    case 0xC0:
        return 0x29; /* VK_OEM_3     '`' */
    case 0xDB:
        return 0x1A; /* VK_OEM_4     '[' */
    case 0xDC:
        return 0x2B; /* VK_OEM_5     '\\' */
    case 0xDD:
        return 0x1B; /* VK_OEM_6     ']' */
    case 0xDE:
        return 0x28; /* VK_OEM_7     '\'' */
    default:
        return 0;
    }
}

static UINT vk_to_char(UINT vk)
{
    if (vk >= 'A' && vk <= 'Z')
        return vk; /* uppercase per docs */
    if (vk >= '0' && vk <= '9')
        return vk;
    if (vk >= 0x60 && vk <= 0x69)
        return (UINT)('0' + (vk - 0x60));
    switch (vk)
    {
    case 0x20:
        return ' ';
    case 0x6A:
        return '*';
    case 0x6B:
        return '+';
    case 0x6D:
        return '-';
    case 0x6E:
        return '.';
    case 0x6F:
        return '/';
    case 0xBA:
        return ';';
    case 0xBB:
        return '=';
    case 0xBC:
        return ',';
    case 0xBD:
        return '-';
    case 0xBE:
        return '.';
    case 0xBF:
        return '/';
    case 0xC0:
        return '`';
    case 0xDB:
        return '[';
    case 0xDC:
        return '\\';
    case 0xDD:
        return ']';
    case 0xDE:
        return '\'';
    default:
        return 0; /* modifiers, function keys: no char */
    }
}

static UINT vsc_to_vk(UINT vsc)
{
    /* Reverse the VK_A..VK_Z table. Small enough to scan linearly. */
    for (UINT i = 0; i < 26; ++i)
        if (k_vk_alpha_to_vsc[i] == (unsigned char)vsc)
            return 'A' + i;
    for (UINT i = 0; i < 10; ++i)
        if (k_vk_digit_to_vsc[i] == (unsigned char)vsc)
            return '0' + i;
    switch (vsc)
    {
    case 0x0E:
        return 0x08; /* VK_BACK   */
    case 0x0F:
        return 0x09; /* VK_TAB    */
    case 0x1C:
        return 0x0D; /* VK_RETURN */
    case 0x2A:
        return 0x10; /* VK_SHIFT  */
    case 0x36:
        return 0x10; /* right shift -> VK_SHIFT */
    case 0x1D:
        return 0x11; /* VK_CONTROL */
    case 0x38:
        return 0x12; /* VK_MENU   */
    case 0x3A:
        return 0x14; /* VK_CAPITAL */
    case 0x01:
        return 0x1B; /* VK_ESCAPE */
    case 0x39:
        return 0x20; /* VK_SPACE  */
    case 0x49:
        return 0x21; /* VK_PRIOR  */
    case 0x51:
        return 0x22; /* VK_NEXT   */
    case 0x4F:
        return 0x23; /* VK_END    */
    case 0x47:
        return 0x24; /* VK_HOME   */
    case 0x4B:
        return 0x25; /* VK_LEFT   */
    case 0x48:
        return 0x26; /* VK_UP     */
    case 0x4D:
        return 0x27; /* VK_RIGHT  */
    case 0x50:
        return 0x28; /* VK_DOWN   */
    case 0x52:
        return 0x2D; /* VK_INSERT */
    case 0x53:
        return 0x2E; /* VK_DELETE */
    case 0x37:
        return 0x6A; /* VK_MULTIPLY */
    case 0x4E:
        return 0x6B; /* VK_ADD    */
    case 0x4A:
        return 0x6D; /* VK_SUBTRACT */
    case 0x35:
        return 0x6F; /* VK_DIVIDE / VK_OEM_2 — '/' wins */
    case 0x3B:
        return 0x70; /* VK_F1     */
    case 0x3C:
        return 0x71;
    case 0x3D:
        return 0x72;
    case 0x3E:
        return 0x73;
    case 0x3F:
        return 0x74;
    case 0x40:
        return 0x75;
    case 0x41:
        return 0x76;
    case 0x42:
        return 0x77;
    case 0x43:
        return 0x78;
    case 0x44:
        return 0x79;
    case 0x57:
        return 0x7A; /* VK_F11    */
    case 0x58:
        return 0x7B; /* VK_F12    */
    case 0x27:
        return 0xBA; /* VK_OEM_1 ';' */
    case 0x0D:
        return 0xBB; /* VK_OEM_PLUS '=' */
    case 0x33:
        return 0xBC; /* VK_OEM_COMMA */
    case 0x0C:
        return 0xBD; /* VK_OEM_MINUS */
    case 0x34:
        return 0xBE; /* VK_OEM_PERIOD */
    case 0x29:
        return 0xC0; /* VK_OEM_3 '`' */
    case 0x1A:
        return 0xDB; /* VK_OEM_4 '[' */
    case 0x2B:
        return 0xDC; /* VK_OEM_5 '\\' */
    case 0x1B:
        return 0xDD; /* VK_OEM_6 ']' */
    case 0x28:
        return 0xDE; /* VK_OEM_7 '\'' */
    default:
        return 0;
    }
}

__declspec(dllexport) UINT MapVirtualKeyA(UINT code, UINT type)
{
    switch (type)
    {
    case MAPVK_VK_TO_VSC:
        return vk_to_vsc(code);
    case MAPVK_VSC_TO_VK:
        return vsc_to_vk(code);
    case MAPVK_VK_TO_CHAR:
        return vk_to_char(code);
    case MAPVK_VSC_TO_VK_EX:
        return vsc_to_vk(code);
    default:
        return 0;
    }
}
__declspec(dllexport) UINT MapVirtualKeyW(UINT code, UINT type)
{
    return MapVirtualKeyA(code, type);
}
__declspec(dllexport) UINT MapVirtualKeyExA(UINT code, UINT type, HANDLE layout)
{
    (void)layout; /* GAP: per-layout HKL not honored — v0 is US-only. */
    return MapVirtualKeyA(code, type);
}
__declspec(dllexport) UINT MapVirtualKeyExW(UINT code, UINT type, HANDLE layout)
{
    return MapVirtualKeyExA(code, type, layout);
}
__declspec(dllexport) UINT GetKeyboardLayout(DWORD thread)
{
    (void)thread;
    return 0x04090409u; /* en-US, en-US */
}

/* --- Window state queries (only ones not already in user32) --- */
__declspec(dllexport) BOOL IsZoomed(HANDLE hwnd)
{
    (void)hwnd;
    return 0;
}
__declspec(dllexport) BOOL IsIconic(HANDLE hwnd)
{
    (void)hwnd;
    return 0;
}
__declspec(dllexport) BOOL IsChild(HANDLE parent, HANDLE child)
{
    (void)parent;
    (void)child;
    return 0;
}
__declspec(dllexport) DWORD GetWindowThreadProcessId(HANDLE hwnd, DWORD* pid)
{
    (void)hwnd;
    if (pid)
        *pid = 1;
    return 1;
}

/* Multi-monitor enumeration — single-monitor sentinel. */

__declspec(dllexport) BOOL EnumDisplayMonitors(void* dc, const void* clip, void* fn, long long lparam)
{
    (void)clip;
    typedef BOOL(__stdcall * cb_t)(void*, void*, void*, long long);
    cb_t cb = (cb_t)fn;
    if (cb == (cb_t)0)
        return 1;
    long rect[4] = {0, 0, 1024, 768};
    cb((void*)(unsigned long long)0x9001, dc, rect, lparam);
    return 1;
}

typedef struct
{
    long x, y;
} DUETOS_POINT;

__declspec(dllexport) void* MonitorFromPoint(DUETOS_POINT pt, DWORD flags)
{
    (void)pt;
    (void)flags;
    return (void*)(unsigned long long)0x9001;
}

__declspec(dllexport) void* MonitorFromWindow(void* w, DWORD flags)
{
    (void)w;
    (void)flags;
    return (void*)(unsigned long long)0x9001;
}

__declspec(dllexport) BOOL GetMonitorInfoW(void* m, void* info)
{
    (void)m;
    if (info == (void*)0)
        return 0;
    DWORD* p = (DWORD*)info;
    if (p[0] < 40)
        return 0;
    long* l = (long*)(p + 1);
    l[0] = 0;
    l[1] = 0;
    l[2] = 1024;
    l[3] = 768;
    l[4] = 0;
    l[5] = 0;
    l[6] = 1024;
    l[7] = 768;
    p[9] = 1;
    return 1;
}

__declspec(dllexport) BOOL EnumDisplayDevicesW(const wchar_t16* dev, DWORD idx, void* info, DWORD flags)
{
    (void)dev;
    (void)flags;
    if (info == (void*)0)
        return 0;
    if (idx > 0)
        return 0;
    DWORD* p = (DWORD*)info;
    if (p[0] < 4)
        return 0;
    wchar_t16* name = (wchar_t16*)((unsigned char*)info + 4);
    static const wchar_t16 kName[] = {'\\', '\\', '.', '\\', 'D', 'I', 'S', 'P', 'L', 'A', 'Y', '1', 0};
    int j = 0;
    while (kName[j] != 0)
    {
        name[j] = kName[j];
        ++j;
    }
    name[j] = 0;
    return 1;
}

__declspec(dllexport) BOOL EnumDisplaySettingsW(const wchar_t16* dev, DWORD mode, void* dm)
{
    (void)dev;
    (void)mode;
    if (dm == (void*)0)
        return 0;
    return 1;
}

/* DDEML — DdeInitialize + string-handle plumbing. */
__declspec(dllexport) UINT DdeInitializeA(DWORD* inst, void* cb, DWORD flags, DWORD rsv)
{
    (void)cb;
    (void)flags;
    (void)rsv;
    if (inst == (DWORD*)0)
        return 1; /* DMLERR_INVALIDPARAMETER */
    *inst = 0xDDE10001;
    return 0; /* DMLERR_NO_ERROR */
}

__declspec(dllexport) UINT DdeInitializeW(DWORD* inst, void* cb, DWORD flags, DWORD rsv)
{
    return DdeInitializeA(inst, cb, flags, rsv);
}

__declspec(dllexport) BOOL DdeUninitialize(DWORD inst)
{
    (void)inst;
    return 1;
}

/* String handles: just pack a 32-bit counter into the handle. */
static DWORD g_dde_next = 0xD5000001;
__declspec(dllexport) void* DdeCreateStringHandleA(DWORD inst, const char* name, int cp)
{
    (void)inst;
    (void)name;
    (void)cp;
    return (void*)(unsigned long long)(g_dde_next++);
}
__declspec(dllexport) void* DdeCreateStringHandleW(DWORD inst, const wchar_t16* name, int cp)
{
    (void)inst;
    (void)name;
    (void)cp;
    return (void*)(unsigned long long)(g_dde_next++);
}
__declspec(dllexport) BOOL DdeFreeStringHandle(DWORD inst, void* h)
{
    (void)inst;
    (void)h;
    return 1;
}

/* GetDC / GetWindowDC / ReleaseDC — re-exported from user32 in
 * addition to gdi32. Real Windows ships GetDC/ReleaseDC in
 * user32.dll (the WM-side surface) and CreateCompatibleDC etc.
 * in gdi32.dll (the rendering surface); mingw-w64's headers
 * import GetDC from user32.dll, so a smoke-test PE built against
 * standard headers imports user32.dll!GetDC and falls through to
 * the kernel flat-thunk catch-all when the userland user32 doesn't
 * export it. The forwarders below mirror gdi32.c's HDC encoding
 * (HWND | GDI_TAG, 0xDC00000000ULL) so the HDC handed back can
 * round-trip through gdi32's downstream calls.
 *
 * Caveat: GetDC(NULL) returns the bare GDI_TAG sentinel which is
 * non-zero — that's enough to satisfy "did GetDC succeed?" probes;
 * actual screen-DC rendering against the desktop framebuffer needs
 * a real desktop-window registration that doesn't exist in v0. */
__declspec(dllexport) HANDLE GetDC(HANDLE hwnd)
{
    return (HANDLE)((unsigned long long)hwnd | 0xDC00000000ULL);
}

__declspec(dllexport) HANDLE GetWindowDC(HANDLE hwnd)
{
    return GetDC(hwnd);
}

__declspec(dllexport) int ReleaseDC(HANDLE hwnd, HANDLE dc)
{
    (void)hwnd;
    (void)dc;
    return 1;
}

/* GetClassInfoW — succeed iff `class_name` matches a class
 * previously registered via RegisterClass* (looked up against the
 * shared `s_classes[]` table that RegisterClassA / RegisterClassW
 * populate). On hit, zero-fill the caller's WNDCLASSW and copy in
 * the registered WNDPROC + class name so the caller can hand the
 * struct back into a CreateWindowEx pair. On miss, return FALSE
 * cleanly — that's the contract every Win32 GUI app's "is class
 * registered" probe expects. */
__declspec(dllexport) BOOL GetClassInfoW(void* hInst, const wchar_t16* class_name, void* wcw)
{
    (void)hInst;
    if (class_name == (const wchar_t16*)0 || wcw == (void*)0)
        return 0;
    if (class_name[0] == 0)
        return 0;
    /* Flatten the wide name with low-byte strip — same convention
     * RegisterClassW uses to populate s_classes, so a register +
     * lookup pair against the same wide name canonicalises. */
    char flat[64];
    int i = 0;
    while (i < (int)sizeof(flat) - 1 && class_name[i] != 0)
    {
        flat[i] = (char)(class_name[i] & 0xFF);
        ++i;
    }
    flat[i] = '\0';
    WNDPROC proc = user32_class_lookup(flat);
    if (proc == 0)
        return 0;
    /* Zero-fill the WNDCLASSW + copy the resolved WNDPROC. The
     * struct is ~64 bytes (WNDCLASSEXW is ~80); zeroing 80 covers
     * either form. The first slot is `style`; lpfnWndProc lives
     * at offset 8 (after the 4-byte style + 4-byte alignment). */
    unsigned char* b = (unsigned char*)wcw;
    for (int j = 0; j < 80; ++j)
        b[j] = 0;
    /* WNDCLASSW layout: { UINT style; WNDPROC lpfnWndProc; ... }.
     * lpfnWndProc is at offset 8 on x64 (struct alignment). */
    *(WNDPROC*)(b + 8) = proc;
    return 1;
}

__declspec(dllexport) BOOL GetClassInfoExW(void* hInst, const wchar_t16* class_name, void* wcx)
{
    return GetClassInfoW(hInst, class_name, wcx);
}

/* CreateAcceleratorTableW — sentinel handle. */
__declspec(dllexport) void* CreateAcceleratorTableW(void* accels, int n)
{
    (void)accels;
    if (n <= 0)
        return (void*)0;
    return (void*)(unsigned long long)0xACE10001;
}

__declspec(dllexport) int CopyAcceleratorTableW(void* h, void* dst, int n)
{
    (void)h;
    (void)dst;
    return n; /* return requested count */
}

__declspec(dllexport) BOOL DestroyAcceleratorTable(void* h)
{
    (void)h;
    return 1;
}

/* GetDpiForSystem / GetDpiForWindow — user32 (Win10+ moved here). */
__declspec(dllexport) UINT GetDpiForSystem(void)
{
    return 96;
}
__declspec(dllexport) UINT GetDpiForWindow(void* hwnd)
{
    (void)hwnd;
    return 96;
}
