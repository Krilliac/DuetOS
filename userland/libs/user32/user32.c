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
 *   - PostQuitMessage posts HWND-less WM_QUIT (0x0012) to the exact
 *     calling task queue.
 *   - CreateWindowExA/W returns a PE32-safe slot+generation HWND; a
 *     destroyed generation never resolves after its slot is reused.
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
#define SYS_GETPID 1 /* Duet task id / Win32 thread id */
#define SYS_WIN_CREATE 58
#define SYS_WIN_DESTROY 59
#define SYS_WIN_SHOW 60
#define SYS_WIN_MSGBOX 61
#define SYS_WIN_PEEK_MSG 62
#define SYS_WIN_GET_MSG 63
#define SYS_WIN_POST_MSG 64
#define DUETOS_THREAD_MESSAGE_TAG 0x80000000u
#define DUETOS_THREAD_MESSAGE_TID_MASK 0x7FFFFFFFu
#define SYS_WIN_MOVE 69
#define SYS_WIN_GET_RECT 70
#define SYS_WIN_SET_TEXT 71
#define SYS_WIN_TIMER_SET 72
#define SYS_WIN_TIMER_KILL 73
#define SYS_WIN_GET_KEYSTATE 77
#define SYS_WIN_GET_CURSOR 78
#define SYS_WIN_SET_CURSOR 79
#define SYS_GDI_CREATE_COMPAT_BITMAP 107
#define SYS_GDI_SET_CURSOR 174
#define SYS_GDI_CREATE_CURSOR 175
#define SYS_GDI_SET_DIBITS 214
#define SYS_GDI_CREATE_CURSOR_RGBA 224

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
    if (rv >= 0)
    {
        user32_zero_msg_tail(msg);
        return (BOOL)rv;
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
    /* HWND and thread messages share the kernel's exact task-owned queue. */
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
/* TranslateAccelerator — implemented below (after user32_post_msg_core
 * and GetKeyState are defined). These thin wrappers forward to
 * user32_translate_accel. */
#define FVIRTKEY 1
#define FSHIFT 4
#define FCONTROL 8
#define FALT 16
#define WM_KEYDOWN 0x0100
#define WM_SYSKEYDOWN 0x0104
#define WM_COMMAND 0x0111

/* In-memory accelerator table: count + pointer to raw entries. */
typedef struct
{
    unsigned int count;
    const unsigned char* entries; /* array of 8-byte ACCEL entries */
} ACCEL_TABLE;

/* Forward declarations — bodies appear later in this TU. */
static BOOL user32_post_msg_core(HANDLE h, UINT msg, WPARAM w, LPARAM l);
__declspec(dllexport) short GetKeyState(int vk);

static BOOL user32_translate_accel(HANDLE hwnd, HANDLE accel, void* pmsg)
{
    const ACCEL_TABLE* tbl;
    struct user32_msg_wire* m;
    unsigned int i;
    unsigned int vk_code;
    unsigned int fVirt;
    unsigned int key;
    unsigned int cmd;
    BOOL shift;
    BOOL ctrl;
    BOOL alt;

    if (!accel || !pmsg)
        return 0;

    m = (struct user32_msg_wire*)pmsg;
    /* Only WM_KEYDOWN / WM_SYSKEYDOWN are accelerator candidates. */
    if (m->message != WM_KEYDOWN && m->message != WM_SYSKEYDOWN)
        return 0;

    tbl = (const ACCEL_TABLE*)(unsigned long long)accel;
    if (!tbl->entries || tbl->count == 0)
        return 0;

    vk_code = (unsigned int)(m->wParam & 0xFFFF);
    /* Query modifier state via GetKeyState. VK_SHIFT=0x10,
     * VK_CONTROL=0x11, VK_MENU=0x12. High bit set = down. */
    shift = (GetKeyState(0x10) & 0x8000) ? 1 : 0;
    ctrl = (GetKeyState(0x11) & 0x8000) ? 1 : 0;
    alt = (GetKeyState(0x12) & 0x8000) ? 1 : 0;

    for (i = 0; i < tbl->count; ++i)
    {
        const unsigned char* e = tbl->entries + (unsigned long long)i * 8;
        fVirt = (unsigned int)e[0] | ((unsigned int)e[1] << 8);
        key = (unsigned int)e[2] | ((unsigned int)e[3] << 8);
        cmd = (unsigned int)e[4] | ((unsigned int)e[5] << 8);

        if (fVirt & FVIRTKEY)
        {
            /* VK match -- compare virtual-key code. */
            if (key != vk_code)
                continue;
            /* Check modifier requirements. */
            if (((fVirt & FSHIFT) != 0) != shift)
                continue;
            if (((fVirt & FCONTROL) != 0) != ctrl)
                continue;
            if (((fVirt & FALT) != 0) != alt)
                continue;
        }
        else
        {
            /* ASCII character match (rare but spec'd). */
            if (key != vk_code)
                continue;
        }
        /* Match found -- post WM_COMMAND. wParam high word = 1
         * (accelerator source), low word = cmd id. */
        user32_post_msg_core(hwnd, WM_COMMAND, (WPARAM)(((unsigned long long)1 << 16) | (unsigned long long)cmd), 0);
        return 1;
    }
    return 0;
}

__declspec(dllexport) BOOL TranslateAcceleratorA(HANDLE h, HANDLE accel, void* msg)
{
    return user32_translate_accel(h, accel, msg);
}
__declspec(dllexport) BOOL TranslateAcceleratorW(HANDLE h, HANDLE accel, void* msg)
{
    return user32_translate_accel(h, accel, msg);
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
static DWORD user32_current_tid(void)
{
    long long tid;
    __asm__ volatile("int $0x80" : "=a"(tid) : "a"((long long)SYS_GETPID) : "memory");
    if (tid <= 0 || (unsigned long long)tid > DUETOS_THREAD_MESSAGE_TID_MASK)
        return 0;
    return (DWORD)tid;
}

static HANDLE user32_thread_target(DWORD tid)
{
    if (tid == 0 || (tid & DUETOS_THREAD_MESSAGE_TAG) != 0)
        return (HANDLE)0;
    return (HANDLE)(unsigned long long)(DUETOS_THREAD_MESSAGE_TAG | tid);
}

__declspec(dllexport) void PostQuitMessage(int code)
{
    HANDLE target = user32_thread_target(user32_current_tid());
    if (target)
        (void)user32_post_msg_core(target, WM_QUIT, (WPARAM)(unsigned)code, 0);
}

__declspec(dllexport) BOOL PostThreadMessageA(DWORD tid, UINT msg, WPARAM w, LPARAM l)
{
    HANDLE target = user32_thread_target(tid);
    return target ? user32_post_msg_core(target, msg, w, l) : 0;
}

__declspec(dllexport) BOOL PostThreadMessageW(DWORD tid, UINT msg, WPARAM w, LPARAM l)
{
    return PostThreadMessageA(tid, msg, w, l);
}
/* SendMessage is synchronous — it must return the WndProc's
 * result. v1 implements this by pulling the target's WNDPROC
 * out of GWLP_WNDPROC and calling it directly. Cross-process and
 * cross-thread SendMessage return 0 until a kernel broker exists. */
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
 * the kernel. Returns a generation-tagged compositor handle (or 0). */
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
    /* A live generation-tagged HWND whose owner matches the caller's pid is a
     * valid window; SYS_WIN_GET_RECT succeeds iff both hold. */
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
    /* v1: no true desktop HWND. NULL remains the sentinel callers can pass
     * into GetClientRect to fetch the screen dimensions. */
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

/* --- Win32 dialog manager ---
 *
 * REAL implementation of the dialog template parser, modal and
 * modeless dialog creation, the modal message loop, EndDialog,
 * dialog item accessors, IsDialogMessage, and DefDlgProc.
 *
 * Templates are parsed from in-memory DLGTEMPLATE / DLGITEMTEMPLATE
 * structures (the "Indirect" family). The non-Indirect variants
 * (DialogBoxParamA, CreateDialogParamA) look up the template from
 * PE resources via the same .rsrc walker LoadString uses.
 *
 * Control class ordinals:
 *   0x0080 = BUTTON   0x0081 = EDIT     0x0082 = STATIC
 *   0x0083 = LISTBOX  0x0084 = SCROLLBAR 0x0085 = COMBOBOX
 *
 * Standard control WndProcs (BUTTON + STATIC) are registered once
 * on first use. EDIT gets a minimal text-echo proc. The rest are
 * stubs that create a window but don't paint.
 *
 * GAP: dialog units are approximated as du_x*2, du_y*2 (no font
 * metrics available). DS_SETFONT is accepted but the font data is
 * skipped. Tab navigation via IsDialogMessage handles WM_KEYDOWN
 * VK_TAB only; full keyboard mnemonics are not wired. */

typedef long long INT_PTR;
typedef INT_PTR(__stdcall* DLGPROC)(HANDLE, UINT, WPARAM, LPARAM);

/* Win32 message IDs and style bits used by the dialog manager. */
#define WM_INITDIALOG 0x0110
#define WM_COMMAND 0x0111
#define WM_CLOSE 0x0010
#define WM_DESTROY 0x0002
#define WM_PAINT 0x000F
#define WM_SETTEXT 0x000C
#define WM_GETTEXT 0x000D
#define WM_GETTEXTLENGTH 0x000E
#define WM_NEXTDLGCTL 0x0028
#define WM_KEYDOWN 0x0100
#define WM_LBUTTONDOWN 0x0201
#define DM_GETDEFID 0x0400
#define DM_SETDEFID 0x0401
#define DS_MODALFRAME 0x80
#define DS_SETFONT 0x40
#define DS_CENTER 0x0800
#define WS_CHILD 0x40000000u
#define WS_VISIBLE 0x10000000u
#define WS_POPUP 0x80000000u
#define WS_SYSMENU 0x00080000u
#define WS_TABSTOP 0x00010000u
#define WS_GROUP 0x00020000u
#define WS_DISABLED 0x08000000u
#define VK_TAB 0x09
#define VK_RETURN 0x0D
#define VK_ESCAPE 0x1B

#define DLG_CHILD_MAX 16
#define DLG_TEXT_MAX 64

/* Per-dialog state for modal loop + EndDialog. Stored in
 * GWLP_USERDATA on the dialog's main window. Max 4 concurrent
 * dialogs per process (plenty for nested modal prompts). */
struct dlg_state
{
    HANDLE hwnd;
    DLGPROC dlgproc;
    INT_PTR result;
    int ended;   /* set by EndDialog */
    UINT def_id; /* DM_SETDEFID / DM_GETDEFID */
    int in_use;
};
static struct dlg_state s_dlg_states[4];

static struct dlg_state* dlg_state_alloc(void)
{
    for (int i = 0; i < 4; ++i)
    {
        if (!s_dlg_states[i].in_use)
        {
            s_dlg_states[i].in_use = 1;
            s_dlg_states[i].ended = 0;
            s_dlg_states[i].result = 0;
            s_dlg_states[i].def_id = 0;
            return &s_dlg_states[i];
        }
    }
    return 0;
}

static void dlg_state_free(struct dlg_state* s)
{
    if (s)
    {
        s->in_use = 0;
        s->hwnd = (HANDLE)0;
        s->dlgproc = 0;
    }
}

static struct dlg_state* dlg_state_for_hwnd(HANDLE hwnd)
{
    for (int i = 0; i < 4; ++i)
    {
        if (s_dlg_states[i].in_use && s_dlg_states[i].hwnd == hwnd)
            return &s_dlg_states[i];
    }
    return 0;
}

/* --- Per-child text storage for controls ---
 * Controls like STATIC and BUTTON need to remember their label
 * text for WM_GETTEXT / WM_SETTEXT / painting. This is a small
 * per-process table keyed by HWND. */
struct ctrl_text
{
    HANDLE hwnd;
    char text[DLG_TEXT_MAX];
    int in_use;
};
#define CTRL_TEXT_CAP 64
static struct ctrl_text s_ctrl_texts[CTRL_TEXT_CAP];

static struct ctrl_text* ctrl_text_for(HANDLE hwnd, int create)
{
    for (int i = 0; i < CTRL_TEXT_CAP; ++i)
    {
        if (s_ctrl_texts[i].in_use && s_ctrl_texts[i].hwnd == hwnd)
            return &s_ctrl_texts[i];
    }
    if (!create)
        return 0;
    for (int i = 0; i < CTRL_TEXT_CAP; ++i)
    {
        if (!s_ctrl_texts[i].in_use)
        {
            s_ctrl_texts[i].in_use = 1;
            s_ctrl_texts[i].hwnd = hwnd;
            s_ctrl_texts[i].text[0] = '\0';
            return &s_ctrl_texts[i];
        }
    }
    return 0;
}

static void ctrl_text_set(HANDLE hwnd, const char* text)
{
    struct ctrl_text* ct = ctrl_text_for(hwnd, 1);
    if (ct)
        user32_strcpy_ascii(ct->text, DLG_TEXT_MAX, text);
}

static int ctrl_text_get(HANDLE hwnd, char* buf, int cap)
{
    struct ctrl_text* ct = ctrl_text_for(hwnd, 0);
    if (!ct || cap <= 0)
    {
        if (buf && cap > 0)
            buf[0] = '\0';
        return 0;
    }
    int i = 0;
    for (; i < cap - 1 && ct->text[i]; ++i)
        buf[i] = ct->text[i];
    buf[i] = '\0';
    return i;
}

/* --- Standard control WndProcs ---
 * BUTTON and STATIC need at least a minimal paint response. EDIT
 * gets a text-echo handler. */

/* Forward decl — defined later or above in this file. */
__declspec(dllexport) HANDLE BeginPaint(HANDLE hwnd, void* ps);
__declspec(dllexport) BOOL EndPaint(HANDLE hwnd, const void* ps);
__declspec(dllexport) HANDLE GetParent(HANDLE h);
static int dlg_child_id_of(HANDLE hwnd);

/* SYS_GDI_TEXT_OUT = 66 — for painting control labels directly.
 * Same syscall TextOutA uses. */
#define SYS_GDI_TEXT_OUT 66

static LRESULT __stdcall ButtonWndProc(HANDLE hwnd, UINT msg, WPARAM w, LPARAM l)
{
    switch (msg)
    {
    case WM_SETTEXT:
    {
        const char* t = (const char*)(unsigned long long)l;
        ctrl_text_set(hwnd, t ? t : "");
        SetWindowTextA(hwnd, t ? t : "");
        return 1;
    }
    case WM_GETTEXT:
    {
        return ctrl_text_get(hwnd, (char*)(unsigned long long)l, (int)w);
    }
    case WM_GETTEXTLENGTH:
    {
        char tmp[DLG_TEXT_MAX];
        return ctrl_text_get(hwnd, tmp, DLG_TEXT_MAX);
    }
    case WM_PAINT:
    {
        PAINTSTRUCT ps;
        HANDLE hdc = BeginPaint(hwnd, &ps);
        /* Draw button label centred in the client area. */
        char text[DLG_TEXT_MAX];
        int tlen = ctrl_text_get(hwnd, text, DLG_TEXT_MAX);
        if (tlen > 0)
        {
            /* Simple centred text using GDI TextOut. The button's
             * client rect from PAINTSTRUCT gives the bounds; we
             * centre horizontally with 8px per glyph. */
            int cw = ps.right - ps.left;
            int ch = ps.bottom - ps.top;
            int tw = tlen * 8;
            int tx = (cw - tw) / 2;
            int ty = (ch - 8) / 2;
            if (tx < 0)
                tx = 0;
            if (ty < 0)
                ty = 0;
            /* Use the existing SYS_GDI_TEXT_OUT via the HDC. */
            register long long r10_text asm("r10") = (long long)(unsigned long long)text;
            register long long r8_len asm("r8") = (long long)tlen;
            long long rv;
            __asm__ volatile("int $0x80"
                             : "=a"(rv)
                             : "a"((long long)SYS_GDI_TEXT_OUT), "D"((long long)(unsigned long long)hdc),
                               "S"((long long)tx), "d"((long long)ty), "r"(r10_text), "r"(r8_len),
                               "c"((long long)0x00FFFFFF) /* white text */
                             : "memory");
            (void)rv;
        }
        EndPaint(hwnd, &ps);
        return 0;
    }
    case WM_LBUTTONDOWN:
    {
        /* Notify the parent with WM_COMMAND + BN_CLICKED. */
        HANDLE parent = GetParent(hwnd);
        if (parent)
        {
            /* Control id from the HMENU slot set at CreateWindowEx
             * time. The kernel has no GWL_ID slot, so we look
             * up the ctrl_id from our per-process child table. */
            int ctrl_id = dlg_child_id_of(hwnd);
            WPARAM wp = (WPARAM)((unsigned)(unsigned short)ctrl_id);
            PostMessageA(parent, WM_COMMAND, wp, (LPARAM)(unsigned long long)hwnd);
        }
        return 0;
    }
    default:
        return DefWindowProcA(hwnd, msg, w, l);
    }
}

static LRESULT __stdcall StaticWndProc(HANDLE hwnd, UINT msg, WPARAM w, LPARAM l)
{
    switch (msg)
    {
    case WM_SETTEXT:
    {
        const char* t = (const char*)(unsigned long long)l;
        ctrl_text_set(hwnd, t ? t : "");
        SetWindowTextA(hwnd, t ? t : "");
        return 1;
    }
    case WM_GETTEXT:
        return ctrl_text_get(hwnd, (char*)(unsigned long long)l, (int)w);
    case WM_GETTEXTLENGTH:
    {
        char tmp[DLG_TEXT_MAX];
        return ctrl_text_get(hwnd, tmp, DLG_TEXT_MAX);
    }
    case WM_PAINT:
    {
        PAINTSTRUCT ps;
        HANDLE hdc = BeginPaint(hwnd, &ps);
        char text[DLG_TEXT_MAX];
        int tlen = ctrl_text_get(hwnd, text, DLG_TEXT_MAX);
        if (tlen > 0)
        {
            register long long r10_text asm("r10") = (long long)(unsigned long long)text;
            register long long r8_len asm("r8") = (long long)tlen;
            long long rv;
            __asm__ volatile("int $0x80"
                             : "=a"(rv)
                             : "a"((long long)SYS_GDI_TEXT_OUT), "D"((long long)(unsigned long long)hdc),
                               "S"((long long)2), "d"((long long)2), "r"(r10_text), "r"(r8_len),
                               "c"((long long)0x00FFFFFF)
                             : "memory");
            (void)rv;
        }
        EndPaint(hwnd, &ps);
        return 0;
    }
    default:
        return DefWindowProcA(hwnd, msg, w, l);
    }
}

static LRESULT __stdcall EditWndProc(HANDLE hwnd, UINT msg, WPARAM w, LPARAM l)
{
    switch (msg)
    {
    case WM_SETTEXT:
    {
        const char* t = (const char*)(unsigned long long)l;
        ctrl_text_set(hwnd, t ? t : "");
        return 1;
    }
    case WM_GETTEXT:
        return ctrl_text_get(hwnd, (char*)(unsigned long long)l, (int)w);
    case WM_GETTEXTLENGTH:
    {
        char tmp[DLG_TEXT_MAX];
        return ctrl_text_get(hwnd, tmp, DLG_TEXT_MAX);
    }
    default:
        return DefWindowProcA(hwnd, msg, w, l);
    }
}

static int s_ctrl_classes_registered = 0;

static void dlg_ensure_ctrl_classes(void)
{
    if (s_ctrl_classes_registered)
        return;
    s_ctrl_classes_registered = 1;
    user32_class_register("BUTTON", ButtonWndProc);
    user32_class_register("STATIC", StaticWndProc);
    user32_class_register("EDIT", EditWndProc);
    /* LISTBOX, SCROLLBAR, COMBOBOX — register with DefWindowProc
     * so CreateWindowEx succeeds even though they don't paint. */
    user32_class_register("LISTBOX", (WNDPROC)DefWindowProcA);
    user32_class_register("SCROLLBAR", (WNDPROC)DefWindowProcA);
    user32_class_register("COMBOBOX", (WNDPROC)DefWindowProcA);
}

/* --- Dialog child tracking ---
 * We need GetDlgItem to find a child by control ID. The kernel's
 * GW_CHILD walk returns opaque generation-tagged HWNDs but has no concept of
 * ctrl_id. We keep a small per-process side table mapping
 * (dialog_hwnd, ctrl_id) -> child_hwnd. */
struct dlg_child_entry
{
    HANDLE dialog;
    HANDLE child;
    int ctrl_id;
    int in_use;
};
#define DLG_CHILD_TABLE_CAP 64
static struct dlg_child_entry s_dlg_children[DLG_CHILD_TABLE_CAP];

static void dlg_child_register(HANDLE dialog, HANDLE child, int ctrl_id)
{
    for (int i = 0; i < DLG_CHILD_TABLE_CAP; ++i)
    {
        if (!s_dlg_children[i].in_use)
        {
            s_dlg_children[i].dialog = dialog;
            s_dlg_children[i].child = child;
            s_dlg_children[i].ctrl_id = ctrl_id;
            s_dlg_children[i].in_use = 1;
            return;
        }
    }
}

static HANDLE dlg_child_find(HANDLE dialog, int ctrl_id)
{
    for (int i = 0; i < DLG_CHILD_TABLE_CAP; ++i)
    {
        if (s_dlg_children[i].in_use && s_dlg_children[i].dialog == dialog && s_dlg_children[i].ctrl_id == ctrl_id)
        {
            return s_dlg_children[i].child;
        }
    }
    return (HANDLE)0;
}

static int dlg_child_id_of(HANDLE hwnd)
{
    for (int i = 0; i < DLG_CHILD_TABLE_CAP; ++i)
    {
        if (s_dlg_children[i].in_use && s_dlg_children[i].child == hwnd)
            return s_dlg_children[i].ctrl_id;
    }
    return 0;
}

static void dlg_children_cleanup(HANDLE dialog)
{
    for (int i = 0; i < DLG_CHILD_TABLE_CAP; ++i)
    {
        if (s_dlg_children[i].in_use && s_dlg_children[i].dialog == dialog)
            s_dlg_children[i].in_use = 0;
    }
}

/* --- Template parser helpers --- */

/* Align a byte offset up to a DWORD boundary. */
static unsigned dlg_align_dword(unsigned off)
{
    return (off + 3) & ~3u;
}

/* Read a WORD from the template at byte offset `off`. */
static unsigned short dlg_read_word(const unsigned char* tmpl, unsigned off)
{
    return (unsigned short)(tmpl[off] | ((unsigned short)tmpl[off + 1] << 8));
}

/* Read a DWORD from the template at byte offset `off`. */
static unsigned int dlg_read_dword(const unsigned char* tmpl, unsigned off)
{
    return (unsigned int)tmpl[off] | ((unsigned int)tmpl[off + 1] << 8) | ((unsigned int)tmpl[off + 2] << 16) |
           ((unsigned int)tmpl[off + 3] << 24);
}

/* Read a NUL-terminated UTF-16LE string from offset, flatten to
 * ASCII into `dst`, return the number of bytes consumed (including
 * the NUL terminator, in source byte count). */
static unsigned dlg_read_wstr(const unsigned char* tmpl, unsigned off, char* dst, unsigned cap)
{
    unsigned i = 0;
    for (;;)
    {
        unsigned short wc = dlg_read_word(tmpl, off);
        off += 2;
        if (wc == 0)
            break;
        if (i + 1 < cap)
            dst[i++] = (wc < 0x80) ? (char)wc : '?';
    }
    if (cap > 0)
        dst[(i < cap) ? i : cap - 1] = '\0';
    return off;
}

/* Skip a variable-length sz_Or_Ord field (menu, class, or title):
 *   0x0000         = no value (empty)
 *   0xFFFF, <ord>  = ordinal (2 more bytes)
 *   else           = NUL-terminated UTF-16 string */
static unsigned dlg_skip_sz_or_ord(const unsigned char* tmpl, unsigned off)
{
    unsigned short first = dlg_read_word(tmpl, off);
    if (first == 0x0000)
        return off + 2;
    if (first == 0xFFFF)
        return off + 4;
    /* NUL-terminated wchar string. */
    while (dlg_read_word(tmpl, off) != 0)
        off += 2;
    return off + 2; /* skip the NUL terminator */
}

/* Read a sz_Or_Ord into an ASCII buffer. If it is an ordinal,
 * writes "" and returns the ordinal in *out_ord. */
static unsigned dlg_read_sz_or_ord(const unsigned char* tmpl, unsigned off, char* dst, unsigned cap,
                                   unsigned short* out_ord)
{
    unsigned short first = dlg_read_word(tmpl, off);
    if (out_ord)
        *out_ord = 0;
    if (first == 0x0000)
    {
        if (cap > 0)
            dst[0] = '\0';
        return off + 2;
    }
    if (first == 0xFFFF)
    {
        if (out_ord)
            *out_ord = dlg_read_word(tmpl, off + 2);
        if (cap > 0)
            dst[0] = '\0';
        return off + 4;
    }
    return dlg_read_wstr(tmpl, off, dst, cap);
}

/* Map a control class ordinal to a class name string. */
static const char* dlg_ordinal_to_class(unsigned short ord)
{
    switch (ord)
    {
    case 0x0080:
        return "BUTTON";
    case 0x0081:
        return "EDIT";
    case 0x0082:
        return "STATIC";
    case 0x0083:
        return "LISTBOX";
    case 0x0084:
        return "SCROLLBAR";
    case 0x0085:
        return "COMBOBOX";
    default:
        return 0;
    }
}

/* Convert dialog units to pixels. Real Win32 uses the dialog font's
 * average character width/height; we approximate with a fixed 2x
 * multiplier (matches an 8px-wide, 16px-tall system font). */
static int dlg_du_to_px_x(int du)
{
    return du * 2;
}
static int dlg_du_to_px_y(int du)
{
    return du * 2;
}

/* --- Core: create dialog from in-memory template ---
 *
 * Parses DLGTEMPLATE + N DLGITEMTEMPLATE entries, creates the
 * dialog window and all child controls, and optionally enters a
 * modal message loop. Returns the dialog HWND (modeless) or the
 * EndDialog result (modal). */
static HANDLE dlg_create_from_template(const void* tmpl_raw, HANDLE hParent, DLGPROC proc, LPARAM initParam, int modal,
                                       INT_PTR* out_result)
{
    if (!tmpl_raw)
        return (HANDLE)0;

    dlg_ensure_ctrl_classes();

    const unsigned char* tmpl = (const unsigned char*)tmpl_raw;
    unsigned off = 0;

    /* DLGTEMPLATE header: style(4) exstyle(4) cdit(2) x(2) y(2) cx(2) cy(2) = 18 bytes */
    DWORD style = dlg_read_dword(tmpl, off);
    off += 4;
    DWORD exstyle = dlg_read_dword(tmpl, off);
    off += 4;
    unsigned short cdit = dlg_read_word(tmpl, off);
    off += 2;
    short dlg_x = (short)dlg_read_word(tmpl, off);
    off += 2;
    short dlg_y = (short)dlg_read_word(tmpl, off);
    off += 2;
    short dlg_cx = (short)dlg_read_word(tmpl, off);
    off += 2;
    short dlg_cy = (short)dlg_read_word(tmpl, off);
    off += 2;

    /* Menu (sz_Or_Ord) — skip it. */
    off = dlg_skip_sz_or_ord(tmpl, off);

    /* Window class (sz_Or_Ord) — skip it (use default). */
    off = dlg_skip_sz_or_ord(tmpl, off);

    /* Title (NUL-terminated UTF-16 string). */
    char title[WIN_TITLE_MAX];
    off = dlg_read_wstr(tmpl, off, title, WIN_TITLE_MAX);

    /* If DS_SETFONT, skip the font data: point size (WORD) + face name (wstr). */
    if (style & DS_SETFONT)
    {
        off += 2; /* skip point size */
        while (dlg_read_word(tmpl, off) != 0)
            off += 2;
        off += 2; /* skip NUL terminator */
    }

    /* Convert dialog-unit geometry to pixels. */
    int px_x = dlg_du_to_px_x(dlg_x);
    int px_y = dlg_du_to_px_y(dlg_y);
    int px_w = dlg_du_to_px_x(dlg_cx);
    int px_h = dlg_du_to_px_y(dlg_cy);

    /* Centre on screen if DS_CENTER. */
    if (style & DS_CENTER)
    {
        int scr_w = GetSystemMetrics(0 /* SM_CXSCREEN */);
        int scr_h = GetSystemMetrics(1 /* SM_CYSCREEN */);
        if (scr_w > 0 && scr_h > 0)
        {
            px_x = (scr_w - px_w) / 2;
            px_y = (scr_h - px_h) / 2;
        }
    }

    /* Create the dialog window. We use WS_POPUP | WS_CAPTION as
     * the base style; the template's style is merged in. */
    DWORD win_style = style | WS_POPUP;
    HANDLE dlg_hwnd =
        CreateWindowExA(exstyle, "", title, win_style, px_x, px_y, px_w, px_h, hParent, (HANDLE)0, (HANDLE)0, 0);
    if (!dlg_hwnd)
        return (HANDLE)0;

    /* Allocate dialog state. */
    struct dlg_state* ds = dlg_state_alloc();
    if (!ds)
    {
        DestroyWindow(dlg_hwnd);
        return (HANDLE)0;
    }
    ds->hwnd = dlg_hwnd;
    ds->dlgproc = proc;
    ds->def_id = IDOK;

    /* Store the DLGPROC as the WNDPROC so DispatchMessage routes
     * to it. We wrap through DefDlgProc which calls the DLGPROC. */
    /* Actually, store a pointer to DefDlgProcA as the wndproc, and
     * keep the dlgproc in our side table. The DLGPROC has a
     * different return convention (INT_PTR, nonzero = handled). */
    /* For simplicity, install the DLGPROC directly as the WNDPROC.
     * The dialog message dispatch in the modal loop and in
     * IsDialogMessage calls the DLGPROC explicitly. */

    /* Parse and create child controls. */
    unsigned item_count = (cdit > DLG_CHILD_MAX) ? DLG_CHILD_MAX : cdit;
    for (unsigned i = 0; i < item_count; ++i)
    {
        /* DLGITEMTEMPLATE must be DWORD-aligned. */
        off = dlg_align_dword(off);

        /* DLGITEMTEMPLATE: style(4) exstyle(4) x(2) y(2) cx(2) cy(2) id(2) = 18 bytes */
        DWORD item_style = dlg_read_dword(tmpl, off);
        off += 4;
        DWORD item_exstyle = dlg_read_dword(tmpl, off);
        off += 4;
        short item_x = (short)dlg_read_word(tmpl, off);
        off += 2;
        short item_y = (short)dlg_read_word(tmpl, off);
        off += 2;
        short item_cx = (short)dlg_read_word(tmpl, off);
        off += 2;
        short item_cy = (short)dlg_read_word(tmpl, off);
        off += 2;
        unsigned short item_id = dlg_read_word(tmpl, off);
        off += 2;

        /* Class (sz_Or_Ord). */
        char cls_name[64];
        unsigned short cls_ord = 0;
        off = dlg_read_sz_or_ord(tmpl, off, cls_name, 64, &cls_ord);

        const char* cls = cls_name;
        if (cls_ord != 0)
        {
            const char* mapped = dlg_ordinal_to_class(cls_ord);
            if (mapped)
                cls = mapped;
        }
        if (cls[0] == '\0' && cls_ord == 0)
            cls = "STATIC"; /* fallback */

        /* Title / text (sz_Or_Ord). */
        char item_text[DLG_TEXT_MAX];
        unsigned short text_ord = 0;
        off = dlg_read_sz_or_ord(tmpl, off, item_text, DLG_TEXT_MAX, &text_ord);

        /* Extra data count (WORD). */
        unsigned short extra = dlg_read_word(tmpl, off);
        off += 2;
        off += extra; /* skip extra data */

        /* Convert to pixels. */
        int ipx = dlg_du_to_px_x(item_x);
        int ipy = dlg_du_to_px_y(item_y);
        int ipw = dlg_du_to_px_x(item_cx);
        int iph = dlg_du_to_px_y(item_cy);

        /* Create the child control. */
        DWORD child_style = item_style | WS_CHILD | WS_VISIBLE;
        (void)item_exstyle;
        HANDLE child = CreateWindowExA(0, cls, item_text, child_style, ipx, ipy, ipw, iph, dlg_hwnd,
                                       (HANDLE)(unsigned long long)item_id, (HANDLE)0, 0);
        if (child)
        {
            /* Store text for the control's WM_GETTEXT. */
            ctrl_text_set(child, item_text);
            /* Register in the child table for GetDlgItem. */
            dlg_child_register(dlg_hwnd, child, (int)item_id);
            /* Send WM_SETTEXT so the control's wndproc stores it. */
            user32_send_core(child, WM_SETTEXT, 0, (LPARAM)(unsigned long long)item_text);
        }
    }

    /* Show the dialog. */
    ShowWindow(dlg_hwnd, 1 /* SW_SHOW */);

    /* Send WM_INITDIALOG to the DLGPROC. */
    if (proc)
    {
        HANDLE first_child = dlg_child_find(dlg_hwnd, (int)IDOK);
        if (!first_child)
            first_child = dlg_hwnd;
        proc(dlg_hwnd, WM_INITDIALOG, (WPARAM)(unsigned long long)first_child, initParam);
    }

    if (!modal)
    {
        /* Modeless: return the dialog HWND immediately. The caller
         * drives the message pump and calls IsDialogMessage. */
        return dlg_hwnd;
    }

    /* --- Modal message loop --- */
    struct user32_msg_wire msg;
    while (!ds->ended)
    {
        long long rv;
        __asm__ volatile("int $0x80"
                         : "=a"(rv)
                         : "a"((long long)SYS_WIN_GET_MSG), "D"((long long)(unsigned long long)&msg), "S"((long long)0)
                         : "memory");
        if (rv == 0)
            break; /* WM_QUIT */
        if (rv < 0)
            break;

        /* Route the message. If it targets the dialog, call the
         * DLGPROC. Otherwise dispatch normally. */
        HANDLE target = msg.hwnd;
        if (target == dlg_hwnd && proc)
        {
            INT_PTR handled = proc(dlg_hwnd, msg.message, msg.wParam, msg.lParam);
            if (!handled)
                DefWindowProcA(dlg_hwnd, msg.message, msg.wParam, msg.lParam);
        }
        else
        {
            /* Child or unrelated window — check if the target is
             * one of our children and the message is WM_COMMAND;
             * if so, relay to the dlgproc. Otherwise dispatch
             * normally. */
            HANDLE child_parent = GetParent(target);
            if (child_parent == dlg_hwnd && proc && msg.message == WM_COMMAND)
            {
                proc(dlg_hwnd, WM_COMMAND, msg.wParam, msg.lParam);
            }
            else
            {
                user32_dispatch_core(&msg);
            }
        }
    }

    INT_PTR result = ds->result;
    /* Clean up. */
    dlg_children_cleanup(dlg_hwnd);
    dlg_state_free(ds);
    DestroyWindow(dlg_hwnd);

    if (out_result)
        *out_result = result;
    return dlg_hwnd;
}

/* --- Exported dialog APIs --- */

__declspec(dllexport) INT_PTR DialogBoxIndirectParamA(HANDLE hInst, const void* lpTemplate, HANDLE hWndParent,
                                                      void* lpDialogFunc, LPARAM dwInitParam)
{
    (void)hInst;
    INT_PTR result = -1;
    dlg_create_from_template(lpTemplate, hWndParent, (DLGPROC)lpDialogFunc, dwInitParam, 1, &result);
    return result;
}

__declspec(dllexport) INT_PTR DialogBoxIndirectParamW(HANDLE hInst, const void* lpTemplate, HANDLE hWndParent,
                                                      void* lpDialogFunc, LPARAM dwInitParam)
{
    /* Templates are binary — A and W share the same parser. */
    return DialogBoxIndirectParamA(hInst, lpTemplate, hWndParent, lpDialogFunc, dwInitParam);
}

/* DialogBoxParamA/W — resource-based. Look up the template from
 * the PE's .rsrc section via the resource walker, then delegate
 * to the Indirect variant.
 * GAP: resource lookup not wired — if lpTemplate is an integer
 * resource ID (MAKEINTRESOURCE), we cannot resolve it without
 * walking RT_DIALOG. Falls back to IDOK for resource-based
 * dialogs; in-memory (Indirect) dialogs are fully real. */
__declspec(dllexport) INT_PTR DialogBoxParamA(HANDLE hInst, const char* lpTemplate, HANDLE hWndParent,
                                              void* lpDialogFunc, LPARAM dwInitParam)
{
    /* Check if lpTemplate is an in-memory pointer (high bits set)
     * vs a resource ID (low 16 bits only). */
    unsigned long long tval = (unsigned long long)lpTemplate;
    if (tval > 0xFFFF)
    {
        /* Might be a direct pointer to a DLGTEMPLATE in memory. */
        return DialogBoxIndirectParamA(hInst, lpTemplate, hWndParent, lpDialogFunc, dwInitParam);
    }
    // STUB: resource-based dialog lookup requires RT_DIALOG walker.
    // Returns IDOK so callers take the affirmative path.
    (void)hInst;
    (void)hWndParent;
    (void)lpDialogFunc;
    (void)dwInitParam;
    return IDOK;
}

__declspec(dllexport) INT_PTR DialogBoxParamW(HANDLE hInst, const wchar_t16* lpTemplate, HANDLE hWndParent,
                                              void* lpDialogFunc, LPARAM dwInitParam)
{
    unsigned long long tval = (unsigned long long)lpTemplate;
    if (tval > 0xFFFF)
        return DialogBoxIndirectParamW(hInst, lpTemplate, hWndParent, lpDialogFunc, dwInitParam);
    // STUB: resource-based dialog lookup requires RT_DIALOG walker.
    (void)hInst;
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

__declspec(dllexport) BOOL EndDialog(HANDLE hDlg, INT_PTR nResult)
{
    struct dlg_state* ds = dlg_state_for_hwnd(hDlg);
    if (!ds)
        return 0;
    ds->result = nResult;
    ds->ended = 1;
    /* Post WM_CLOSE to break the modal pump the next iteration. */
    PostMessageA(hDlg, WM_CLOSE, 0, 0);
    return 1;
}

/* --- Modeless dialogs --- */

__declspec(dllexport) HANDLE CreateDialogIndirectParamA(HANDLE hInst, const void* lpTemplate, HANDLE hWndParent,
                                                        void* lpDialogFunc, LPARAM dwInitParam)
{
    (void)hInst;
    return dlg_create_from_template(lpTemplate, hWndParent, (DLGPROC)lpDialogFunc, dwInitParam, 0, 0);
}

__declspec(dllexport) HANDLE CreateDialogIndirectParamW(HANDLE hInst, const void* lpTemplate, HANDLE hWndParent,
                                                        void* lpDialogFunc, LPARAM dwInitParam)
{
    return CreateDialogIndirectParamA(hInst, lpTemplate, hWndParent, lpDialogFunc, dwInitParam);
}

__declspec(dllexport) HANDLE CreateDialogParamA(HANDLE hInst, const char* lpTemplate, HANDLE hWndParent,
                                                void* lpDialogFunc, LPARAM dwInitParam)
{
    unsigned long long tval = (unsigned long long)lpTemplate;
    if (tval > 0xFFFF)
        return CreateDialogIndirectParamA(hInst, lpTemplate, hWndParent, lpDialogFunc, dwInitParam);
    // STUB: resource-based modeless dialog requires RT_DIALOG walker.
    (void)hInst;
    (void)hWndParent;
    (void)lpDialogFunc;
    (void)dwInitParam;
    return (HANDLE)0;
}

__declspec(dllexport) HANDLE CreateDialogParamW(HANDLE hInst, const wchar_t16* lpTemplate, HANDLE hWndParent,
                                                void* lpDialogFunc, LPARAM dwInitParam)
{
    unsigned long long tval = (unsigned long long)lpTemplate;
    if (tval > 0xFFFF)
        return CreateDialogIndirectParamW(hInst, lpTemplate, hWndParent, lpDialogFunc, dwInitParam);
    // STUB: resource-based modeless dialog requires RT_DIALOG walker.
    (void)hInst;
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

/* --- IsDialogMessage ---
 * For modeless dialogs in the caller's message pump. Handles tab
 * navigation (VK_TAB) and Enter/Escape shortcuts. Returns TRUE
 * if the message was consumed (caller should NOT dispatch it). */
__declspec(dllexport) BOOL IsDialogMessageA(HANDLE hDlg, void* lpMsg)
{
    if (!hDlg || !lpMsg)
        return 0;
    const struct user32_msg_wire* m = (const struct user32_msg_wire*)lpMsg;
    struct dlg_state* ds = dlg_state_for_hwnd(hDlg);
    if (!ds || !ds->dlgproc)
        return 0;

    if (m->message == WM_KEYDOWN)
    {
        if (m->wParam == VK_TAB)
        {
            /* Tab navigation — cycle focus among children. */
            ds->dlgproc(hDlg, WM_NEXTDLGCTL, 0, 0);
            return 1;
        }
        if (m->wParam == VK_RETURN)
        {
            /* Enter = click the default button (IDOK). */
            ds->dlgproc(hDlg, WM_COMMAND, (WPARAM)ds->def_id, 0);
            return 1;
        }
        if (m->wParam == VK_ESCAPE)
        {
            /* Escape = IDCANCEL. */
            ds->dlgproc(hDlg, WM_COMMAND, (WPARAM)IDCANCEL, 0);
            return 1;
        }
    }
    return 0;
}
__declspec(dllexport) BOOL IsDialogMessageW(HANDLE hDlg, void* lpMsg)
{
    return IsDialogMessageA(hDlg, lpMsg);
}

/* --- Dialog item accessors --- */

__declspec(dllexport) HANDLE GetDlgItem(HANDLE hDlg, int nIDDlgItem)
{
    return dlg_child_find(hDlg, nIDDlgItem);
}

__declspec(dllexport) int GetDlgCtrlID(HANDLE hwnd)
{
    return dlg_child_id_of(hwnd);
}

__declspec(dllexport) BOOL SetDlgItemTextA(HANDLE hDlg, int nIDDlgItem, const char* text)
{
    HANDLE item = GetDlgItem(hDlg, nIDDlgItem);
    if (!item)
        return 0;
    ctrl_text_set(item, text ? text : "");
    return SetWindowTextA(item, text);
}

__declspec(dllexport) BOOL SetDlgItemTextW(HANDLE hDlg, int nIDDlgItem, const wchar_t16* text)
{
    char ascii[DLG_TEXT_MAX];
    win32_w_to_ascii(text, ascii, DLG_TEXT_MAX);
    return SetDlgItemTextA(hDlg, nIDDlgItem, ascii);
}

__declspec(dllexport) UINT GetDlgItemTextA(HANDLE hDlg, int nIDDlgItem, char* buf, int cap)
{
    HANDLE item = GetDlgItem(hDlg, nIDDlgItem);
    if (!item)
    {
        if (buf && cap > 0)
            buf[0] = '\0';
        return 0;
    }
    return (UINT)ctrl_text_get(item, buf, cap);
}

__declspec(dllexport) UINT GetDlgItemTextW(HANDLE hDlg, int nIDDlgItem, wchar_t16* buf, int cap)
{
    char ascii[DLG_TEXT_MAX];
    UINT n = GetDlgItemTextA(hDlg, nIDDlgItem, ascii, DLG_TEXT_MAX);
    if (buf && cap > 0)
    {
        unsigned i = 0;
        for (; i < n && (int)i < cap - 1; ++i)
            buf[i] = (wchar_t16)(unsigned char)ascii[i];
        buf[i] = 0;
        return i;
    }
    return 0;
}

__declspec(dllexport) BOOL SetDlgItemInt(HANDLE hDlg, int nIDDlgItem, UINT value, BOOL signed_)
{
    char buf[12];
    unsigned n = value;
    int neg = 0;
    if (signed_ && (int)value < 0)
    {
        neg = 1;
        n = (unsigned)(-(int)value);
    }
    unsigned i = sizeof(buf);
    buf[--i] = '\0';
    do
    {
        buf[--i] = (char)('0' + (n % 10u));
        n /= 10u;
    } while (n && i > 1);
    if (neg && i > 0)
        buf[--i] = '-';
    return SetDlgItemTextA(hDlg, nIDDlgItem, &buf[i]);
}

__declspec(dllexport) UINT GetDlgItemInt(HANDLE hDlg, int nIDDlgItem, BOOL* translated, BOOL signed_)
{
    char buf[16];
    UINT len = GetDlgItemTextA(hDlg, nIDDlgItem, buf, (int)sizeof(buf));
    if (translated)
        *translated = 0;
    if (len == 0)
        return 0;
    unsigned idx = 0;
    int neg = 0;
    if (signed_ && buf[0] == '-')
    {
        neg = 1;
        idx = 1;
    }
    unsigned val = 0;
    unsigned digits = 0;
    for (; buf[idx]; ++idx)
    {
        if (buf[idx] < '0' || buf[idx] > '9')
            return 0;
        val = val * 10u + (unsigned)(buf[idx] - '0');
        ++digits;
    }
    if (digits == 0)
        return 0;
    if (translated)
        *translated = 1;
    return neg ? (UINT)(-(int)val) : val;
}

__declspec(dllexport) LRESULT SendDlgItemMessageA(HANDLE hDlg, int nIDDlgItem, UINT msg, WPARAM w, LPARAM l)
{
    HANDLE item = GetDlgItem(hDlg, nIDDlgItem);
    if (!item)
        return 0;
    return user32_send_core(item, msg, w, l);
}

__declspec(dllexport) LRESULT SendDlgItemMessageW(HANDLE hDlg, int nIDDlgItem, UINT msg, WPARAM w, LPARAM l)
{
    return SendDlgItemMessageA(hDlg, nIDDlgItem, msg, w, l);
}

/* --- DefDlgProc ---
 * Default dialog procedure. Handles DM_GETDEFID, DM_SETDEFID,
 * WM_CLOSE, and delegates to DefWindowProc for unhandled messages. */
__declspec(dllexport) LRESULT DefDlgProcA(HANDLE hDlg, UINT msg, WPARAM w, LPARAM l)
{
    struct dlg_state* ds = dlg_state_for_hwnd(hDlg);
    switch (msg)
    {
    case DM_SETDEFID:
        if (ds)
            ds->def_id = (UINT)w;
        return 1;
    case DM_GETDEFID:
        if (ds)
            return (LRESULT)(0x0001u << 16 | (ds->def_id & 0xFFFF)); /* DC_HASDEFID | id */
        return 0;
    case WM_CLOSE:
        EndDialog(hDlg, 0);
        return 0;
    default:
        return DefWindowProcA(hDlg, msg, w, l);
    }
}
__declspec(dllexport) LRESULT DefDlgProcW(HANDLE hDlg, UINT msg, WPARAM w, LPARAM l)
{
    return DefDlgProcA(hDlg, msg, w, l);
}

/* pe_resources.h is needed by LoadIcon/LoadCursor below (the canonical
 * include is near LoadString but these decoders come first). */
#include "../common/pe_resources.h"

static const void* user32_exe_base(void);
static int user32_string_view(HANDLE h, DUET_RES_VIEW* view);

/* --- Load* family ---
 *
 * LoadStringA/W are REAL as of the `.rsrc` parser slice.
 * LoadIconA/W are REAL: decode RT_GROUP_ICON -> RT_ICON from .rsrc,
 * create a GDI bitmap via SYS_GDI_CREATE_COMPAT_BITMAP + SET_DIBITS.
 * LoadCursorA/W are REAL for system cursors (IDC_*); for PE cursors
 * they decode RT_GROUP_CURSOR -> RT_CURSOR and register via
 * SYS_GDI_CREATE_CURSOR_RGBA.
 * LoadImageA/W dispatch by type to LoadIcon/LoadCursor/LoadBitmap.
 * LoadAcceleratorsA/W are REAL as of the VK-translation slice
 * (2026-07-29) -- defined below after pe_resources.h include. */

/* LoadAcceleratorsA/W -- implemented after the pe_resources.h
 * include (see user32_load_accel below). Forward-declared here
 * so the export list in the EAT stays ordered. */
static HANDLE user32_load_accel(HANDLE h, unsigned int name_id);
__declspec(dllexport) HANDLE LoadAcceleratorsA(HANDLE h, const char* name);
__declspec(dllexport) HANDLE LoadAcceleratorsW(HANDLE h, const wchar_t16* name);
// STUB: returns NULL - no off-screen surface for the decoded DIB to
// live in (backlog item 12).
__declspec(dllexport) HANDLE LoadBitmapA(HANDLE h, const char* name)
{
    (void)h;
    (void)name;
    return (HANDLE)0;
}
// STUB: returns NULL - see LoadBitmapA.
__declspec(dllexport) HANDLE LoadBitmapW(HANDLE h, const wchar_t16* name)
{
    (void)h;
    (void)name;
    return (HANDLE)0;
}
/* LoadCursor — for NULL hInstance, return the IDC_* sentinel as the
 * HCURSOR so a subsequent SetCursor can decode which shape was requested.
 * For a PE hInstance, decode RT_GROUP_CURSOR from .rsrc and register via
 * SYS_GDI_CREATE_CURSOR_RGBA. */
static HANDLE user32_load_cursor_impl(HANDLE h, unsigned long name_id)
{
    /* System cursor (hInstance == NULL) — return IDC_* sentinel. */
    if (h == (HANDLE)0)
    {
        if (name_id == 0 || name_id > 0xFFFF)
            return (HANDLE)(unsigned long long)IDC_ARROW;
        return (HANDLE)(unsigned long long)name_id;
    }
    /* PE cursor — decode from .rsrc. */
    if (name_id == 0 || name_id > 0xFFFF)
        return (HANDLE)(unsigned long long)IDC_ARROW;
    {
        DUET_RES_VIEW view;
        unsigned int cursor_id = 0;
        unsigned int cw = 0, ch = 0;
        if (!user32_string_view(h, &view))
            return (HANDLE)(unsigned long long)IDC_ARROW;
        if (!duet_res_pick_icon(&view, DUET_RES_TYPE_GROUP_CURSOR, name_id, 32, 32, &cursor_id, &cw, &ch))
            return (HANDLE)(unsigned long long)IDC_ARROW;
        if (cw == 0 || ch == 0 || cw > 256 || ch > 256)
            return (HANDLE)(unsigned long long)IDC_ARROW;
        {
            /* Decode the RT_CURSOR body to BGRA pixels on the stack.
             * Max 256*256*4 = 256KB — within PE stack limits. For large
             * cursors, cap at 64x64 to keep stack usage sane. */
            unsigned int use_w = cw > 64 ? 64 : cw;
            unsigned int use_h = ch > 64 ? 64 : ch;
            static unsigned char bgra[64 * 64 * 4];
            unsigned int x_hot = 0, y_hot = 0;
            if (!duet_res_decode_icon(&view, DUET_RES_TYPE_CURSOR, cursor_id, use_w, use_h, bgra, 64 * 64, &x_hot,
                                      &y_hot))
                return (HANDLE)(unsigned long long)IDC_ARROW;
            /* Register via SYS_GDI_CREATE_CURSOR_RGBA. */
            {
                long long result;
                unsigned long long packed_dim = (unsigned long long)use_w | ((unsigned long long)use_h << 16);
                unsigned long long packed_hot =
                    (unsigned long long)(x_hot & 0xFF) | ((unsigned long long)(y_hot & 0xFF) << 8);
                asm volatile("syscall"
                             : "=a"(result)
                             : "a"((long long)SYS_GDI_CREATE_CURSOR_RGBA), "D"((long long)(unsigned long long)bgra),
                               "S"((long long)packed_dim), "d"((long long)packed_hot)
                             : "memory", "rcx", "r11");
                if (result > 0)
                    return (HANDLE)(unsigned long long)result;
            }
        }
    }
    return (HANDLE)(unsigned long long)IDC_ARROW;
}

__declspec(dllexport) HANDLE LoadCursorA(HANDLE h, const char* name)
{
    unsigned long id = (unsigned long)(unsigned long long)name;
    return user32_load_cursor_impl(h, id);
}
__declspec(dllexport) HANDLE LoadCursorW(HANDLE h, const wchar_t16* name)
{
    unsigned long id = (unsigned long)(unsigned long long)name;
    return user32_load_cursor_impl(h, id);
}

/* LoadIcon — for NULL hInstance, return a non-NULL sentinel (system icon).
 * For a PE hInstance, decode RT_GROUP_ICON from .rsrc into a GDI bitmap
 * (SYS_GDI_CREATE_COMPAT_BITMAP + SYS_GDI_SET_DIBITS) and return that
 * as the HICON. */
static HANDLE user32_load_icon_impl(HANDLE h, unsigned long name_id)
{
    /* System icon (hInstance == NULL) — return sentinel. */
    if (h == (HANDLE)0)
        return (HANDLE)1; /* non-NULL sentinel for RegisterClassEx */
    /* PE icon — decode from .rsrc. */
    if (name_id == 0 || name_id > 0xFFFF)
        return (HANDLE)1;
    {
        DUET_RES_VIEW view;
        unsigned int icon_id = 0;
        unsigned int iw = 0, ih = 0;
        if (!user32_string_view(h, &view))
            return (HANDLE)1;
        if (!duet_res_pick_icon(&view, DUET_RES_TYPE_GROUP_ICON, name_id, 32, 32, &icon_id, &iw, &ih))
            return (HANDLE)1;
        if (iw == 0 || ih == 0 || iw > 64 || ih > 64)
            return (HANDLE)1;
        {
            static unsigned char bgra[64 * 64 * 4];
            if (!duet_res_decode_icon(&view, DUET_RES_TYPE_ICON, icon_id, iw, ih, bgra, 64 * 64, (unsigned int*)0,
                                      (unsigned int*)0))
                return (HANDLE)1;
            /* Create a GDI bitmap and upload the decoded pixels. */
            {
                long long bmp_h;
                asm volatile("syscall"
                             : "=a"(bmp_h)
                             : "a"((long long)SYS_GDI_CREATE_COMPAT_BITMAP),
                               "D"((long long)0), /* hdc — 0 for screen-compat */
                               "S"((long long)iw), "d"((long long)ih)
                             : "memory", "rcx", "r11");
                if (bmp_h == 0)
                    return (HANDLE)1;
                /* Upload BGRA pixels via SYS_GDI_SET_DIBITS. The kernel
                 * expects: rdi=bitmap_handle, rsi=pixels, rdx=width,
                 * r10=height, r8=bpp(32), r9=stride. */
                {
                    long long set_r;
                    unsigned long long stride = (unsigned long long)(iw * 4);
                    register long long r10 asm("r10") = (long long)ih;
                    register long long r8 asm("r8") = (long long)32;
                    register long long r9 asm("r9") = (long long)stride;
                    asm volatile("syscall"
                                 : "=a"(set_r)
                                 : "a"((long long)SYS_GDI_SET_DIBITS), "D"((long long)(unsigned long long)bmp_h),
                                   "S"((long long)(unsigned long long)bgra), "d"((long long)iw), "r"(r10), "r"(r8),
                                   "r"(r9)
                                 : "memory", "rcx", "r11");
                    (void)set_r;
                }
                return (HANDLE)(unsigned long long)bmp_h;
            }
        }
    }
}

__declspec(dllexport) HANDLE LoadIconA(HANDLE h, const char* name)
{
    unsigned long id = (unsigned long)(unsigned long long)name;
    return user32_load_icon_impl(h, id);
}
__declspec(dllexport) HANDLE LoadIconW(HANDLE h, const wchar_t16* name)
{
    unsigned long id = (unsigned long)(unsigned long long)name;
    return user32_load_icon_impl(h, id);
}

/* LoadImage — unified loader. Dispatches by type. */
#define IMAGE_BITMAP 0
#define IMAGE_ICON 1
#define IMAGE_CURSOR 2

__declspec(dllexport) HANDLE LoadImageA(HANDLE h, const char* name, UINT t, int w, int ht, UINT flags)
{
    (void)w;
    (void)ht;
    (void)flags;
    /* GAP: LR_DEFAULTSIZE, LR_SHARED, LR_LOADFROMFILE not implemented — revisit when file-load is needed. */
    if (t == IMAGE_ICON)
        return LoadIconA(h, name);
    if (t == IMAGE_CURSOR)
        return LoadCursorA(h, name);
    /* IMAGE_BITMAP falls through to LoadBitmap stub. */
    return LoadBitmapA(h, name);
}

__declspec(dllexport) HANDLE LoadImageW(HANDLE h, const wchar_t16* name, UINT t, int w, int ht, UINT flags)
{
    (void)w;
    (void)ht;
    (void)flags;
    /* GAP: LR_DEFAULTSIZE, LR_SHARED, LR_LOADFROMFILE not implemented — revisit when file-load is needed. */
    if (t == IMAGE_ICON)
        return LoadIconW(h, (const wchar_t16*)name);
    if (t == IMAGE_CURSOR)
        return LoadCursorW(h, name);
    return LoadBitmapW(h, (const wchar_t16*)name);
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
/* LoadStringA/W — real RT_STRING lookup through the shared `.rsrc`
 * walker.
 *
 * This used to return a fixed "DuetOS" placeholder because there was no
 * resource parser. That was a present-but-lying export: every caller got
 * the same six characters whatever id it asked for, so a menu, a caption
 * and an error message all rendered identically. The walker in
 * ../common/pe_resources.h makes the real string reachable — the whole
 * image is already mapped by the kernel loader, so no syscall is needed
 * beyond resolving the module base.
 *
 * user32.dll links with /nodefaultlib and imports nothing, so it cannot
 * call kernel32!GetModuleHandleW; it issues SYS_DLL_BASE_BY_NAME itself,
 * exactly as kernel32 does. */
#include "../common/pe_resources.h"

#define SYS_DLL_BASE_BY_NAME 172

/* Base VA of the calling process's EXE image. An empty name is the
 * kernel's documented request for Process::pe_image_base. */
static const void* user32_exe_base(void)
{
    static const char kEmpty[1] = {0};
    long long rv;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"((long long)SYS_DLL_BASE_BY_NAME), "D"((long long)(unsigned long long)kEmpty),
                       "S"((long long)0)
                     : "memory");
    return (const void*)(unsigned long long)rv;
}

static int user32_string_view(HANDLE h, DUET_RES_VIEW* view)
{
    const void* base = (const void*)h;
    if (base == (const void*)0)
        base = user32_exe_base();
    if (base == (const void*)0)
        return 0;
    return duet_res_init(base, view);
}

/* LoadStringW. Honours the documented cchBufferMax == 0 contract: the
 * caller gets a read-only pointer to the (unterminated) resource string
 * written through lpBuffer, and the return value is its length. */
__declspec(dllexport) int LoadStringW(HANDLE h, UINT id, wchar_t16* buf, int len)
{
    DUET_RES_VIEW view;
    const unsigned short* chars;
    unsigned int chars_len;
    int i;

    if (!buf || len < 0)
        return 0;
    if (!user32_string_view(h, &view))
        return 0;
    if (!duet_res_find_string(&view, id, 0, 0, &chars, &chars_len))
        return 0;

    if (len == 0)
    {
        /* Documented pointer-return form: lpBuffer is treated as a
         * LPWSTR* and receives the address of the resource itself. */
        *(const wchar_t16**)(void*)buf = (const wchar_t16*)chars;
        return (int)chars_len;
    }

    for (i = 0; i < len - 1 && (unsigned int)i < chars_len; ++i)
        buf[i] = (wchar_t16)chars[i];
    buf[i] = 0;
    return i;
}

/* LoadStringA — same lookup, narrowed. The cchBufferMax == 0 pointer
 * form is W-only on Win32 (there is no ANSI copy to point at), so a
 * zero-length buffer returns 0 here.
 *
 * GAP: narrowing is Latin-1 truncation, not a codepage conversion —
 * a code unit above 0xFF becomes '?'. Revisit when the NLS layer grows
 * a real WideCharToMultiByte the DLLs can share. */
__declspec(dllexport) int LoadStringA(HANDLE h, UINT id, char* buf, int len)
{
    DUET_RES_VIEW view;
    const unsigned short* chars;
    unsigned int chars_len;
    int i;

    if (!buf || len <= 0)
        return 0;
    if (!user32_string_view(h, &view))
        return 0;
    if (!duet_res_find_string(&view, id, 0, 0, &chars, &chars_len))
        return 0;

    for (i = 0; i < len - 1 && (unsigned int)i < chars_len; ++i)
        buf[i] = (chars[i] < 0x100u) ? (char)(unsigned char)chars[i] : '?';
    buf[i] = 0;
    return i;
}

/* --- Accelerator table implementation (after pe_resources.h) --- */

/* Per-process accelerator table pool. We store up to 4 tables
 * (most apps use one or two) statically to avoid heap allocation
 * in user32's freestanding environment. */
#define USER32_MAX_ACCEL_TABLES 4
static ACCEL_TABLE g_accel_pool[USER32_MAX_ACCEL_TABLES];
static unsigned int g_accel_pool_used = 0;

static HANDLE user32_load_accel(HANDLE h, unsigned int name_id)
{
    DUET_RES_VIEW view;
    DUET_RES_KEY type;
    DUET_RES_KEY name;
    unsigned int rva;
    unsigned int size;
    const unsigned char* data;
    ACCEL_TABLE* tbl;

    if (!user32_string_view(h, &view))
        return (HANDLE)0;

    type.by_name = 0;
    type.id = DUET_RES_TYPE_ACCELERATOR;
    type.name = (const unsigned short*)0;
    type.name_len = 0;

    name.by_name = 0;
    name.id = name_id;
    name.name = (const unsigned short*)0;
    name.name_len = 0;

    if (!duet_res_find(&view, &type, &name, 0, 0, &rva, &size))
        return (HANDLE)0;

    data = duet_res_at(&view, rva, size);
    if (!data || size < 8)
        return (HANDLE)0;

    if (g_accel_pool_used >= USER32_MAX_ACCEL_TABLES)
        return (HANDLE)0;

    tbl = &g_accel_pool[g_accel_pool_used++];
    tbl->count = size / 8;
    tbl->entries = data;
    return (HANDLE)(unsigned long long)tbl;
}

__declspec(dllexport) HANDLE LoadAcceleratorsA(HANDLE h, const char* name)
{
    /* MAKEINTRESOURCE check: high bits zero = ordinal. */
    unsigned long long p = (unsigned long long)(const void*)name;
    if (p < 0x10000)
        return user32_load_accel(h, (unsigned int)p);
    /* GAP: named (string) accelerator tables -- no real-world PE
     * in our v0 corpus uses a named accel table, so we skip the
     * UTF-8 -> UTF-16 name conversion for now. */
    return (HANDLE)0;
}
__declspec(dllexport) HANDLE LoadAcceleratorsW(HANDLE h, const wchar_t16* name)
{
    unsigned long long p = (unsigned long long)(const void*)name;
    if (p < 0x10000)
        return user32_load_accel(h, (unsigned int)p);
    /* GAP: named (wide-string) accelerator tables. */
    return (HANDLE)0;
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
 * syscall flattens the HMENU tree (depth-first) into the kernel's
 * fixed-size flat array, with parent rows carrying child_index /
 * child_count back-references into the same array. Depth is capped
 * at the kernel's kMenuMaxStack (4 panels).
 *
 * SetMenu/GetMenu/GetSystemMenu keep the HWND->HMENU association in
 * a small userland-side table (s_window_menus below); the kernel
 * compositor owns the window chrome, so the HMENU here is purely the
 * client-side data model that a PE can round-trip. DrawMenuBar can
 * only trigger an invalidate/redraw — see its GAP marker.
 * LoadMenu remains a stub because resource-loaded menus are out of
 * scope. */

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

/* Per-HWND menu association. The kernel owns the window object; this
 * table is the userland-side data model only, mapping an HWND to its
 * attached menubar HMENU (SetMenu/GetMenu) and to a lazily-synthesized
 * cached system menu (GetSystemMenu). Linear scan, matching the
 * s_classes idiom — windows with menus are few. */
#define USER32_WINDOW_MENU_CAP 32

struct user32_window_menu
{
    HANDLE hwnd;     /* 0 when the slot is free */
    HANDLE menu;     /* attached menubar HMENU, or 0 */
    HANDLE sys_menu; /* cached GetSystemMenu HMENU, or 0 */
};

static struct user32_window_menu s_window_menus[USER32_WINDOW_MENU_CAP];

/* Find the slot for `hwnd`, optionally allocating one. Returns 0 when
 * the table is full and `create` was requested, or when no slot exists
 * and `create` is 0. */
static struct user32_window_menu* user32_window_menu_slot(HANDLE hwnd, int create)
{
    if (!hwnd)
        return 0;
    for (unsigned i = 0; i < USER32_WINDOW_MENU_CAP; ++i)
    {
        if (s_window_menus[i].hwnd == hwnd)
            return &s_window_menus[i];
    }
    if (!create)
        return 0;
    for (unsigned i = 0; i < USER32_WINDOW_MENU_CAP; ++i)
    {
        if (s_window_menus[i].hwnd == (HANDLE)0)
        {
            s_window_menus[i].hwnd = hwnd;
            s_window_menus[i].menu = (HANDLE)0;
            s_window_menus[i].sys_menu = (HANDLE)0;
            return &s_window_menus[i];
        }
    }
    return 0; /* table full */
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
/* Menubar association — userland data-model round-trip. The kernel
 * compositor does not yet paint the menubar band (see DrawMenuBar). */
__declspec(dllexport) HANDLE GetMenu(HANDLE hwnd)
{
    struct user32_window_menu* slot = user32_window_menu_slot(hwnd, 0);
    return slot ? slot->menu : (HANDLE)0;
}
__declspec(dllexport) BOOL SetMenu(HANDLE hwnd, HANDLE menu)
{
    if (!hwnd)
        return 0;
    /* SetMenu(hwnd, NULL) clears the association. Only allocate a slot
     * when there is actually a menu to store. */
    struct user32_window_menu* slot = user32_window_menu_slot(hwnd, menu ? 1 : 0);
    if (!slot)
        return menu ? 0 : 1; /* table full only matters when storing */
    slot->menu = menu;
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
/* GetSystemMenu — synthesize (and cache per HWND) a minimal system
 * menu using the same CreatePopupMenu/AppendMenu machinery a PE would
 * use. bRevert==TRUE destroys the cached copy and returns NULL, per
 * MSDN. The SC_* command ids match the Win32 ABI so a PE that handles
 * WM_SYSCOMMAND sees the expected values. */
#define USER32_SC_SIZE 0xF000u
#define USER32_SC_MOVE 0xF010u
#define USER32_SC_MINIMIZE 0xF020u
#define USER32_SC_MAXIMIZE 0xF030u
#define USER32_SC_CLOSE 0xF060u
#define USER32_SC_RESTORE 0xF120u

__declspec(dllexport) HANDLE GetSystemMenu(HANDLE hwnd, BOOL bRevert)
{
    if (!hwnd)
        return (HANDLE)0;
    struct user32_window_menu* slot = user32_window_menu_slot(hwnd, bRevert ? 0 : 1);
    if (bRevert)
    {
        /* Destroy the cached copy; the next non-revert call rebuilds
         * the default system menu. */
        if (slot && slot->sys_menu)
        {
            DestroyMenu(slot->sys_menu);
            slot->sys_menu = (HANDLE)0;
        }
        return (HANDLE)0;
    }
    if (!slot)
        return (HANDLE)0; /* table full */
    if (slot->sys_menu)
        return slot->sys_menu;

    HANDLE menu = CreatePopupMenu();
    if (!menu)
        return (HANDLE)0;
    AppendMenuA(menu, 0, USER32_SC_RESTORE, "&Restore");
    AppendMenuA(menu, 0, USER32_SC_MOVE, "&Move");
    AppendMenuA(menu, 0, USER32_SC_SIZE, "&Size");
    AppendMenuA(menu, 0, USER32_SC_MINIMIZE, "Mi&nimize");
    AppendMenuA(menu, 0, USER32_SC_MAXIMIZE, "Ma&ximize");
    AppendMenuA(menu, USER32_MF_SEPARATOR, 0, (const char*)0);
    AppendMenuA(menu, 0, USER32_SC_CLOSE, "&Close");
    slot->sys_menu = menu;
    return menu;
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
 * in kernel/subsystems/win32/window_syscall.cpp). MUST match.
 *
 * Flat-array submenu marshaling: items are laid out as one flat
 * array. The first `root_count` items are the root menu; subsequent
 * items are the depth-first-flattened children of submenu rows.
 * Each submenu-flagged item carries `child_index` (start of its
 * children in the same flat array; -1 means none) and `child_count`.
 *
 * Depth cap mirrors the kernel's kMenuMaxStack = 4 panels (root +
 * 3 submenus); any HMENU nested deeper is rejected by the thunk
 * before issuing the syscall. */
#define USER32_TP_LABEL_CAP 32
#define USER32_TP_MAX_ITEMS 32
#define USER32_TP_MAX_DEPTH 4

struct user32_tp_item
{
    unsigned action_id;
    unsigned flags;
    int child_index; /* -1 = no children */
    unsigned child_count;
    char label[USER32_TP_LABEL_CAP];
};

struct user32_tp_req
{
    unsigned count;      /* total items in the flat array */
    unsigned root_count; /* first `root_count` items form the root menu */
    unsigned flags;
    int screen_x, screen_y;
    unsigned long long hwnd_biased;
    struct user32_tp_item items[USER32_TP_MAX_ITEMS];
};

/* Depth-first flatten of a userland menu tree into the wire array.
 *
 * Lays the input HMENU's items at `out_start` first, then for every
 * row with a submenu, recursively appends its children to the tail
 * and patches the parent's child_index back to that tail offset.
 * Forward-only layout matches the kernel's "child_index > parent"
 * validation.
 *
 * Returns 1 on success, 0 if the layout would exceed the flat-array
 * cap or the depth cap. `*out_used` is the total items emitted so
 * far; the caller seeds it with the root count and the function
 * grows it as submenus get appended.
 */
static int user32_tp_flatten(struct user32_menu* m, struct user32_tp_req* req, unsigned out_start, unsigned* out_used,
                             unsigned depth)
{
    if (depth > USER32_TP_MAX_DEPTH)
        return 0;
    /* Copy this panel's items into the slots reserved by the caller. */
    for (unsigned i = 0; i < m->count; ++i)
    {
        const unsigned slot = out_start + i;
        if (slot >= USER32_TP_MAX_ITEMS)
            return 0;
        req->items[slot].action_id = m->items[i].action_id;
        req->items[slot].flags = m->items[i].flags;
        req->items[slot].child_index = -1;
        req->items[slot].child_count = 0;
        unsigned j = 0;
        for (; j + 1 < USER32_TP_LABEL_CAP && m->items[i].label[j]; ++j)
            req->items[slot].label[j] = m->items[i].label[j];
        req->items[slot].label[j] = '\0';
    }
    /* Now walk again to emit children depth-first. We do this in a
     * second pass so all of THIS panel's slots are stable before any
     * recursion bumps `*out_used`. */
    for (unsigned i = 0; i < m->count; ++i)
    {
        struct user32_menu* child = m->items[i].submenu ? user32_menu_resolve(m->items[i].submenu) : 0;
        if (!child || child->count == 0)
        {
            /* MF_POPUP set without a real submenu (null pointer,
             * dangling HMENU, or zero-row child) — strip the flag
             * so the kernel doesn't see a submenu row that points
             * nowhere. */
            req->items[out_start + i].flags &= ~USER32_KMENU_FLAG_SUBMENU;
            continue;
        }
        const unsigned child_at = *out_used;
        if (child_at + child->count > USER32_TP_MAX_ITEMS)
            return 0;
        req->items[out_start + i].child_index = (int)child_at;
        req->items[out_start + i].child_count = child->count;
        *out_used += child->count;
        if (!user32_tp_flatten(child, req, child_at, out_used, depth + 1))
            return 0;
    }
    return 1;
}

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
    /* Zero the whole request so kernel-side validation sees
     * child_index = 0 / child_count = 0 for any slot we don't
     * touch (the kernel rejects 0 < self, so unwritten slots can't
     * masquerade as valid back-pointers). */
    for (unsigned i = 0; i < sizeof(req); ++i)
        ((unsigned char*)&req)[i] = 0;
    req.root_count = m->count;
    req.flags = flags;
    req.screen_x = x;
    req.screen_y = y;
    req.hwnd_biased = (unsigned long long)hwnd;
    /* Seed `count` with the root population, then let the
     * depth-first walker grow it as it emits each submenu. */
    unsigned used = m->count;
    if (!user32_tp_flatten(m, &req, 0, &used, 1))
        return 0;
    req.count = used;
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
    /* GAP: the kernel compositor does not yet paint menu-bar item
     * glyphs — only the HWND->HMENU data model (SetMenu/GetMenu) and
     * this redraw trigger are wired. Revisit when the compositor
     * grows a non-client menu band. For now, request a window
     * invalidate so a PE that calls DrawMenuBar after mutating its
     * menu still gets a WM_PAINT, matching the observable Win32
     * contract that the bar is refreshed. */
    if (hwnd)
    {
        long long rv;
        __asm__ volatile("int $0x80"
                         : "=a"(rv)
                         : "a"((long long)SYS_WIN_INVALIDATE), "D"((long long)(unsigned long long)hwnd),
                           "S"((long long)1)
                         : "memory");
        (void)rv;
    }
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

/* ------------------------------------------------------------------
 * wsprintf family — user32's restricted printf.
 *
 * Win32 GUI apps build titles / status text with wsprintf instead of
 * the CRT sprintf (it avoids linking the CRT). The format engine lives
 * in user32_wsprintf_core.h (shared with shlwapi's bounded wnsprintf
 * and pinned by tests/host/test_kernel32_nls.cpp); these exports keep
 * the unbounded legacy contract — wsprintf's documented 1024-char
 * output convention is the caller's responsibility, so they pass an
 * effectively-infinite cap. Returns the count written, excluding the
 * NUL.
 * ------------------------------------------------------------------ */
#include "user32_wsprintf_core.h"

__declspec(dllexport) int wvsprintfA(char* out, const char* fmt, duetos_valist ap)
{
    return duetos_wvsnprintf_a(out, 0x7FFFFFFF, fmt, ap);
}

__declspec(dllexport) int wsprintfA(char* out, const char* fmt, ...)
{
    duetos_valist ap;
    __builtin_va_start(ap, fmt);
    int r = wvsprintfA(out, fmt, ap);
    __builtin_va_end(ap);
    return r;
}

__declspec(dllexport) int wvsprintfW(wchar_t16* out, const wchar_t16* fmt, duetos_valist ap)
{
    return duetos_wvsnprintf_w(out, 0x7FFFFFFF, fmt, ap);
}

__declspec(dllexport) int wsprintfW(wchar_t16* out, const wchar_t16* fmt, ...)
{
    duetos_valist ap;
    __builtin_va_start(ap, fmt);
    int r = wvsprintfW(out, fmt, ap);
    __builtin_va_end(ap);
    return r;
}
