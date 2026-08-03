/*
 * userland/libs/user32_32/user32_32.c
 *
 * Freestanding DuetOS user32.dll (i386 / PE32 variant) — the window
 * lifecycle, the class table, and the message pump, all bridged to
 * the kernel window manager over SYS_WIN_* the same way the 64-bit
 * userland/libs/user32/user32.c does. The remaining WM-adjacent
 * shims (paint, caret, clipboard, resources, metrics) live in the
 * sibling TU user32_32_misc.c.
 *
 * Before this slice every export here returned a constant and the
 * file issued no syscalls at all: RegisterClassA discarded
 * lpfnWndProc and returned a fake atom, CreateWindowExA returned
 * NULL, and GetMessageA returned 0 forever. A PE32 that reached its
 * own code created no window, received no message, and spun without
 * ever faulting — a present-but-lying export is worse than a missing
 * one, because a missing import at least leaves a [win32-32miss]
 * sentinel to trace.
 *
 * Three things differ from the 64-bit sibling and each one is a
 * silent-corruption trap if missed:
 *
 *  1. MSG is 28 bytes on i386; the kernel's wire struct is 32. The
 *     kernel blind-writes all 32 bytes to whatever pointer it is
 *     handed, so passing the caller's real MSG* through misaligns
 *     every field AND writes 4 bytes past the end of the caller's
 *     struct. Both pump entrypoints pass a local wire buffer and
 *     repack (user32_msg_unpack).
 *
 *  2. WNDCLASS and WNDCLASSEX have DIFFERENT field offsets on i386.
 *     On x86_64 the prepended cbSize shares the first 8-byte slot
 *     with `style`, so lpfnWndProc lands at offset 8 in both and the
 *     64-bit RegisterClassExW can legitimately forward to
 *     RegisterClassW. With 4-byte pointers there is no such padding:
 *     cbSize shifts every subsequent field by 4. The two shapes get
 *     two structs here.
 *
 *  3. The WndProc callback needs no kernel mechanism. The window
 *     manager stores the pointer in the GWLP_WNDPROC long slot;
 *     DispatchMessage reads it back and makes a plain 32-bit
 *     __stdcall indirect call, in-process. (The header comment on
 *     kernel/subsystems/win32/window_syscall.cpp describing a
 *     synthetic ring-3 frame does not describe what ships.)
 *
 * Built as PE32 (Machine=0x014C, OptHdrMagic=0x10B). Export
 * Directory Name field = "user32.dll" (from /out: basename).
 */

#include "user32_32_internal.h"

/* ------------------------------------------------------------------
 * Shared helpers (declared in user32_32_internal.h)
 * ------------------------------------------------------------------ */

void user32_w_to_ascii(const wchar_t16* src, char* dst, unsigned cap)
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

int user32_strieq(const char* a, const char* b, unsigned cap)
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

unsigned user32_get_long(HWND hwnd, int slot)
{
    return (unsigned)duet_syscall2(SYS_WIN_GET_LONG, (unsigned)(unsigned long)hwnd, (unsigned)slot);
}

unsigned user32_set_long(HWND hwnd, int slot, unsigned value)
{
    return (unsigned)duet_syscall3(SYS_WIN_SET_LONG, (unsigned)(unsigned long)hwnd, (unsigned)slot, value);
}

/* The kernel writes 64-bit hwnd / wParam / lParam. Every one of them
 * is truncated to the i386 width here: HWNDs are PE32-safe public
 * slot+generation identities, and wParam/lParam only ever carry values a
 * 32-bit guest put there in the first place, so the high halves are
 * discarded rather than reported. */
void user32_msg_unpack(const struct user32_msg_wire* wire, struct user32_msg32* out)
{
    out->hwnd = (HWND)(unsigned long)wire->hwnd_lo;
    out->message = wire->message;
    out->wParam = (WPARAM)wire->wparam_lo;
    out->lParam = (LPARAM)wire->lparam_lo;
    out->time = 0;
    out->pt_x = 0;
    out->pt_y = 0;
}

/* ------------------------------------------------------------------
 * Class table
 *
 * RegisterClass* records (name -> WNDPROC) here in-process;
 * CreateWindowEx* copies the matching WNDPROC into the new window's
 * GWLP_WNDPROC slot so DispatchMessage can recover it from the HWND
 * alone. The kernel never sees a class name.
 * ------------------------------------------------------------------ */

#define USER32_CLASS_CAP 32

struct user32_wndclass_entry
{
    char name[USER32_CLASS_NAME_MAX];
    WNDPROC wndproc;
    int in_use;
};
static struct user32_wndclass_entry s_classes[USER32_CLASS_CAP];

void user32_strcpy_ascii(char* dst, unsigned cap, const char* src)
{
    unsigned i = 0;
    if (src)
    {
        for (; i + 1 < cap && src[i]; ++i)
            dst[i] = src[i];
    }
    dst[i] = '\0';
}

/* Register or update a class record. Returns the 1-based table index
 * as the ATOM (non-zero == success), matching Win32's contract that
 * the atom is an opaque non-zero token that UnregisterClass and the
 * CreateWindowEx class-name argument can both be resolved against. */
static ATOM user32_class_register(const char* name, WNDPROC proc)
{
    if (!name || !name[0])
        return 0;
    for (unsigned i = 0; i < USER32_CLASS_CAP; ++i)
    {
        if (s_classes[i].in_use && user32_strieq(s_classes[i].name, name, USER32_CLASS_NAME_MAX))
        {
            s_classes[i].wndproc = proc;
            return (ATOM)(i + 1);
        }
    }
    for (unsigned i = 0; i < USER32_CLASS_CAP; ++i)
    {
        if (!s_classes[i].in_use)
        {
            user32_strcpy_ascii(s_classes[i].name, USER32_CLASS_NAME_MAX, name);
            s_classes[i].wndproc = proc;
            s_classes[i].in_use = 1;
            return (ATOM)(i + 1);
        }
    }
    return 0; /* table full */
}

static WNDPROC user32_class_lookup(const char* name)
{
    if (!name)
        return 0;
    /* CreateWindowEx accepts an ATOM cast to a pointer (MAKEINTATOM)
     * as well as a string. Win32 reserves the low 64 KiB of the
     * address space for exactly this, so a pointer value below
     * 0x10000 is an atom, never a string. */
    const unsigned raw = (unsigned)(unsigned long)name;
    if (raw < 0x10000u)
    {
        const unsigned idx = raw - 1u;
        if (raw == 0 || idx >= USER32_CLASS_CAP || !s_classes[idx].in_use)
            return 0;
        return s_classes[idx].wndproc;
    }
    for (unsigned i = 0; i < USER32_CLASS_CAP; ++i)
    {
        if (s_classes[i].in_use && user32_strieq(s_classes[i].name, name, USER32_CLASS_NAME_MAX))
        {
            return s_classes[i].wndproc;
        }
    }
    return 0;
}

/* WNDCLASSA / WNDCLASSW on i386: every pointer is 4 bytes and there
 * is no padding after `style`, so the layout is dense. */
struct user32_wndclass32
{
    UINT style;
    WNDPROC lpfnWndProc;
    INT cbClsExtra;
    INT cbWndExtra;
    HINSTANCE hInstance;
    HICON hIcon;
    HCURSOR hCursor;
    HBRUSH hbrBackground;
    const char* lpszMenuName;
    const char* lpszClassName;
};

/* WNDCLASSEXA / WNDCLASSEXW on i386: cbSize is prepended (shifting
 * every field by 4 — unlike x86_64, where it packs into `style`'s
 * 8-byte slot) and hIconSm is appended. */
struct user32_wndclassex32
{
    UINT cbSize;
    UINT style;
    WNDPROC lpfnWndProc;
    INT cbClsExtra;
    INT cbWndExtra;
    HINSTANCE hInstance;
    HICON hIcon;
    HCURSOR hCursor;
    HBRUSH hbrBackground;
    const char* lpszMenuName;
    const char* lpszClassName;
    HICON hIconSm;
};

/* Flatten a wide class name, falling back to a WNDPROC-derived
 * synthetic label when the caller registered an anonymous class so
 * two anonymous classes stay distinct. */
static void user32_class_name_from_wide(const wchar_t16* wide, WNDPROC proc, char* out, unsigned cap)
{
    user32_w_to_ascii(wide, out, cap);
    if (out[0] != '\0')
        return;
    unsigned v = (unsigned)(unsigned long)proc;
    out[0] = 'W';
    out[1] = '-';
    for (unsigned i = 0; i < 8 && i + 2 < cap - 1; ++i)
    {
        out[2 + i] = (char)('a' + ((v >> (i * 4)) & 0xF));
    }
    out[10 < cap - 1 ? 10 : cap - 1] = '\0';
}

__declspec(dllexport) ATOM __stdcall RegisterClassA(const void* wc)
{
    if (!wc)
        return 0;
    const struct user32_wndclass32* c = (const struct user32_wndclass32*)wc;
    return user32_class_register(c->lpszClassName, c->lpfnWndProc);
}

__declspec(dllexport) ATOM __stdcall RegisterClassW(const void* wc)
{
    if (!wc)
        return 0;
    const struct user32_wndclass32* c = (const struct user32_wndclass32*)wc;
    char name[USER32_CLASS_NAME_MAX];
    user32_class_name_from_wide((const wchar_t16*)c->lpszClassName, c->lpfnWndProc, name, USER32_CLASS_NAME_MAX);
    return user32_class_register(name, c->lpfnWndProc);
}

__declspec(dllexport) ATOM __stdcall RegisterClassExA(const void* wcex)
{
    if (!wcex)
        return 0;
    const struct user32_wndclassex32* c = (const struct user32_wndclassex32*)wcex;
    return user32_class_register(c->lpszClassName, c->lpfnWndProc);
}

__declspec(dllexport) ATOM __stdcall RegisterClassExW(const void* wcex)
{
    if (!wcex)
        return 0;
    const struct user32_wndclassex32* c = (const struct user32_wndclassex32*)wcex;
    char name[USER32_CLASS_NAME_MAX];
    user32_class_name_from_wide((const wchar_t16*)c->lpszClassName, c->lpfnWndProc, name, USER32_CLASS_NAME_MAX);
    return user32_class_register(name, c->lpfnWndProc);
}

static BOOL user32_class_unregister(const char* name)
{
    if (!name)
        return 0;
    for (unsigned i = 0; i < USER32_CLASS_CAP; ++i)
    {
        if (s_classes[i].in_use && user32_strieq(s_classes[i].name, name, USER32_CLASS_NAME_MAX))
        {
            s_classes[i].in_use = 0;
            s_classes[i].wndproc = 0;
            s_classes[i].name[0] = '\0';
            return 1;
        }
    }
    return 0;
}

__declspec(dllexport) BOOL __stdcall UnregisterClassA(const char* name, HINSTANCE inst)
{
    (void)inst;
    return user32_class_unregister(name);
}

__declspec(dllexport) BOOL __stdcall UnregisterClassW(const wchar_t16* name, HINSTANCE inst)
{
    (void)inst;
    char flat[USER32_CLASS_NAME_MAX];
    user32_w_to_ascii(name, flat, USER32_CLASS_NAME_MAX);
    return user32_class_unregister(flat);
}

/* ------------------------------------------------------------------
 * Window lifecycle
 * ------------------------------------------------------------------ */

/* Shared create core. `title` is caller-owned ASCII (nullable — the
 * kernel substitutes a generic label). Geometry is passed through
 * as-is: CW_USEDEFAULT is (int)0x80000000, which the kernel clamps
 * against the framebuffer like any other out-of-range coordinate. */
static HWND user32_create_core(int x, int y, int w, int h, const char* title)
{
    const int rv = duet_syscall5(SYS_WIN_CREATE, (unsigned)x, (unsigned)y, (unsigned)w, (unsigned)h,
                                 (unsigned)(unsigned long)title);
    return (HWND)(unsigned long)(unsigned)rv;
}

/* Copy the registered class's WNDPROC into the new window's
 * GWLP_WNDPROC slot, and record style/ex-style so GetWindowLong can
 * read them back. No-op when the class has no registered proc — such
 * a window still pumps, DispatchMessage just returns 0 for it. */
/* WS_CHILD — when set, CreateWindowEx's `hMenu` argument is the
 * control id, not a menu handle (Win32 convention). That id is what
 * makes GetDlgItem a real lookup. */
#define WS_CHILD 0x40000000u

static void user32_install_create_state(HWND hwnd, const char* cls, const char* title, DWORD style, DWORD ex,
                                        HWND parent, HMENU menu)
{
    if (!hwnd)
        return;
    WNDPROC proc = user32_class_lookup(cls);
    if (proc)
    {
        (void)user32_set_long(hwnd, GWLP_WNDPROC, (unsigned)(unsigned long)proc);
    }
    (void)user32_set_long(hwnd, USER32_LONG_STYLE, (unsigned)style);
    (void)user32_set_long(hwnd, USER32_LONG_EXSTYLE, (unsigned)ex);
    if (parent)
    {
        (void)duet_syscall2(SYS_WIN_SET_PARENT, (unsigned)(unsigned long)hwnd, (unsigned)(unsigned long)parent);
    }
    /* A MAKEINTATOM class is an integer, not text — record the empty
     * string rather than dereferencing it. */
    const unsigned cls_raw = (unsigned)(unsigned long)cls;
    const int ctrl_id = (style & WS_CHILD) ? (int)(unsigned)(unsigned long)menu : 0;
    user32_record_create(hwnd, (cls_raw >= 0x10000u) ? cls : "", title, parent, ctrl_id);
}

__declspec(dllexport) HWND __stdcall CreateWindowExA(DWORD ex, const char* cls, const char* name, DWORD style, int x,
                                                     int y, int w, int h, HWND parent, HMENU menu, HINSTANCE inst,
                                                     void* param)
{
    (void)inst;
    (void)param;
    HWND hwnd = user32_create_core(x, y, w, h, name);
    user32_install_create_state(hwnd, cls, name, style, ex, parent, menu);
    return hwnd;
}

__declspec(dllexport) HWND __stdcall CreateWindowExW(DWORD ex, const wchar_t16* cls, const wchar_t16* name, DWORD style,
                                                     int x, int y, int w, int h, HWND parent, HMENU menu,
                                                     HINSTANCE inst, void* param)
{
    (void)inst;
    (void)param;
    char title[WIN_TITLE_MAX];
    char class_a[USER32_CLASS_NAME_MAX];
    user32_w_to_ascii(name, title, WIN_TITLE_MAX);
    /* A MAKEINTATOM class survives the wide flatten only if it is
     * passed through unmodified — it is a small integer, not a
     * string. Detect it before treating `cls` as text. */
    const unsigned cls_raw = (unsigned)(unsigned long)cls;
    if (cls_raw != 0 && cls_raw < 0x10000u)
    {
        HWND hwnd = user32_create_core(x, y, w, h, title);
        user32_install_create_state(hwnd, (const char*)cls, title, style, ex, parent, menu);
        return hwnd;
    }
    user32_w_to_ascii(cls, class_a, USER32_CLASS_NAME_MAX);
    HWND hwnd = user32_create_core(x, y, w, h, title);
    user32_install_create_state(hwnd, class_a, title, style, ex, parent, menu);
    return hwnd;
}

__declspec(dllexport) BOOL __stdcall DestroyWindow(HWND h)
{
    user32_record_destroy(h);
    return duet_syscall1(SYS_WIN_DESTROY, (unsigned)(unsigned long)h) ? 1 : 0;
}

__declspec(dllexport) BOOL __stdcall ShowWindow(HWND h, INT cmd)
{
    (void)duet_syscall2(SYS_WIN_SHOW, (unsigned)(unsigned long)h, (unsigned)cmd);
    /* Win32 returns the PREVIOUS visibility state. The compositor
     * does not track visibility history, so every call reports
     * FALSE — the safe under-report for the "was it already shown?"
     * probe that is virtually the only real use of the result. */
    return 0;
}

__declspec(dllexport) BOOL __stdcall UpdateWindow(HWND h)
{
    /* The compositor repaints on the next drain after an invalidate,
     * so UpdateWindow is InvalidateRect's synchronous twin. */
    return duet_syscall2(SYS_WIN_INVALIDATE, (unsigned)(unsigned long)h, 0) ? 1 : 0;
}

/* ------------------------------------------------------------------
 * Message pump
 * ------------------------------------------------------------------ */

#define DUETOS_THREAD_MESSAGE_TAG 0x80000000u

static BOOL user32_post_core(HWND h, UINT msg, WPARAM w, LPARAM l)
{
    return duet_syscall4(SYS_WIN_POST_MSG, (unsigned)(unsigned long)h, msg, w, l) ? 1 : 0;
}

__declspec(dllexport) BOOL __stdcall PostMessageA(HWND h, UINT msg, WPARAM w, LPARAM l)
{
    return user32_post_core(h, msg, w, l);
}

__declspec(dllexport) BOOL __stdcall PostMessageW(HWND h, UINT msg, WPARAM w, LPARAM l)
{
    return user32_post_core(h, msg, w, l);
}

__declspec(dllexport) void __stdcall PostQuitMessage(int code)
{
    const unsigned tid = (unsigned)duet_syscall0(SYS_GETPID);
    if (tid != 0 && (tid & DUETOS_THREAD_MESSAGE_TAG) == 0)
        (void)user32_post_core((HWND)(unsigned long)(DUETOS_THREAD_MESSAGE_TAG | tid), WM_QUIT, (WPARAM)(unsigned)code,
                               0);
}

/* Non-blocking kernel dequeue into the caller's 28-byte MSG. */
static BOOL user32_peek_core(struct user32_msg32* msg, HWND filter, int remove)
{
    struct user32_msg_wire wire = {0, 0, 0, 0, 0, 0, 0, 0};
    const int rv = duet_syscall3(SYS_WIN_PEEK_MSG, (unsigned)(unsigned long)&wire, (unsigned)(unsigned long)filter,
                                 (unsigned)remove);
    if (rv != 1)
        return 0;
    user32_msg_unpack(&wire, msg);
    return 1;
}

__declspec(dllexport) BOOL __stdcall GetMessageA(void* lpMsg, HWND hWnd, UINT min, UINT max)
{
    (void)min;
    (void)max;
    if (!lpMsg)
        return 0;
    struct user32_msg32* msg = (struct user32_msg32*)lpMsg;

    struct user32_msg_wire wire = {0, 0, 0, 0, 0, 0, 0, 0};
    const int rv = duet_syscall2(SYS_WIN_GET_MSG, (unsigned)(unsigned long)&wire, (unsigned)(unsigned long)hWnd);
    /* rv = 1 for a normal message, 0 when the dequeued message was
     * WM_QUIT, -1 on a bad pointer. Win32 callers treat -1 the same
     * as 0 (break the loop), so both fall through un-translated. */
    if (rv < 0)
        return (BOOL)rv;
    user32_msg_unpack(&wire, msg);
    return (BOOL)rv;
}

__declspec(dllexport) BOOL __stdcall GetMessageW(void* lpMsg, HWND hWnd, UINT min, UINT max)
{
    return GetMessageA(lpMsg, hWnd, min, max);
}

__declspec(dllexport) BOOL __stdcall PeekMessageA(void* lpMsg, HWND hWnd, UINT min, UINT max, UINT flags)
{
    (void)min;
    (void)max;
    if (!lpMsg)
        return 0;
    struct user32_msg32* msg = (struct user32_msg32*)lpMsg;
    const int remove = (flags & PM_REMOVE) ? 1 : 0;
    return user32_peek_core(msg, hWnd, remove);
}

__declspec(dllexport) BOOL __stdcall PeekMessageW(void* lpMsg, HWND hWnd, UINT min, UINT max, UINT flags)
{
    return PeekMessageA(lpMsg, hWnd, min, max, flags);
}

/* TranslateMessage synthesises WM_CHAR from WM_KEYDOWN. The kernel's
 * input dispatch already posts character messages directly, so there
 * is nothing left to translate and FALSE ("no translation happened")
 * is the accurate answer, not a placeholder. */
__declspec(dllexport) BOOL __stdcall TranslateMessage(const void* lpMsg)
{
    (void)lpMsg;
    return 0;
}

/* DispatchMessage recovers the target window's WNDPROC from its long
 * slot and calls it in-process. No kernel mechanism is involved. */
static LRESULT user32_dispatch_core(const void* msg_any)
{
    if (!msg_any)
        return 0;
    const struct user32_msg32* m = (const struct user32_msg32*)msg_any;
    if (!m->hwnd)
        return 0;
    WNDPROC proc = (WNDPROC)(unsigned long)user32_get_long(m->hwnd, GWLP_WNDPROC);
    if (!proc)
        return 0;
    return proc(m->hwnd, m->message, m->wParam, m->lParam);
}

__declspec(dllexport) LRESULT __stdcall DispatchMessageA(const void* lpMsg)
{
    return user32_dispatch_core(lpMsg);
}

__declspec(dllexport) LRESULT __stdcall DispatchMessageW(const void* lpMsg)
{
    return user32_dispatch_core(lpMsg);
}

/* SendMessage is synchronous: it must return the WNDPROC's result,
 * so it resolves the proc and calls it directly rather than queueing.
 * A cross-process or cross-thread target yields 0 because the kernel
 * refuses the WNDPROC read until a synchronous broker exists. */
static LRESULT user32_send_core(HWND h, UINT msg, WPARAM w, LPARAM l)
{
    if (!h)
        return 0;
    WNDPROC proc = (WNDPROC)(unsigned long)user32_get_long(h, GWLP_WNDPROC);
    if (!proc)
        return 0;
    return proc(h, msg, w, l);
}

__declspec(dllexport) LRESULT __stdcall SendMessageA(HWND h, UINT msg, WPARAM w, LPARAM l)
{
    return user32_send_core(h, msg, w, l);
}

__declspec(dllexport) LRESULT __stdcall SendMessageW(HWND h, UINT msg, WPARAM w, LPARAM l)
{
    return user32_send_core(h, msg, w, l);
}

/* DefWindowProc is the caller's fallback for messages its WNDPROC
 * does not handle. The compositor owns chrome, hit-testing and
 * repaint, so there is no default behaviour left to run in ring 3;
 * 0 ("handled, nothing to do") is what every message resolves to. */
__declspec(dllexport) LRESULT __stdcall DefWindowProcA(HWND h, UINT msg, WPARAM w, LPARAM l)
{
    (void)h;
    (void)msg;
    (void)w;
    (void)l;
    return 0;
}

__declspec(dllexport) LRESULT __stdcall DefWindowProcW(HWND h, UINT msg, WPARAM w, LPARAM l)
{
    return DefWindowProcA(h, msg, w, l);
}

/* ------------------------------------------------------------------
 * Window long slots
 * ------------------------------------------------------------------ */

/* Win32 addresses style / ex-style with negative indices. Map those
 * onto the kernel's slot numbers; a non-negative index is a
 * cbWndExtra offset, which the kernel exposes as slots 0..3 only. */
static int user32_long_slot(int index)
{
    switch (index)
    {
    case -4: /* GWLP_WNDPROC */
        return GWLP_WNDPROC;
    case -21: /* GWLP_USERDATA */
        return GWLP_USERDATA;
    case -16: /* GWL_STYLE */
        return USER32_LONG_STYLE;
    case -20: /* GWL_EXSTYLE */
        return USER32_LONG_EXSTYLE;
    default:
        break;
    }
    // GAP: cbWndExtra byte offsets beyond the four kernel long slots
    // are unbacked — revisit when a PE is seen using SetWindowLong
    // with a positive index.
    if (index >= 0 && index < 4)
        return index;
    return -1;
}

__declspec(dllexport) LONG __stdcall GetWindowLongA(HWND h, int index)
{
    const int slot = user32_long_slot(index);
    if (!h || slot < 0)
        return 0;
    return (LONG)user32_get_long(h, slot);
}

__declspec(dllexport) LONG __stdcall GetWindowLongW(HWND h, int index)
{
    return GetWindowLongA(h, index);
}

__declspec(dllexport) LONG __stdcall SetWindowLongA(HWND h, int index, LONG value)
{
    const int slot = user32_long_slot(index);
    if (!h || slot < 0)
        return 0;
    return (LONG)user32_set_long(h, slot, (unsigned)value);
}

__declspec(dllexport) LONG __stdcall SetWindowLongW(HWND h, int index, LONG value)
{
    return SetWindowLongA(h, index, value);
}
