/*
 * userland/libs/user32_32/user32_32_util.c
 *
 * The computational half of the i386 (PE32) user32 companion: the
 * character classifiers, the RECT algebra, the system palette, the
 * window-relationship queries, and the per-window record table that
 * GetWindowText / GetClassName read back from.
 *
 * Everything here is either pure computation on caller memory or a
 * thin translation of one SYS_WIN_* / SYS_GDI_* call. Nothing in this
 * file invents a value: an export with no honest answer available
 * carries its STUB marker and returns the documented failure.
 *
 * Two i386 hazards worth naming, both of which shape code below:
 *
 *  - POINT and RECT are passed differently. A RECT always crosses as
 *    a pointer to four int32s, which is layout-identical on every
 *    Win32 ABI. A POINT is passed BY VALUE to PtInRect, which on
 *    i386 __stdcall means two dwords pushed on the stack — not the
 *    single 64-bit register slot the x86_64 sibling sees. The struct
 *    is therefore declared and taken by value, never faked as a
 *    pointer.
 *
 *  - GetSysColorBrush must NOT call SYS_GDI_GET_SYS_COLOR_BRUSH
 *    (128). That op hands back a handle from the kernel's GDI object
 *    table, which is what the PE32+ gdi32 consumes; the i386 pair
 *    uses the self-describing encoding in duet32_gdi_abi.h, where a
 *    brush IS its colour. Handing an i386 caller a kernel handle
 *    would make FillRect decode a garbage colour. The brush is minted
 *    locally from the palette colour instead.
 */

#include "user32_32_internal.h"

/* ------------------------------------------------------------------
 * Per-window record table
 *
 * See the contract + GAP note in user32_32_internal.h. Sized to match
 * the class table; a window past the cap simply has no record, and
 * GetWindowText / GetClassName report empty for it rather than
 * reporting someone else's.
 * ------------------------------------------------------------------ */

#define USER32_WINDOW_CAP 32

struct user32_window_record
{
    HWND hwnd;
    HWND parent;
    int ctrl_id;
    int enabled;
    char cls[USER32_CLASS_NAME_MAX];
    char title[WIN_TITLE_MAX];
    int in_use;
};
static struct user32_window_record s_windows[USER32_WINDOW_CAP];

static struct user32_window_record* user32_record_find(HWND hwnd)
{
    if (!hwnd)
        return 0;
    for (unsigned i = 0; i < USER32_WINDOW_CAP; ++i)
    {
        if (s_windows[i].in_use && s_windows[i].hwnd == hwnd)
            return &s_windows[i];
    }
    return 0;
}

void user32_record_create(HWND hwnd, const char* cls, const char* title, HWND parent, int ctrl_id)
{
    if (!hwnd)
        return;
    struct user32_window_record* r = user32_record_find(hwnd);
    if (!r)
    {
        for (unsigned i = 0; i < USER32_WINDOW_CAP; ++i)
        {
            if (!s_windows[i].in_use)
            {
                r = &s_windows[i];
                r->hwnd = hwnd;
                r->in_use = 1;
                break;
            }
        }
    }
    if (!r)
        return;
    r->parent = parent;
    r->ctrl_id = ctrl_id;
    r->enabled = 1;
    user32_strcpy_ascii(r->cls, USER32_CLASS_NAME_MAX, cls);
    user32_strcpy_ascii(r->title, WIN_TITLE_MAX, title);
}

HWND user32_record_child_by_id(HWND parent, int ctrl_id)
{
    for (unsigned i = 0; i < USER32_WINDOW_CAP; ++i)
    {
        if (s_windows[i].in_use && s_windows[i].parent == parent && s_windows[i].ctrl_id == ctrl_id)
            return s_windows[i].hwnd;
    }
    return (HWND)0;
}

int user32_record_ctrl_id(HWND hwnd)
{
    const struct user32_window_record* r = user32_record_find(hwnd);
    return r ? r->ctrl_id : 0;
}

int user32_record_enabled(HWND hwnd)
{
    const struct user32_window_record* r = user32_record_find(hwnd);
    /* A window with no record is not one this process created; Win32
     * reports unknown windows as enabled. */
    return r ? r->enabled : 1;
}

void user32_record_set_enabled(HWND hwnd, int enabled)
{
    struct user32_window_record* r = user32_record_find(hwnd);
    if (r)
        r->enabled = enabled;
}

void user32_record_destroy(HWND hwnd)
{
    struct user32_window_record* r = user32_record_find(hwnd);
    if (!r)
        return;
    r->in_use = 0;
    r->hwnd = 0;
    r->cls[0] = '\0';
    r->title[0] = '\0';
}

void user32_record_set_title(HWND hwnd, const char* title)
{
    struct user32_window_record* r = user32_record_find(hwnd);
    if (r)
        user32_strcpy_ascii(r->title, WIN_TITLE_MAX, title);
}

static unsigned user32_copy_out(const char* src, char* out, unsigned cap)
{
    unsigned n = 0;
    if (!out || cap == 0)
        return 0;
    for (; n + 1 < cap && src[n]; ++n)
        out[n] = src[n];
    out[n] = '\0';
    return n;
}

unsigned user32_record_title(HWND hwnd, char* out, unsigned cap)
{
    const struct user32_window_record* r = user32_record_find(hwnd);
    if (!r)
    {
        if (out && cap)
            out[0] = '\0';
        return 0;
    }
    return user32_copy_out(r->title, out, cap);
}

unsigned user32_record_class(HWND hwnd, char* out, unsigned cap)
{
    const struct user32_window_record* r = user32_record_find(hwnd);
    if (!r)
    {
        if (out && cap)
            out[0] = '\0';
        return 0;
    }
    return user32_copy_out(r->cls, out, cap);
}

/* ------------------------------------------------------------------
 * Character helpers
 *
 * Win32 overloads Char*A / Char*W: a pointer below 0x10000 is not a
 * string, it is a single character in the low word (the same
 * reserved-low-64K convention MAKEINTATOM uses). Both forms are
 * handled — the single-character form is what most callers of
 * CharUpperW actually use.
 *
 * GAP: case mapping is ASCII A-Z / a-z only. Correct Unicode casing
 * needs a case-folding table, which belongs with the NLS surface
 * rather than here.
 * ------------------------------------------------------------------ */

static int user32_is_char_ptr(const void* p)
{
    return (unsigned)(unsigned long)p >= 0x10000u;
}

static char user32_upper_a(char c)
{
    return (c >= 'a' && c <= 'z') ? (char)(c - ('a' - 'A')) : c;
}

static char user32_lower_a(char c)
{
    return (c >= 'A' && c <= 'Z') ? (char)(c + ('a' - 'A')) : c;
}

__declspec(dllexport) char* __stdcall CharNextA(const char* s)
{
    if (!s)
        return (char*)0;
    /* GAP: no DBCS lead-byte handling — the code page is single-byte
     * (kernel32_32's GetACP reports one), so "next" is one byte. */
    return (char*)(*s ? s + 1 : s);
}

__declspec(dllexport) char* __stdcall CharPrevA(const char* start, const char* cur)
{
    if (!start || !cur || cur <= start)
        return (char*)start;
    return (char*)(cur - 1);
}

__declspec(dllexport) wchar_t16* __stdcall CharNextW(const wchar_t16* s)
{
    if (!s)
        return (wchar_t16*)0;
    /* GAP: surrogate pairs advance one code unit, not one code point.
     * The rest of this DLL flattens non-ASCII to '?' anyway, so a
     * caller that reaches a surrogate has already lost the character. */
    return (wchar_t16*)(*s ? s + 1 : s);
}

__declspec(dllexport) wchar_t16* __stdcall CharPrevW(const wchar_t16* start, const wchar_t16* cur)
{
    if (!start || !cur || cur <= start)
        return (wchar_t16*)start;
    return (wchar_t16*)(cur - 1);
}

__declspec(dllexport) char* __stdcall CharUpperA(char* s)
{
    if (!user32_is_char_ptr(s))
        return (char*)(unsigned long)(unsigned char)user32_upper_a((char)(unsigned long)s);
    for (char* p = s; *p; ++p)
        *p = user32_upper_a(*p);
    return s;
}

__declspec(dllexport) char* __stdcall CharLowerA(char* s)
{
    if (!user32_is_char_ptr(s))
        return (char*)(unsigned long)(unsigned char)user32_lower_a((char)(unsigned long)s);
    for (char* p = s; *p; ++p)
        *p = user32_lower_a(*p);
    return s;
}

__declspec(dllexport) wchar_t16* __stdcall CharUpperW(wchar_t16* s)
{
    if (!user32_is_char_ptr(s))
    {
        const wchar_t16 c = (wchar_t16)(unsigned long)s;
        return (wchar_t16*)(unsigned long)(unsigned)((c >= 'a' && c <= 'z') ? (c - ('a' - 'A')) : c);
    }
    for (wchar_t16* p = s; *p; ++p)
    {
        if (*p >= 'a' && *p <= 'z')
            *p = (wchar_t16)(*p - ('a' - 'A'));
    }
    return s;
}

__declspec(dllexport) wchar_t16* __stdcall CharLowerW(wchar_t16* s)
{
    if (!user32_is_char_ptr(s))
    {
        const wchar_t16 c = (wchar_t16)(unsigned long)s;
        return (wchar_t16*)(unsigned long)(unsigned)((c >= 'A' && c <= 'Z') ? (c + ('a' - 'A')) : c);
    }
    for (wchar_t16* p = s; *p; ++p)
    {
        if (*p >= 'A' && *p <= 'Z')
            *p = (wchar_t16)(*p + ('a' - 'A'));
    }
    return s;
}

__declspec(dllexport) DWORD __stdcall CharUpperBuffW(wchar_t16* s, DWORD len)
{
    if (!s)
        return 0;
    for (DWORD i = 0; i < len; ++i)
    {
        if (s[i] >= 'a' && s[i] <= 'z')
            s[i] = (wchar_t16)(s[i] - ('a' - 'A'));
    }
    return len;
}

__declspec(dllexport) DWORD __stdcall CharLowerBuffW(wchar_t16* s, DWORD len)
{
    if (!s)
        return 0;
    for (DWORD i = 0; i < len; ++i)
    {
        if (s[i] >= 'A' && s[i] <= 'Z')
            s[i] = (wchar_t16)(s[i] + ('a' - 'A'));
    }
    return len;
}

__declspec(dllexport) BOOL __stdcall IsCharAlphaA(char c)
{
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
}

__declspec(dllexport) BOOL __stdcall IsCharAlphaW(wchar_t16 c)
{
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
}

__declspec(dllexport) BOOL __stdcall IsCharAlphaNumericA(char c)
{
    return IsCharAlphaA(c) || (c >= '0' && c <= '9');
}

__declspec(dllexport) BOOL __stdcall IsCharAlphaNumericW(wchar_t16 c)
{
    return IsCharAlphaW(c) || (c >= '0' && c <= '9');
}

/* ------------------------------------------------------------------
 * RECT algebra — pure computation on caller memory, exact Win32
 * semantics (right/bottom exclusive, empty rects normalise to all
 * zeroes in IntersectRect).
 * ------------------------------------------------------------------ */

__declspec(dllexport) BOOL __stdcall PtInRect(const struct user32_rect* r, struct user32_point pt)
{
    if (!r)
        return 0;
    return (pt.x >= r->left && pt.x < r->right && pt.y >= r->top && pt.y < r->bottom) ? 1 : 0;
}

__declspec(dllexport) BOOL __stdcall SetRect(struct user32_rect* r, INT l, INT t, INT rt, INT b)
{
    if (!r)
        return 0;
    r->left = l;
    r->top = t;
    r->right = rt;
    r->bottom = b;
    return 1;
}

__declspec(dllexport) BOOL __stdcall SetRectEmpty(struct user32_rect* r)
{
    return SetRect(r, 0, 0, 0, 0);
}

__declspec(dllexport) BOOL __stdcall CopyRect(struct user32_rect* dst, const struct user32_rect* src)
{
    if (!dst || !src)
        return 0;
    *dst = *src;
    return 1;
}

__declspec(dllexport) BOOL __stdcall IsRectEmpty(const struct user32_rect* r)
{
    if (!r)
        return 1;
    return (r->left >= r->right || r->top >= r->bottom) ? 1 : 0;
}

__declspec(dllexport) BOOL __stdcall EqualRect(const struct user32_rect* a, const struct user32_rect* b)
{
    if (!a || !b)
        return 0;
    return (a->left == b->left && a->top == b->top && a->right == b->right && a->bottom == b->bottom) ? 1 : 0;
}

__declspec(dllexport) BOOL __stdcall InflateRect(struct user32_rect* r, INT dx, INT dy)
{
    if (!r)
        return 0;
    r->left -= dx;
    r->right += dx;
    r->top -= dy;
    r->bottom += dy;
    return 1;
}

__declspec(dllexport) BOOL __stdcall OffsetRect(struct user32_rect* r, INT dx, INT dy)
{
    if (!r)
        return 0;
    r->left += dx;
    r->right += dx;
    r->top += dy;
    r->bottom += dy;
    return 1;
}

__declspec(dllexport) BOOL __stdcall IntersectRect(struct user32_rect* out, const struct user32_rect* a,
                                                   const struct user32_rect* b)
{
    if (!out || !a || !b)
        return 0;
    const INT l = (a->left > b->left) ? a->left : b->left;
    const INT t = (a->top > b->top) ? a->top : b->top;
    const INT r = (a->right < b->right) ? a->right : b->right;
    const INT bo = (a->bottom < b->bottom) ? a->bottom : b->bottom;
    if (l >= r || t >= bo)
    {
        (void)SetRectEmpty(out);
        return 0;
    }
    return SetRect(out, l, t, r, bo);
}

__declspec(dllexport) BOOL __stdcall UnionRect(struct user32_rect* out, const struct user32_rect* a,
                                               const struct user32_rect* b)
{
    if (!out || !a || !b)
        return 0;
    /* Win32 treats an empty operand as absent rather than as a rect
     * anchored at its coordinates. */
    if (IsRectEmpty(a))
    {
        if (IsRectEmpty(b))
        {
            (void)SetRectEmpty(out);
            return 0;
        }
        return CopyRect(out, b);
    }
    if (IsRectEmpty(b))
        return CopyRect(out, a);
    return SetRect(out, (a->left < b->left) ? a->left : b->left, (a->top < b->top) ? a->top : b->top,
                   (a->right > b->right) ? a->right : b->right, (a->bottom > b->bottom) ? a->bottom : b->bottom);
}

/* ------------------------------------------------------------------
 * System palette
 * ------------------------------------------------------------------ */

__declspec(dllexport) DWORD __stdcall GetSysColor(int index)
{
    return (DWORD)duet_syscall1(SYS_GDI_GET_SYS_COLOR, (unsigned)index);
}

/* See the file header for why this mints the handle rather than
 * calling SYS_GDI_GET_SYS_COLOR_BRUSH: the i386 pair's brushes are
 * self-describing (colour IS the handle), so a kernel-table handle
 * would decode as a garbage colour in FillRect. */
__declspec(dllexport) HBRUSH __stdcall GetSysColorBrush(int index)
{
    const unsigned colour = (unsigned)duet_syscall1(SYS_GDI_GET_SYS_COLOR, (unsigned)index);
    return (HBRUSH)(unsigned long)(DUET32_GDI_BRUSH_TAG | (colour & DUET32_GDI_COLOUR_MASK));
}

/* ------------------------------------------------------------------
 * Window queries
 * ------------------------------------------------------------------ */

/* A biased compositor index whose owner matches the caller's pid is a
 * valid window, and SYS_WIN_GET_RECT succeeds iff both hold — which
 * is exactly the Win32 IsWindow contract. Same trick the PE32+
 * sibling uses. */
__declspec(dllexport) BOOL __stdcall IsWindow(HWND h)
{
    struct user32_rect r = {0, 0, 0, 0};
    return duet_syscall3(SYS_WIN_GET_RECT, (unsigned)(unsigned long)h, 0, (unsigned)(unsigned long)&r) ? 1 : 0;
}

/* GetWindow relationship selectors (winuser.h) mapped onto
 * SYS_WIN_GET_RELATED's kind argument. */
#define GW_HWNDFIRST 0
#define GW_HWNDLAST 1
#define GW_HWNDNEXT 2
#define GW_HWNDPREV 3
#define GW_OWNER 4
#define GW_CHILD 5

__declspec(dllexport) HWND __stdcall GetWindow(HWND h, UINT cmd)
{
    unsigned kind;
    switch (cmd)
    {
    case GW_HWNDNEXT:
        kind = 0;
        break;
    case GW_HWNDPREV:
        kind = 1;
        break;
    case GW_HWNDFIRST:
        kind = 2;
        break;
    case GW_HWNDLAST:
        kind = 3;
        break;
    case GW_CHILD:
        kind = 4;
        break;
    case GW_OWNER:
        kind = 5;
        break;
    default:
        return (HWND)0;
    }
    return (HWND)(unsigned long)(unsigned)duet_syscall2(SYS_WIN_GET_RELATED, (unsigned)(unsigned long)h, kind);
}

__declspec(dllexport) HWND __stdcall FindWindowA(const char* cls, const char* title)
{
    /* SYS_WIN_FIND matches on the window title only — the compositor
     * has no class concept. Passing the class as the needle when no
     * title was given is what a caller searching by class expects to
     * work at least as often as it can. */
    const char* needle = title ? title : cls;
    if (!needle)
        return (HWND)0;
    return (HWND)(unsigned long)(unsigned)duet_syscall1(SYS_WIN_FIND, (unsigned)(unsigned long)needle);
}

__declspec(dllexport) HWND __stdcall FindWindowW(const wchar_t16* cls, const wchar_t16* title)
{
    char flat[WIN_TITLE_MAX];
    user32_w_to_ascii(title ? title : cls, flat, WIN_TITLE_MAX);
    if (!flat[0])
        return (HWND)0;
    return (HWND)(unsigned long)(unsigned)duet_syscall1(SYS_WIN_FIND, (unsigned)(unsigned long)flat);
}

__declspec(dllexport) HWND __stdcall SetParent(HWND child, HWND parent)
{
    return (HWND)(unsigned long)(unsigned)duet_syscall2(SYS_WIN_SET_PARENT, (unsigned)(unsigned long)child,
                                                        (unsigned)(unsigned long)parent);
}

/* GAP: the compositor does not record which process owns a foreign
 * HWND, so this reports the CALLER's ids. For the overwhelmingly
 * common case — a process asking about its own window — that is the
 * right answer, and it agrees with what kernel32_32's
 * GetCurrentProcessId / GetCurrentThreadId told the same caller. A
 * cross-process query silently gets the caller's pid instead of the
 * owner's. */
__declspec(dllexport) DWORD __stdcall GetWindowThreadProcessId(HWND h, DWORD* pid)
{
    (void)h;
    const DWORD id = (DWORD)duet_syscall0(SYS_GETPID);
    if (pid)
        *pid = id;
    return id;
}

__declspec(dllexport) int __stdcall GetWindowTextA(HWND h, char* buf, int len)
{
    if (!buf || len <= 0)
        return 0;
    return (int)user32_record_title(h, buf, (unsigned)len);
}

__declspec(dllexport) int __stdcall GetWindowTextW(HWND h, wchar_t16* buf, int len)
{
    if (!buf || len <= 0)
        return 0;
    char flat[WIN_TITLE_MAX];
    const unsigned n = user32_record_title(h, flat, WIN_TITLE_MAX);
    unsigned i = 0;
    for (; i < n && (int)i + 1 < len; ++i)
        buf[i] = (wchar_t16)(unsigned char)flat[i];
    buf[i] = 0;
    return (int)i;
}

__declspec(dllexport) int __stdcall GetWindowTextLengthA(HWND h)
{
    char flat[WIN_TITLE_MAX];
    return (int)user32_record_title(h, flat, WIN_TITLE_MAX);
}

__declspec(dllexport) int __stdcall GetWindowTextLengthW(HWND h)
{
    return GetWindowTextLengthA(h);
}

__declspec(dllexport) int __stdcall GetClassNameA(HWND h, char* buf, int len)
{
    if (!buf || len <= 0)
        return 0;
    return (int)user32_record_class(h, buf, (unsigned)len);
}

__declspec(dllexport) int __stdcall GetClassNameW(HWND h, wchar_t16* buf, int len)
{
    if (!buf || len <= 0)
        return 0;
    char flat[USER32_CLASS_NAME_MAX];
    const unsigned n = user32_record_class(h, flat, USER32_CLASS_NAME_MAX);
    unsigned i = 0;
    for (; i < n && (int)i + 1 < len; ++i)
        buf[i] = (wchar_t16)(unsigned char)flat[i];
    buf[i] = 0;
    return (int)i;
}

/* MapWindowPoints — translate an array of POINTs between two windows'
 * client spaces. Both endpoints resolve through the same window-rect
 * pair ScreenToClient / ClientToScreen use, so a NULL (screen)
 * endpoint and a window endpoint compose correctly.
 *
 * Win32 returns the (y << 16 | x) delta that was applied. */
static void user32_client_origin(HWND h, INT* ox, INT* oy)
{
    *ox = 0;
    *oy = 0;
    if (!h)
        return;
    struct user32_rect wr = {0, 0, 0, 0};
    struct user32_rect cr = {0, 0, 0, 0};
    if (!duet_syscall3(SYS_WIN_GET_RECT, (unsigned)(unsigned long)h, 0, (unsigned)(unsigned long)&wr))
        return;
    if (!duet_syscall3(SYS_WIN_GET_RECT, (unsigned)(unsigned long)h, 1, (unsigned)(unsigned long)&cr))
        return;
    const INT border = ((wr.right - wr.left) - (cr.right - cr.left)) / 2;
    *ox = wr.left + border;
    *oy = wr.bottom - (cr.bottom - cr.top);
}

__declspec(dllexport) int __stdcall MapWindowPoints(HWND from, HWND to, struct user32_point* pts, UINT count)
{
    INT fx = 0, fy = 0, tx = 0, ty = 0;
    user32_client_origin(from, &fx, &fy);
    user32_client_origin(to, &tx, &ty);
    const INT dx = fx - tx;
    const INT dy = fy - ty;
    if (pts)
    {
        for (UINT i = 0; i < count; ++i)
        {
            pts[i].x += dx;
            pts[i].y += dy;
        }
    }
    return (int)(((unsigned)(dy & 0xFFFF) << 16) | ((unsigned)dx & 0xFFFF));
}
