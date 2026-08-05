/*
 * userland/libs/user32_32/user32_32_dlg.c
 *
 * The dialog-item surface, the enabled-state pair, and the odds and
 * ends of the i386 (PE32) user32 companion that did not belong with
 * the window lifecycle (user32_32.c), the WM shims
 * (user32_32_misc.c), or the computational helpers
 * (user32_32_util.c).
 *
 * WHAT IS AND IS NOT REAL HERE — read before extending.
 *
 * A Windows dialog has two halves. The first is a resource-driven
 * one: DialogBoxParam / CreateDialogParam take a template out of the
 * PE's `.rsrc` section, instantiate every control the template
 * describes, and run a modal loop against them. DuetOS has NO PE
 * resource parser — nothing in kernel/loader or userland/libs walks
 * IMAGE_DIRECTORY_ENTRY_RESOURCE — so that half cannot be
 * implemented honestly and every entry point belonging to it carries
 * a STUB marker and returns the documented failure.
 *
 * The second half is the item accessors: GetDlgItem, SetDlgItemText,
 * SendDlgItemMessage, CheckDlgButton and friends. Those are defined
 * purely in terms of "find the child window with this control id,
 * then do a normal window operation on it" — no resource data
 * involved. That works today, because CreateWindowEx records a
 * child's parent and its control id (the `hMenu` argument, per the
 * WS_CHILD convention) in the per-window record table. So an
 * application that builds its dialog by calling CreateWindowEx for
 * each control — which is exactly what code written without a
 * resource compiler does — gets a REAL item surface.
 *
 * The dividing line, stated once so a future reader does not have to
 * re-derive it: anything that needs a TEMPLATE is stubbed; anything
 * that needs only a CONTROL ID is real.
 */

#include "user32_32_internal.h"

/* Defined in the sibling TUs; declared here rather than exported
 * through the internal header because these are the public Win32
 * entry points, not internal plumbing. */
LRESULT __stdcall SendMessageA(HWND h, UINT msg, WPARAM w, LPARAM l);
BOOL __stdcall SetWindowTextA(HWND h, const char* text);
BOOL __stdcall PostMessageA(HWND h, UINT msg, WPARAM w, LPARAM l);
int __stdcall GetWindowTextA(HWND h, char* buf, int len);
int __stdcall GetWindowTextW(HWND h, wchar_t16* buf, int len);
INT __stdcall GetSystemMetrics(int index);

/* Button control messages / states (winuser.h). */
#define BM_GETCHECK 0x00F0
#define BM_SETCHECK 0x00F1

/* ------------------------------------------------------------------
 * Dialog items — real, keyed on control id
 * ------------------------------------------------------------------ */

__declspec(dllexport) HWND __stdcall GetDlgItem(HWND dlg, int id)
{
    return user32_record_child_by_id(dlg, id);
}

__declspec(dllexport) int __stdcall GetDlgCtrlID(HWND h)
{
    return user32_record_ctrl_id(h);
}

__declspec(dllexport) BOOL __stdcall SetDlgItemTextA(HWND dlg, int id, const char* text)
{
    HWND item = GetDlgItem(dlg, id);
    if (!item)
        return 0;
    return SetWindowTextA(item, text);
}

__declspec(dllexport) BOOL __stdcall SetDlgItemTextW(HWND dlg, int id, const wchar_t16* text)
{
    char flat[WIN_TITLE_MAX];
    user32_w_to_ascii(text, flat, WIN_TITLE_MAX);
    return SetDlgItemTextA(dlg, id, flat);
}

__declspec(dllexport) UINT __stdcall GetDlgItemTextA(HWND dlg, int id, char* buf, int cap)
{
    HWND item = GetDlgItem(dlg, id);
    if (!item)
    {
        if (buf && cap > 0)
            buf[0] = '\0';
        return 0;
    }
    return (UINT)GetWindowTextA(item, buf, cap);
}

__declspec(dllexport) UINT __stdcall GetDlgItemTextW(HWND dlg, int id, wchar_t16* buf, int cap)
{
    HWND item = GetDlgItem(dlg, id);
    if (!item)
    {
        if (buf && cap > 0)
            buf[0] = 0;
        return 0;
    }
    return (UINT)GetWindowTextW(item, buf, cap);
}

__declspec(dllexport) LRESULT __stdcall SendDlgItemMessageA(HWND dlg, int id, UINT msg, WPARAM w, LPARAM l)
{
    HWND item = GetDlgItem(dlg, id);
    return item ? SendMessageA(item, msg, w, l) : 0;
}

__declspec(dllexport) LRESULT __stdcall SendDlgItemMessageW(HWND dlg, int id, UINT msg, WPARAM w, LPARAM l)
{
    return SendDlgItemMessageA(dlg, id, msg, w, l);
}

__declspec(dllexport) BOOL __stdcall CheckDlgButton(HWND dlg, int id, UINT check)
{
    HWND item = GetDlgItem(dlg, id);
    if (!item)
        return 0;
    (void)SendMessageA(item, BM_SETCHECK, (WPARAM)check, 0);
    return 1;
}

__declspec(dllexport) UINT __stdcall IsDlgButtonChecked(HWND dlg, int id)
{
    HWND item = GetDlgItem(dlg, id);
    if (!item)
        return 0;
    return (UINT)SendMessageA(item, BM_GETCHECK, 0, 0);
}

__declspec(dllexport) BOOL __stdcall CheckRadioButton(HWND dlg, int first, int last, int check)
{
    if (first > last)
        return 0;
    for (int id = first; id <= last; ++id)
        (void)CheckDlgButton(dlg, id, (UINT)((id == check) ? 1 : 0));
    return 1;
}

__declspec(dllexport) BOOL __stdcall SetDlgItemInt(HWND dlg, int id, UINT value, BOOL is_signed)
{
    /* Format in place — no CRT dependency, and the buffer is sized
     * for the widest 32-bit decimal plus sign and terminator. */
    char buf[12];
    unsigned n = value;
    int neg = 0;
    if (is_signed && (int)value < 0)
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
    return SetDlgItemTextA(dlg, id, &buf[i]);
}

__declspec(dllexport) UINT __stdcall GetDlgItemInt(HWND dlg, int id, BOOL* translated, BOOL is_signed)
{
    char buf[16];
    const UINT len = GetDlgItemTextA(dlg, id, buf, (int)sizeof(buf));
    if (translated)
        *translated = 0;
    if (len == 0)
        return 0;
    unsigned i = 0;
    int neg = 0;
    if (is_signed && buf[0] == '-')
    {
        neg = 1;
        i = 1;
    }
    unsigned value = 0;
    unsigned digits = 0;
    for (; buf[i]; ++i)
    {
        if (buf[i] < '0' || buf[i] > '9')
            return 0;
        value = value * 10u + (unsigned)(buf[i] - '0');
        ++digits;
    }
    if (digits == 0)
        return 0;
    if (translated)
        *translated = 1;
    return neg ? (UINT)(-(int)value) : value;
}

/* ------------------------------------------------------------------
 * Dialog templates — blocked on an RT_DIALOG template decoder
 * ------------------------------------------------------------------ */

// STUB: a dialog template cannot be read, so no controls can be
// instantiated. The rationale that used to sit here -- "no PE resource
// (.rsrc) parser exists anywhere in the tree" -- is stale: the walker
// landed in userland/libs/common/pe_resources.h and this DLL already
// uses it for LoadString / LoadIcon / LoadCursor / LoadBitmap. What is
// still missing is the layer above it: a DLGTEMPLATE / DLGITEMTEMPLATE
// decoder and the control instantiation it drives. Returning -1 is the
// Win32 failure contract for DialogBoxParam and lets a caller take its
// error path instead of waiting forever on a modal loop that never
// runs.
__declspec(dllexport) INT __stdcall DialogBoxParamA(HINSTANCE inst, const char* tmpl, HWND owner, void* proc,
                                                    LPARAM param)
{
    (void)inst;
    (void)tmpl;
    (void)owner;
    (void)proc;
    (void)param;
    return -1;
}

__declspec(dllexport) INT __stdcall DialogBoxParamW(HINSTANCE inst, const wchar_t16* tmpl, HWND owner, void* proc,
                                                    LPARAM param)
{
    (void)inst;
    (void)tmpl;
    (void)owner;
    (void)proc;
    (void)param;
    return -1;
}

// STUB: same missing template decoder. NULL is the Win32 failure return.
__declspec(dllexport) HWND __stdcall CreateDialogParamA(HINSTANCE inst, const char* tmpl, HWND owner, void* proc,
                                                        LPARAM param)
{
    (void)inst;
    (void)tmpl;
    (void)owner;
    (void)proc;
    (void)param;
    return (HWND)0;
}

__declspec(dllexport) HWND __stdcall CreateDialogParamW(HINSTANCE inst, const wchar_t16* tmpl, HWND owner, void* proc,
                                                        LPARAM param)
{
    (void)inst;
    (void)tmpl;
    (void)owner;
    (void)proc;
    (void)param;
    return (HWND)0;
}

// STUB: there is no modal loop to end, because DialogBoxParam never
// started one. A caller reaching EndDialog is on a path its own
// DialogBoxParam failure return should already have diverted; the
// window is destroyed so a hand-built dialog still tears down.
__declspec(dllexport) BOOL __stdcall EndDialog(HWND dlg, INT result)
{
    (void)result;
    user32_record_destroy(dlg);
    return duet_syscall1(SYS_WIN_DESTROY, (unsigned)(unsigned long)dlg) ? 1 : 0;
}

// STUB: no table is ever translated against, so no message is ever
// consumed. The blocker is not the .rsrc walker -- that exists -- but
// this DLL's LoadAcceleratorsA/W, which still return NULL because
// RT_ACCELERATOR needs the KeyCode->VK translation the x86_64 sibling
// has (user32_load_accel in userland/libs/user32/user32.c) and this
// half does not. Returning 0 ("not translated") keeps the caller's pump
// correct — it just dispatches the message normally, which is what
// happens on Windows when no accelerator matches.
__declspec(dllexport) INT __stdcall TranslateAcceleratorA(HWND h, HANDLE accel, void* msg)
{
    (void)h;
    (void)accel;
    (void)msg;
    return 0;
}

__declspec(dllexport) INT __stdcall TranslateAcceleratorW(HWND h, HANDLE accel, void* msg)
{
    (void)h;
    (void)accel;
    (void)msg;
    return 0;
}

/* ------------------------------------------------------------------
 * Enabled state
 * ------------------------------------------------------------------ */

/* GAP: the flag round-trips exactly, and EnableWindow fires the
 * WM_ENABLE the Win32 contract promises, but the compositor does not
 * consult it — a disabled window still receives mouse and keyboard
 * messages. Dialog code that greys a control and later re-reads its
 * own state works; code that relies on the input block does not.
 * Closing this needs an enabled bit in the kernel's window record and
 * a check in the input router. */
__declspec(dllexport) BOOL __stdcall EnableWindow(HWND h, BOOL enable)
{
    const int was = user32_record_enabled(h);
    user32_record_set_enabled(h, enable ? 1 : 0);
    if (was != (enable ? 1 : 0))
    {
        /* WM_ENABLE = 0x000A, wParam = new enabled state. */
        (void)SendMessageA(h, 0x000A, (WPARAM)(enable ? 1u : 0u), 0);
    }
    /* Win32 returns non-zero iff the window was PREVIOUSLY disabled. */
    return was ? 0 : 1;
}

__declspec(dllexport) BOOL __stdcall IsWindowEnabled(HWND h)
{
    return user32_record_enabled(h) ? 1 : 0;
}

/* ------------------------------------------------------------------
 * Thread-targeted messages
 * ------------------------------------------------------------------ */

#define DUETOS_THREAD_MESSAGE_TAG 0x80000000u

/* The high-bit target is an internal SYS_WIN_POST_MSG transport tag. Public
 * PE32 HWND values reserve the high byte as zero, so it cannot alias a window. */
__declspec(dllexport) BOOL __stdcall PostThreadMessageA(DWORD tid, UINT msg, WPARAM w, LPARAM l)
{
    if (tid == 0 || (tid & DUETOS_THREAD_MESSAGE_TAG) != 0)
        return 0;
    return PostMessageA((HWND)(unsigned long)(DUETOS_THREAD_MESSAGE_TAG | tid), msg, w, l);
}

__declspec(dllexport) BOOL __stdcall PostThreadMessageW(DWORD tid, UINT msg, WPARAM w, LPARAM l)
{
    return PostThreadMessageA(tid, msg, w, l);
}

/* ------------------------------------------------------------------
 * System parameters
 * ------------------------------------------------------------------ */

#define SPI_GETWORKAREA 0x0030
#define SM_CXSCREEN 0
#define SM_CYSCREEN 1

/* SPI_GETWORKAREA is answerable: the compositor has no reserved
 * taskbar strip, so the work area IS the screen, and both extents
 * come from the same SYS_WIN_GET_METRIC the caller could have asked
 * GetSystemMetrics for.
 *
 * GAP: every other SPI_* action reports failure. The ones callers ask
 * for most (SPI_GETNONCLIENTMETRICS, SPI_GETICONTITLELOGFONT) want
 * LOGFONT data, which needs a font pipeline that does not exist; the
 * rest describe desktop preferences DuetOS does not model. Reporting
 * failure lets a caller fall back to its own defaults, which is
 * strictly better than handing it a zeroed LOGFONT it would then try
 * to render with. */
__declspec(dllexport) BOOL __stdcall SystemParametersInfoA(UINT action, UINT param, void* data, UINT winini)
{
    (void)param;
    (void)winini;
    if (action == SPI_GETWORKAREA)
    {
        if (!data)
            return 0;
        struct user32_rect* r = (struct user32_rect*)data;
        r->left = 0;
        r->top = 0;
        r->right = GetSystemMetrics(SM_CXSCREEN);
        r->bottom = GetSystemMetrics(SM_CYSCREEN);
        return 1;
    }
    return 0;
}

__declspec(dllexport) BOOL __stdcall SystemParametersInfoW(UINT action, UINT param, void* data, UINT winini)
{
    return SystemParametersInfoA(action, param, data, winini);
}

/* ------------------------------------------------------------------
 * Icon / cursor lifetime + monitors
 * ------------------------------------------------------------------ */

// STUB: these report success without releasing anything. The rationale
// that used to sit here -- "LoadIcon / LoadCursor hand back non-null
// sentinels, so there is nothing allocated" -- is stale: LoadIcon and
// LoadCursor now decode .rsrc and return a real GDI bitmap / cursor
// handle for a PE hInstance (see user32_32_misc.c), so a caller that
// loads in a loop leaks one kernel object per call. Retiring this needs
// a GDI object-delete syscall these DLLs do not import yet. TRUE keeps
// a caller's cleanup path quiet; it is not evidence anything was freed.
__declspec(dllexport) BOOL __stdcall DestroyIcon(HICON icon)
{
    (void)icon;
    return 1;
}

__declspec(dllexport) BOOL __stdcall DestroyCursor(HCURSOR cursor)
{
    (void)cursor;
    return 1;
}

// STUB: single-monitor sentinel. The compositor drives one
// framebuffer and has no monitor objects, so every query resolves to
// the same pseudo-handle. 0x9001 matches the PE32+ sibling so the two
// surfaces do not diverge on the value a caller might compare.
__declspec(dllexport) HANDLE __stdcall MonitorFromWindow(HWND h, DWORD flags)
{
    (void)h;
    (void)flags;
    return (HANDLE)(unsigned long)0x9001u;
}

__declspec(dllexport) HANDLE __stdcall MonitorFromPoint(struct user32_point pt, DWORD flags)
{
    (void)pt;
    (void)flags;
    return (HANDLE)(unsigned long)0x9001u;
}

__declspec(dllexport) HANDLE __stdcall MonitorFromRect(const struct user32_rect* r, DWORD flags)
{
    (void)r;
    (void)flags;
    return (HANDLE)(unsigned long)0x9001u;
}
