/*
 * userland/libs/user32_32/user32_32_internal.h
 *
 * Shared plumbing for the i386 (PE32) user32 companion DLL: the
 * Win32 scalar typedefs, the SYS_WIN_* numbers this DLL issues, the
 * kernel message wire format, and the small string helpers both TUs
 * use. Nothing here is exported.
 *
 * Companion to userland/libs/user32/user32.c (the PE32+ x86_64
 * variant). Both drive the same kernel window manager through the
 * same syscalls; only the ABI differs.
 */

#ifndef DUETOS_USER32_32_INTERNAL_H
#define DUETOS_USER32_32_INTERNAL_H

#include "../common/duet32_gdi_abi.h"
#include "../common/duet32_syscall.h"

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
typedef HANDLE HBRUSH;
typedef long LONG;
typedef short SHORT;
typedef unsigned short USHORT;
typedef unsigned short ATOM;
typedef unsigned short wchar_t16;

/* i386 Win32 scalars: LRESULT / WPARAM / LPARAM are all pointer-
 * sized, i.e. 32 bits here — NOT the 64-bit spellings the x86_64
 * user32.c uses. Every value crossing the syscall boundary is
 * therefore truncated to 32 bits on the way back out. */
typedef int LRESULT;
typedef unsigned int WPARAM;
typedef unsigned int LPARAM;

typedef LRESULT(__stdcall* WNDPROC)(HWND hwnd, UINT msg, WPARAM w, LPARAM l);

/* Syscall numbers duplicated from kernel/syscall/syscall.h. Kept in
 * sync by tools/test/check-syscall-numbers.py, which parses the
 * `#define SYS_* <n>` lines below against the kernel enum. */
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
#define SYS_WIN_FIND 93
#define SYS_WIN_SET_PARENT 94
#define SYS_WIN_GET_PARENT 95
#define SYS_WIN_GET_RELATED 96
#define SYS_WIN_SET_FOCUS 97
#define SYS_WIN_GET_FOCUS 98
#define SYS_WIN_CARET 99
#define SYS_GDI_GET_SYS_COLOR 127

/* The scheduler id syscall. kernel32_32 reports it as both the
 * process id and the thread id, and GetWindowThreadProcessId has to
 * agree with whatever GetCurrentProcessId told the same caller. */
#define SYS_GETPID 1

/* Per-window long slots addressed by SYS_WIN_GET/SET_LONG. Slot 0
 * holds the WNDPROC that DispatchMessage recovers; slot 1 is
 * GWLP_USERDATA; slots 2/3 mirror the Win32 GWL_STYLE (-16) and
 * GWL_EXSTYLE (-20) indices. */
#define GWLP_WNDPROC 0
#define GWLP_USERDATA 1
#define USER32_LONG_STYLE 2
#define USER32_LONG_EXSTYLE 3

#define WM_QUIT 0x0012
#define PM_REMOVE 0x0001

/* Longest window title the kernel stores (kWinTitleMax). Titles are
 * copied into a bounded stack buffer before the syscall so a wide
 * caller string never reaches the kernel un-flattened. */
#define WIN_TITLE_MAX 64

/* Longest class name the in-process class table stores. Shared with
 * the per-window record table below, which mirrors it. */
#define USER32_CLASS_NAME_MAX 64

/* Windows homes part of the drawing surface in USER32 — FillRect,
 * FrameRect and DrawText draw, but an importer resolves them
 * against user32.dll, so they have to live here too. They speak the
 * same handle ABI gdi32_32 does (duet32_gdi_abi.h) and go straight
 * to the same display-list syscalls. */
#define SYS_GDI_FILL_RECT 65
#define SYS_GDI_TEXT_OUT 66
#define SYS_GDI_RECTANGLE 67

/* The kernel's message wire format — the first 32 bytes of the
 * *x86_64* MSG, which is what SYS_WIN_{PEEK,GET}_MSG blind-writes
 * to whatever pointer it is handed:
 *   { u64 hwnd; u32 message; u32 _pad; u64 wParam; u64 lParam; }
 *
 * An i386 MSG is only 28 bytes and lays its fields out differently.
 * Passing a caller's real MSG* straight through would misalign every
 * field AND scribble 4 bytes past the end of the caller's struct, so
 * both pump entrypoints hand the kernel one of these and repack. */
struct user32_msg_wire
{
    unsigned hwnd_lo;
    unsigned hwnd_hi;
    UINT message;
    UINT _pad;
    unsigned wparam_lo;
    unsigned wparam_hi;
    unsigned lparam_lo;
    unsigned lparam_hi;
};

/* RECT is four int32s on every Win32 ABI, so a kernel 16-byte write
 * lands correctly on i386 without repacking — unlike MSG. POINT is
 * two int32s, but note it is passed BY VALUE to PtInRect, which on
 * i386 __stdcall means two pushed dwords rather than the single
 * register slot the x86_64 sibling gets. */
struct user32_rect
{
    INT left;
    INT top;
    INT right;
    INT bottom;
};

struct user32_point
{
    INT x;
    INT y;
};

/* The i386 MSG the caller actually owns. 28 bytes. */
struct user32_msg32
{
    HWND hwnd;
    UINT message;
    WPARAM wParam;
    LPARAM lParam;
    DWORD time;
    INT pt_x;
    INT pt_y;
};

/* Copy the kernel's 32-byte wire message into the caller's 28-byte
 * i386 MSG. Defined in user32_32.c. */
void user32_msg_unpack(const struct user32_msg_wire* wire, struct user32_msg32* out);

/* Flatten a UTF-16 string into a bounded ASCII buffer; non-ASCII
 * code units become '?'. Always NUL-terminates. Defined in
 * user32_32.c. */
void user32_w_to_ascii(const wchar_t16* src, char* dst, unsigned cap);

/* Case-insensitive bounded compare, used by the class table. */
int user32_strieq(const char* a, const char* b, unsigned cap);

/* Read/write one of the target window's long slots. */
unsigned user32_get_long(HWND hwnd, int slot);
unsigned user32_set_long(HWND hwnd, int slot, unsigned value);

/* Copy a bounded NUL-terminated ASCII string. Defined in
 * user32_32.c; shared with the record table. */
void user32_strcpy_ascii(char* dst, unsigned cap, const char* src);

/* ------------------------------------------------------------------
 * Per-window record table (user32_32_util.c)
 *
 * The compositor stores a window's title but exposes no read-back op
 * (SYS_WIN_SET_TEXT has no GET counterpart), and it has no notion of
 * a window class at all — the class table is entirely in-process. So
 * GetWindowText and GetClassName need a local record, written on
 * CreateWindowEx* and updated on SetWindowText*.
 *
 * GAP: the records are per-process. A title set by another process,
 * or by the kernel's own default-label path when CreateWindowEx was
 * passed a NULL name, reads back empty here. Every same-process
 * set-then-get sequence — which is what these two APIs are for —
 * is exact.
 * ------------------------------------------------------------------ */
void user32_record_create(HWND hwnd, const char* cls, const char* title, HWND parent, int ctrl_id);
void user32_record_destroy(HWND hwnd);
void user32_record_set_title(HWND hwnd, const char* title);

/* Dialog-item plumbing. A control is a child window whose creator
 * passed its id in CreateWindowEx's `hMenu` slot (the Win32
 * convention when WS_CHILD is set), so GetDlgItem is a real lookup
 * over the records rather than a resource-table walk. */
HWND user32_record_child_by_id(HWND parent, int ctrl_id);
int user32_record_ctrl_id(HWND hwnd);

/* Per-window enabled flag. The compositor has no enabled/disabled
 * state, so EnableWindow records here and IsWindowEnabled reads back.
 */
int user32_record_enabled(HWND hwnd);
void user32_record_set_enabled(HWND hwnd, int enabled);

/* Copy the recorded title / class name into `out` (always
 * NUL-terminated). Returns the character count written, 0 when the
 * window has no record. */
unsigned user32_record_title(HWND hwnd, char* out, unsigned cap);
unsigned user32_record_class(HWND hwnd, char* out, unsigned cap);

#endif /* DUETOS_USER32_32_INTERNAL_H */
