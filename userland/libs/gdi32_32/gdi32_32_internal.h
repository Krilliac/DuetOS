/*
 * userland/libs/gdi32_32/gdi32_32_internal.h
 *
 * Shared plumbing for the i386 (PE32) gdi32 companion DLL: Win32
 * scalar typedefs, the SYS_GDI_* numbers, the HDC/handle encodings,
 * and the draw-call cores. Nothing here is exported.
 *
 * Companion to userland/libs/gdi32/gdi32.c (the PE32+ x86_64
 * variant), which uses the same syscalls and the same handle
 * encodings widened to 64 bits.
 */

#ifndef DUETOS_GDI32_32_INTERNAL_H
#define DUETOS_GDI32_32_INTERNAL_H

#include "../common/duet32_gdi_abi.h"
#include "../common/duet32_syscall.h"

typedef unsigned int DWORD;
typedef unsigned int UINT;
typedef int INT;
typedef int BOOL;
typedef void* HANDLE;
typedef HANDLE HDC;
typedef HANDLE HGDIOBJ;
typedef HANDLE HBITMAP;
typedef HANDLE HBRUSH;
typedef HANDLE HFONT;
typedef HANDLE HPEN;
typedef HANDLE HRGN;
typedef HANDLE HPALETTE;
typedef HANDLE HWND;
typedef unsigned int COLORREF;
typedef unsigned short wchar_t16;

#define SYS_GDI_FILL_RECT 65
#define SYS_GDI_TEXT_OUT 66
#define SYS_GDI_RECTANGLE 67
#define SYS_GDI_CLEAR 68
#define SYS_GDI_LINE 74
#define SYS_GDI_ELLIPSE 75
#define SYS_GDI_SET_PIXEL 76

/* Local spellings of the shared handle encodings (duet32_gdi_abi.h)
 * so the call sites below read as GDI code rather than as ABI
 * plumbing. */
#define GDI32_BRUSH_TAG DUET32_GDI_BRUSH_TAG
#define GDI32_PEN_TAG DUET32_GDI_PEN_TAG
#define GDI32_TYPE_MASK DUET32_GDI_TYPE_MASK
#define GDI32_COLOUR_MASK DUET32_GDI_COLOUR_MASK

typedef struct
{
    INT left;
    INT top;
    INT right;
    INT bottom;
} RECT;

typedef struct
{
    INT x;
    INT y;
} POINT;

static inline HWND gdi32_hwnd_from_hdc(HDC dc)
{
    return (HWND)(unsigned long)Duet32HwndFromHdc(dc);
}

static inline COLORREF gdi32_object_colour(HGDIOBJ obj, unsigned tag)
{
    return (COLORREF)Duet32GdiObjectColour(obj, tag);
}

/* Shared 6-arg rect-shaped primitive: FILL_RECT / RECTANGLE /
 * ELLIPSE all take (hwnd, x, y, w, h, colour). */
static inline BOOL gdi32_rect_core(int nr, HWND hwnd, INT x, INT y, INT w, INT h, COLORREF colour)
{
    return duet_syscall6(nr, (unsigned)(unsigned long)hwnd, (unsigned)x, (unsigned)y, (unsigned)w, (unsigned)h,
                         (unsigned)colour)
               ? 1
               : 0;
}

#endif /* DUETOS_GDI32_32_INTERNAL_H */
