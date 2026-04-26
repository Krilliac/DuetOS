/*
 * userland/libs/dx_shared.h
 *
 * Freestanding shared header for the four DirectX DLLs that
 * make up DuetOS's DirectX v0 (d3d9, d3d11, d3d12, dxgi).
 *
 * Each DLL is built independently by tools/build/build-stub-dll.sh
 * with no include path; this header lives one directory up so
 * a `#include "../dx_shared.h"` in each .c file picks it up.
 *
 * Contents:
 *   - Win32 type aliases (DWORD, HRESULT, ...)
 *   - HRESULT codes
 *   - GUID type + comparison helper
 *   - Heap / window / blit syscall wrappers (int 0x80)
 *   - Byte-loop memcpy / memset / memcmp (no-builtin) helpers
 *   - "ok" stub trio (HRESULT/UINT/void) used to fill cold
 *     vtable slots that we don't (yet) implement
 *   - The shared back-buffer descriptor that swap chains in
 *     all four DLLs use, so Present always BitBlts the same
 *     pixel layout (BGRA8, row-major, no padding)
 */

#ifndef DUETOS_DX_SHARED_H
#define DUETOS_DX_SHARED_H

/* MSVC PE link-time marker: any TU that uses floating-point ops
 * has to define `_fltused`. Each DX DLL is a single .c file that
 * includes this header exactly once, so putting the definition
 * here keeps all four DLLs one symbol per image. */
__attribute__((used)) int _fltused = 0;

/* ---------------------------------------------------------------- *
 * Type aliases                                                     *
 * ---------------------------------------------------------------- */

typedef unsigned char BYTE;
typedef unsigned short WORD;
typedef unsigned int DWORD;
typedef unsigned long long UINT64;
typedef unsigned int UINT;
typedef unsigned long ULONG;
typedef long LONG;
typedef int INT;
typedef int BOOL;
typedef int HRESULT_; /* internal use; HRESULT below */
typedef unsigned long HRESULT;
typedef unsigned long long SIZE_T;
typedef long long SSIZE_T;
typedef void* HWND;
typedef void* HANDLE;
typedef void* HMODULE;
typedef unsigned long long ULONGLONG;
typedef long long LONGLONG;
typedef unsigned int UINT32;
typedef unsigned long long UINT64_T;

#ifndef NULL
#define NULL ((void*)0)
#endif

/* ---------------------------------------------------------------- *
 * HRESULT codes                                                    *
 * ---------------------------------------------------------------- */

#define DX_S_OK ((HRESULT)0x00000000UL)
#define DX_S_FALSE ((HRESULT)0x00000001UL)
#define DX_E_FAIL ((HRESULT)0x80004005UL)
#define DX_E_NOTIMPL ((HRESULT)0x80004001UL)
#define DX_E_NOINTERFACE ((HRESULT)0x80004002UL)
#define DX_E_POINTER ((HRESULT)0x80004003UL)
#define DX_E_INVALIDARG ((HRESULT)0x80070057UL)
#define DX_E_OUTOFMEMORY ((HRESULT)0x8007000EUL)
#define DXGI_ERROR_NOT_FOUND ((HRESULT)0x887A0002UL)
#define DXGI_ERROR_INVALID_CALL ((HRESULT)0x887A0001UL)

/* ---------------------------------------------------------------- *
 * GUIDs                                                            *
 * ---------------------------------------------------------------- */

typedef struct DxGuid
{
    DWORD Data1;
    WORD Data2;
    WORD Data3;
    BYTE Data4[8];
} DxGuid;

typedef const DxGuid* REFIID;

#define DX_NO_BUILTIN __attribute__((no_builtin("memset", "memcpy", "memcmp", "memmove")))

static DX_NO_BUILTIN inline void dx_memzero(void* p, SIZE_T n)
{
    BYTE* d = (BYTE*)p;
    for (SIZE_T i = 0; i < n; ++i)
        d[i] = 0;
}

static DX_NO_BUILTIN inline void dx_memset(void* p, int v, SIZE_T n)
{
    BYTE* d = (BYTE*)p;
    for (SIZE_T i = 0; i < n; ++i)
        d[i] = (BYTE)v;
}

static DX_NO_BUILTIN inline void dx_memcpy(void* dst, const void* src, SIZE_T n)
{
    BYTE* d = (BYTE*)dst;
    const BYTE* s = (const BYTE*)src;
    for (SIZE_T i = 0; i < n; ++i)
        d[i] = s[i];
}

static DX_NO_BUILTIN inline int dx_guid_eq(const DxGuid* a, const DxGuid* b)
{
    if (!a || !b)
        return 0;
    const BYTE* x = (const BYTE*)a;
    const BYTE* y = (const BYTE*)b;
    for (int i = 0; i < 16; ++i)
        if (x[i] != y[i])
            return 0;
    return 1;
}

/* IUnknown's IID — every COM interface must respond to this in
 * QueryInterface. Value: {00000000-0000-0000-C000-000000000046}. */
static const DxGuid kIID_IUnknown = {0x00000000, 0x0000, 0x0000, {0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}};

/* ---------------------------------------------------------------- *
 * Native syscall wrappers                                          *
 *                                                                  *
 * DuetOS native syscall ABI:                                       *
 *   int 0x80                                                       *
 *   rax = number, rdi/rsi/rdx/r10/r8/r9 = args                     *
 *   rax = return                                                   *
 *                                                                  *
 * MSVC x64 calling convention (this DLL's ABI) → translation       *
 * happens in the inline asm constraint string.                     *
 * ---------------------------------------------------------------- */

/* SYS_HEAP_ALLOC = 11 */
static inline void* dx_heap_alloc(SIZE_T n)
{
    long long rv;
    __asm__ volatile("int $0x80" : "=a"(rv) : "a"((long long)11), "D"((long long)n) : "memory");
    return (void*)rv;
}

/* SYS_HEAP_FREE = 12 */
static inline void dx_heap_free(void* p)
{
    long long discard;
    __asm__ volatile("int $0x80"
                     : "=a"(discard)
                     : "a"((long long)12), "D"((long long)(unsigned long long)p)
                     : "memory");
    (void)discard;
}

/* SYS_DEBUG_PRINT = 46 — short trace string. */
static inline void dx_dbg(const char* s)
{
    long long discard;
    __asm__ volatile("int $0x80"
                     : "=a"(discard)
                     : "a"((long long)46), "D"((long long)(unsigned long long)s)
                     : "memory");
    (void)discard;
}

/* SYS_GFX_D3D_STUB = 101 — bumps the graphics ICD's per-API
 * counter so the `gfx` shell command can see how many times this
 * DLL was entered. kind: 1=D3D11, 2=D3D12, 3=DXGI, 4=D3D9. */
static inline void dx_gfx_trace(int kind)
{
    long long discard;
    __asm__ volatile("int $0x80" : "=a"(discard) : "a"((long long)101), "D"((long long)kind) : "memory");
    (void)discard;
}

/* SYS_WIN_GET_RECT = 70 — read window geometry into a user RECT
 * { i32 left, top, right, bottom }. Returns 1 on success. */
typedef struct DxRect
{
    LONG left, top, right, bottom;
} DxRect;

static inline int dx_win_get_rect(HWND hwnd, DxRect* out)
{
    long long rv;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"((long long)70), "D"((long long)(unsigned long long)hwnd),
                       "S"((long long)(unsigned long long)out)
                     : "memory");
    return (int)rv;
}

/* SYS_GDI_BITBLT = 102 — push BGRA8 pixel buffer onto a window's
 * compositor display list. Pixels are copied in immediately. */
static inline int dx_gdi_bitblt(HWND hwnd, int dst_x, int dst_y, int w, int h, const void* px)
{
    register long long r10 __asm__("r10") = (long long)w;
    register long long r8 __asm__("r8") = (long long)h;
    register long long r9 __asm__("r9") = (long long)(unsigned long long)px;
    long long rv;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"((long long)102), "D"((long long)(unsigned long long)hwnd), "S"((long long)dst_x),
                       "d"((long long)dst_y), "r"(r10), "r"(r8), "r"(r9)
                     : "memory");
    return (int)rv;
}

/* ---------------------------------------------------------------- *
 * Cold-vtable stubs                                                *
 *                                                                  *
 * COM vtables are dense arrays of function pointers. Many real DX  *
 * methods we don't yet implement still need a slot filled — apps  *
 * crash if they call into a NULL slot. These three stubs cover    *
 * every return type in the DX surface: HRESULT, UINT, void.       *
 *                                                                  *
 * The MSVC x64 ABI puts `this` in rcx and ignores extra slots, so *
 * a `(void* self)` stub safely binds to any vtable slot of its    *
 * return type (caller args land in rdx/r8/r9 and on the stack and *
 * are simply unread).                                             *
 * ---------------------------------------------------------------- */

__attribute__((used)) static HRESULT dx_stub_hresult(void* self)
{
    (void)self;
    return DX_E_NOTIMPL;
}

__attribute__((used)) static unsigned int dx_stub_uint(void* self)
{
    (void)self;
    return 0;
}

__attribute__((used)) static void dx_stub_void(void* self)
{
    (void)self;
}

/* Cast helpers — keep the vtable initializers compact. */
#define DX_HSTUB ((void*)dx_stub_hresult)
#define DX_USTUB ((void*)dx_stub_uint)
#define DX_VSTUB ((void*)dx_stub_void)

/* ---------------------------------------------------------------- *
 * Shared back-buffer descriptor                                    *
 *                                                                  *
 * Allocated by every swap chain (across all four DLLs). The owner *
 * passes this struct around internally and Present BitBlts the    *
 * BGRA8 pixels to the owning HWND.                                *
 * ---------------------------------------------------------------- */

typedef struct DxBackBuffer
{
    UINT width;
    UINT height;
    UINT pitch_bytes;  /* width * 4 */
    UINT buffer_bytes; /* width * height * 4 */
    BYTE* pixels;      /* BGRA8 row-major */
    HWND hwnd;         /* present target; may be NULL for offscreen */
} DxBackBuffer;

static inline DxBackBuffer* dx_bb_create(HWND hwnd, UINT w, UINT h)
{
    if (w == 0 || h == 0)
        return NULL;
    DxBackBuffer* bb = (DxBackBuffer*)dx_heap_alloc(sizeof(DxBackBuffer));
    if (!bb)
        return NULL;
    dx_memzero(bb, sizeof(*bb));
    bb->width = w;
    bb->height = h;
    bb->pitch_bytes = w * 4;
    bb->buffer_bytes = w * h * 4;
    bb->pixels = (BYTE*)dx_heap_alloc(bb->buffer_bytes);
    if (!bb->pixels)
    {
        dx_heap_free(bb);
        return NULL;
    }
    dx_memzero(bb->pixels, bb->buffer_bytes);
    bb->hwnd = hwnd;
    return bb;
}

static inline void dx_bb_destroy(DxBackBuffer* bb)
{
    if (!bb)
        return;
    if (bb->pixels)
        dx_heap_free(bb->pixels);
    dx_heap_free(bb);
}

/* Fill the entire back buffer with a 32-bit BGRA colour. */
static inline void dx_bb_clear_rgba(DxBackBuffer* bb, float r, float g, float b, float a)
{
    if (!bb || !bb->pixels)
        return;
    /* clamp + 0..255 quantize */
    if (r < 0.f)
        r = 0.f;
    else if (r > 1.f)
        r = 1.f;
    if (g < 0.f)
        g = 0.f;
    else if (g > 1.f)
        g = 1.f;
    if (b < 0.f)
        b = 0.f;
    else if (b > 1.f)
        b = 1.f;
    if (a < 0.f)
        a = 0.f;
    else if (a > 1.f)
        a = 1.f;
    BYTE br = (BYTE)(r * 255.f);
    BYTE bg = (BYTE)(g * 255.f);
    BYTE bb_ = (BYTE)(b * 255.f);
    BYTE ba = (BYTE)(a * 255.f);
    DWORD packed = ((DWORD)ba << 24) | ((DWORD)br << 16) | ((DWORD)bg << 8) | (DWORD)bb_;
    DWORD* p = (DWORD*)bb->pixels;
    UINT count = bb->width * bb->height;
    for (UINT i = 0; i < count; ++i)
        p[i] = packed;
}

/* Push back buffer to its owning HWND. Returns 1 on success.
 * No-op (returns 1) when hwnd is NULL — offscreen Present is a
 * legitimate use-case (compute-only D3D12 jobs, etc.). */
static inline int dx_bb_present(const DxBackBuffer* bb)
{
    if (!bb || !bb->pixels)
        return 0;
    if (!bb->hwnd)
        return 1;
    /* If the window has resized, our buffer is the wrong size;
     * crop to what fits. SYS_GDI_BITBLT will reject anything
     * larger than kWinBlitMaxPx so we additionally clamp. */
    DxRect r;
    dx_memzero(&r, sizeof(r));
    int w = (int)bb->width, h = (int)bb->height;
    if (dx_win_get_rect(bb->hwnd, &r))
    {
        int cw = r.right - r.left;
        int ch = r.bottom - r.top;
        if (cw > 0 && cw < w)
            w = cw;
        if (ch > 0 && ch < h)
            h = ch;
    }
    return dx_gdi_bitblt(bb->hwnd, 0, 0, w, h, bb->pixels);
}

#endif /* DUETOS_DX_SHARED_H */
