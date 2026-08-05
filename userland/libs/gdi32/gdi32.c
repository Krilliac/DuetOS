/*
 * userland/libs/gdi32/gdi32.c — GDI surface for PE callers.
 *
 * Two HDC flavours coexist:
 *   - "Window DC" (returned by GetDC / GetWindowDC): the HDC bit-
 *     packs the HWND with GDI_TAG so later GDI calls can recover
 *     the target window. Draws on a window DC route through
 *     SYS_GDI_FILL_RECT / SYS_GDI_TEXT_OUT / SYS_GDI_RECTANGLE etc.
 *     to the kernel compositor's per-window display list.
 *   - "Memory DC" (returned by CreateCompatibleDC): the HDC is the
 *     bare kernel-allocated MemDC handle from
 *     `kernel/subsystems/win32/gdi_objects.cpp`. The matching
 *     bitmap (allocated by CreateCompatibleBitmap) attaches via
 *     SelectObject; BitBlt copies pixels mem→mem or mem→window
 *     through SYS_GDI_BITBLT_DC.
 *
 * COLORREF on the Win32 side is 0x00BBGGRR; the kernel repacks to
 * 0x00RRGGBB before framebuffer writes, so we pass the user's value
 * through verbatim.
 */

typedef int BOOL;
typedef unsigned int UINT;
typedef int INT;
typedef unsigned int DWORD;
typedef unsigned int COLORREF;
typedef void* HDC;
typedef void* HGDIOBJ;
typedef void* HBITMAP;
typedef void* HBRUSH;
typedef void* HFONT;
typedef void* HPEN;
typedef void* HANDLE;
typedef unsigned short wchar_t16;

typedef struct
{
    INT left, top, right, bottom;
} RECT;

#define SYS_GDI_FILL_RECT 65
#define SYS_GDI_TEXT_OUT 66
#define SYS_GDI_RECTANGLE 67
#define SYS_GDI_CLEAR 68
#define SYS_GDI_SET_TEXT_COLOR 114
#define SYS_GDI_SET_BK_COLOR 115
#define SYS_GDI_SET_BK_MODE 116
#define SYS_GDI_LINE 74
#define SYS_GDI_ELLIPSE 75
#define SYS_GDI_SET_PIXEL 76
#define SYS_GDI_DRAW_TEXT_W 126
/* Memory-DC + bitmap-backed object surface — backed by per-process
 * MemDC / Bitmap tables in `kernel/subsystems/win32/gdi_objects.cpp`.
 * The DC + bitmap handles returned by these calls live in the kernel
 * for the lifetime of the process; subsequent SelectObject /
 * BitBlt / DeleteDC / DeleteObject calls dispatch against those
 * tables. */
#define SYS_GDI_CREATE_COMPAT_DC 106
#define SYS_GDI_CREATE_COMPAT_BITMAP 107
#define SYS_GDI_SELECT_OBJECT 110
#define SYS_GDI_DELETE_DC 111
#define SYS_GDI_DELETE_OBJECT 112
#define SYS_GDI_BITBLT_DC 113
#define SYS_GDI_STRETCH_BLT_DC 117
#define SYS_GDI_CREATE_SOLID_BRUSH 108
#define SYS_GDI_CREATE_PEN 118
#define SYS_GDI_CREATE_FONT 225
#define SYS_GDI_GET_TEXT_METRICS 226
/* Pixel-DATA transfer (as opposed to draw commands). Six register
 * arguments, no struct — see kernel/subsystems/win32/gdi_dib.cpp. */
#define SYS_GDI_SET_DIBITS 214
#define SYS_GDI_GET_DIBITS 215
/* DIB sections need a user-visible pixel buffer of their own. */
#define SYS_VIRTUAL_ALLOC 199
#define SYS_VIRTUAL_FREE 200
#define GDI_MEM_COMMIT 0x1000u
#define GDI_MEM_RESERVE 0x2000u
#define GDI_MEM_RELEASE 0x8000u
#define GDI_PAGE_READWRITE 0x04u

static long long gdi32_syscall1(long n, long long a)
{
    long long rv;
    __asm__ volatile("int $0x80" : "=a"(rv) : "a"((long long)n), "D"(a) : "memory");
    return rv;
}

static long long gdi32_syscall2(long n, long long a, long long b)
{
    long long rv;
    __asm__ volatile("int $0x80" : "=a"(rv) : "a"((long long)n), "D"(a), "S"(b) : "memory");
    return rv;
}

static long long gdi32_syscall3(long n, long long a, long long b, long long c)
{
    long long rv;
    __asm__ volatile("int $0x80" : "=a"(rv) : "a"((long long)n), "D"(a), "S"(b), "d"(c) : "memory");
    return rv;
}

static long long gdi32_syscall4(long n, long long a, long long b, long long c, long long d)
{
    long long rv;
    register long long r10 __asm__("r10") = d;
    __asm__ volatile("int $0x80" : "=a"(rv) : "a"((long long)n), "D"(a), "S"(b), "d"(c), "r"(r10) : "memory");
    return rv;
}

static long long gdi32_syscall6(long n, long long a, long long b, long long c, long long d, long long e, long long f)
{
    long long rv;
    register long long r10 __asm__("r10") = d;
    register long long r8 __asm__("r8") = e;
    register long long r9 __asm__("r9") = f;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"((long long)n), "D"(a), "S"(b), "d"(c), "r"(r10), "r"(r8), "r"(r9)
                     : "memory");
    return rv;
}

/* Encode the HWND inside the HDC pointer so later GDI calls can
 * recover it. Bit layout: HDC == (HWND | GDI_TAG). GDI_TAG keeps
 * the pointer obviously-non-null (Win32 callers null-check HDCs)
 * and distinguishable from a real memory address. */
#define GDI_TAG 0xDC00000000ULL

static HDC gdi32_hdc_from_hwnd(HANDLE hWnd)
{
    return (HDC)((unsigned long long)hWnd | GDI_TAG);
}

static HANDLE gdi32_hwnd_from_hdc(HDC dc)
{
    unsigned long long v = (unsigned long long)dc;
    if ((v & GDI_TAG) != GDI_TAG)
        return (HANDLE)0;
    return (HANDLE)(v & ~GDI_TAG);
}

/* --- DC clip state (forward declarations) ------------------------
 *
 * The clip engine (per-DC clip-region pool + the SelectClipRgn /
 * ExtSelectClipRgn / IntersectClipRect / ExcludeClipRect family) is
 * defined with the Region API at the end of this file; the draw
 * wrappers above it consult these three helpers. All return "draw
 * everything" answers when the DC has no clip region set. */
static int gdi32_clip_pt_visible(HDC dc, INT x, INT y);
static int gdi32_clip_rect_visible(HDC dc, INT l, INT t, INT r, INT b);
/* Intersect [l,t,r,b) with the DC clip. Returns the piece count
 * written to `out`, or -1 when the DC has no clip (caller draws the
 * original rect unclipped). */
static int gdi32_clip_fill_pieces(HDC dc, INT l, INT t, INT r, INT b, RECT* out, int cap);
static void gdi32_clip_release(HDC dc);

/* --- ROP2 shadow -------------------------------------------------
 *
 * The kernel stores a per-DC rop2 for memory-DC drawing
 * (SYS_GDI_SET_ROP2); this user-side shadow answers GetROP2 and
 * drives the window-DC colour transform below. Module-global like
 * g_bk_mode — same single-DC-at-a-time limitation. */
#define GDI32_R2_BLACK 1
#define GDI32_R2_NOT 6
#define GDI32_R2_XORPEN 7
#define GDI32_R2_COPYPEN 13
#define GDI32_R2_WHITE 16

static INT g_rop2 = GDI32_R2_COPYPEN;

/* Window-DC drawing goes through the compositor display list, which
 * carries a colour but no raster op — so the only ROP2 modes a
 * window DC can honour are the ones expressible as a colour:
 * R2_BLACK and R2_WHITE.
 * GAP: R2_NOT / R2_XORPEN on a window DC draw with the pen colour
 * (no destination read-back path) — memory-DC drawing honours them
 * in the kernel. */
static COLORREF gdi32_rop2_colour(COLORREF c)
{
    if (g_rop2 == GDI32_R2_BLACK)
        return 0x00000000;
    if (g_rop2 == GDI32_R2_WHITE)
        return 0x00FFFFFF;
    return c;
}

/* --- DC management --- */
__declspec(dllexport) HDC GetDC(HANDLE hWnd)
{
    return gdi32_hdc_from_hwnd(hWnd);
}
__declspec(dllexport) HDC GetWindowDC(HANDLE hWnd)
{
    return gdi32_hdc_from_hwnd(hWnd);
}
__declspec(dllexport) INT ReleaseDC(HANDLE hWnd, HDC dc)
{
    (void)hWnd;
    /* Common-DC semantics: attributes (incl. the clip region) reset
     * between GetDC / ReleaseDC pairs. */
    gdi32_clip_release(dc);
    return 1;
}
/* CreateCompatibleDC — allocates a kernel-side MemDC (no pixel
 * backing yet; that arrives via SelectObject of a compatible
 * bitmap). The returned HDC is the bare kernel handle (NOT
 * GDI_TAG-wrapped) so gdi32_hwnd_from_hdc returns 0 — the
 * draw-into-window helpers correctly reject it, while
 * BitBlt / SelectObject / DeleteDC look it up against the
 * kernel MemDC table directly. */
__declspec(dllexport) HDC CreateCompatibleDC(HDC dc)
{
    long long hdc = gdi32_syscall1(SYS_GDI_CREATE_COMPAT_DC, (long long)(unsigned long long)dc);
    return (HDC)(unsigned long long)hdc;
}
__declspec(dllexport) BOOL DeleteDC(HDC dc)
{
    if (dc == (HDC)0)
        return 0;
    /* A recycled kernel DC handle must not inherit this DC's clip. */
    gdi32_clip_release(dc);
    /* GDI_TAG-wrapped HDCs (window DCs) are not kernel-tracked;
     * succeed silently. Real memory DCs get released. */
    if (((unsigned long long)dc & GDI_TAG) == GDI_TAG)
        return 1;
    return gdi32_syscall1(SYS_GDI_DELETE_DC, (long long)(unsigned long long)dc) ? 1 : 0;
}
__declspec(dllexport) INT SaveDC(HDC dc)
{
    (void)dc;
    return 1;
}
__declspec(dllexport) BOOL RestoreDC(HDC dc, INT saved)
{
    (void)dc;
    (void)saved;
    return 1;
}

/* --- Object creation --- */

/* Brush colour side table.
 *
 * A kernel brush handle is an opaque index — the colour lives in the
 * kernel and there is no query syscall — but the window-DC fill paths
 * (FillRect / FrameRect) need the COLORREF on the user side, because
 * they pass a colour rather than a brush to the compositor. So each
 * kernel-backed brush records its colour here at creation.
 *
 * Sized to match the kernel's per-process brush ceiling, so a caller
 * that can get a kernel brush can always record it. */
#define GDI32_MAX_BRUSHES 16

typedef struct
{
    HBRUSH h; /* 0 == free slot */
    COLORREF c;
} GDI32_BRUSHCOLOUR;

static GDI32_BRUSHCOLOUR g_brush_colours[GDI32_MAX_BRUSHES];

static int gdi32_brush_remember(HBRUSH h, COLORREF c)
{
    int i;
    if (!h)
        return 0;
    for (i = 0; i < GDI32_MAX_BRUSHES; ++i)
    {
        if (!g_brush_colours[i].h)
        {
            g_brush_colours[i].h = h;
            g_brush_colours[i].c = c;
            return 1;
        }
    }
    return 0;
}

static int gdi32_brush_lookup(HBRUSH h, COLORREF* out)
{
    int i;
    if (!h)
        return 0;
    for (i = 0; i < GDI32_MAX_BRUSHES; ++i)
    {
        if (g_brush_colours[i].h == h)
        {
            *out = g_brush_colours[i].c;
            return 1;
        }
    }
    return 0;
}

__declspec(dllexport) HBRUSH CreateSolidBrush(COLORREF clr);

static void gdi32_brush_forget(HBRUSH h)
{
    int i;
    for (i = 0; i < GDI32_MAX_BRUSHES; ++i)
    {
        if (g_brush_colours[i].h == h)
        {
            g_brush_colours[i].h = (HBRUSH)0;
            g_brush_colours[i].c = 0;
            return;
        }
    }
}

/* --- DIB support -------------------------------------------------
 *
 * A kernel surface is 32bpp BGRA and knows nothing about DIB layout;
 * SYS_GDI_SET_DIBITS / SYS_GDI_GET_DIBITS do the conversion. What
 * lives here is the Win32-shaped scaffolding around them: reading a
 * BITMAPINFOHEADER, computing the DWORD-padded stride the caller's
 * buffer actually uses, and — for CreateDIBSection — owning the
 * user-visible pixel buffer the caller writes into directly.
 *
 * Field offsets of BITMAPINFOHEADER (all little-endian, 40 bytes):
 *   0 biSize(u32) 4 biWidth(i32) 8 biHeight(i32) 12 biPlanes(u16)
 *   14 biBitCount(u16) 16 biCompression(u32) ...
 * Read byte-wise rather than through a struct: the caller's buffer
 * has no alignment guarantee, and the layout is identical on i386
 * and x86_64 so there is no struct-shape divergence to get wrong. */

static unsigned gdi32_rd32(const unsigned char* p)
{
    return (unsigned)p[0] | ((unsigned)p[1] << 8) | ((unsigned)p[2] << 16) | ((unsigned)p[3] << 24);
}
static unsigned gdi32_rd16(const unsigned char* p)
{
    return (unsigned)p[0] | ((unsigned)p[1] << 8);
}

/* Rows pad up to a 4-byte boundary. This is the calculation that
 * gets written as `w * bpp / 8` and then shears every 24bpp image. */
static unsigned gdi32_dib_stride(int w, unsigned bpp)
{
    if (w <= 0 || (bpp != 16 && bpp != 24 && bpp != 32))
        return 0;
    return (unsigned)((((long long)w * (long long)bpp + 31) / 32) * 4);
}

/* Pull width / height / bpp out of a BITMAPINFOHEADER. Returns 0 if
 * the header is absent, too small, or describes a format the kernel
 * side will refuse anyway. `out_h` keeps its SIGN — negative means a
 * top-down DIB and the kernel needs that, not its magnitude. */
static int gdi32_dib_header(const void* bi, int* out_w, int* out_h, unsigned* out_bpp)
{
    const unsigned char* p = (const unsigned char*)bi;
    if (!p)
        return 0;
    if (gdi32_rd32(p) < 40)
        return 0; /* BITMAPCOREHEADER (12 bytes) is not supported */
    const int w = (int)gdi32_rd32(p + 4);
    const int h = (int)gdi32_rd32(p + 8);
    const unsigned bpp = gdi32_rd16(p + 14);
    if (w <= 0 || h == 0)
        return 0;
    if (bpp != 16 && bpp != 24 && bpp != 32)
        return 0;
    *out_w = w;
    *out_h = h;
    *out_bpp = bpp;
    return 1;
}

/* Row count, independent of origin. h == INT_MIN is filtered by the
 * caller's header check (h == 0 is the only rejected magnitude, and
 * INT_MIN survives it) so negate in 64-bit. */
static int gdi32_dib_rows(int h)
{
    long long v = (long long)h;
    return (int)(v < 0 ? -v : v);
}

/* Upload `bits` into kernel bitmap `bmp`. Returns the number of
 * scanlines actually transferred, which is NOT always the number
 * requested: if the caller's buffer ends before the header says it
 * should, the kernel stops at the edge of the mapping rather than
 * reading on, and the short count is how the caller finds out. */
static int gdi32_push_dibits(HBITMAP bmp, const void* bits, int w, int h, unsigned bpp)
{
    unsigned stride = gdi32_dib_stride(w, bpp);
    unsigned long long bytes;
    if (!bmp || !bits || !stride)
        return 0;
    bytes = (unsigned long long)stride * (unsigned long long)gdi32_dib_rows(h);
    return (int)gdi32_syscall6(SYS_GDI_SET_DIBITS, (long long)(unsigned long long)bmp,
                               (long long)(unsigned long long)bits, (long long)w, (long long)h, (long long)bpp,
                               (long long)bytes);
}

/* DIB sections the process owns. A section's defining property is
 * that the CALLER writes pixels straight into `bits` with no GDI call
 * in between, so the kernel surface cannot be kept in sync as it
 * happens — the bits are pushed down on the next BitBlt / StretchBlt
 * that reads the section (see gdi32_flush_dibsections).
 *
 * Fixed table rather than a heap: this DLL is freestanding, and 16
 * live sections is already more than a v0 Win32 app opens. */
#define GDI32_MAX_DIBSECTIONS 16

typedef struct
{
    HBITMAP bmp; /* kernel surface handle; 0 == free slot */
    void* bits;  /* user-visible pixel buffer (SYS_VIRTUAL_ALLOC) */
    unsigned long res_bytes;
    int w;
    int h; /* signed: keeps the origin convention */
    unsigned bpp;
} GDI32_DIBSECTION;

static GDI32_DIBSECTION g_dibsections[GDI32_MAX_DIBSECTIONS];

static GDI32_DIBSECTION* gdi32_find_dibsection(HBITMAP bmp)
{
    int i;
    if (!bmp)
        return 0;
    for (i = 0; i < GDI32_MAX_DIBSECTIONS; ++i)
    {
        if (g_dibsections[i].bmp == bmp)
            return &g_dibsections[i];
    }
    return 0;
}

/* Push every live section's user bits into its kernel surface.
 * Called before a blit because that is the first moment the kernel
 * has to agree with what the caller drew. Sections the caller never
 * touched are re-pushed too — cheap next to the blit itself, and it
 * avoids a dirty-tracking scheme that would need a page-fault hook
 * this DLL has no way to install. */
static void gdi32_flush_dibsections(void)
{
    int i;
    for (i = 0; i < GDI32_MAX_DIBSECTIONS; ++i)
    {
        GDI32_DIBSECTION* s = &g_dibsections[i];
        if (s->bmp && s->bits)
            (void)gdi32_push_dibits(s->bmp, s->bits, s->w, s->h, s->bpp);
    }
}

/* Release a DIB section's slot + user buffer. Returns 1 if `bmp` was
 * a section (the kernel surface still needs deleting by the caller). */
static int gdi32_release_dibsection(HBITMAP bmp)
{
    GDI32_DIBSECTION* s = gdi32_find_dibsection(bmp);
    if (!s)
        return 0;
    if (s->bits)
    {
        (void)gdi32_syscall3(SYS_VIRTUAL_FREE, (long long)(unsigned long long)s->bits, 0, (long long)GDI_MEM_RELEASE);
    }
    s->bmp = (HBITMAP)0;
    s->bits = (void*)0;
    s->res_bytes = 0;
    s->w = 0;
    s->h = 0;
    s->bpp = 0;
    return 1;
}

__declspec(dllexport) HBITMAP CreateCompatibleBitmap(HDC dc, INT w, INT h)
{
    if (w <= 0 || h <= 0)
        return (HBITMAP)0;
    long long hbmp =
        gdi32_syscall3(SYS_GDI_CREATE_COMPAT_BITMAP, (long long)(unsigned long long)dc, (long long)w, (long long)h);
    return (HBITMAP)(unsigned long long)hbmp;
}

/* CreateBitmap — allocate a surface and, when the caller supplies
 * them, seed it with `bits`.
 *
 * Win32 CreateBitmap takes a DDB, whose scanlines are WORD-aligned
 * and top-down, not the DWORD-aligned bottom-up DIB layout. The
 * kernel transfer speaks DIB, so a top-down height is passed (a
 * negative value) and only the depths whose WORD and DWORD alignment
 * coincide are accepted.
 * GAP: 32bpp initial bits only; a 24bpp DDB's WORD-aligned rows do
 * not match the DIB stride the kernel assumes — revisit when a PE
 * ships one. A NULL `bits` (the common "give me a scratch surface"
 * call) works at any depth because nothing is read. */
__declspec(dllexport) HBITMAP CreateBitmap(INT w, INT h, UINT planes, UINT bits_per_pel, const void* bits)
{
    HBITMAP bmp;
    if (w <= 0 || h <= 0 || planes != 1)
        return (HBITMAP)0;
    bmp = CreateCompatibleBitmap((HDC)0, w, h);
    if (!bmp)
        return (HBITMAP)0;
    if (bits && bits_per_pel == 32)
    {
        /* Negative height: a DDB's first scanline is its top one. */
        (void)gdi32_push_dibits(bmp, bits, w, -h, 32);
    }
    return bmp;
}

/* CreateDIBSection — a surface whose pixels the caller writes to
 * directly. The user-side buffer is a real committed mapping, so a
 * caller that memsets it or draws into it with its own code works;
 * the kernel surface picks the bytes up on the next blit.
 *
 * GAP: `section` / `offset` (backing a DIB with a file mapping) are
 * ignored — revisit when a PE passes a non-NULL section. */
__declspec(dllexport) HBITMAP CreateDIBSection(HDC dc, const void* bi, UINT usage, void** bits, HANDLE section,
                                               DWORD offset)
{
    int w = 0, h = 0, i;
    unsigned bpp = 0, stride;
    unsigned long long need;
    long long base;
    HBITMAP bmp;
    GDI32_DIBSECTION* slot = 0;

    (void)dc;
    (void)usage;
    (void)section;
    (void)offset;
    if (bits)
        *bits = (void*)0;
    if (!gdi32_dib_header(bi, &w, &h, &bpp))
        return (HBITMAP)0;
    stride = gdi32_dib_stride(w, bpp);
    if (!stride)
        return (HBITMAP)0;
    need = (unsigned long long)stride * (unsigned long long)gdi32_dib_rows(h);

    for (i = 0; i < GDI32_MAX_DIBSECTIONS; ++i)
    {
        if (!g_dibsections[i].bmp)
        {
            slot = &g_dibsections[i];
            break;
        }
    }
    if (!slot)
        return (HBITMAP)0;

    bmp = CreateCompatibleBitmap((HDC)0, w, gdi32_dib_rows(h));
    if (!bmp)
        return (HBITMAP)0;

    base = gdi32_syscall4(SYS_VIRTUAL_ALLOC, (long long)need, (long long)(GDI_MEM_RESERVE | GDI_MEM_COMMIT),
                          (long long)GDI_PAGE_READWRITE, 0);
    if (!base)
    {
        (void)gdi32_syscall1(SYS_GDI_DELETE_OBJECT, (long long)(unsigned long long)bmp);
        return (HBITMAP)0;
    }

    slot->bmp = bmp;
    slot->bits = (void*)(unsigned long long)base;
    slot->res_bytes = (unsigned long)need;
    slot->w = w;
    slot->h = h;
    slot->bpp = bpp;
    if (bits)
        *bits = slot->bits;
    return bmp;
}

/* CreateDIBitmap — a compatible surface seeded from a DIB. Unlike
 * CreateDIBSection the caller gets no pointer back, so this is a
 * one-shot upload. CBM_INIT (0x04) selects "copy the bits"; without
 * it the surface is simply left zeroed. */
__declspec(dllexport) HBITMAP CreateDIBitmap(HDC dc, const void* header, DWORD init, const void* bits, const void* bi,
                                             UINT usage)
{
    int w = 0, h = 0;
    unsigned bpp = 0;
    HBITMAP bmp;

    (void)dc;
    (void)bi;
    (void)usage;
    if (!gdi32_dib_header(header, &w, &h, &bpp))
        return (HBITMAP)0;
    bmp = CreateCompatibleBitmap((HDC)0, w, gdi32_dib_rows(h));
    if (!bmp)
        return (HBITMAP)0;
    if ((init & 0x04u) && bits)
        (void)gdi32_push_dibits(bmp, bits, w, h, bpp);
    return bmp;
}

/* SetDIBits / GetDIBits — the explicit transfer pair.
 *
 * Both return the number of scanlines moved, which is what a caller
 * checks. `start` / `scans` (a partial-band transfer) are honoured
 * only in the degenerate whole-image case.
 * GAP: no partial scanline bands — a call with start != 0 or scans
 * short of the image height is refused rather than transferring the
 * wrong rows. Revisit when a PE streams a DIB in bands. */
__declspec(dllexport) INT SetDIBits(HDC dc, HBITMAP bmp, UINT start, UINT scans, const void* bits, const void* bi,
                                    UINT usage)
{
    int w = 0, h = 0;
    unsigned bpp = 0;

    (void)dc;
    (void)usage;
    if (!bmp || !bits || !gdi32_dib_header(bi, &w, &h, &bpp))
        return 0;
    if (start != 0 || scans != (UINT)gdi32_dib_rows(h))
        return 0;
    /* Report what actually moved, not what was asked for. */
    return (INT)gdi32_push_dibits(bmp, bits, w, h, bpp);
}

__declspec(dllexport) INT GetDIBits(HDC dc, HBITMAP bmp, UINT start, UINT scans, void* bits, void* bi, UINT usage)
{
    int w = 0, h = 0;
    unsigned bpp = 0, stride;
    unsigned long long bytes;
    long long moved;

    (void)dc;
    (void)usage;
    if (!bmp || !gdi32_dib_header(bi, &w, &h, &bpp))
        return 0;
    /* Win32 contract: a NULL `bits` means "just fill in the header",
     * which our caller already supplied in full. Report the height. */
    if (!bits)
        return gdi32_dib_rows(h);
    if (start != 0 || scans != (UINT)gdi32_dib_rows(h))
        return 0;
    stride = gdi32_dib_stride(w, bpp);
    if (!stride)
        return 0;
    bytes = (unsigned long long)stride * (unsigned long long)gdi32_dib_rows(h);
    moved = gdi32_syscall6(SYS_GDI_GET_DIBITS, (long long)(unsigned long long)bmp, (long long)(unsigned long long)bits,
                           (long long)w, (long long)h, (long long)bpp, (long long)bytes);
    return (INT)moved;
}
__declspec(dllexport) HBRUSH CreateBrushIndirect(const void* lb)
{
    if (!lb)
        return (HBRUSH)0;
    /* LOGBRUSH = { UINT style; COLORREF color; ULONG_PTR hatch; } */
    const unsigned* b = (const unsigned*)lb;
    return CreateSolidBrush((COLORREF)b[1]);
}

/* CreateSolidBrush — a REAL kernel brush.
 *
 * This used to hand back a userland sentinel (0xB<COLORREF>) and
 * never call SYS_GDI_CREATE_SOLID_BRUSH, even though the kernel has
 * implemented it all along. The consequence was quiet and total: the
 * kernel could not resolve the sentinel, so SelectObject left the
 * memory DC's brush unset, and every PatBlt / Rectangle / Ellipse
 * into an off-screen surface painted the implicit WHITE_BRUSH
 * regardless of what the app asked for. Nothing returned an error;
 * the pixels were just the wrong colour.
 *
 * The sentinel survives as the fallback, because the window-DC fill
 * paths (FillRect / FrameRect) decode the colour straight out of the
 * handle and must keep working if the kernel brush table is full. */
__declspec(dllexport) HBRUSH CreateSolidBrush(COLORREF clr)
{
    long long h = gdi32_syscall1(SYS_GDI_CREATE_SOLID_BRUSH, (long long)(unsigned long long)clr);
    if (h != 0 && gdi32_brush_remember((HBRUSH)(unsigned long long)h, clr))
        return (HBRUSH)(unsigned long long)h;
    if (h != 0)
    {
        /* Out of side-table slots: releasing the kernel brush keeps
         * the two tables from drifting, and the sentinel still
         * carries the colour for the window-DC paths. */
        (void)gdi32_syscall1(SYS_GDI_DELETE_OBJECT, h);
    }
    return (HBRUSH)(0xB0000000ULL | (unsigned long long)clr);
}
/* CreatePen — a REAL kernel pen. Same story as CreateSolidBrush: the
 * kernel has backed SYS_GDI_CREATE_PEN since it landed, but this
 * returned NULL, so SelectObject had nothing to select and every
 * LineTo / Rectangle outline into a memory DC drew in the implicit
 * BLACK_PEN whatever colour the app chose. */
__declspec(dllexport) HPEN CreatePen(INT style, INT width, COLORREF clr)
{
    long long h =
        gdi32_syscall3(SYS_GDI_CREATE_PEN, (long long)style, (long long)width, (long long)(unsigned long long)clr);
    return (HPEN)(unsigned long long)h;
}
__declspec(dllexport) HFONT CreateFontA(INT h, INT w, INT esc, INT orient, INT weight, DWORD italic, DWORD underline,
                                        DWORD strikeout, DWORD charset, DWORD out_prec, DWORD clip_prec, DWORD quality,
                                        DWORD pitch, const char* face)
{
    (void)w;
    (void)esc;
    (void)orient;
    (void)underline;
    (void)strikeout;
    (void)out_prec;
    (void)clip_prec;
    (void)quality;
    (void)pitch;

    /* Pack the arguments into the struct the kernel expects. */
    struct
    {
        unsigned long long height;
        unsigned long long font_weight;
        unsigned long long is_italic;
        unsigned long long font_charset;
        char face_name[32];
    } args;
    args.height = (unsigned long long)(h < 0 ? -h : h);
    args.font_weight = (unsigned long long)weight;
    args.is_italic = italic ? 1ULL : 0ULL;
    args.font_charset = (unsigned long long)(unsigned char)charset;
    /* Copy face name. */
    int i = 0;
    if (face)
    {
        for (; i < 31 && face[i]; ++i)
            args.face_name[i] = face[i];
    }
    args.face_name[i] = '\0';

    long long result = gdi32_syscall1(SYS_GDI_CREATE_FONT, (long long)(unsigned long long)&args);
    return (HFONT)(unsigned long long)result;
}
__declspec(dllexport) HFONT CreateFontW(INT h, INT w, INT esc, INT orient, INT weight, DWORD italic, DWORD underline,
                                        DWORD strikeout, DWORD charset, DWORD out_prec, DWORD clip_prec, DWORD quality,
                                        DWORD pitch, const wchar_t16* face)
{
    (void)h;
    (void)w;
    (void)esc;
    (void)orient;
    (void)weight;
    (void)italic;
    (void)underline;
    (void)strikeout;
    (void)charset;
    (void)out_prec;
    (void)clip_prec;
    (void)quality;
    (void)pitch;
    (void)face;
    return (HFONT)0;
}
__declspec(dllexport) HFONT CreateFontIndirectA(const void* lf)
{
    (void)lf;
    return (HFONT)0;
}
__declspec(dllexport) HFONT CreateFontIndirectW(const void* lf)
{
    (void)lf;
    return (HFONT)0;
}

__declspec(dllexport) HGDIOBJ GetStockObject(INT idx)
{
    /* Stock objects 0..18. Font indices (13=SYSTEM_FONT,
     * 16=SYSTEM_FIXED_FONT) need a real kernel handle because
     * SelectObject must route them as HFONT. Other indices return
     * a sentinel handle (0xD000 + idx). */
    if (idx < 0 || idx > 18)
        return (HGDIOBJ)0;
    if (idx == 13 || idx == 16)
    {
        long long h = gdi32_syscall1(109 /* SYS_GDI_GET_STOCK_OBJECT */, (long long)idx);
        if (h != 0)
            return (HGDIOBJ)(unsigned long long)h;
    }
    return (HGDIOBJ)(unsigned long long)(0xD000 + idx);
}
__declspec(dllexport) HGDIOBJ SelectObject(HDC dc, HGDIOBJ obj)
{
    if (obj == (HGDIOBJ)0)
        return (HGDIOBJ)0;
    /* GDI_TAG-wrapped HDCs (window DCs) don't have an in-kernel DC
     * table entry for most object types — return a sentinel. But font
     * handles (tag 0x05) must route through the kernel so the per-
     * window DC state records the selection for GetTextMetrics / text
     * drawing. For other types the kernel has no window-DC brush/pen
     * state yet, so we keep the sentinel path. */
    if (((unsigned long long)dc & GDI_TAG) == GDI_TAG)
    {
        unsigned long long obj_val = (unsigned long long)obj;
        if ((obj_val & 0x0F000000ULL) == 0x05000000ULL)
        {
            /* Font handle on a window DC — route through kernel.
             * Pass the raw HWND (strip GDI_TAG) since the kernel's
             * GdiSelectObject expects a plain window handle for the
             * window-DC path. */
            unsigned long long hwnd = (unsigned long long)dc & ~GDI_TAG;
            long long prev = gdi32_syscall3(SYS_GDI_SELECT_OBJECT, (long long)hwnd, (long long)obj_val, 0);
            if (prev == 0)
                return (HGDIOBJ)(unsigned long long)0xD0FFEDULL;
            return (HGDIOBJ)(unsigned long long)prev;
        }
        return (HGDIOBJ)(unsigned long long)0xD0FFEDULL;
    }
    long long prev =
        gdi32_syscall3(SYS_GDI_SELECT_OBJECT, (long long)(unsigned long long)dc, (long long)(unsigned long long)obj, 0);
    if (prev == 0)
        return (HGDIOBJ)(unsigned long long)0xD0FFEDULL;
    return (HGDIOBJ)(unsigned long long)prev;
}
/* Defined with the Region API near the end of the file: frees a
 * user-mode region's pool slot. Returns 1 if `obj` was one of our
 * region handles (so DeleteObject doesn't fall through to the
 * kernel-bitmap branch), 0 otherwise. */
static int gdi32_region_delete(HGDIOBJ obj);

__declspec(dllexport) BOOL DeleteObject(HGDIOBJ obj)
{
    if (obj == (HGDIOBJ)0)
        return 0;
    /* Brushes / pens / stocks — sentinel handles, no kernel state.
     * Brushes carry tag 0xB...; pens / stock objects use small
     * sentinels; only kernel-allocated bitmaps need to be released
     * via the syscall. Treat any handle that isn't obviously a
     * kernel-table handle (i.e. >= 0x100 and not in the brush /
     * stock tag ranges) as a kernel bitmap. */
    unsigned long long v = (unsigned long long)obj;
    if ((v & 0xF0000000ULL) == 0xB0000000ULL)
        return 1; /* brush sentinel */
    if (v < 0x100)
        return 1; /* stock-object sentinel range */
    if (v == 0xD0FFEDULL)
        return 1; /* SelectObject "prev" sentinel */
    if (gdi32_region_delete(obj))
        return 1; /* user-mode region — freed its pool slot */
    /* A DIB section owns a user-side pixel mapping as well as the
     * kernel surface. Release the mapping first, then fall through
     * so the surface itself is deleted exactly once. */
    (void)gdi32_release_dibsection((HBITMAP)obj);
    /* Drop the brush colour record too, so a recycled kernel handle
     * cannot inherit the previous brush's colour. */
    gdi32_brush_forget((HBRUSH)obj);
    return gdi32_syscall1(SYS_GDI_DELETE_OBJECT, (long long)v) ? 1 : 0;
}
__declspec(dllexport) INT GetObjectA(HGDIOBJ obj, INT cb, void* buf)
{
    (void)obj;
    (void)cb;
    (void)buf;
    return 0;
}
__declspec(dllexport) INT GetObjectW(HGDIOBJ obj, INT cb, void* buf)
{
    (void)obj;
    (void)cb;
    (void)buf;
    return 0;
}

/* Recover brush colour from the stub's tag. Returns 0 if the
 * brush is NULL or not our tagged format. */
static COLORREF gdi32_brush_colour(HBRUSH br)
{
    unsigned long long v = (unsigned long long)br;
    COLORREF c;
    /* Kernel-backed brushes carry no colour in the handle, so their
     * COLORREF comes from the side table CreateSolidBrush fills. */
    if (gdi32_brush_lookup(br, &c))
        return c;
    if ((v & 0xF0000000ULL) != 0xB0000000ULL)
        return 0;
    return (COLORREF)(v & 0x00FFFFFFULL);
}

/* Call SYS_GDI_FILL_RECT / SYS_GDI_RECTANGLE. Six args: hwnd, x,
 * y, w, h, colour. r8 / r9 via register vars. */
static BOOL gdi32_rect_core(unsigned num, HANDLE hwnd, INT x, INT y, INT w, INT h, COLORREF colour)
{
    colour = gdi32_rop2_colour(colour);
    register long long r10_w asm("r10") = (long long)w;
    register long long r8_h asm("r8") = (long long)h;
    register long long r9_c asm("r9") = (long long)(unsigned long long)colour;
    long long rv;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"((long long)num), "D"((long long)(unsigned long long)hwnd), "S"((long long)x),
                       "d"((long long)y), "r"(r10_w), "r"(r8_h), "r"(r9_c)
                     : "memory");
    return rv ? 1 : 0;
}

static BOOL gdi32_text_core(HANDLE hwnd, INT x, INT y, const char* text, UINT len, COLORREF colour)
{
    register long long r10_t asm("r10") = (long long)(unsigned long long)text;
    register long long r8_l asm("r8") = (long long)len;
    register long long r9_c asm("r9") = (long long)(unsigned long long)colour;
    long long rv;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"((long long)SYS_GDI_TEXT_OUT), "D"((long long)(unsigned long long)hwnd), "S"((long long)x),
                       "d"((long long)y), "r"(r10_t), "r"(r8_l), "r"(r9_c)
                     : "memory");
    return rv ? 1 : 0;
}

/* --- Draw calls --- */
/* BitBlt — copy a `w x h` block from `src` at (sx,sy) to `dst`
 * at (x,y). The kernel (`DoGdiBitBltDC`) requires the source to
 * be a memory DC with a selected compatible bitmap; the
 * destination can be a memory DC or a window-tagged HDC. The
 * 9-arg form is packed into a contiguous struct on the user
 * stack — Win64 calling convention only passes the first four
 * args in registers, so this is the only sane way to keep all
 * nine on a single syscall.
 *
 * Returns 1 on success, 0 if either DC isn't a kernel-managed
 * memory DC, dimensions are invalid, or the copy is rejected
 * (e.g. source rect out of bitmap bounds, dest blit-pool
 * exceeded). ROP is currently ignored beyond SRCCOPY semantics
 * — every blit is a tight memcpy in BGRA order. */
__declspec(dllexport) BOOL BitBlt(HDC dst, INT x, INT y, INT w, INT h, HDC src, INT sx, INT sy, DWORD rop)
{
    if (w <= 0 || h <= 0)
        return 0;
    /* A DIB section's pixels are written by the caller with no GDI
     * call in between, so this blit is the first point at which the
     * kernel surface can be brought up to date. */
    gdi32_flush_dibsections();
    /* Pack 9 args contiguous on the stack — must match the
     * kernel's `BitBltArgs` struct in
     * `kernel/subsystems/win32/gdi_objects.cpp` (9 x u64). */
    unsigned long long args[9];
    args[0] = (unsigned long long)dst;
    args[1] = (unsigned long long)(unsigned int)x;
    args[2] = (unsigned long long)(unsigned int)y;
    args[3] = (unsigned long long)(unsigned int)w;
    args[4] = (unsigned long long)(unsigned int)h;
    args[5] = (unsigned long long)src;
    args[6] = (unsigned long long)(unsigned int)sx;
    args[7] = (unsigned long long)(unsigned int)sy;
    args[8] = (unsigned long long)rop;
    return gdi32_syscall1(SYS_GDI_BITBLT_DC, (long long)(unsigned long long)args) ? 1 : 0;
}
/* StretchBlt — as BitBlt, with independent source and destination
 * extents. The kernel has implemented this since SYS_GDI_STRETCH_BLT_DC
 * landed; this stub used to return success without calling it, so a
 * caller saw "it worked" and no pixels. Same 11-slot packed-argument
 * shape as the kernel's `StretchBltArgs`. */
__declspec(dllexport) BOOL StretchBlt(HDC dst, INT x, INT y, INT w, INT h, HDC src, INT sx, INT sy, INT sw, INT sh,
                                      DWORD rop)
{
    unsigned long long args[11];
    if (w <= 0 || h <= 0 || sw <= 0 || sh <= 0)
        return 0;
    gdi32_flush_dibsections();
    args[0] = (unsigned long long)dst;
    args[1] = (unsigned long long)(unsigned int)x;
    args[2] = (unsigned long long)(unsigned int)y;
    args[3] = (unsigned long long)(unsigned int)w;
    args[4] = (unsigned long long)(unsigned int)h;
    args[5] = (unsigned long long)src;
    args[6] = (unsigned long long)(unsigned int)sx;
    args[7] = (unsigned long long)(unsigned int)sy;
    args[8] = (unsigned long long)(unsigned int)sw;
    args[9] = (unsigned long long)(unsigned int)sh;
    args[10] = (unsigned long long)rop;
    return gdi32_syscall1(SYS_GDI_STRETCH_BLT_DC, (long long)(unsigned long long)args) ? 1 : 0;
}

/* DrawText — trivial one-line implementation: treats the rect's
 * top-left as the anchor and paints the (NUL-terminated or `len`-
 * bounded) text with the DC's HWND. Ignores alignment flags for
 * v0; callers that want centered text will see left-aligned. */
static unsigned gdi32_strnlen(const char* s, INT len)
{
    unsigned n = 0;
    if (!s)
        return 0;
    while ((len < 0 || (INT)n < len) && s[n] != 0 && n < 4096)
        ++n;
    return n;
}
__declspec(dllexport) INT DrawTextA(HDC dc, const char* text, INT len, void* r, UINT fmt)
{
    (void)fmt;
    if (!r || !text)
        return 0;
    HANDLE hwnd = gdi32_hwnd_from_hdc(dc);
    if (!hwnd)
        return 0;
    RECT* rc = (RECT*)r;
    unsigned n = gdi32_strnlen(text, len);
    /* GAP: text clip is whole-run reject on the 8x8 cell bbox. */
    if (!gdi32_clip_rect_visible(dc, rc->left, rc->top, rc->left + (INT)n * 8, rc->top + 8))
        return 8;
    /* Default text colour is black — real GDI uses the DC's
     * stored text colour; v0 ignores SetTextColor. */
    gdi32_text_core(hwnd, rc->left, rc->top, text, n, 0);
    return 8; /* "glyph height" best-effort — callers use this as a row height */
}
__declspec(dllexport) INT DrawTextW(HDC dc, const wchar_t16* text, INT len, void* r, UINT fmt)
{
    if (!r || !text)
        return 0;
    /* GAP: clip-region text clip is whole-rect reject. */
    {
        const RECT* rc = (const RECT*)r;
        if (!gdi32_clip_rect_visible(dc, rc->left, rc->top, rc->right, rc->bottom))
            return 8; /* nominal row height — nothing drawn */
    }
    /* The kernel handler accepts the HDC directly (memDC tag or
     * window-DC raw handle), copies in `rdx` wchar_ts, downcodes
     * non-ASCII to '?', and applies DT_CENTER / DT_VCENTER /
     * DT_RIGHT / DT_LEFT / DT_TOP / DT_SINGLELINE. Returns the
     * drawn-text pixel height in eax. */
    register long long r10_r asm("r10") = (long long)(unsigned long long)r;
    register long long r8_f asm("r8") = (long long)fmt;
    long long rv;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"((long long)SYS_GDI_DRAW_TEXT_W), "D"((long long)(unsigned long long)dc),
                       "S"((long long)(unsigned long long)text), "d"((long long)len), "r"(r10_r), "r"(r8_f)
                     : "memory");
    return (INT)(rv > 0 ? rv : 0);
}

/* ExtTextOut clip-rect helper. The caller passes a RECT* (4 LONG:
 * left/top/right/bottom) and a flag bitmask. v0 honours ETO_CLIPPED
 * by trimming the (text, x) pair to the visible columns of the rect
 * — kernel-side text drawing has no clip path, so the dispatch in
 * user mode is the actual clip.
 *
 * Returns 1 if there's still text to draw after clipping, 0 if the
 * rect rejected the entire bbox (caller treats that as a successful
 * no-op). On entry *out_x / *out_text / *out_len are the unclipped
 * starting position; on success they're rewritten in place. v0 uses
 * the kernel font's 8x8 cell — see GetTextExtentPoint32A/W which
 * also assumes 8px cells. */
#define ETO_OPAQUE 0x0002u
#define ETO_CLIPPED 0x0004u
#define GDI_FONT_CELL_PX 8

static int gdi32_eto_clip(UINT opts, const void* rect, INT* out_x, INT* y_in, const char** out_text, UINT* out_len)
{
    if (!(opts & ETO_CLIPPED) || !rect)
        return 1;
    const long* r = (const long*)rect;
    const long left = r[0], top = r[1], right = r[2], bottom = r[3];
    /* Bail entirely if the rect is empty / inverted. */
    if (right <= left || bottom <= top)
        return 0;
    /* Vertical reject: text line is one cell tall starting at y. */
    if (*y_in >= bottom || *y_in + GDI_FONT_CELL_PX <= top)
        return 0;
    /* Horizontal: clip leading chars whose right edge falls left of
     * the rect, then trailing chars whose left edge falls past the
     * rect. Both translate to (x, text_offset, len) updates. */
    INT x = *out_x;
    UINT len = *out_len;
    const char* text = *out_text;
    if (x < left)
    {
        const long skip_px = left - x;
        const UINT skip = (UINT)((skip_px + GDI_FONT_CELL_PX - 1) / GDI_FONT_CELL_PX);
        if (skip >= len)
            return 0;
        text += skip;
        len -= skip;
        x += (INT)skip * GDI_FONT_CELL_PX;
    }
    if (x >= right)
        return 0;
    const long room_px = right - x;
    const UINT room_chars = (UINT)(room_px / GDI_FONT_CELL_PX);
    if (room_chars == 0)
        return 0;
    if (len > room_chars)
        len = room_chars;
    *out_x = x;
    *out_text = text;
    *out_len = len;
    return 1;
}

__declspec(dllexport) BOOL ExtTextOutA(HDC dc, INT x, INT y, UINT opts, const void* r, const char* text, UINT len,
                                       const INT* dx)
{
    (void)dx;
    HANDLE hwnd = gdi32_hwnd_from_hdc(dc);
    if (!hwnd)
        return 0;
    /* If the clip rejects the entire string the call still returns
     * TRUE — the contract is "succeeded at drawing nothing", not
     * "failed". */
    if (!gdi32_eto_clip(opts, r, &x, &y, &text, &len))
        return 1;
    /* GAP: clip-region text clip is whole-run reject on the cell bbox. */
    if (!gdi32_clip_rect_visible(dc, x, y, x + (INT)len * GDI_FONT_CELL_PX, y + GDI_FONT_CELL_PX))
        return 1;
    return gdi32_text_core(hwnd, x, y, text, len, 0);
}
__declspec(dllexport) BOOL ExtTextOutW(HDC dc, INT x, INT y, UINT opts, const void* r, const wchar_t16* text, UINT len,
                                       const INT* dx)
{
    (void)dx;
    HANDLE hwnd = gdi32_hwnd_from_hdc(dc);
    if (!hwnd || !text)
        return 0;
    /* Best-effort UTF-16 → ASCII flatten into a 256-char buffer.
     * Long strings are truncated; non-ASCII becomes '?'. */
    char buf[256];
    unsigned n = 0;
    unsigned cap = sizeof(buf) - 1;
    unsigned limit = (len == 0xFFFFFFFFu) ? cap : (len < cap ? len : cap);
    for (; n < limit && text[n] != 0; ++n)
    {
        wchar_t16 c = text[n];
        buf[n] = (c > 0 && c < 0x7F) ? (char)c : '?';
    }
    buf[n] = 0;
    const char* clipped_text = buf;
    UINT clipped_len = n;
    if (!gdi32_eto_clip(opts, r, &x, &y, &clipped_text, &clipped_len))
        return 1;
    /* GAP: clip-region text clip is whole-run reject on the cell bbox. */
    if (!gdi32_clip_rect_visible(dc, x, y, x + (INT)clipped_len * GDI_FONT_CELL_PX, y + GDI_FONT_CELL_PX))
        return 1;
    return gdi32_text_core(hwnd, x, y, clipped_text, clipped_len, 0);
}
__declspec(dllexport) BOOL TextOutA(HDC dc, INT x, INT y, const char* text, INT len)
{
    HANDLE hwnd = gdi32_hwnd_from_hdc(dc);
    if (!hwnd)
        return 0;
    unsigned n = gdi32_strnlen(text, len);
    /* GAP: text clip is whole-run reject on the 8x8 cell bbox. */
    if (!gdi32_clip_rect_visible(dc, x, y, x + (INT)n * GDI_FONT_CELL_PX, y + GDI_FONT_CELL_PX))
        return 1;
    return gdi32_text_core(hwnd, x, y, text, n, 0);
}
__declspec(dllexport) BOOL TextOutW(HDC dc, INT x, INT y, const wchar_t16* text, INT len)
{
    HANDLE hwnd = gdi32_hwnd_from_hdc(dc);
    if (!hwnd || !text)
        return 0;
    char buf[256];
    unsigned cap = sizeof(buf) - 1;
    unsigned limit = (len < 0) ? cap : ((unsigned)len < cap ? (unsigned)len : cap);
    unsigned n = 0;
    for (; n < limit && text[n] != 0; ++n)
    {
        wchar_t16 c = text[n];
        buf[n] = (c > 0 && c < 0x7F) ? (char)c : '?';
    }
    buf[n] = 0;
    /* GAP: text clip is whole-run reject on the 8x8 cell bbox. */
    if (!gdi32_clip_rect_visible(dc, x, y, x + (INT)n * GDI_FONT_CELL_PX, y + GDI_FONT_CELL_PX))
        return 1;
    return gdi32_text_core(hwnd, x, y, buf, n, 0);
}
__declspec(dllexport) INT FillRect(HDC dc, const void* r, HBRUSH br)
{
    HANDLE hwnd = gdi32_hwnd_from_hdc(dc);
    if (!hwnd || !r)
        return 0;
    const RECT* rc = (const RECT*)r;
    INT w = rc->right - rc->left;
    INT h = rc->bottom - rc->top;
    if (w <= 0 || h <= 0)
        return 1;
    COLORREF col = gdi32_brush_colour(br);
    /* Clip enforcement: a fill decomposes exactly — one kernel fill
     * per surviving clip piece. */
    RECT pieces[8];
    int np = gdi32_clip_fill_pieces(dc, rc->left, rc->top, rc->right, rc->bottom, pieces, 8);
    if (np < 0)
        return gdi32_rect_core(SYS_GDI_FILL_RECT, hwnd, rc->left, rc->top, w, h, col) ? 1 : 0;
    for (int i = 0; i < np; ++i)
    {
        (void)gdi32_rect_core(SYS_GDI_FILL_RECT, hwnd, pieces[i].left, pieces[i].top, pieces[i].right - pieces[i].left,
                              pieces[i].bottom - pieces[i].top, col);
    }
    return 1; /* fully clipped out == succeeded at drawing nothing */
}
__declspec(dllexport) INT FrameRect(HDC dc, const void* r, HBRUSH br)
{
    HANDLE hwnd = gdi32_hwnd_from_hdc(dc);
    if (!hwnd || !r)
        return 0;
    const RECT* rc = (const RECT*)r;
    INT w = rc->right - rc->left;
    INT h = rc->bottom - rc->top;
    if (w <= 0 || h <= 0)
        return 1;
    /* GAP: outline clip is whole-shape reject only — a partially
     * clipped frame draws its full outline. */
    if (!gdi32_clip_rect_visible(dc, rc->left, rc->top, rc->right, rc->bottom))
        return 1;
    COLORREF col = gdi32_brush_colour(br);
    return gdi32_rect_core(SYS_GDI_RECTANGLE, hwnd, rc->left, rc->top, w, h, col) ? 1 : 0;
}
/* DC current-point state. Real GDI stores (x, y) per DC; v1
 * uses a single module-global — good enough when programs only
 * paint on one DC at a time. Concurrent DCs share the cursor;
 * documented limitation. */
static INT g_cur_x = 0;
static INT g_cur_y = 0;

typedef struct
{
    INT x;
    INT y;
} POINT;

static BOOL gdi32_line_core(HANDLE hwnd, INT x0, INT y0, INT x1, INT y1, COLORREF col)
{
    col = gdi32_rop2_colour(col);
    register long long r10_x1 asm("r10") = (long long)x1;
    register long long r8_y1 asm("r8") = (long long)y1;
    register long long r9_c asm("r9") = (long long)(unsigned long long)col;
    long long rv;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"((long long)SYS_GDI_LINE), "D"((long long)(unsigned long long)hwnd), "S"((long long)x0),
                       "d"((long long)y0), "r"(r10_x1), "r"(r8_y1), "r"(r9_c)
                     : "memory");
    return rv ? 1 : 0;
}

/* --- Path bookkeeping (BeginPath / EndPath / Stroke / Fill / CloseFigure) ---
 *
 * Real GDI keeps a "path bracket" per DC: between BeginPath and
 * EndPath every drawing primitive that would have painted instead
 * appends to the DC's current path. After EndPath the path is
 * "closed for recording" and StrokePath / FillPath replay it.
 *
 * The DLL is freestanding (no malloc), so the path lives in a
 * small fixed pool of slots keyed by HDC — mirroring the
 * module-global current-point pattern above. Each slot stores a
 * flat point list plus per-subpath start indices (a MoveToEx
 * starts a new subpath). Polyline / Polygon are already line
 * lists, so flattening on record needs no curve handling.
 *
 * GAP: fixed GDI_PATH_SLOTS open paths / GDI_PATH_MAX_PTS points /
 * GDI_PATH_MAX_SUBPATHS subpaths — overflow drops the excess
 * (Stroke/Fill still replay what fit). Revisit if a real PE drives
 * a path larger than this.
 * GAP: no Bezier/arc curve flattening — only the straight-line
 * primitives wired to the recorder (MoveTo/LineTo/Polyline/Polygon)
 * are path-aware; PolyBezier is not.
 */
#define GDI_PATH_SLOTS 4
#define GDI_PATH_MAX_PTS 256
#define GDI_PATH_MAX_SUBPATHS 16

typedef struct
{
    HDC dc;         /* owning DC; 0 == free slot */
    BOOL recording; /* inside BeginPath..EndPath */
    BOOL closed;    /* EndPath seen — ready for Stroke/Fill */
    INT pt_count;   /* points recorded */
    INT sub_count;  /* subpaths recorded */
    INT pts_x[GDI_PATH_MAX_PTS];
    INT pts_y[GDI_PATH_MAX_PTS];
    INT sub_start[GDI_PATH_MAX_SUBPATHS]; /* index into pts_* of each subpath start */
    BOOL sub_closed[GDI_PATH_MAX_SUBPATHS];
} GdiPath;

static GdiPath g_paths[GDI_PATH_SLOTS];

static GdiPath* gdi32_path_find(HDC dc)
{
    for (int i = 0; i < GDI_PATH_SLOTS; ++i)
    {
        if (g_paths[i].dc == dc)
            return &g_paths[i];
    }
    return (GdiPath*)0;
}

/* Return the path slot actively recording for `dc`, or NULL if the
 * DC has no open path bracket. */
static GdiPath* gdi32_path_recording(HDC dc)
{
    GdiPath* p = gdi32_path_find(dc);
    if (p && p->recording)
        return p;
    return (GdiPath*)0;
}

static void gdi32_path_open_subpath(GdiPath* p, INT x, INT y)
{
    if (p->sub_count < GDI_PATH_MAX_SUBPATHS && p->pt_count < GDI_PATH_MAX_PTS)
    {
        p->sub_start[p->sub_count] = p->pt_count;
        p->sub_closed[p->sub_count] = 0;
        ++p->sub_count;
    }
    if (p->pt_count < GDI_PATH_MAX_PTS)
    {
        p->pts_x[p->pt_count] = x;
        p->pts_y[p->pt_count] = y;
        ++p->pt_count;
    }
}

static void gdi32_path_add_point(GdiPath* p, INT x, INT y)
{
    /* A LineTo before any MoveTo opens an implicit subpath at the
     * DC's current point; otherwise extend the current subpath. */
    if (p->sub_count == 0)
    {
        gdi32_path_open_subpath(p, x, y);
        return;
    }
    if (p->pt_count < GDI_PATH_MAX_PTS)
    {
        p->pts_x[p->pt_count] = x;
        p->pts_y[p->pt_count] = y;
        ++p->pt_count;
    }
}

__declspec(dllexport) BOOL MoveToEx(HDC dc, INT x, INT y, void* prev)
{
    if (prev)
    {
        POINT* p = (POINT*)prev;
        p->x = g_cur_x;
        p->y = g_cur_y;
    }
    g_cur_x = x;
    g_cur_y = y;
    /* Inside a path bracket a MoveTo opens a new subpath. */
    GdiPath* path = gdi32_path_recording(dc);
    if (path)
        gdi32_path_open_subpath(path, x, y);
    return 1;
}
__declspec(dllexport) BOOL LineTo(HDC dc, INT x, INT y)
{
    /* Inside a path bracket the segment is recorded, not drawn. */
    GdiPath* path = gdi32_path_recording(dc);
    if (path)
    {
        if (path->sub_count == 0)
            gdi32_path_open_subpath(path, g_cur_x, g_cur_y);
        gdi32_path_add_point(path, x, y);
        g_cur_x = x;
        g_cur_y = y;
        return 1;
    }
    HANDLE hwnd = gdi32_hwnd_from_hdc(dc);
    if (!hwnd)
        return 0;
    /* Clip: skip the draw when the segment's bounding box misses the
     * clip entirely; the current position still advances.
     * GAP: a partially clipped segment draws in full (no span clip). */
    INT bl = g_cur_x < x ? g_cur_x : x;
    INT br2 = g_cur_x > x ? g_cur_x : x;
    INT bt = g_cur_y < y ? g_cur_y : y;
    INT bb = g_cur_y > y ? g_cur_y : y;
    BOOL rv = 1;
    if (gdi32_clip_rect_visible(dc, bl, bt, br2 + 1, bb + 1))
        rv = gdi32_line_core(hwnd, g_cur_x, g_cur_y, x, y, 0);
    g_cur_x = x;
    g_cur_y = y;
    return rv;
}
__declspec(dllexport) BOOL Polyline(HDC dc, const void* pts, INT n)
{
    if (!pts || n < 2)
        return 0;
    const POINT* p = (const POINT*)pts;
    /* Inside a path bracket the run becomes one open subpath. */
    GdiPath* path = gdi32_path_recording(dc);
    if (path)
    {
        gdi32_path_open_subpath(path, p[0].x, p[0].y);
        for (INT i = 1; i < n; ++i)
            gdi32_path_add_point(path, p[i].x, p[i].y);
        g_cur_x = p[n - 1].x;
        g_cur_y = p[n - 1].y;
        return 1;
    }
    HANDLE hwnd = gdi32_hwnd_from_hdc(dc);
    if (!hwnd)
        return 0;
    /* Clip: per-segment bounding-box reject.
     * GAP: partially clipped segments draw in full. */
    for (INT i = 0; i + 1 < n; ++i)
    {
        INT bl = p[i].x < p[i + 1].x ? p[i].x : p[i + 1].x;
        INT br2 = p[i].x > p[i + 1].x ? p[i].x : p[i + 1].x;
        INT bt = p[i].y < p[i + 1].y ? p[i].y : p[i + 1].y;
        INT bb = p[i].y > p[i + 1].y ? p[i].y : p[i + 1].y;
        if (!gdi32_clip_rect_visible(dc, bl, bt, br2 + 1, bb + 1))
            continue;
        (void)gdi32_line_core(hwnd, p[i].x, p[i].y, p[i + 1].x, p[i + 1].y, 0);
    }
    return 1;
}
__declspec(dllexport) BOOL Polygon(HDC dc, const void* pts, INT n)
{
    if (!pts || n < 2)
        return 0;
    const POINT* p = (const POINT*)pts;
    /* Inside a path bracket the polygon becomes one closed subpath. */
    GdiPath* path = gdi32_path_recording(dc);
    if (path)
    {
        gdi32_path_open_subpath(path, p[0].x, p[0].y);
        for (INT i = 1; i < n; ++i)
            gdi32_path_add_point(path, p[i].x, p[i].y);
        if (path->sub_count > 0)
            path->sub_closed[path->sub_count - 1] = 1;
        return 1;
    }
    HANDLE hwnd = gdi32_hwnd_from_hdc(dc);
    if (!hwnd)
        return 0;
    Polyline(dc, pts, n);
    /* Closing edge gets the same per-segment clip reject. */
    INT bl = p[n - 1].x < p[0].x ? p[n - 1].x : p[0].x;
    INT br2 = p[n - 1].x > p[0].x ? p[n - 1].x : p[0].x;
    INT bt = p[n - 1].y < p[0].y ? p[n - 1].y : p[0].y;
    INT bb = p[n - 1].y > p[0].y ? p[n - 1].y : p[0].y;
    if (gdi32_clip_rect_visible(dc, bl, bt, br2 + 1, bb + 1))
        (void)gdi32_line_core(hwnd, p[n - 1].x, p[n - 1].y, p[0].x, p[0].y, 0);
    return 1;
}
/* Win32 Rectangle paints a bordered outline + fills the interior
 * with the currently-selected brush. v0 has no selected-object
 * tracking, so the fill is black and the outline is black. */
__declspec(dllexport) BOOL Rectangle(HDC dc, INT l, INT t, INT r, INT b)
{
    HANDLE hwnd = gdi32_hwnd_from_hdc(dc);
    if (!hwnd)
        return 0;
    INT w = r - l;
    INT h = b - t;
    if (w <= 0 || h <= 0)
        return 1;
    /* GAP: outline clip is whole-shape reject only. */
    if (!gdi32_clip_rect_visible(dc, l, t, r, b))
        return 1;
    return gdi32_rect_core(SYS_GDI_RECTANGLE, hwnd, l, t, w, h, 0);
}
__declspec(dllexport) BOOL Ellipse(HDC dc, INT l, INT t, INT r, INT b)
{
    HANDLE hwnd = gdi32_hwnd_from_hdc(dc);
    if (!hwnd)
        return 0;
    INT w = r - l;
    INT h = b - t;
    if (w <= 0 || h <= 0)
        return 1;
    /* GAP: ellipse clip is whole-shape reject only. */
    if (!gdi32_clip_rect_visible(dc, l, t, r, b))
        return 1;
    return gdi32_rect_core(SYS_GDI_ELLIPSE, hwnd, l, t, w, h, 0);
}

__declspec(dllexport) COLORREF SetPixel(HDC dc, INT x, INT y, COLORREF col)
{
    HANDLE hwnd = gdi32_hwnd_from_hdc(dc);
    if (!hwnd)
        return (COLORREF)-1;
    /* Clip enforcement is exact for single pixels. A clipped-out
     * pixel is a successful no-op. */
    if (!gdi32_clip_pt_visible(dc, x, y))
        return col;
    col = gdi32_rop2_colour(col);
    register long long r10_c asm("r10") = (long long)(unsigned long long)col;
    long long rv;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"((long long)SYS_GDI_SET_PIXEL), "D"((long long)(unsigned long long)hwnd), "S"((long long)x),
                       "d"((long long)y), "r"(r10_c)
                     : "memory");
    return rv ? col : (COLORREF)-1;
}
__declspec(dllexport) BOOL SetPixelV(HDC dc, INT x, INT y, COLORREF col)
{
    return SetPixel(dc, x, y, col) != (COLORREF)-1;
}
__declspec(dllexport) COLORREF GetPixel(HDC dc, INT x, INT y)
{
    (void)dc;
    (void)x;
    (void)y;
    /* No framebuffer read-back syscall in v1 — return CLR_INVALID
     * so callers that check for it take the "couldn't query"
     * path. Most programs use GetPixel for hit-testing which
     * has other paths. */
    return (COLORREF)-1;
}

/* --- DC state setters / getters ---
 *
 * The kernel stores bk_color, bk_mode per DC but exposes only Set
 * syscalls (which return the *previous* value). To implement the
 * Get* queries without adding new syscalls, we keep a user-side
 * shadow that the Set wrappers maintain. Initialised to the GDI
 * defaults (white background, OPAQUE). Per-DC state would require
 * a DC table here; v0 uses a single module-global — same pattern
 * as g_cur_x/g_cur_y, same single-DC-at-a-time limitation.
 *
 * PolyFillMode is purely user-side (the kernel has no polygon-fill
 * primitive yet), so it lives only in the shadow. */
static COLORREF g_bk_color = 0x00FFFFFF; /* RGB white — GDI default */
static INT g_bk_mode = 2;                /* OPAQUE (2) — GDI default */
static INT g_poly_fill_mode = 1;         /* ALTERNATE (1) — GDI default */

__declspec(dllexport) COLORREF SetBkColor(HDC dc, COLORREF clr)
{
    long long rv;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"((long long)SYS_GDI_SET_BK_COLOR), "D"((long long)(unsigned long long)dc), "S"((long long)clr)
                     : "memory");
    COLORREF prev = g_bk_color;
    g_bk_color = clr;
    return prev;
}
__declspec(dllexport) COLORREF GetBkColor(HDC dc)
{
    (void)dc;
    return g_bk_color;
}
__declspec(dllexport) INT SetBkMode(HDC dc, INT mode)
{
    long long rv;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"((long long)SYS_GDI_SET_BK_MODE), "D"((long long)(unsigned long long)dc), "S"((long long)mode)
                     : "memory");
    INT prev = g_bk_mode;
    g_bk_mode = mode;
    return prev;
}
__declspec(dllexport) INT GetBkMode(HDC dc)
{
    (void)dc;
    return g_bk_mode;
}
__declspec(dllexport) INT SetPolyFillMode(HDC dc, INT mode)
{
    (void)dc;
    if (mode != 1 && mode != 2)
        return 0;
    INT prev = g_poly_fill_mode;
    g_poly_fill_mode = mode;
    return prev;
}
__declspec(dllexport) INT GetPolyFillMode(HDC dc)
{
    (void)dc;
    return g_poly_fill_mode;
}
__declspec(dllexport) INT SetMapMode(HDC dc, INT mode)
{
    (void)dc;
    (void)mode;
    return 0;
}
__declspec(dllexport) UINT SetTextAlign(HDC dc, UINT align)
{
    (void)dc;
    (void)align;
    return 0;
}
__declspec(dllexport) COLORREF SetTextColor(HDC dc, COLORREF clr)
{
    long long rv;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"((long long)SYS_GDI_SET_TEXT_COLOR), "D"((long long)(unsigned long long)dc),
                       "S"((long long)clr)
                     : "memory");
    return (COLORREF)rv;
}

/* GetDeviceCaps — report device capability ints. The kernel's
 * default framebuffer is 32-bpp; hardcode the constants apps
 * routinely query. Index list:
 *   8  = HORZRES        (pixels)
 *   10 = VERTRES        (pixels)
 *   12 = BITSPIXEL      (32)
 *   14 = PLANES         (1)
 *   88 = LOGPIXELSX     (96 — standard DPI)
 *   90 = LOGPIXELSY     (96)
 *   24 = NUMCOLORS      (-1 = "more than 256")
 *   26 = ASPECTX        (36 — square pixels)
 *   40 = ASPECTY        (36)
 *   38 = TECHNOLOGY     (0 = DT_PLOTTER, but 1 = DT_RASDISPLAY is canonical)
 * Anything else returns 0.
 */
__declspec(dllexport) INT GetDeviceCaps(HDC dc, INT index)
{
    (void)dc;
    switch (index)
    {
    case 8:
        return 1024; /* HORZRES — matches the default framebuffer */
    case 10:
        return 768; /* VERTRES */
    case 12:
        return 32; /* BITSPIXEL */
    case 14:
        return 1; /* PLANES */
    case 88:
    case 90:
        return 96; /* LOGPIXELSX/Y */
    case 24:
        return -1; /* NUMCOLORS — "true colour" sentinel */
    case 26:
    case 40:
        return 36; /* ASPECTX/Y — square pixels */
    case 38:
        return 1; /* TECHNOLOGY = DT_RASDISPLAY */
    case 22:
        return 8; /* HORZSIZE — millimetres (ballpark) */
    case 6:
        return 8; /* VERTSIZE */
    default:
        return 0;
    }
}

/* GetTextExtentPoint32A/W — measure text using the DC's selected
 * font. Queries GetTextMetricsA to get the glyph dimensions. */
typedef struct
{
    INT cx;
    INT cy;
} SIZE_GDI;

/* Helper: get the DC's font cell size via GetTextMetrics. */
static void gdi32_font_cell_size(HDC dc, INT* out_w, INT* out_h)
{
    unsigned char tm_buf[57];
    for (int i = 0; i < 57; ++i)
        tm_buf[i] = 0;
    INT* fields = (INT*)tm_buf;
    /* Strip GDI_TAG for window DCs. */
    unsigned long long hdc_val = (unsigned long long)dc;
    if ((hdc_val & GDI_TAG) == GDI_TAG)
        hdc_val = hdc_val & ~GDI_TAG;
    long long ok = gdi32_syscall2(SYS_GDI_GET_TEXT_METRICS, (long long)hdc_val, (long long)(unsigned long long)tm_buf);
    if (ok)
    {
        *out_w = fields[5]; /* tmAveCharWidth */
        *out_h = fields[0]; /* tmHeight */
    }
    else
    {
        *out_w = 8;
        *out_h = 8;
    }
}
__declspec(dllexport) BOOL GetTextExtentPoint32A(HDC dc, const char* str, INT cnt, SIZE_GDI* sz)
{
    (void)str;
    if (sz)
    {
        INT cw, ch;
        gdi32_font_cell_size(dc, &cw, &ch);
        sz->cx = (cnt < 0 ? 0 : cnt) * cw;
        sz->cy = ch;
    }
    return 1;
}
__declspec(dllexport) BOOL GetTextExtentPoint32W(HDC dc, const wchar_t16* str, INT cnt, SIZE_GDI* sz)
{
    (void)str;
    if (sz)
    {
        INT cw, ch;
        gdi32_font_cell_size(dc, &cw, &ch);
        sz->cx = (cnt < 0 ? 0 : cnt) * cw;
        sz->cy = ch;
    }
    return 1;
}
__declspec(dllexport) BOOL GetTextExtentExPointW(HDC dc, const wchar_t16* str, INT cnt, INT max_extent, INT* fit,
                                                 INT* dx, SIZE_GDI* sz)
{
    (void)str;
    (void)max_extent;
    (void)dx;
    if (fit)
        *fit = cnt;
    if (sz)
    {
        INT cw, ch;
        gdi32_font_cell_size(dc, &cw, &ch);
        sz->cx = (cnt < 0 ? 0 : cnt) * cw;
        sz->cy = ch;
    }
    return 1;
}

/* GetTextMetricsA/W — fill a TEXTMETRIC from the DC's selected
 * font via the kernel. Falls back to hardcoded 8x8 if the
 * syscall fails (defensive). */
__declspec(dllexport) BOOL GetTextMetricsA(HDC dc, void* tm)
{
    if (!tm)
        return 0;
    /* Zero the struct first. */
    unsigned char* p = (unsigned char*)tm;
    for (int i = 0; i < 57; ++i)
        p[i] = 0;

    /* Strip GDI_TAG for window DCs so the kernel sees a plain
     * window handle it can look up in WindowDcState. */
    unsigned long long hdc_val = (unsigned long long)dc;
    if ((hdc_val & GDI_TAG) == GDI_TAG)
        hdc_val = hdc_val & ~GDI_TAG;

    long long ok = gdi32_syscall2(SYS_GDI_GET_TEXT_METRICS, (long long)hdc_val, (long long)(unsigned long long)tm);
    if (ok)
        return 1;

    /* Fallback: hardcoded 8x8 metrics. */
    INT* fields = (INT*)tm;
    fields[0] = 8;   /* tmHeight */
    fields[1] = 8;   /* tmAscent */
    fields[5] = 8;   /* tmAveCharWidth */
    fields[6] = 8;   /* tmMaxCharWidth */
    fields[7] = 400; /* tmWeight = FW_NORMAL */
    return 1;
}
__declspec(dllexport) BOOL GetTextMetricsW(HDC dc, void* tm)
{
    return GetTextMetricsA(dc, tm);
}

/* GetCharWidth32A/W — width of each character in the range. Uses
 * the DC's selected font's cell width. */
__declspec(dllexport) BOOL GetCharWidth32A(HDC dc, UINT first, UINT last, INT* widths)
{
    if (!widths || last < first)
        return 0;
    INT cw, ch;
    gdi32_font_cell_size(dc, &cw, &ch);
    UINT n = last - first + 1;
    for (UINT i = 0; i < n; ++i)
        widths[i] = cw;
    return 1;
}
__declspec(dllexport) BOOL GetCharWidth32W(HDC dc, UINT first, UINT last, INT* widths)
{
    return GetCharWidth32A(dc, first, last, widths);
}

/* SetROP2 / GetROP2 — binary raster op. The kernel keeps a per-DC
 * rop2 that the memory-DC paint helpers honour (R2_BLACK / R2_NOT /
 * R2_XORPEN / R2_COPYPEN / R2_WHITE); the user shadow answers
 * GetROP2 and drives the window-DC colour transform (see
 * gdi32_rop2_colour). */
#define SYS_GDI_SET_ROP2 229

__declspec(dllexport) INT SetROP2(HDC dc, INT mode)
{
    if (mode < 1 || mode > 16)
        return 0;
    (void)gdi32_syscall2(SYS_GDI_SET_ROP2, (long long)(unsigned long long)dc, (long long)mode);
    INT prev = g_rop2;
    g_rop2 = mode;
    return prev;
}
__declspec(dllexport) INT GetROP2(HDC dc)
{
    (void)dc;
    return g_rop2;
}

/* GetClipBox / IntersectClipRect / ExcludeClipRect are implemented
 * with the DC clip engine at the end of this file (they need the
 * clip pool that lives below the Region API). */

__declspec(dllexport) INT SetStretchBltMode(HDC dc, INT mode)
{
    (void)dc;
    (void)mode;
    return 1;
}

__declspec(dllexport) INT GetStretchBltMode(HDC dc)
{
    (void)dc;
    return 1;
}

/* --- Path API ---
 *
 * BeginPath opens a path bracket on the DC: subsequent MoveTo /
 * LineTo / Polyline / Polygon append to the path instead of
 * painting (see the recorder hooks above). EndPath closes the
 * bracket. StrokePath replays each recorded segment as a line;
 * FillPath replays each subpath's outline and closes it (no scan-
 * line interior fill — the kernel has no polygon-fill primitive).
 */

/* Replay one path slot via the per-segment line core; if `close`,
 * also draw the closing edge of every subpath. Resets the slot to
 * free afterwards (Stroke/Fill discard the path, matching GDI). */
static BOOL gdi32_path_replay(HANDLE hwnd, GdiPath* p, BOOL close)
{
    for (INT s = 0; s < p->sub_count; ++s)
    {
        INT start = p->sub_start[s];
        INT end = (s + 1 < p->sub_count) ? p->sub_start[s + 1] : p->pt_count;
        for (INT i = start; i + 1 < end; ++i)
            (void)gdi32_line_core(hwnd, p->pts_x[i], p->pts_y[i], p->pts_x[i + 1], p->pts_y[i + 1], 0);
        /* Close the figure if requested (FillPath) or if CloseFigure
         * marked this subpath closed. */
        if ((close || p->sub_closed[s]) && end - start >= 2)
            (void)gdi32_line_core(hwnd, p->pts_x[end - 1], p->pts_y[end - 1], p->pts_x[start], p->pts_y[start], 0);
    }
    p->dc = (HDC)0;
    p->recording = 0;
    p->closed = 0;
    p->pt_count = 0;
    p->sub_count = 0;
    return 1;
}

__declspec(dllexport) BOOL BeginPath(HDC dc)
{
    if (!dc)
        return 0;
    /* Reuse an existing slot for this DC, else grab a free one. */
    GdiPath* p = gdi32_path_find(dc);
    if (!p)
        p = gdi32_path_find((HDC)0);
    if (!p)
        return 0; /* GAP: all GDI_PATH_SLOTS in use — see pool note above */
    p->dc = dc;
    p->recording = 1;
    p->closed = 0;
    p->pt_count = 0;
    p->sub_count = 0;
    return 1;
}

__declspec(dllexport) BOOL EndPath(HDC dc)
{
    GdiPath* p = gdi32_path_recording(dc);
    if (!p)
        return 0;
    p->recording = 0;
    p->closed = 1;
    return 1;
}

__declspec(dllexport) BOOL CloseFigure(HDC dc)
{
    GdiPath* p = gdi32_path_recording(dc);
    if (!p || p->sub_count == 0)
        return 0;
    /* Mark the current (last) subpath closed; the next MoveTo opens
     * a fresh one, matching GDI's CloseFigure semantics. */
    p->sub_closed[p->sub_count - 1] = 1;
    return 1;
}

__declspec(dllexport) BOOL StrokePath(HDC dc)
{
    GdiPath* p = gdi32_path_find(dc);
    if (!p || !p->closed)
        return 0;
    HANDLE hwnd = gdi32_hwnd_from_hdc(dc);
    if (!hwnd)
    {
        /* Non-window DC has no line primitive — discard and report
         * success (the path was consumed). */
        p->dc = (HDC)0;
        p->closed = 0;
        p->pt_count = 0;
        p->sub_count = 0;
        return 1;
    }
    return gdi32_path_replay(hwnd, p, 0);
}

__declspec(dllexport) BOOL FillPath(HDC dc)
{
    GdiPath* p = gdi32_path_find(dc);
    if (!p || !p->closed)
        return 0;
    HANDLE hwnd = gdi32_hwnd_from_hdc(dc);
    if (!hwnd)
    {
        p->dc = (HDC)0;
        p->closed = 0;
        p->pt_count = 0;
        p->sub_count = 0;
        return 1;
    }
    /* GAP: no scanline interior fill — FillPath strokes each
     * subpath's closed outline (the kernel exposes no polygon-fill
     * primitive). Revisit when SYS_GDI gains a fill-region call. */
    return gdi32_path_replay(hwnd, p, 1);
}

/* StrokeAndFillPath — stroke every subpath outline then close and
 * fill every subpath. In v0 both operations reduce to the same line
 * replay (the kernel has no polygon-fill), so this is FillPath with
 * the close flag set (matching real GDI's documented behaviour of
 * closing all open figures). */
__declspec(dllexport) BOOL StrokeAndFillPath(HDC dc)
{
    GdiPath* p = gdi32_path_find(dc);
    if (!p || !p->closed)
        return 0;
    HANDLE hwnd = gdi32_hwnd_from_hdc(dc);
    if (!hwnd)
    {
        p->dc = (HDC)0;
        p->closed = 0;
        p->pt_count = 0;
        p->sub_count = 0;
        return 1;
    }
    return gdi32_path_replay(hwnd, p, 1);
}

/* FlattenPath — convert curves to line segments. v0 paths contain
 * only straight-line data (no Bezier/arc recording), so flattening
 * is a no-op. */
__declspec(dllexport) BOOL FlattenPath(HDC dc)
{
    // STUB: no curves in v0 path data — nothing to flatten.
    GdiPath* p = gdi32_path_find(dc);
    return p && p->closed ? 1 : 0;
}

/* WidenPath — expand the path outline by the pen width. The kernel
 * has no pen-width-aware path expansion primitive, so this is a
 * stub that succeeds without modifying the path data. */
__declspec(dllexport) BOOL WidenPath(HDC dc)
{
    // STUB: no pen-width expansion in v0 — path data unchanged.
    GdiPath* p = gdi32_path_find(dc);
    return p && p->closed ? 1 : 0;
}

/* AbortPath — discard a path (recording or closed) without replaying.
 * Matches GDI's AbortPath, which resets the DC's path state. */
__declspec(dllexport) BOOL AbortPath(HDC dc)
{
    GdiPath* p = gdi32_path_find(dc);
    if (!p)
        return 0;
    p->dc = (HDC)0;
    p->recording = 0;
    p->closed = 0;
    p->pt_count = 0;
    p->sub_count = 0;
    return 1;
}

/* GetPath — retrieve the recorded path points and types.
 *
 * If `pts` is NULL, returns the point count (so the caller can
 * allocate). Otherwise fills `pts` (array of POINT) and `types`
 * (array of BYTE: PT_MOVETO=6, PT_LINETO=2, PT_CLOSEFIGURE=1 flag).
 * `buf_count` is the size of both arrays; if the path has more
 * points than that, the call fails. Returns -1 on error. */
#define PT_MOVETO 0x06
#define PT_LINETO 0x02
#define PT_CLOSEFIGURE 0x01

__declspec(dllexport) INT GetPath(HDC dc, void* pts, unsigned char* types, INT buf_count)
{
    GdiPath* p = gdi32_path_find(dc);
    if (!p || !p->closed)
        return -1;
    if (!pts || !types)
        return p->pt_count; /* query mode */
    if (buf_count < p->pt_count)
        return -1;

    POINT* out = (POINT*)pts;
    for (INT i = 0; i < p->pt_count; ++i)
    {
        out[i].x = p->pts_x[i];
        out[i].y = p->pts_y[i];
        /* Determine the type: is this point the start of a subpath? */
        int is_moveto = 0;
        for (INT s = 0; s < p->sub_count; ++s)
        {
            if (p->sub_start[s] == i)
            {
                is_moveto = 1;
                break;
            }
        }
        types[i] = is_moveto ? PT_MOVETO : PT_LINETO;
    }
    /* Mark the last point of each closed subpath with PT_CLOSEFIGURE. */
    for (INT s = 0; s < p->sub_count; ++s)
    {
        if (p->sub_closed[s])
        {
            INT end = (s + 1 < p->sub_count) ? p->sub_start[s + 1] - 1 : p->pt_count - 1;
            if (end >= 0 && end < p->pt_count)
                types[end] |= PT_CLOSEFIGURE;
        }
    }
    return p->pt_count;
}

/* PathToRegion is defined after the Region API section (it needs
 * GdiRegion / HRGN / gdi32_rgn_alloc which are declared below). */

/* --- Region API ---
 *
 * The pure rect-list geometry (bbox, point/rect containment, offset,
 * equality) lives in gdi32_region.h so it can be unit-tested on the
 * host (tests/host/test_gdi32_region.cpp); this file owns the HRGN
 * pool and the dllexport wrappers.
 *
 * Regions are user-mode rectangle lists. CreateRectRgn makes a
 * single-rect region; CombineRgn merges two source regions into a
 * destination per the RGN_* mode. The handle is an index into a
 * fixed pool, tagged GDI_RGN_TAG so DeleteObject can free the slot
 * and the kernel-bitmap branch never mistakes it for a bitmap.
 *
 * CombineRgn runs the exact rect-list set algebra from
 * gdi32_region.h (AND = pairwise intersection, DIFF = band
 * subtraction, OR/XOR = disjoint composition) and only collapses to
 * a bounding-box over-approximation when the exact result exceeds
 * GDI_RGN_MAX_RECTS rects.
 *
 * GAP: GDI_RGN_SLOTS regions / GDI_RGN_MAX_RECTS rects each —
 * CreateRectRgn over capacity returns NULL; over-capacity combine
 * results collapse to a bounding box (see CombineRgn).
 */
#define GDI_RGN_SLOTS 16
#define GDI_RGN_MAX_RECTS 8
#define GDI_RGN_TAG 0x52470000ULL /* 'RG' — region handle tag */
#define GDI_RGN_TAG_MASK 0xFFFF0000ULL

#define RGN_AND 1
#define RGN_OR 2
#define RGN_XOR 3
#define RGN_DIFF 4
#define RGN_COPY 5

#define RGN_NULLREGION 1
#define RGN_SIMPLEREGION 2
#define RGN_COMPLEXREGION 3
#define RGN_ERROR 0

/* Pure rect-list geometry (host-tested freestanding header). RECT and
 * GdiRgnRect are both four ints in the same order; the wrappers copy
 * field-by-field rather than pun, so no layout assumption is baked in. */
#include "gdi32_region.h"

typedef void* HRGN;

typedef struct
{
    BOOL used;
    INT count; /* number of rects; 0 == empty (NULLREGION) */
    RECT rects[GDI_RGN_MAX_RECTS];
} GdiRegion;

static GdiRegion g_regions[GDI_RGN_SLOTS];

/* Defined below CombineRgn (kept near their historical position);
 * forward-declared so CombineRgn can use the exact set algebra. */
static int gdi32_rgn_copy_rects(const GdiRegion* rg, GdiRgnRect* out);
static INT gdi32_rgn_complexity(const GdiRegion* rg);

/* Store an exact rect-list result into a destination region. */
static void gdi32_rgn_store(GdiRegion* dst, const GdiRgnRect* rects, int count)
{
    if (count > GDI_RGN_MAX_RECTS)
        count = GDI_RGN_MAX_RECTS;
    dst->count = count;
    for (int i = 0; i < count; ++i)
    {
        dst->rects[i].left = rects[i].left;
        dst->rects[i].top = rects[i].top;
        dst->rects[i].right = rects[i].right;
        dst->rects[i].bottom = rects[i].bottom;
    }
}

/* Map an HRGN back to its pool slot, or NULL if the handle isn't
 * one of ours / is stale. */
static GdiRegion* gdi32_rgn_resolve(HRGN h)
{
    unsigned long long v = (unsigned long long)h;
    if ((v & GDI_RGN_TAG_MASK) != GDI_RGN_TAG)
        return (GdiRegion*)0;
    unsigned idx = (unsigned)(v & 0xFFFFULL);
    if (idx >= GDI_RGN_SLOTS || !g_regions[idx].used)
        return (GdiRegion*)0;
    return &g_regions[idx];
}

static HRGN gdi32_rgn_handle(unsigned idx)
{
    return (HRGN)(GDI_RGN_TAG | (unsigned long long)idx);
}

static GdiRegion* gdi32_rgn_alloc(unsigned* out_idx)
{
    for (unsigned i = 0; i < GDI_RGN_SLOTS; ++i)
    {
        if (!g_regions[i].used)
        {
            g_regions[i].used = 1;
            g_regions[i].count = 0;
            *out_idx = i;
            return &g_regions[i];
        }
    }
    return (GdiRegion*)0;
}

__declspec(dllexport) HRGN CreateRectRgn(INT l, INT t, INT r, INT b)
{
    unsigned idx;
    GdiRegion* rg = gdi32_rgn_alloc(&idx);
    if (!rg)
        return (HRGN)0; /* GAP: pool exhausted */
    /* Normalise so left<=right, top<=bottom (GDI does the same). */
    if (r < l)
    {
        INT tmp = l;
        l = r;
        r = tmp;
    }
    if (b < t)
    {
        INT tmp = t;
        t = b;
        b = tmp;
    }
    if (r > l && b > t)
    {
        rg->rects[0].left = l;
        rg->rects[0].top = t;
        rg->rects[0].right = r;
        rg->rects[0].bottom = b;
        rg->count = 1;
    }
    else
    {
        rg->count = 0; /* empty region */
    }
    return gdi32_rgn_handle(idx);
}

__declspec(dllexport) HRGN CreateRectRgnIndirect(const void* prc)
{
    if (!prc)
        return (HRGN)0;
    const RECT* rc = (const RECT*)prc;
    return CreateRectRgn(rc->left, rc->top, rc->right, rc->bottom);
}

/* Union bounding box of every rect in a region into *out; returns
 * 1 if the region is non-empty. */
static int gdi32_rgn_bbox(const GdiRegion* rg, RECT* out)
{
    if (!rg || rg->count == 0)
        return 0;
    *out = rg->rects[0];
    for (INT i = 1; i < rg->count; ++i)
    {
        if (rg->rects[i].left < out->left)
            out->left = rg->rects[i].left;
        if (rg->rects[i].top < out->top)
            out->top = rg->rects[i].top;
        if (rg->rects[i].right > out->right)
            out->right = rg->rects[i].right;
        if (rg->rects[i].bottom > out->bottom)
            out->bottom = rg->rects[i].bottom;
    }
    return 1;
}

static void gdi32_rgn_set_single(GdiRegion* dst, const RECT* rc)
{
    if (rc->right > rc->left && rc->bottom > rc->top)
    {
        dst->rects[0] = *rc;
        dst->count = 1;
    }
    else
    {
        dst->count = 0;
    }
}

__declspec(dllexport) INT CombineRgn(HRGN hDst, HRGN hSrc1, HRGN hSrc2, INT mode)
{
    GdiRegion* dst = gdi32_rgn_resolve(hDst);
    GdiRegion* s1 = gdi32_rgn_resolve(hSrc1);
    if (!dst || !s1)
        return RGN_ERROR;

    if (mode == RGN_COPY)
    {
        /* Element-wise copy of the live rects only. A whole-struct
         * assignment (*dst = *s1) gets lowered to a memcpy libcall,
         * which freestanding DLLs don't link; per-RECT copies inline. */
        dst->count = s1->count;
        for (INT i = 0; i < s1->count && i < (INT)GDI_RGN_MAX_RECTS; i++)
            dst->rects[i] = s1->rects[i];
        dst->used = 1;
        return dst->count == 0 ? RGN_NULLREGION : (dst->count == 1 ? RGN_SIMPLEREGION : RGN_COMPLEXREGION);
    }

    GdiRegion* s2 = gdi32_rgn_resolve(hSrc2);
    if (!s2)
        return RGN_ERROR;

    /* Exact rect-list set algebra (gdi32_region.h). The sources are
     * copied out first, so hDst may alias either source (Win32 allows
     * CombineRgn(h, h, other, ...)). */
    GdiRgnRect ra[GDI_RGN_MAX_RECTS];
    GdiRgnRect rb[GDI_RGN_MAX_RECTS];
    GdiRgnRect res[GDI_RGN_MAX_RECTS];
    const int na = gdi32_rgn_copy_rects(s1, ra);
    const int nb = gdi32_rgn_copy_rects(s2, rb);
    int nres;
    switch (mode)
    {
    case RGN_AND:
        nres = GdiRgnIntersect(ra, na, rb, nb, res, GDI_RGN_MAX_RECTS);
        break;
    case RGN_OR:
        nres = GdiRgnUnion(ra, na, rb, nb, res, GDI_RGN_MAX_RECTS);
        break;
    case RGN_XOR:
        nres = GdiRgnXor(ra, na, rb, nb, res, GDI_RGN_MAX_RECTS);
        break;
    case RGN_DIFF:
        nres = GdiRgnSubtract(ra, na, rb, nb, res, GDI_RGN_MAX_RECTS);
        break;
    default:
        return RGN_ERROR;
    }

    dst->used = 1;
    if (nres >= 0)
    {
        gdi32_rgn_store(dst, res, nres);
        return gdi32_rgn_complexity(dst);
    }

    /* GAP: exact result exceeded GDI_RGN_MAX_RECTS rects — collapse
     * to a bounding-box over-approximation (per-mode, mirroring the
     * pre-exact behaviour). Revisit by raising GDI_RGN_MAX_RECTS if
     * a real PE trips this. */
    RECT b1, b2;
    const int have1 = gdi32_rgn_bbox(s1, &b1);
    const int have2 = gdi32_rgn_bbox(s2, &b2);
    RECT result = {0, 0, 0, 0};
    if (mode == RGN_AND)
    {
        if (have1 && have2)
        {
            result.left = b1.left > b2.left ? b1.left : b2.left;
            result.top = b1.top > b2.top ? b1.top : b2.top;
            result.right = b1.right < b2.right ? b1.right : b2.right;
            result.bottom = b1.bottom < b2.bottom ? b1.bottom : b2.bottom;
        }
    }
    else if (mode == RGN_DIFF)
    {
        if (have1)
            result = b1;
    }
    else /* RGN_OR / RGN_XOR: union bounding box */
    {
        if (have1 && have2)
        {
            result.left = b1.left < b2.left ? b1.left : b2.left;
            result.top = b1.top < b2.top ? b1.top : b2.top;
            result.right = b1.right > b2.right ? b1.right : b2.right;
            result.bottom = b1.bottom > b2.bottom ? b1.bottom : b2.bottom;
        }
        else if (have1)
        {
            result = b1;
        }
        else if (have2)
        {
            result = b2;
        }
    }
    gdi32_rgn_set_single(dst, &result);
    return dst->count == 0 ? RGN_NULLREGION : RGN_SIMPLEREGION;
}

/* DeleteObject hook: if `obj` is one of our region handles, free
 * its slot and return 1. Returns 0 for any non-region handle so
 * DeleteObject continues to its kernel-bitmap path. */
static int gdi32_region_delete(HGDIOBJ obj)
{
    GdiRegion* rg = gdi32_rgn_resolve((HRGN)obj);
    if (!rg)
        return 0;
    rg->used = 0;
    rg->count = 0;
    return 1;
}

/* Copy a region's live RECTs into a GdiRgnRect[] for the freestanding
 * geometry helpers. Returns the count copied (clamped to capacity). */
static int gdi32_rgn_copy_rects(const GdiRegion* rg, GdiRgnRect* out)
{
    int n = rg->count;
    if (n > GDI_RGN_MAX_RECTS)
        n = GDI_RGN_MAX_RECTS;
    for (int i = 0; i < n; ++i)
    {
        out[i].left = rg->rects[i].left;
        out[i].top = rg->rects[i].top;
        out[i].right = rg->rects[i].right;
        out[i].bottom = rg->rects[i].bottom;
    }
    return n;
}

/* RGN_* complexity code for a region's current rect count. */
static INT gdi32_rgn_complexity(const GdiRegion* rg)
{
    if (rg->count == 0)
        return RGN_NULLREGION;
    return rg->count == 1 ? RGN_SIMPLEREGION : RGN_COMPLEXREGION;
}

/* GetRgnBox — fill *prc with the region bounding box; return the
 * region complexity (RGN_NULLREGION / SIMPLEREGION / COMPLEXREGION),
 * or RGN_ERROR for a bad handle / null pointer. */
__declspec(dllexport) INT GetRgnBox(HRGN hrgn, RECT* prc)
{
    GdiRegion* rg = gdi32_rgn_resolve(hrgn);
    if (!rg || !prc)
        return RGN_ERROR;
    GdiRgnRect buf[GDI_RGN_MAX_RECTS];
    const int n = gdi32_rgn_copy_rects(rg, buf);
    GdiRgnRect box;
    GdiRgnBBox(buf, n, &box);
    prc->left = box.left;
    prc->top = box.top;
    prc->right = box.right;
    prc->bottom = box.bottom;
    return gdi32_rgn_complexity(rg);
}

/* PtInRegion — TRUE if point (x,y) is inside the region (half-open). */
__declspec(dllexport) BOOL PtInRegion(HRGN hrgn, INT x, INT y)
{
    GdiRegion* rg = gdi32_rgn_resolve(hrgn);
    if (!rg)
        return 0;
    GdiRgnRect buf[GDI_RGN_MAX_RECTS];
    const int n = gdi32_rgn_copy_rects(rg, buf);
    return GdiRgnPtIn(buf, n, x, y) ? 1 : 0;
}

/* RectInRegion — TRUE if any part of *prc lies within the region. */
__declspec(dllexport) BOOL RectInRegion(HRGN hrgn, const RECT* prc)
{
    GdiRegion* rg = gdi32_rgn_resolve(hrgn);
    if (!rg || !prc)
        return 0;
    GdiRgnRect buf[GDI_RGN_MAX_RECTS];
    const int n = gdi32_rgn_copy_rects(rg, buf);
    GdiRgnRect q = {prc->left, prc->top, prc->right, prc->bottom};
    GdiRgnNormRect(&q); /* a user RECT may be inverted */
    return GdiRgnRectIn(buf, n, &q) ? 1 : 0;
}

/* OffsetRgn — translate the region in place; return its complexity. */
__declspec(dllexport) INT OffsetRgn(HRGN hrgn, INT dx, INT dy)
{
    GdiRegion* rg = gdi32_rgn_resolve(hrgn);
    if (!rg)
        return RGN_ERROR;
    for (INT i = 0; i < rg->count; ++i)
    {
        rg->rects[i].left += dx;
        rg->rects[i].right += dx;
        rg->rects[i].top += dy;
        rg->rects[i].bottom += dy;
    }
    return gdi32_rgn_complexity(rg);
}

/* SetRectRgn — reset an existing region to a single rectangle. */
__declspec(dllexport) BOOL SetRectRgn(HRGN hrgn, INT l, INT t, INT r, INT b)
{
    GdiRegion* rg = gdi32_rgn_resolve(hrgn);
    if (!rg)
        return 0;
    GdiRgnRect nr = {l, t, r, b};
    if (GdiRgnNormRect(&nr))
    {
        rg->rects[0].left = nr.left;
        rg->rects[0].top = nr.top;
        rg->rects[0].right = nr.right;
        rg->rects[0].bottom = nr.bottom;
        rg->count = 1;
    }
    else
    {
        rg->count = 0; /* degenerate rect → empty region */
    }
    return 1;
}

/* EqualRgn — TRUE if the two regions hold the same rectangle list. */
__declspec(dllexport) BOOL EqualRgn(HRGN h1, HRGN h2)
{
    GdiRegion* a = gdi32_rgn_resolve(h1);
    GdiRegion* b = gdi32_rgn_resolve(h2);
    if (!a || !b)
        return 0;
    GdiRgnRect ba[GDI_RGN_MAX_RECTS];
    GdiRgnRect bb[GDI_RGN_MAX_RECTS];
    const int na = gdi32_rgn_copy_rects(a, ba);
    const int nb = gdi32_rgn_copy_rects(b, bb);
    return GdiRgnEqual(ba, na, bb, nb) ? 1 : 0;
}

/* CreateEllipticRgn — build a region approximating an axis-aligned
 * ellipse. Uses the scan-line decomposition in gdi32_region.h,
 * bounded to GDI_RGN_MAX_RECTS bands. */
__declspec(dllexport) HRGN CreateEllipticRgn(INT l, INT t, INT r, INT b)
{
    GdiRgnRect buf[GDI_RGN_MAX_RECTS];
    int n = GdiRgnEllipseRects(l, t, r, b, buf, GDI_RGN_MAX_RECTS);
    if (n <= 0)
    {
        /* Degenerate — return an empty region (matching GDI). */
        return CreateRectRgn(0, 0, 0, 0);
    }
    unsigned idx;
    GdiRegion* rg = gdi32_rgn_alloc(&idx);
    if (!rg)
        return (HRGN)0;
    rg->count = n;
    for (int i = 0; i < n; ++i)
    {
        rg->rects[i].left = buf[i].left;
        rg->rects[i].top = buf[i].top;
        rg->rects[i].right = buf[i].right;
        rg->rects[i].bottom = buf[i].bottom;
    }
    return gdi32_rgn_handle(idx);
}

/* --- DC clip regions ---------------------------------------------
 *
 * Per-DC clip state, keyed by HDC in a fixed pool (same pattern as
 * the path slots). A DC with no slot has NO clip — the implicit
 * clip is the whole device surface. A slot with count == 0 is a
 * legitimately EMPTY clip (everything clipped out), reachable via
 * IntersectClipRect with a disjoint rect.
 *
 * Enforcement is user-side, in the draw wrappers above: FillRect
 * decomposes into one kernel fill per clip piece (exact), SetPixel
 * tests membership (exact), and the outline / text primitives
 * reject whole shapes by bounding box.
 * GAP: partially clipped outlines / text / memory-DC blits draw
 * unclipped — the kernel draw paths carry no clip region. Revisit
 * when the compositor display list grows a clip channel.
 */
#define GDI_CLIP_SLOTS 8
#define GDI_DEVICE_W 1024 /* keep in sync with GetDeviceCaps HORZRES */
#define GDI_DEVICE_H 768  /* keep in sync with GetDeviceCaps VERTRES */

typedef struct
{
    HDC dc; /* 0 == free slot */
    INT count;
    RECT rects[GDI_RGN_MAX_RECTS];
} GdiDcClip;

static GdiDcClip g_dc_clips[GDI_CLIP_SLOTS];

static GdiDcClip* gdi32_clip_find(HDC dc)
{
    if (!dc)
        return (GdiDcClip*)0;
    for (int i = 0; i < GDI_CLIP_SLOTS; ++i)
    {
        if (g_dc_clips[i].dc == dc)
            return &g_dc_clips[i];
    }
    return (GdiDcClip*)0;
}

static GdiDcClip* gdi32_clip_get(HDC dc)
{
    GdiDcClip* s = gdi32_clip_find(dc);
    if (s || !dc)
        return s;
    for (int i = 0; i < GDI_CLIP_SLOTS; ++i)
    {
        if (!g_dc_clips[i].dc)
        {
            g_dc_clips[i].dc = dc;
            g_dc_clips[i].count = 0;
            return &g_dc_clips[i];
        }
    }
    return (GdiDcClip*)0; /* GAP: clip pool exhausted — caller fails */
}

static void gdi32_clip_release(HDC dc)
{
    GdiDcClip* s = gdi32_clip_find(dc);
    if (s)
    {
        s->dc = (HDC)0;
        s->count = 0;
    }
}

/* Copy a clip slot's rects — or, for a DC with no clip (s == NULL),
 * the device rect — into a GdiRgnRect list of GDI_RGN_MAX_RECTS
 * capacity. Returns the count. */
static int gdi32_clip_base_rects(const GdiDcClip* s, GdiRgnRect* out)
{
    if (!s)
    {
        out[0].left = 0;
        out[0].top = 0;
        out[0].right = GDI_DEVICE_W;
        out[0].bottom = GDI_DEVICE_H;
        return 1;
    }
    int n = s->count;
    if (n > GDI_RGN_MAX_RECTS)
        n = GDI_RGN_MAX_RECTS;
    for (int i = 0; i < n; ++i)
    {
        out[i].left = s->rects[i].left;
        out[i].top = s->rects[i].top;
        out[i].right = s->rects[i].right;
        out[i].bottom = s->rects[i].bottom;
    }
    return n;
}

static void gdi32_clip_store(GdiDcClip* s, const GdiRgnRect* rects, int count)
{
    if (count > GDI_RGN_MAX_RECTS)
        count = GDI_RGN_MAX_RECTS;
    s->count = count;
    for (int i = 0; i < count; ++i)
    {
        s->rects[i].left = rects[i].left;
        s->rects[i].top = rects[i].top;
        s->rects[i].right = rects[i].right;
        s->rects[i].bottom = rects[i].bottom;
    }
}

static INT gdi32_clip_complexity(const GdiDcClip* s)
{
    if (s->count == 0)
        return RGN_NULLREGION;
    return s->count == 1 ? RGN_SIMPLEREGION : RGN_COMPLEXREGION;
}

/* Enforcement helpers (forward-declared near the top of the file). */
static int gdi32_clip_pt_visible(HDC dc, INT x, INT y)
{
    GdiDcClip* s = gdi32_clip_find(dc);
    if (!s)
        return 1;
    GdiRgnRect buf[GDI_RGN_MAX_RECTS];
    const int n = gdi32_clip_base_rects(s, buf);
    return GdiRgnPtIn(buf, n, x, y);
}

static int gdi32_clip_rect_visible(HDC dc, INT l, INT t, INT r, INT b)
{
    GdiDcClip* s = gdi32_clip_find(dc);
    if (!s)
        return 1;
    GdiRgnRect buf[GDI_RGN_MAX_RECTS];
    const int n = gdi32_clip_base_rects(s, buf);
    GdiRgnRect q;
    q.left = l;
    q.top = t;
    q.right = r;
    q.bottom = b;
    if (!GdiRgnNormRect(&q))
        return 0;
    return GdiRgnRectIn(buf, n, &q);
}

static int gdi32_clip_fill_pieces(HDC dc, INT l, INT t, INT r, INT b, RECT* out, int cap)
{
    GdiDcClip* s = gdi32_clip_find(dc);
    if (!s)
        return -1; /* no clip — caller draws the original rect */
    GdiRgnRect base[GDI_RGN_MAX_RECTS];
    const int n = gdi32_clip_base_rects(s, base);
    GdiRgnRect q;
    q.left = l;
    q.top = t;
    q.right = r;
    q.bottom = b;
    if (!GdiRgnNormRect(&q))
        return 0;
    GdiRgnRect res[GDI_RGN_MAX_RECTS];
    /* n disjoint rects ∩ one rect yields ≤ n pieces — cannot
     * overflow GDI_RGN_MAX_RECTS. */
    int m = GdiRgnIntersect(base, n, &q, 1, res, GDI_RGN_MAX_RECTS);
    if (m < 0)
        m = 0;
    if (m > cap)
        m = cap;
    for (int i = 0; i < m; ++i)
    {
        out[i].left = res[i].left;
        out[i].top = res[i].top;
        out[i].right = res[i].right;
        out[i].bottom = res[i].bottom;
    }
    return m;
}

/* SelectClipRgn — set (a COPY of) the region as the DC's clip; a
 * NULL region resets to "no clip". Returns the resulting clip
 * complexity. */
__declspec(dllexport) INT SelectClipRgn(HDC dc, HRGN hrgn)
{
    if (!dc)
        return RGN_ERROR;
    if (!hrgn)
    {
        gdi32_clip_release(dc); /* NULL = reset to no clip */
        return RGN_SIMPLEREGION;
    }
    GdiRegion* rg = gdi32_rgn_resolve(hrgn);
    if (!rg)
        return RGN_ERROR;
    GdiDcClip* s = gdi32_clip_get(dc);
    if (!s)
        return RGN_ERROR; /* GAP: clip pool exhausted */
    GdiRgnRect buf[GDI_RGN_MAX_RECTS];
    const int n = gdi32_rgn_copy_rects(rg, buf);
    gdi32_clip_store(s, buf, n);
    return gdi32_clip_complexity(s);
}

/* ExtSelectClipRgn — combine a region with the DC's current clip
 * (device surface when none is set) per the RGN_* mode. */
__declspec(dllexport) INT ExtSelectClipRgn(HDC dc, HRGN hrgn, INT mode)
{
    if (!dc)
        return RGN_ERROR;
    if (!hrgn)
    {
        /* A NULL region is only legal with RGN_COPY (full reset). */
        if (mode != RGN_COPY)
            return RGN_ERROR;
        gdi32_clip_release(dc);
        return RGN_SIMPLEREGION;
    }
    if (mode == RGN_COPY)
        return SelectClipRgn(dc, hrgn);
    GdiRegion* rg = gdi32_rgn_resolve(hrgn);
    if (!rg)
        return RGN_ERROR;

    GdiRgnRect base[GDI_RGN_MAX_RECTS];
    const int bn = gdi32_clip_base_rects(gdi32_clip_find(dc), base);
    GdiRgnRect rr[GDI_RGN_MAX_RECTS];
    const int rn = gdi32_rgn_copy_rects(rg, rr);
    GdiRgnRect res[GDI_RGN_MAX_RECTS];
    int m;
    switch (mode)
    {
    case RGN_AND:
        m = GdiRgnIntersect(base, bn, rr, rn, res, GDI_RGN_MAX_RECTS);
        break;
    case RGN_OR:
        m = GdiRgnUnion(base, bn, rr, rn, res, GDI_RGN_MAX_RECTS);
        break;
    case RGN_XOR:
        m = GdiRgnXor(base, bn, rr, rn, res, GDI_RGN_MAX_RECTS);
        break;
    case RGN_DIFF:
        m = GdiRgnSubtract(base, bn, rr, rn, res, GDI_RGN_MAX_RECTS);
        break;
    default:
        return RGN_ERROR;
    }
    GdiDcClip* s = gdi32_clip_get(dc);
    if (!s)
        return RGN_ERROR; /* GAP: clip pool exhausted */
    if (m >= 0)
    {
        gdi32_clip_store(s, res, m);
    }
    else
    {
        /* GAP: exact combine overflowed GDI_RGN_MAX_RECTS — collapse
         * to the union bounding box of both operands (over-
         * approximation: clips less than the exact result would). */
        GdiRgnRect b1, b2, box;
        const int h1 = GdiRgnBBox(base, bn, &b1);
        const int h2 = GdiRgnBBox(rr, rn, &b2);
        box = h1 ? b1 : b2;
        if (h1 && h2)
        {
            box.left = b1.left < b2.left ? b1.left : b2.left;
            box.top = b1.top < b2.top ? b1.top : b2.top;
            box.right = b1.right > b2.right ? b1.right : b2.right;
            box.bottom = b1.bottom > b2.bottom ? b1.bottom : b2.bottom;
        }
        gdi32_clip_store(s, &box, (h1 || h2) ? 1 : 0);
    }
    return gdi32_clip_complexity(s);
}

/* GetClipRgn — copy the DC's clip into `hrgn`. Returns 0 if the DC
 * has no clip region, 1 on success, -1 on a bad handle. */
__declspec(dllexport) INT GetClipRgn(HDC dc, HRGN hrgn)
{
    GdiRegion* rg = gdi32_rgn_resolve(hrgn);
    if (!dc || !rg)
        return -1;
    GdiDcClip* s = gdi32_clip_find(dc);
    if (!s)
        return 0;
    rg->count = s->count;
    for (INT i = 0; i < s->count; ++i)
        rg->rects[i] = s->rects[i];
    return 1;
}

/* OffsetClipRgn — translate the DC's clip region. */
__declspec(dllexport) INT OffsetClipRgn(HDC dc, INT dx, INT dy)
{
    if (!dc)
        return RGN_ERROR;
    GdiDcClip* s = gdi32_clip_find(dc);
    if (!s)
        return RGN_SIMPLEREGION; /* no clip — whole surface, unmoved */
    for (INT i = 0; i < s->count; ++i)
    {
        s->rects[i].left += dx;
        s->rects[i].right += dx;
        s->rects[i].top += dy;
        s->rects[i].bottom += dy;
    }
    return gdi32_clip_complexity(s);
}

/* IntersectClipRect — shrink the clip to its intersection with the
 * rect. With no clip set, the clip becomes rect ∩ device surface. */
__declspec(dllexport) INT IntersectClipRect(HDC dc, INT l, INT t, INT r, INT b)
{
    if (!dc)
        return RGN_ERROR;
    GdiRgnRect base[GDI_RGN_MAX_RECTS];
    const int bn = gdi32_clip_base_rects(gdi32_clip_find(dc), base);
    GdiRgnRect q;
    q.left = l;
    q.top = t;
    q.right = r;
    q.bottom = b;
    GdiRgnRect res[GDI_RGN_MAX_RECTS];
    int m = 0;
    if (GdiRgnNormRect(&q))
    {
        /* ≤ bn disjoint pieces — cannot overflow the cap. */
        m = GdiRgnIntersect(base, bn, &q, 1, res, GDI_RGN_MAX_RECTS);
        if (m < 0)
            m = 0;
    }
    GdiDcClip* s = gdi32_clip_get(dc);
    if (!s)
        return RGN_ERROR; /* GAP: clip pool exhausted */
    gdi32_clip_store(s, res, m);
    return gdi32_clip_complexity(s);
}

/* ExcludeClipRect — remove the rect from the clip. With no clip
 * set, the clip becomes device surface \ rect. */
__declspec(dllexport) INT ExcludeClipRect(HDC dc, INT l, INT t, INT r, INT b)
{
    if (!dc)
        return RGN_ERROR;
    GdiDcClip* existing = gdi32_clip_find(dc);
    GdiRgnRect q;
    q.left = l;
    q.top = t;
    q.right = r;
    q.bottom = b;
    if (!GdiRgnNormRect(&q))
    {
        /* Empty rect excludes nothing. */
        if (existing)
            return gdi32_clip_complexity(existing);
        return RGN_SIMPLEREGION;
    }
    GdiRgnRect base[GDI_RGN_MAX_RECTS];
    const int bn = gdi32_clip_base_rects(existing, base);
    /* bn ≤ 8 rects minus one rect → ≤ 32 pieces, which always fits
     * GDI_RGN_WORK_CAP; only the ≤ 8 store cap can overflow. */
    GdiRgnRect res[GDI_RGN_WORK_CAP];
    int m = GdiRgnSubtract(base, bn, &q, 1, res, GDI_RGN_WORK_CAP);
    GdiDcClip* s = gdi32_clip_get(dc);
    if (!s)
        return RGN_ERROR; /* GAP: clip pool exhausted */
    if (m >= 0 && m <= GDI_RGN_MAX_RECTS)
    {
        gdi32_clip_store(s, res, m);
    }
    else if (m > GDI_RGN_MAX_RECTS)
    {
        /* GAP: exact exclusion needs more than GDI_RGN_MAX_RECTS
         * rects — collapse to the surviving pieces' bounding box
         * (over-approximation: the excluded band may still draw). */
        GdiRgnRect box;
        GdiRgnBBox(res, m, &box);
        gdi32_clip_store(s, &box, 1);
    }
    else
    {
        /* Unreachable with the caps above; keep the base clip. */
        gdi32_clip_store(s, base, bn);
    }
    return gdi32_clip_complexity(s);
}

/* GetClipBox — bounding box of the DC's clip (device surface when
 * no clip is set). Returns the clip complexity. */
__declspec(dllexport) INT GetClipBox(HDC dc, RECT* r)
{
    if (!r)
        return RGN_ERROR;
    GdiDcClip* s = gdi32_clip_find(dc);
    if (!s)
    {
        r->left = 0;
        r->top = 0;
        r->right = GDI_DEVICE_W;
        r->bottom = GDI_DEVICE_H;
        return RGN_SIMPLEREGION;
    }
    GdiRgnRect buf[GDI_RGN_MAX_RECTS];
    const int n = gdi32_clip_base_rects(s, buf);
    GdiRgnRect box;
    GdiRgnBBox(buf, n, &box);
    r->left = box.left;
    r->top = box.top;
    r->right = box.right;
    r->bottom = box.bottom;
    return gdi32_clip_complexity(s);
}

/* PtVisible / RectVisible — visibility against the DC's clip
 * (device surface when no clip is set). */
__declspec(dllexport) BOOL PtVisible(HDC dc, INT x, INT y)
{
    GdiDcClip* s = gdi32_clip_find(dc);
    GdiRgnRect buf[GDI_RGN_MAX_RECTS];
    const int n = gdi32_clip_base_rects(s, buf);
    return GdiRgnPtIn(buf, n, x, y) ? 1 : 0;
}

__declspec(dllexport) BOOL RectVisible(HDC dc, const RECT* prc)
{
    if (!prc)
        return 0;
    GdiDcClip* s = gdi32_clip_find(dc);
    GdiRgnRect buf[GDI_RGN_MAX_RECTS];
    const int n = gdi32_clip_base_rects(s, buf);
    GdiRgnRect q;
    q.left = prc->left;
    q.top = prc->top;
    q.right = prc->right;
    q.bottom = prc->bottom;
    if (!GdiRgnNormRect(&q))
        return 0;
    return GdiRgnRectIn(buf, n, &q) ? 1 : 0;
}

/* PathToRegion — convert the closed path into a region. Each subpath
 * contributes its bounding box as one rect in the region (up to
 * GDI_RGN_MAX_RECTS). Consumes the path (matching GDI). */
__declspec(dllexport) HRGN PathToRegion(HDC dc)
{
    GdiPath* p = gdi32_path_find(dc);
    if (!p || !p->closed || p->sub_count == 0)
    {
        if (p)
        {
            p->dc = (HDC)0;
            p->closed = 0;
            p->pt_count = 0;
            p->sub_count = 0;
        }
        return (HRGN)0;
    }

    unsigned idx;
    GdiRegion* rg = gdi32_rgn_alloc(&idx);
    if (!rg)
    {
        p->dc = (HDC)0;
        p->closed = 0;
        p->pt_count = 0;
        p->sub_count = 0;
        return (HRGN)0;
    }

    rg->count = 0;
    for (INT s = 0; s < p->sub_count && rg->count < (INT)GDI_RGN_MAX_RECTS; ++s)
    {
        INT start = p->sub_start[s];
        INT end = (s + 1 < p->sub_count) ? p->sub_start[s + 1] : p->pt_count;
        if (end <= start)
            continue;
        INT minx = p->pts_x[start], maxx = minx;
        INT miny = p->pts_y[start], maxy = miny;
        for (INT i = start + 1; i < end; ++i)
        {
            if (p->pts_x[i] < minx)
                minx = p->pts_x[i];
            if (p->pts_x[i] > maxx)
                maxx = p->pts_x[i];
            if (p->pts_y[i] < miny)
                miny = p->pts_y[i];
            if (p->pts_y[i] > maxy)
                maxy = p->pts_y[i];
        }
        if (maxx > minx && maxy > miny)
        {
            rg->rects[rg->count].left = minx;
            rg->rects[rg->count].top = miny;
            rg->rects[rg->count].right = maxx;
            rg->rects[rg->count].bottom = maxy;
            ++rg->count;
        }
    }

    /* Consume the path. */
    p->dc = (HDC)0;
    p->closed = 0;
    p->pt_count = 0;
    p->sub_count = 0;

    return gdi32_rgn_handle(idx);
}
