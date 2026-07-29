/*
 * surface_smoke — prove the off-screen surface actually holds pixels.
 *
 * gdi_smoke already reports whether the GDI object calls return
 * handles. That is a different question from whether the surface
 * behind those handles stores what you drew, and it is the question
 * the double-buffered drawing every real Win32 app does depends on.
 *
 * So this fixture never asks "did I get a handle" as its verdict. It
 * writes known colours through four different paths and reads them
 * back out with GetDIBits, comparing exact pixel values:
 *
 *   1. Draw into a memory DC (PatBlt / Rectangle) -> read back.
 *   2. Upload a DIB with SetDIBits -> read back. Includes a BOTTOM-UP
 *      DIB, because a positive biHeight is the default nobody thinks
 *      about and "the image is upside down" is the classic bug: the
 *      test writes a distinctive top row and checks it comes back as
 *      the top row.
 *   3. Blit memory DC -> memory DC, then read the destination.
 *   4. CreateDIBSection: write pixels DIRECTLY through the returned
 *      pointer, blit, and confirm the bytes reached the surface.
 *
 * It also checks the two refusals that matter, because a surface that
 * accepts them is a kernel memory bug rather than a missing feature:
 * an overflowing size, and a DIB whose declared buffer is too small
 * for its header.
 */
#include <windows.h>

static void Out(const char* s)
{
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD n = 0;
    DWORD len = 0;
    while (s[len] != '\0')
        ++len;
    WriteConsoleA(h, s, len, &n, 0);
}

static int g_fail = 0;

static void Check(const char* what, int ok)
{
    Out("[surface_smoke] ");
    Out(what);
    Out(ok ? " = PASS\r\n" : " = FAIL\r\n");
    if (!ok)
        ++g_fail;
}

/* 8x8 test surface throughout: small enough that a whole readback is
 * 256 bytes of stack, big enough to have a distinct top row. */
#define SW 8
#define SH 8

/* A 40-byte BITMAPINFOHEADER, built by hand so the fixture does not
 * depend on the SDK struct layout matching ours. `height` keeps its
 * sign: negative = top-down. */
static void MakeHeader(unsigned char* hdr, int width, int height, unsigned short bpp)
{
    int i;
    for (i = 0; i < 40; ++i)
        hdr[i] = 0;
    hdr[0] = 40; /* biSize */
    hdr[4] = (unsigned char)(width & 0xFF);
    hdr[5] = (unsigned char)((width >> 8) & 0xFF);
    hdr[8] = (unsigned char)(height & 0xFF);
    hdr[9] = (unsigned char)((height >> 8) & 0xFF);
    hdr[10] = (unsigned char)((height >> 16) & 0xFF);
    hdr[11] = (unsigned char)((height >> 24) & 0xFF);
    hdr[12] = 1; /* biPlanes */
    hdr[14] = (unsigned char)(bpp & 0xFF);
}

/* Read `bmp` back as a TOP-DOWN 32bpp DIB, so out[y * SW + x] is
 * always the pixel at (x, y) regardless of how it was written. */
static int ReadBack(HBITMAP bmp, unsigned* out)
{
    unsigned char hdr[40];
    MakeHeader(hdr, SW, -SH, 32);
    return GetDIBits(NULL, bmp, 0, SH, out, (BITMAPINFO*)hdr, 0) == SH;
}

/* DIB 32bpp pixel bytes are B,G,R,A. */
static unsigned Bgra(unsigned r, unsigned g, unsigned b)
{
    return (b) | (g << 8) | (r << 16) | 0xFF000000u;
}

void __cdecl mainCRTStartup(void)
{
    HDC mem_dc, dst_dc;
    HBITMAP bmp, dst_bmp, dib;
    unsigned back[SW * SH];
    unsigned src[SW * SH];
    unsigned char hdr[40];
    void* dib_bits = NULL;
    int i, x, y;

    Out("[surface_smoke] starting\r\n");

    mem_dc = CreateCompatibleDC(NULL);
    bmp = CreateCompatibleBitmap(NULL, SW, SH);
    if (mem_dc == NULL || bmp == NULL)
    {
        Check("memory DC + bitmap", 0);
        Out("[ring3-surface-smoke] FAIL no-memory-dc\r\n");
        ExitProcess(1);
    }
    SelectObject(mem_dc, bmp);

    /* --- 1. A fresh surface starts zeroed ----------------------- */
    Check("fresh surface reads back", ReadBack(bmp, back));
    {
        int all_zero = 1;
        for (i = 0; i < SW * SH; ++i)
        {
            if ((back[i] & 0x00FFFFFFu) != 0)
                all_zero = 0;
        }
        Check("fresh surface is zeroed", all_zero);
    }

    /* --- 2. Draw into the memory DC, read the pixels back ------- */
    {
        HBRUSH br = CreateSolidBrush(RGB(0x20, 0x40, 0x80));
        HBRUSH prev = (HBRUSH)SelectObject(mem_dc, br);
        PatBlt(mem_dc, 0, 0, SW, SH, PATCOPY);
        SelectObject(mem_dc, prev);
        DeleteObject(br);
    }
    if (ReadBack(bmp, back))
    {
        int filled = 1;
        const unsigned want = Bgra(0x20, 0x40, 0x80) & 0x00FFFFFFu;
        for (i = 0; i < SW * SH; ++i)
        {
            if ((back[i] & 0x00FFFFFFu) != want)
                filled = 0;
        }
        Check("PatBlt colour lands in the surface", filled);
    }
    else
    {
        Check("PatBlt colour lands in the surface", 0);
    }

    /* --- 3. SetDIBits with a BOTTOM-UP DIB ---------------------- */
    /* Row 0 of a bottom-up DIB is the BOTTOM row of the image, so the
     * marker written last must come back FIRST. If the orientation is
     * mishandled the image arrives vertically mirrored and this check
     * is what notices. */
    for (y = 0; y < SH; ++y)
    {
        for (x = 0; x < SW; ++x)
            src[y * SW + x] = Bgra((unsigned)(y * 16), 0, 0);
    }
    MakeHeader(hdr, SW, SH, 32); /* POSITIVE height == bottom-up */
    Check("SetDIBits (bottom-up) accepted", SetDIBits(NULL, bmp, 0, SH, src, (BITMAPINFO*)hdr, 0) == SH);
    if (ReadBack(bmp, back))
    {
        /* src row 0 is the bottom of the image -> top-down row SH-1.
         * src row SH-1 is the top -> top-down row 0. */
        const unsigned top_want = Bgra((unsigned)((SH - 1) * 16), 0, 0) & 0x00FFFFFFu;
        const unsigned bot_want = Bgra(0, 0, 0) & 0x00FFFFFFu;
        Check("bottom-up DIB is not vertically mirrored",
              (back[0] & 0x00FFFFFFu) == top_want && (back[(SH - 1) * SW] & 0x00FFFFFFu) == bot_want);
    }
    else
    {
        Check("bottom-up DIB is not vertically mirrored", 0);
    }

    /* --- 4. SetDIBits with a TOP-DOWN DIB ----------------------- */
    for (i = 0; i < SW * SH; ++i)
        src[i] = Bgra(0, 0, 0);
    for (x = 0; x < SW; ++x)
        src[x] = Bgra(0, 0xC0, 0); /* first row in memory */
    MakeHeader(hdr, SW, -SH, 32);  /* NEGATIVE height == top-down */
    Check("SetDIBits (top-down) accepted", SetDIBits(NULL, bmp, 0, SH, src, (BITMAPINFO*)hdr, 0) == SH);
    if (ReadBack(bmp, back))
    {
        Check("top-down DIB keeps its first row on top",
              (back[0] & 0x00FFFFFFu) == (Bgra(0, 0xC0, 0) & 0x00FFFFFFu) && (back[SW] & 0x00FFFFFFu) == 0);
    }
    else
    {
        Check("top-down DIB keeps its first row on top", 0);
    }

    /* --- 5. Memory DC -> memory DC blit ------------------------- */
    dst_dc = CreateCompatibleDC(NULL);
    dst_bmp = CreateCompatibleBitmap(NULL, SW, SH);
    if (dst_dc != NULL && dst_bmp != NULL)
    {
        SelectObject(dst_dc, dst_bmp);
        Check("BitBlt mem->mem accepted", BitBlt(dst_dc, 0, 0, SW, SH, mem_dc, 0, 0, SRCCOPY) != 0);
        if (ReadBack(dst_bmp, back))
        {
            Check("blitted pixels arrived at the destination",
                  (back[0] & 0x00FFFFFFu) == (Bgra(0, 0xC0, 0) & 0x00FFFFFFu));
        }
        else
        {
            Check("blitted pixels arrived at the destination", 0);
        }
    }
    else
    {
        Check("BitBlt mem->mem accepted", 0);
    }

    /* --- 6. CreateDIBSection: write straight through the pointer  */
    MakeHeader(hdr, SW, -SH, 32);
    dib = CreateDIBSection(NULL, (BITMAPINFO*)hdr, 0, &dib_bits, NULL, 0);
    if (dib != NULL && dib_bits != NULL)
    {
        HDC dib_dc = CreateCompatibleDC(NULL);
        unsigned* px = (unsigned*)dib_bits;
        for (i = 0; i < SW * SH; ++i)
            px[i] = Bgra(0xFF, 0x00, 0xFF);
        if (dib_dc != NULL)
        {
            SelectObject(dib_dc, dib);
            /* The blit is what pushes the caller's writes down. */
            BitBlt(dst_dc, 0, 0, SW, SH, dib_dc, 0, 0, SRCCOPY);
            if (ReadBack(dst_bmp, back))
            {
                Check("DIB section pixels reach the surface",
                      (back[0] & 0x00FFFFFFu) == (Bgra(0xFF, 0x00, 0xFF) & 0x00FFFFFFu));
            }
            else
            {
                Check("DIB section pixels reach the surface", 0);
            }
            DeleteDC(dib_dc);
        }
        DeleteObject(dib);
    }
    else
    {
        Check("CreateDIBSection returns a writable buffer", 0);
    }

    /* --- 7. Refusals ------------------------------------------- */
    /* 65536 * 65536 wraps a 32-bit pixel count to zero. A surface
     * that "succeeds" here allocated nothing and will be written
     * past on the first blit. */
    Check("overflowing CreateCompatibleBitmap is refused", CreateCompatibleBitmap(NULL, 65536, 65536) == NULL);
    Check("oversize CreateCompatibleBitmap is refused", CreateCompatibleBitmap(NULL, 4096, 4096) == NULL);

    /* A header that claims 1024 rows against a buffer holding 8. The
     * declared byte count is derived from the header, so the kernel
     * cannot catch this arithmetically — CopyFromUser has to stop at
     * the end of the caller's mapping. What that guarantees is a
     * SHORT transfer, not a refusal, and a short transfer is exactly
     * the evidence that nothing was read past the buffer. A full
     * 1024-row "success" would mean the kernel read 32 KiB out of a
     * 256-byte allocation. */
    MakeHeader(hdr, SW, -1024, 32);
    Check("DIB claiming more rows than its buffer holds is truncated",
          SetDIBits(NULL, bmp, 0, 1024, src, (BITMAPINFO*)hdr, 0) < 1024);

    /* Palettised depths are not converted; better refused than
     * rendered as noise. */
    MakeHeader(hdr, SW, -SH, 8);
    Check("8bpp DIB is refused", SetDIBits(NULL, bmp, 0, SH, src, (BITMAPINFO*)hdr, 0) == 0);

    DeleteObject(dst_bmp);
    DeleteDC(dst_dc);
    DeleteObject(bmp);
    DeleteDC(mem_dc);

    /* --- 8. Deliberate leak ------------------------------------ */
    /* Everything above is released properly, which means it proves
     * nothing about teardown. The GDI tables are system-wide, so a
     * process that exits still holding objects used to strand both
     * the pixel bytes and the table slots for the rest of the boot.
     *
     * These four are intentionally NOT deleted. ProcessRelease has to
     * reclaim them, and it says so on the wire:
     *
     *     [gdi] reap pid=<pid> objects=0x4 bytes=0x...
     *
     * The absence of that line on a boot is the regression signal.
     * Sized 64x64 (16 KiB) so the byte count is unmistakable. */
    {
        HDC leak_dc = CreateCompatibleDC(NULL);
        HBITMAP leak_bmp = CreateCompatibleBitmap(NULL, 64, 64);
        HBRUSH leak_brush = CreateSolidBrush(RGB(1, 2, 3));
        HPEN leak_pen = CreatePen(0, 1, RGB(4, 5, 6));
        if (leak_dc && leak_bmp)
            SelectObject(leak_dc, leak_bmp);
        Check("leak fixture allocated (reaper input)",
              leak_dc != NULL && leak_bmp != NULL && leak_brush != NULL && leak_pen != NULL);
        /* No DeleteObject / DeleteDC here. That is the point. */
    }

    /* The one line the battery aggregator scans for. Label must match
     * this fixture's kPeCompatBattery row exactly. */
    if (g_fail == 0)
        Out("[ring3-surface-smoke] PASS\r\n");
    else
        Out("[ring3-surface-smoke] FAIL pixel-roundtrip\r\n");
    ExitProcess(g_fail == 0 ? 0 : 1);
}
