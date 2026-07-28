/*
 * userland/libs/common/duet32_gdi_abi.h
 *
 * The handle encodings the i386 (PE32) user32 and gdi32 companion
 * DLLs must agree on. They live here rather than in either DLL
 * because both sides create AND consume them: user32's GetDC and
 * BeginPaint mint HDCs that gdi32's draw calls decode, and user32's
 * FillRect decodes brushes that gdi32's CreateSolidBrush minted.
 * Two private copies of these constants is the sentinel-divergence
 * bug waiting to happen.
 *
 * Real Windows splits the drawing surface across the two DLLs by
 * history, not by layer: FillRect, FrameRect, DrawText, GetDC and
 * BeginPaint are USER32 exports even though they draw, while
 * TextOut, Rectangle and the object constructors are GDI32. An
 * importer resolves against whichever DLL Windows homes the symbol
 * in, so both DLLs must be able to speak this ABI.
 */

#ifndef DUETOS_COMMON_DUET32_GDI_ABI_H
#define DUETOS_COMMON_DUET32_GDI_ABI_H

/* HDC = biased HWND | tag. HWNDs are small compositor indices, so
 * the top byte is free and the tag cannot collide with a real
 * handle. The 64-bit pair uses 0xDC00000000 for the same purpose;
 * an i386 HDC is only 32 bits wide, so the tag moves down. */
#define DUET32_GDI_HDC_TAG 0xDC000000u

/* Pens and brushes are self-describing: a type nibble over the BGR
 * colour. No allocation table, so nothing leaks and SelectObject is
 * a pointer assignment. */
#define DUET32_GDI_BRUSH_TAG 0xB0000000u
#define DUET32_GDI_PEN_TAG 0xA0000000u
#define DUET32_GDI_COLOUR_MASK 0x00FFFFFFu
#define DUET32_GDI_TYPE_MASK 0xF0000000u

/* Recover the target window from a DC, or 0 when the DC is not a
 * window DC (a memory DC, or garbage). */
static inline unsigned Duet32HwndFromHdc(const void* dc)
{
    const unsigned v = (unsigned)(unsigned long)dc;
    if ((v & DUET32_GDI_HDC_TAG) != DUET32_GDI_HDC_TAG)
        return 0;
    return v & ~DUET32_GDI_HDC_TAG;
}

/* Colour carried by a brush or pen handle; 0 (black) for anything
 * that is not one of ours, which is also what a NULL brush means. */
static inline unsigned Duet32GdiObjectColour(const void* obj, unsigned tag)
{
    const unsigned v = (unsigned)(unsigned long)obj;
    if ((v & DUET32_GDI_TYPE_MASK) != tag)
        return 0;
    return v & DUET32_GDI_COLOUR_MASK;
}

#endif /* DUETOS_COMMON_DUET32_GDI_ABI_H */
