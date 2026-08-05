/*
 * bitmap_smoke — PE32 (i386) test image for the RT_BITMAP resource
 * loading rung. Has a genuine .rsrc section with an 8x8 24bpp bitmap
 * compiled by windres, and exercises LoadBitmapW and
 * LoadImageW(IMAGE_BITMAP) to prove the real RT_BITMAP packed-DIB
 * decode path works end-to-end from ring 3 via the IAT.
 *
 * What each step proves:
 *
 *   1. LoadBitmapW(hInst, MAKEINTRESOURCE(1)) returns non-NULL
 *      (PE bitmap decoded and uploaded to a GDI bitmap).
 *   2. LoadImageW(hInst, MAKEINTRESOURCE(1), IMAGE_BITMAP, 0, 0, 0)
 *      returns non-NULL (LoadImage dispatch).
 *   3. LoadBitmapW(hInst, MAKEINTRESOURCE(99)) returns NULL
 *      (missing id fails closed).
 *   4. LoadBitmapW(NULL, MAKEINTRESOURCE(1)) returns NULL
 *      (no module, no .rsrc — Win32 has no system-bitmap fallback).
 *
 * Built with i686-w64-mingw32-gcc + i686-w64-mingw32-windres,
 * freestanding, entry mainCRTStartup.
 */

typedef void* HANDLE;
typedef unsigned long DWORD;
typedef unsigned int UINT;
typedef int BOOL;
typedef unsigned short WCHAR;

#define STD_OUTPUT_HANDLE ((DWORD) - 11)
#define MAKEINTRESOURCEW(i) ((const WCHAR*)(unsigned long)(unsigned short)(i))
#define IMAGE_BITMAP 0

/* kernel32 */
__declspec(dllimport) void __stdcall ExitProcess(unsigned);
__declspec(dllimport) HANDLE __stdcall GetStdHandle(DWORD);
__declspec(dllimport) BOOL __stdcall WriteConsoleA(HANDLE, const void*, DWORD, DWORD*, void*);
__declspec(dllimport) HANDLE __stdcall GetModuleHandleW(const WCHAR*);

/* user32 */
__declspec(dllimport) HANDLE __stdcall LoadBitmapW(HANDLE, const WCHAR*);
__declspec(dllimport) HANDLE __stdcall LoadImageW(HANDLE, const WCHAR*, UINT, int, int, UINT);

static int g_failures = 0;

static void Out(const char* s)
{
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD n = 0;
    DWORD len = 0;
    while (s[len] != '\0')
        ++len;
    WriteConsoleA(h, s, len, &n, 0);
}

static void Check(const char* what, int ok)
{
    Out("[bitmap_smoke] ");
    Out(what);
    Out(ok ? " = PASS\r\n" : " = FAIL\r\n");
    if (!ok)
        ++g_failures;
}

void __cdecl mainCRTStartup(void)
{
    HANDLE me = GetModuleHandleW(0);

    Out("[bitmap_smoke] starting\r\n");

    /* 1. PE bitmap (id 1 from bitmap_smoke.rc). */
    {
        HANDLE h = LoadBitmapW(me, MAKEINTRESOURCEW(1));
        Check("LoadBitmapW(pe)     ", h != 0);
    }

    /* 2. LoadImageW dispatch for IMAGE_BITMAP. */
    {
        HANDLE h = LoadImageW(me, MAKEINTRESOURCEW(1), IMAGE_BITMAP, 0, 0, 0);
        Check("LoadImageW(bitmap)  ", h != 0);
    }

    /* 3. Missing id fails closed. */
    {
        HANDLE h = LoadBitmapW(me, MAKEINTRESOURCEW(99));
        Check("LoadBitmapW(missing)", h == 0);
    }

    /* 4. NULL hInstance fails closed (no system-bitmap fallback). */
    {
        HANDLE h = LoadBitmapW(0, MAKEINTRESOURCEW(1));
        Check("LoadBitmapW(null)   ", h == 0);
    }

    if (g_failures == 0)
        Out("[ring3-bitmap-smoke] PASS\r\n");
    else
        Out("[ring3-bitmap-smoke] FAIL bitmap checks did not all pass\r\n");
    ExitProcess(g_failures == 0 ? 0x42 : 1);
}
