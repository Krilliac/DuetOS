/*
 * ddraw_smoke — exercise ddraw.dll IDirectDraw7 + surface.
 *   DirectDrawCreate
 *   IDirectDraw7::SetCooperativeLevel
 *   IDirectDraw7::SetDisplayMode
 *   IDirectDraw7::CreateSurface (offscreen)
 *   IDirectDrawSurface7::Lock / Unlock / Blt(COLORFILL)
 */
#include <windows.h>

extern long DirectDrawCreate(const void* guid, void** out, void* unk);

static void Out(const char* s)
{
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD n = 0, len = 0;
    while (s[len])
        ++len;
    WriteConsoleA(h, s, len, &n, 0);
}

void __cdecl mainCRTStartup(void)
{
    Out("[ddraw_smoke] starting\r\n");

    void* dd = NULL;
    long hr = DirectDrawCreate(NULL, &dd, NULL);
    Out("[ddraw_smoke] DirectDrawCreate         = ");
    Out((hr == 0 && dd) ? "PASS\r\n" : "FAIL\r\n");
    if (!dd)
        ExitProcess(1);

    void** dd_vt = *(void***)dd;

    /* slot 20 = SetCooperativeLevel */
    typedef long (*PFN_SCL)(void*, HWND, DWORD);
    hr = ((PFN_SCL)dd_vt[20])(dd, NULL, 8 /*DDSCL_NORMAL*/);
    Out("[ddraw_smoke] SetCooperativeLevel      = ");
    Out((hr == 0) ? "PASS\r\n" : "FAIL\r\n");

    /* slot 21 = SetDisplayMode */
    typedef long (*PFN_SDM)(void*, DWORD, DWORD, DWORD, DWORD, DWORD);
    hr = ((PFN_SDM)dd_vt[21])(dd, 320, 240, 32, 60, 0);
    Out("[ddraw_smoke] SetDisplayMode(320x240)  = ");
    Out((hr == 0) ? "PASS\r\n" : "FAIL\r\n");

    /* DDSURFACEDESC2 (124B): set width/height + caps=offscreen */
    BYTE desc[124];
    for (UINT i = 0; i < sizeof(desc); ++i)
        desc[i] = 0;
    *(DWORD*)(desc + 0) = 124;                       /* dwSize */
    *(DWORD*)(desc + 4) = 0x1 | 0x2 | 0x4 | 0x40000; /* CAPS|HEIGHT|WIDTH|PIXELFORMAT */
    *(DWORD*)(desc + 12) = 320;                      /* dwWidth */
    *(DWORD*)(desc + 16) = 240;                      /* dwHeight */
    *(DWORD*)(desc + 108) = 0x40;                    /* DDSCAPS_OFFSCREENPLAIN */

    /* slot 6 = CreateSurface */
    void* surf = NULL;
    typedef long (*PFN_CS)(void*, const void*, void**, void*);
    hr = ((PFN_CS)dd_vt[6])(dd, desc, &surf, NULL);
    Out("[ddraw_smoke] CreateSurface            = ");
    Out((hr == 0 && surf) ? "PASS\r\n" : "FAIL\r\n");

    if (surf)
    {
        void** s_vt = *(void***)surf;

        /* slot 25 = Lock */
        BYTE lock_desc[124];
        for (UINT i = 0; i < sizeof(lock_desc); ++i)
            lock_desc[i] = 0;
        *(DWORD*)(lock_desc + 0) = 124;
        typedef long (*PFN_Lock)(void*, void*, void*, DWORD, HANDLE);
        hr = ((PFN_Lock)s_vt[25])(surf, NULL, lock_desc, 0, NULL);
        void* surface_ptr = *(void**)(lock_desc + 36);
        Out("[ddraw_smoke] Surface::Lock            = ");
        Out((hr == 0 && surface_ptr) ? "PASS\r\n" : "FAIL\r\n");

        /* Touch the locked memory to verify it's mapped. */
        if (surface_ptr)
            *(BYTE*)surface_ptr = 0xCD;

        /* slot 32 = Unlock */
        typedef long (*PFN_Unlock)(void*, void*);
        hr = ((PFN_Unlock)s_vt[32])(surf, NULL);
        Out("[ddraw_smoke] Surface::Unlock          = ");
        Out((hr == 0) ? "PASS\r\n" : "FAIL\r\n");

        /* slot 5 = Blt with COLORFILL. fx struct: dwSize@0 + ... + dwFillColor@12 */
        BYTE fx[100];
        for (UINT i = 0; i < sizeof(fx); ++i)
            fx[i] = 0;
        *(DWORD*)(fx + 0) = sizeof(fx);
        *(DWORD*)(fx + 12) = 0xff00ff00; /* green */
        typedef long (*PFN_Blt)(void*, void*, void*, void*, DWORD, void*);
        hr = ((PFN_Blt)s_vt[5])(surf, NULL, NULL, NULL, 0x0400 /*DDBLT_COLORFILL*/, fx);
        Out("[ddraw_smoke] Surface::Blt(COLORFILL)  = ");
        Out((hr == 0) ? "PASS\r\n" : "FAIL\r\n");

        typedef unsigned long (*PFN_Rel)(void*);
        ((PFN_Rel)s_vt[2])(surf);
    }

    typedef unsigned long (*PFN_Rel)(void*);
    ((PFN_Rel)dd_vt[2])(dd);
    Out("[ddraw_smoke] done\r\n");
    ExitProcess(0);
}
