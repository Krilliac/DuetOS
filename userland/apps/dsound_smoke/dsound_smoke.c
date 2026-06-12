/*
 * dsound_smoke — exercise dsound.dll IDirectSound + buffer.
 *   DirectSoundCreate8
 *   IDirectSound::SetCooperativeLevel
 *   IDirectSound::CreateSoundBuffer
 *   IDirectSoundBuffer::Lock / Unlock / Play / Stop
 *   IDirectSoundBuffer::GetCurrentPosition
 */
#include <windows.h>

extern long DirectSoundCreate8(const void* guid, void** out, void* unk);

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
    Out("[dsound_smoke] starting\r\n");

    void* ds = NULL;
    long hr = DirectSoundCreate8(NULL, &ds, NULL);
    Out("[dsound_smoke] DirectSoundCreate8       = ");
    Out((hr == 0 && ds) ? "PASS\r\n" : "FAIL\r\n");
    if (!ds)
    {
        Out("[ring3-dsound-smoke] FAIL create\r\n");
        ExitProcess(1);
    }

    void** ds_vt = *(void***)ds;

    /* slot 6 = SetCooperativeLevel */
    typedef long (*PFN_SCL)(void*, HWND, DWORD);
    hr = ((PFN_SCL)ds_vt[6])(ds, NULL, 1 /*DSSCL_NORMAL*/);
    Out("[dsound_smoke] SetCooperativeLevel      = ");
    Out((hr == 0) ? "PASS\r\n" : "FAIL\r\n");

    /* DSBUFFERDESC layout (40B):
     *   +0 dwSize, +4 dwFlags, +8 dwBufferBytes, +12 dwReserved,
     *   +16 lpwfxFormat (8B aligned), +24 guid3DAlgorithm
     * Set BufferBytes=4096 + lpwfxFormat=NULL (DLL fills 48k stereo). */
    BYTE desc[40] = {0};
    *(DWORD*)(desc + 0) = sizeof(desc);
    *(DWORD*)(desc + 8) = 4096;

    /* slot 3 = CreateSoundBuffer */
    void* buf = NULL;
    typedef long (*PFN_CSB)(void*, const void*, void**, void*);
    hr = ((PFN_CSB)ds_vt[3])(ds, desc, &buf, NULL);
    Out("[dsound_smoke] CreateSoundBuffer        = ");
    Out((hr == 0 && buf) ? "PASS\r\n" : "FAIL\r\n");

    if (buf)
    {
        void** b_vt = *(void***)buf;

        /* slot 11 = Lock */
        void* p1 = NULL;
        DWORD n1 = 0;
        typedef long (*PFN_Lock)(void*, DWORD, DWORD, void**, DWORD*, void**, DWORD*, DWORD);
        hr = ((PFN_Lock)b_vt[11])(buf, 0, 4096, &p1, &n1, NULL, NULL, 0);
        Out("[dsound_smoke] Buffer::Lock             = ");
        Out((hr == 0 && p1 && n1 == 4096) ? "PASS\r\n" : "FAIL\r\n");

        /* Write a sentinel byte so we know the pointer is real. */
        if (p1)
            *(BYTE*)p1 = 0xAA;

        /* slot 19 = Unlock */
        typedef long (*PFN_Unlock)(void*, void*, DWORD, void*, DWORD);
        hr = ((PFN_Unlock)b_vt[19])(buf, p1, n1, NULL, 0);
        Out("[dsound_smoke] Buffer::Unlock           = ");
        Out((hr == 0) ? "PASS\r\n" : "FAIL\r\n");

        /* slot 12 = Play */
        typedef long (*PFN_Play)(void*, DWORD, DWORD, DWORD);
        hr = ((PFN_Play)b_vt[12])(buf, 0, 0, 0 /*DSBPLAY_LOOPING off*/);
        Out("[dsound_smoke] Buffer::Play             = ");
        Out((hr == 0) ? "PASS\r\n" : "FAIL\r\n");

        /* slot 4 = GetCurrentPosition */
        DWORD play = 0, write = 0;
        typedef long (*PFN_GCP)(void*, DWORD*, DWORD*);
        hr = ((PFN_GCP)b_vt[4])(buf, &play, &write);
        Out("[dsound_smoke] Buffer::GetCurrentPos    = ");
        Out((hr == 0) ? "PASS\r\n" : "FAIL\r\n");

        /* slot 18 = Stop */
        typedef long (*PFN_Stop)(void*);
        hr = ((PFN_Stop)b_vt[18])(buf);
        Out("[dsound_smoke] Buffer::Stop             = ");
        Out((hr == 0) ? "PASS\r\n" : "FAIL\r\n");

        typedef unsigned long (*PFN_Rel)(void*);
        ((PFN_Rel)b_vt[2])(buf);
    }

    typedef unsigned long (*PFN_Rel)(void*);
    ((PFN_Rel)ds_vt[2])(ds);
    Out("[dsound_smoke] done\r\n");
    Out("[ring3-dsound-smoke] PASS\r\n");
    ExitProcess(0);
}
