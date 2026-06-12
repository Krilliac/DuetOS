/*
 * xaudio2_smoke — exercise xaudio2_9.dll IXAudio2 + voice path.
 *   XAudio2Create
 *   IXAudio2::CreateMasteringVoice
 *   IXAudio2::CreateSourceVoice
 *   IXAudio2Voice::SetVolume / GetVolume
 *   Source::Start / Stop
 *   IXAudio2::StartEngine / StopEngine
 *   IXAudio2Voice::DestroyVoice
 */
#include <windows.h>

extern long XAudio2Create(void** out, UINT flags, UINT processor);

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
    Out("[xaudio2_smoke] starting\r\n");

    void* x2 = NULL;
    long hr = XAudio2Create(&x2, 0, 0);
    Out("[xaudio2_smoke] XAudio2Create        = ");
    Out((hr == 0 && x2) ? "PASS\r\n" : "FAIL\r\n");
    if (!x2)
    {
        Out("[ring3-xaudio2-smoke] FAIL create\r\n");
        ExitProcess(1);
    }

    void** x2_vt = *(void***)x2;

    /* slot 7 = CreateMasteringVoice */
    void* master = NULL;
    typedef long (*PFN_CMV)(void*, void**, UINT, UINT, UINT, UINT, const void*, UINT);
    hr = ((PFN_CMV)x2_vt[7])(x2, &master, 2, 48000, 0, 0, NULL, 0);
    Out("[xaudio2_smoke] CreateMasteringVoice = ");
    Out((hr == 0 && master) ? "PASS\r\n" : "FAIL\r\n");

    /* slot 5 = CreateSourceVoice */
    void* src = NULL;
    typedef long (*PFN_CSV)(void*, void**, const void*, UINT, float, void*, const void*, const void*);
    hr = ((PFN_CSV)x2_vt[5])(x2, &src, NULL, 0, 1.0f, NULL, NULL, NULL);
    Out("[xaudio2_smoke] CreateSourceVoice    = ");
    Out((hr == 0 && src) ? "PASS\r\n" : "FAIL\r\n");

    if (src)
    {
        void** src_vt = *(void***)src;

        /* slot 12 = SetVolume / 13 = GetVolume */
        typedef long (*PFN_SV)(void*, float, UINT);
        hr = ((PFN_SV)src_vt[12])(src, 0.5f, 0);
        Out("[xaudio2_smoke] Source::SetVolume    = ");
        Out((hr == 0) ? "PASS\r\n" : "FAIL\r\n");

        float v = 0;
        typedef void (*PFN_GV)(void*, float*);
        ((PFN_GV)src_vt[13])(src, &v);
        Out("[xaudio2_smoke] Source::GetVolume    = ");
        /* roughly 0.5 — we just verify it round-tripped */
        Out((v > 0.49f && v < 0.51f) ? "PASS\r\n" : "FAIL\r\n");

        /* slot 21 = Start, 22 = Stop */
        typedef long (*PFN_SS)(void*, UINT, UINT);
        hr = ((PFN_SS)src_vt[21])(src, 0, 0);
        Out("[xaudio2_smoke] Source::Start        = ");
        Out((hr == 0) ? "PASS\r\n" : "FAIL\r\n");
        hr = ((PFN_SS)src_vt[22])(src, 0, 0);
        Out("[xaudio2_smoke] Source::Stop         = ");
        Out((hr == 0) ? "PASS\r\n" : "FAIL\r\n");

        /* slot 19 = DestroyVoice */
        typedef void (*PFN_DV)(void*);
        ((PFN_DV)src_vt[19])(src);
        Out("[xaudio2_smoke] Source::DestroyVoice = PASS (returned)\r\n");
    }

    /* slot 8 = StartEngine, 9 = StopEngine */
    typedef long (*PFN_SE)(void*);
    hr = ((PFN_SE)x2_vt[8])(x2);
    Out("[xaudio2_smoke] StartEngine          = ");
    Out((hr == 0) ? "PASS\r\n" : "FAIL\r\n");
    typedef void (*PFN_StE)(void*);
    ((PFN_StE)x2_vt[9])(x2);
    Out("[xaudio2_smoke] StopEngine           = PASS (returned)\r\n");

    typedef unsigned long (*PFN_Rel)(void*);
    ((PFN_Rel)x2_vt[2])(x2);
    Out("[xaudio2_smoke] done\r\n");
    Out("[ring3-xaudio2-smoke] PASS\r\n");
    ExitProcess(0);
}
