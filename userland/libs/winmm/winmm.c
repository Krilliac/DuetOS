/*
 * userland/libs/winmm/winmm.c — 8 multimedia timer / sound stubs.
 * timeGetTime returns ms since boot; rest are pretend-success.
 */

typedef unsigned int UINT;
typedef unsigned int MMRESULT;
typedef unsigned int DWORD;
typedef unsigned short wchar_t16;
typedef void* HANDLE;

#define MMSYSERR_NOERROR 0U

/* timeGetTime — ms since boot via SYS_PERF_COUNTER (13) * 10. */
__declspec(dllexport) DWORD timeGetTime(void)
{
    long long rv;
    __asm__ volatile("int $0x80" : "=a"(rv) : "a"((long long)13) : "memory");
    return (DWORD)((unsigned long long)rv * 10ULL);
}

__declspec(dllexport) MMRESULT timeBeginPeriod(UINT period)
{
    (void)period;
    return MMSYSERR_NOERROR;
}

__declspec(dllexport) MMRESULT timeEndPeriod(UINT period)
{
    (void)period;
    return MMSYSERR_NOERROR;
}

__declspec(dllexport) MMRESULT timeGetDevCaps(void* caps, UINT size)
{
    (void)size;
    if (caps)
    {
        UINT* c = (UINT*)caps;
        c[0] = 1;       /* wPeriodMin = 1 ms */
        c[1] = 1000000; /* wPeriodMax */
    }
    return MMSYSERR_NOERROR;
}

__declspec(dllexport) UINT timeSetEvent(UINT delay, UINT resolution, void* cb, unsigned long long user, UINT flags)
{
    (void)delay;
    (void)resolution;
    (void)cb;
    (void)user;
    (void)flags;
    return 0; /* NULL MMTIMER handle — caller sees failure, no callback fires. */
}

__declspec(dllexport) MMRESULT timeKillEvent(UINT id)
{
    (void)id;
    return MMSYSERR_NOERROR;
}

__declspec(dllexport) int PlaySoundW(const wchar_t16* name, HANDLE hmod, DWORD flags)
{
    (void)name;
    (void)hmod;
    (void)flags;
    return 0; /* No audio; pretend no-sound. */
}

__declspec(dllexport) MMRESULT mciSendStringW(const wchar_t16* cmd, wchar_t16* ret, UINT ret_len, HANDLE cb)
{
    (void)cmd;
    (void)cb;
    if (ret && ret_len > 0)
        ret[0] = 0;
    return 0x110; /* MCIERR_UNSUPPORTED_FUNCTION */
}

/* PlaySoundA — narrow alias of PlaySoundW (shares the no-audio
 * v0 semantic). */
__declspec(dllexport) int PlaySoundA(const char* name, HANDLE hmod, DWORD flags)
{
    (void)name;
    (void)hmod;
    (void)flags;
    return 0;
}

__declspec(dllexport) MMRESULT mciSendStringA(const char* cmd, char* ret, UINT ret_len, HANDLE cb)
{
    (void)cmd;
    (void)cb;
    if (ret && ret_len > 0)
        ret[0] = 0;
    return 0x110;
}

/* waveOut*: digital-audio output. v0 has no audio backend wired
 * to user-mode, so each call pretends success but no-ops. Common
 * games / tools probe this at startup. */
__declspec(dllexport) UINT waveOutGetNumDevs(void)
{
    return 0; /* No devices. */
}

__declspec(dllexport) MMRESULT waveOutOpen(HANDLE* h, UINT id, const void* fmt, void* cb, unsigned long long user,
                                           DWORD flags)
{
    (void)id;
    (void)fmt;
    (void)cb;
    (void)user;
    (void)flags;
    if (h)
        *h = (HANDLE)0;
    return 0x6; /* MMSYSERR_NODRIVER — caller falls back. */
}

__declspec(dllexport) MMRESULT waveOutClose(HANDLE h)
{
    (void)h;
    return MMSYSERR_NOERROR;
}

__declspec(dllexport) MMRESULT waveOutPrepareHeader(HANDLE h, void* hdr, UINT cb)
{
    (void)h;
    (void)hdr;
    (void)cb;
    return MMSYSERR_NOERROR;
}

__declspec(dllexport) MMRESULT waveOutUnprepareHeader(HANDLE h, void* hdr, UINT cb)
{
    (void)h;
    (void)hdr;
    (void)cb;
    return MMSYSERR_NOERROR;
}

__declspec(dllexport) MMRESULT waveOutWrite(HANDLE h, void* hdr, UINT cb)
{
    (void)h;
    (void)hdr;
    (void)cb;
    return MMSYSERR_NOERROR;
}

__declspec(dllexport) MMRESULT waveOutReset(HANDLE h)
{
    (void)h;
    return MMSYSERR_NOERROR;
}

__declspec(dllexport) MMRESULT waveOutSetVolume(HANDLE h, DWORD vol)
{
    (void)h;
    (void)vol;
    return MMSYSERR_NOERROR;
}

__declspec(dllexport) MMRESULT waveOutGetVolume(HANDLE h, DWORD* vol)
{
    (void)h;
    if (vol)
        *vol = 0xFFFFFFFFu; /* max volume */
    return MMSYSERR_NOERROR;
}
