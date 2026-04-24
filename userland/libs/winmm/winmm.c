/*
 * userland/libs/winmm/winmm.c — 8 multimedia timer / sound stubs.
 * timeGetTime returns ms since boot; rest are pretend-success.
 */

typedef unsigned int   UINT;
typedef unsigned int   MMRESULT;
typedef unsigned int   DWORD;
typedef unsigned short wchar_t16;
typedef void*          HANDLE;

#define MMSYSERR_NOERROR 0U

/* timeGetTime — ms since boot via SYS_PERF_COUNTER (13) * 10. */
__declspec(dllexport) DWORD timeGetTime(void)
{
    long long rv;
    __asm__ volatile("int $0x80" : "=a"(rv) : "a"((long long) 13) : "memory");
    return (DWORD) ((unsigned long long) rv * 10ULL);
}

__declspec(dllexport) MMRESULT timeBeginPeriod(UINT period)
{
    (void) period;
    return MMSYSERR_NOERROR;
}

__declspec(dllexport) MMRESULT timeEndPeriod(UINT period)
{
    (void) period;
    return MMSYSERR_NOERROR;
}

__declspec(dllexport) MMRESULT timeGetDevCaps(void* caps, UINT size)
{
    (void) size;
    if (caps)
    {
        UINT* c = (UINT*) caps;
        c[0]    = 1;      /* wPeriodMin = 1 ms */
        c[1]    = 1000000; /* wPeriodMax */
    }
    return MMSYSERR_NOERROR;
}

__declspec(dllexport) UINT timeSetEvent(UINT delay, UINT resolution, void* cb, unsigned long long user, UINT flags)
{
    (void) delay;
    (void) resolution;
    (void) cb;
    (void) user;
    (void) flags;
    return 0; /* NULL MMTIMER handle — caller sees failure, no callback fires. */
}

__declspec(dllexport) MMRESULT timeKillEvent(UINT id)
{
    (void) id;
    return MMSYSERR_NOERROR;
}

__declspec(dllexport) int PlaySoundW(const wchar_t16* name, HANDLE hmod, DWORD flags)
{
    (void) name;
    (void) hmod;
    (void) flags;
    return 0; /* No audio; pretend no-sound. */
}

__declspec(dllexport) MMRESULT mciSendStringW(const wchar_t16* cmd, wchar_t16* ret, UINT ret_len, HANDLE cb)
{
    (void) cmd;
    (void) cb;
    if (ret && ret_len > 0)
        ret[0] = 0;
    return 0x110; /* MCIERR_UNSUPPORTED_FUNCTION */
}
