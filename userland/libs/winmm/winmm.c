/*
 * userland/libs/winmm/winmm.c — multimedia timer + sound stubs.
 * timeGetTime returns ms since boot; timeSetEvent runs callbacks
 * from a polling service thread (~10 ms cadence); the rest of the
 * surface is pretend-success.
 */

typedef unsigned int UINT;
typedef unsigned int MMRESULT;
typedef unsigned int DWORD;
typedef unsigned long long ULONGLONG;
typedef unsigned long long DWORD_PTR;
typedef unsigned long SIZE_T;
typedef unsigned short wchar_t16;
typedef int BOOL;
typedef void* HANDLE;

#define MMSYSERR_NOERROR 0U
#define TIME_PERIODIC 0x0001U

/* timeGetTime — ms since boot via SYS_PERF_COUNTER (13) * 10. */
__declspec(dllexport) DWORD timeGetTime(void)
{
    long long rv;
    __asm__ volatile("int $0x80" : "=a"(rv) : "a"((long long)13) : "memory");
    return (DWORD)((unsigned long long)rv * 10ULL);
}

/* GetTickCount64 equivalent for the timer service. SYS_PERF_COUNTER
 * (13) returns 10-ms ticks since boot; multiply for ms. */
static ULONGLONG winmm_now_ms(void)
{
    long long rv;
    __asm__ volatile("int $0x80" : "=a"(rv) : "a"((long long)13) : "memory");
    return (ULONGLONG)rv * 10ULL;
}

/* The build pipeline links each stub DLL standalone (no
 * kernel32.dll import library), so reach the kernel directly via
 * the same int-0x80 surface kernel32 uses internally:
 *   SYS_THREAD_CREATE = 45 (rdi = start VA, rsi = arg)
 *   SYS_SLEEP_MS      = 19 (rdi = ms)
 *   SYS_EVENT_SET     = 31 (rdi = event handle)
 *   SYS_EVENT_RESET   = 32 (rdi = event handle) */
typedef DWORD (*WINMM_THREAD_FN)(void*);
static long long winmm_thread_create(WINMM_THREAD_FN fn, void* arg)
{
    long long rv;
    __asm__ volatile("int $0x80" : "=a"(rv) : "a"((long long)45), "D"((long long)fn), "S"((long long)arg) : "memory");
    return rv;
}
static void winmm_sleep_ms(DWORD ms)
{
    long long rv;
    __asm__ volatile("int $0x80" : "=a"(rv) : "a"((long long)19), "D"((long long)ms) : "memory");
    (void)rv;
}
static void winmm_event_set(void* handle)
{
    if (handle == (void*)0)
        return;
    long long rv;
    __asm__ volatile("int $0x80" : "=a"(rv) : "a"((long long)31), "D"((long long)handle) : "memory");
    (void)rv;
}
static void winmm_event_reset(void* handle)
{
    if (handle == (void*)0)
        return;
    long long rv;
    __asm__ volatile("int $0x80" : "=a"(rv) : "a"((long long)32), "D"((long long)handle) : "memory");
    (void)rv;
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

/* timeSetEvent v0. A polling service thread runs every 10 ms,
 * fires callbacks whose due time has arrived, and re-arms periodic
 * ones. Single-shot timers self-deactivate on fire. timeKillEvent
 * deactivates a slot by id.
 *
 * Callback shapes honoured (low nibble of `flags`):
 *   TIME_CALLBACK_FUNCTION  (0x00) — call `cb` as TIMECALLBACK.
 *   TIME_CALLBACK_EVENT_SET (0x10) — treat `cb` as HANDLE,
 *                                    SetEvent it (signaled).
 *   TIME_CALLBACK_EVENT_PULSE (0x20) — treat `cb` as HANDLE,
 *                                    SetEvent then ResetEvent (a
 *                                    close-enough PulseEvent — wakes
 *                                    any waiter that was already in
 *                                    the wait, then drops the
 *                                    signal). Real Win32 PulseEvent
 *                                    is deprecated and famously
 *                                    racy; the SetEvent+ResetEvent
 *                                    pair is the documented
 *                                    workaround.
 *
 * Out of scope:
 *   - Sub-10 ms resolution (the polling cadence is the floor).
 */
typedef void(__stdcall* TIMECALLBACK)(UINT uTimerID, UINT uMsg, DWORD_PTR dwUser, DWORD_PTR dw1, DWORD_PTR dw2);

#define TIME_CALLBACK_FUNCTION 0x0000U
#define TIME_CALLBACK_EVENT_SET 0x0010U
#define TIME_CALLBACK_EVENT_PULSE 0x0020U
#define TIME_CALLBACK_TYPE_MASK 0x0030U

typedef struct
{
    TIMECALLBACK callback;
    DWORD_PTR user;
    UINT delay_ms;
    UINT flags;
    ULONGLONG due_ms;
    int active;
} WINMM_MMTIMER_SLOT;

#define WINMM_MMTIMER_MAX 16
static WINMM_MMTIMER_SLOT g_mmtimers[WINMM_MMTIMER_MAX];
static volatile int g_mmtimer_thread_started = 0;

static DWORD winmm_mmtimer_service_thread(void* arg)
{
    (void)arg;
    for (;;)
    {
        ULONGLONG now = winmm_now_ms();
        for (int i = 0; i < WINMM_MMTIMER_MAX; ++i)
        {
            if (g_mmtimers[i].active && now >= g_mmtimers[i].due_ms)
            {
                TIMECALLBACK cb = g_mmtimers[i].callback;
                DWORD_PTR user = g_mmtimers[i].user;
                const UINT callback_type = g_mmtimers[i].flags & TIME_CALLBACK_TYPE_MASK;
                /* Fire callback before rearming so a re-entrant
                 * callback that calls timeKillEvent on its own id
                 * sees the slot still alive. The callback runs on
                 * the service thread — Win32 contract is that the
                 * timer callback is called from a system thread, so
                 * callers must not assume the calling thread's
                 * locale / TLS. */
                if (callback_type == TIME_CALLBACK_EVENT_SET)
                {
                    winmm_event_set((void*)cb);
                }
                else if (callback_type == TIME_CALLBACK_EVENT_PULSE)
                {
                    /* Pulse = Set then Reset. Wakes any waiters
                     * who were already blocked; drops the signal
                     * before new waiters can latch onto it. */
                    winmm_event_set((void*)cb);
                    winmm_event_reset((void*)cb);
                }
                else if (cb)
                {
                    cb((UINT)(i + 1), 0 /*MM_TIMER*/, user, 0, 0);
                }
                if ((g_mmtimers[i].flags & TIME_PERIODIC) != 0 && g_mmtimers[i].active)
                {
                    g_mmtimers[i].due_ms = now + g_mmtimers[i].delay_ms;
                }
                else
                {
                    g_mmtimers[i].active = 0;
                }
            }
        }
        winmm_sleep_ms(10);
    }
    return 0;
}

static void winmm_ensure_mmtimer_service(void)
{
    if (g_mmtimer_thread_started)
        return;
    g_mmtimer_thread_started = 1;
    (void)winmm_thread_create(winmm_mmtimer_service_thread, (void*)0);
}

__declspec(dllexport) UINT timeSetEvent(UINT delay, UINT resolution, void* cb, unsigned long long user, UINT flags)
{
    (void)resolution; /* Polling cadence is fixed at 10 ms. */
    if (delay == 0 || cb == (void*)0)
        return 0;
    int slot = -1;
    for (int i = 0; i < WINMM_MMTIMER_MAX; ++i)
    {
        if (!g_mmtimers[i].active)
        {
            slot = i;
            break;
        }
    }
    if (slot < 0)
        return 0; /* Out of slots. */
    g_mmtimers[slot].callback = (TIMECALLBACK)cb;
    g_mmtimers[slot].user = (DWORD_PTR)user;
    g_mmtimers[slot].delay_ms = delay;
    g_mmtimers[slot].flags = flags;
    g_mmtimers[slot].due_ms = winmm_now_ms() + delay;
    g_mmtimers[slot].active = 1;
    winmm_ensure_mmtimer_service();
    return (UINT)(slot + 1); /* Non-zero MMTIMER id. */
}

__declspec(dllexport) MMRESULT timeKillEvent(UINT id)
{
    if (id == 0 || id > WINMM_MMTIMER_MAX)
        return 0x60; /* MMSYSERR_INVALPARAM */
    g_mmtimers[id - 1].active = 0;
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

/* waveOut*: digital-audio output. T12-03 partial — surfaces the
 * real HDA device count via SYS_AUDIO_DEVICE_INFO (op 0) so a PE
 * that probes "is audio available?" sees `1` when an HDA codec
 * has been brought up, `0` otherwise. waveOutOpen returns a
 * sentinel handle when a device is present so the caller's
 * subsequent waveOutPrepareHeader / waveOutWrite calls can
 * proceed; samples are still dropped because the kernel-side DMA
 * buffer alloc + BDL programming are deferred (see Roadmap
 * §"Audio — HDA codec / stream programming"). The full
 * "samples reach the codec" path lands when the DMA-coherent
 * buffer pool grows the audio backend.
 *
 * WAVEHDR layout that waveOutPrepareHeader / waveOutWrite expect:
 *   +0  LPSTR     lpData
 *   +8  DWORD     dwBufferLength
 *   +12 DWORD     dwBytesRecorded
 *   +16 DWORD_PTR dwUser
 *   +24 DWORD     dwFlags          ← WHDR_PREPARED = 0x2, WHDR_DONE = 0x1
 *   +28 DWORD     dwLoops
 *   +32 LPWAVEHDR lpNext
 *   +40 DWORD_PTR reserved
 * Stamping WHDR_DONE on Write is what real Windows does after
 * the device has played the buffer; mirroring that lets a PE's
 * "did the buffer drain?" loop terminate even though no audio
 * actually played.
 */
#define WHDR_DONE 0x00000001u
#define WHDR_PREPARED 0x00000002u

#define MM_AUDIO_HDA_HANDLE_SENTINEL ((HANDLE)0xA1A0001ULL)

static long long winmm_audio_device_info(long long op)
{
    long long rv;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"((long long)198), /* SYS_AUDIO_DEVICE_INFO */
                       "D"(op)
                     : "memory");
    return rv;
}

/* SYS_AUDIO_WRITE: hand the kernel HDA backend a PCM buffer and let
 * it DMA + RUN the stream. Returns frames accepted (0 if no backend
 * / bad args). The kernel bounded-copies, so passing the app's own
 * buffer pointer is safe. */
static long long winmm_audio_write(const void* pcm, unsigned long bytes)
{
    long long rv;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"((long long)210), /* SYS_AUDIO_WRITE */
                       "D"(pcm), "S"((long long)bytes)
                     : "memory");
    return rv;
}

__declspec(dllexport) UINT waveOutGetNumDevs(void)
{
    long long n = winmm_audio_device_info(0);
    if (n < 0)
        return 0;
    return (UINT)n;
}

__declspec(dllexport) MMRESULT waveOutOpen(HANDLE* h, UINT id, const void* fmt, void* cb, unsigned long long user,
                                           DWORD flags)
{
    (void)id;
    (void)fmt;
    (void)cb;
    (void)user;
    (void)flags;
    if (winmm_audio_device_info(0) <= 0)
    {
        if (h)
            *h = (HANDLE)0;
        return 0x6; /* MMSYSERR_NODRIVER — caller falls back. */
    }
    if (h)
        *h = MM_AUDIO_HDA_HANDLE_SENTINEL;
    return MMSYSERR_NOERROR;
}

__declspec(dllexport) MMRESULT waveOutClose(HANDLE h)
{
    (void)h;
    return MMSYSERR_NOERROR;
}

__declspec(dllexport) MMRESULT waveOutPrepareHeader(HANDLE h, void* hdr, UINT cb)
{
    (void)h;
    (void)cb;
    /* Stamp WHDR_PREPARED into dwFlags (offset +24 in WAVEHDR). */
    if (hdr != (void*)0)
    {
        unsigned char* p = (unsigned char*)hdr;
        DWORD f;
        __builtin_memcpy(&f, p + 24, sizeof(f));
        f |= WHDR_PREPARED;
        __builtin_memcpy(p + 24, &f, sizeof(f));
    }
    return MMSYSERR_NOERROR;
}

__declspec(dllexport) MMRESULT waveOutUnprepareHeader(HANDLE h, void* hdr, UINT cb)
{
    (void)h;
    (void)cb;
    if (hdr != (void*)0)
    {
        unsigned char* p = (unsigned char*)hdr;
        DWORD f;
        __builtin_memcpy(&f, p + 24, sizeof(f));
        f &= ~WHDR_PREPARED;
        __builtin_memcpy(p + 24, &f, sizeof(f));
    }
    return MMSYSERR_NOERROR;
}

__declspec(dllexport) MMRESULT waveOutWrite(HANDLE h, void* hdr, UINT cb)
{
    (void)h;
    (void)cb;
    /* Route the WAVEHDR's PCM to the kernel HDA backend, then stamp
     * WHDR_DONE so a poll-for-completion loop terminates. WAVEHDR
     * (Win64): lpData @0 (8-byte ptr), dwBufferLength @8 (4 bytes),
     * dwFlags @24. The kernel DMA's the bytes (audible only when a
     * codec path is routed; always consumed on the byte path). */
    if (hdr != (void*)0)
    {
        unsigned char* p = (unsigned char*)hdr;
        void* lp_data;
        DWORD buf_len;
        DWORD f;
        __builtin_memcpy(&lp_data, p + 0, sizeof(lp_data));
        __builtin_memcpy(&buf_len, p + 8, sizeof(buf_len));
        if (lp_data != (void*)0 && buf_len != 0)
            (void)winmm_audio_write(lp_data, (unsigned long)buf_len);
        __builtin_memcpy(&f, p + 24, sizeof(f));
        f |= WHDR_DONE;
        __builtin_memcpy(p + 24, &f, sizeof(f));
    }
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
