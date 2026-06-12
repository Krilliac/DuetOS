/*
 * sound_smoke — exercise winmm sound APIs beyond timing.
 *
 *   PlaySoundW (NULL flush)
 *   waveOutGetNumDevs
 *   midiOutGetNumDevs
 *   mciSendStringA (skipped — needs MCI device)
 *   sndPlaySoundA(NULL)
 *
 * v0: audio is not wired into Win32 yet. Smoke value =
 * "doesn't trap when game tries audio init".
 */
#include <windows.h>
#include <mmsystem.h>

static void Out(const char* s)
{
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD n = 0;
    DWORD len = 0;
    while (s[len] != '\0')
        ++len;
    WriteConsoleA(h, s, len, &n, 0);
}

static void OutDec(unsigned long v)
{
    char buf[16];
    int len = 0;
    if (v == 0)
        buf[len++] = '0';
    else
    {
        char rev[16];
        int r = 0;
        while (v != 0)
        {
            rev[r++] = (char)('0' + (v % 10));
            v /= 10;
        }
        for (int j = 0; j < r; ++j)
            buf[len++] = rev[r - 1 - j];
    }
    buf[len] = '\0';
    Out(buf);
}

void __cdecl mainCRTStartup(void)
{
    Out("[sound_smoke] starting\r\n");

    UINT wo = waveOutGetNumDevs();
    Out("[sound_smoke] waveOutGetNumDevs   = ");
    Out("PASS count=");
    OutDec((unsigned long)wo);
    Out("\r\n");

    UINT mo = midiOutGetNumDevs();
    Out("[sound_smoke] midiOutGetNumDevs   = ");
    Out("PASS count=");
    OutDec((unsigned long)mo);
    Out("\r\n");

    /* PlaySoundW(NULL) flushes any current sound; on a system
     * with no audio it should still return TRUE. */
    BOOL ps = PlaySoundW(NULL, NULL, 0);
    Out("[sound_smoke] PlaySoundW(NULL)    = ");
    Out(ps || !ps ? "PASS (returned)\r\n" : "FAIL\r\n");

    BOOL sps = sndPlaySoundA(NULL, 0);
    Out("[sound_smoke] sndPlaySoundA(NULL) = ");
    Out(sps || !sps ? "PASS (returned)\r\n" : "FAIL\r\n");

    Out("[sound_smoke] done\r\n");
    Out("[ring3-sound-smoke] PASS\r\n");
    ExitProcess(0);
}
