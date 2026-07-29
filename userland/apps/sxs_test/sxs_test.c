/*
 * sxstest.exe — proof that DuetOS can load a DLL that ships beside
 *               the .exe instead of one embedded in the kernel image.
 *
 * Staged onto the FAT32 volume root next to SXSLIB.DLL. Neither file
 * is compiled into the kernel, so the only way SxsAnswer() can be
 * reachable is if the loader took the on-disk side-by-side path.
 *
 * Prints exactly one verdict line on stdout for the ring3 PE-compat
 * battery to scrape:
 *     [ring3-sxs] PASS answer=4242 double=84
 *     [ring3-sxs] FAIL <why>
 */
#include <windows.h>

__declspec(dllimport) unsigned int SxsAnswer(void);
__declspec(dllimport) unsigned int SxsDouble(unsigned int v);

static void Out(const char* s)
{
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD n = 0;
    DWORD len = 0;
    while (s[len] != '\0')
        ++len;
    WriteConsoleA(h, s, len, &n, 0);
}

static void OutDec(unsigned int v)
{
    char buf[12];
    int i = 11;
    buf[i] = '\0';
    if (v == 0)
    {
        buf[--i] = '0';
    }
    while (v > 0 && i > 0)
    {
        buf[--i] = (char)('0' + (v % 10u));
        v /= 10u;
    }
    Out(buf + i);
}

void __cdecl mainCRTStartup(void)
{
    const unsigned int answer = SxsAnswer();
    if (answer != 4242u)
    {
        Out("[ring3-sxs] FAIL wrong-answer got=");
        OutDec(answer);
        Out("\r\n");
        ExitProcess(1);
    }

    const unsigned int doubled = SxsDouble(42u);
    if (doubled != 84u)
    {
        Out("[ring3-sxs] FAIL wrong-double got=");
        OutDec(doubled);
        Out("\r\n");
        ExitProcess(1);
    }

    Out("[ring3-sxs] PASS answer=");
    OutDec(answer);
    Out(" double=");
    OutDec(doubled);
    Out("\r\n");
    ExitProcess(0);
}
