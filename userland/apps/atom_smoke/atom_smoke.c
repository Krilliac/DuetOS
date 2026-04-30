/*
 * atom_smoke — exercise atom-table APIs.
 *
 * Atoms are 16-bit integer aliases for short strings, used by
 * the Win32 windowing system (RegisterClassA stores its class
 * name as an atom). Local + global atom tables exist:
 *   AddAtomA / AddAtomW
 *   FindAtomA / FindAtomW
 *   GetAtomNameA
 *   DeleteAtom
 *   GlobalAddAtomA / GlobalAddAtomW
 *   GlobalFindAtomA
 *   GlobalGetAtomNameA
 *   GlobalDeleteAtom
 */
#include <windows.h>

static void Out(const char* s)
{
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD n = 0;
    DWORD len = 0;
    while (s[len] != '\0')
        ++len;
    WriteConsoleA(h, s, len, &n, 0);
}

static int StrEqA(const char* a, const char* b)
{
    int i = 0;
    while (a[i] && b[i])
    {
        if (a[i] != b[i])
            return 0;
        ++i;
    }
    return a[i] == b[i];
}

void __cdecl mainCRTStartup(void)
{
    Out("[atom_smoke] starting\r\n");

    /* Global atom table. */
    {
        ATOM a = GlobalAddAtomA("DuetOSTestAtom");
        Out("[atom_smoke] GlobalAddAtomA      = ");
        Out(a != 0 ? "PASS\r\n" : "FAIL\r\n");

        ATOM b = GlobalFindAtomA("DuetOSTestAtom");
        Out("[atom_smoke] GlobalFindAtomA     = ");
        Out(b == a && b != 0 ? "PASS (matches)\r\n" : "FAIL\r\n");

        char buf[32] = {0};
        UINT n = GlobalGetAtomNameA(a, buf, 32);
        Out("[atom_smoke] GlobalGetAtomNameA  = ");
        Out(n > 0 && StrEqA(buf, "DuetOSTestAtom") ? "PASS (round-trip)\r\n" : "FAIL\r\n");

        ATOM dr = GlobalDeleteAtom(a);
        Out("[atom_smoke] GlobalDeleteAtom    = ");
        Out(dr == 0 ? "PASS\r\n" : "FAIL/STUB\r\n");
    }

    /* Local atom table (shares the same backing in many impls). */
    {
        ATOM a = AddAtomA("LocalTestAtom");
        Out("[atom_smoke] AddAtomA            = ");
        Out(a != 0 ? "PASS\r\n" : "FAIL\r\n");

        ATOM b = FindAtomA("LocalTestAtom");
        Out("[atom_smoke] FindAtomA           = ");
        Out(b == a && b != 0 ? "PASS\r\n" : "FAIL\r\n");

        DeleteAtom(a);
    }

    /* FindAtom on a non-existent atom → 0. */
    {
        ATOM a = GlobalFindAtomA("DuetOSDefinitelyMissing");
        Out("[atom_smoke] GlobalFindAtomA(?)  = ");
        Out(a == 0 ? "PASS (not found)\r\n" : "FAIL (false positive)\r\n");
    }

    Out("[atom_smoke] done\r\n");
    ExitProcess(0);
}
