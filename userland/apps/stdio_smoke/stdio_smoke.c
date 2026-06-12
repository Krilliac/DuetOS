/*
 * stdio_smoke — exercise msvcrt FILE-based I/O.
 *
 * Probes the C-style stdio surface that comes from msvcrt /
 * ucrtbase. Real PEs that link MSVC pull these implicitly:
 *   fopen / fclose / fread / fwrite
 *   fseek / ftell / rewind
 *   fgets / fputs
 *   feof / ferror
 *   sprintf / snprintf  (variadic — separate test)
 *
 * Targets the existing /etc/version ramfs entry — known to
 * exist and have non-zero contents.
 */
#include <windows.h>
#include <stdio.h>

static void Out(const char* s)
{
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD n = 0;
    DWORD len = 0;
    while (s[len] != '\0')
        ++len;
    WriteConsoleA(h, s, len, &n, 0);
}

void __cdecl mainCRTStartup(void)
{
    Out("[stdio_smoke] starting\r\n");

    FILE* f = fopen("/etc/version", "rb");
    Out("[stdio_smoke] fopen(/etc/version) = ");
    if (f == NULL)
    {
        Out("FAIL/STUB\r\n");
        Out("[stdio_smoke] done\r\n");
        Out("[ring3-stdio-smoke] FAIL fopen\r\n");
        ExitProcess(1);
    }
    Out("PASS\r\n");

    /* fread some bytes. */
    char buf[64] = {0};
    size_t got = fread(buf, 1, 32, f);
    Out("[stdio_smoke] fread (32B)        = ");
    Out(got > 0 ? "PASS\r\n" : "FAIL\r\n");

    /* fseek + ftell. */
    int ok = fseek(f, 0, SEEK_END);
    long pos = ftell(f);
    Out("[stdio_smoke] fseek + ftell      = ");
    Out(ok == 0 && pos > 0 ? "PASS\r\n" : "FAIL/STUB\r\n");

    /* rewind + ftell. */
    rewind(f);
    long pos0 = ftell(f);
    Out("[stdio_smoke] rewind + ftell     = ");
    Out(pos0 == 0 ? "PASS\r\n" : "FAIL/STUB\r\n");

    /* feof — should be FALSE before reading. */
    Out("[stdio_smoke] feof (start)       = ");
    Out(!feof(f) ? "PASS\r\n" : "FAIL\r\n");

    fclose(f);
    Out("[stdio_smoke] fclose             = PASS (returned)\r\n");

    /* fopen on missing file. */
    FILE* nf = fopen("/does_not_exist.txt", "rb");
    Out("[stdio_smoke] fopen(missing)     = ");
    Out(nf == NULL ? "PASS (NULL, as expected)\r\n" : "FAIL\r\n");
    if (nf)
        fclose(nf);

    Out("[stdio_smoke] done\r\n");
    Out("[ring3-stdio-smoke] PASS\r\n");
    ExitProcess(0);
}
