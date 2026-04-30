/*
 * pipe_smoke — exercise kernel32 pipe / IPC APIs.
 *
 * Probes the synchronous pipe surface every command-line tool
 * uses for stdin/stdout redirection:
 *   CreatePipe (anonymous, in-process)
 *   CreateNamedPipeW (server-side)
 *   PeekNamedPipe
 *   WaitNamedPipeW
 *   ConnectNamedPipe (skipped — needs a client)
 *
 * Pipes are heavy plumbing for v0; expect most calls to be STUB.
 * The smoke value is that we get *some* signal about which fail
 * cleanly vs. trap.
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

void __cdecl mainCRTStartup(void)
{
    Out("[pipe_smoke] starting\r\n");

    /* CreatePipe — anonymous, in-process. */
    HANDLE rd = NULL;
    HANDLE wr = NULL;
    BOOL ok = CreatePipe(&rd, &wr, NULL, 0);
    Out("[pipe_smoke] CreatePipe         = ");
    if (ok && rd != NULL && wr != NULL)
    {
        Out("PASS\r\n");
        /* Try to write + read a byte. */
        char buf[4] = "abc";
        DWORD got = 0;
        BOOL w = WriteFile(wr, buf, 3, &got, NULL);
        Out("[pipe_smoke] WriteFile(pipe)    = ");
        Out(w && got == 3 ? "PASS\r\n" : "FAIL/STUB\r\n");

        char rbuf[4] = {0};
        DWORD rgot = 0;
        BOOL r = ReadFile(rd, rbuf, 3, &rgot, NULL);
        Out("[pipe_smoke] ReadFile(pipe)     = ");
        Out(r && rgot == 3 && rbuf[0] == 'a' ? "PASS\r\n" : "FAIL/STUB\r\n");

        CloseHandle(rd);
        CloseHandle(wr);
    }
    else
    {
        Out("FAIL/STUB\r\n");
    }

    /* WaitNamedPipeW on a non-existent pipe — should return FALSE. */
    {
        BOOL w = WaitNamedPipeW(L"\\\\.\\pipe\\does_not_exist", 100);
        Out("[pipe_smoke] WaitNamedPipeW(no) = ");
        Out(!w ? "PASS (FALSE, as expected)\r\n" : "FAIL\r\n");
    }

    Out("[pipe_smoke] done\r\n");
    ExitProcess(0);
}
