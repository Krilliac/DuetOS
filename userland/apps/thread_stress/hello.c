/*
 * userland/apps/thread_stress/hello.c
 *
 * Exercises the CreateThread -> SYS_THREAD_CREATE path added in
 * batch 50. Flow:
 *
 *   main:
 *     - CreateEventW(manual-reset, non-signaled)
 *     - CreateThread(&ChildProc, 0xC0FFEE)
 *     - WaitForSingleObject(event, INFINITE)
 *     - Print the shared counter the child wrote
 *     - ExitProcess(0xABCDE)
 *
 *   ChildProc(param):
 *     - Writes param into a global
 *     - Prints "child: running\n" via WriteFile
 *     - SetEvent(event)
 *     - Falls off the entry point — kernel reaps via SYS_EXIT(0)
 *
 * The child's param is 0xC0FFEE; the shared global ends up with
 * that value iff the thread ran. Main prints the hex value
 * before exiting, which verifies the thread actually executed.
 */

typedef void* HANDLE;
typedef unsigned int DWORD;
typedef int BOOL;
typedef const void* LPCVOID;
typedef void* LPVOID;
typedef DWORD* LPDWORD;
typedef unsigned long long SIZE_T;

#define STD_OUTPUT_HANDLE ((DWORD) - 11)
#define INFINITE 0xFFFFFFFFu

typedef DWORD(__stdcall* LPTHREAD_START_ROUTINE)(LPVOID);

__declspec(dllimport) HANDLE __stdcall GetStdHandle(DWORD nStdHandle);
__declspec(dllimport) BOOL __stdcall WriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite,
                                               LPDWORD lpNumberOfBytesWritten, void* lpOverlapped);
__declspec(dllimport) void __stdcall ExitProcess(unsigned int uExitCode);
__declspec(dllimport) HANDLE __stdcall CreateThread(void* lpThreadAttributes, SIZE_T dwStackSize,
                                                    LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter,
                                                    DWORD dwCreationFlags, LPDWORD lpThreadId);
__declspec(dllimport) HANDLE __stdcall CreateEventW(void* lpEventAttributes, BOOL bManualReset, BOOL bInitialState,
                                                    const unsigned short* lpName);
__declspec(dllimport) BOOL __stdcall SetEvent(HANDLE hEvent);
__declspec(dllimport) DWORD __stdcall WaitForSingleObject(HANDLE hHandle, DWORD dwMilliseconds);

static HANDLE g_done_event;
static unsigned long long g_shared;

static void WriteString(const char* s)
{
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD n = 0;
    while (s[n] != '\0')
        ++n;
    DWORD written;
    WriteFile(h, s, n, &written, 0);
}

static void WriteHex64(unsigned long long v)
{
    char buf[19];
    buf[0] = '0';
    buf[1] = 'x';
    for (int i = 0; i < 16; ++i)
    {
        unsigned nibble = (v >> ((15 - i) * 4)) & 0xF;
        buf[2 + i] = nibble < 10 ? ('0' + nibble) : ('a' + nibble - 10);
    }
    buf[18] = '\n';
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD written;
    WriteFile(h, buf, 19, &written, 0);
}

static DWORD __stdcall ChildProc(LPVOID param)
{
    g_shared = (unsigned long long)(unsigned long long)param;
    WriteString("[thread-stress] child: running\n");
    SetEvent(g_done_event);
    return 0;
}

int __stdcall _start(void)
{
    WriteString("[thread-stress] main: CreateEventW\n");
    g_done_event = CreateEventW(0, 1, 0, 0); // manual-reset, non-signaled
    if (g_done_event == 0)
    {
        WriteString("[thread-stress] main: CreateEventW returned NULL — abort\n");
        ExitProcess(1);
    }

    WriteString("[thread-stress] main: CreateThread\n");
    HANDLE h = CreateThread(0, 0, ChildProc, (LPVOID)0xC0FFEEULL, 0, 0);
    if (h == 0)
    {
        WriteString("[thread-stress] main: CreateThread returned NULL — wiring broken\n");
        ExitProcess(2);
    }

    WriteString("[thread-stress] main: WaitForSingleObject(event, INFINITE)\n");
    WaitForSingleObject(g_done_event, INFINITE);

    WriteString("[thread-stress] main: child exited; shared=\n");
    WriteHex64(g_shared);

    if (g_shared != 0xC0FFEEULL)
    {
        WriteString("[thread-stress] main: FAIL shared != 0xC0FFEE\n");
        ExitProcess(3);
    }
    WriteString("[thread-stress] main: PASS\n");
    ExitProcess(0xABCDE);
}
