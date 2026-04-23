/*
 * userland/apps/syscall_stress/hello.c
 *
 * Drives the batch-51 Win32 additions:
 *   - OutputDebugStringA         → SYS_DEBUG_PRINT
 *   - GetProcessTimes            → zero-fill stub
 *   - GetThreadTimes             → alias of GetProcessTimes
 *   - GetSystemTimes             → zero-fill stub
 *   - GlobalMemoryStatusEx       → SYS_MEM_STATUS
 *   - CreateThread + ExitThread  → SYS_THREAD_CREATE + SYS_EXIT
 *   - CreateEventW + SetEvent    → SYS_EVENT_*
 *   - WaitForMultipleObjects     → SYS_WAIT_MULTI
 *
 * Flow:
 *   main:
 *     - OutputDebugStringA("hello")
 *     - GetProcessTimes / GetThreadTimes / GetSystemTimes (non-fatal if FALSE)
 *     - GlobalMemoryStatusEx — print out ullTotalPhys / ullAvailPhys
 *     - Create two CreateEventW events (both manual-reset, non-signaled)
 *     - CreateThread(ChildA) signals event0
 *     - CreateThread(ChildB) signals event1
 *     - WaitForMultipleObjects(2, events, TRUE, INFINITE)  // wait-all
 *     - Print verdict, ExitProcess(0xCAFE)
 *
 * Each child thread calls ExitThread(0x42) to exit explicitly
 * (exercises the ExitThread stub — the thread-exit trampoline
 *  fallback from batch 50 is the non-explicit path).
 */

typedef void* HANDLE;
typedef unsigned int DWORD;
typedef int BOOL;
typedef const void* LPCVOID;
typedef void* LPVOID;
typedef DWORD* LPDWORD;
typedef unsigned long long SIZE_T;
typedef unsigned long long ULONGLONG;
typedef const char* LPCSTR;

typedef struct _FILETIME
{
    DWORD dwLowDateTime;
    DWORD dwHighDateTime;
} FILETIME, *LPFILETIME, *PFILETIME;

typedef struct _MEMORYSTATUSEX
{
    DWORD dwLength;
    DWORD dwMemoryLoad;
    ULONGLONG ullTotalPhys;
    ULONGLONG ullAvailPhys;
    ULONGLONG ullTotalPageFile;
    ULONGLONG ullAvailPageFile;
    ULONGLONG ullTotalVirtual;
    ULONGLONG ullAvailVirtual;
    ULONGLONG ullAvailExtendedVirtual;
} MEMORYSTATUSEX, *LPMEMORYSTATUSEX;

#define STD_OUTPUT_HANDLE ((DWORD) - 11)
#define INFINITE 0xFFFFFFFFu
#define WAIT_OBJECT_0 0x00000000

typedef DWORD(__stdcall* LPTHREAD_START_ROUTINE)(LPVOID);

__declspec(dllimport) HANDLE __stdcall GetStdHandle(DWORD nStdHandle);
__declspec(dllimport) BOOL __stdcall WriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite,
                                               LPDWORD lpNumberOfBytesWritten, void* lpOverlapped);
__declspec(dllimport) void __stdcall ExitProcess(unsigned int uExitCode);
__declspec(dllimport) HANDLE __stdcall CreateThread(void* lpThreadAttributes, SIZE_T dwStackSize,
                                                    LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter,
                                                    DWORD dwCreationFlags, LPDWORD lpThreadId);
__declspec(dllimport) void __stdcall ExitThread(DWORD dwExitCode);
__declspec(dllimport) HANDLE __stdcall CreateEventW(void* lpEventAttributes, BOOL bManualReset, BOOL bInitialState,
                                                    const unsigned short* lpName);
__declspec(dllimport) BOOL __stdcall SetEvent(HANDLE hEvent);
__declspec(dllimport) DWORD __stdcall WaitForSingleObject(HANDLE hHandle, DWORD dwMilliseconds);
__declspec(dllimport) DWORD __stdcall WaitForMultipleObjects(DWORD nCount, const HANDLE* lpHandles, BOOL bWaitAll,
                                                             DWORD dwMilliseconds);
__declspec(dllimport) void __stdcall OutputDebugStringA(LPCSTR lpOutputString);
__declspec(dllimport) HANDLE __stdcall GetCurrentProcess(void);
__declspec(dllimport) HANDLE __stdcall GetCurrentThread(void);
__declspec(dllimport) BOOL __stdcall GetProcessTimes(HANDLE hProcess, LPFILETIME ct, LPFILETIME et, LPFILETIME kt,
                                                     LPFILETIME ut);
__declspec(dllimport) BOOL __stdcall GetThreadTimes(HANDLE hThread, LPFILETIME ct, LPFILETIME et, LPFILETIME kt,
                                                    LPFILETIME ut);
__declspec(dllimport) BOOL __stdcall GetSystemTimes(PFILETIME idle, PFILETIME kernel_t, PFILETIME user);
__declspec(dllimport) BOOL __stdcall GlobalMemoryStatusEx(LPMEMORYSTATUSEX lpBuffer);

static HANDLE g_events[2];

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

static DWORD __stdcall ChildA(LPVOID param)
{
    (void)param;
    WriteString("[syscall-stress] childA: running\n");
    SetEvent(g_events[0]);
    ExitThread(0x42);
    return 0; // unreached — ExitThread is noreturn
}

static DWORD __stdcall ChildB(LPVOID param)
{
    (void)param;
    WriteString("[syscall-stress] childB: running\n");
    SetEvent(g_events[1]);
    ExitThread(0x43);
    return 0;
}

int __stdcall _start(void)
{
    WriteString("[syscall-stress] main: OutputDebugStringA\n");
    OutputDebugStringA("syscall_stress: hello from OutputDebugStringA");

    WriteString("[syscall-stress] main: GetProcessTimes\n");
    FILETIME ct, et, kt, ut;
    if (!GetProcessTimes(GetCurrentProcess(), &ct, &et, &kt, &ut))
    {
        WriteString("[syscall-stress] FAIL GetProcessTimes returned FALSE\n");
        ExitProcess(1);
    }

    WriteString("[syscall-stress] main: GetThreadTimes\n");
    if (!GetThreadTimes(GetCurrentThread(), &ct, &et, &kt, &ut))
    {
        WriteString("[syscall-stress] FAIL GetThreadTimes returned FALSE\n");
        ExitProcess(2);
    }

    WriteString("[syscall-stress] main: GetSystemTimes\n");
    FILETIME idle_ft, kernel_ft, user_ft;
    if (!GetSystemTimes(&idle_ft, &kernel_ft, &user_ft))
    {
        WriteString("[syscall-stress] FAIL GetSystemTimes returned FALSE\n");
        ExitProcess(3);
    }

    WriteString("[syscall-stress] main: GlobalMemoryStatusEx\n");
    MEMORYSTATUSEX ms;
    ms.dwLength = sizeof(MEMORYSTATUSEX);
    if (!GlobalMemoryStatusEx(&ms))
    {
        WriteString("[syscall-stress] FAIL GlobalMemoryStatusEx returned FALSE\n");
        ExitProcess(4);
    }
    WriteString("[syscall-stress] main: ullTotalPhys=\n");
    WriteHex64(ms.ullTotalPhys);
    WriteString("[syscall-stress] main: ullAvailPhys=\n");
    WriteHex64(ms.ullAvailPhys);

    WriteString("[syscall-stress] main: CreateEventW x2\n");
    g_events[0] = CreateEventW(0, 1, 0, 0);
    g_events[1] = CreateEventW(0, 1, 0, 0);
    if (g_events[0] == 0 || g_events[1] == 0)
    {
        WriteString("[syscall-stress] FAIL CreateEventW returned NULL\n");
        ExitProcess(5);
    }

    WriteString("[syscall-stress] main: CreateThread childA\n");
    HANDLE hA = CreateThread(0, 0, ChildA, 0, 0, 0);
    WriteString("[syscall-stress] main: CreateThread childB\n");
    HANDLE hB = CreateThread(0, 0, ChildB, 0, 0, 0);
    if (hA == 0 || hB == 0)
    {
        WriteString("[syscall-stress] FAIL CreateThread returned NULL\n");
        ExitProcess(6);
    }

    WriteString("[syscall-stress] main: WaitForMultipleObjects(2, evs, WAIT_ALL, INFINITE)\n");
    DWORD rc = WaitForMultipleObjects(2, g_events, 1, INFINITE);
    if (rc != WAIT_OBJECT_0)
    {
        WriteString("[syscall-stress] FAIL WaitForMultipleObjects returned unexpected code\n");
        WriteHex64(rc);
        ExitProcess(7);
    }

    WriteString("[syscall-stress] main: PASS\n");
    ExitProcess(0xCAFE);
}
