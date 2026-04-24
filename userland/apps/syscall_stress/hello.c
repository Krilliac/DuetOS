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

typedef unsigned short WORD;
typedef short SHORT;

typedef struct _SYSTEM_INFO
{
    WORD wProcessorArchitecture;
    WORD wReserved;
    DWORD dwPageSize;
    void* lpMinimumApplicationAddress;
    void* lpMaximumApplicationAddress;
    unsigned long long dwActiveProcessorMask;
    DWORD dwNumberOfProcessors;
    DWORD dwProcessorType;
    DWORD dwAllocationGranularity;
    WORD wProcessorLevel;
    WORD wProcessorRevision;
} SYSTEM_INFO, *LPSYSTEM_INFO;

typedef struct _COORD
{
    SHORT X;
    SHORT Y;
} COORD;

typedef struct _SMALL_RECT
{
    SHORT Left;
    SHORT Top;
    SHORT Right;
    SHORT Bottom;
} SMALL_RECT;

typedef struct _CONSOLE_SCREEN_BUFFER_INFO
{
    COORD dwSize;
    COORD dwCursorPosition;
    WORD wAttributes;
    SMALL_RECT srWindow;
    COORD dwMaximumWindowSize;
} CONSOLE_SCREEN_BUFFER_INFO;

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
__declspec(dllimport) void __stdcall GetSystemInfo(LPSYSTEM_INFO lpSystemInfo);
__declspec(dllimport) void __stdcall GetNativeSystemInfo(LPSYSTEM_INFO lpSystemInfo);
__declspec(dllimport) void __stdcall OutputDebugStringW(const unsigned short* lpOutputString);
__declspec(dllimport) DWORD __stdcall FormatMessageA(DWORD flags, const void* src, DWORD msgId, DWORD lang, char* buf,
                                                     DWORD nSize, void* args);
__declspec(dllimport) BOOL __stdcall GetConsoleScreenBufferInfo(HANDLE hOut, CONSOLE_SCREEN_BUFFER_INFO* p);
__declspec(dllimport) void* __stdcall DecodePointer(void* Ptr);
__declspec(dllimport) void* __stdcall EncodePointer(void* Ptr);
__declspec(dllimport) HANDLE __stdcall CreateSemaphoreW(void* attrs, int lInitial, int lMax,
                                                        const unsigned short* name);
__declspec(dllimport) BOOL __stdcall ReleaseSemaphore(HANDLE hSem, int lReleaseCount, int* lpPrev);

typedef struct _SRWLOCK
{
    void* Ptr;
} SRWLOCK, *PSRWLOCK;
typedef struct _INIT_ONCE
{
    void* Ptr;
} INIT_ONCE, *PINIT_ONCE;
typedef BOOL(__stdcall* PINIT_ONCE_FN)(PINIT_ONCE, void*, void**);

__declspec(dllimport) void __stdcall InitializeSRWLock(PSRWLOCK);
__declspec(dllimport) void __stdcall AcquireSRWLockExclusive(PSRWLOCK);
__declspec(dllimport) void __stdcall ReleaseSRWLockExclusive(PSRWLOCK);
__declspec(dllimport) unsigned char __stdcall TryAcquireSRWLockExclusive(PSRWLOCK);
__declspec(dllimport) void __stdcall InitOnceInitialize(PINIT_ONCE);
__declspec(dllimport) BOOL __stdcall InitOnceExecuteOnce(PINIT_ONCE, PINIT_ONCE_FN, void*, void**);

typedef struct _STARTUPINFOW
{
    DWORD cb;
    unsigned short* lpReserved;
    unsigned short* lpDesktop;
    unsigned short* lpTitle;
    DWORD dwX, dwY;
    DWORD dwXSize, dwYSize;
    DWORD dwXCountChars, dwYCountChars;
    DWORD dwFillAttribute;
    DWORD dwFlags;
    unsigned short wShowWindow;
    unsigned short cbReserved2;
    unsigned char* lpReserved2;
    HANDLE hStdInput, hStdOutput, hStdError;
} STARTUPINFOW;
__declspec(dllimport) void __stdcall GetStartupInfoW(STARTUPINFOW* p);
__declspec(dllimport) BOOL __stdcall GetExitCodeThread(HANDLE hThread, DWORD* lpExitCode);

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

    // === Batch 52 coverage ===
    WriteString("[syscall-stress] main: GetSystemInfo\n");
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    if (si.dwPageSize != 4096 || si.dwNumberOfProcessors == 0 || si.wProcessorArchitecture != 9)
    {
        WriteString("[syscall-stress] FAIL GetSystemInfo returned bad fields\n");
        ExitProcess(8);
    }
    WriteString("[syscall-stress] main: si.dwNumberOfProcessors=\n");
    WriteHex64(si.dwNumberOfProcessors);

    WriteString("[syscall-stress] main: GetNativeSystemInfo\n");
    SYSTEM_INFO nsi;
    GetNativeSystemInfo(&nsi);
    if (nsi.dwPageSize != 4096)
    {
        WriteString("[syscall-stress] FAIL GetNativeSystemInfo returned bad page size\n");
        ExitProcess(9);
    }

    WriteString("[syscall-stress] main: OutputDebugStringW\n");
    static const unsigned short wmsg[] = {'w', 'i', 'd', 'e', ' ', 'h', 'e', 'l', 'l', 'o', 0};
    OutputDebugStringW(wmsg);

    WriteString("[syscall-stress] main: FormatMessageA\n");
    char fmbuf[64];
    fmbuf[0] = 'x'; // sentinel
    DWORD fmrc = FormatMessageA(0, 0, 0x12345, 0, fmbuf, sizeof(fmbuf), 0);
    if (fmrc == 0 || fmbuf[0] != 'E')
    {
        WriteString("[syscall-stress] FAIL FormatMessageA didn't write buffer\n");
        WriteHex64(fmrc);
        ExitProcess(10);
    }
    WriteString("[syscall-stress] main: FormatMessageA wrote: ");
    WriteString(fmbuf);

    WriteString("[syscall-stress] main: GetConsoleScreenBufferInfo\n");
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    csbi.dwSize.X = 0; // sentinel
    if (!GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &csbi))
    {
        WriteString("[syscall-stress] FAIL GetConsoleScreenBufferInfo returned FALSE\n");
        ExitProcess(11);
    }
    if (csbi.dwSize.X != 80 || csbi.dwSize.Y != 25)
    {
        WriteString("[syscall-stress] FAIL GetConsoleScreenBufferInfo bad size\n");
        ExitProcess(12);
    }

    // === Batch 57 coverage: WaitForSingleObject on a thread handle ===
    // Both child threads have already completed (the WaitForMultipleObjects
    // above returned only after both signaled + child code reached
    // ExitThread). So a WaitForSingleObject on hA should return
    // WAIT_OBJECT_0 essentially immediately via the thread-dead
    // branch of SYS_THREAD_WAIT.
    WriteString("[syscall-stress] main: WaitForSingleObject(thread, INFINITE)\n");
    DWORD twrc = WaitForSingleObject(hA, INFINITE);
    if (twrc != WAIT_OBJECT_0)
    {
        WriteString("[syscall-stress] FAIL thread-handle wait didn't return WAIT_OBJECT_0\n");
        WriteHex64(twrc);
        ExitProcess(21);
    }

    // === Batch 59 coverage: GetExitCodeThread returns recorded 0x42 ===
    // ChildA called ExitThread(0x42); by the time we get here the
    // task is Dead and the SYS_EXIT path has written 0x42 into the
    // thread-handle's exit_code slot.
    WriteString("[syscall-stress] main: GetExitCodeThread(childA)\n");
    DWORD childA_rc = 0xDEADBEEF;
    if (!GetExitCodeThread(hA, &childA_rc))
    {
        WriteString("[syscall-stress] FAIL GetExitCodeThread returned FALSE\n");
        ExitProcess(23);
    }
    if (childA_rc != 0x42)
    {
        WriteString("[syscall-stress] FAIL GetExitCodeThread got wrong code\n");
        WriteHex64(childA_rc);
        ExitProcess(24);
    }

    // === Batch 53 coverage: Decode/Encode round-trip ===
    WriteString("[syscall-stress] main: Decode/Encode round-trip\n");
    void* p_in = (void*)0xDEADBEEFCAFEBABEULL;
    void* p_enc = EncodePointer(p_in);
    void* p_dec = DecodePointer(p_enc);
    if (p_dec != p_in)
    {
        WriteString("[syscall-stress] FAIL Encode/Decode didn't round-trip\n");
        ExitProcess(13);
    }

    // === Batch 54 coverage: Semaphore create + wait + release ===
    WriteString("[syscall-stress] main: CreateSemaphoreW(initial=1, max=4)\n");
    HANDLE hSem = CreateSemaphoreW(0, 1, 4, 0);
    if (hSem == 0)
    {
        WriteString("[syscall-stress] FAIL CreateSemaphoreW returned NULL\n");
        ExitProcess(14);
    }
    // Wait immediately — count=1 so should succeed without blocking.
    WriteString("[syscall-stress] main: WaitForSingleObject(sem, 0)\n");
    DWORD wrc = WaitForSingleObject(hSem, 0);
    if (wrc != WAIT_OBJECT_0)
    {
        WriteString("[syscall-stress] FAIL sem wait didn't get immediate ownership\n");
        WriteHex64(wrc);
        ExitProcess(15);
    }
    // Now count=0. Release 2 back — prev should be 0.
    WriteString("[syscall-stress] main: ReleaseSemaphore(2)\n");
    int sem_prev = -1;
    if (!ReleaseSemaphore(hSem, 2, &sem_prev))
    {
        WriteString("[syscall-stress] FAIL ReleaseSemaphore returned FALSE\n");
        ExitProcess(16);
    }
    if (sem_prev != 0)
    {
        WriteString("[syscall-stress] FAIL ReleaseSemaphore lpPreviousCount != 0\n");
        WriteHex64((unsigned long long)sem_prev);
        ExitProcess(17);
    }
    // Count is now 2. Overflow: release 3 more would be count=5 > max=4.
    WriteString("[syscall-stress] main: ReleaseSemaphore overflow (expect FALSE)\n");
    if (ReleaseSemaphore(hSem, 3, 0))
    {
        WriteString("[syscall-stress] FAIL overflow release succeeded\n");
        ExitProcess(18);
    }

    // === Batch 55 coverage: SRW + InitOnce smoke ===
    WriteString("[syscall-stress] main: SRWLock init + acquire + release\n");
    SRWLOCK srw;
    srw.Ptr = 0;
    InitializeSRWLock(&srw);
    AcquireSRWLockExclusive(&srw);
    ReleaseSRWLockExclusive(&srw);
    if (!TryAcquireSRWLockExclusive(&srw))
    {
        WriteString("[syscall-stress] FAIL TryAcquireSRWLockExclusive returned FALSE\n");
        ExitProcess(19);
    }
    ReleaseSRWLockExclusive(&srw);

    WriteString("[syscall-stress] main: InitOnce init + execute\n");
    INIT_ONCE io;
    io.Ptr = 0;
    InitOnceInitialize(&io);
    if (!InitOnceExecuteOnce(&io, 0, 0, 0)) // null callback — v0 stub skips it
    {
        WriteString("[syscall-stress] FAIL InitOnceExecuteOnce returned FALSE\n");
        ExitProcess(20);
    }

    // === Batch 58 coverage: GetStartupInfoW fills cb ===
    WriteString("[syscall-stress] main: GetStartupInfoW\n");
    STARTUPINFOW sui;
    // Deliberately fill with 0xCC to detect real zeroing.
    for (int i = 0; i < (int)sizeof(sui); ++i)
        ((unsigned char*)&sui)[i] = 0xCC;
    GetStartupInfoW(&sui);
    if (sui.cb != 104 || sui.dwFlags != 0 || sui.lpDesktop != 0)
    {
        WriteString("[syscall-stress] FAIL GetStartupInfoW didn't zero-fill or set cb\n");
        WriteHex64(sui.cb);
        ExitProcess(22);
    }

    WriteString("[syscall-stress] main: PASS\n");
    ExitProcess(0xCAFE);
}
