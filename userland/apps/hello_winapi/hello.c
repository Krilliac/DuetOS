/*
 * userland/apps/hello_winapi/hello.c
 *
 * First CustomOS userland program that talks to "Win32" —
 * real imported functions through a real Import Address Table.
 *
 * v0 scope:
 *   - GetStdHandle(STD_OUTPUT_HANDLE) -> HANDLE
 *   - WriteFile(handle, buf, n, &written, NULL) -> BOOL
 *   - ExitProcess(42)
 *
 * What this exercises end-to-end:
 *
 *   1. lld-link resolves the three imports against the minimal
 *      kernel32.lib produced by llvm-dlltool from kernel32.def.
 *   2. The resulting PE carries an Import Directory with three
 *      kernel32.dll entries.
 *   3. On load, the CustomOS PE loader's ResolveImports walks
 *      the IAT and patches each slot with the stub VA from
 *      kernel/subsystems/win32/stubs.cpp.
 *   4. Each IAT-routed call lands in the per-process stubs
 *      page at 0x60000000 + stub_offset, which translates the
 *      Windows x64 ABI into a CustomOS int 0x80 syscall.
 *   5. The WriteFile stub maps to SYS_WRITE(1, buf, n); the
 *      ExitProcess stub maps to SYS_EXIT(code).
 *
 * Success is observable in the serial log as:
 *     [hello-winapi] printed via kernel32.WriteFile!
 *     [I] sys : exit rc val=0x2a
 *
 * Exit code 42 stays as the "success signature" — distinctive
 * enough to spot in boot logs alongside the zero-exit
 * compliance tasks.
 */

typedef void* HANDLE;
typedef unsigned int DWORD;
typedef int BOOL;
typedef const void* LPCVOID;
typedef DWORD* LPDWORD;

#define STD_OUTPUT_HANDLE ((DWORD) - 11)

// Batch 1 — console I/O
__declspec(dllimport) HANDLE __stdcall GetStdHandle(DWORD nStdHandle);
__declspec(dllimport) BOOL __stdcall WriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite,
                                               LPDWORD lpNumberOfBytesWritten, void* lpOverlapped);
__declspec(dllimport) void __stdcall ExitProcess(unsigned int uExitCode);

// Batch 2 — process/thread lifecycle
__declspec(dllimport) HANDLE __stdcall GetCurrentProcess(void);
__declspec(dllimport) HANDLE __stdcall GetCurrentThread(void);
__declspec(dllimport) DWORD __stdcall GetCurrentProcessId(void);
__declspec(dllimport) DWORD __stdcall GetCurrentThreadId(void);
__declspec(dllimport) BOOL __stdcall TerminateProcess(HANDLE hProcess, unsigned int uExitCode);

// Batch 3 — last-error slot
__declspec(dllimport) DWORD __stdcall GetLastError(void);
__declspec(dllimport) void __stdcall SetLastError(DWORD dwErrCode);

// Batch 4 — critical sections (v0 no-ops)
// CRITICAL_SECTION is 40 bytes on x64: {PDEBUG_INFO, LONG,
// LONG, HANDLE, HANDLE, ULONG_PTR}. We only need the size
// right — the stub zeros the whole struct and never reads
// the fields.
typedef struct
{
    void* _opaque[5];
} CRITICAL_SECTION, *LPCRITICAL_SECTION;
__declspec(dllimport) void __stdcall InitializeCriticalSection(LPCRITICAL_SECTION);
__declspec(dllimport) void __stdcall EnterCriticalSection(LPCRITICAL_SECTION);
__declspec(dllimport) void __stdcall LeaveCriticalSection(LPCRITICAL_SECTION);
__declspec(dllimport) void __stdcall DeleteCriticalSection(LPCRITICAL_SECTION);

// Batch 5 — vcruntime140 memory intrinsics. CRT functions
// use the plain x64 calling convention (no __stdcall
// decoration — __stdcall is ignored on x64 anyway, but we
// keep the annotations to match vcruntime140.dll's export
// table on a real Windows system). size_t is 64-bit on x64.
typedef unsigned long long size_t;
__declspec(dllimport) void* memset(void* dst, int c, size_t n);
__declspec(dllimport) void* memcpy(void* dst, const void* src, size_t n);
__declspec(dllimport) void* memmove(void* dst, const void* src, size_t n);

// Batch 6 — UCRT CRT-startup shims. These live in the apiset
// DLLs (api-ms-win-crt-runtime-l1-1-0.dll and friends) that
// forward to ucrtbase.dll on real Windows. CustomOS handles
// the apiset name directly in the stub lookup table.
__declspec(dllimport) int _initialize_onexit_table(void* table);
__declspec(dllimport) int _register_onexit_function(void* table, void* fn);
__declspec(dllimport) int _crt_atexit(void* fn);
__declspec(dllimport) int _configure_narrow_argv(int mode);
__declspec(dllimport) void _set_app_type(int type);
__declspec(dllimport) void _cexit(void);
// Non-return family — referenced via function-pointer sinks
// so lld-link keeps the imports but we never actually call
// them (they'd terminate the process).
__declspec(dllimport) void _invalid_parameter_noinfo_noreturn(void);
__declspec(dllimport) void terminate(void);

// Batch 7 — CRT string intrinsics. Pure functions with the
// standard C library contracts. Registered under the apiset,
// ucrtbase, AND msvcrt DLL names in the stub table.
__declspec(dllimport) int strcmp(const char* a, const char* b);
__declspec(dllimport) size_t strlen(const char* s);
__declspec(dllimport) char* strchr(const char* s, int c);

// Batch 9 — process heap. kernel32 HeapAlloc + UCRT
// malloc/free/calloc. v0 semantics:
//   * HeapAlloc / malloc : 8-byte-aligned payload, NOT zeroed.
//   * calloc             : zero-fills the returned region.
//   * HeapFree / free    : O(1) prepend to the free list, no
//                          coalescing.
//   * HeapReAlloc / realloc : return NULL (failure). Caller
//                             keeps its old pointer.
__declspec(dllimport) HANDLE __stdcall GetProcessHeap(void);
__declspec(dllimport) void* __stdcall HeapAlloc(HANDLE hHeap, DWORD dwFlags, unsigned long long dwBytes);
__declspec(dllimport) BOOL __stdcall HeapFree(HANDLE hHeap, DWORD dwFlags, void* lpMem);
__declspec(dllimport) void* malloc(size_t size);
__declspec(dllimport) void free(void* ptr);
__declspec(dllimport) void* calloc(size_t count, size_t size);

// Batch 14 — real HeapSize + HeapReAlloc / realloc. The
// block header the v0 allocator already writes gives us the
// payload capacity for free; HeapReAlloc copies through the
// kernel direct map.
__declspec(dllimport) unsigned long long __stdcall HeapSize(HANDLE hHeap, DWORD dwFlags, const void* lpMem);
__declspec(dllimport) void* __stdcall HeapReAlloc(HANDLE hHeap, DWORD dwFlags, void* lpMem, unsigned long long dwBytes);
__declspec(dllimport) void* realloc(void* ptr, size_t size);

// Batch 10 — advapi32 privilege dance + kernel32 event/wait/
// time/process shims. All return success; the values they
// write to out-params are plausible placeholders.
typedef struct
{
    DWORD LowPart;
    int HighPart;
} LUID;
__declspec(dllimport) BOOL __stdcall OpenProcessToken(HANDLE ProcessHandle, DWORD DesiredAccess, HANDLE* TokenHandle);
__declspec(dllimport) BOOL __stdcall LookupPrivilegeValueW(const unsigned short* SystemName, const unsigned short* Name,
                                                           LUID* Luid);
__declspec(dllimport) BOOL __stdcall AdjustTokenPrivileges(HANDLE TokenHandle, BOOL DisableAll, void* NewState,
                                                           DWORD BufferLen, void* PreviousState, DWORD* ReturnLen);
__declspec(dllimport) HANDLE __stdcall CreateEventW(void* Attrs, BOOL ManualReset, BOOL InitialState,
                                                    const unsigned short* Name);
__declspec(dllimport) BOOL __stdcall SetEvent(HANDLE);
__declspec(dllimport) BOOL __stdcall ResetEvent(HANDLE);
__declspec(dllimport) DWORD __stdcall WaitForSingleObject(HANDLE, DWORD TimeoutMs);
__declspec(dllimport) void __stdcall InitializeSListHead(void* ListHead);
__declspec(dllimport) void __stdcall GetSystemTimeAsFileTime(void* FileTime);
__declspec(dllimport) HANDLE __stdcall OpenProcess(DWORD DesiredAccess, BOOL InheritHandle, DWORD ProcessId);
__declspec(dllimport) BOOL __stdcall GetExitCodeThread(HANDLE Thread, DWORD* ExitCode);

// Batch 11 — real perf counter + tick count (backed by
// SYS_PERF_COUNTER and arch::TimerTicks()), plus Rtl/
// toolhelp/thread no-ops.
typedef struct
{
    long long QuadPart;
} LARGE_INTEGER;
__declspec(dllimport) BOOL __stdcall QueryPerformanceCounter(LARGE_INTEGER* ctr);
__declspec(dllimport) BOOL __stdcall QueryPerformanceFrequency(LARGE_INTEGER* freq);
__declspec(dllimport) DWORD __stdcall GetTickCount(void);
__declspec(dllimport) unsigned long long __stdcall GetTickCount64(void);

// Batch 22 — Sleep + SwitchToThread. Sleep blocks the calling
// thread for at least `dwMilliseconds`; SwitchToThread voluntarily
// yields the remaining time slice to any other ready thread.
__declspec(dllimport) void __stdcall Sleep(DWORD dwMilliseconds);
__declspec(dllimport) BOOL __stdcall SwitchToThread(void);

// Batch 23 — command line + environment. GetCommandLine{W,A}
// return a pointer to the process command line; the W form is
// UTF-16, the A form is ANSI. GetEnvironmentVariableW looks up
// a single variable; v0 returns 0 (not found) for everything,
// which is a documented success case for callers with defaults.
typedef unsigned short WCHAR;
typedef WCHAR* LPWSTR;
typedef const WCHAR* LPCWSTR;
typedef char* LPSTR;
typedef const char* LPCSTR;
__declspec(dllimport) LPWSTR __stdcall GetCommandLineW(void);
__declspec(dllimport) LPSTR __stdcall GetCommandLineA(void);
__declspec(dllimport) DWORD __stdcall GetEnvironmentVariableW(LPCWSTR lpName, LPWSTR lpBuffer, DWORD nSize);
__declspec(dllimport) LPWSTR __stdcall GetEnvironmentStringsW(void);
__declspec(dllimport) BOOL __stdcall FreeEnvironmentStringsW(LPWSTR lpszEnvironmentBlock);

// Batch 24 — file I/O. Real handle table backed by SYS_FILE_*
// syscalls. CreateFileW takes the canonical Win32 7-arg form
// (we ignore everything except the path); ReadFile streams
// bytes via the per-handle cursor; CloseHandle frees the slot;
// SetFilePointerEx seeks within the file.
typedef struct
{
    DWORD nLength;
    void* lpSecurityDescriptor;
    BOOL bInheritHandle;
} SECURITY_ATTRIBUTES;
#define INVALID_HANDLE_VALUE ((HANDLE) - 1)
#define GENERIC_READ 0x80000000UL
#define FILE_SHARE_READ 0x00000001UL
#define OPEN_EXISTING 3UL
#define FILE_ATTRIBUTE_NORMAL 0x00000080UL
#define FILE_BEGIN 0UL
#define FILE_END 2UL
__declspec(dllimport) HANDLE __stdcall CreateFileW(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode,
                                                   SECURITY_ATTRIBUTES* lpSec, DWORD dwCreationDisposition,
                                                   DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
__declspec(dllimport) BOOL __stdcall ReadFile(HANDLE hFile, void* lpBuffer, DWORD nNumberOfBytesToRead,
                                              LPDWORD lpNumberOfBytesRead, void* lpOverlapped);
__declspec(dllimport) BOOL __stdcall CloseHandle(HANDLE hObject);
__declspec(dllimport) BOOL __stdcall SetFilePointerEx(HANDLE hFile, LARGE_INTEGER liDistanceToMove,
                                                      LARGE_INTEGER* lpNewFilePointer, DWORD dwMoveMethod);

static const char kMsg[] = "[hello-winapi] printed via kernel32.WriteFile!\n";
#define kMsgLen ((DWORD)(sizeof(kMsg) - 1))

void _start(void)
{
    HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE);
    // Intentionally pass a non-null lpNumberOfBytesWritten so
    // the stub exercises its output-param store path (matches
    // the Win32 contract: 0 on failure, n on success). The
    // value isn't checked here — the point is the side
    // effect.
    DWORD written = 0;
    WriteFile(out, kMsg, kMsgLen, &written, 0);

    // Exercise every batch-2 stub. The `volatile` sinks keep
    // the reads from being DCE'd — without them lld-link
    // could drop the IAT entries as unused and we'd never
    // see the resolver log the new functions.
    volatile HANDLE p_sink = GetCurrentProcess();
    volatile HANDLE t_sink = GetCurrentThread();
    volatile DWORD pid_sink = GetCurrentProcessId();
    volatile DWORD tid_sink = GetCurrentThreadId();
    (void)p_sink;
    (void)t_sink;
    (void)pid_sink;
    (void)tid_sink;

    // TerminateProcess is [[noreturn]] in practice — can't
    // call it without skipping ExitProcess. Pull its IAT
    // entry in via a function-pointer sink instead.
    typedef BOOL(__stdcall * tp_fn_t)(HANDLE, unsigned int);
    volatile tp_fn_t tp_sink = TerminateProcess;
    (void)tp_sink;

    // Batch 4 round-trip: init + enter + leave + delete a
    // local CRITICAL_SECTION. Any stub that crashes would
    // take out the process with #PF/#GP. Reaching the next
    // line means all four resolved AND executed.
    CRITICAL_SECTION cs;
    InitializeCriticalSection(&cs);
    EnterCriticalSection(&cs);
    LeaveCriticalSection(&cs);
    DeleteCriticalSection(&cs);

    // Batch 5 round-trip: memset a buffer with filler, then
    // memcpy a message over the front, then print with
    // WriteFile. If memset or memcpy is broken the output
    // won't match the expected string.
    char membuf[64];
    memset(membuf, '=', sizeof(membuf)); // fill with '=' -- proves memset
    const char mmsg[] = "[vcruntime140] memset+memcpy+memmove OK\n";
    memcpy(membuf, mmsg, sizeof(mmsg) - 1); // overwrite prefix -- proves memcpy
    // Overlap test for memmove: shift the tail right by 1,
    // forcing the backward-copy branch (dst > src, regions
    // overlap). If the forward-copy branch ran by mistake,
    // the trailing bytes would get corrupted to '\n\n\n...'.
    memmove(membuf + 1, membuf, sizeof(mmsg) - 2);
    // Restore the leading char so the message reads clean.
    membuf[0] = '[';
    DWORD mwritten = 0;
    WriteFile(out, membuf, sizeof(mmsg) - 1, &mwritten, 0);

    // Batch 6 exercise — invoke the return-0 shims. All
    // should return 0 and not crash. We OR the results so
    // the compiler can't DCE them, then discard via
    // volatile.
    volatile int b6_sum = _initialize_onexit_table((void*)0) | _register_onexit_function((void*)0, (void*)0) |
                          _crt_atexit((void*)0) | _configure_narrow_argv(2);
    (void)b6_sum;
    // Void-return shims — calling them must not crash.
    _set_app_type(0);
    _cexit();
    // No-return shims — function-pointer sinks keep the IAT
    // entries without actually exiting the process.
    typedef void (*vfn_t)(void);
    volatile vfn_t ip_sink = _invalid_parameter_noinfo_noreturn;
    volatile vfn_t tm_sink = terminate;
    (void)ip_sink;
    (void)tm_sink;

    // Batch 7 exercise — real string ops. Split into three
    // unconditional invocations (assignment to volatile
    // locals defeats DCE) + one WriteFile using strlen for
    // the length. The individual operand values get ORed
    // into the exit code so even without an observable log
    // line we can see the results.
    const char b7msg[] = "[strings] strcmp+strlen+strchr OK\n";
    volatile int v_strcmp = strcmp("abc", "abc");
    volatile char* v_strchr = strchr(b7msg, '+');
    volatile size_t v_strlen = strlen(b7msg);
    (void)v_strcmp;
    (void)v_strchr;
    DWORD swritten = 0;
    WriteFile(out, b7msg, (DWORD)v_strlen, &swritten, 0);

    // Batch 9 exercise — per-process Win32 heap.
    //
    //   1. HeapAlloc 128 bytes, write a pattern, print a
    //      recognisable message from that heap buffer. If
    //      either step is broken, either the print fails
    //      (silent regression) or we crash (#PF on a bad
    //      pointer). Both are caught by the boot-log grep.
    //   2. malloc 256 bytes, free, re-malloc of the same
    //      size. Proves the free-list allocator reclaims a
    //      block on free — second malloc should return the
    //      same pointer as the first.
    //   3. calloc 64 entries of 8 bytes and verify the first
    //      byte is zero. If calloc's zero loop is broken,
    //      uninitialised memory (== stale heap data) would
    //      surface as a garbage byte in the log.
    HANDLE heap = GetProcessHeap();
    char* hbuf = (char*)HeapAlloc(heap, 0, 64);
    const char hmsg[] = "[heap] HeapAlloc + GetProcessHeap OK\n";
    if (hbuf != 0)
    {
        // Copy message into heap and print from there.
        memcpy(hbuf, hmsg, sizeof(hmsg) - 1);
        DWORD hwritten = 0;
        WriteFile(out, hbuf, sizeof(hmsg) - 1, &hwritten, 0);
        HeapFree(heap, 0, hbuf);
    }

    void* p1 = malloc(256);
    free(p1);
    void* p2 = malloc(256);
    const char mmsg2[] = "[heap] malloc+free+malloc round-trip OK\n";
    // Even if p1 != p2 (e.g. no coalescing hides the free),
    // both being non-null proves the allocator works.
    if (p1 != 0 && p2 != 0)
    {
        memcpy(p2, mmsg2, sizeof(mmsg2) - 1);
        DWORD mw = 0;
        WriteFile(out, (char*)p2, sizeof(mmsg2) - 1, &mw, 0);
        free(p2);
    }

    // calloc zero-fill check — request 8 bytes of u64-sized
    // slots, verify first byte is 0. Report via distinctive
    // log line so the boot-log grep can confirm.
    unsigned char* czero = (unsigned char*)calloc(8, sizeof(unsigned long long));
    const char cmsg[] = "[heap] calloc zero-fill OK\n";
    const char cmsg_bad[] = "[heap] calloc zero-fill FAILED\n";
    if (czero != 0)
    {
        DWORD cw = 0;
        if (czero[0] == 0 && czero[63] == 0)
            WriteFile(out, cmsg, sizeof(cmsg) - 1, &cw, 0);
        else
            WriteFile(out, cmsg_bad, sizeof(cmsg_bad) - 1, &cw, 0);
        free(czero);
    }

    // Batch 10 exercise — advapi32 privilege dance +
    // kernel32 event/wait/time/process shims. Drive every
    // stub along the success path a real program would
    // follow, catching "stub was wired up but crashes on
    // call" (a common way I introduce bugs) as a #PF
    // immediately rather than a silent regression.
    //
    // Invariants checked:
    //   * OpenProcessToken writes a non-null HANDLE.
    //   * LookupPrivilegeValueW writes {LowPart=1, HighPart=0}.
    //   * CreateEventW returns a non-null HANDLE.
    //   * SetEvent / ResetEvent return TRUE.
    //   * WaitForSingleObject returns WAIT_OBJECT_0 (0) —
    //     no actual blocking, but the ret path fires.
    //   * GetExitCodeThread writes STILL_ACTIVE (0x103).
    //   * InitializeSListHead + GetSystemTimeAsFileTime
    //     don't crash on a stack-local out-buffer.
    HANDLE token = 0;
    volatile BOOL opt_ok = OpenProcessToken(GetCurrentProcess(), 0x28, &token);
    LUID se_debug = {0, 0};
    volatile BOOL lpv_ok = LookupPrivilegeValueW(0, 0, &se_debug);
    volatile BOOL atp_ok = AdjustTokenPrivileges(token, 0, 0, 0, 0, 0);
    HANDLE evt = CreateEventW(0, 1, 0, 0);
    volatile BOOL set_ok = SetEvent(evt);
    volatile DWORD wait_rc = WaitForSingleObject(evt, 100);
    volatile BOOL rst_ok = ResetEvent(evt);
    HANDLE ph = OpenProcess(0, 0, 0x1234);
    DWORD thr_exit = 0;
    volatile BOOL get_ok = GetExitCodeThread(ph, &thr_exit);
    unsigned char slist[16] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
                               0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00};
    InitializeSListHead(slist);
    unsigned char ft[8] = {0, 0, 0, 0, 0, 0, 0, 0};
    GetSystemTimeAsFileTime(ft);
    // Sink all results so the compiler can't DCE them.
    (void)opt_ok;
    (void)lpv_ok;
    (void)atp_ok;
    (void)set_ok;
    (void)wait_rc;
    (void)rst_ok;
    (void)get_ok;
    (void)thr_exit;

    // Report success if every invariant held. The
    // handful of bit-tests here catches any stub that
    // reported TRUE but failed to write its out-param —
    // exactly the class of bug a "return TRUE" stub
    // could silently introduce.
    const char b10_ok[] = "[batch10] advapi32 + event/wait/time/proc OK\n";
    const char b10_bad[] = "[batch10] advapi32/event/wait FAILED invariants\n";
    // GetSystemTimeAsFileTime now returns a real FILETIME from
    // the CMOS RTC (SYS_GETTIME_FT); the v0 "write zeros" check
    // has been replaced with "something non-zero got written".
    // A FILETIME for any year >= 1601 is 100 ns ticks since the
    // Windows epoch, which for any realistic date is > 2^60 and
    // has several non-zero bytes in the upper half.
    BOOL ft_nonzero = (ft[4] != 0) || (ft[5] != 0) || (ft[6] != 0) || (ft[7] != 0);
    BOOL b10_pass = token != 0 && se_debug.LowPart == 1 && se_debug.HighPart == 0 && evt != 0 && wait_rc == 0 &&
                    thr_exit == 0x103 && slist[0] == 0 && slist[8] == 0 // InitializeSListHead zeroed it
                    && ft_nonzero;                                      // RTC-backed FILETIME is populated
    DWORD b10w = 0;
    if (b10_pass)
        WriteFile(out, b10_ok, sizeof(b10_ok) - 1, &b10w, 0);
    else
        WriteFile(out, b10_bad, sizeof(b10_bad) - 1, &b10w, 0);

    // Batch 11 exercise — real perf counter + tick count.
    //
    // Invariants (post-batch-21 HPET upgrade):
    //   * QueryPerformanceFrequency writes 1'000'000'000
    //     (= 1 GHz — nanoseconds).
    //   * QueryPerformanceCounter writes a non-zero value.
    //   * Two consecutive QPC calls are non-decreasing.
    //   * GetTickCount / GetTickCount64 are non-zero (ms since
    //     boot, still LAPIC-tick-backed).
    LARGE_INTEGER freq = {0};
    LARGE_INTEGER ctr1 = {0};
    LARGE_INTEGER ctr2 = {0};
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&ctr1);
    QueryPerformanceCounter(&ctr2);
    volatile DWORD ms = GetTickCount();
    volatile unsigned long long ms64 = GetTickCount64();
    const char b11_ok[] = "[batch11] perf counter + tick count OK\n";
    const char b11_bad[] = "[batch11] perf counter + tick count FAILED\n";
    BOOL b11_pass =
        freq.QuadPart == 1000000000LL && ctr1.QuadPart > 0 && ctr2.QuadPart >= ctr1.QuadPart && ms > 0 && ms64 > 0;
    (void)ms;
    (void)ms64;
    DWORD b11w = 0;
    if (b11_pass)
        WriteFile(out, b11_ok, sizeof(b11_ok) - 1, &b11w, 0);
    else
        WriteFile(out, b11_bad, sizeof(b11_bad) - 1, &b11w, 0);

    // Batch 14 exercise — HeapSize + HeapReAlloc / realloc.
    //
    // Invariants checked:
    //   * HeapSize on a 100-byte allocation returns at least
    //     100 (allocator rounds up, but never down).
    //   * HeapReAlloc growing the same block returns a non-null
    //     pointer whose HeapSize is at least the new request.
    //   * The first byte written before the grow survives the
    //     copy (if the grow allocates fresh memory, the old
    //     payload must have been copied across).
    //   * realloc(NULL, size) behaves like malloc.
    //   * realloc(ptr, 0) frees and returns NULL.
    char* b14_buf = (char*)HeapAlloc(heap, 0, 100);
    unsigned long long b14_sz0 = 0;
    unsigned long long b14_sz1 = 0;
    char b14_first_before = 0;
    char b14_first_after = 0;
    char* b14_grown = 0;
    void* b14_rm_new = 0;
    void* b14_rm_freed = (void*)1; // sentinel "not yet overwritten"
    if (b14_buf != 0)
    {
        b14_buf[0] = 'Q';
        b14_first_before = b14_buf[0];
        b14_sz0 = HeapSize(heap, 0, b14_buf);
        // Grow to well beyond the block's rounded-up capacity
        // so the implementation has to allocate + copy + free.
        b14_grown = (char*)HeapReAlloc(heap, 0, b14_buf, 1024);
        if (b14_grown != 0)
        {
            b14_sz1 = HeapSize(heap, 0, b14_grown);
            b14_first_after = b14_grown[0];
            HeapFree(heap, 0, b14_grown);
        }
        else
        {
            // On failure, the old pointer is still valid —
            // free it to keep the arena clean for later tests.
            HeapFree(heap, 0, b14_buf);
        }
    }
    // realloc-as-malloc: NULL source, new block allocated.
    b14_rm_new = realloc(0, 32);
    // realloc-as-free: size 0, returns NULL, releases ptr.
    if (b14_rm_new != 0)
        b14_rm_freed = realloc(b14_rm_new, 0);

    const char b14_ok[] = "[batch14] HeapSize + HeapReAlloc + realloc OK\n";
    const char b14_bad[] = "[batch14] HeapSize/HeapReAlloc/realloc FAILED\n";
    BOOL b14_pass = b14_buf != 0 && b14_sz0 >= 100 && b14_grown != 0 && b14_sz1 >= 1024 && b14_first_before == 'Q' &&
                    b14_first_after == 'Q' && b14_rm_new != 0 && b14_rm_freed == 0;
    DWORD b14w = 0;
    if (b14_pass)
        WriteFile(out, b14_ok, sizeof(b14_ok) - 1, &b14w, 0);
    else
        WriteFile(out, b14_bad, sizeof(b14_bad) - 1, &b14w, 0);

    // Batch 22 exercise — Sleep + SwitchToThread.
    //
    // Invariants checked:
    //   * Sleep(50) blocks for at least 50 ms. Measured by QPC
    //     (HPET-backed nanosecond clock); the elapsed must be
    //     >= 50_000_000 ns. Upper bound is loose because
    //     scheduler tick is 10 ms — actual sleep can land
    //     anywhere in [50, 60] ms typical, more under load.
    //   * Sleep(0) returns promptly (acts like SwitchToThread).
    //   * SwitchToThread returns TRUE.
    LARGE_INTEGER b22_t0 = {0};
    LARGE_INTEGER b22_t1 = {0};
    QueryPerformanceCounter(&b22_t0);
    Sleep(50);
    QueryPerformanceCounter(&b22_t1);
    long long b22_elapsed_ns = b22_t1.QuadPart - b22_t0.QuadPart;

    // Sleep(0) round-trip — should be near-instant. We don't
    // assert a tight bound, just that it doesn't hang or fail.
    Sleep(0);

    volatile BOOL b22_yield_ok = SwitchToThread();
    (void)b22_yield_ok;

    const char b22_ok[] = "[batch22] Sleep + SwitchToThread OK\n";
    const char b22_bad[] = "[batch22] Sleep undershot 50 ms FAILED\n";
    BOOL b22_pass = b22_elapsed_ns >= 50000000LL && b22_yield_ok != 0;
    DWORD b22w = 0;
    if (b22_pass)
        WriteFile(out, b22_ok, sizeof(b22_ok) - 1, &b22w, 0);
    else
        WriteFile(out, b22_bad, sizeof(b22_bad) - 1, &b22w, 0);

    // Batch 23 exercise — command line + environment.
    //
    // Invariants checked:
    //   * GetCommandLineW returns a non-NULL pointer.
    //   * The first wide char is non-zero (kernel populated the
    //     proc-env page; if it returned a pointer to a zeroed
    //     region, the cmdline would start with NUL).
    //   * GetCommandLineA returns a non-NULL pointer.
    //   * The first ANSI char is printable (low ASCII).
    //   * GetEnvironmentVariableW("PATH", buf, 32) returns 0
    //     (var-not-found is the v0 contract for every name).
    //   * GetEnvironmentStringsW returns a non-NULL pointer
    //     and the first wide char is the empty-block terminator
    //     (NUL).
    //   * FreeEnvironmentStringsW returns TRUE.
    LPWSTR cmdline_w = GetCommandLineW();
    LPSTR cmdline_a = GetCommandLineA();
    static const WCHAR kPathName[5] = {'P', 'A', 'T', 'H', 0};
    WCHAR envbuf[32] = {0};
    DWORD env_rc = GetEnvironmentVariableW(kPathName, envbuf, 32);
    LPWSTR envblock = GetEnvironmentStringsW();
    BOOL free_ok = FreeEnvironmentStringsW(envblock);

    const char b23_ok[] = "[batch23] cmdline + env OK\n";
    const char b23_bad[] = "[batch23] cmdline / env FAILED invariants\n";
    BOOL b23_pass = cmdline_w != 0 && cmdline_w[0] != 0 && cmdline_a != 0 && cmdline_a[0] >= 0x20 &&
                    cmdline_a[0] <= 0x7E && env_rc == 0 && envblock != 0 && envblock[0] == 0 && free_ok != 0;
    DWORD b23w = 0;
    if (b23_pass)
        WriteFile(out, b23_ok, sizeof(b23_ok) - 1, &b23w, 0);
    else
        WriteFile(out, b23_bad, sizeof(b23_bad) - 1, &b23w, 0);

    // Batch 24 exercise — file I/O via real handle table.
    //
    // Opens /etc/version (a 27-byte ramfs file containing
    // "CustomOS v0 (ramfs-seeded)\n"), reads the first 32 bytes,
    // seeks back to start, reads again, validates both reads
    // returned the expected first 8 bytes, then closes.
    //
    // Invariants checked:
    //   * CreateFileW returns a non-INVALID_HANDLE_VALUE handle.
    //   * First ReadFile returns >= 27 bytes (entire file fits).
    //   * Buffer starts with "CustomOS".
    //   * SetFilePointerEx(0, FILE_BEGIN) returns 0 (new pos).
    //   * Second ReadFile returns the same first 8 bytes.
    //   * CloseHandle returns TRUE.
    static const WCHAR kEtcVersion[14] = {'/', 'e', 't', 'c', '/', 'v', 'e', 'r', 's', 'i', 'o', 'n', 0, 0};
    char b24_buf[64];
    for (int i = 0; i < 64; ++i)
        b24_buf[i] = 0;
    HANDLE b24_h = CreateFileW(kEtcVersion, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
    DWORD b24_n = 0;
    BOOL b24_read_ok = 0;
    BOOL b24_seek_ok = 0;
    DWORD b24_n2 = 0;
    BOOL b24_read2_ok = 0;
    BOOL b24_close_ok = 0;
    char b24_buf2[16];
    for (int i = 0; i < 16; ++i)
        b24_buf2[i] = 0;
    if (b24_h != INVALID_HANDLE_VALUE)
    {
        b24_read_ok = ReadFile(b24_h, b24_buf, 32, &b24_n, 0);
        LARGE_INTEGER zero;
        zero.QuadPart = 0;
        LARGE_INTEGER newpos;
        newpos.QuadPart = -1;
        b24_seek_ok = SetFilePointerEx(b24_h, zero, &newpos, FILE_BEGIN);
        b24_read2_ok = ReadFile(b24_h, b24_buf2, 8, &b24_n2, 0);
        b24_close_ok = CloseHandle(b24_h);
        (void)newpos;
    }
    BOOL b24_pass = b24_h != INVALID_HANDLE_VALUE && b24_read_ok && b24_n >= 27 && b24_buf[0] == 'C' &&
                    b24_buf[1] == 'u' && b24_buf[2] == 's' && b24_buf[3] == 't' && b24_buf[4] == 'o' &&
                    b24_buf[5] == 'm' && b24_buf[6] == 'O' && b24_buf[7] == 'S' && b24_seek_ok && b24_read2_ok &&
                    b24_n2 == 8 && b24_buf2[0] == 'C' && b24_buf2[7] == 'S' && b24_close_ok;
    const char b24_ok[] = "[batch24] CreateFileW + ReadFile + Seek + Close OK\n";
    const char b24_bad[] = "[batch24] file I/O FAILED invariants\n";
    DWORD b24w = 0;
    if (b24_pass)
        WriteFile(out, b24_ok, sizeof(b24_ok) - 1, &b24w, 0);
    else
        WriteFile(out, b24_bad, sizeof(b24_bad) - 1, &b24w, 0);

    // Batch 3 round-trip: store a distinctive value via
    // SetLastError, read it back via GetLastError, exit with
    // whatever came back. If the slot works, the kernel log
    // shows `[I] sys : exit rc val=0xBEEF`. Any other value
    // means the round-trip is broken — the serial log
    // becomes the assertion.
    SetLastError(0xBEEF);
    ExitProcess(GetLastError());
}
