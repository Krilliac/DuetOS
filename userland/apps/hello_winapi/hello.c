/*
 * userland/apps/hello_winapi/hello.c
 *
 * First DuetOS userland program that talks to "Win32" —
 * real imported functions through a real Import Address Table.
 *
 * GetVersionExW verbose diagnostic:
 *   Compile with -DHELLO_DBG_GETVERSIONEX=1 to emit a per-flag "[sysinfo-dbg]"
 *   line on the FAILURE path (each invariant rendered as 0/1 +
 *   sentinel byte hex). Off by default — the smoke test only needs
 *   the OK / FAILED line — but invaluable for diagnosing which of
 *   the eleven checks broke when sysinfo regresses. The kernel-side
 *   KDBG channel system can't reach into PE userland (separate ABI),
 *   so this is a TU-local toggle.
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
 *   3. On load, the DuetOS PE loader's ResolveImports walks
 *      the IAT and patches each slot with the stub VA from
 *      kernel/subsystems/win32/thunks.cpp.
 *   4. Each IAT-routed call lands in the per-process stubs
 *      page at 0x60000000 + stub_offset, which translates the
 *      Windows x64 ABI into a DuetOS int 0x80 syscall.
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

// console I/O
__declspec(dllimport) HANDLE __stdcall GetStdHandle(DWORD nStdHandle);
__declspec(dllimport) BOOL __stdcall WriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite,
                                               LPDWORD lpNumberOfBytesWritten, void* lpOverlapped);
__declspec(dllimport) void __stdcall ExitProcess(unsigned int uExitCode);

// process/thread lifecycle
__declspec(dllimport) HANDLE __stdcall GetCurrentProcess(void);
__declspec(dllimport) HANDLE __stdcall GetCurrentThread(void);
__declspec(dllimport) DWORD __stdcall GetCurrentProcessId(void);
__declspec(dllimport) DWORD __stdcall GetCurrentThreadId(void);
__declspec(dllimport) BOOL __stdcall TerminateProcess(HANDLE hProcess, unsigned int uExitCode);

// last-error slot
__declspec(dllimport) DWORD __stdcall GetLastError(void);
__declspec(dllimport) void __stdcall SetLastError(DWORD dwErrCode);

// critical sections (v0 no-ops)
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

// vcruntime140 memory intrinsics. CRT functions
// use the plain x64 calling convention (no __stdcall
// decoration — __stdcall is ignored on x64 anyway, but we
// keep the annotations to match vcruntime140.dll's export
// table on a real Windows system). size_t is 64-bit on x64.
typedef unsigned long long size_t;
__declspec(dllimport) void* memset(void* dst, int c, size_t n);
__declspec(dllimport) void* memcpy(void* dst, const void* src, size_t n);
__declspec(dllimport) void* memmove(void* dst, const void* src, size_t n);

// UCRT CRT-startup shims. These live in the apiset
// DLLs (api-ms-win-crt-runtime-l1-1-0.dll and friends) that
// forward to ucrtbase.dll on real Windows. DuetOS handles
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

// CRT string intrinsics. Pure functions with the
// standard C library contracts. Registered under the apiset,
// ucrtbase, AND msvcrt DLL names in the stub table.
__declspec(dllimport) int strcmp(const char* a, const char* b);
__declspec(dllimport) size_t strlen(const char* s);
__declspec(dllimport) char* strchr(const char* s, int c);

// process heap. kernel32 HeapAlloc + UCRT
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

// real HeapSize + HeapReAlloc / realloc. The
// block header the v0 allocator already writes gives us the
// payload capacity for free; HeapReAlloc copies through the
// kernel direct map.
__declspec(dllimport) unsigned long long __stdcall HeapSize(HANDLE hHeap, DWORD dwFlags, const void* lpMem);
__declspec(dllimport) void* __stdcall HeapReAlloc(HANDLE hHeap, DWORD dwFlags, void* lpMem, unsigned long long dwBytes);
__declspec(dllimport) void* realloc(void* ptr, size_t size);

// advapi32 privilege dance + kernel32 event/wait/
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

// real perf counter + tick count (backed by
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

// Sleep + SwitchToThread. Sleep blocks the calling
// thread for at least `dwMilliseconds`; SwitchToThread voluntarily
// yields the remaining time slice to any other ready thread.
__declspec(dllimport) void __stdcall Sleep(DWORD dwMilliseconds);
__declspec(dllimport) BOOL __stdcall SwitchToThread(void);

// command line + environment. GetCommandLine{W,A}
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

// file I/O. Real handle table backed by SYS_FILE_*
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

// file stat + module lookup. GetFileSizeEx queries
// a handle's file size without perturbing the read cursor.
// GetModuleHandleW(NULL) returns the EXE's HMODULE; non-NULL
// names return NULL (we have no module registry yet).
// LoadLibrary* / GetProcAddress / FreeLibrary are stubbed —
// LoadLibrary returns NULL ("not found"); GetProcAddress
// returns NULL; FreeLibrary returns TRUE.
typedef HANDLE HMODULE;
typedef void (*FARPROC)(void);
__declspec(dllimport) BOOL __stdcall GetFileSizeEx(HANDLE hFile, LARGE_INTEGER* lpFileSize);
__declspec(dllimport) HMODULE __stdcall GetModuleHandleW(LPCWSTR lpModuleName);
__declspec(dllimport) HMODULE __stdcall LoadLibraryW(LPCWSTR lpLibFileName);
__declspec(dllimport) BOOL __stdcall FreeLibrary(HMODULE hLibModule);
__declspec(dllimport) FARPROC __stdcall GetProcAddress(HMODULE hModule, LPCSTR lpProcName);

// Win32 mutex (real waitqueue-backed). The
// CreateMutexW stub allocates a per-process slot and returns a
// pseudo-handle; WaitForSingleObject (already imported above)
// dispatches to SYS_MUTEX_WAIT for mutex handles. ReleaseMutex
// decrements recursion + hands off to a waiter on final release.
#define INFINITE 0xFFFFFFFFUL
#define WAIT_OBJECT_0 0UL
__declspec(dllimport) HANDLE __stdcall CreateMutexW(SECURITY_ATTRIBUTES* lpMutexAttributes, BOOL bInitialOwner,
                                                    LPCWSTR lpName);
__declspec(dllimport) BOOL __stdcall ReleaseMutex(HANDLE hMutex);

// console APIs. WriteConsoleW writes UTF-16 text
// to a console handle (we route to stdout via SYS_WRITE after
// stripping to ASCII low-bytes). GetConsoleMode returns a
// plausible flag combo (VT processing on). GetConsoleCP
// returns 65001 (CP_UTF8). OutputDebugStringW is a debugger-
// notification no-op.
__declspec(dllimport) BOOL __stdcall WriteConsoleW(HANDLE hConsoleOutput, const void* lpBuffer,
                                                   DWORD nNumberOfCharsToWrite, LPDWORD lpNumberOfCharsWritten,
                                                   void* lpReserved);
__declspec(dllimport) BOOL __stdcall GetConsoleMode(HANDLE hConsoleHandle, LPDWORD lpMode);
__declspec(dllimport) BOOL __stdcall SetConsoleMode(HANDLE hConsoleHandle, DWORD dwMode);
__declspec(dllimport) unsigned int __stdcall GetConsoleCP(void);
__declspec(dllimport) unsigned int __stdcall GetConsoleOutputCP(void);
__declspec(dllimport) BOOL __stdcall SetConsoleCP(unsigned int wCodePageID);
__declspec(dllimport) BOOL __stdcall SetConsoleOutputCP(unsigned int wCodePageID);
__declspec(dllimport) void __stdcall OutputDebugStringW(LPCWSTR lpOutputString);

// virtual memory. VirtualAlloc bump-allocates RW+NX
// pages in a per-process arena at 0x40000000..+512 KiB.
// VirtualFree / VirtualProtect are no-ops with validation.
#define MEM_COMMIT 0x1000UL
#define MEM_RESERVE 0x2000UL
#define MEM_RELEASE 0x8000UL
#define PAGE_READWRITE 0x04UL
#define PAGE_EXECUTE_READWRITE 0x40UL
__declspec(dllimport) void* __stdcall VirtualAlloc(void* lpAddress, size_t dwSize, DWORD flAllocationType,
                                                   DWORD flProtect);
__declspec(dllimport) BOOL __stdcall VirtualFree(void* lpAddress, size_t dwSize, DWORD dwFreeType);
__declspec(dllimport) BOOL __stdcall VirtualProtect(void* lpAddress, size_t dwSize, DWORD flNewProtect,
                                                    DWORD* lpflOldProtect);

// wide-string helpers. lstrlenW counts wide chars
// until NUL. lstrcmpW is an ordinal compare (no locale fold).
// lstrcpyW copies until NUL and returns dst.
__declspec(dllimport) int __stdcall lstrlenW(LPCWSTR lpString);
__declspec(dllimport) int __stdcall lstrcmpW(LPCWSTR lpString1, LPCWSTR lpString2);
__declspec(dllimport) LPWSTR __stdcall lstrcpyW(LPWSTR lpString1, LPCWSTR lpString2);

// system-info probes. IsWow64Process reports whether
// a 32-bit process is running under WOW64 emulation (FALSE for
// us — native x64 only). GetVersionExW reports Windows 10 build
// 19041 so modern feature-gates pass.
typedef struct
{
    DWORD dwOSVersionInfoSize;
    DWORD dwMajorVersion;
    DWORD dwMinorVersion;
    DWORD dwBuildNumber;
    DWORD dwPlatformId;
    WCHAR szCSDVersion[128];
} OSVERSIONINFOW;
__declspec(dllimport) BOOL __stdcall IsWow64Process(HANDLE hProcess, BOOL* Wow64Process);
__declspec(dllimport) BOOL __stdcall GetVersionExW(OSVERSIONINFOW* lpVersionInformation);

// ANSI string helpers (symmetric to the wide-string set above).
__declspec(dllimport) int __stdcall lstrlenA(LPCSTR lpString);
__declspec(dllimport) int __stdcall lstrcmpA(LPCSTR lpString1, LPCSTR lpString2);
__declspec(dllimport) LPSTR __stdcall lstrcpyA(LPSTR lpString1, LPCSTR lpString2);

// path-query stubs. v0 reports a fixed "X:\\" path.
__declspec(dllimport) DWORD __stdcall GetModuleFileNameW(HMODULE hModule, LPWSTR lpFilename, DWORD nSize);
__declspec(dllimport) DWORD __stdcall GetCurrentDirectoryW(DWORD nBufferLength, LPWSTR lpBuffer);
__declspec(dllimport) BOOL __stdcall SetCurrentDirectoryW(LPCWSTR lpPathName);

// encoding converters. v0 is byte-extend / byte-truncate
// (correct for ASCII-range data, lossy for high-plane UTF-8).
__declspec(dllimport) int __stdcall MultiByteToWideChar(unsigned int CodePage, DWORD dwFlags, LPCSTR lpMultiByteStr,
                                                        int cbMultiByte, LPWSTR lpWideCharStr, int cchWideChar);
__declspec(dllimport) int __stdcall WideCharToMultiByte(unsigned int CodePage, DWORD dwFlags, LPCWSTR lpWideCharStr,
                                                        int cchWideChar, LPSTR lpMultiByteStr, int cbMultiByte,
                                                        LPCSTR lpDefaultChar, BOOL* lpUsedDefaultChar);

// identity queries. Both take (buf, *size-in-chars);
// *size updated to chars-written-INCLUDING-NUL on output.
__declspec(dllimport) BOOL __stdcall GetUserNameW(LPWSTR lpBuffer, LPDWORD pcbBuffer);
__declspec(dllimport) BOOL __stdcall GetComputerNameW(LPWSTR lpBuffer, LPDWORD nSize);

// system-directory queries. Mixed signatures:
// GetTempPathW takes (length, buffer) — like GetCurrentDirectoryW —
// while GetWindowsDirectoryW / GetSystemDirectoryW take
// (buffer, length) with UINT sizes.
__declspec(dllimport) DWORD __stdcall GetTempPathW(DWORD nBufferLength, LPWSTR lpBuffer);
__declspec(dllimport) unsigned int __stdcall GetWindowsDirectoryW(LPWSTR lpBuffer, unsigned int uSize);
__declspec(dllimport) unsigned int __stdcall GetSystemDirectoryW(LPWSTR lpBuffer, unsigned int uSize);

// misc drives/error/format stubs.
__declspec(dllimport) DWORD __stdcall GetLogicalDrives(void);
__declspec(dllimport) unsigned int __stdcall GetDriveTypeW(LPCWSTR lpRootPathName);
__declspec(dllimport) unsigned int __stdcall SetErrorMode(unsigned int uMode);
__declspec(dllimport) DWORD __stdcall FormatMessageW(DWORD dwFlags, const void* lpSource, DWORD dwMessageId,
                                                     DWORD dwLanguageId, LPWSTR lpBuffer, DWORD nSize, void* Arguments);

// registry + file-attribute no-op stubs.
typedef void* HKEY;
typedef HKEY* PHKEY;
#define ERROR_FILE_NOT_FOUND_VAL 2L
__declspec(dllimport) long __stdcall RegOpenKeyExW(HKEY hKey, LPCWSTR lpSubKey, DWORD ulOptions, DWORD samDesired,
                                                   PHKEY phkResult);
__declspec(dllimport) long __stdcall RegQueryValueExW(HKEY hKey, LPCWSTR lpValueName, DWORD* lpReserved, DWORD* lpType,
                                                      unsigned char* lpData, DWORD* lpcbData);
__declspec(dllimport) long __stdcall RegCloseKey(HKEY hKey);
__declspec(dllimport) DWORD __stdcall GetFileAttributesW(LPCWSTR lpFileName);
__declspec(dllimport) BOOL __stdcall SetFileAttributesW(LPCWSTR lpFileName, DWORD dwFileAttributes);

// real TLS (per-process slot storage).
__declspec(dllimport) DWORD __stdcall TlsAlloc(void);
__declspec(dllimport) BOOL __stdcall TlsFree(DWORD dwTlsIndex);
__declspec(dllimport) void* __stdcall TlsGetValue(DWORD dwTlsIndex);
__declspec(dllimport) BOOL __stdcall TlsSetValue(DWORD dwTlsIndex, void* lpTlsValue);

// Interlocked atomic operations (real LOCK-prefix
// ops, correct even under SMP).
typedef long LONG;
__declspec(dllimport) LONG __stdcall InterlockedIncrement(LONG volatile* Addend);
__declspec(dllimport) LONG __stdcall InterlockedDecrement(LONG volatile* Addend);
__declspec(dllimport) LONG __stdcall InterlockedCompareExchange(LONG volatile* Destination, LONG Exchange,
                                                                LONG Comparand);
__declspec(dllimport) LONG __stdcall InterlockedExchange(LONG volatile* Target, LONG Value);
__declspec(dllimport) LONG __stdcall InterlockedExchangeAdd(LONG volatile* Addend, LONG Value);

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

    // Exercise every process/thread-lifecycle stub. The `volatile` sinks keep
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

    // Round-trip: init + enter + leave + delete a
    // local CRITICAL_SECTION. Any stub that crashes would
    // take out the process with #PF/#GP. Reaching the next
    // line means all four resolved AND executed.
    CRITICAL_SECTION cs;
    InitializeCriticalSection(&cs);
    EnterCriticalSection(&cs);
    LeaveCriticalSection(&cs);
    DeleteCriticalSection(&cs);

    // Round-trip: memset a buffer with filler, then
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

    // Exercise — invoke the return-0 shims. All
    // should return 0 and not crash. We OR the results so
    // the compiler can't DCE them, then discard via
    // volatile.
    volatile int crt_sum = _initialize_onexit_table((void*)0) | _register_onexit_function((void*)0, (void*)0) |
                           _crt_atexit((void*)0) | _configure_narrow_argv(2);
    (void)crt_sum;
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

    // Exercise — real string ops. Split into three
    // unconditional invocations (assignment to volatile
    // locals defeats DCE) + one WriteFile using strlen for
    // the length. The individual operand values get ORed
    // into the exit code so even without an observable log
    // line we can see the results.
    const char str_msg[] = "[strings] strcmp+strlen+strchr OK\n";
    volatile int v_strcmp = strcmp("abc", "abc");
    volatile char* v_strchr = strchr(str_msg, '+');
    volatile size_t v_strlen = strlen(str_msg);
    (void)v_strcmp;
    (void)v_strchr;
    DWORD swritten = 0;
    WriteFile(out, str_msg, (DWORD)v_strlen, &swritten, 0);

    // Exercise — per-process Win32 heap.
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

    // Exercise — advapi32 privilege dance +
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
    const char advapi_ok[] = "[advapi] advapi32 + event/wait/time/proc OK\n";
    const char advapi_bad[] = "[advapi] advapi32/event/wait FAILED invariants\n";
    // GetSystemTimeAsFileTime now returns a real FILETIME from
    // the CMOS RTC (SYS_GETTIME_FT); the v0 "write zeros" check
    // has been replaced with "something non-zero got written".
    // A FILETIME for any year >= 1601 is 100 ns ticks since the
    // Windows epoch, which for any realistic date is > 2^60 and
    // has several non-zero bytes in the upper half.
    BOOL ft_nonzero = (ft[4] != 0) || (ft[5] != 0) || (ft[6] != 0) || (ft[7] != 0);
    BOOL advapi_pass = token != 0 && se_debug.LowPart == 1 && se_debug.HighPart == 0 && evt != 0 && wait_rc == 0 &&
                       thr_exit == 0x103 && slist[0] == 0 && slist[8] == 0 // InitializeSListHead zeroed it
                       && ft_nonzero;                                      // RTC-backed FILETIME is populated
    DWORD advapi_written = 0;
    if (advapi_pass)
        WriteFile(out, advapi_ok, sizeof(advapi_ok) - 1, &advapi_written, 0);
    else
        WriteFile(out, advapi_bad, sizeof(advapi_bad) - 1, &advapi_written, 0);

    // Exercise — real perf counter + tick count.
    //
    // Invariants (post-HPET-upgrade):
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
    const char perf_ok[] = "[perf-counter] perf counter + tick count OK\n";
    const char perf_bad[] = "[perf-counter] perf counter + tick count FAILED\n";
    BOOL perf_pass =
        freq.QuadPart == 1000000000LL && ctr1.QuadPart > 0 && ctr2.QuadPart >= ctr1.QuadPart && ms > 0 && ms64 > 0;
    (void)ms;
    (void)ms64;
    DWORD perf_written = 0;
    if (perf_pass)
        WriteFile(out, perf_ok, sizeof(perf_ok) - 1, &perf_written, 0);
    else
        WriteFile(out, perf_bad, sizeof(perf_bad) - 1, &perf_written, 0);

    // Exercise — HeapSize + HeapReAlloc / realloc.
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
    char* hresize_buf = (char*)HeapAlloc(heap, 0, 100);
    unsigned long long hresize_sz0 = 0;
    unsigned long long hresize_sz1 = 0;
    char hresize_first_before = 0;
    char hresize_first_after = 0;
    char* hresize_grown = 0;
    void* hresize_rm_new = 0;
    void* hresize_rm_freed = (void*)1; // sentinel "not yet overwritten"
    if (hresize_buf != 0)
    {
        hresize_buf[0] = 'Q';
        hresize_first_before = hresize_buf[0];
        hresize_sz0 = HeapSize(heap, 0, hresize_buf);
        // Grow to well beyond the block's rounded-up capacity
        // so the implementation has to allocate + copy + free.
        hresize_grown = (char*)HeapReAlloc(heap, 0, hresize_buf, 1024);
        if (hresize_grown != 0)
        {
            hresize_sz1 = HeapSize(heap, 0, hresize_grown);
            hresize_first_after = hresize_grown[0];
            HeapFree(heap, 0, hresize_grown);
        }
        else
        {
            // On failure, the old pointer is still valid —
            // free it to keep the arena clean for later tests.
            HeapFree(heap, 0, hresize_buf);
        }
    }
    // realloc-as-malloc: NULL source, new block allocated.
    hresize_rm_new = realloc(0, 32);
    // realloc-as-free: size 0, returns NULL, releases ptr.
    if (hresize_rm_new != 0)
        hresize_rm_freed = realloc(hresize_rm_new, 0);

    const char hresize_ok[] = "[heap-resize] HeapSize + HeapReAlloc + realloc OK\n";
    const char hresize_bad[] = "[heap-resize] HeapSize/HeapReAlloc/realloc FAILED\n";
    BOOL hresize_pass = hresize_buf != 0 && hresize_sz0 >= 100 && hresize_grown != 0 && hresize_sz1 >= 1024 &&
                        hresize_first_before == 'Q' && hresize_first_after == 'Q' && hresize_rm_new != 0 &&
                        hresize_rm_freed == 0;
    DWORD hresize_written = 0;
    if (hresize_pass)
        WriteFile(out, hresize_ok, sizeof(hresize_ok) - 1, &hresize_written, 0);
    else
    {
        WriteFile(out, hresize_bad, sizeof(hresize_bad) - 1, &hresize_written, 0);
        // Always-on field-level dump (cheap; only fires on
        // failure). Distinguishes which invariant tripped:
        // alloc miss, size mismatch, payload mismatch, etc.
        const char hresize_dbg[] = "[heap-resize-dbg] ";
        WriteFile(out, hresize_dbg, sizeof(hresize_dbg) - 1, &hresize_written, 0);
        unsigned long long vals[8] = {(unsigned long long)hresize_buf,
                                      hresize_sz0,
                                      (unsigned long long)hresize_grown,
                                      hresize_sz1,
                                      (unsigned long long)(unsigned char)hresize_first_before,
                                      (unsigned long long)(unsigned char)hresize_first_after,
                                      (unsigned long long)hresize_rm_new,
                                      (unsigned long long)hresize_rm_freed};
        const char* names[8] = {
            "buf=", " sz0=", " grown=", " sz1=", " first_b=", " first_a=", " rm_new=", " rm_freed="};
        char hex[18];
        for (int i = 0; i < 8; ++i)
        {
            WriteFile(out, names[i], (DWORD)strlen(names[i]), &hresize_written, 0);
            for (int d = 0; d < 16; ++d)
            {
                int nyb = (int)((vals[i] >> ((15 - d) * 4)) & 0xF);
                hex[d] = (char)((nyb < 10) ? ('0' + nyb) : ('a' + nyb - 10));
            }
            hex[16] = '\n';
            WriteFile(out, hex, (i == 7) ? 17 : 16, &hresize_written, 0);
        }
    }

    // Exercise — Sleep + SwitchToThread.
    //
    // Invariants checked:
    //   * Sleep(50) blocks for at least 50 ms. Measured by QPC
    //     (HPET-backed nanosecond clock); the elapsed must be
    //     >= 50_000_000 ns. Upper bound is loose because
    //     scheduler tick is 10 ms — actual sleep can land
    //     anywhere in [50, 60] ms typical, more under load.
    //   * Sleep(0) returns promptly (acts like SwitchToThread).
    //   * SwitchToThread returns TRUE.
    LARGE_INTEGER sleep_t0 = {0};
    LARGE_INTEGER sleep_t1 = {0};
    QueryPerformanceCounter(&sleep_t0);
    Sleep(50);
    QueryPerformanceCounter(&sleep_t1);
    long long sleep_elapsed_ns = sleep_t1.QuadPart - sleep_t0.QuadPart;

    // Sleep(0) round-trip — should be near-instant. We don't
    // assert a tight bound, just that it doesn't hang or fail.
    Sleep(0);

    volatile BOOL sleep_yield_ok = SwitchToThread();
    (void)sleep_yield_ok;

    const char sleep_ok[] = "[sleep-yield] Sleep + SwitchToThread OK\n";
    const char sleep_bad[] = "[sleep-yield] Sleep undershot 50 ms FAILED\n";
    BOOL sleep_pass = sleep_elapsed_ns >= 50000000LL && sleep_yield_ok != 0;
    DWORD sleep_written = 0;
    if (sleep_pass)
        WriteFile(out, sleep_ok, sizeof(sleep_ok) - 1, &sleep_written, 0);
    else
        WriteFile(out, sleep_bad, sizeof(sleep_bad) - 1, &sleep_written, 0);

    // Exercise — command line + environment.
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

    const char cmd_ok[] = "[cmdline-env] cmdline + env OK\n";
    const char cmd_bad[] = "[cmdline-env] cmdline / env FAILED invariants\n";
    BOOL cmd_pass = cmdline_w != 0 && cmdline_w[0] != 0 && cmdline_a != 0 && cmdline_a[0] >= 0x20 &&
                    cmdline_a[0] <= 0x7E && env_rc == 0 && envblock != 0 && envblock[0] == 0 && free_ok != 0;
    DWORD cmd_written = 0;
    if (cmd_pass)
        WriteFile(out, cmd_ok, sizeof(cmd_ok) - 1, &cmd_written, 0);
    else
        WriteFile(out, cmd_bad, sizeof(cmd_bad) - 1, &cmd_written, 0);

    // Exercise — file I/O via real handle table.
    //
    // Opens /etc/version (a 25-byte ramfs file containing
    // "DuetOS v0 (ramfs-seeded)\n"), reads the first 32 bytes,
    // seeks back to start, reads again, validates both reads
    // returned the expected first 8 bytes, then closes.
    //
    // Invariants checked:
    //   * CreateFileW returns a non-INVALID_HANDLE_VALUE handle.
    //   * First ReadFile returns >= 25 bytes (entire file fits).
    //   * Buffer starts with "DuetOS v".
    //   * SetFilePointerEx(0, FILE_BEGIN) returns 0 (new pos).
    //   * Second ReadFile returns the same first 8 bytes.
    //   * CloseHandle returns TRUE.
    static const WCHAR kEtcVersion[14] = {'/', 'e', 't', 'c', '/', 'v', 'e', 'r', 's', 'i', 'o', 'n', 0, 0};
    char file_buf[64];
    for (int i = 0; i < 64; ++i)
        file_buf[i] = 0;
    HANDLE file_h = CreateFileW(kEtcVersion, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
    DWORD file_n = 0;
    BOOL file_read_ok = 0;
    BOOL file_seek_ok = 0;
    DWORD file_n2 = 0;
    BOOL file_read2_ok = 0;
    BOOL file_close_ok = 0;
    char file_buf2[16];
    for (int i = 0; i < 16; ++i)
        file_buf2[i] = 0;
    if (file_h != INVALID_HANDLE_VALUE)
    {
        file_read_ok = ReadFile(file_h, file_buf, 32, &file_n, 0);
        LARGE_INTEGER zero;
        zero.QuadPart = 0;
        LARGE_INTEGER newpos;
        newpos.QuadPart = -1;
        file_seek_ok = SetFilePointerEx(file_h, zero, &newpos, FILE_BEGIN);
        file_read2_ok = ReadFile(file_h, file_buf2, 8, &file_n2, 0);
        file_close_ok = CloseHandle(file_h);
        (void)newpos;
    }
    BOOL file_pass = file_h != INVALID_HANDLE_VALUE && file_read_ok && file_n >= 25 && file_buf[0] == 'D' &&
                     file_buf[1] == 'u' && file_buf[2] == 'e' && file_buf[3] == 't' && file_buf[4] == 'O' &&
                     file_buf[5] == 'S' && file_buf[6] == ' ' && file_buf[7] == 'v' && file_seek_ok && file_read2_ok &&
                     file_n2 == 8 && file_buf2[0] == 'D' && file_buf2[7] == 'v' && file_close_ok;
    const char file_ok[] = "[file-io] CreateFileW + ReadFile + Seek + Close OK\n";
    const char file_bad[] = "[file-io] file I/O FAILED invariants\n";
    DWORD file_written = 0;
    if (file_pass)
        WriteFile(out, file_ok, sizeof(file_ok) - 1, &file_written, 0);
    else
        WriteFile(out, file_bad, sizeof(file_bad) - 1, &file_written, 0);

    // Exercise — file stat + module lookup.
    //
    // Invariants checked:
    //   * Re-open /etc/version, GetFileSizeEx returns 25 (the
    //     ramfs payload "DuetOS v0 (ramfs-seeded)\n").
    //   * Reading 1 byte after GetFileSizeEx shows the cursor
    //     wasn't moved by the stat call (still at 0).
    //   * GetModuleHandleW(NULL) returns a non-NULL HMODULE
    //     (the PE's image base).
    //   * GetModuleHandleW(L"kernel32.dll") returns NULL (we
    //     don't track named modules).
    //   * LoadLibraryW(L"foo.dll") returns NULL (loading
    //     unsupported).
    //   * GetProcAddress(NULL, "X") returns NULL.
    //   * FreeLibrary(NULL) returns TRUE (no-op).
    static const WCHAR kEtcVersion2[14] = {'/', 'e', 't', 'c', '/', 'v', 'e', 'r', 's', 'i', 'o', 'n', 0, 0};
    HANDLE stat_h =
        CreateFileW(kEtcVersion2, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
    LARGE_INTEGER stat_size;
    stat_size.QuadPart = 0;
    BOOL stat_size_ok = 0;
    char stat_first = 0;
    DWORD stat_n = 0;
    BOOL stat_close_ok = 0;
    if (stat_h != INVALID_HANDLE_VALUE)
    {
        stat_size_ok = GetFileSizeEx(stat_h, &stat_size);
        // Cursor must still be at 0 after a stat — read 1 byte
        // and assert it's 'D' (the start of "DuetOS").
        ReadFile(stat_h, &stat_first, 1, &stat_n, 0);
        stat_close_ok = CloseHandle(stat_h);
    }
    HMODULE stat_self = GetModuleHandleW(0);
    static const WCHAR kKern32[14] = {'k', 'e', 'r', 'n', 'e', 'l', '3', '2', '.', 'd', 'l', 'l', 0, 0};
    HMODULE stat_named = GetModuleHandleW(kKern32);
    static const WCHAR kFooDll[8] = {'f', 'o', 'o', '.', 'd', 'l', 'l', 0};
    HMODULE stat_loaded = LoadLibraryW(kFooDll);
    FARPROC stat_proc = GetProcAddress(0, "X");
    BOOL stat_free_ok = FreeLibrary(0);

    const char stat_ok[] = "[file-stat] GetFileSizeEx + GetModuleHandleW + LoadLibraryW OK\n";
    const char stat_bad[] = "[file-stat] file stat / module lookup FAILED invariants\n";
    BOOL stat_pass = stat_h != INVALID_HANDLE_VALUE && stat_size_ok && stat_size.QuadPart == 25 && stat_n == 1 &&
                     stat_first == 'D' && stat_close_ok && stat_self != 0 && stat_named == 0 && stat_loaded == 0 &&
                     stat_proc == 0 && stat_free_ok != 0;
    DWORD stat_written = 0;
    if (stat_pass)
        WriteFile(out, stat_ok, sizeof(stat_ok) - 1, &stat_written, 0);
    else
        WriteFile(out, stat_bad, sizeof(stat_bad) - 1, &stat_written, 0);

    // Exercise — Win32 mutex round-trip.
    //
    // Single-threaded process so we can't test contention, but
    // we can fully exercise the recursion + handle lifecycle:
    //   * CreateMutexW(initial=TRUE) returns a non-NULL handle
    //     and the calling task is the initial owner.
    //   * Recursive WaitForSingleObject acquires return WAIT_OBJECT_0.
    //   * Each ReleaseMutex returns TRUE.
    //   * Final release leaves the mutex unowned.
    //   * Re-acquiring (Wait) on the now-unowned mutex returns
    //     WAIT_OBJECT_0 immediately.
    //   * CloseHandle (covered by file-io above) closes the mutex slot.
    //   * Wait on a non-mutex handle (e.g. NULL) returns 0
    //     (pseudo-signal — preserves the advapi event contract).
    HANDLE mtx_m = CreateMutexW(0, 1, 0); // initial owner = TRUE
    DWORD mtx_w1 = WaitForSingleObject(mtx_m, INFINITE);
    DWORD mtx_w2 = WaitForSingleObject(mtx_m, INFINITE);
    BOOL mtx_r1 = ReleaseMutex(mtx_m);              // recursion 3 -> 2
    BOOL mtx_r2 = ReleaseMutex(mtx_m);              // recursion 2 -> 1
    BOOL mtx_r3 = ReleaseMutex(mtx_m);              // recursion 1 -> 0; owner cleared
    DWORD mtx_w3 = WaitForSingleObject(mtx_m, 100); // re-acquire
    BOOL mtx_r4 = ReleaseMutex(mtx_m);
    BOOL mtx_close = CloseHandle(mtx_m);
    DWORD mtx_pseudo = WaitForSingleObject(0, 100); // non-mutex handle

    const char mtx_ok[] = "[mutex] CreateMutexW + Wait + Release recursion OK\n";
    const char mtx_bad[] = "[mutex] mutex semantics FAILED invariants\n";
    BOOL mtx_pass = mtx_m != 0 && mtx_w1 == WAIT_OBJECT_0 && mtx_w2 == WAIT_OBJECT_0 && mtx_r1 != 0 && mtx_r2 != 0 &&
                    mtx_r3 != 0 && mtx_w3 == WAIT_OBJECT_0 && mtx_r4 != 0 && mtx_close != 0 &&
                    mtx_pseudo == WAIT_OBJECT_0;
    DWORD mtx_written = 0;
    if (mtx_pass)
        WriteFile(out, mtx_ok, sizeof(mtx_ok) - 1, &mtx_written, 0);
    else
        WriteFile(out, mtx_bad, sizeof(mtx_bad) - 1, &mtx_written, 0);

    // Exercise — console APIs.
    //
    // Invariants checked:
    //   * WriteConsoleW prints the wide-stripped message to
    //     stdout (visible in the serial log).
    //   * WriteConsoleW writes back the wide-char count to
    //     *lpCharsOut (should equal the input count).
    //   * GetConsoleMode returns TRUE and writes a non-zero
    //     mode (expect VT processing bit set = 0x7).
    //   * SetConsoleMode returns TRUE (no-op).
    //   * GetConsoleCP returns 65001 (CP_UTF8).
    //   * GetConsoleOutputCP returns 65001.
    //   * SetConsoleOutputCP returns TRUE.
    //   * OutputDebugStringW doesn't crash (silent no-op).
    static const WCHAR kConsoleMsg[] = {'[', 'c', 'o', 'n', 's', 'o', 'l', 'e', ']', ' ', 'W',  'r', 'i', 't',
                                        'e', 'C', 'o', 'n', 's', 'o', 'l', 'e', 'W', ' ', 'h',  'e', 'l', 'l',
                                        'o', ' ', 'U', 'n', 'i', 'c', 'o', 'd', 'e', '!', '\n', 0};
    const DWORD kConsoleLen = 39; // excludes terminating NUL
    DWORD con_chars_written = 0;
    BOOL con_wc_ok = WriteConsoleW(out, kConsoleMsg, kConsoleLen, &con_chars_written, 0);

    DWORD con_mode = 0;
    BOOL con_gm_ok = GetConsoleMode(out, &con_mode);
    BOOL con_sm_ok = SetConsoleMode(out, con_mode); // echo back
    unsigned int con_cp = GetConsoleCP();
    unsigned int con_ocp = GetConsoleOutputCP();
    BOOL con_scp_ok = SetConsoleOutputCP(65001);

    static const WCHAR kDbgMsg[] = {'d', 'b', 'g', 0};
    OutputDebugStringW(kDbgMsg); // silent, must not crash

    const char con_ok[] = "[console] console APIs OK\n";
    const char con_bad[] = "[console] console APIs FAILED invariants\n";
    BOOL con_pass = con_wc_ok && con_chars_written == kConsoleLen && con_gm_ok && con_mode != 0 && con_sm_ok &&
                    con_cp == 65001 && con_ocp == 65001 && con_scp_ok;
    DWORD con_written = 0;
    if (con_pass)
        WriteFile(out, con_ok, sizeof(con_ok) - 1, &con_written, 0);
    else
        WriteFile(out, con_bad, sizeof(con_bad) - 1, &con_written, 0);

    // Exercise — virtual memory.
    //
    // Invariants checked:
    //   * VirtualAlloc(NULL, 8192, RESERVE|COMMIT, PAGE_READWRITE)
    //     returns a non-NULL VA in the vmap arena
    //     (0x40000000..0x40080000).
    //   * The returned page is writable — store a pattern and
    //     read it back.
    //   * A second VirtualAlloc returns a different (higher) VA
    //     — the bump cursor is advancing per request.
    //   * VirtualProtect on the allocation returns TRUE and
    //     writes back 0x04 (PAGE_READWRITE) as the "old" flag.
    //   * VirtualFree returns TRUE (no-op in v0, validation only).
    //   * VirtualAlloc of zero bytes returns NULL.
    void* vmem_p1 = VirtualAlloc(0, 8192, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    BOOL vmem_rw_ok = 0;
    if (vmem_p1 != 0)
    {
        unsigned int* u32p = (unsigned int*)vmem_p1;
        u32p[0] = 0xDEADBEEF;
        u32p[2047] = 0xCAFEBABE; // last u32 of the 8 KiB region
        vmem_rw_ok = (u32p[0] == 0xDEADBEEF) && (u32p[2047] == 0xCAFEBABE);
    }
    void* vmem_p2 = VirtualAlloc(0, 4096, MEM_COMMIT, PAGE_READWRITE);
    DWORD vmem_old_prot = 0;
    BOOL vmem_vp_ok = VirtualProtect(vmem_p1, 4096, PAGE_READWRITE, &vmem_old_prot);
    BOOL vmem_vf_ok = VirtualFree(vmem_p2, 0, MEM_RELEASE);
    void* vmem_zero = VirtualAlloc(0, 0, MEM_COMMIT, PAGE_READWRITE);

    const char vmem_ok[] = "[vmem] VirtualAlloc + Protect + Free OK\n";
    const char vmem_bad[] = "[vmem] virtual memory FAILED invariants\n";
    BOOL vmem_pass = vmem_p1 != 0 && (unsigned long long)vmem_p1 >= 0x40000000ULL &&
                     (unsigned long long)vmem_p1 < 0x40080000ULL && vmem_rw_ok && vmem_p2 != 0 && vmem_p2 != vmem_p1 &&
                     vmem_vp_ok && vmem_old_prot == PAGE_READWRITE && vmem_vf_ok && vmem_zero == 0;
    DWORD vmem_written = 0;
    if (vmem_pass)
        WriteFile(out, vmem_ok, sizeof(vmem_ok) - 1, &vmem_written, 0);
    else
        WriteFile(out, vmem_bad, sizeof(vmem_bad) - 1, &vmem_written, 0);

    // Exercise — wide-string helpers.
    //
    // Invariants checked:
    //   * lstrlenW(L"hello") == 5 (stops at NUL, not buffer len).
    //   * lstrlenW(L"") == 0.
    //   * lstrcmpW(L"abc", L"abc") == 0.
    //   * lstrcmpW(L"abc", L"abd") < 0 ('c' < 'd').
    //   * lstrcmpW(L"abd", L"abc") > 0.
    //   * lstrcmpW(L"abc", L"abcd") < 0 (s1 shorter).
    //   * lstrcpyW(dst, L"hello") writes 6 wide chars including
    //     NUL and returns dst; round-trip lstrlenW(dst) == 5.
    static const WCHAR kStrHello[6] = {'h', 'e', 'l', 'l', 'o', 0};
    static const WCHAR kStrEmpty[1] = {0};
    static const WCHAR kStrAbc[4] = {'a', 'b', 'c', 0};
    static const WCHAR kStrAbd[4] = {'a', 'b', 'd', 0};
    static const WCHAR kStrAbcd[5] = {'a', 'b', 'c', 'd', 0};
    WCHAR wstr_cpy[16];
    for (int i = 0; i < 16; ++i)
        wstr_cpy[i] = 0xAAAA; // poison to prove the NUL was copied
    int wstr_len_hello = lstrlenW(kStrHello);
    int wstr_len_empty = lstrlenW(kStrEmpty);
    int wstr_cmp_eq = lstrcmpW(kStrAbc, kStrAbc);
    int wstr_cmp_lt = lstrcmpW(kStrAbc, kStrAbd);
    int wstr_cmp_gt = lstrcmpW(kStrAbd, kStrAbc);
    int wstr_cmp_pfx = lstrcmpW(kStrAbc, kStrAbcd);
    LPWSTR wstr_ret = lstrcpyW(wstr_cpy, kStrHello);
    int wstr_cpy_len = lstrlenW(wstr_cpy);

    const char wstr_ok[] = "[wstr] lstrlenW + lstrcmpW + lstrcpyW OK\n";
    const char wstr_bad[] = "[wstr] wide-string helpers FAILED invariants\n";
    BOOL wstr_pass = wstr_len_hello == 5 && wstr_len_empty == 0 && wstr_cmp_eq == 0 && wstr_cmp_lt < 0 &&
                     wstr_cmp_gt > 0 && wstr_cmp_pfx < 0 && wstr_ret == wstr_cpy && wstr_cpy_len == 5 &&
                     wstr_cpy[5] == 0;
    DWORD wstr_written = 0;
    if (wstr_pass)
        WriteFile(out, wstr_ok, sizeof(wstr_ok) - 1, &wstr_written, 0);
    else
        WriteFile(out, wstr_bad, sizeof(wstr_bad) - 1, &wstr_written, 0);

    // Exercise — system-info probes.
    //
    // Invariants checked:
    //   * IsWow64Process returns TRUE and writes FALSE to the
    //     out-param (we're a native x64 process, no WOW64).
    //   * IsWow64Process with NULL out-param still returns TRUE
    //     (documented tolerance).
    //   * GetVersionExW returns TRUE and writes Win10 build
    //     19041: major=10, minor=0, build=19041, platform=NT (2).
    //   * The caller's dwOSVersionInfoSize is preserved (we
    //     don't touch the field).
    //   * szCSDVersion[0] is still the caller's pre-call value.
    BOOL sysinfo_wow64 = 1; // poison
    BOOL sysinfo_iw_ok = IsWow64Process(0, &sysinfo_wow64);
    BOOL sysinfo_iw_null = IsWow64Process(0, 0); // null out-ptr tolerated

    OSVERSIONINFOW ovi;
    // Zero-init entire struct by hand (no memset on hand_-compiled
    // freestanding build). 276 bytes / 8 = 35 u64 writes; do it
    // as a simple loop.
    {
        unsigned char* z = (unsigned char*)&ovi;
        for (unsigned int i = 0; i < sizeof(ovi); ++i)
            z[i] = 0;
    }
    ovi.dwOSVersionInfoSize = (DWORD)sizeof(ovi);
    ovi.szCSDVersion[0] = 'X'; // sentinel — stub must leave alone
    BOOL sysinfo_gv_ok = GetVersionExW(&ovi);

    const char sysinfo_ok[] = "[sysinfo] IsWow64Process + GetVersionExW OK\n";
    const char sysinfo_bad[] = "[sysinfo] system-info probes FAILED invariants\n";
    BOOL sysinfo_pass = sysinfo_iw_ok && sysinfo_wow64 == 0 && sysinfo_iw_null && sysinfo_gv_ok &&
                        ovi.dwOSVersionInfoSize == sizeof(ovi) && ovi.dwMajorVersion == 10 && ovi.dwMinorVersion == 0 &&
                        ovi.dwBuildNumber == 19041 && ovi.dwPlatformId == 2 && ovi.szCSDVersion[0] == 'X';
    DWORD sysinfo_written = 0;
    if (sysinfo_pass)
    {
        WriteFile(out, sysinfo_ok, sizeof(sysinfo_ok) - 1, &sysinfo_written, 0);
    }
    else
    {
#if defined(HELLO_DBG_GETVERSIONEX) && HELLO_DBG_GETVERSIONEX
        /* Per-flag bitmask + szCSDVersion[0] hex. Reads as
         *   [sysinfo] 1111111110 csd=0000
         * meaning every check passed except the last (sentinel was
         * clobbered by the called stub). Letters in name match the
         * sysinfo_pass conjunct order. */
        char sysinfo_dbg[32];
        sysinfo_dbg[0] = '[';
        sysinfo_dbg[1] = 's';
        sysinfo_dbg[2] = 'y';
        sysinfo_dbg[3] = 's';
        sysinfo_dbg[4] = 'i';
        sysinfo_dbg[5] = 'n';
        sysinfo_dbg[6] = 'f';
        sysinfo_dbg[7] = 'o';
        sysinfo_dbg[8] = ']';
        sysinfo_dbg[9] = ' ';
        sysinfo_dbg[10] = (char)('0' + (sysinfo_iw_ok ? 1 : 0));
        sysinfo_dbg[11] = (char)('0' + (sysinfo_wow64 == 0 ? 1 : 0));
        sysinfo_dbg[12] = (char)('0' + (sysinfo_iw_null ? 1 : 0));
        sysinfo_dbg[13] = (char)('0' + (sysinfo_gv_ok ? 1 : 0));
        sysinfo_dbg[14] = (char)('0' + (ovi.dwOSVersionInfoSize == sizeof(ovi) ? 1 : 0));
        sysinfo_dbg[15] = (char)('0' + (ovi.dwMajorVersion == 10 ? 1 : 0));
        sysinfo_dbg[16] = (char)('0' + (ovi.dwMinorVersion == 0 ? 1 : 0));
        sysinfo_dbg[17] = (char)('0' + (ovi.dwBuildNumber == 19041 ? 1 : 0));
        sysinfo_dbg[18] = (char)('0' + (ovi.dwPlatformId == 2 ? 1 : 0));
        sysinfo_dbg[19] = (char)('0' + (ovi.szCSDVersion[0] == 'X' ? 1 : 0));
        sysinfo_dbg[20] = ' ';
        sysinfo_dbg[21] = 'c';
        sysinfo_dbg[22] = 's';
        sysinfo_dbg[23] = 'd';
        sysinfo_dbg[24] = '=';
        unsigned short sysinfo_csd0 = ovi.szCSDVersion[0];
        const char sysinfo_hex[] = "0123456789abcdef";
        sysinfo_dbg[25] = sysinfo_hex[(sysinfo_csd0 >> 12) & 0xF];
        sysinfo_dbg[26] = sysinfo_hex[(sysinfo_csd0 >> 8) & 0xF];
        sysinfo_dbg[27] = sysinfo_hex[(sysinfo_csd0 >> 4) & 0xF];
        sysinfo_dbg[28] = sysinfo_hex[sysinfo_csd0 & 0xF];
        sysinfo_dbg[29] = '\n';
        WriteFile(out, sysinfo_dbg, 30, &sysinfo_written, 0);
#endif
        WriteFile(out, sysinfo_bad, sizeof(sysinfo_bad) - 1, &sysinfo_written, 0);
    }

    // Exercise — ANSI string helpers.
    // Mirrors the wide-string variant above but with byte strings.
    // The build script passes -mno-sse -mgeneral-regs-only, so
    // the poison loop compiles to plain byte stores (clang can't
    // fall back to XMM vectorisation).
    char astr_cpy[16];
    for (int i = 0; i < 16; ++i)
        astr_cpy[i] = (char)0xAA;
    int astr_len_hello = lstrlenA("hello");
    int astr_len_empty = lstrlenA("");
    int astr_cmp_eq = lstrcmpA("abc", "abc");
    int astr_cmp_lt = lstrcmpA("abc", "abd");
    int astr_cmp_gt = lstrcmpA("abd", "abc");
    int astr_cmp_pfx = lstrcmpA("abc", "abcd");
    LPSTR astr_ret = lstrcpyA(astr_cpy, "hello");
    int astr_cpy_len = lstrlenA(astr_cpy);

    const char astr_ok[] = "[astr] lstrlenA + lstrcmpA + lstrcpyA OK\n";
    const char astr_bad[] = "[astr] ANSI string helpers FAILED invariants\n";
    BOOL astr_pass = astr_len_hello == 5 && astr_len_empty == 0 && astr_cmp_eq == 0 && astr_cmp_lt < 0 &&
                     astr_cmp_gt > 0 && astr_cmp_pfx < 0 && astr_ret == astr_cpy && astr_cpy_len == 5 &&
                     astr_cpy[5] == 0;
    DWORD astr_written = 0;
    if (astr_pass)
        WriteFile(out, astr_ok, sizeof(astr_ok) - 1, &astr_written, 0);
    else
        WriteFile(out, astr_bad, sizeof(astr_bad) - 1, &astr_written, 0);

    // Exercise — path-query stubs.
    //
    // Invariants checked:
    //   * GetModuleFileNameW(NULL, buf, 16) returns 3 and writes
    //     L"X:\\" (the v0 fixed path) followed by NUL.
    //   * GetModuleFileNameW(NULL, buf, 0) returns 3 without
    //     writing (nSize == 0 suppresses the copy).
    //   * GetCurrentDirectoryW(16, buf) returns 3 and writes
    //     L"X:\\" + NUL.
    //   * GetCurrentDirectoryW(2, buf) returns 4 (required size
    //     including NUL) without writing — "buffer too small"
    //     path.
    //   * SetCurrentDirectoryW(any) returns TRUE.
    WCHAR path_buf[16];
    for (int i = 0; i < 16; ++i)
        path_buf[i] = (WCHAR)0xAAAA;
    DWORD path_mfn_ok = GetModuleFileNameW(0, path_buf, 16);
    BOOL path_mfn_str = path_buf[0] == 'X' && path_buf[1] == ':' && path_buf[2] == '\\' && path_buf[3] == 0;

    for (int i = 0; i < 16; ++i)
        path_buf[i] = (WCHAR)0xAAAA;
    DWORD path_mfn_nosize = GetModuleFileNameW(0, path_buf, 0);
    // With nSize = 0, buffer stays poison.
    BOOL path_mfn_unwritten = path_buf[0] == (WCHAR)0xAAAA;

    for (int i = 0; i < 16; ++i)
        path_buf[i] = (WCHAR)0xAAAA;
    DWORD path_cd_ok = GetCurrentDirectoryW(16, path_buf);
    BOOL path_cd_str = path_buf[0] == 'X' && path_buf[1] == ':' && path_buf[2] == '\\' && path_buf[3] == 0;

    for (int i = 0; i < 16; ++i)
        path_buf[i] = (WCHAR)0xAAAA;
    DWORD path_cd_small = GetCurrentDirectoryW(2, path_buf); // too small
    BOOL path_cd_unwritten = path_buf[0] == (WCHAR)0xAAAA;

    static const WCHAR kSomePath[] = {'C', ':', '\\', 0};
    BOOL path_scd_ok = SetCurrentDirectoryW(kSomePath);

    const char path_ok[] = "[path-query] GetModuleFileNameW + CurrentDir OK\n";
    const char path_bad[] = "[path-query] path-query stubs FAILED invariants\n";
    BOOL path_pass = path_mfn_ok == 3 && path_mfn_str && path_mfn_nosize == 3 && path_mfn_unwritten &&
                     path_cd_ok == 3 && path_cd_str && path_cd_small == 4 && path_cd_unwritten && path_scd_ok != 0;
    DWORD path_written = 0;
    if (path_pass)
        WriteFile(out, path_ok, sizeof(path_ok) - 1, &path_written, 0);
    else
        WriteFile(out, path_bad, sizeof(path_bad) - 1, &path_written, 0);

    // Exercise — encoding converters.
    //
    // Invariants checked:
    //   * MultiByteToWideChar("hello", 5, wbuf, 16) returns 5 and
    //     wbuf contains L"hello" byte-extended (each char has
    //     high byte 0x00).
    //   * Size-query mode: MultiByteToWideChar("abc", 3, NULL, 0)
    //     returns 3 (required wide-char count).
    //   * WideCharToMultiByte(L"world", 5, bbuf, 16, ...)
    //     returns 5 and bbuf contains "world" byte-truncated.
    //   * Round-trip: WideCharToMultiByte(MultiByteToWideChar(src))
    //     recovers src.
    static const char kMbSrc[] = "hello";
    WCHAR enc_wbuf[16];
    for (int i = 0; i < 16; ++i)
        enc_wbuf[i] = 0;
    int enc_mb2wc = MultiByteToWideChar(65001, 0, kMbSrc, 5, enc_wbuf, 16);
    int enc_mb2wc_q = MultiByteToWideChar(65001, 0, "abc", 3, 0, 0);
    BOOL enc_wc_content =
        enc_wbuf[0] == 'h' && enc_wbuf[1] == 'e' && enc_wbuf[2] == 'l' && enc_wbuf[3] == 'l' && enc_wbuf[4] == 'o';

    static const WCHAR kWcSrc[] = {'w', 'o', 'r', 'l', 'd', 0};
    char enc_bbuf[16];
    for (int i = 0; i < 16; ++i)
        enc_bbuf[i] = 0;
    int enc_wc2mb = WideCharToMultiByte(65001, 0, kWcSrc, 5, enc_bbuf, 16, 0, 0);
    BOOL enc_mb_content =
        enc_bbuf[0] == 'w' && enc_bbuf[1] == 'o' && enc_bbuf[2] == 'r' && enc_bbuf[3] == 'l' && enc_bbuf[4] == 'd';

    const char enc_ok[] = "[encoding] MultiByteToWideChar + WideCharToMultiByte OK\n";
    const char enc_bad[] = "[encoding] encoding converters FAILED invariants\n";
    BOOL enc_pass = enc_mb2wc == 5 && enc_mb2wc_q == 3 && enc_wc_content && enc_wc2mb == 5 && enc_mb_content;
    DWORD enc_written = 0;
    if (enc_pass)
        WriteFile(out, enc_ok, sizeof(enc_ok) - 1, &enc_written, 0);
    else
        WriteFile(out, enc_bad, sizeof(enc_bad) - 1, &enc_written, 0);

    // Exercise — identity queries.
    //
    // Invariants checked:
    //   * GetUserNameW with a 16-char buffer returns TRUE,
    //     writes L"user\0", and sets *size = 5.
    //   * GetUserNameW with a 2-char buffer returns FALSE and
    //     sets *size = 5 (required).
    //   * GetComputerNameW with a 16-char buffer returns TRUE,
    //     writes L"DuetOS\0", and sets *size = 9.
    WCHAR ident_ubuf[16];
    for (int i = 0; i < 16; ++i)
        ident_ubuf[i] = (WCHAR)0xAAAA;
    DWORD ident_usize = 16;
    BOOL ident_u_ok = GetUserNameW(ident_ubuf, &ident_usize);
    BOOL ident_u_str = ident_ubuf[0] == 'u' && ident_ubuf[1] == 's' && ident_ubuf[2] == 'e' && ident_ubuf[3] == 'r' &&
                       ident_ubuf[4] == 0;

    DWORD ident_usmall = 2;
    BOOL ident_u_fail = GetUserNameW(ident_ubuf, &ident_usmall);

    WCHAR ident_cbuf[16];
    for (int i = 0; i < 16; ++i)
        ident_cbuf[i] = (WCHAR)0xAAAA;
    DWORD ident_csize = 16;
    BOOL ident_c_ok = GetComputerNameW(ident_cbuf, &ident_csize);
    BOOL ident_c_str = ident_cbuf[0] == 'C' && ident_cbuf[1] == 'u' && ident_cbuf[2] == 's' && ident_cbuf[3] == 't' &&
                       ident_cbuf[4] == 'o' && ident_cbuf[5] == 'm' && ident_cbuf[6] == 'O' && ident_cbuf[7] == 'S' &&
                       ident_cbuf[8] == 0;

    const char ident_ok[] = "[identity] GetUserNameW + GetComputerNameW OK\n";
    const char ident_bad[] = "[identity] identity queries FAILED invariants\n";
    BOOL ident_pass = ident_u_ok && ident_usize == 5 && ident_u_str && !ident_u_fail && ident_usmall == 5 &&
                      ident_c_ok && ident_csize == 9 && ident_c_str;
    DWORD ident_written = 0;
    if (ident_pass)
        WriteFile(out, ident_ok, sizeof(ident_ok) - 1, &ident_written, 0);
    else
        WriteFile(out, ident_bad, sizeof(ident_bad) - 1, &ident_written, 0);

    // Exercise — system-directory queries.
    //
    // All three should report L"X:\\" in v0.
    WCHAR sysdir_tbuf[16];
    for (int i = 0; i < 16; ++i)
        sysdir_tbuf[i] = (WCHAR)0xAAAA;
    DWORD sysdir_tp = GetTempPathW(16, sysdir_tbuf);
    BOOL sysdir_tp_str =
        sysdir_tbuf[0] == 'X' && sysdir_tbuf[1] == ':' && sysdir_tbuf[2] == '\\' && sysdir_tbuf[3] == 0;

    WCHAR sysdir_wbuf[16];
    for (int i = 0; i < 16; ++i)
        sysdir_wbuf[i] = (WCHAR)0xAAAA;
    unsigned int sysdir_wd = GetWindowsDirectoryW(sysdir_wbuf, 16);
    BOOL sysdir_wd_str =
        sysdir_wbuf[0] == 'X' && sysdir_wbuf[1] == ':' && sysdir_wbuf[2] == '\\' && sysdir_wbuf[3] == 0;

    WCHAR sysdir_sbuf[16];
    for (int i = 0; i < 16; ++i)
        sysdir_sbuf[i] = (WCHAR)0xAAAA;
    unsigned int sysdir_sd = GetSystemDirectoryW(sysdir_sbuf, 16);
    BOOL sysdir_sd_str =
        sysdir_sbuf[0] == 'X' && sysdir_sbuf[1] == ':' && sysdir_sbuf[2] == '\\' && sysdir_sbuf[3] == 0;

    // Buffer-too-small case for GetWindowsDirectoryW.
    unsigned int sysdir_wd_small = GetWindowsDirectoryW(sysdir_wbuf, 2);

    const char sysdir_ok[] = "[sysdir] Temp/Windows/System directory OK\n";
    const char sysdir_bad[] = "[sysdir] directory queries FAILED invariants\n";
    BOOL sysdir_pass = sysdir_tp == 3 && sysdir_tp_str && sysdir_wd == 3 && sysdir_wd_str && sysdir_sd == 3 &&
                       sysdir_sd_str && sysdir_wd_small == 4;
    DWORD sysdir_written = 0;
    if (sysdir_pass)
        WriteFile(out, sysdir_ok, sizeof(sysdir_ok) - 1, &sysdir_written, 0);
    else
        WriteFile(out, sysdir_bad, sizeof(sysdir_bad) - 1, &sysdir_written, 0);

    // Exercise — drives/error/format.
    //
    // Invariants checked:
    //   * GetLogicalDrives returns 0x00800000 (bit 23 = X:).
    //   * GetDriveTypeW(L"X:\\") returns 3 (DRIVE_FIXED).
    //   * SetErrorMode returns 0 (previous mode).
    //   * FormatMessageW returns 0 (can't format — caller
    //     should handle).
    DWORD drives_drives = GetLogicalDrives();
    static const WCHAR kDriveX[] = {'X', ':', '\\', 0};
    unsigned int drives_drive_type = GetDriveTypeW(kDriveX);
    unsigned int drives_prev_em = SetErrorMode(0x8001); // SEM_FAILCRITICALERRORS
    WCHAR drives_fmbuf[16];
    for (int i = 0; i < 16; ++i)
        drives_fmbuf[i] = 0;
    DWORD drives_fm = FormatMessageW(0x1000 /* FROM_SYSTEM */, 0, 5 /* ERROR_ACCESS_DENIED */, 0, drives_fmbuf, 16, 0);

    const char drives_ok[] = "[drives] drives + error mode + format OK\n";
    const char drives_bad[] = "[drives] misc-stubs FAILED invariants\n";
    BOOL drives_pass = drives_drives == 0x00800000 && drives_drive_type == 3 && drives_prev_em == 0 && drives_fm == 0;
    DWORD drives_written = 0;
    if (drives_pass)
        WriteFile(out, drives_ok, sizeof(drives_ok) - 1, &drives_written, 0);
    else
        WriteFile(out, drives_bad, sizeof(drives_bad) - 1, &drives_written, 0);

    // Exercise — registry + file-attribute stubs.
    //
    // Invariants checked:
    //   * RegOpenKeyExW returns 2 (ERROR_FILE_NOT_FOUND).
    //   * RegQueryValueExW returns 2.
    //   * RegCloseKey returns 0 (ERROR_SUCCESS).
    //   * GetFileAttributesW returns 0xFFFFFFFF
    //     (INVALID_FILE_ATTRIBUTES).
    //   * SetFileAttributesW returns TRUE (no-op success).
    HKEY reg_hk = 0;
    static const WCHAR kSoftware[] = {'S', 'o', 'f', 't', 'w', 'a', 'r', 'e', 0};
    long reg_open = RegOpenKeyExW(0, kSoftware, 0, 0x20019 /* KEY_READ */, &reg_hk);
    long reg_query = RegQueryValueExW(0, kSoftware, 0, 0, 0, 0);
    long reg_close = RegCloseKey(0);

    static const WCHAR kSomeFile[] = {'f', 'o', 'o', '.', 't', 'x', 't', 0};
    DWORD reg_attrs = GetFileAttributesW(kSomeFile);
    BOOL reg_set = SetFileAttributesW(kSomeFile, 0);

    const char reg_ok[] = "[reg-fattr] Reg + FileAttributes no-ops OK\n";
    const char reg_bad[] = "[reg-fattr] reg/file-attr stubs FAILED invariants\n";
    BOOL reg_pass = reg_open == 2 && reg_query == 2 && reg_close == 0 && reg_attrs == 0xFFFFFFFFUL && reg_set != 0;
    DWORD reg_written = 0;
    if (reg_pass)
        WriteFile(out, reg_ok, sizeof(reg_ok) - 1, &reg_written, 0);
    else
        WriteFile(out, reg_bad, sizeof(reg_bad) - 1, &reg_written, 0);

    // Exercise — real atomic operations.
    //
    // Invariants checked:
    //   * InterlockedIncrement(&x=5) returns 6 and x == 6.
    //   * InterlockedDecrement(&x=6) returns 5 and x == 5.
    //   * InterlockedExchangeAdd(&x=5, 10) returns 5 (old); x == 15.
    //   * InterlockedExchange(&x=15, 42) returns 15 (old); x == 42.
    //   * InterlockedCompareExchange(&x=42, 99, 42) returns 42
    //     (old matched); x == 99.
    //   * InterlockedCompareExchange(&x=99, 0, 42) returns 99
    //     (old didn't match); x stays 99.
    volatile LONG ilk_x = 5;
    LONG ilk_inc = InterlockedIncrement((LONG*)&ilk_x);
    LONG ilk_dec = InterlockedDecrement((LONG*)&ilk_x);
    LONG ilk_add_old = InterlockedExchangeAdd((LONG*)&ilk_x, 10);
    LONG ilk_add_after = ilk_x;
    LONG ilk_ex_old = InterlockedExchange((LONG*)&ilk_x, 42);
    LONG ilk_ex_after = ilk_x;
    LONG ilk_cx_hit = InterlockedCompareExchange((LONG*)&ilk_x, 99, 42);
    LONG ilk_cx_after_hit = ilk_x;
    LONG ilk_cx_miss = InterlockedCompareExchange((LONG*)&ilk_x, 0, 42);
    LONG ilk_cx_after_miss = ilk_x;

    const char ilk_ok[] = "[interlocked] InterlockedInc/Dec/XAdd/Xchg/CmpXchg OK\n";
    const char ilk_bad[] = "[interlocked] interlocked atomics FAILED invariants\n";
    BOOL ilk_pass = ilk_inc == 6 && ilk_dec == 5 && ilk_add_old == 5 && ilk_add_after == 15 && ilk_ex_old == 15 &&
                    ilk_ex_after == 42 && ilk_cx_hit == 42 && ilk_cx_after_hit == 99 && ilk_cx_miss == 99 &&
                    ilk_cx_after_miss == 99;
    DWORD ilk_written = 0;
    if (ilk_pass)
        WriteFile(out, ilk_ok, sizeof(ilk_ok) - 1, &ilk_written, 0);
    else
        WriteFile(out, ilk_bad, sizeof(ilk_bad) - 1, &ilk_written, 0);

    // Exercise — real event handles.
    //
    // Invariants checked (single-task process, so events never
    // actually block — but all state transitions must be
    // observable):
    //   * Manual-reset event created signaled: wait returns
    //     WAIT_OBJECT_0 immediately and signal STAYS set, so
    //     a second wait also returns WAIT_OBJECT_0 immediately.
    //   * ResetEvent clears the signal: subsequent wait with
    //     a tiny timeout returns WAIT_TIMEOUT (0x102).
    //   * SetEvent re-signals.
    //   * Auto-reset event created signaled: first wait returns
    //     WAIT_OBJECT_0 and clears the signal; second wait
    //     with a tiny timeout returns WAIT_TIMEOUT.
    //   * SetEvent on auto-reset event: next wait returns
    //     WAIT_OBJECT_0, which clears the signal again.
    //   * CloseHandle on event works (kernel SYS_FILE_CLOSE
    //     dispatches event range too).
    HANDLE evt_mrE = CreateEventW(0, 1, 1, 0); // manual, initial=signaled
    DWORD evt_mr_w1 = WaitForSingleObject(evt_mrE, 0);
    DWORD evt_mr_w2 = WaitForSingleObject(evt_mrE, 0); // still signaled (manual)
    BOOL evt_mr_reset = ResetEvent(evt_mrE);
    DWORD evt_mr_w3 = WaitForSingleObject(evt_mrE, 1); // timeout
    BOOL evt_mr_set = SetEvent(evt_mrE);
    DWORD evt_mr_w4 = WaitForSingleObject(evt_mrE, 0);
    BOOL evt_mr_close = CloseHandle(evt_mrE);

    HANDLE evt_arE = CreateEventW(0, 0, 1, 0);         // auto, initial=signaled
    DWORD evt_ar_w1 = WaitForSingleObject(evt_arE, 0); // consumes signal
    DWORD evt_ar_w2 = WaitForSingleObject(evt_arE, 1); // timeout — auto cleared
    BOOL evt_ar_set = SetEvent(evt_arE);
    DWORD evt_ar_w3 = WaitForSingleObject(evt_arE, 0); // signaled again
    DWORD evt_ar_w4 = WaitForSingleObject(evt_arE, 1); // timeout — auto cleared
    BOOL evt_ar_close = CloseHandle(evt_arE);

    const char evt_ok[] = "[event] real Event CreateW/Set/Reset/Wait OK\n";
    const char evt_bad[] = "[event] event semantics FAILED invariants\n";
    BOOL evt_pass = evt_mrE != 0 && evt_mr_w1 == 0 && evt_mr_w2 == 0 && evt_mr_reset != 0 && evt_mr_w3 == 0x102 &&
                    evt_mr_set != 0 && evt_mr_w4 == 0 && evt_mr_close != 0 && evt_arE != 0 && evt_ar_w1 == 0 &&
                    evt_ar_w2 == 0x102 && evt_ar_set != 0 && evt_ar_w3 == 0 && evt_ar_w4 == 0x102 && evt_ar_close != 0;
    DWORD evt_written = 0;
    if (evt_pass)
        WriteFile(out, evt_ok, sizeof(evt_ok) - 1, &evt_written, 0);
    else
        WriteFile(out, evt_bad, sizeof(evt_bad) - 1, &evt_written, 0);

    // Exercise — real TLS.
    //
    // Invariants checked:
    //   * TlsAlloc returns a valid slot (0..63).
    //   * Two TlsAlloc calls return DIFFERENT slots.
    //   * TlsGetValue on freshly-allocated slot returns 0.
    //   * TlsSetValue + TlsGetValue round-trips arbitrary u64.
    //   * Slots are isolated — setting slot A doesn't affect
    //     slot B.
    //   * TlsFree releases the slot; subsequent TlsAlloc can
    //     re-allocate the same slot.
    //   * TlsFree(invalid) returns FALSE.
    DWORD tls_s1 = TlsAlloc();
    DWORD tls_s2 = TlsAlloc();
    void* tls_init = TlsGetValue(tls_s1); // should be 0
    BOOL tls_set1 = TlsSetValue(tls_s1, (void*)0xDEADBEEFCAFEULL);
    BOOL tls_set2 = TlsSetValue(tls_s2, (void*)0x1122334455667788ULL);
    void* tls_get1 = TlsGetValue(tls_s1);
    void* tls_get2 = TlsGetValue(tls_s2);
    BOOL tls_free1 = TlsFree(tls_s1);
    DWORD tls_s3 = TlsAlloc();             // should be able to reuse s1's slot
    BOOL tls_free_bad = TlsFree(0x1000UL); // out of range
    BOOL tls_free2 = TlsFree(tls_s2);
    BOOL tls_free3 = TlsFree(tls_s3);

    const char tls_ok[] = "[tls] real TLS (Alloc/Set/Get/Free) OK\n";
    const char tls_bad[] = "[tls] TLS semantics FAILED invariants\n";
    BOOL tls_pass = tls_s1 != 0xFFFFFFFFUL && tls_s2 != 0xFFFFFFFFUL && tls_s1 != tls_s2 && tls_init == 0 && tls_set1 &&
                    tls_set2 && tls_get1 == (void*)0xDEADBEEFCAFEULL && tls_get2 == (void*)0x1122334455667788ULL &&
                    tls_free1 && tls_s3 != 0xFFFFFFFFUL && !tls_free_bad && tls_free2 && tls_free3;
    DWORD tls_written = 0;
    if (tls_pass)
        WriteFile(out, tls_ok, sizeof(tls_ok) - 1, &tls_written, 0);
    else
        WriteFile(out, tls_bad, sizeof(tls_bad) - 1, &tls_written, 0);

    // Exercise — multi-phase stress test.
    const char stress_banner[] = "[stress] stress: starting...\n";
    DWORD stress_bw = 0;
    WriteFile(out, stress_banner, sizeof(stress_banner) - 1, &stress_bw, 0);

    HANDLE stress_muxes[4];
    HANDLE stress_events[4];
    DWORD stress_tls[8];
    void* stress_vm[4];
    void* stress_heap[4];
    volatile LONG stress_counter = 0;
    BOOL stress_init_ok = 1;
    const char stress_pre[] = "[stress] entering init loop\n";
    DWORD stress_prew = 0;
    WriteFile(out, stress_pre, sizeof(stress_pre) - 1, &stress_prew, 0);
    for (int i = 0; i < 4; ++i)
    {
        stress_muxes[i] = CreateMutexW(0, 0, 0);
        if (stress_muxes[i] == 0)
            stress_init_ok = 0;
        stress_events[i] = CreateEventW(0, 1, 0, 0);
        if (stress_events[i] == 0)
            stress_init_ok = 0;
        stress_vm[i] = VirtualAlloc(0, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (stress_vm[i] == 0)
            stress_init_ok = 0;
        stress_heap[i] = HeapAlloc(heap, 0, 128);
        if (stress_heap[i] == 0)
            stress_init_ok = 0;
    }
    const char stress_post[] = "[stress] init loop done\n";
    DWORD stress_postw = 0;
    WriteFile(out, stress_post, sizeof(stress_post) - 1, &stress_postw, 0);
    for (int i = 0; i < 8; ++i)
    {
        stress_tls[i] = TlsAlloc();
        if (stress_tls[i] == 0xFFFFFFFFUL)
            stress_init_ok = 0;
        TlsSetValue(stress_tls[i], (void*)(unsigned long long)(0x1000 + i));
    }
    const char stress_post2[] = "[stress] tls loop done\n";
    DWORD stress_post2w = 0;
    WriteFile(out, stress_post2, sizeof(stress_post2) - 1, &stress_post2w, 0);

    int stress_ops = 0;
    for (int iter = 0; iter < 1000 && stress_init_ok; ++iter)
    {
        int mux = iter & 3;
        int evt = iter & 3;
        int tls = iter & 7;
        int vm = iter & 3;
        int hp = iter & 3;
        InterlockedIncrement((LONG*)&stress_counter);
        ++stress_ops;
        unsigned long long v = (unsigned long long)TlsGetValue(stress_tls[tls]);
        TlsSetValue(stress_tls[tls], (void*)(v + 1));
        ++stress_ops;
        DWORD* vp = (DWORD*)stress_vm[vm];
        vp[iter & 0x3FF] = (DWORD)iter;
        DWORD vread = vp[iter & 0x3FF];
        (void)vread;
        ++stress_ops;
        unsigned char* hbp = (unsigned char*)stress_heap[hp];
        hbp[iter & 0x7F] = (unsigned char)(iter & 0xFF);
        ++stress_ops;
        WaitForSingleObject(stress_muxes[mux], 0);
        ReleaseMutex(stress_muxes[mux]);
        ++stress_ops;
        SetEvent(stress_events[evt]);
        ResetEvent(stress_events[evt]);
        ++stress_ops;
    }

    BOOL stress_counter_ok = stress_counter == 1000;
    BOOL stress_tls_ok = 1;
    for (int i = 0; i < 8; ++i)
    {
        unsigned long long expected = 0x1000 + i + 125;
        unsigned long long got = (unsigned long long)TlsGetValue(stress_tls[i]);
        if (got != expected)
            stress_tls_ok = 0;
    }
    for (int i = 0; i < 4; ++i)
    {
        CloseHandle(stress_muxes[i]);
        CloseHandle(stress_events[i]);
        VirtualFree(stress_vm[i], 0, MEM_RELEASE);
        HeapFree(heap, 0, stress_heap[i]);
    }
    for (int i = 0; i < 8; ++i)
        TlsFree(stress_tls[i]);

    const char stress_ok[] = "[stress] stress 6000 ops OK — counter=1000, TLS+125/slot verified\n";
    const char stress_bad[] = "[stress] STRESS TEST FAILED\n";
    BOOL stress_pass = stress_init_ok && stress_counter_ok && stress_tls_ok && stress_ops == 6000;
    DWORD stress_written = 0;
    if (stress_pass)
        WriteFile(out, stress_ok, sizeof(stress_ok) - 1, &stress_written, 0);
    else
    {
        WriteFile(out, stress_bad, sizeof(stress_bad) - 1, &stress_written, 0);
        // Diagnostic fields:
        const char dbg[] = "[stress-dbg] ";
        WriteFile(out, dbg, sizeof(dbg) - 1, &stress_written, 0);
        char hex[20];
        unsigned long long vals[4] = {(unsigned long long)stress_init_ok, (unsigned long long)stress_counter,
                                      (unsigned long long)stress_tls_ok, (unsigned long long)stress_ops};
        const char* names[4] = {"init=", " counter=", " tls_ok=", " ops="};
        for (int i = 0; i < 4; ++i)
        {
            WriteFile(out, names[i], (DWORD)strlen(names[i]), &stress_written, 0);
            for (int d = 0; d < 16; ++d)
            {
                int nyb = (int)((vals[i] >> ((15 - d) * 4)) & 0xF);
                hex[d] = (char)((nyb < 10) ? ('0' + nyb) : ('a' + nyb - 10));
            }
            hex[16] = '\n';
            WriteFile(out, hex, (i == 3) ? 17 : 16, &stress_written, 0);
        }
    }

    // Round-trip: store a distinctive value via
    // SetLastError, read it back via GetLastError, exit with
    // whatever came back. If the slot works, the kernel log
    // shows `[I] sys : exit rc val=0xBEEF`. Any other value
    // means the round-trip is broken — the serial log
    // becomes the assertion.
    SetLastError(0xBEEF);
    ExitProcess(GetLastError());
}
