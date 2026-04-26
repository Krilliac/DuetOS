    // console I/O
    {"kernel32.dll", "ExitProcess", kOffExitProcess},
    {"kernel32.dll", "GetStdHandle", kOffGetStdHandle},
    // WriteFile and WriteConsoleA share the same stub — both
    // take the same 5-arg shape and we ignore the handle +
    // trailing arg anyway. Aliasing keeps the stubs page
    // small and means any improvement (clamping, error
    // codes, real handle dispatch) lands in both at once.
    {"kernel32.dll", "WriteFile", kOffWriteFile},
    {"kernel32.dll", "WriteConsoleA", kOffWriteFile},
    // process/thread lifecycle
    {"kernel32.dll", "GetCurrentProcess", kOffGetCurrentProcess},
    {"kernel32.dll", "GetCurrentThread", kOffGetCurrentThread},
    {"kernel32.dll", "GetCurrentProcessId", kOffGetCurrentProcessId},
    {"kernel32.dll", "GetCurrentThreadId", kOffGetCurrentThreadId},
    {"kernel32.dll", "TerminateProcess", kOffTerminateProcess},
    // last-error slot
    {"kernel32.dll", "GetLastError", kOffGetLastError},
    {"kernel32.dll", "SetLastError", kOffSetLastError},
    // critical sections (v0 no-ops)
    {"kernel32.dll", "InitializeCriticalSection", kOffInitCritSec},
    {"kernel32.dll", "InitializeCriticalSectionEx", kOffInitCritSec},
    {"kernel32.dll", "InitializeCriticalSectionAndSpinCount", kOffInitCritSec},
    {"kernel32.dll", "EnterCriticalSection", kOffEnterCritSecReal},
    {"kernel32.dll", "LeaveCriticalSection", kOffLeaveCritSecReal},
    // DeleteCriticalSection stays a bare `ret` — our CS doesn't own
    // any kernel handle or heap state, so there's literally nothing
    // to tear down. Real Windows's Rtl code only zeroes the DebugInfo
    // pointer and frees a reserved slot; neither applies here.
    {"kernel32.dll", "DeleteCriticalSection", kOffCritSecNop},
    // vcruntime140 memory intrinsics
    {"vcruntime140.dll", "memmove", kOffMemmove},
    // memcpy is safe to alias to memmove — memmove is a strict
    // superset (handles overlap), same return value contract.
    {"vcruntime140.dll", "memcpy", kOffMemmove},
    {"vcruntime140.dll", "memset", kOffMemset},

    // UCRT CRT-startup shims.
    //
    // Most of these are "return success, do nothing" stubs that
    // let a CRT-driven startup sequence advance far enough for
    // main() to get called. They live under api-set DLL names
    // (api-ms-win-crt-*-l1-1-0.dll) on modern Windows — each
    // apiset forwards to ucrtbase.dll. The real runtime is
    // distributed across both; programs reference whichever
    // DLL name the linker chose.
    //
    // We register each stub under ALL plausible DLL names the
    // import resolver might see (apiset, ucrtbase, and the
    // legacy msvcrt.dll where applicable). The lookup scan is
    // linear and small — duplicate entries are cheap.

    // Return-0 family (spread across several apisets).
    {"api-ms-win-crt-runtime-l1-1-0.dll", "_initialize_onexit_table", kOffReturnZero},
    {"api-ms-win-crt-runtime-l1-1-0.dll", "_register_onexit_function", kOffReturnZero},
    {"api-ms-win-crt-runtime-l1-1-0.dll", "_crt_atexit", kOffReturnZero},
    {"api-ms-win-crt-runtime-l1-1-0.dll", "_initterm_e", kOffReturnZero},
    {"api-ms-win-crt-runtime-l1-1-0.dll", "_configure_narrow_argv", kOffReturnZero},
    {"api-ms-win-crt-runtime-l1-1-0.dll", "_initialize_narrow_environment", kOffReturnZero},
    {"api-ms-win-crt-runtime-l1-1-0.dll", "_get_initial_narrow_environment", kOffReturnZero},
    {"api-ms-win-crt-runtime-l1-1-0.dll", "_seh_filter_exe", kOffReturnZero},
    {"api-ms-win-crt-runtime-l1-1-0.dll", "_register_thread_local_exe_atexit_callback", kOffReturnZero},
    {"api-ms-win-crt-locale-l1-1-0.dll", "_configthreadlocale", kOffReturnZero},
    {"api-ms-win-crt-heap-l1-1-0.dll", "_set_new_mode", kOffReturnZero},
    {"api-ms-win-crt-stdio-l1-1-0.dll", "_set_fmode", kOffReturnZero},

    // Return-void family.
    {"api-ms-win-crt-runtime-l1-1-0.dll", "_initterm", kOffCritSecNop},
    {"api-ms-win-crt-runtime-l1-1-0.dll", "_cexit", kOffCritSecNop},
    {"api-ms-win-crt-runtime-l1-1-0.dll", "_c_exit", kOffCritSecNop},
    {"api-ms-win-crt-runtime-l1-1-0.dll", "_set_app_type", kOffCritSecNop},
    {"api-ms-win-crt-math-l1-1-0.dll", "__setusermatherr", kOffCritSecNop},

    // Exit family — `exit` and `_exit` alias ExitProcess
    // (same rcx=code ABI, same SYS_EXIT semantic).
    {"api-ms-win-crt-runtime-l1-1-0.dll", "exit", kOffExitProcess},
    {"api-ms-win-crt-runtime-l1-1-0.dll", "_exit", kOffExitProcess},
    {"api-ms-win-crt-runtime-l1-1-0.dll", "terminate", kOffTerminate},
    {"api-ms-win-crt-runtime-l1-1-0.dll", "_invalid_parameter_noinfo_noreturn", kOffInvalidParam},
    // Same functions surface directly under ucrtbase too.
    {"ucrtbase.dll", "exit", kOffExitProcess},
    {"ucrtbase.dll", "_exit", kOffExitProcess},
    {"ucrtbase.dll", "terminate", kOffTerminate},

    // CRT string intrinsics. Pure functions; no
    // kernel state, no ABI surprises. Register under the
    // apiset + ucrtbase + msvcrt names to cover all three
    // common link paths.
    {"api-ms-win-crt-string-l1-1-0.dll", "strcmp", kOffStrcmp},
    {"api-ms-win-crt-string-l1-1-0.dll", "strlen", kOffStrlen},
    {"api-ms-win-crt-string-l1-1-0.dll", "wcslen", kOffWcslen},
    {"api-ms-win-crt-string-l1-1-0.dll", "strchr", kOffStrchr},
    {"api-ms-win-crt-string-l1-1-0.dll", "strcpy", kOffStrcpy},
    {"ucrtbase.dll", "strcmp", kOffStrcmp},
    {"ucrtbase.dll", "strlen", kOffStrlen},
    {"ucrtbase.dll", "wcslen", kOffWcslen},
    {"ucrtbase.dll", "strchr", kOffStrchr},
    {"ucrtbase.dll", "strcpy", kOffStrcpy},
    {"msvcrt.dll", "strcmp", kOffStrcmp},
    {"msvcrt.dll", "strlen", kOffStrlen},
    {"msvcrt.dll", "wcslen", kOffWcslen},
    {"msvcrt.dll", "strchr", kOffStrchr},
    {"msvcrt.dll", "strcpy", kOffStrcpy},

    // kernel32 "safe ignore" shims. These functions
    // do real work on Windows but can safely return a sentinel
    // value in v0 without causing the caller to immediately
    // crash. Most of them surface in the windows-kill.exe
    // import list; these stubs narrow that gap.
    //
    // Return-zero family (returns NULL / FALSE / 0):
    // GetModuleHandle* — NULL means "module not found"
    // (or, for NULL arg, a default that's fine to be 0).
    // GetProcAddress — NULL means "symbol not exported";
    // caller falls back.
    // IsDebuggerPresent — FALSE = not debugged.
    // IsProcessorFeaturePresent — FALSE = feature absent;
    // caller uses non-SIMD fallback path.
    // SetUnhandledExceptionFilter — NULL = no previous filter.
    // UnhandledExceptionFilter — 0 = EXCEPTION_CONTINUE_SEARCH.
    // GetModuleHandleA / GetModuleHandleW / GetProcAddress moved to
    // below — GetModuleHandleW(NULL) now returns the EXE
    // image base instead of always-zero. The Win32ThunksLookup walk
    // returns the first match, so the real entries take precedence
    // by appearing earlier in the table.
    {"kernel32.dll", "IsDebuggerPresent", kOffReturnZero},
    {"kernel32.dll", "IsDebuggerPresent", kOffReturnZero},
    // IsProcessorFeaturePresent(dwFeature) → claim every queried
    // feature is present. x86_64 universally has SSE / SSE2 / CMPXCHG16B
    // / NX; AES / PCLMUL / AVX / AVX2 / RDRAND / RDSEED are visible in
    // this kernel's CPU probe log. Returning 0 forced every caller
    // onto scalar fallback paths; returning 1 optimistically matches
    // modern hardware. Genuinely-absent feature callers almost always
    // have a runtime fallback anyway.
    {"kernel32.dll", "IsProcessorFeaturePresent", kOffReturnOne},
    {"kernel32.dll", "SetUnhandledExceptionFilter", kOffSetUnhandledFilter},
    {"kernel32.dll", "UnhandledExceptionFilter", kOffUnhandledFilter},

    // Return-one family (returns TRUE / 1 = success):
    // SetConsoleCtrlHandler — pretend we registered.
    {"kernel32.dll", "SetConsoleCtrlHandler", kOffReturnOne},

    // file I/O. Real handle table on Process,
    // backed by SYS_FILE_OPEN / SYS_FILE_READ / SYS_FILE_CLOSE
    // / SYS_FILE_SEEK. CloseHandle is the file-close path —
    // also harmlessly handles non-file handles (the kernel
    // SYS_FILE_CLOSE returns 0 for an unrecognised handle).
    {"kernel32.dll", "CreateFileW", kOffCreateFileW},
    {"kernel32.dll", "ReadFile", kOffReadFile},
    {"kernel32.dll", "CloseHandle", kOffCloseHandle},
    {"kernel32.dll", "SetFilePointerEx", kOffSetFilePtrEx},

    // file stat + module lookup. GetFileSizeEx is
    // backed by SYS_FILE_FSTAT (non-destructive size).
    // GetModuleHandleW(NULL) returns the EXE image base from
    // the proc-env page; any non-NULL name returns 0. Library
    // loading is unsupported in v0 — LoadLibraryW/A return 0
    // (failed) and GetProcAddress returns 0 (not found). Apps
    // that GetProcAddress for an optional API gracefully fall
    // back to their non-dynamic path.
    {"kernel32.dll", "GetFileSizeEx", kOffGetFileSizeEx},
    {"kernel32.dll", "GetFileSize", kOffGetFileSizeEx}, // close enough for callers w/ small files
    {"kernel32.dll", "GetModuleHandleW", kOffGetModuleHandleW},
    {"kernel32.dll", "GetModuleHandleA", kOffGetModuleHandleW}, // ASCII path also accepts NULL
    {"kernel32.dll", "GetModuleHandleExW", kOffReturnZero},
    {"kernel32.dll", "GetModuleHandleExA", kOffReturnZero},
    {"kernel32.dll", "LoadLibraryW", kOffReturnZero},
    {"kernel32.dll", "LoadLibraryA", kOffReturnZero},
    {"kernel32.dll", "LoadLibraryExW", kOffReturnZero},
    {"kernel32.dll", "LoadLibraryExA", kOffReturnZero},
    {"kernel32.dll", "FreeLibrary", kOffReturnOne}, // pretend success
    // GetProcAddress — real trampoline into SYS_DLL_PROC_ADDRESS
    //. Returns the exported VA out of the
    // process's DLL image table, or 0 on miss (= same contract
    // the old return-zero stub honoured, so existing callers that
    // GetProcAddress an optional API and NULL-check gracefully fall
    // back either way).
    {"kernel32.dll", "GetProcAddress", kOffGetProcAddressReal},

    // Win32 mutex (real waitqueue-backed semantics).
    // CreateMutexW allocates a per-process slot returning a 0x200+
    // pseudo-handle. WaitForSingleObject dispatches by handle range
    // — mutex handles route to SYS_MUTEX_WAIT, anything else
    // pseudo-signals as before. ReleaseMutex routes to
    // SYS_MUTEX_RELEASE. All three are recursive (Win32 contract).
    // CloseHandle handles mutex slots too via range
    // dispatch in SYS_FILE_CLOSE.
    {"kernel32.dll", "CreateMutexW", kOffCreateMutexW},
    {"kernel32.dll", "CreateMutexA", kOffCreateMutexW},
    {"kernel32.dll", "CreateMutexExW", kOffCreateMutexW},     // ignores extra Ex args
    {"kernel32.dll", "WaitForSingleObject", kOffWaitForObj4}, // upgrade
    {"kernel32.dll", "WaitForSingleObjectEx", kOffWaitForObj4},
    {"kernel32.dll", "ReleaseMutex", kOffReleaseMutex},

    // Real event handles. Replaces the kOffReturnOne
    // no-op CreateEventW / SetEvent / ResetEvent from the
    // earlier kernel32 binding.
    // Per-process event table at 0x300..0x307.
    {"kernel32.dll", "CreateEventW", kOffCreateEventReal},
    {"kernel32.dll", "CreateEventA", kOffCreateEventReal},
    {"kernel32.dll", "CreateEventExW", kOffCreateEventReal}, // ignores extra Ex args
    {"kernel32.dll", "CreateEventExA", kOffCreateEventReal},
    {"kernel32.dll", "SetEvent", kOffSetEventReal},
    {"kernel32.dll", "ResetEvent", kOffResetEventReal},

    // real TLS. Replaces 's alias-to-
    // TLS_OUT_OF_INDEXES TlsAlloc. Per-process 64-slot table.
    // Fls* aliases to the same storage (v0 has no fibers).
    {"kernel32.dll", "TlsAlloc", kOffTlsAllocReal},
    {"kernel32.dll", "TlsFree", kOffTlsFreeReal},
    {"kernel32.dll", "TlsGetValue", kOffTlsGetValueReal},
    {"kernel32.dll", "TlsSetValue", kOffTlsSetValueReal},
    {"kernel32.dll", "FlsAlloc", kOffTlsAllocReal},
    {"kernel32.dll", "FlsFree", kOffTlsFreeReal},
    {"kernel32.dll", "FlsGetValue", kOffTlsGetValueReal},
    {"kernel32.dll", "FlsSetValue", kOffTlsSetValueReal},

    // console APIs. WriteConsoleW is the major
    // Unicode-output entry point; the stub UTF-16-strips to
    // ASCII on a stack buffer and routes through SYS_WRITE
    // (same path as WriteFile-to-stdout). GetConsoleMode /
    // GetConsoleCP / GetConsoleOutputCP hand back plausible
    // constants (VT processing enabled, UTF-8 code page). The
    // Set* counterparts are no-ops that return TRUE.
    {"kernel32.dll", "WriteConsoleW", kOffWriteConsoleW},
    {"kernel32.dll", "GetConsoleMode", kOffGetConsoleMode},
    {"kernel32.dll", "SetConsoleMode", kOffReturnOne},
    {"kernel32.dll", "GetConsoleCP", kOffGetConsoleCP},
    {"kernel32.dll", "GetConsoleOutputCP", kOffGetConsoleCP},
    {"kernel32.dll", "SetConsoleCP", kOffReturnOne},
    {"kernel32.dll", "SetConsoleOutputCP", kOffReturnOne},
    // OutputDebugString* is a debugger-notification call. Real
    // Windows silently drops when no debugger is attached. We
    // do the same — kOffReturnZero returns 0 as a `void` sink
    // (both signatures: LPCWSTR / LPCSTR, no return).
    // OutputDebugStringA → real kernel debug-print syscall.
    // OutputDebugStringW unchanged for now (UTF-16 → ASCII strip in
    // a follow-up; most real callers use the A form).
    {"kernel32.dll", "OutputDebugStringW", kOffOutputDebugStringW},
    {"kernel32.dll", "OutputDebugStringA", kOffOutputDebugStringA},

    // virtual memory. VirtualAlloc is the single
    // most-requested Win32 memory primitive for non-trivial
    // PEs (JIT, CoreCLR, TLS setup, custom allocators). Bump-
    // only arena at 0x40000000..+512KiB per process.
    // VirtualFree is a no-op (range-check only). VirtualProtect
    // no-ops and echoes PAGE_READWRITE back — W^X forbids the
    // RWX pages a JIT would actually want, so a a follow-up
    // adds a separate "JIT image" mechanism when a real JIT
    // workload needs it.
    {"kernel32.dll", "VirtualAlloc", kOffVirtualAlloc},
    {"kernel32.dll", "VirtualAllocEx", kOffVirtualAlloc}, // ignores the extra HANDLE arg
    {"kernel32.dll", "VirtualFree", kOffVirtualFree},
    {"kernel32.dll", "VirtualFreeEx", kOffVirtualFree},
    {"kernel32.dll", "VirtualProtect", kOffVirtualProtect},
    {"kernel32.dll", "VirtualProtectEx", kOffVirtualProtect},
    {"kernel32.dll", "VirtualQuery", kOffReturnZero}, // v0 query returns 0 = failed
    {"kernel32.dll", "VirtualQueryEx", kOffReturnZero},

    // wide-string helpers. Pure-compute primitives
    // heavily used by multilingual PEs and MSVC CRT. lstrcmpW
    // is ordinal compare (no locale fold — lstrcmpiW would
    // case-fold, not stubbed). lstrlen has a hard cap of
    // effectively "until NUL" — a wild unterminated string
    // scans forever, matching the documented Win32 behaviour.
    {"kernel32.dll", "lstrlenW", kOffLstrlenW},
    {"kernel32.dll", "lstrcmpW", kOffLstrcmpW},
    {"kernel32.dll", "lstrcpyW", kOffLstrcpyW},

    // system-info probes. IsWow64Process returns FALSE
    // (native x64 process, no 32-bit emulation). GetVersionEx*
    // reports Windows 10 build 19041 (2004 / 20H1) — a modern-
    // enough version to pass most feature-gate checks without
    // triggering "too new, not yet supported" fallbacks apps
    // have for very recent builds.
    {"kernel32.dll", "IsWow64Process", kOffIsWow64},
    {"kernel32.dll", "IsWow64Process2", kOffIsWow64}, // fills similar PBOOL
    {"kernel32.dll", "GetVersionExW", kOffGetVersionExW},
    {"kernel32.dll", "GetVersionExA", kOffGetVersionExW}, // ASCII CSD left untouched

    // ANSI-byte string helpers. Symmetric to
    // but for LPCSTR. Pure compute, no syscalls.
    {"kernel32.dll", "lstrlenA", kOffLstrlenA},
    {"kernel32.dll", "lstrcmpA", kOffLstrcmpA},
    {"kernel32.dll", "lstrcpyA", kOffLstrcpyA},

    // path-query stubs. All v0 paths report a single
    // fixed "X:\\" — well-formed, absolute, drive-qualified —
    // which is enough for literal path comparisons without
    // crashing. Real spawn-path plumbing is a follow-up.
    {"kernel32.dll", "GetModuleFileNameW", kOffGetModFileNameW},
    {"kernel32.dll", "GetModuleFileNameA",
     kOffGetModFileNameW}, // ASCII caller: single-byte chars happen to alias-ok for ASCII path
    {"kernel32.dll", "GetCurrentDirectoryW", kOffGetCurrentDirW},
    {"kernel32.dll", "GetCurrentDirectoryA", kOffGetCurrentDirW},
    {"kernel32.dll", "SetCurrentDirectoryW", kOffReturnOne}, // pretend success
    {"kernel32.dll", "SetCurrentDirectoryA", kOffReturnOne},

    // encoding converters. v0 handles ASCII-range
    // content perfectly (byte-extend / byte-truncate); non-ASCII
    // UTF-8 sequences lose high-plane data.
    {"kernel32.dll", "MultiByteToWideChar", kOffMBtoWC},
    {"kernel32.dll", "WideCharToMultiByte", kOffWCtoMB},

    // identity queries. Fixed-string stubs.
    // kernel32 hosts GetComputerNameW; advapi32 hosts
    // GetUserNameW (on real Windows it's an advapi32 export
    // that delegates to LsaQueryInformationPolicy). Both land
    // on our same in/out-size stub pattern.
    {"advapi32.dll", "GetUserNameW", kOffGetUserNameW},
    {"advapi32.dll", "GetUserNameA", kOffGetUserNameW}, // ASCII caller gets ASCII-range bytes OK
    {"kernel32.dll", "GetComputerNameW", kOffGetComputerNameW},
    {"kernel32.dll", "GetComputerNameA", kOffGetComputerNameW},

    // system-directory queries. GetTempPathW shares
    // GetCurrentDirectoryW's (size, buffer) signature so it
    // aliases to that stub. GetWindowsDirectoryW /
    // GetSystemDirectoryW have (buffer, size) — separate stub.
    // All report "X:\\" as v0's single system path.
    {"kernel32.dll", "GetTempPathW", kOffGetCurrentDirW}, // alias: same sig
    {"kernel32.dll", "GetTempPathA", kOffGetCurrentDirW},
    {"kernel32.dll", "GetWindowsDirectoryW", kOffGetWinDirW},
    {"kernel32.dll", "GetWindowsDirectoryA", kOffGetWinDirW},
    {"kernel32.dll", "GetSystemDirectoryW", kOffGetWinDirW},
    {"kernel32.dll", "GetSystemDirectoryA", kOffGetWinDirW},
    {"kernel32.dll", "GetSystemWindowsDirectoryW", kOffGetWinDirW},
    {"kernel32.dll", "GetSystemWindowsDirectoryA", kOffGetWinDirW},

    // drives, error modes, format messages.
    // GetLogicalDrives returns bit 23 set (only X: mounted).
    // GetDriveType* returns 3 (DRIVE_FIXED) for any input.
    // SetErrorMode / GetErrorMode return 0 (no special mode).
    // FormatMessage{W,A} returns 0 — callers usually fall
    // back to their own format-by-code path.
    {"kernel32.dll", "GetLogicalDrives", kOffGetLogicalDrives},
    {"kernel32.dll", "GetDriveTypeW", kOffGetDriveType},
    {"kernel32.dll", "GetDriveTypeA", kOffGetDriveType},
    {"kernel32.dll", "SetErrorMode", kOffReturnZero},
    {"kernel32.dll", "GetErrorMode", kOffReturnZero},
    {"kernel32.dll", "SetThreadErrorMode", kOffReturnOne}, // return TRUE, ignore mode
    // FormatMessageW stays NO-OP: our v0 stub writes ASCII bytes
    // which would corrupt a WCHAR* buffer. A proper UTF-16 variant
    // is a follow-up.
    {"kernel32.dll", "FormatMessageW", kOffReturnZero},
    {"kernel32.dll", "FormatMessageA", kOffFormatMessageA},

    // registry + file-attribute no-op stubs.
    // Reg open / read family returns ERROR_FILE_NOT_FOUND (2),
    // the standard "key doesn't exist" status.
    // Reg write / close family returns ERROR_SUCCESS (0).
    // GetFileAttributesW returns INVALID_FILE_ATTRIBUTES (-1)
    // — caller treats as "file not present".
    // SetFileAttributesW returns TRUE (pretend success).
    {"advapi32.dll", "RegOpenKeyW", kOffReturnTwo},
    {"advapi32.dll", "RegOpenKeyA", kOffReturnTwo},
    {"advapi32.dll", "RegOpenKeyExW", kOffReturnTwo},
    {"advapi32.dll", "RegOpenKeyExA", kOffReturnTwo},
    {"advapi32.dll", "RegQueryValueW", kOffReturnTwo},
    {"advapi32.dll", "RegQueryValueA", kOffReturnTwo},
    {"advapi32.dll", "RegQueryValueExW", kOffReturnTwo},
    {"advapi32.dll", "RegQueryValueExA", kOffReturnTwo},
    {"advapi32.dll", "RegEnumKeyW", kOffReturnTwo},
    {"advapi32.dll", "RegEnumKeyExW", kOffReturnTwo},
    {"advapi32.dll", "RegEnumValueW", kOffReturnTwo},
    {"advapi32.dll", "RegCreateKeyW", kOffReturnZero}, // pretend success
    {"advapi32.dll", "RegCreateKeyExW", kOffReturnZero},
    {"advapi32.dll", "RegSetValueW", kOffReturnZero},
    {"advapi32.dll", "RegSetValueExW", kOffReturnZero},
    {"advapi32.dll", "RegCloseKey", kOffReturnZero},
    {"advapi32.dll", "RegDeleteKeyW", kOffReturnZero},
    {"advapi32.dll", "RegDeleteValueW", kOffReturnZero},
    {"kernel32.dll", "GetFileAttributesW", kOffReturnMinus1},
    {"kernel32.dll", "GetFileAttributesA", kOffReturnMinus1},
    {"kernel32.dll", "GetFileAttributesExW", kOffReturnZero}, // BOOL FALSE = "file not found"
    {"kernel32.dll", "SetFileAttributesW", kOffReturnOne},    // pretend success
    {"kernel32.dll", "SetFileAttributesA", kOffReturnOne},
    {"kernel32.dll", "DeleteFileW", kOffReturnOne}, // pretend success
    {"kernel32.dll", "DeleteFileA", kOffReturnOne},
    {"kernel32.dll", "CopyFileW", kOffReturnOne},
    {"kernel32.dll", "MoveFileW", kOffReturnOne},
    {"kernel32.dll", "CreateDirectoryW", kOffReturnOne},
    {"kernel32.dll", "RemoveDirectoryW", kOffReturnOne},

    // locale / processor / time-zone probes. All
    // aliases to existing constant-returning stubs; zero new
    // stub bytes needed.
    // GetACP / GetOEMCP -> 65001 (CP_UTF8) via kOffGetConsoleCP.
    // IsValidCodePage -> TRUE.
    // GetThreadLocale / *DefaultLCID -> 0 (LOCALE_INVARIANT).
    // GetTimeZoneInformation -> 1 (TIME_ZONE_ID_STANDARD).
    // GetProcessTimes / GetThreadTimes -> FALSE ("couldn't
    // query — use fallback"), safer than TRUE + uninit out.
    // GetStartupInfoW -> kOffCritSecNop (void return, 1-byte ret).
    // VerifyVersionInfoW -> TRUE (version probe passes).
    {"kernel32.dll", "GetACP", kOffGetConsoleCP},
    {"kernel32.dll", "GetOEMCP", kOffGetConsoleCP},
    {"kernel32.dll", "IsValidCodePage", kOffReturnOne},
    {"kernel32.dll", "GetThreadLocale", kOffReturnZero},
    {"kernel32.dll", "SetThreadLocale", kOffReturnOne},
    {"kernel32.dll", "GetUserDefaultLCID", kOffReturnZero},
    {"kernel32.dll", "GetSystemDefaultLCID", kOffReturnZero},
    {"kernel32.dll", "GetUserDefaultUILanguage", kOffReturnZero},
    {"kernel32.dll", "GetSystemDefaultUILanguage", kOffReturnZero},
    {"kernel32.dll", "GetTimeZoneInformation", kOffReturnOne},
    {"kernel32.dll", "GetDynamicTimeZoneInformation", kOffReturnOne},
    {"kernel32.dll", "GetCurrentProcessorNumber", kOffReturnZero},
    // GetProcessTimes / GetThreadTimes → zero-fill stubs.
    {"kernel32.dll", "GetProcessTimes", kOffGetProcessTimes},
    {"kernel32.dll", "GetThreadTimes", kOffGetProcessTimes}, // same shape
    // GetStartupInfo{W,A} now zero-fill the caller's
    // 104-byte STARTUPINFO and set cb = 104 (the nop previously
    // here left the buffer uninitialised — callers read a wild
    // pointer from lpDesktop / hStdInput and faulted).
    {"kernel32.dll", "GetStartupInfoW", kOffGetStartupInfo},
    {"kernel32.dll", "GetStartupInfoA", kOffGetStartupInfo},
    {"kernel32.dll", "VerSetConditionMask", kOffReturnZero},
    {"kernel32.dll", "VerifyVersionInfoW", kOffReturnOne},
    {"kernel32.dll", "VerifyVersionInfoA", kOffReturnOne},
    // Paired with 's InitializeSListHead — more InterlockedX
    // SList ops all no-op (return NULL = empty list).
    {"kernel32.dll", "InterlockedPushEntrySList", kOffReturnZero},
    {"kernel32.dll", "InterlockedPopEntrySList", kOffReturnZero},
    {"kernel32.dll", "InterlockedFlushSList", kOffReturnZero},
    {"kernel32.dll", "QueryDepthSList", kOffReturnZero},
    // Misc memory / CPU / numa probes.
    // GlobalMemoryStatusEx → real SYS_MEM_STATUS;
    // GetSystemTimes → zero-fill stub.
    {"kernel32.dll", "GlobalMemoryStatusEx", kOffGlobalMemoryStatusEx},
    {"kernel32.dll", "GetSystemTimes", kOffGetSystemTimes},
    // GetSystemInfo / GetNativeSystemInfo populate a
    // Win32 SYSTEM_INFO struct with x86_64 constants.
    {"kernel32.dll", "GetSystemInfo", kOffGetSystemInfo},
    {"kernel32.dll", "GetNativeSystemInfo", kOffGetSystemInfo},
    {"kernel32.dll", "GetNumaHighestNodeNumber", kOffReturnZero},

    // process priority / TLS / file-type aliases.
    // TlsAlloc returning TLS_OUT_OF_INDEXES (0xFFFFFFFF) is a
    // supported "no slots available" signal — forces the MSVC
    // CRT into its single-threaded fallback path instead of
    // panicking. TlsGetValue/SetValue/Free still return sane
    // values so callers holding stale slot indices don't
    // fault.
    {"kernel32.dll", "GetPriorityClass", kOffReturnPrioNormal}, // 0x20 = NORMAL
    {"kernel32.dll", "SetPriorityClass", kOffReturnOne},
    {"kernel32.dll", "GetThreadPriority", kOffReturnZero}, // 0 = NORMAL
    {"kernel32.dll", "SetThreadPriority", kOffReturnOne},
    {"kernel32.dll", "CreateThread", kOffCreateThreadReal}, // real spawn via SYS_THREAD_CREATE
    {"kernel32.dll", "CreateRemoteThread", kOffReturnZero}, // fallback stays (no cross-proc v0)
    // ExitThread routes to SYS_EXIT (kills just this
    // task). FreeLibraryAndExitThread aliases to ExitThread — the
    // FreeLibrary half is a no-op in v0 (no DLL unload path).
    {"kernel32.dll", "ExitThread", kOffExitThread},
    {"kernel32.dll", "FreeLibraryAndExitThread", kOffExitThread},
    // WaitForMultipleObjects via SYS_WAIT_MULTI.
    {"kernel32.dll", "WaitForMultipleObjects", kOffWaitForMultipleObjects},
    {"kernel32.dll", "WaitForMultipleObjectsEx", kOffWaitForMultipleObjects},
    // RaiseException → SYS_EXIT. DecodePointer /
    // EncodePointer → identity (round-trip preserved).
    {"kernel32.dll", "RaiseException", kOffRaiseException},
    {"kernel32.dll", "DecodePointer", kOffDecodePointer},
    {"kernel32.dll", "EncodePointer", kOffDecodePointer},
    {"kernel32.dll", "RtlDecodePointer", kOffDecodePointer},
    {"kernel32.dll", "RtlEncodePointer", kOffDecodePointer},
    // Semaphore family — CreateSemaphore(W/A/ExW) route
    // through SYS_SEM_CREATE; ReleaseSemaphore through SYS_SEM_RELEASE;
    // WaitForSingleObject on a semaphore handle is dispatched by
    // the new v3 stub to SYS_SEM_WAIT.
    {"kernel32.dll", "CreateSemaphoreW", kOffCreateSemaphoreW},
    {"kernel32.dll", "CreateSemaphoreA", kOffCreateSemaphoreW},
    {"kernel32.dll", "CreateSemaphoreExW", kOffCreateSemaphoreW},
    {"kernel32.dll", "CreateSemaphoreExA", kOffCreateSemaphoreW},
    {"kernel32.dll", "ReleaseSemaphore", kOffReleaseSemaphore},
    // === SRW locks, condition variables, one-time
    // init, waitable timers, file mapping. All NO-OP-correct for
    // a single-threaded-by-default v0 — SRW acquire/release is a
    // ret on a process whose threads never contend for the lock;
    // TryAcquire always succeeds; condition variables never fire
    // but SleepConditionVariable* returns TRUE so callers treat
    // it as "woke up"; waitable timers and file mappings return
    // NULL (not supported — callers see CreateFileMapping fail
    // and fall back to non-mapped I/O). Wiring these through the
    // existing shared stubs costs no stub-page bytes.
    {"kernel32.dll", "InitializeSRWLock", kOffSrwInit},
    {"kernel32.dll", "AcquireSRWLockExclusive", kOffSrwAcquireExcl},
    // Shared variants degrade to exclusive acquire in v0 — we
    // don't track reader counts yet, so letting concurrent
    // readers through would violate the reader/writer barrier
    // against an exclusive holder. Correctness > throughput.
    {"kernel32.dll", "AcquireSRWLockShared", kOffSrwAcquireExcl},
    {"kernel32.dll", "ReleaseSRWLockExclusive", kOffSrwReleaseExcl},
    {"kernel32.dll", "ReleaseSRWLockShared", kOffSrwReleaseExcl},
    {"kernel32.dll", "TryAcquireSRWLockExclusive", kOffSrwTryAcquireExcl},
    {"kernel32.dll", "TryAcquireSRWLockShared", kOffSrwTryAcquireExcl},
    {"kernel32.dll", "InitializeConditionVariable", kOffCritSecNop},
    {"kernel32.dll", "WakeConditionVariable", kOffCritSecNop},
    {"kernel32.dll", "WakeAllConditionVariable", kOffCritSecNop},
    {"kernel32.dll", "SleepConditionVariableCS", kOffReturnOne},
    {"kernel32.dll", "SleepConditionVariableSRW", kOffReturnOne},
    // InitOnceInitialize zeroes the 8-byte INIT_ONCE slot. Same
    // byte sequence as InitializeSRWLock, so share the stub.
    {"kernel32.dll", "InitOnceInitialize", kOffSrwInit},
    {"kernel32.dll", "InitializeInitOnce", kOffCritSecNop},
    {"kernel32.dll", "InitOnceComplete", kOffReturnOne},
    {"kernel32.dll", "InitOnceExecuteOnce", kOffInitOnceExec},
    {"kernel32.dll", "InitOnceBeginInitialize", kOffReturnOne},
    {"kernel32.dll", "CreateWaitableTimerW", kOffReturnZero},
    {"kernel32.dll", "CreateWaitableTimerA", kOffReturnZero},
    {"kernel32.dll", "CreateWaitableTimerExW", kOffReturnZero},
    {"kernel32.dll", "SetWaitableTimer", kOffReturnZero},
    {"kernel32.dll", "SetWaitableTimerEx", kOffReturnZero},
    {"kernel32.dll", "CancelWaitableTimer", kOffReturnZero},
    {"kernel32.dll", "CreateFileMappingW", kOffReturnZero},
    {"kernel32.dll", "CreateFileMappingA", kOffReturnZero},
    {"kernel32.dll", "OpenFileMappingW", kOffReturnZero},
    {"kernel32.dll", "OpenFileMappingA", kOffReturnZero},
    {"kernel32.dll", "OpenThread", kOffReturnZero},
    {"kernel32.dll", "GetThreadId", kOffReturnZero},
    {"kernel32.dll", "DuplicateHandle", kOffReturnZero},
    // QueryInterruptTime / QueryUnbiasedInterruptTime NOT wired:
    // both fill an LPULONGLONG output that kOffCritSecNop wouldn't
    // touch. Leaving them unbound lets the miss-logger record the
    // call (more diagnostic than a silent ret into junk memory).

    // === File I/O + thread/fiber + debug + precise time.
    // All NO-OP-correct for v0 — no async I/O (CancelIo nothing to
    // cancel; GetOverlappedResult pretends sync completion), no
    // multi-CPU affinity knobs (v0 is uni-processor from the user
    // angle — AffinityMask set always "succeeds"), no fibers (real
    // stack-swap fibers need SwapContext which isn't hooked up).
    {"kernel32.dll", "LockFile", kOffReturnOne},
    {"kernel32.dll", "LockFileEx", kOffReturnOne},
    {"kernel32.dll", "UnlockFile", kOffReturnOne},
    {"kernel32.dll", "UnlockFileEx", kOffReturnOne},
    {"kernel32.dll", "CancelIo", kOffReturnOne},
    {"kernel32.dll", "CancelIoEx", kOffReturnOne},
    {"kernel32.dll", "CancelSynchronousIo", kOffReturnOne},
    {"kernel32.dll", "GetOverlappedResult", kOffReturnOne},
    {"kernel32.dll", "GetOverlappedResultEx", kOffReturnOne},
    {"kernel32.dll", "SetThreadAffinityMask", kOffReturnOne},
    {"kernel32.dll", "SetProcessAffinityMask", kOffReturnOne},
    {"kernel32.dll", "SetThreadIdealProcessor", kOffReturnZero}, // prev ideal = 0
    {"kernel32.dll", "GetThreadIdealProcessorEx", kOffReturnOne},
    {"kernel32.dll", "DisableThreadLibraryCalls", kOffReturnOne},
    {"kernel32.dll", "CreateFiber", kOffReturnZero},
    {"kernel32.dll", "CreateFiberEx", kOffReturnZero},
    {"kernel32.dll", "ConvertThreadToFiber", kOffReturnZero},
    {"kernel32.dll", "ConvertThreadToFiberEx", kOffReturnZero},
    {"kernel32.dll", "ConvertFiberToThread", kOffReturnOne},
    {"kernel32.dll", "SwitchToFiber", kOffCritSecNop}, // void
    {"kernel32.dll", "DeleteFiber", kOffCritSecNop},   // void
    {"kernel32.dll", "IsThreadAFiber", kOffReturnZero},
    {"kernel32.dll", "DebugBreak", kOffCritSecNop}, // void — no int3 (would kill us)
    {"kernel32.dll", "DebugActiveProcess", kOffReturnZero},
    {"kernel32.dll", "DebugActiveProcessStop", kOffReturnZero},
    // GetSystemTimePreciseAsFileTime has the same shape as
    // GetSystemTimeAsFileTime — reuse the existing real stub.
    {"kernel32.dll", "GetSystemTimePreciseAsFileTime", kOffGetSysTimeFTReal},
    // Named pipes: unsupported — all return FALSE / NULL / invalid.
    {"kernel32.dll", "CreateNamedPipeW", kOffReturnMinus1}, // INVALID_HANDLE_VALUE
    {"kernel32.dll", "CreateNamedPipeA", kOffReturnMinus1},
    {"kernel32.dll", "ConnectNamedPipe", kOffReturnZero},
    {"kernel32.dll", "DisconnectNamedPipe", kOffReturnOne},
    {"kernel32.dll", "WaitNamedPipeW", kOffReturnZero},
    {"kernel32.dll", "WaitNamedPipeA", kOffReturnZero},
    {"kernel32.dll", "PeekConsoleInputW", kOffReturnZero},
    {"kernel32.dll", "GetLogicalProcessorInformation", kOffReturnZero},
    {"kernel32.dll", "GetLogicalProcessorInformationEx", kOffReturnZero},
    {"kernel32.dll", "GetSystemFirmwareTable", kOffReturnZero}, // 0 = size unavailable
    {"kernel32.dll", "EnumSystemFirmwareTables", kOffReturnZero},
    {"kernel32.dll", "RegisterApplicationRestart", kOffReturnZero}, // S_OK
    {"kernel32.dll", "UnregisterApplicationRestart", kOffReturnZero},
    {"kernel32.dll", "SetSearchPathMode", kOffReturnOne},
    {"kernel32.dll", "SetDefaultDllDirectories", kOffReturnOne},
    {"kernel32.dll", "AddDllDirectory", kOffReturnZero}, // NULL cookie
    {"kernel32.dll", "RemoveDllDirectory", kOffReturnOne},
    // Tls/Fls now route through real per-process storage —
    // moved to below.
    {"kernel32.dll", "SetEndOfFile", kOffReturnOne},
    {"kernel32.dll", "FlushFileBuffers", kOffReturnOne}, // pretend fsync
    {"kernel32.dll", "GetFileType", kOffReturnTwo},      // 2 = FILE_TYPE_CHAR (console-ish)
    {"kernel32.dll", "GetConsoleWindow", kOffReturnZero},
    {"kernel32.dll", "AddVectoredExceptionHandler", kOffReturnZero},
    {"kernel32.dll", "RemoveVectoredExceptionHandler", kOffReturnZero},
    {"kernel32.dll", "AddVectoredContinueHandler", kOffReturnZero},

    // Interlocked atomics. Real LOCK-prefixed instr
    // sequences; correct even if DuetOS gains ring-3 SMP.
    // Exported under both legacy `InterlockedX` names and the
    // `_InterlockedX` compiler intrinsic-style names (clang/MSVC
    // alias them).
    {"kernel32.dll", "InterlockedIncrement", kOffInterlockedInc},
    {"kernel32.dll", "InterlockedDecrement", kOffInterlockedDec},
    {"kernel32.dll", "InterlockedCompareExchange", kOffInterlockedCmpXchg},
    {"kernel32.dll", "InterlockedExchange", kOffInterlockedExchg},
    {"kernel32.dll", "InterlockedExchangeAdd", kOffInterlockedExchgAdd},
    // vcruntime140 intrinsic exports (used by MSVC CRT).
    {"vcruntime140.dll", "_InterlockedIncrement", kOffInterlockedInc},
    {"vcruntime140.dll", "_InterlockedDecrement", kOffInterlockedDec},
    {"vcruntime140.dll", "_InterlockedCompareExchange", kOffInterlockedCmpXchg},
    {"vcruntime140.dll", "_InterlockedExchange", kOffInterlockedExchg},
    {"vcruntime140.dll", "_InterlockedExchangeAdd", kOffInterlockedExchgAdd},
    // __chkstk: MSVC stack-probe helper for functions with
    // frames > 4 KiB. DuetOS maps the full user stack up-
    // front at PE load, so no probe is needed — just ret. RAX
    // holds the requested size; we preserve it by doing nothing.
    {"vcruntime140.dll", "__chkstk", kOffCritSecNop},
    {"ntdll.dll", "__chkstk", kOffCritSecNop},
    // 64-bit variants
    {"kernel32.dll", "InterlockedIncrement64", kOffInterlockedInc64},
    {"kernel32.dll", "InterlockedDecrement64", kOffInterlockedDec64},
    {"kernel32.dll", "InterlockedCompareExchange64", kOffInterlockedCmpXchg64},
    {"kernel32.dll", "InterlockedExchange64", kOffInterlockedExchg64},
    {"kernel32.dll", "InterlockedExchangeAdd64", kOffInterlockedExchgAdd64},
    // Interlocked{And,Or,Xor} 32 + 64. CAS-loop stubs
    // backed by LOCK CMPXCHG — correct under SMP + timer-tick
    // preemption. Return the ORIGINAL pre-modify value per Win32
    // contract.
    {"kernel32.dll", "InterlockedAnd", kOffInterlockedAnd},
    {"kernel32.dll", "InterlockedOr", kOffInterlockedOr},
    {"kernel32.dll", "InterlockedXor", kOffInterlockedXor},
    {"kernel32.dll", "InterlockedAnd64", kOffInterlockedAnd64},
    {"kernel32.dll", "InterlockedOr64", kOffInterlockedOr64},
    {"kernel32.dll", "InterlockedXor64", kOffInterlockedXor64},
    {"vcruntime140.dll", "_InterlockedIncrement64", kOffInterlockedInc64},
    {"vcruntime140.dll", "_InterlockedDecrement64", kOffInterlockedDec64},
    {"vcruntime140.dll", "_InterlockedCompareExchange64", kOffInterlockedCmpXchg64},
    {"vcruntime140.dll", "_InterlockedExchange64", kOffInterlockedExchg64},
    {"vcruntime140.dll", "_InterlockedExchangeAdd64", kOffInterlockedExchgAdd64},

    // === ntdll.dll coverage =========================
    //
    // A PE that bypasses kernel32 and imports directly from ntdll
    // (installers, anti-debug tooling, some Microsoft-shipped
    // binaries) reaches this table. Most NT functions have
    // signatures incompatible with their kernel32 analogues
    // (NtWriteFile has 9 args vs kernel32 WriteFile's 5), so we
    // can't cross-alias. Instead, most entries return
    // STATUS_NOT_IMPLEMENTED (0xC00000BB) — callers either fall
    // back or propagate the status up cleanly.
    //
    // Two exceptions where the signature matches perfectly:
    // * NtClose(HANDLE rcx) matches CloseHandle(HANDLE rcx),
    // so we alias to kOffCloseHandle — NtClose actually works.
    // * NtYieldExecution() takes no args; reuse kOffCritSecNop
    // (1-byte ret) since the return value (NTSTATUS 0 =
    // STATUS_SUCCESS) is what we'd emit anyway.
    //
    // Rtl* functions are mostly pure-compute user-mode helpers
    // that don't cross the kernel boundary on real Windows.
    // RtlGetLastWin32Error has the same sig as GetLastError →
    // alias. RtlSetLastWin32Error aliases to SetLastError.
    {"ntdll.dll", "NtClose", kOffCloseHandle},
    {"ntdll.dll", "ZwClose", kOffCloseHandle}, // Zw == Nt in user mode
    {"ntdll.dll", "NtYieldExecution", kOffCritSecNop},
    {"ntdll.dll", "ZwYieldExecution", kOffCritSecNop},
    {"ntdll.dll", "RtlGetLastWin32Error", kOffGetLastError},
    {"ntdll.dll", "RtlSetLastWin32Error", kOffSetLastError},
    {"ntdll.dll", "RtlNtStatusToDosError", kOffReturnZero}, // 0 = ERROR_SUCCESS
    // Everything else returns STATUS_NOT_IMPLEMENTED.
    {"ntdll.dll", "NtCreateFile", kOffReturnStatusNotImpl},
    {"ntdll.dll", "ZwCreateFile", kOffReturnStatusNotImpl},
    {"ntdll.dll", "NtOpenFile", kOffReturnStatusNotImpl},
    {"ntdll.dll", "ZwOpenFile", kOffReturnStatusNotImpl},
    {"ntdll.dll", "NtReadFile", kOffReturnStatusNotImpl},
    {"ntdll.dll", "ZwReadFile", kOffReturnStatusNotImpl},
    {"ntdll.dll", "NtWriteFile", kOffReturnStatusNotImpl},
    {"ntdll.dll", "ZwWriteFile", kOffReturnStatusNotImpl},
    {"ntdll.dll", "NtDeviceIoControlFile", kOffReturnStatusNotImpl},
    {"ntdll.dll", "ZwDeviceIoControlFile", kOffReturnStatusNotImpl},
    {"ntdll.dll", "NtQueryInformationFile", kOffReturnStatusNotImpl},
    {"ntdll.dll", "ZwQueryInformationFile", kOffReturnStatusNotImpl},
    {"ntdll.dll", "NtSetInformationFile", kOffReturnStatusNotImpl},
    {"ntdll.dll", "ZwSetInformationFile", kOffReturnStatusNotImpl},
    {"ntdll.dll", "NtQueryVolumeInformationFile", kOffReturnStatusNotImpl},
    {"ntdll.dll", "ZwQueryVolumeInformationFile", kOffReturnStatusNotImpl},
    // : real NtAllocateVirtualMemory / NtFreeVirtualMemory
    // trampolines that route to SYS_VMAP / SYS_VUNMAP (the same
    // page-grain allocator backing kernel32.VirtualAlloc/Free).
    // Was kOffReturnStatusNotImpl before — every PE that bypassed
    // kernel32 and called these from ntdll directly used to fail.
    {"ntdll.dll", "NtAllocateVirtualMemory", kOffNtAllocateVirtualMemory},
    {"ntdll.dll", "NtFreeVirtualMemory", kOffNtFreeVirtualMemory},
    {"ntdll.dll", "NtProtectVirtualMemory", kOffReturnStatusNotImpl},
    {"ntdll.dll", "ZwProtectVirtualMemory", kOffReturnStatusNotImpl},
    {"ntdll.dll", "NtQueryVirtualMemory", kOffReturnStatusNotImpl},
    {"ntdll.dll", "ZwQueryVirtualMemory", kOffReturnStatusNotImpl},
    {"ntdll.dll", "NtCreateEvent", kOffReturnStatusNotImpl},
    {"ntdll.dll", "ZwCreateEvent", kOffReturnStatusNotImpl},
    // Signature-compatible enough with SetEvent/ResetEvent:
    // Nt* variants carry an optional "previous state" out-pointer
    // in rdx that our v0 ignores.
    {"ntdll.dll", "NtSetEvent", kOffSetEventReal},
    {"ntdll.dll", "ZwSetEvent", kOffSetEventReal},
    {"ntdll.dll", "NtResetEvent", kOffResetEventReal},
    {"ntdll.dll", "ZwResetEvent", kOffResetEventReal},
    {"ntdll.dll", "NtCreateMutant", kOffReturnStatusNotImpl},
    {"ntdll.dll", "ZwCreateMutant", kOffReturnStatusNotImpl},
    // NtReleaseMutant(handle, prevCount*) is close enough to
    // ReleaseMutex(handle) for v0; prevCount is ignored.
    {"ntdll.dll", "NtReleaseMutant", kOffReleaseMutex},
    {"ntdll.dll", "ZwReleaseMutant", kOffReleaseMutex},
    {"ntdll.dll", "NtWaitForSingleObject", kOffReturnStatusNotImpl},
    {"ntdll.dll", "ZwWaitForSingleObject", kOffReturnStatusNotImpl},
    {"ntdll.dll", "NtWaitForMultipleObjects", kOffReturnStatusNotImpl},
    {"ntdll.dll", "ZwWaitForMultipleObjects", kOffReturnStatusNotImpl},
    {"ntdll.dll", "NtDelayExecution", kOffReturnStatusNotImpl},
    {"ntdll.dll", "ZwDelayExecution", kOffReturnStatusNotImpl},
    // Dedicated NTSTATUS-returning stubs, so ntdll
    // callers see STATUS_SUCCESS (0) instead of kernel32 BOOL.
    {"ntdll.dll", "NtQueryPerformanceCounter", kOffNtQueryPerfCounterReal},
    {"ntdll.dll", "ZwQueryPerformanceCounter", kOffNtQueryPerfCounterReal},
    {"ntdll.dll", "NtQuerySystemTime", kOffNtQuerySystemTimeReal},
    {"ntdll.dll", "ZwQuerySystemTime", kOffNtQuerySystemTimeReal},
    {"ntdll.dll", "NtQuerySystemInformation", kOffReturnStatusNotImpl},
    {"ntdll.dll", "ZwQuerySystemInformation", kOffReturnStatusNotImpl},
    {"ntdll.dll", "NtQueryInformationProcess", kOffReturnStatusNotImpl},
    {"ntdll.dll", "ZwQueryInformationProcess", kOffReturnStatusNotImpl},
    {"ntdll.dll", "NtQueryInformationThread", kOffReturnStatusNotImpl},
    {"ntdll.dll", "ZwQueryInformationThread", kOffReturnStatusNotImpl},
    {"ntdll.dll", "NtSetInformationProcess", kOffReturnStatusNotImpl},
    {"ntdll.dll", "ZwSetInformationProcess", kOffReturnStatusNotImpl},
    {"ntdll.dll", "NtSetInformationThread", kOffReturnStatusNotImpl},
    {"ntdll.dll", "ZwSetInformationThread", kOffReturnStatusNotImpl},
    {"ntdll.dll", "NtTerminateProcess", kOffReturnStatusNotImpl},
    {"ntdll.dll", "ZwTerminateProcess", kOffReturnStatusNotImpl},
    {"ntdll.dll", "NtTerminateThread", kOffReturnStatusNotImpl},
    {"ntdll.dll", "ZwTerminateThread", kOffReturnStatusNotImpl},
    {"ntdll.dll", "NtContinue", kOffReturnStatusNotImpl},
    {"ntdll.dll", "ZwContinue", kOffReturnStatusNotImpl},
    {"ntdll.dll", "NtOpenKey", kOffReturnStatusNotImpl},
    {"ntdll.dll", "ZwOpenKey", kOffReturnStatusNotImpl},
    {"ntdll.dll", "NtQueryValueKey", kOffReturnStatusNotImpl},
    {"ntdll.dll", "ZwQueryValueKey", kOffReturnStatusNotImpl},
    {"ntdll.dll", "NtQueryKey", kOffReturnStatusNotImpl},
    {"ntdll.dll", "ZwQueryKey", kOffReturnStatusNotImpl},
    {"ntdll.dll", "NtEnumerateKey", kOffReturnStatusNotImpl},
    {"ntdll.dll", "ZwEnumerateKey", kOffReturnStatusNotImpl},
    {"ntdll.dll", "NtEnumerateValueKey", kOffReturnStatusNotImpl},
    {"ntdll.dll", "ZwEnumerateValueKey", kOffReturnStatusNotImpl},
    {"ntdll.dll", "NtCreateSection", kOffReturnStatusNotImpl},
    {"ntdll.dll", "ZwCreateSection", kOffReturnStatusNotImpl},
    {"ntdll.dll", "NtMapViewOfSection", kOffReturnStatusNotImpl},
    {"ntdll.dll", "ZwMapViewOfSection", kOffReturnStatusNotImpl},
    {"ntdll.dll", "NtUnmapViewOfSection", kOffReturnStatusNotImpl},
    {"ntdll.dll", "ZwUnmapViewOfSection", kOffReturnStatusNotImpl},
    // Zw aliases for already-routed Nt VM calls.
    {"ntdll.dll", "ZwAllocateVirtualMemory", kOffNtAllocateVirtualMemory},
    {"ntdll.dll", "ZwFreeVirtualMemory", kOffNtFreeVirtualMemory},

    // === UI / locale / clipboard / mapping ==========
    //
    // Broad coverage sweep. Most bindings are "best-effort
    // failure" aliases so a PE that probes any of these at
    // startup sees a documented negative return and falls back
    // cleanly rather than hitting the miss-logger.

    // user32 — UI surface. DuetOS has no window system
    // reachable from ring 3 yet, so every user32 entry either
    // returns failure or a benign constant.
    {"user32.dll", "MessageBoxW", kOffReturnOne}, // IDOK (1) — caller proceeds
    {"user32.dll", "MessageBoxA", kOffReturnOne},
    {"user32.dll", "MessageBoxExW", kOffReturnOne},
    {"user32.dll", "GetDesktopWindow", kOffReturnZero},
    {"user32.dll", "GetProcessWindowStation", kOffReturnZero},
    {"user32.dll", "GetSysColor", kOffGetSysColor},
    {"user32.dll", "GetSysColorBrush", kOffGetSysColorBrush},
    {"user32.dll", "GetSystemMetrics", kOffReturnZero},
    {"user32.dll", "OpenClipboard", kOffReturnZero}, // FALSE — unavailable
    {"user32.dll", "CloseClipboard", kOffReturnOne},
    {"user32.dll", "EmptyClipboard", kOffReturnOne},
    {"user32.dll", "GetClipboardData", kOffReturnZero},
    {"user32.dll", "SetClipboardData", kOffReturnZero},
    {"user32.dll", "LoadStringW", kOffReturnZero}, // 0 chars copied
    {"user32.dll", "CharUpperW", kOffReturnZero},
    {"user32.dll", "CharLowerW", kOffReturnZero},
    {"user32.dll", "IsWindow", kOffReturnZero},
    {"user32.dll", "GetActiveWindow", kOffReturnZero},
    {"user32.dll", "GetForegroundWindow", kOffReturnZero},

    // kernel32 — handle / file-mapping / env extensions.
    {"kernel32.dll", "SetHandleInformation", kOffReturnOne},
    {"kernel32.dll", "GetHandleInformation", kOffReturnZero},
    {"kernel32.dll", "DuplicateHandle", kOffReturnZero}, // FALSE
    {"kernel32.dll", "CreateFileMappingW", kOffReturnZero},
    {"kernel32.dll", "CreateFileMappingA", kOffReturnZero},
    {"kernel32.dll", "OpenFileMappingW", kOffReturnZero},
    {"kernel32.dll", "MapViewOfFile", kOffReturnZero},
    {"kernel32.dll", "MapViewOfFileEx", kOffReturnZero},
    {"kernel32.dll", "UnmapViewOfFile", kOffReturnOne},
    {"kernel32.dll", "FlushViewOfFile", kOffReturnOne},
    {"kernel32.dll", "ExpandEnvironmentStringsW", kOffReturnZero},
    {"kernel32.dll", "ExpandEnvironmentStringsA", kOffReturnZero},
    {"kernel32.dll", "GetEnvironmentStringsA", kOffReturnZero},
    {"kernel32.dll", "FreeEnvironmentStringsA", kOffReturnOne},
    {"kernel32.dll", "SetStdHandle", kOffReturnOne},
    {"kernel32.dll", "GetConsoleScreenBufferInfo", kOffGetConsoleScreenBufferInfo},
    {"kernel32.dll", "GetNumberOfConsoleInputEvents", kOffReturnZero},
    {"kernel32.dll", "PeekConsoleInputW", kOffReturnZero},
    {"kernel32.dll", "ReadConsoleInputW", kOffReturnZero},
    {"kernel32.dll", "WaitForInputIdle", kOffReturnZero}, // 0 = WAIT_OBJECT_0
    {"kernel32.dll", "PeekNamedPipe", kOffReturnZero},

    // kernel32 — locale / comparison.
    // CompareStringW returns 2 (CSTR_EQUAL) so callers treating
    // it as a 3-way compare see "equal" — the conservative
    // fallback that avoids misordering.
    {"kernel32.dll", "CompareStringW", kOffReturnTwo}, // CSTR_EQUAL
    {"kernel32.dll", "CompareStringA", kOffReturnTwo},
    {"kernel32.dll", "CompareStringEx", kOffReturnTwo},
    {"kernel32.dll", "LCMapStringW", kOffReturnZero},
    {"kernel32.dll", "LCMapStringA", kOffReturnZero},
    {"kernel32.dll", "LCMapStringEx", kOffReturnZero},
    {"kernel32.dll", "GetLocaleInfoW", kOffReturnZero},
    {"kernel32.dll", "GetLocaleInfoA", kOffReturnZero},
    {"kernel32.dll", "GetLocaleInfoEx", kOffReturnZero},
    {"kernel32.dll", "EnumSystemLocalesW", kOffReturnOne}, // pretend iteration done
    {"kernel32.dll", "EnumSystemLocalesA", kOffReturnOne},
    {"kernel32.dll", "GetStringTypeW", kOffReturnOne},
    {"kernel32.dll", "GetStringTypeA", kOffReturnOne},
    {"kernel32.dll", "GetStringTypeExW", kOffReturnOne},
    {"kernel32.dll", "IsDBCSLeadByte", kOffReturnZero}, // FALSE — no DBCS

    // === shell32 / ole32 / winmm / shlwapi / psapi ==
    //
    // Another broad coverage sweep. All aliases to existing
    // constant-return stubs. Most return "failure" or "empty
    // result" so callers fall back cleanly.

    // shell32 — folder paths + shell-execute.
    {"shell32.dll", "SHGetFolderPathW", kOffReturnZero},
    {"shell32.dll", "SHGetFolderPathA", kOffReturnZero},
    {"shell32.dll", "SHGetKnownFolderPath", kOffReturnZero},
    {"shell32.dll", "SHCreateDirectoryW", kOffReturnZero},
    {"shell32.dll", "SHCreateDirectoryExW", kOffReturnZero},
    {"shell32.dll", "SHGetPathFromIDListW", kOffReturnOne},
    {"shell32.dll", "CommandLineToArgvW", kOffReturnZero},
    {"shell32.dll", "ShellExecuteW", kOffReturnOne},
    {"shell32.dll", "ShellExecuteExW", kOffReturnOne},
    {"shell32.dll", "SHGetSpecialFolderPathW", kOffReturnOne},
    {"shell32.dll", "SHFileOperationW", kOffReturnZero},
    {"shell32.dll", "ExtractIconW", kOffReturnZero},
    {"shell32.dll", "ExtractIconExW", kOffReturnZero},

    // ole32 + oleaut32 — COM.
    {"ole32.dll", "CoInitialize", kOffReturnZero},
    {"ole32.dll", "CoInitializeEx", kOffReturnZero},
    {"ole32.dll", "CoUninitialize", kOffCritSecNop},
    {"ole32.dll", "CoCreateInstance", kOffHresultEFail},
    {"ole32.dll", "CoCreateInstanceEx", kOffHresultEFail},
    {"ole32.dll", "CoGetClassObject", kOffHresultEFail},
    {"ole32.dll", "CoTaskMemAlloc", kOffReturnZero},
    {"ole32.dll", "CoTaskMemFree", kOffCritSecNop},
    {"ole32.dll", "CoTaskMemRealloc", kOffReturnZero},
    {"ole32.dll", "OleInitialize", kOffReturnZero},
    {"ole32.dll", "OleUninitialize", kOffCritSecNop},
    {"ole32.dll", "CLSIDFromString", kOffHresultEFail},
    {"ole32.dll", "CLSIDFromProgID", kOffHresultEFail},
    {"ole32.dll", "StringFromCLSID", kOffHresultEFail},
    {"ole32.dll", "IIDFromString", kOffHresultEFail},
    {"oleaut32.dll", "SysAllocString", kOffReturnZero},
    {"oleaut32.dll", "SysFreeString", kOffCritSecNop},
    {"oleaut32.dll", "SysStringLen", kOffReturnZero},
    {"oleaut32.dll", "VariantInit", kOffCritSecNop},
    {"oleaut32.dll", "VariantClear", kOffReturnZero},

    // winmm — timer + multimedia.
    {"winmm.dll", "timeGetTime", kOffGetTickCount},
    {"winmm.dll", "timeBeginPeriod", kOffReturnZero},
    {"winmm.dll", "timeEndPeriod", kOffReturnZero},
    {"winmm.dll", "timeGetDevCaps", kOffReturnZero},
    {"winmm.dll", "PlaySoundW", kOffReturnOne},
    {"winmm.dll", "mciSendStringW", kOffReturnZero},

    // shlwapi — path / string helpers.
    {"shlwapi.dll", "PathFileExistsW", kOffReturnZero},
    {"shlwapi.dll", "PathFileExistsA", kOffReturnZero},
    {"shlwapi.dll", "PathFindFileNameW", kOffReturnZero},
    {"shlwapi.dll", "PathFindFileNameA", kOffReturnZero},
    {"shlwapi.dll", "PathFindExtensionW", kOffReturnZero},
    {"shlwapi.dll", "PathFindExtensionA", kOffReturnZero},
    {"shlwapi.dll", "PathCombineW", kOffReturnZero},
    {"shlwapi.dll", "PathIsDirectoryW", kOffReturnZero},
    {"shlwapi.dll", "PathRemoveFileSpecW", kOffReturnZero},
    {"shlwapi.dll", "PathStripPathW", kOffCritSecNop},
    {"shlwapi.dll", "PathAppendW", kOffReturnZero},
    {"shlwapi.dll", "PathAddBackslashW", kOffReturnZero},
    {"shlwapi.dll", "StrStrW", kOffReturnZero},
    {"shlwapi.dll", "StrStrIW", kOffReturnZero},
    {"shlwapi.dll", "StrCmpNW", kOffReturnZero},
    {"shlwapi.dll", "StrCmpW", kOffReturnZero},

    // psapi — process/module enumeration.
    {"psapi.dll", "EnumProcesses", kOffReturnZero},
    {"psapi.dll", "EnumProcessModules", kOffReturnZero},
    {"psapi.dll", "GetModuleBaseNameW", kOffReturnZero},
    {"psapi.dll", "GetModuleFileNameExW", kOffReturnZero},
    {"psapi.dll", "GetProcessMemoryInfo", kOffReturnZero},
    {"psapi.dll", "GetMappedFileNameW", kOffReturnZero},
    {"psapi.dll", "QueryWorkingSet", kOffReturnZero},

    // === kernelbase / bcrypt / dbghelp / extended ntdll ===
    //
    // Coverage for the newer DLL split (kernelbase.dll = common
    // kernel32+advapi32 core since Win8) + crypto + debugging
    // helpers + more ntdll. All aliases.

    // kernelbase.dll — most exports mirror kernel32. Real apps
    // built against the Win8+ SDK bind directly to kernelbase.
    // Aliasing to the same internal stubs means they work
    // identically.
    {"kernelbase.dll", "GetLastError", kOffGetLastError},
    {"kernelbase.dll", "SetLastError", kOffSetLastError},
    {"kernelbase.dll", "GetCurrentProcess", kOffGetCurrentProcess},
    {"kernelbase.dll", "GetCurrentProcessId", kOffGetCurrentProcessId},
    {"kernelbase.dll", "GetCurrentThreadId", kOffGetCurrentThreadId},
    {"kernelbase.dll", "ExitProcess", kOffExitProcess},
    {"kernelbase.dll", "WriteFile", kOffWriteFile},
    {"kernelbase.dll", "ReadFile", kOffReadFile},
    {"kernelbase.dll", "CloseHandle", kOffCloseHandle},
    {"kernelbase.dll", "CreateFileW", kOffCreateFileW},
    {"kernelbase.dll", "HeapAlloc", kOffHeapAlloc},
    {"kernelbase.dll", "HeapFree", kOffHeapFree},
    {"kernelbase.dll", "GetProcessHeap", kOffGetProcessHeap},
    {"kernelbase.dll", "GetStdHandle", kOffGetStdHandle},
    {"kernelbase.dll", "VirtualAlloc", kOffVirtualAlloc},
    {"kernelbase.dll", "VirtualFree", kOffVirtualFree},
    {"kernelbase.dll", "VirtualProtect", kOffVirtualProtect},
    {"kernelbase.dll", "CreateMutexW", kOffCreateMutexW},
    {"kernelbase.dll", "WaitForSingleObject", kOffWaitForObj4},
    {"kernelbase.dll", "WaitForSingleObjectEx", kOffWaitForObj4},
    {"kernelbase.dll", "ReleaseMutex", kOffReleaseMutex},
    {"kernelbase.dll", "CreateEventW", kOffCreateEventReal},
    {"kernelbase.dll", "SetEvent", kOffSetEventReal},
    {"kernelbase.dll", "ResetEvent", kOffResetEventReal},
    {"kernelbase.dll", "Sleep", kOffSleep},
    {"kernelbase.dll", "SwitchToThread", kOffSwitchToThread},
    {"kernelbase.dll", "GetCommandLineW", kOffGetCmdLineW},
    {"kernelbase.dll", "GetCommandLineA", kOffGetCmdLineA},
    {"kernelbase.dll", "GetModuleHandleW", kOffGetModuleHandleW},
    {"kernelbase.dll", "GetModuleFileNameW", kOffGetModFileNameW},
    {"kernelbase.dll", "TlsAlloc", kOffTlsAllocReal},
    {"kernelbase.dll", "TlsFree", kOffTlsFreeReal},
    {"kernelbase.dll", "TlsGetValue", kOffTlsGetValueReal},
    {"kernelbase.dll", "TlsSetValue", kOffTlsSetValueReal},
    {"kernelbase.dll", "InterlockedIncrement", kOffInterlockedInc},
    {"kernelbase.dll", "InterlockedDecrement", kOffInterlockedDec},
    {"kernelbase.dll", "InterlockedCompareExchange", kOffInterlockedCmpXchg},
    {"kernelbase.dll", "InterlockedExchange", kOffInterlockedExchg},
    {"kernelbase.dll", "VerifyVersionInfoW", kOffReturnOne},
    {"kernelbase.dll", "IsWow64Process", kOffIsWow64},
    {"kernelbase.dll", "GetVersionExW", kOffGetVersionExW},
    {"kernelbase.dll", "lstrlenW", kOffLstrlenW},
    {"kernelbase.dll", "lstrcmpW", kOffLstrcmpW},
    {"kernelbase.dll", "MultiByteToWideChar", kOffMBtoWC},
    {"kernelbase.dll", "WideCharToMultiByte", kOffWCtoMB},

    // bcrypt.dll — CNG crypto. All "no-op success" for v0; real
    // entropy comes from RtlGenRandom (below) if callers fall
    // through to it. Most callers handle STATUS_UNSUCCESSFUL by
    // bailing the crypto path cleanly.
    {"bcrypt.dll", "BCryptOpenAlgorithmProvider", kOffReturnStatusNotImpl},
    {"bcrypt.dll", "BCryptCloseAlgorithmProvider", kOffReturnZero},
    {"bcrypt.dll", "BCryptGenRandom", kOffReturnStatusNotImpl},
    {"bcrypt.dll", "BCryptCreateHash", kOffReturnStatusNotImpl},
    {"bcrypt.dll", "BCryptHashData", kOffReturnStatusNotImpl},
    {"bcrypt.dll", "BCryptFinishHash", kOffReturnStatusNotImpl},
    {"bcrypt.dll", "BCryptDestroyHash", kOffReturnZero},
    {"bcrypt.dll", "BCryptGetProperty", kOffReturnStatusNotImpl},
    // advapi32 has a legacy crypto entry that some CRT builds probe.
    {"advapi32.dll", "SystemFunction036", kOffReturnOne}, // RtlGenRandom — return TRUE, buf untouched

    // dbghelp.dll — symbolic debugging. Everything stubbed to
    // "not available"; programs usually fall back to raw addresses.
    {"dbghelp.dll", "SymInitialize", kOffReturnOne},
    {"dbghelp.dll", "SymInitializeW", kOffReturnOne},
    {"dbghelp.dll", "SymCleanup", kOffReturnOne},
    {"dbghelp.dll", "SymFromAddr", kOffReturnZero},
    {"dbghelp.dll", "SymFromAddrW", kOffReturnZero},
    {"dbghelp.dll", "SymGetLineFromAddr64", kOffReturnZero},
    {"dbghelp.dll", "SymLoadModule64", kOffReturnZero},
    {"dbghelp.dll", "StackWalk64", kOffReturnZero},
    {"dbghelp.dll", "SymFunctionTableAccess64", kOffReturnZero},
    {"dbghelp.dll", "SymGetModuleBase64", kOffReturnZero},
    {"dbghelp.dll", "MiniDumpWriteDump", kOffReturnZero},

    // More ntdll Rtl* — pure user-mode helpers often touched
    // even from kernel32-using apps. Most return 0/success.
    {"ntdll.dll", "RtlInitUnicodeString", kOffCritSecNop}, // void
    {"ntdll.dll", "RtlInitAnsiString", kOffCritSecNop},    // void
    {"ntdll.dll", "RtlFreeUnicodeString", kOffCritSecNop},
    {"ntdll.dll", "RtlAllocateHeap", kOffHeapAlloc}, // real heap
    {"ntdll.dll", "RtlFreeHeap", kOffHeapFree},      // real heap
    {"ntdll.dll", "RtlSizeHeap", kOffHeapSize},
    {"ntdll.dll", "RtlReAllocateHeap", kOffHeapRealloc},
    {"ntdll.dll", "RtlCreateHeap", kOffReturnZero}, // NULL
    {"ntdll.dll", "RtlDestroyHeap", kOffReturnZero},
    {"ntdll.dll", "RtlCompareMemory", kOffReturnZero},
    {"ntdll.dll", "RtlZeroMemory", kOffCritSecNop}, // void
    {"ntdll.dll", "RtlFillMemory", kOffCritSecNop},
    {"ntdll.dll", "RtlCopyMemory", kOffMemmove}, // real memcpy
    {"ntdll.dll", "RtlMoveMemory", kOffMemmove},
    {"ntdll.dll", "RtlEnterCriticalSection", kOffEnterCritSecReal},
    {"ntdll.dll", "RtlLeaveCriticalSection", kOffLeaveCritSecReal},
    {"ntdll.dll", "RtlInitializeCriticalSection", kOffInitCritSec},
    {"ntdll.dll", "RtlDeleteCriticalSection", kOffCritSecNop},
    {"ntdll.dll", "RtlTryEnterCriticalSection", kOffTryEnterCritSecReal},
    // kernel32 doesn't export TryEnterCriticalSection under that
    // exact name — programs hit it through the Rtl alias above or
    // via the (unstubbed) kernel32!TryEnterCriticalSection thunk.
    {"kernel32.dll", "TryEnterCriticalSection", kOffTryEnterCritSecReal},
    {"ntdll.dll", "LdrLoadDll", kOffReturnStatusNotImpl},
    {"ntdll.dll", "LdrGetDllHandle", kOffReturnStatusNotImpl},
    {"ntdll.dll", "LdrGetProcedureAddress", kOffReturnStatusNotImpl},
    {"ntdll.dll", "RtlRunOnceExecuteOnce", kOffReturnZero}, // S_OK

    // Win32 process heap, backed by the per-process
    // 16-page region at 0x50000000 and SYS_HEAP_ALLOC /
    // SYS_HEAP_FREE. See kernel/subsystems/win32/heap.cpp.
    //
    // kernel32 heap exports: take a HANDLE arg that v0
    // ignores — GetProcessHeap returns the same cookie
    // HeapAlloc ignores, so it's internally consistent.
    {"kernel32.dll", "GetProcessHeap", kOffGetProcessHeap},
    {"kernel32.dll", "HeapAlloc", kOffHeapAlloc},
    {"kernel32.dll", "HeapFree", kOffHeapFree},
    // HeapCreate: Win32 normally creates a private heap.
    // v0 collapses to the shared process heap — same handle
    // as GetProcessHeap. HeapDestroy is a no-op returning
    // TRUE (we never actually free the heap pages).
    {"kernel32.dll", "HeapCreate", kOffGetProcessHeap},
    {"kernel32.dll", "HeapDestroy", kOffReturnOne},
    // HeapReAlloc / HeapSize: backed by SYS_HEAP_REALLOC +
    // SYS_HEAP_SIZE as of — block header carries the
    // rounded-up size so we can translate both operations
    // without extra per-block bookkeeping.
    {"kernel32.dll", "HeapReAlloc", kOffHeapRealloc},
    {"kernel32.dll", "HeapSize", kOffHeapSize},

    // UCRT / msvcrt / apiset heap names — all forward to the
    // same syscall-backed stubs. realloc returns NULL; malloc
    // and free are straight-through.
    {"api-ms-win-crt-heap-l1-1-0.dll", "malloc", kOffMalloc},
    {"api-ms-win-crt-heap-l1-1-0.dll", "free", kOffFree},
    {"api-ms-win-crt-heap-l1-1-0.dll", "calloc", kOffCalloc},
    {"api-ms-win-crt-heap-l1-1-0.dll", "realloc", kOffRealloc},
    // _aligned_malloc / _aligned_free: v0 ignores alignment.
    // The allocator already returns 8-byte aligned pointers,
    // which covers most callers (16-byte alignment failure
    // will surface later if anything needs AVX/SSE locals
    // stored in a heap allocation).
    {"api-ms-win-crt-heap-l1-1-0.dll", "_aligned_malloc", kOffMalloc},
    {"api-ms-win-crt-heap-l1-1-0.dll", "_aligned_free", kOffFree},

    {"ucrtbase.dll", "malloc", kOffMalloc},
    {"ucrtbase.dll", "free", kOffFree},
    {"ucrtbase.dll", "calloc", kOffCalloc},
    {"ucrtbase.dll", "realloc", kOffRealloc},
    {"ucrtbase.dll", "_aligned_malloc", kOffMalloc},
    {"ucrtbase.dll", "_aligned_free", kOffFree},

    {"msvcrt.dll", "malloc", kOffMalloc},
    {"msvcrt.dll", "free", kOffFree},
    {"msvcrt.dll", "calloc", kOffCalloc},
    {"msvcrt.dll", "realloc", kOffRealloc},

    // advapi32 privilege/token + kernel32 event /
    // wait / system-time / process shims. Mostly "return
    // success and do nothing" since the kernel has no real
    // security model, no multi-threading in user land, and
    // no wall-clock yet. The exceptions are the two advapi32
    // token stubs that fill an out-param (see stub comments)
    // and the three kernel32 functions with real out-param
    // contracts (InitializeSListHead, GetSystemTimeAsFileTime,
    // GetExitCodeThread).

    // advapi32 — privilege/token dance. All BOOL-returning.
    {"advapi32.dll", "OpenProcessToken", kOffOpenProcessToken},
    {"advapi32.dll", "LookupPrivilegeValueW", kOffLookupPrivVal},
    // ASCII variant shares the same stub — v0 ignores the
    // name string entirely.
    {"advapi32.dll", "LookupPrivilegeValueA", kOffLookupPrivVal},
    {"advapi32.dll", "AdjustTokenPrivileges", kOffReturnOne},
    // Uppercase aliases — llvm-dlltool writes the DLL name
    // using the .def file's LIBRARY line verbatim, but some
    // linkers normalise to uppercase. Register both so
    // capitalisation in the PE's import table (either way)
    // hits the stub.
    {"ADVAPI32.dll", "OpenProcessToken", kOffOpenProcessToken},
    {"ADVAPI32.dll", "LookupPrivilegeValueW", kOffLookupPrivVal},
    {"ADVAPI32.dll", "LookupPrivilegeValueA", kOffLookupPrivVal},
    {"ADVAPI32.dll", "AdjustTokenPrivileges", kOffReturnOne},

    // kernel32 — event objects (v0: no real signalling, every
    // event is "always signaled"; CreateEventW returns a fake
    // non-null handle; SetEvent/ResetEvent return TRUE).
    // CreateEventW / SetEvent / ResetEvent now route to real
    // event infrastructure — moved to below.

    // kernel32 — wait (v0: immediate return with
    // WaitForSingleObject moved to below — now mutex-aware.
    // The stub still pseudo-signals (returns 0 = WAIT_OBJECT_0) for
    // non-mutex handles, preserving the original contract
    // for events / thread handles that v0 doesn't track.

    // kernel32 — interlocked SList (zero-init an SList head).
    {"kernel32.dll", "InitializeSListHead", kOffInitSListHead},

    // kernel32 — system time. Reads the CMOS RTC via
    // SYS_GETTIME_FT and writes the FILETIME into *rcx. The
    // old kOffGetSysTimeFT stub at 0x1DE (writes 0) remains
    // in the page as dead bytes — not worth restructuring the
    // layout to reclaim 8 bytes.
    {"kernel32.dll", "GetSystemTimeAsFileTime", kOffGetSysTimeFTReal},

    // kernel32 — process handles. OpenProcess returns the
    // PID as the handle (non-null iff PID != 0). Real
    // implementations would have a handle table; the handle
    // value is opaque to callers so this "identity"
    // mapping is fine.
    {"kernel32.dll", "OpenProcess", kOffOpenProcess},
    // real GetExitCodeThread backed by per-handle
    // exit_code storage updated at SYS_EXIT time.
    {"kernel32.dll", "GetExitCodeThread", kOffGetExitCodeThreadReal},
    {"kernel32.dll", "GenerateConsoleCtrlEvent", kOffReturnOne},

    // performance counters, tick count, and the
    // Rtl*/Toolhelp32/thread-management clusters. The perf
    // counter family is REAL — backed by SYS_PERF_COUNTER
    // and the kernel 100 Hz tick. The rest are safe no-ops
    // that let callers proceed without crashing:
    // * Rtl* unwind family returns 0 — "no function entry
    // found" / "no frames captured". Code that uses
    // these for crash-report formatting gets an empty
    // report but doesn't fault.
    // * Toolhelp32 snapshot returns 1 (non-null handle)
    // but Process32First returns FALSE — program sees
    // an empty process list.
    // * CreateRemoteThread returns 0 (NULL) — the target
    // program handles failure gracefully per the Win32
    // contract (GetLastError returns the last set
    // error; our stub stack doesn't populate that yet).
    // QueryPerformance{Counter,Frequency} upgraded to
    // HPET-backed nanosecond resolution. The old stubs at 0x1F6
    // / 0x206 stay in the page as dead bytes.
    {"kernel32.dll", "QueryPerformanceCounter", kOffQpcNs},
    {"kernel32.dll", "QueryPerformanceFrequency", kOffQpfNs},
    {"kernel32.dll", "GetTickCount", kOffGetTickCount},
    {"kernel32.dll", "GetTickCount64", kOffGetTickCount},

    // Sleep + SwitchToThread (timer + voluntary yield).
    // Sleep routes to SYS_SLEEP_MS; SwitchToThread routes to
    // SYS_YIELD. SleepEx ignores its bAlertable arg and aliases
    // to Sleep — no APC delivery in v0, so the alertable form
    // would never actually fire user-mode APCs anyway.
    {"kernel32.dll", "Sleep", kOffSleep},
    {"kernel32.dll", "SleepEx", kOffSleep},
    {"kernel32.dll", "SwitchToThread", kOffSwitchToThread},

    // command line + environment (proc-env page reads).
    // GetCommandLineW / GetCommandLineA hand back pointers into
    // the proc-env page populated by Win32ProcEnvPopulate at PE
    // load. GetEnvironmentVariableW returns 0 (var-not-found)
    // for every query in v0; that's a documented success-case
    // outcome of the Win32 contract and cleanly degrades for
    // any caller that has a default. GetEnvironmentStringsW
    // returns a pointer to an empty block (two NUL bytes).
    // FreeEnvironmentStringsW is a no-op returning TRUE.
    {"kernel32.dll", "GetCommandLineW", kOffGetCmdLineW},
    {"kernel32.dll", "GetCommandLineA", kOffGetCmdLineA},
    {"kernel32.dll", "GetEnvironmentVariableW", kOffReturnZero},
    {"kernel32.dll", "GetEnvironmentVariableA", kOffReturnZero},
    {"kernel32.dll", "GetEnvironmentStringsW", kOffGetEnvBlockW},
    {"kernel32.dll", "GetEnvironmentStrings", kOffGetEnvBlockW},
    {"kernel32.dll", "FreeEnvironmentStringsW", kOffReturnOne},
    {"kernel32.dll", "FreeEnvironmentStringsA", kOffReturnOne},
    {"kernel32.dll", "SetEnvironmentVariableW", kOffReturnOne}, // pretend success
    {"kernel32.dll", "SetEnvironmentVariableA", kOffReturnOne},

    // Rtl* unwind (v0: empty / not-found sentinels)
    {"kernel32.dll", "RtlCaptureStackBackTrace", kOffReturnZero},
    {"kernel32.dll", "RtlCaptureContext", kOffReturnZero},
    {"kernel32.dll", "RtlLookupFunctionEntry", kOffReturnZero},
    {"kernel32.dll", "RtlVirtualUnwind", kOffReturnZero},

    // Toolhelp32 + thread management (empty snapshot / no
    // ops). Real implementation requires the kernel to
    // expose the process table to ring 3 — deferred.
    {"kernel32.dll", "CreateToolhelp32Snapshot", kOffReturnOne},
    {"kernel32.dll", "Process32First", kOffReturnZero},
    {"kernel32.dll", "Process32FirstW", kOffReturnZero},
    {"kernel32.dll", "Process32Next", kOffReturnZero},
    {"kernel32.dll", "Process32NextW", kOffReturnZero},
    {"kernel32.dll", "CreateRemoteThread", kOffReturnZero},
    {"kernel32.dll", "ResumeThread", kOffReturnZero},
    {"kernel32.dll", "GetExitCodeProcess", kOffGetExitCodeThread},

    // dbghelp + vcruntime SEH + UCRT convert.
    // All aliases to existing stubs; no new bytecode.
    //
    // dbghelp: symbol-table code paths. Succeed-but-find-nothing
    // is the safe stub semantic for crash loggers that call
    // SymFromAddr — they'll print "address=0x???" instead of
    // "file:line", but never fault.
    {"dbghelp.dll", "SymInitialize", kOffReturnOne},
    {"dbghelp.dll", "SymCleanup", kOffReturnOne},
    {"dbghelp.dll", "SymFromAddr", kOffReturnZero},

    // vcruntime SEH / C++ ABI — any program that actually
    // throws or dispatches a pure-virtual call will hit these.
    // We route them to SYS_EXIT(3) so a crash is visible in
    // the log (rc=0x3) rather than a silent #PF. Non-terminal
    // ones return 0.
    {"vcruntime140.dll", "__CxxFrameHandler3", kOffTerminate},
    {"vcruntime140.dll", "__C_specific_handler", kOffTerminate},
    {"vcruntime140.dll", "_CxxThrowException", kOffTerminate},
    {"vcruntime140.dll", "_purecall", kOffTerminate},
    {"vcruntime140.dll", "__std_terminate", kOffTerminate},
    {"vcruntime140.dll", "__std_exception_copy", kOffReturnZero},
    {"vcruntime140.dll", "__std_exception_destroy", kOffReturnZero},
    // Same shape as InitCritSec: zero-init 40 bytes at [rcx].
    {"vcruntime140.dll", "__vcrt_InitializeCriticalSectionEx", kOffInitCritSec},

    // UCRT convert — return 0 for every parse. Callers that
    // check errno get the wrong answer (we don't wire errno)
    // but won't crash.
    {"api-ms-win-crt-convert-l1-1-0.dll", "strtoul", kOffReturnZero},
    {"api-ms-win-crt-convert-l1-1-0.dll", "strtol", kOffReturnZero},
    {"api-ms-win-crt-convert-l1-1-0.dll", "atoi", kOffReturnZero},
    {"api-ms-win-crt-convert-l1-1-0.dll", "atol", kOffReturnZero},
    {"ucrtbase.dll", "strtoul", kOffReturnZero},
    {"ucrtbase.dll", "strtol", kOffReturnZero},
    {"ucrtbase.dll", "atoi", kOffReturnZero},
    {"ucrtbase.dll", "atol", kOffReturnZero},
    {"msvcrt.dll", "strtoul", kOffReturnZero},
    {"msvcrt.dll", "strtol", kOffReturnZero},
    {"msvcrt.dll", "atoi", kOffReturnZero},
    {"msvcrt.dll", "atol", kOffReturnZero},

    // MSVCP140 throw helpers + small-return helpers.
    // All aliases. The `?_X*_error` + `?_Xbad_alloc`
    // family are unconditionally-throwing functions; under
    // Windows a caller wraps them in try/catch. We don't have
    // SEH, so reaching any of these is a crash by definition —
    // route to SYS_EXIT(3) so the serial log shows a
    // recognisable rc=3 instead of a #PF at some arbitrary
    // site.
    //
    // The `?_Winerror_*` + `?_Syserror_*` functions map Win32
    // error codes to human strings or category values; callers
    // format the result into log output. Returning 0 (or the
    // null string) is plausible "no translation available".
    //
    // `?uncaught_exception@std@@YA_NXZ` is std::uncaught_exception()
    // which returns bool — safe answer is false (no exception
    // currently in flight), i.e. kOffReturnZero.
    //
    // Not yet covered: the cout / basic_ostream cluster.
    // windows-kill.exe's next UNRESOLVED after these
    // helpers land will be in that group.
    {"MSVCP140.dll", "?_Xbad_alloc@std@@YAXXZ", kOffTerminate},
    {"MSVCP140.dll", "?_Xlength_error@std@@YAXPEBD@Z", kOffTerminate},
    {"MSVCP140.dll", "?_Xout_of_range@std@@YAXPEBD@Z", kOffTerminate},
    {"MSVCP140.dll", "?_Syserror_map@std@@YAPEBDH@Z", kOffReturnZero},
    {"MSVCP140.dll", "?_Winerror_map@std@@YAHH@Z", kOffReturnZero},
    {"MSVCP140.dll", "?_Winerror_message@std@@YAKKPEADK@Z", kOffReturnZero},
    {"MSVCP140.dll", "?uncaught_exception@std@@YA_NXZ", kOffReturnZero},

    // MSVC CRT argc / argv accessors. These are the
    // first real-valued reads the CRT's __scrt_common_main_seh
    // makes during startup: `argc = *__p___argc()` and
    // `argv = *__p___argv()`. Previously they landed on
    // the catch-all NO-OP stub, returned 0, and the CRT faulted
    // when it dereferenced the zero. Now they return pointers
    // into the per-process proc-env page (kProcEnvVa), which the
    // PE loader populates with argc=1 and argv=[program_name, NULL].
    //
    // Registered under every DLL the resolver might see the
    // import under — api-ms-win-crt-runtime is the modern apiset,
    // ucrtbase is where the code lives, msvcrt is the legacy
    // name.
    {"api-ms-win-crt-runtime-l1-1-0.dll", "__p___argc", kOffPArgc},
    {"api-ms-win-crt-runtime-l1-1-0.dll", "__p___argv", kOffPArgv},
    {"ucrtbase.dll", "__p___argc", kOffPArgc},
    {"ucrtbase.dll", "__p___argv", kOffPArgv},
    {"msvcrt.dll", "__p___argc", kOffPArgc},
    {"msvcrt.dll", "__p___argv", kOffPArgv},

    // UCRT stdio accessors. `__p__commode` returns
    // &_commode for callers that want the default-file-mode
    // flags (every UCRT-linked program reads it during startup
    // to pick text vs binary I/O). `_callnewh` is the C++
    // new-handler trampoline; v0 always "no handler set" so
    // the caller throws bad_alloc or returns failure — aliased
    // to the shared return-zero stub.
    {"api-ms-win-crt-stdio-l1-1-0.dll", "__p__commode", kOffPCommode},
    {"ucrtbase.dll", "__p__commode", kOffPCommode},
    {"msvcrt.dll", "__p__commode", kOffPCommode},
    {"api-ms-win-crt-heap-l1-1-0.dll", "_callnewh", kOffReturnZero},
    {"ucrtbase.dll", "_callnewh", kOffReturnZero},
    {"msvcrt.dll", "_callnewh", kOffReturnZero},

    // MSVCP140 iostream methods. Direct-call paths
    // (via IAT) now do the right thing; virtual-dispatch paths
    // still walk the fake-object data-miss pad. The mangled
    // names are the MSVC x64 form (`?method@class@@Q..Z`).
    //
    // sputn → real SYS_WRITE; writes chars to serial and
    // returns the count. Same for the `MSVCP140` and MSVCP110
    // variants (older CRT link paths).
    {"MSVCP140.dll", "?sputn@?$basic_streambuf@DU?$char_traits@D@std@@@std@@QEAA_JPEBD_J@Z", kOffSputn},
    {"msvcp140.dll", "?sputn@?$basic_streambuf@DU?$char_traits@D@std@@@std@@QEAA_JPEBD_J@Z", kOffSputn},

    // sputc → "can't usefully write one char without spilling
    // to stack" in a hand-assembled stub. Fall through to the
    // return-zero family for now; a PE that relies on sputc
    // (rare — operator<< for char goes through put()) will see
    // "0 chars written" and can degrade. Revisit if it matters.
    {"MSVCP140.dll", "?sputc@?$basic_streambuf@DU?$char_traits@D@std@@@std@@QEAAHD@Z", kOffReturnZero},

    // put → returns *this (chainable). Doesn't actually emit
    // the char in v0 — the call still does its real work if
    // the caller reads a buffer pointer off the return value
    // (nobody does).
    {"MSVCP140.dll", "?put@?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAAAEAV12@D@Z", kOffReturnThis},

    // flush → returns *this. No buffers to drain in v0.
    {"MSVCP140.dll", "?flush@?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAAAEAV12@XZ", kOffReturnThis},

    // _Osfx (sentry epilog) → void, no-op.
    {"MSVCP140.dll", "?_Osfx@?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAAXXZ", kOffCritSecNop},

    // setstate → void, no-op. (Silently drops the bits; any
    // code that inspects rdstate() later sees goodbit.)
    {"MSVCP140.dll", "?setstate@?$basic_ios@DU?$char_traits@D@std@@@std@@QEAAXH_N@Z", kOffCritSecNop},

    // widen → char identity.
    {"MSVCP140.dll", "?widen@?$basic_ios@DU?$char_traits@D@std@@@std@@QEBADD@Z", kOffWiden},

    // operator<<(int) / operator<<(unsigned long) /
    // operator<<(manipulator) — all three chain `*this` as
    // the return value. The int/ulong forms also conceptually
    // emit a formatted number; we don't format, but the
    // chaining return lets `cout << x << y << z` typecheck +
    // run past the first call site. Output is silent.
    {"MSVCP140.dll", "??6?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAAAEAV01@H@Z", kOffReturnThis},
    {"MSVCP140.dll", "??6?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAAAEAV01@K@Z", kOffReturnThis},
    {"MSVCP140.dll", "??6?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAAAEAV01@P6AAEAV01@AEAV01@@Z@Z",
     kOffReturnThis},

    // D3D / DXGI create-device family. Returning
    // HRESULT E_FAIL lets a caller's "no graphics" fallback
    // kick in. Covers the entry points DXVK / vkd3d-proton
    // intercept at the top of their translation chain:
    //
    // D3D11CreateDevice / D3D11CreateDeviceAndSwapChain
    // — MSVC d3d11.dll direct
    // D3D12CreateDevice
    // — MSVC d3d12.dll direct
    // CreateDXGIFactory / CreateDXGIFactory1 / CreateDXGIFactory2
    // — dxgi.dll, prerequisite for D3D device creation
    // Direct3DCreate9 / Direct3DCreate9Ex
    // — legacy d3d9.dll entry
    //
    // Direct3DCreate9 returns an IDirect3D9* — NULL on failure.
    // E_FAIL (0x80004005) in eax still lands as a non-NULL
    // pointer from the caller's perspective. For the pre-D3D10
    // path we use kOffReturnZero instead.
    // Route through SYS_GFX_D3D_STUB so the graphics ICD's
    // handle-table counters tick (visible via the `gfx` shell
    // command). Return value is still HRESULT E_FAIL.
    {"d3d11.dll", "D3D11CreateDevice", kOffD3d11CreateStub},
    {"d3d11.dll", "D3D11CreateDeviceAndSwapChain", kOffD3d11CreateStub},
    {"D3D11.dll", "D3D11CreateDevice", kOffD3d11CreateStub},
    {"D3D11.dll", "D3D11CreateDeviceAndSwapChain", kOffD3d11CreateStub},
    {"d3d12.dll", "D3D12CreateDevice", kOffD3d12CreateStub},
    {"d3d12.dll", "D3D12GetDebugInterface", kOffD3d12CreateStub},
    {"d3d12.dll", "D3D12SerializeRootSignature", kOffD3d12CreateStub},
    {"D3D12.dll", "D3D12CreateDevice", kOffD3d12CreateStub},
    {"dxgi.dll", "CreateDXGIFactory", kOffDxgiCreateStub},
    {"dxgi.dll", "CreateDXGIFactory1", kOffDxgiCreateStub},
    {"dxgi.dll", "CreateDXGIFactory2", kOffDxgiCreateStub},
    {"DXGI.dll", "CreateDXGIFactory", kOffDxgiCreateStub},
    {"DXGI.dll", "CreateDXGIFactory1", kOffDxgiCreateStub},
    {"DXGI.dll", "CreateDXGIFactory2", kOffDxgiCreateStub},
    // d3d9 predates HRESULT-first API — it returns an interface
    // pointer, NULL = failure. Alias to the shared return-zero
    // stub rather than E_FAIL.
    {"d3d9.dll", "Direct3DCreate9", kOffReturnZero},
    {"d3d9.dll", "Direct3DCreate9Ex", kOffHresultEFail},

    // -----------------------------------------------------------------
    // GUI pass-through: user32 + gdi32 + a handful of kernel32/winmm
    // gaps. Prior art: evmar/theseus pointed at these module groups
    // (kernel32::nls / user32::message / user32::window / user32::
    // resource / gdi32::{dc,bitmap,object}) as the surface you need
    // to cover to run a non-console Windows PE. Every entry below
    // aliases to one of the shared canned stubs — kOffReturnZero
    // (xor eax,eax; ret) or kOffReturnOne (mov eax, 1; ret) — so no
    // new stub bytes land; the file's static_assert on kThunksBytes
    // size stays valid.
    //
    // Semantics chosen per MSDN so a well-behaved PE sees "call
    // succeeded but nothing happened":
    // - CreateWindowExW -> non-zero (caller treats 0 as failure).
    // - GetMessageW -> 0 (signals WM_QUIT; main loop exits
    // cleanly instead of spinning forever).
    // - DefWindowProc* -> 0 (most messages ignore the return).
    // - GDI object/DC handles -> non-zero so SelectObject /
    // DeleteObject later don't hit ERROR_
    // INVALID_HANDLE paths.
    //
    // Pointer-output APIs that *populate a struct* (GetSystemTime,
    // GetLocalTime, SystemTimeToFileTime, etc.) need real stub
    // bytes — those are a follow-up; returning 0/1 alone would
    // leave a zero struct and the CRT often treats that as a
    // sentinel anyway.

    // kernel32: locale / code-page sanity probes.
    {"kernel32.dll", "IsValidLocale", kOffReturnOne},
    {"kernel32.dll", "GetCPInfo", kOffReturnOne},
    {"kernel32.dll", "GetCPInfoExA", kOffReturnOne},
    {"kernel32.dll", "GetCPInfoExW", kOffReturnOne},

    // winmm: multimedia-timer — fake a valid timer ID + silent kill.
    {"winmm.dll", "timeSetEvent", kOffReturnOne},
    {"winmm.dll", "timeKillEvent", kOffReturnZero},

    // user32: window class + window lifecycle.
    {"user32.dll", "RegisterClassA", kOffReturnOne},
    {"user32.dll", "RegisterClassW", kOffReturnOne},
    {"user32.dll", "RegisterClassExA", kOffReturnOne},
    {"user32.dll", "RegisterClassExW", kOffReturnOne},
    {"user32.dll", "UnregisterClassA", kOffReturnOne},
    {"user32.dll", "UnregisterClassW", kOffReturnOne},
    {"user32.dll", "CreateWindowExA", kOffReturnOne},
    {"user32.dll", "CreateWindowExW", kOffReturnOne},
    {"user32.dll", "DestroyWindow", kOffReturnOne},
    {"user32.dll", "DefWindowProcA", kOffReturnZero},
    {"user32.dll", "DefWindowProcW", kOffReturnZero},
    {"user32.dll", "CallWindowProcA", kOffReturnZero},
    {"user32.dll", "CallWindowProcW", kOffReturnZero},
    {"user32.dll", "ShowWindow", kOffReturnZero},
    {"user32.dll", "UpdateWindow", kOffWinUpdateWindow},
    {"user32.dll", "GetClientRect", kOffReturnOne},
    {"user32.dll", "GetWindowRect", kOffReturnOne},
    {"user32.dll", "MoveWindow", kOffReturnOne},
    {"user32.dll", "SetWindowPos", kOffReturnOne},
    {"user32.dll", "InvalidateRect", kOffWinInvalidateRect},
    {"user32.dll", "BeginPaint", kOffWinBeginPaint},
    {"user32.dll", "EndPaint", kOffWinEndPaint},
    {"user32.dll", "GetDC", kOffWinGetDC},
    {"user32.dll", "ReleaseDC", kOffWinReleaseDC},

    // user32: message loop. GetMessage returns 0 so the canonical
    // `while (GetMessage(...)) DispatchMessage(...)` loop sees
    // WM_QUIT on the first iteration and exits cleanly. PeekMessage
    // returns 0 (no message available) for the variant that spins.
    {"user32.dll", "GetMessageA", kOffGetMessageA},
    {"user32.dll", "GetMessageW", kOffGetMessageA},
    {"user32.dll", "PeekMessageA", kOffPeekMessageA},
    {"user32.dll", "PeekMessageW", kOffPeekMessageA},
    {"user32.dll", "DispatchMessageA", kOffDispatchMessageA},
    {"user32.dll", "DispatchMessageW", kOffDispatchMessageA},
    {"user32.dll", "TranslateMessage", kOffReturnZero},
    {"user32.dll", "TranslateAcceleratorA", kOffReturnZero},
    {"user32.dll", "TranslateAcceleratorW", kOffReturnZero},
    {"user32.dll", "PostMessageA", kOffReturnOne},
    {"user32.dll", "PostMessageW", kOffReturnOne},
    {"user32.dll", "SendMessageA", kOffReturnZero},
    {"user32.dll", "SendMessageW", kOffReturnZero},
    {"user32.dll", "PostQuitMessage", kOffReturnZero},
    {"user32.dll", "PostThreadMessageA", kOffReturnOne},
    {"user32.dll", "PostThreadMessageW", kOffReturnOne},

    // user32: resource loaders — fake non-zero HICON/HCURSOR/HBITMAP.
    {"user32.dll", "LoadIconA", kOffReturnOne},
    {"user32.dll", "LoadIconW", kOffReturnOne},
    {"user32.dll", "LoadCursorA", kOffReturnOne},
    {"user32.dll", "LoadCursorW", kOffReturnOne},
    {"user32.dll", "LoadImageA", kOffReturnOne},
    {"user32.dll", "LoadImageW", kOffReturnOne},
    {"user32.dll", "LoadBitmapA", kOffReturnOne},
    {"user32.dll", "LoadBitmapW", kOffReturnOne},
    {"user32.dll", "LoadMenuA", kOffReturnOne},
    {"user32.dll", "LoadMenuW", kOffReturnOne},
    {"user32.dll", "LoadAcceleratorsA", kOffReturnOne},
    {"user32.dll", "LoadAcceleratorsW", kOffReturnOne},
    {"user32.dll", "LoadStringA", kOffReturnZero},
    {"user32.dll", "LoadStringW", kOffReturnZero},

    // user32: cursor + caret + misc — most callers treat non-zero
    // as "ok, previous state returned".
    {"user32.dll", "SetCursor", kOffReturnZero},
    {"user32.dll", "ShowCursor", kOffReturnZero},
    {"user32.dll", "GetCursorPos", kOffReturnOne},
    {"user32.dll", "SetCursorPos", kOffReturnOne},
    {"user32.dll", "ClipCursor", kOffReturnOne},
    {"user32.dll", "GetSystemMetrics", kOffReturnZero},
    {"user32.dll", "MessageBoxA", kOffReturnOne},
    {"user32.dll", "MessageBoxW", kOffReturnOne},
    {"user32.dll", "MessageBoxExA", kOffReturnOne},
    {"user32.dll", "MessageBoxExW", kOffReturnOne},

    // gdi32: device contexts — DC-less entry points still return a
    // non-zero fake handle; CreateCompatibleDC / DeleteDC go through
    // the real GDI object table so memory DCs are real.
    {"gdi32.dll", "GetDC", kOffReturnOne},
    {"gdi32.dll", "GetWindowDC", kOffReturnOne},
    {"gdi32.dll", "ReleaseDC", kOffReturnOne},
    {"gdi32.dll", "CreateCompatibleDC", kOffGdiCreateCompatDC},
    {"gdi32.dll", "DeleteDC", kOffGdiDeleteDC},
    {"gdi32.dll", "SaveDC", kOffReturnOne},
    {"gdi32.dll", "RestoreDC", kOffReturnOne},

    // gdi32: object table — real handle registry. SelectObject
    // tracks the currently-selected HBITMAP per memory DC; stock
    // + solid brushes live in the brush registry.
    {"gdi32.dll", "SelectObject", kOffGdiSelectObject},
    {"gdi32.dll", "DeleteObject", kOffGdiDeleteObject},
    {"gdi32.dll", "GetStockObject", kOffGdiGetStockObject},
    {"gdi32.dll", "GetObjectA", kOffReturnOne},
    {"gdi32.dll", "GetObjectW", kOffReturnOne},

    // gdi32: bitmap + brush creation. CompatibleBitmap + SolidBrush
    // allocate real kernel state; the rest remain dummies until we
    // need them.
    {"gdi32.dll", "CreateBitmap", kOffReturnOne},
    {"gdi32.dll", "CreateCompatibleBitmap", kOffGdiCreateCompatBmp},
    {"gdi32.dll", "CreateDIBitmap", kOffReturnOne},
    {"gdi32.dll", "CreateDIBSection", kOffReturnOne},
    {"gdi32.dll", "CreateSolidBrush", kOffGdiCreateSolidBrush},
    {"gdi32.dll", "CreateBrushIndirect", kOffReturnOne},
    {"gdi32.dll", "CreatePen", kOffGdiCreatePen},
    {"gdi32.dll", "CreateFontA", kOffReturnOne},
    {"gdi32.dll", "CreateFontW", kOffReturnOne},
    {"gdi32.dll", "CreateFontIndirectA", kOffReturnOne},
    {"gdi32.dll", "CreateFontIndirectW", kOffReturnOne},

    // gdi32: drawing primitives — all boolean, return TRUE so the
    // caller's "draw succeeded" flag is set.
    {"gdi32.dll", "BitBlt", kOffGdiBitBltDC},
    {"gdi32.dll", "StretchBlt", kOffGdiStretchBltDC},
    {"gdi32.dll", "MoveToEx", kOffGdiMoveToEx},
    {"gdi32.dll", "LineTo", kOffGdiLineTo},
    // Rectangle / Ellipse now default to the filled variants (which
    // match Win32's fill-with-current-brush + outline-with-current-
    // pen semantics). The outline-only offsets stay around for
    // callers that want them explicitly.
    {"gdi32.dll", "Rectangle", kOffGdiRectangleFilled},
    {"gdi32.dll", "Ellipse", kOffGdiEllipseFilled},
    {"gdi32.dll", "SetPixel", kOffGdiSetPixel},
    {"gdi32.dll", "SetPixelV", kOffGdiSetPixel},
    {"gdi32.dll", "PatBlt", kOffGdiPatBlt},
    {"gdi32.dll", "Polygon", kOffReturnOne},
    {"gdi32.dll", "Polyline", kOffReturnOne},
    // FillRect is technically a user32 export (not gdi32) in real
    // Windows, but we honour whichever DLL a PE imports it from.
    {"gdi32.dll", "FillRect", kOffGdiFillRectUser},
    {"user32.dll", "FillRect", kOffGdiFillRectUser},
    {"gdi32.dll", "FrameRect", kOffReturnOne},
    {"gdi32.dll", "TextOutA", kOffGdiTextOutA},
    {"gdi32.dll", "TextOutW", kOffGdiTextOutW},
    {"gdi32.dll", "ExtTextOutA", kOffReturnOne},
    {"gdi32.dll", "ExtTextOutW", kOffReturnOne},
    {"gdi32.dll", "DrawTextA", kOffGdiDrawTextA},
    {"user32.dll", "DrawTextA", kOffGdiDrawTextA},
    {"gdi32.dll", "DrawTextW", kOffGdiDrawTextW},
    {"user32.dll", "DrawTextW", kOffGdiDrawTextW},
    {"gdi32.dll", "SetBkMode", kOffGdiSetBkMode},
    {"gdi32.dll", "SetBkColor", kOffGdiSetBkColor},
    {"gdi32.dll", "SetTextColor", kOffGdiSetTextColor},
    {"gdi32.dll", "SetMapMode", kOffReturnOne},
    {"gdi32.dll", "SetTextAlign", kOffReturnZero},

    // -----------------------------------------------------------------
    // Real stubs for pointer-output time APIs — the ones
    // deliberately skipped by the prior GUI bindings because a 0/1
    // return leaves their caller-allocated output struct
    // uninitialised. These bridge Win64 ABI -> int 0x80 with the
    // new SYS_GETTIME_ST / SYS_ST_TO_FT / SYS_FT_TO_ST syscalls
    // (40..42).
    // -----------------------------------------------------------------
    {"kernel32.dll", "GetSystemTime", kOffGetSystemTimeSt},
    {"kernel32.dll", "GetLocalTime", kOffGetSystemTimeSt},
    {"kernel32.dll", "SystemTimeToFileTime", kOffSystemTimeToFileTime},
    {"kernel32.dll", "FileTimeToSystemTime", kOffFileTimeToSystemTime},
