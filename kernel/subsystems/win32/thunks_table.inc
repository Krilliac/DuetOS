// console I/O
{"kernel32.dll", "ExitProcess", kOffExitProcess}, {"kernel32.dll", "GetStdHandle", kOffGetStdHandle},
    // WriteFile and WriteConsoleA share the same stub — both
    // take the same 5-arg shape and we ignore the handle +
    // trailing arg anyway. Aliasing keeps the stubs page
    // small and means any improvement (clamping, error
    // codes, real handle dispatch) lands in both at once.
    {"kernel32.dll", "WriteFile", kOffWriteFile}, {"kernel32.dll", "WriteConsoleA", kOffWriteFile},
    // process/thread lifecycle
    {"kernel32.dll", "GetCurrentProcess", kOffGetCurrentProcess},
    {"kernel32.dll", "GetCurrentThread", kOffGetCurrentThread},
    {"kernel32.dll", "GetCurrentProcessId", kOffGetCurrentProcessId},
    {"kernel32.dll", "GetCurrentThreadId", kOffGetCurrentThreadId},
    {"kernel32.dll", "TerminateProcess", kOffTerminateProcess},
    // last-error slot
    {"kernel32.dll", "GetLastError", kOffGetLastError}, {"kernel32.dll", "SetLastError", kOffSetLastError},
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
    {"kernel32.dll", "DeleteCriticalSection", kOffPinVoidNop},
    // vcruntime140 memory intrinsics
    {"vcruntime140.dll", "memmove", kOffMemmove},
    // memcpy is safe to alias to memmove — memmove is a strict
    // superset (handles overlap), same return value contract.
    {"vcruntime140.dll", "memcpy", kOffMemmove}, {"vcruntime140.dll", "memset", kOffMemset},

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
    // _initialize_onexit_table / _register_onexit_function /
    // _crt_atexit / _configure_narrow_argv: real implementations
    // backed by the per-process atexit table in proc_env.h
    // (kProcEnvAtexit*). _cexit walks the table LIFO.
    {"api-ms-win-crt-runtime-l1-1-0.dll", "_initialize_onexit_table", kOffInitOnexitTable},
    {"api-ms-win-crt-runtime-l1-1-0.dll", "_register_onexit_function", kOffRegisterOnexitFn},
    {"api-ms-win-crt-runtime-l1-1-0.dll", "_crt_atexit", kOffCrtAtexit},
    {"api-ms-win-crt-runtime-l1-1-0.dll", "_initterm_e", kOffInittermE},
    {"api-ms-win-crt-runtime-l1-1-0.dll", "_configure_narrow_argv", kOffConfigureNarrowArgv},
    {"api-ms-win-crt-runtime-l1-1-0.dll", "_initialize_narrow_environment", kOffNoNarrowEnv},
    {"api-ms-win-crt-runtime-l1-1-0.dll", "_get_initial_narrow_environment", kOffNoNarrowEnv},
    {"api-ms-win-crt-runtime-l1-1-0.dll", "_seh_filter_exe", kOffSehFilterExe},
    {"api-ms-win-crt-runtime-l1-1-0.dll", "_register_thread_local_exe_atexit_callback", kOffRegThreadLocalAtexit},
    {"api-ms-win-crt-locale-l1-1-0.dll", "_configthreadlocale", kOffConfigthreadlocale},
    {"api-ms-win-crt-heap-l1-1-0.dll", "_set_new_mode", kOffSetNewMode},
    {"api-ms-win-crt-stdio-l1-1-0.dll", "_set_fmode", kOffSetFmode},

    // Return-void family.
    // _cexit / _c_exit: route through the proc-env atexit walker
    // (kOffCexit) — runs every handler registered via _crt_atexit
    // / _register_onexit_function in LIFO order. _set_app_type
    // stores its arg into the proc-env app_type slot so a later
    // _get_app_type would observe the program-asserted value.
    {"api-ms-win-crt-runtime-l1-1-0.dll", "_initterm", kOffInitterm},
    {"api-ms-win-crt-runtime-l1-1-0.dll", "_cexit", kOffCexit},
    {"api-ms-win-crt-runtime-l1-1-0.dll", "_c_exit", kOffCexit},
    {"api-ms-win-crt-runtime-l1-1-0.dll", "_set_app_type", kOffSetAppType},
    {"api-ms-win-crt-math-l1-1-0.dll", "__setusermatherr", kOffSetUsermatherr},

    // Exit family — `exit` and `_exit` alias ExitProcess
    // (same rcx=code ABI, same SYS_EXIT semantic).
    {"api-ms-win-crt-runtime-l1-1-0.dll", "exit", kOffExitProcess},
    {"api-ms-win-crt-runtime-l1-1-0.dll", "_exit", kOffExitProcess},
    {"api-ms-win-crt-runtime-l1-1-0.dll", "terminate", kOffTerminate},
    {"api-ms-win-crt-runtime-l1-1-0.dll", "_invalid_parameter_noinfo_noreturn", kOffInvalidParam},
    // Same functions surface directly under ucrtbase too.
    {"ucrtbase.dll", "exit", kOffExitProcess}, {"ucrtbase.dll", "_exit", kOffExitProcess},
    {"ucrtbase.dll", "terminate", kOffTerminate},

    // CRT string intrinsics. Pure functions; no
    // kernel state, no ABI surprises. Register under the
    // apiset + ucrtbase + msvcrt names to cover all three
    // common link paths.
    {"api-ms-win-crt-string-l1-1-0.dll", "strcmp", kOffStrcmp},
    {"api-ms-win-crt-string-l1-1-0.dll", "strlen", kOffStrlen},
    {"api-ms-win-crt-string-l1-1-0.dll", "wcslen", kOffWcslen},
    {"api-ms-win-crt-string-l1-1-0.dll", "strchr", kOffStrchr},
    {"api-ms-win-crt-string-l1-1-0.dll", "strcpy", kOffStrcpy}, {"ucrtbase.dll", "strcmp", kOffStrcmp},
    {"ucrtbase.dll", "strlen", kOffStrlen}, {"ucrtbase.dll", "wcslen", kOffWcslen},
    {"ucrtbase.dll", "strchr", kOffStrchr}, {"ucrtbase.dll", "strcpy", kOffStrcpy},
    {"msvcrt.dll", "strcmp", kOffStrcmp}, {"msvcrt.dll", "strlen", kOffStrlen}, {"msvcrt.dll", "wcslen", kOffWcslen},
    {"msvcrt.dll", "strchr", kOffStrchr}, {"msvcrt.dll", "strcpy", kOffStrcpy},

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
    {"kernel32.dll", "IsDebuggerPresent", kOffPinReturn0}, {"kernel32.dll", "IsDebuggerPresent", kOffPinReturn0},
    // IsProcessorFeaturePresent(dwFeature) → claim every queried
    // feature is present. x86_64 universally has SSE / SSE2 / CMPXCHG16B
    // / NX; AES / PCLMUL / AVX / AVX2 / RDRAND / RDSEED are visible in
    // this kernel's CPU probe log. Returning 0 forced every caller
    // onto scalar fallback paths; returning 1 optimistically matches
    // modern hardware. Genuinely-absent feature callers almost always
    // have a runtime fallback anyway.
    {"kernel32.dll", "IsProcessorFeaturePresent", kOffPinReturn1},
    {"kernel32.dll", "SetUnhandledExceptionFilter", kOffSetUnhandledFilter},
    {"kernel32.dll", "UnhandledExceptionFilter", kOffUnhandledFilter},

    // Return-one family (returns TRUE / 1 = success):
    // SetConsoleCtrlHandler — pretend we registered.
    {"kernel32.dll", "SetConsoleCtrlHandler", kOffPinReturn1},

    // file I/O. Real handle table on Process,
    // backed by SYS_FILE_OPEN / SYS_FILE_READ / SYS_FILE_CLOSE
    // / SYS_FILE_SEEK. CloseHandle is the file-close path —
    // also harmlessly handles non-file handles (the kernel
    // SYS_FILE_CLOSE returns 0 for an unrecognised handle).
    {"kernel32.dll", "CreateFileW", kOffCreateFileW}, {"kernel32.dll", "ReadFile", kOffReadFile},
    {"kernel32.dll", "CloseHandle", kOffCloseHandle}, {"kernel32.dll", "SetFilePointerEx", kOffSetFilePtrEx},

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
    {"kernel32.dll", "GetModuleHandleExW", kOffPinReturn0}, {"kernel32.dll", "GetModuleHandleExA", kOffPinReturn0},
    {"kernel32.dll", "LoadLibraryW", kOffPinReturn0}, {"kernel32.dll", "LoadLibraryA", kOffPinReturn0},
    {"kernel32.dll", "LoadLibraryExW", kOffPinReturn0}, {"kernel32.dll", "LoadLibraryExA", kOffPinReturn0},
    {"kernel32.dll", "FreeLibrary", kOffPinReturn1}, // pretend success
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
    {"kernel32.dll", "CreateMutexW", kOffCreateMutexW}, {"kernel32.dll", "CreateMutexA", kOffCreateMutexW},
    {"kernel32.dll", "CreateMutexExW", kOffCreateMutexW},     // ignores extra Ex args
    {"kernel32.dll", "WaitForSingleObject", kOffWaitForObj4}, // upgrade
    {"kernel32.dll", "WaitForSingleObjectEx", kOffWaitForObj4}, {"kernel32.dll", "ReleaseMutex", kOffReleaseMutex},

    // Real event handles. Replaces the kOffReturnOne
    // no-op CreateEventW / SetEvent / ResetEvent from the
    // earlier kernel32 binding.
    // Per-process event table at 0x300..0x307.
    {"kernel32.dll", "CreateEventW", kOffCreateEventReal}, {"kernel32.dll", "CreateEventA", kOffCreateEventReal},
    {"kernel32.dll", "CreateEventExW", kOffCreateEventReal}, // ignores extra Ex args
    {"kernel32.dll", "CreateEventExA", kOffCreateEventReal}, {"kernel32.dll", "SetEvent", kOffSetEventReal},
    {"kernel32.dll", "ResetEvent", kOffResetEventReal},

    // real TLS. Replaces 's alias-to-
    // TLS_OUT_OF_INDEXES TlsAlloc. Per-process 64-slot table.
    // Fls* aliases to the same storage (v0 has no fibers).
    {"kernel32.dll", "TlsAlloc", kOffTlsAllocReal}, {"kernel32.dll", "TlsFree", kOffTlsFreeReal},
    {"kernel32.dll", "TlsGetValue", kOffTlsGetValueReal}, {"kernel32.dll", "TlsSetValue", kOffTlsSetValueReal},
    {"kernel32.dll", "FlsAlloc", kOffTlsAllocReal}, {"kernel32.dll", "FlsFree", kOffTlsFreeReal},
    {"kernel32.dll", "FlsGetValue", kOffTlsGetValueReal}, {"kernel32.dll", "FlsSetValue", kOffTlsSetValueReal},

    // console APIs. WriteConsoleW is the major
    // Unicode-output entry point; the stub UTF-16-strips to
    // ASCII on a stack buffer and routes through SYS_WRITE
    // (same path as WriteFile-to-stdout). GetConsoleMode /
    // GetConsoleCP / GetConsoleOutputCP hand back plausible
    // constants (VT processing enabled, UTF-8 code page). The
    // Set* counterparts are no-ops that return TRUE.
    {"kernel32.dll", "WriteConsoleW", kOffWriteConsoleW}, {"kernel32.dll", "GetConsoleMode", kOffGetConsoleMode},
    {"kernel32.dll", "SetConsoleMode", kOffPinReturn1}, {"kernel32.dll", "GetConsoleCP", kOffGetConsoleCP},
    {"kernel32.dll", "GetConsoleOutputCP", kOffGetConsoleCP}, {"kernel32.dll", "SetConsoleCP", kOffPinReturn1},
    {"kernel32.dll", "SetConsoleOutputCP", kOffPinReturn1},
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
    {"kernel32.dll", "VirtualFree", kOffVirtualFree}, {"kernel32.dll", "VirtualFreeEx", kOffVirtualFree},
    {"kernel32.dll", "VirtualProtect", kOffVirtualProtect}, {"kernel32.dll", "VirtualProtectEx", kOffVirtualProtect},
    {"kernel32.dll", "VirtualQuery", kOffPinReturn0}, // v0 query returns 0 = failed
    {"kernel32.dll", "VirtualQueryEx", kOffPinReturn0},

    // wide-string helpers. Pure-compute primitives
    // heavily used by multilingual PEs and MSVC CRT. lstrcmpW
    // is ordinal compare (no locale fold — lstrcmpiW would
    // case-fold, not stubbed). lstrlen has a hard cap of
    // effectively "until NUL" — a wild unterminated string
    // scans forever, matching the documented Win32 behaviour.
    {"kernel32.dll", "lstrlenW", kOffLstrlenW}, {"kernel32.dll", "lstrcmpW", kOffLstrcmpW},
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
    {"kernel32.dll", "lstrlenA", kOffLstrlenA}, {"kernel32.dll", "lstrcmpA", kOffLstrcmpA},
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
    {"kernel32.dll", "SetCurrentDirectoryW", kOffPinReturn1}, // pretend success
    {"kernel32.dll", "SetCurrentDirectoryA", kOffPinReturn1},

    // encoding converters. v0 handles ASCII-range
    // content perfectly (byte-extend / byte-truncate); non-ASCII
    // UTF-8 sequences lose high-plane data.
    {"kernel32.dll", "MultiByteToWideChar", kOffMBtoWC}, {"kernel32.dll", "WideCharToMultiByte", kOffWCtoMB},

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
    {"kernel32.dll", "GetTempPathA", kOffGetCurrentDirW}, {"kernel32.dll", "GetWindowsDirectoryW", kOffGetWinDirW},
    {"kernel32.dll", "GetWindowsDirectoryA", kOffGetWinDirW}, {"kernel32.dll", "GetSystemDirectoryW", kOffGetWinDirW},
    {"kernel32.dll", "GetSystemDirectoryA", kOffGetWinDirW},
    {"kernel32.dll", "GetSystemWindowsDirectoryW", kOffGetWinDirW},
    {"kernel32.dll", "GetSystemWindowsDirectoryA", kOffGetWinDirW},

    // drives, error modes, format messages.
    // GetLogicalDrives returns bit 23 set (only X: mounted).
    // GetDriveType* returns 3 (DRIVE_FIXED) for any input.
    // SetErrorMode / GetErrorMode return 0 (no special mode).
    // FormatMessage{W,A} returns 0 — callers usually fall
    // back to their own format-by-code path.
    {"kernel32.dll", "GetLogicalDrives", kOffGetLogicalDrives}, {"kernel32.dll", "GetDriveTypeW", kOffGetDriveType},
    {"kernel32.dll", "GetDriveTypeA", kOffGetDriveType}, {"kernel32.dll", "SetErrorMode", kOffPinReturn0},
    {"kernel32.dll", "GetErrorMode", kOffPinReturn0},
    {"kernel32.dll", "SetThreadErrorMode", kOffPinReturn1}, // return TRUE, ignore mode
    // FormatMessageW stays NO-OP: our v0 stub writes ASCII bytes
    // which would corrupt a WCHAR* buffer. A proper UTF-16 variant
    // is a follow-up.
    {"kernel32.dll", "FormatMessageW", kOffPinReturn0}, {"kernel32.dll", "FormatMessageA", kOffFormatMessageA},

    // registry + file-attribute no-op stubs.
    // Reg open / read family returns ERROR_FILE_NOT_FOUND (2),
    // the standard "key doesn't exist" status.
    // Reg write / close family returns ERROR_SUCCESS (0).
    // GetFileAttributesW returns INVALID_FILE_ATTRIBUTES (-1)
    // — caller treats as "file not present".
    // SetFileAttributesW returns TRUE (pretend success).
    {"advapi32.dll", "RegOpenKeyW", kOffReturnTwo}, {"advapi32.dll", "RegOpenKeyA", kOffReturnTwo},
    {"advapi32.dll", "RegOpenKeyExW", kOffReturnTwo}, {"advapi32.dll", "RegOpenKeyExA", kOffReturnTwo},
    {"advapi32.dll", "RegQueryValueW", kOffReturnTwo}, {"advapi32.dll", "RegQueryValueA", kOffReturnTwo},
    {"advapi32.dll", "RegQueryValueExW", kOffReturnTwo}, {"advapi32.dll", "RegQueryValueExA", kOffReturnTwo},
    {"advapi32.dll", "RegEnumKeyW", kOffReturnTwo}, {"advapi32.dll", "RegEnumKeyExW", kOffReturnTwo},
    {"advapi32.dll", "RegEnumValueW", kOffReturnTwo},
    // Reg write family: pin ERROR_SUCCESS (0) — userland advapi32
    // has the real registry-write path; this fallback returns 0
    // (= ERROR_SUCCESS) so callers see "write accepted" if the
    // DLL preload was skipped.
    {"advapi32.dll", "RegCreateKeyW", kOffPinReturn0}, // pretend success
    {"advapi32.dll", "RegCreateKeyExW", kOffPinReturn0}, {"advapi32.dll", "RegSetValueW", kOffPinReturn0},
    {"advapi32.dll", "RegSetValueExW", kOffPinReturn0}, {"advapi32.dll", "RegCloseKey", kOffPinReturn0},
    {"advapi32.dll", "RegDeleteKeyW", kOffPinReturn0}, {"advapi32.dll", "RegDeleteValueW", kOffPinReturn0},
    {"kernel32.dll", "GetFileAttributesW", kOffReturnMinus1}, {"kernel32.dll", "GetFileAttributesA", kOffReturnMinus1},
    {"kernel32.dll", "GetFileAttributesExW", kOffPinReturn0}, // BOOL FALSE = "file not found"
    {"kernel32.dll", "SetFileAttributesW", kOffPinReturn1},   // pretend success
    {"kernel32.dll", "SetFileAttributesA", kOffPinReturn1},
    // Destructive FS ops: pin TRUE — userland kernel32.dll
    // (Delete/Copy/Move/Create/RemoveDirectory) provides the real
    // implementations when the DLL preload succeeds. The thunk
    // fallback here returns success so a PE whose DLL preload was
    // skipped still completes startup without spurious failure.
    {"kernel32.dll", "DeleteFileW", kOffPinReturn1}, // pretend success
    {"kernel32.dll", "DeleteFileA", kOffPinReturn1}, {"kernel32.dll", "CopyFileW", kOffPinReturn1},
    {"kernel32.dll", "MoveFileW", kOffPinReturn1}, {"kernel32.dll", "CreateDirectoryW", kOffPinReturn1},
    {"kernel32.dll", "RemoveDirectoryW", kOffPinReturn1},

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
    {"kernel32.dll", "GetACP", kOffGetConsoleCP}, {"kernel32.dll", "GetOEMCP", kOffGetConsoleCP},
    {"kernel32.dll", "IsValidCodePage", kOffPinReturn1},
    // LCID / LANGID defaults: pin to 0x0409 (en-US). The earlier
    // binding to kOffReturnZero returned 0, which is not a valid
    // LCID — CRT locale-init that runs `if (lcid == 0) abort()`
    // tripped on it. 0x0409 matches what the userland kernel32
    // GetUserDefaultLCID export returns when the DLL preload
    // succeeds, so behaviour is identical via either path.
    {"kernel32.dll", "GetThreadLocale", kOffPinLcidEnUs}, {"kernel32.dll", "SetThreadLocale", kOffPinReturn1},
    {"kernel32.dll", "GetUserDefaultLCID", kOffPinLcidEnUs}, {"kernel32.dll", "GetSystemDefaultLCID", kOffPinLcidEnUs},
    {"kernel32.dll", "GetUserDefaultUILanguage", kOffPinLcidEnUs},
    {"kernel32.dll", "GetSystemDefaultUILanguage", kOffPinLcidEnUs},
    {"kernel32.dll", "GetTimeZoneInformation", kOffPinReturn1},
    {"kernel32.dll", "GetDynamicTimeZoneInformation", kOffPinReturn1},
    // GetCurrentProcessorNumber: pin 0 — DuetOS user code always
    // observes a single logical CPU from ring 3 in v0 (no
    // user-visible SMP API surface yet).
    {"kernel32.dll", "GetCurrentProcessorNumber", kOffPinReturn0},
    // GetProcessTimes / GetThreadTimes → zero-fill stubs.
    {"kernel32.dll", "GetProcessTimes", kOffGetProcessTimes},
    {"kernel32.dll", "GetThreadTimes", kOffGetProcessTimes}, // same shape
    // GetStartupInfo{W,A} now zero-fill the caller's
    // 104-byte STARTUPINFO and set cb = 104 (the nop previously
    // here left the buffer uninitialised — callers read a wild
    // pointer from lpDesktop / hStdInput and faulted).
    {"kernel32.dll", "GetStartupInfoW", kOffGetStartupInfo}, {"kernel32.dll", "GetStartupInfoA", kOffGetStartupInfo},
    {"kernel32.dll", "VerSetConditionMask", kOffPinReturn0}, {"kernel32.dll", "VerifyVersionInfoW", kOffPinReturn1},
    {"kernel32.dll", "VerifyVersionInfoA", kOffPinReturn1},
    // Paired with 's InitializeSListHead — more InterlockedX
    // SList ops all no-op (return NULL = empty list).
    {"kernel32.dll", "InterlockedPushEntrySList", kOffPinReturn0},
    {"kernel32.dll", "InterlockedPopEntrySList", kOffPinReturn0},
    {"kernel32.dll", "InterlockedFlushSList", kOffPinReturn0}, {"kernel32.dll", "QueryDepthSList", kOffPinReturn0},
    // Misc memory / CPU / numa probes.
    // GlobalMemoryStatusEx → real SYS_MEM_STATUS;
    // GetSystemTimes → zero-fill stub.
    {"kernel32.dll", "GlobalMemoryStatusEx", kOffGlobalMemoryStatusEx},
    {"kernel32.dll", "GetSystemTimes", kOffGetSystemTimes},
    // GetSystemInfo / GetNativeSystemInfo populate a
    // Win32 SYSTEM_INFO struct with x86_64 constants.
    {"kernel32.dll", "GetSystemInfo", kOffGetSystemInfo}, {"kernel32.dll", "GetNativeSystemInfo", kOffGetSystemInfo},
    {"kernel32.dll", "GetNumaHighestNodeNumber", kOffPinReturn0},

    // process priority / TLS / file-type aliases.
    // TlsAlloc returning TLS_OUT_OF_INDEXES (0xFFFFFFFF) is a
    // supported "no slots available" signal — forces the MSVC
    // CRT into its single-threaded fallback path instead of
    // panicking. TlsGetValue/SetValue/Free still return sane
    // values so callers holding stale slot indices don't
    // fault.
    {"kernel32.dll", "GetPriorityClass", kOffReturnPrioNormal}, // 0x20 = NORMAL
    {"kernel32.dll", "SetPriorityClass", kOffPinReturn1},
    // GetThreadPriority returning 0 IS correct — THREAD_PRIORITY_NORMAL is 0.
    // Pin the offset to make the audit accurate.
    {"kernel32.dll", "GetThreadPriority", kOffPinReturn0}, // 0 = NORMAL
    {"kernel32.dll", "SetThreadPriority", kOffPinReturn1},
    {"kernel32.dll", "CreateThread", kOffCreateThreadReal},        // real spawn via SYS_THREAD_CREATE
    {"kernel32.dll", "CreateRemoteThread", kOffNoCrossProcThread}, // fallback stays (no cross-proc v0)
    // ExitThread routes to SYS_EXIT (kills just this
    // task). FreeLibraryAndExitThread aliases to ExitThread — the
    // FreeLibrary half is a no-op in v0 (no DLL unload path).
    {"kernel32.dll", "ExitThread", kOffExitThread}, {"kernel32.dll", "FreeLibraryAndExitThread", kOffExitThread},
    // WaitForMultipleObjects via SYS_WAIT_MULTI.
    {"kernel32.dll", "WaitForMultipleObjects", kOffWaitForMultipleObjects},
    {"kernel32.dll", "WaitForMultipleObjectsEx", kOffWaitForMultipleObjects},
    // RaiseException → SYS_EXIT. DecodePointer /
    // EncodePointer → identity (round-trip preserved).
    {"kernel32.dll", "RaiseException", kOffRaiseException}, {"kernel32.dll", "DecodePointer", kOffDecodePointer},
    {"kernel32.dll", "EncodePointer", kOffDecodePointer}, {"kernel32.dll", "RtlDecodePointer", kOffDecodePointer},
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
    {"kernel32.dll", "InitializeSRWLock", kOffSrwInit}, {"kernel32.dll", "AcquireSRWLockExclusive", kOffSrwAcquireExcl},
    // Shared variants degrade to exclusive acquire in v0 — we
    // don't track reader counts yet, so letting concurrent
    // readers through would violate the reader/writer barrier
    // against an exclusive holder. Correctness > throughput.
    {"kernel32.dll", "AcquireSRWLockShared", kOffSrwAcquireExcl},
    {"kernel32.dll", "ReleaseSRWLockExclusive", kOffSrwReleaseExcl},
    {"kernel32.dll", "ReleaseSRWLockShared", kOffSrwReleaseExcl},
    {"kernel32.dll", "TryAcquireSRWLockExclusive", kOffSrwTryAcquireExcl},
    {"kernel32.dll", "TryAcquireSRWLockShared", kOffSrwTryAcquireExcl},
    // Condition variables: pin void / TRUE — v0 has no waiter
    // queue, but the user-visible contract (init/wake are void,
    // SleepCV returns TRUE = "woke up") is preserved.
    {"kernel32.dll", "InitializeConditionVariable", kOffPinVoidNop},
    {"kernel32.dll", "WakeConditionVariable", kOffPinVoidNop},
    {"kernel32.dll", "WakeAllConditionVariable", kOffPinVoidNop},
    {"kernel32.dll", "SleepConditionVariableCS", kOffPinReturn1},
    {"kernel32.dll", "SleepConditionVariableSRW", kOffPinReturn1},
    // InitOnceInitialize zeroes the 8-byte INIT_ONCE slot. Same
    // byte sequence as InitializeSRWLock, so share the stub.
    {"kernel32.dll", "InitOnceInitialize", kOffSrwInit}, {"kernel32.dll", "InitializeInitOnce", kOffPinVoidNop},
    {"kernel32.dll", "InitOnceComplete", kOffPinReturn1}, {"kernel32.dll", "InitOnceExecuteOnce", kOffInitOnceExec},
    {"kernel32.dll", "InitOnceBeginInitialize", kOffPinReturn1},
    // Waitable timer fallback rows: pin 0. The real implementations
    // live in the userland kernel32.dll's CreateWaitableTimer{W,A} /
    // SetWaitableTimer / CancelWaitableTimer exports (T11-04). The
    // fallback bytecode here returns 0 (= "no handle / set failed")
    // so a PE whose DLL preload was skipped sees a documented
    // failure rather than incorrectly succeeding.
    {"kernel32.dll", "CreateWaitableTimerW", kOffPinReturn0}, {"kernel32.dll", "CreateWaitableTimerA", kOffPinReturn0},
    {"kernel32.dll", "CreateWaitableTimerExW", kOffPinReturn0}, {"kernel32.dll", "SetWaitableTimer", kOffPinReturn0},
    {"kernel32.dll", "SetWaitableTimerEx", kOffPinReturn0}, {"kernel32.dll", "CancelWaitableTimer", kOffPinReturn0},
    // File mapping: pin 0 — no SECTION objects in v0; callers
    // typically fall back to non-mapped I/O on NULL.
    {"kernel32.dll", "CreateFileMappingW", kOffPinReturn0}, {"kernel32.dll", "CreateFileMappingA", kOffPinReturn0},
    {"kernel32.dll", "OpenFileMappingW", kOffPinReturn0}, {"kernel32.dll", "OpenFileMappingA", kOffPinReturn0},
    // OpenThread / GetThreadId / DuplicateHandle: pin 0 — no
    // cross-thread handle table in the v0 thunks; userland kernel32
    // implements GetThreadId on top of the current-thread syscall.
    {"kernel32.dll", "OpenThread", kOffPinReturn0}, {"kernel32.dll", "GetThreadId", kOffPinReturn0},
    {"kernel32.dll", "DuplicateHandle", kOffPinReturn0},
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
    // File locking + async-I/O cancel: pin TRUE — v0 has no
    // concurrent writers and no overlapped-I/O backlog, so "success
    // without taking a lock / nothing to cancel" is faithful.
    {"kernel32.dll", "LockFile", kOffPinReturn1}, {"kernel32.dll", "LockFileEx", kOffPinReturn1},
    {"kernel32.dll", "UnlockFile", kOffPinReturn1}, {"kernel32.dll", "UnlockFileEx", kOffPinReturn1},
    {"kernel32.dll", "CancelIo", kOffPinReturn1}, {"kernel32.dll", "CancelIoEx", kOffPinReturn1},
    {"kernel32.dll", "CancelSynchronousIo", kOffPinReturn1}, {"kernel32.dll", "GetOverlappedResult", kOffPinReturn1},
    {"kernel32.dll", "GetOverlappedResultEx", kOffPinReturn1},
    // Thread/process scheduling knobs: pin TRUE — v0 accepts the
    // request but the scheduler observes its own policy.
    {"kernel32.dll", "SetThreadAffinityMask", kOffPinReturn1},
    {"kernel32.dll", "SetProcessAffinityMask", kOffPinReturn1},
    {"kernel32.dll", "SetThreadIdealProcessor", kOffPinReturn0}, // prev ideal = 0
    {"kernel32.dll", "GetThreadIdealProcessorEx", kOffPinReturn1},
    {"kernel32.dll", "DisableThreadLibraryCalls", kOffPinReturn1},
    // Fiber API: pin 0 / void — no fiber scheduler in v0. Create*
    // returning NULL forces callers onto thread fallback; the
    // Switch/Delete leg is genuinely void.
    {"kernel32.dll", "CreateFiber", kOffPinFiberZero}, {"kernel32.dll", "CreateFiberEx", kOffPinFiberZero},
    {"kernel32.dll", "ConvertThreadToFiber", kOffPinFiberZero},
    {"kernel32.dll", "ConvertThreadToFiberEx", kOffPinFiberZero},
    {"kernel32.dll", "ConvertFiberToThread", kOffPinReturn1},
    {"kernel32.dll", "SwitchToFiber", kOffPinFiberVoid}, // void
    {"kernel32.dll", "DeleteFiber", kOffPinFiberVoid},   // void
    {"kernel32.dll", "IsThreadAFiber", kOffPinFiberZero},
    {"kernel32.dll", "DebugBreak", kOffPinVoidNop}, // void — no int3 (would kill us)
    {"kernel32.dll", "DebugActiveProcess", kOffPinReturn0}, {"kernel32.dll", "DebugActiveProcessStop", kOffPinReturn0},
    // GetSystemTimePreciseAsFileTime has the same shape as
    // GetSystemTimeAsFileTime — reuse the existing real stub.
    {"kernel32.dll", "GetSystemTimePreciseAsFileTime", kOffGetSysTimeFTReal},
    // Named pipes: unsupported — all return FALSE / NULL / invalid.
    {"kernel32.dll", "CreateNamedPipeW", kOffReturnMinus1}, // INVALID_HANDLE_VALUE
    {"kernel32.dll", "CreateNamedPipeA", kOffReturnMinus1}, {"kernel32.dll", "ConnectNamedPipe", kOffPinReturn0},
    {"kernel32.dll", "DisconnectNamedPipe", kOffPinReturn1}, {"kernel32.dll", "WaitNamedPipeW", kOffPinReturn0},
    {"kernel32.dll", "WaitNamedPipeA", kOffPinReturn0}, {"kernel32.dll", "PeekConsoleInputW", kOffPinReturn0},
    {"kernel32.dll", "GetLogicalProcessorInformation", kOffPinReturn0},
    {"kernel32.dll", "GetLogicalProcessorInformationEx", kOffPinReturn0},
    {"kernel32.dll", "GetSystemFirmwareTable", kOffPinReturn0}, // 0 = size unavailable
    {"kernel32.dll", "EnumSystemFirmwareTables", kOffPinReturn0},
    {"kernel32.dll", "RegisterApplicationRestart", kOffPinReturn0}, // S_OK
    {"kernel32.dll", "UnregisterApplicationRestart", kOffPinReturn0},
    {"kernel32.dll", "SetSearchPathMode", kOffPinReturn1}, {"kernel32.dll", "SetDefaultDllDirectories", kOffPinReturn1},
    {"kernel32.dll", "AddDllDirectory", kOffPinReturn0}, // NULL cookie
    {"kernel32.dll", "RemoveDllDirectory", kOffPinReturn1},
    // Tls/Fls now route through real per-process storage —
    // moved to below.
    {"kernel32.dll", "SetEndOfFile", kOffPinReturn1},
    {"kernel32.dll", "FlushFileBuffers", kOffPinReturn1}, // pretend fsync
    {"kernel32.dll", "GetFileType", kOffReturnTwo},       // 2 = FILE_TYPE_CHAR (console-ish)
    {"kernel32.dll", "GetConsoleWindow", kOffPinReturn0},
    // Vectored exception handlers: pin 0. The kernel SEH path
    // owns the unwind today, so registering a per-process
    // vectored handler is a no-op; returning 0 (= "register
    // failed") forces callers to fall through to their
    // __try / SetUnhandledExceptionFilter path which IS wired.
    {"kernel32.dll", "AddVectoredExceptionHandler", kOffPinReturn0},
    {"kernel32.dll", "RemoveVectoredExceptionHandler", kOffPinReturn0},
    {"kernel32.dll", "AddVectoredContinueHandler", kOffPinReturn0},

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
    // frames > 4 KiB. Real implementation (kOffChkStk) walks
    // the would-be-allocated range one byte per page so the OS
    // commits each page before the caller's `sub rsp, rax`.
    // DuetOS pre-commits user stacks today, but the probe is
    // forward-compatible with future demand-paged stacks.
    {"vcruntime140.dll", "__chkstk", kOffChkStk}, {"ntdll.dll", "__chkstk", kOffChkStk},
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
    {"kernel32.dll", "InterlockedAnd", kOffInterlockedAnd}, {"kernel32.dll", "InterlockedOr", kOffInterlockedOr},
    {"kernel32.dll", "InterlockedXor", kOffInterlockedXor}, {"kernel32.dll", "InterlockedAnd64", kOffInterlockedAnd64},
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
    {"ntdll.dll", "NtClose", kOffCloseHandle}, {"ntdll.dll", "ZwClose", kOffCloseHandle}, // Zw == Nt in user mode
    {"ntdll.dll", "NtYieldExecution", kOffPinVoidNop}, {"ntdll.dll", "ZwYieldExecution", kOffPinVoidNop},
    {"ntdll.dll", "RtlGetLastWin32Error", kOffGetLastError}, {"ntdll.dll", "RtlSetLastWin32Error", kOffSetLastError},
    {"ntdll.dll", "RtlNtStatusToDosError", kOffPinReturn0}, // 0 = ERROR_SUCCESS
    // Everything else returns STATUS_NOT_IMPLEMENTED.
    {"ntdll.dll", "NtCreateFile", kOffReturnStatusNotImpl}, {"ntdll.dll", "ZwCreateFile", kOffReturnStatusNotImpl},
    {"ntdll.dll", "NtOpenFile", kOffReturnStatusNotImpl}, {"ntdll.dll", "ZwOpenFile", kOffReturnStatusNotImpl},
    {"ntdll.dll", "NtReadFile", kOffReturnStatusNotImpl}, {"ntdll.dll", "ZwReadFile", kOffReturnStatusNotImpl},
    {"ntdll.dll", "NtWriteFile", kOffReturnStatusNotImpl}, {"ntdll.dll", "ZwWriteFile", kOffReturnStatusNotImpl},
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
    {"ntdll.dll", "NtCreateEvent", kOffReturnStatusNotImpl}, {"ntdll.dll", "ZwCreateEvent", kOffReturnStatusNotImpl},
    // Signature-compatible enough with SetEvent/ResetEvent:
    // Nt* variants carry an optional "previous state" out-pointer
    // in rdx that our v0 ignores.
    {"ntdll.dll", "NtSetEvent", kOffSetEventReal}, {"ntdll.dll", "ZwSetEvent", kOffSetEventReal},
    {"ntdll.dll", "NtResetEvent", kOffResetEventReal}, {"ntdll.dll", "ZwResetEvent", kOffResetEventReal},
    {"ntdll.dll", "NtCreateMutant", kOffReturnStatusNotImpl}, {"ntdll.dll", "ZwCreateMutant", kOffReturnStatusNotImpl},
    // NtReleaseMutant(handle, prevCount*) is close enough to
    // ReleaseMutex(handle) for v0; prevCount is ignored.
    {"ntdll.dll", "NtReleaseMutant", kOffReleaseMutex}, {"ntdll.dll", "ZwReleaseMutant", kOffReleaseMutex},
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
    {"ntdll.dll", "ZwTerminateThread", kOffReturnStatusNotImpl}, {"ntdll.dll", "NtContinue", kOffReturnStatusNotImpl},
    {"ntdll.dll", "ZwContinue", kOffReturnStatusNotImpl}, {"ntdll.dll", "NtOpenKey", kOffReturnStatusNotImpl},
    {"ntdll.dll", "ZwOpenKey", kOffReturnStatusNotImpl}, {"ntdll.dll", "NtQueryValueKey", kOffReturnStatusNotImpl},
    {"ntdll.dll", "ZwQueryValueKey", kOffReturnStatusNotImpl}, {"ntdll.dll", "NtQueryKey", kOffReturnStatusNotImpl},
    {"ntdll.dll", "ZwQueryKey", kOffReturnStatusNotImpl}, {"ntdll.dll", "NtEnumerateKey", kOffReturnStatusNotImpl},
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
    {"user32.dll", "MessageBoxW", kOffPinReturn1}, // IDOK (1) — caller proceeds
    {"user32.dll", "MessageBoxA", kOffPinReturn1}, {"user32.dll", "MessageBoxExW", kOffPinReturn1},
    {"user32.dll", "GetDesktopWindow", kOffPinReturn0}, {"user32.dll", "GetProcessWindowStation", kOffPinReturn0},
    {"user32.dll", "GetSysColor", kOffGetSysColor}, {"user32.dll", "GetSysColorBrush", kOffGetSysColorBrush},
    {"user32.dll", "GetSystemMetrics", kOffPinReturn0},
    {"user32.dll", "OpenClipboard", kOffPinReturn0}, // FALSE — unavailable
    {"user32.dll", "CloseClipboard", kOffPinReturn1}, {"user32.dll", "EmptyClipboard", kOffPinReturn1},
    {"user32.dll", "GetClipboardData", kOffPinReturn0}, {"user32.dll", "SetClipboardData", kOffPinReturn0},
    {"user32.dll", "LoadStringW", kOffPinReturn0}, // 0 chars copied
    {"user32.dll", "CharUpperW", kOffPinReturn0}, {"user32.dll", "CharLowerW", kOffPinReturn0},
    {"user32.dll", "IsWindow", kOffPinReturn0}, {"user32.dll", "GetActiveWindow", kOffPinReturn0},
    {"user32.dll", "GetForegroundWindow", kOffPinReturn0},

    // kernel32 — handle / file-mapping / env extensions.
    {"kernel32.dll", "SetHandleInformation", kOffPinReturn1}, {"kernel32.dll", "GetHandleInformation", kOffPinReturn0},
    {"kernel32.dll", "DuplicateHandle", kOffPinReturn0}, // FALSE
    {"kernel32.dll", "CreateFileMappingW", kOffPinReturn0}, {"kernel32.dll", "CreateFileMappingA", kOffPinReturn0},
    {"kernel32.dll", "OpenFileMappingW", kOffPinReturn0}, {"kernel32.dll", "MapViewOfFile", kOffPinReturn0},
    {"kernel32.dll", "MapViewOfFileEx", kOffPinReturn0}, {"kernel32.dll", "UnmapViewOfFile", kOffPinReturn1},
    {"kernel32.dll", "FlushViewOfFile", kOffPinReturn1}, {"kernel32.dll", "ExpandEnvironmentStringsW", kOffPinReturn0},
    {"kernel32.dll", "ExpandEnvironmentStringsA", kOffPinReturn0},
    {"kernel32.dll", "GetEnvironmentStringsA", kOffPinReturn0},
    {"kernel32.dll", "FreeEnvironmentStringsA", kOffPinReturn1}, {"kernel32.dll", "SetStdHandle", kOffPinReturn1},
    {"kernel32.dll", "GetConsoleScreenBufferInfo", kOffGetConsoleScreenBufferInfo},
    {"kernel32.dll", "GetNumberOfConsoleInputEvents", kOffPinReturn0},
    {"kernel32.dll", "PeekConsoleInputW", kOffPinReturn0}, {"kernel32.dll", "ReadConsoleInputW", kOffPinReturn0},
    {"kernel32.dll", "WaitForInputIdle", kOffPinReturn0}, // 0 = WAIT_OBJECT_0
    {"kernel32.dll", "PeekNamedPipe", kOffPinReturn0},

    // kernel32 — locale / comparison.
    // CompareStringW returns 2 (CSTR_EQUAL) so callers treating
    // it as a 3-way compare see "equal" — the conservative
    // fallback that avoids misordering.
    {"kernel32.dll", "CompareStringW", kOffReturnTwo}, // CSTR_EQUAL
    {"kernel32.dll", "CompareStringA", kOffReturnTwo}, {"kernel32.dll", "CompareStringEx", kOffReturnTwo},
    {"kernel32.dll", "LCMapStringW", kOffPinReturn0}, {"kernel32.dll", "LCMapStringA", kOffPinReturn0},
    {"kernel32.dll", "LCMapStringEx", kOffPinReturn0}, {"kernel32.dll", "GetLocaleInfoW", kOffPinReturn0},
    {"kernel32.dll", "GetLocaleInfoA", kOffPinReturn0}, {"kernel32.dll", "GetLocaleInfoEx", kOffPinReturn0},
    {"kernel32.dll", "EnumSystemLocalesW", kOffPinReturn1}, // pretend iteration done
    {"kernel32.dll", "EnumSystemLocalesA", kOffPinReturn1}, {"kernel32.dll", "GetStringTypeW", kOffPinReturn1},
    {"kernel32.dll", "GetStringTypeA", kOffPinReturn1}, {"kernel32.dll", "GetStringTypeExW", kOffPinReturn1},
    {"kernel32.dll", "IsDBCSLeadByte", kOffPinReturn0}, // FALSE — no DBCS

    // === shell32 / ole32 / winmm / shlwapi / psapi ==
    //
    // Another broad coverage sweep. All aliases to existing
    // constant-return stubs. Most return "failure" or "empty
    // result" so callers fall back cleanly.

    // shell32 — folder paths + shell-execute.
    {"shell32.dll", "SHGetFolderPathW", kOffPinReturn0}, {"shell32.dll", "SHGetFolderPathA", kOffPinReturn0},
    {"shell32.dll", "SHGetKnownFolderPath", kOffPinReturn0}, {"shell32.dll", "SHCreateDirectoryW", kOffPinReturn0},
    {"shell32.dll", "SHCreateDirectoryExW", kOffPinReturn0}, {"shell32.dll", "SHGetPathFromIDListW", kOffPinReturn1},
    {"shell32.dll", "CommandLineToArgvW", kOffPinReturn0}, {"shell32.dll", "ShellExecuteW", kOffPinReturn1},
    {"shell32.dll", "ShellExecuteExW", kOffPinReturn1}, {"shell32.dll", "SHGetSpecialFolderPathW", kOffPinReturn1},
    {"shell32.dll", "SHFileOperationW", kOffPinReturn0}, {"shell32.dll", "ExtractIconW", kOffPinReturn0},
    {"shell32.dll", "ExtractIconExW", kOffPinReturn0},

    // ole32 + oleaut32 — COM. Pin contracts: Init returns S_OK (0),
    // Uninitialize/Free are void, CreateInstance returns E_FAIL,
    // BSTR allocators return NULL / 0.
    {"ole32.dll", "CoInitialize", kOffPinReturn0}, {"ole32.dll", "CoInitializeEx", kOffPinReturn0},
    {"ole32.dll", "CoUninitialize", kOffPinVoidNop}, {"ole32.dll", "CoCreateInstance", kOffHresultEFail},
    {"ole32.dll", "CoCreateInstanceEx", kOffHresultEFail}, {"ole32.dll", "CoGetClassObject", kOffHresultEFail},
    {"ole32.dll", "CoTaskMemAlloc", kOffPinReturn0}, {"ole32.dll", "CoTaskMemFree", kOffPinVoidNop},
    {"ole32.dll", "CoTaskMemRealloc", kOffPinReturn0}, {"ole32.dll", "OleInitialize", kOffPinReturn0},
    {"ole32.dll", "OleUninitialize", kOffPinVoidNop}, {"ole32.dll", "CLSIDFromString", kOffHresultEFail},
    {"ole32.dll", "CLSIDFromProgID", kOffHresultEFail}, {"ole32.dll", "StringFromCLSID", kOffHresultEFail},
    {"ole32.dll", "IIDFromString", kOffHresultEFail}, {"oleaut32.dll", "SysAllocString", kOffPinReturn0},
    {"oleaut32.dll", "SysFreeString", kOffPinVoidNop}, {"oleaut32.dll", "SysStringLen", kOffPinReturn0},
    {"oleaut32.dll", "VariantInit", kOffPinVoidNop}, {"oleaut32.dll", "VariantClear", kOffPinReturn0},

    // winmm — timer + multimedia.
    {"winmm.dll", "timeGetTime", kOffGetTickCount}, {"winmm.dll", "timeBeginPeriod", kOffPinReturn0},
    {"winmm.dll", "timeEndPeriod", kOffPinReturn0}, {"winmm.dll", "timeGetDevCaps", kOffPinReturn0},
    {"winmm.dll", "PlaySoundW", kOffPinReturn1}, {"winmm.dll", "mciSendStringW", kOffPinReturn0},

    // shlwapi — path / string helpers.
    {"shlwapi.dll", "PathFileExistsW", kOffPinReturn0}, {"shlwapi.dll", "PathFileExistsA", kOffPinReturn0},
    {"shlwapi.dll", "PathFindFileNameW", kOffPinReturn0}, {"shlwapi.dll", "PathFindFileNameA", kOffPinReturn0},
    {"shlwapi.dll", "PathFindExtensionW", kOffPinReturn0}, {"shlwapi.dll", "PathFindExtensionA", kOffPinReturn0},
    {"shlwapi.dll", "PathCombineW", kOffPinReturn0}, {"shlwapi.dll", "PathIsDirectoryW", kOffPinReturn0},
    {"shlwapi.dll", "PathRemoveFileSpecW", kOffPinReturn0}, {"shlwapi.dll", "PathStripPathW", kOffPinVoidNop},
    {"shlwapi.dll", "PathAppendW", kOffPinReturn0}, {"shlwapi.dll", "PathAddBackslashW", kOffPinReturn0},
    {"shlwapi.dll", "StrStrW", kOffPinReturn0}, {"shlwapi.dll", "StrStrIW", kOffPinReturn0},
    {"shlwapi.dll", "StrCmpNW", kOffPinReturn0}, {"shlwapi.dll", "StrCmpW", kOffPinReturn0},

    // psapi — process/module enumeration.
    {"psapi.dll", "EnumProcesses", kOffPinReturn0}, {"psapi.dll", "EnumProcessModules", kOffPinReturn0},
    {"psapi.dll", "GetModuleBaseNameW", kOffPinReturn0}, {"psapi.dll", "GetModuleFileNameExW", kOffPinReturn0},
    {"psapi.dll", "GetProcessMemoryInfo", kOffPinReturn0}, {"psapi.dll", "GetMappedFileNameW", kOffPinReturn0},
    {"psapi.dll", "QueryWorkingSet", kOffPinReturn0},

    // === kernelbase / bcrypt / dbghelp / extended ntdll ===
    //
    // Coverage for the newer DLL split (kernelbase.dll = common
    // kernel32+advapi32 core since Win8) + crypto + debugging
    // helpers + more ntdll. All aliases.

    // kernelbase.dll — most exports mirror kernel32. Real apps
    // built against the Win8+ SDK bind directly to kernelbase.
    // Aliasing to the same internal stubs means they work
    // identically.
    {"kernelbase.dll", "GetLastError", kOffGetLastError}, {"kernelbase.dll", "SetLastError", kOffSetLastError},
    {"kernelbase.dll", "GetCurrentProcess", kOffGetCurrentProcess},
    {"kernelbase.dll", "GetCurrentProcessId", kOffGetCurrentProcessId},
    {"kernelbase.dll", "GetCurrentThreadId", kOffGetCurrentThreadId},
    {"kernelbase.dll", "ExitProcess", kOffExitProcess}, {"kernelbase.dll", "WriteFile", kOffWriteFile},
    {"kernelbase.dll", "ReadFile", kOffReadFile}, {"kernelbase.dll", "CloseHandle", kOffCloseHandle},
    {"kernelbase.dll", "CreateFileW", kOffCreateFileW}, {"kernelbase.dll", "HeapAlloc", kOffHeapAlloc},
    {"kernelbase.dll", "HeapFree", kOffHeapFree}, {"kernelbase.dll", "GetProcessHeap", kOffGetProcessHeap},
    {"kernelbase.dll", "GetStdHandle", kOffGetStdHandle}, {"kernelbase.dll", "VirtualAlloc", kOffVirtualAlloc},
    {"kernelbase.dll", "VirtualFree", kOffVirtualFree}, {"kernelbase.dll", "VirtualProtect", kOffVirtualProtect},
    {"kernelbase.dll", "CreateMutexW", kOffCreateMutexW}, {"kernelbase.dll", "WaitForSingleObject", kOffWaitForObj4},
    {"kernelbase.dll", "WaitForSingleObjectEx", kOffWaitForObj4}, {"kernelbase.dll", "ReleaseMutex", kOffReleaseMutex},
    {"kernelbase.dll", "CreateEventW", kOffCreateEventReal}, {"kernelbase.dll", "SetEvent", kOffSetEventReal},
    {"kernelbase.dll", "ResetEvent", kOffResetEventReal}, {"kernelbase.dll", "Sleep", kOffSleep},
    {"kernelbase.dll", "SwitchToThread", kOffSwitchToThread}, {"kernelbase.dll", "GetCommandLineW", kOffGetCmdLineW},
    {"kernelbase.dll", "GetCommandLineA", kOffGetCmdLineA},
    {"kernelbase.dll", "GetModuleHandleW", kOffGetModuleHandleW},
    {"kernelbase.dll", "GetModuleFileNameW", kOffGetModFileNameW}, {"kernelbase.dll", "TlsAlloc", kOffTlsAllocReal},
    {"kernelbase.dll", "TlsFree", kOffTlsFreeReal}, {"kernelbase.dll", "TlsGetValue", kOffTlsGetValueReal},
    {"kernelbase.dll", "TlsSetValue", kOffTlsSetValueReal},
    {"kernelbase.dll", "InterlockedIncrement", kOffInterlockedInc},
    {"kernelbase.dll", "InterlockedDecrement", kOffInterlockedDec},
    {"kernelbase.dll", "InterlockedCompareExchange", kOffInterlockedCmpXchg},
    {"kernelbase.dll", "InterlockedExchange", kOffInterlockedExchg},
    {"kernelbase.dll", "VerifyVersionInfoW", kOffPinReturn1}, {"kernelbase.dll", "IsWow64Process", kOffIsWow64},
    {"kernelbase.dll", "GetVersionExW", kOffGetVersionExW}, {"kernelbase.dll", "lstrlenW", kOffLstrlenW},
    {"kernelbase.dll", "lstrcmpW", kOffLstrcmpW}, {"kernelbase.dll", "MultiByteToWideChar", kOffMBtoWC},
    {"kernelbase.dll", "WideCharToMultiByte", kOffWCtoMB},

    // bcrypt.dll — CNG crypto. All "no-op success" for v0; real
    // entropy comes from RtlGenRandom (below) if callers fall
    // through to it. Most callers handle STATUS_UNSUCCESSFUL by
    // bailing the crypto path cleanly.
    {"bcrypt.dll", "BCryptOpenAlgorithmProvider", kOffReturnStatusNotImpl},
    {"bcrypt.dll", "BCryptCloseAlgorithmProvider", kOffPinReturn0},
    {"bcrypt.dll", "BCryptGenRandom", kOffReturnStatusNotImpl},
    {"bcrypt.dll", "BCryptCreateHash", kOffReturnStatusNotImpl},
    {"bcrypt.dll", "BCryptHashData", kOffReturnStatusNotImpl},
    {"bcrypt.dll", "BCryptFinishHash", kOffReturnStatusNotImpl}, {"bcrypt.dll", "BCryptDestroyHash", kOffPinReturn0},
    {"bcrypt.dll", "BCryptGetProperty", kOffReturnStatusNotImpl},
    // advapi32 has a legacy crypto entry that some CRT builds probe.
    {"advapi32.dll", "SystemFunction036", kOffPinReturn1}, // RtlGenRandom — return TRUE, buf untouched

    // dbghelp.dll — symbolic debugging. Everything stubbed to
    // "not available"; programs usually fall back to raw addresses.
    {"dbghelp.dll", "SymInitialize", kOffPinReturn1}, {"dbghelp.dll", "SymInitializeW", kOffPinReturn1},
    {"dbghelp.dll", "SymCleanup", kOffPinReturn1}, {"dbghelp.dll", "SymFromAddr", kOffPinReturn0},
    {"dbghelp.dll", "SymFromAddrW", kOffPinReturn0}, {"dbghelp.dll", "SymGetLineFromAddr64", kOffPinReturn0},
    {"dbghelp.dll", "SymLoadModule64", kOffPinReturn0}, {"dbghelp.dll", "StackWalk64", kOffPinReturn0},
    {"dbghelp.dll", "SymFunctionTableAccess64", kOffPinReturn0}, {"dbghelp.dll", "SymGetModuleBase64", kOffPinReturn0},
    {"dbghelp.dll", "MiniDumpWriteDump", kOffPinReturn0},

    // More ntdll Rtl* — pure user-mode helpers often touched
    // even from kernel32-using apps. Most return 0/success.
    // String init / free: pin void — no in-kernel UNICODE_STRING
    // bookkeeping, the caller's storage IS the string.
    {"ntdll.dll", "RtlInitUnicodeString", kOffPinVoidNop},                                                  // void
    {"ntdll.dll", "RtlInitAnsiString", kOffPinVoidNop},                                                     // void
    {"ntdll.dll", "RtlFreeUnicodeString", kOffPinVoidNop}, {"ntdll.dll", "RtlAllocateHeap", kOffHeapAlloc}, // real heap
    {"ntdll.dll", "RtlFreeHeap", kOffHeapFree},                                                             // real heap
    {"ntdll.dll", "RtlSizeHeap", kOffHeapSize}, {"ntdll.dll", "RtlReAllocateHeap", kOffHeapRealloc},
    {"ntdll.dll", "RtlCreateHeap", kOffPinReturn0}, // NULL
    {"ntdll.dll", "RtlDestroyHeap", kOffPinReturn0}, {"ntdll.dll", "RtlCompareMemory", kOffPinReturn0},
    {"ntdll.dll", "RtlZeroMemory", kOffPinVoidNop},                                              // void
    {"ntdll.dll", "RtlFillMemory", kOffPinVoidNop}, {"ntdll.dll", "RtlCopyMemory", kOffMemmove}, // real memcpy
    {"ntdll.dll", "RtlMoveMemory", kOffMemmove}, {"ntdll.dll", "RtlEnterCriticalSection", kOffEnterCritSecReal},
    {"ntdll.dll", "RtlLeaveCriticalSection", kOffLeaveCritSecReal},
    {"ntdll.dll", "RtlInitializeCriticalSection", kOffInitCritSec},
    {"ntdll.dll", "RtlDeleteCriticalSection", kOffPinVoidNop},
    {"ntdll.dll", "RtlTryEnterCriticalSection", kOffTryEnterCritSecReal},
    // kernel32 doesn't export TryEnterCriticalSection under that
    // exact name — programs hit it through the Rtl alias above or
    // via the (unstubbed) kernel32!TryEnterCriticalSection thunk.
    {"kernel32.dll", "TryEnterCriticalSection", kOffTryEnterCritSecReal},
    {"ntdll.dll", "LdrLoadDll", kOffReturnStatusNotImpl}, {"ntdll.dll", "LdrGetDllHandle", kOffReturnStatusNotImpl},
    {"ntdll.dll", "LdrGetProcedureAddress", kOffReturnStatusNotImpl},
    {"ntdll.dll", "RtlRunOnceExecuteOnce", kOffPinReturn0}, // S_OK

    // Win32 process heap, backed by the per-process
    // 16-page region at 0x50000000 and SYS_HEAP_ALLOC /
    // SYS_HEAP_FREE. See kernel/subsystems/win32/heap.cpp.
    //
    // kernel32 heap exports: take a HANDLE arg that v0
    // ignores — GetProcessHeap returns the same cookie
    // HeapAlloc ignores, so it's internally consistent.
    {"kernel32.dll", "GetProcessHeap", kOffGetProcessHeap}, {"kernel32.dll", "HeapAlloc", kOffHeapAlloc},
    {"kernel32.dll", "HeapFree", kOffHeapFree},
    // HeapCreate: Win32 normally creates a private heap.
    // v0 collapses to the shared process heap — same handle
    // as GetProcessHeap. HeapDestroy is a no-op returning
    // TRUE (we never actually free the heap pages).
    {"kernel32.dll", "HeapCreate", kOffGetProcessHeap}, {"kernel32.dll", "HeapDestroy", kOffPinReturn1},
    // HeapReAlloc / HeapSize: backed by SYS_HEAP_REALLOC +
    // SYS_HEAP_SIZE as of — block header carries the
    // rounded-up size so we can translate both operations
    // without extra per-block bookkeeping.
    {"kernel32.dll", "HeapReAlloc", kOffHeapRealloc}, {"kernel32.dll", "HeapSize", kOffHeapSize},

    // UCRT / msvcrt / apiset heap names — all forward to the
    // same syscall-backed stubs. realloc returns NULL; malloc
    // and free are straight-through.
    {"api-ms-win-crt-heap-l1-1-0.dll", "malloc", kOffMalloc}, {"api-ms-win-crt-heap-l1-1-0.dll", "free", kOffFree},
    {"api-ms-win-crt-heap-l1-1-0.dll", "calloc", kOffCalloc},
    {"api-ms-win-crt-heap-l1-1-0.dll", "realloc", kOffRealloc},
    // _aligned_malloc / _aligned_free: v0 ignores alignment.
    // The allocator already returns 8-byte aligned pointers,
    // which covers most callers (16-byte alignment failure
    // will surface later if anything needs AVX/SSE locals
    // stored in a heap allocation).
    {"api-ms-win-crt-heap-l1-1-0.dll", "_aligned_malloc", kOffMalloc},
    {"api-ms-win-crt-heap-l1-1-0.dll", "_aligned_free", kOffFree},

    {"ucrtbase.dll", "malloc", kOffMalloc}, {"ucrtbase.dll", "free", kOffFree}, {"ucrtbase.dll", "calloc", kOffCalloc},
    {"ucrtbase.dll", "realloc", kOffRealloc}, {"ucrtbase.dll", "_aligned_malloc", kOffMalloc},
    {"ucrtbase.dll", "_aligned_free", kOffFree},

    {"msvcrt.dll", "malloc", kOffMalloc}, {"msvcrt.dll", "free", kOffFree}, {"msvcrt.dll", "calloc", kOffCalloc},
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
    {"advapi32.dll", "AdjustTokenPrivileges", kOffPinReturn1},
    // Uppercase aliases — llvm-dlltool writes the DLL name
    // using the .def file's LIBRARY line verbatim, but some
    // linkers normalise to uppercase. Register both so
    // capitalisation in the PE's import table (either way)
    // hits the stub.
    {"ADVAPI32.dll", "OpenProcessToken", kOffOpenProcessToken},
    {"ADVAPI32.dll", "LookupPrivilegeValueW", kOffLookupPrivVal},
    {"ADVAPI32.dll", "LookupPrivilegeValueA", kOffLookupPrivVal},
    {"ADVAPI32.dll", "AdjustTokenPrivileges", kOffPinReturn1},

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
    {"kernel32.dll", "GenerateConsoleCtrlEvent", kOffPinReturn1},

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
    {"kernel32.dll", "QueryPerformanceCounter", kOffQpcNs}, {"kernel32.dll", "QueryPerformanceFrequency", kOffQpfNs},
    {"kernel32.dll", "GetTickCount", kOffGetTickCount}, {"kernel32.dll", "GetTickCount64", kOffGetTickCount},

    // Sleep + SwitchToThread (timer + voluntary yield).
    // Sleep routes to SYS_SLEEP_MS; SwitchToThread routes to
    // SYS_YIELD. SleepEx ignores its bAlertable arg and aliases
    // to Sleep — no APC delivery in v0, so the alertable form
    // would never actually fire user-mode APCs anyway.
    {"kernel32.dll", "Sleep", kOffSleep}, {"kernel32.dll", "SleepEx", kOffSleep},
    {"kernel32.dll", "SwitchToThread", kOffSwitchToThread},

    // command line + environment (proc-env page reads).
    // GetCommandLineW / GetCommandLineA hand back pointers into
    // the proc-env page populated by Win32ProcEnvPopulate at PE
    // load. GetEnvironmentVariableW returns 0 (var-not-found)
    // for every query in v0; that's a documented success-case
    // outcome of the Win32 contract and cleanly degrades for
    // any caller that has a default. GetEnvironmentStringsW
    // returns a pointer to an empty block (two NUL bytes).
    // FreeEnvironmentStrings{W,A}: real implementation returning
    // TRUE — the env block is a static slot inside proc-env, not
    // heap-allocated, so freeing is a true no-op. Distinct named
    // offset (kOffFreeEnvStringsW) ensures the fix-journal noop
    // classifier doesn't flag it as an unimplemented stub.
    {"kernel32.dll", "GetCommandLineW", kOffGetCmdLineW}, {"kernel32.dll", "GetCommandLineA", kOffGetCmdLineA},
    // Env-var query fallback: pin 0 (not found). The userland
    // kernel32.dll has the real per-process env table; this
    // fallback returns 0 (= "not found", no chars written).
    {"kernel32.dll", "GetEnvironmentVariableW", kOffPinReturn0},
    {"kernel32.dll", "GetEnvironmentVariableA", kOffPinReturn0},
    {"kernel32.dll", "GetEnvironmentStringsW", kOffGetEnvBlockW},
    {"kernel32.dll", "GetEnvironmentStrings", kOffGetEnvBlockW},
    {"kernel32.dll", "FreeEnvironmentStringsW", kOffFreeEnvStringsW},
    {"kernel32.dll", "FreeEnvironmentStringsA", kOffFreeEnvStringsW},
    {"kernel32.dll", "SetEnvironmentVariableW", kOffPinReturn1}, // pretend success
    {"kernel32.dll", "SetEnvironmentVariableA", kOffPinReturn1},

    // Rtl* unwind (v0: empty / not-found sentinels)
    {"kernel32.dll", "RtlCaptureStackBackTrace", kOffSehNoUnwind},
    {"kernel32.dll", "RtlCaptureContext", kOffSehNoUnwind}, {"kernel32.dll", "RtlLookupFunctionEntry", kOffSehNoUnwind},
    {"kernel32.dll", "RtlVirtualUnwind", kOffSehNoUnwind},

    // Toolhelp32 + thread management (empty snapshot / no
    // ops). Real implementation requires the kernel to
    // expose the process table to ring 3 — deferred.
    {"kernel32.dll", "CreateToolhelp32Snapshot", kOffPinReturn1}, {"kernel32.dll", "Process32First", kOffPinReturn0},
    {"kernel32.dll", "Process32FirstW", kOffPinReturn0}, {"kernel32.dll", "Process32Next", kOffPinReturn0},
    {"kernel32.dll", "Process32NextW", kOffPinReturn0}, {"kernel32.dll", "CreateRemoteThread", kOffNoCrossProcThread},
    {"kernel32.dll", "ResumeThread", kOffPinReturn0}, {"kernel32.dll", "GetExitCodeProcess", kOffGetExitCodeThread},

    // dbghelp + vcruntime SEH + UCRT convert.
    // All aliases to existing stubs; no new bytecode.
    //
    // dbghelp: symbol-table code paths. Succeed-but-find-nothing
    // is the safe stub semantic for crash loggers that call
    // SymFromAddr — they'll print "address=0x???" instead of
    // "file:line", but never fault.
    {"dbghelp.dll", "SymInitialize", kOffPinReturn1}, {"dbghelp.dll", "SymCleanup", kOffPinReturn1},
    {"dbghelp.dll", "SymFromAddr", kOffPinReturn0},

    // vcruntime SEH / C++ ABI — any program that actually
    // throws or dispatches a pure-virtual call will hit these.
    // We route them to SYS_EXIT(3) so a crash is visible in
    // the log (rc=0x3) rather than a silent #PF. Non-terminal
    // ones return 0.
    {"vcruntime140.dll", "__CxxFrameHandler3", kOffTerminate},
    {"vcruntime140.dll", "__C_specific_handler", kOffTerminate},
    {"vcruntime140.dll", "_CxxThrowException", kOffTerminate}, {"vcruntime140.dll", "_purecall", kOffTerminate},
    {"vcruntime140.dll", "__std_terminate", kOffTerminate},
    {"vcruntime140.dll", "__std_exception_copy", kOffPinReturn0},
    {"vcruntime140.dll", "__std_exception_destroy", kOffPinReturn0},
    // Same shape as InitCritSec: zero-init 40 bytes at [rcx].
    {"vcruntime140.dll", "__vcrt_InitializeCriticalSectionEx", kOffInitCritSec},

    // UCRT convert — return 0 for every parse. Callers that
    // check errno get the wrong answer (we don't wire errno)
    // but won't crash.
    {"api-ms-win-crt-convert-l1-1-0.dll", "strtoul", kOffStrtoulNoop},
    {"api-ms-win-crt-convert-l1-1-0.dll", "strtol", kOffPinReturn0},
    {"api-ms-win-crt-convert-l1-1-0.dll", "atoi", kOffPinReturn0},
    {"api-ms-win-crt-convert-l1-1-0.dll", "atol", kOffPinReturn0}, {"ucrtbase.dll", "strtoul", kOffStrtoulNoop},
    {"ucrtbase.dll", "strtol", kOffPinReturn0}, {"ucrtbase.dll", "atoi", kOffPinReturn0},
    {"ucrtbase.dll", "atol", kOffPinReturn0}, {"msvcrt.dll", "strtoul", kOffStrtoulNoop},
    {"msvcrt.dll", "strtol", kOffPinReturn0}, {"msvcrt.dll", "atoi", kOffPinReturn0},
    {"msvcrt.dll", "atol", kOffPinReturn0},

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
    {"MSVCP140.dll", "?_Syserror_map@std@@YAPEBDH@Z", kOffPinReturn0},
    {"MSVCP140.dll", "?_Winerror_map@std@@YAHH@Z", kOffPinReturn0},
    {"MSVCP140.dll", "?_Winerror_message@std@@YAKKPEADK@Z", kOffPinReturn0},
    {"MSVCP140.dll", "?uncaught_exception@std@@YA_NXZ", kOffPinReturn0},

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
    {"api-ms-win-crt-runtime-l1-1-0.dll", "__p___argv", kOffPArgv}, {"ucrtbase.dll", "__p___argc", kOffPArgc},
    {"ucrtbase.dll", "__p___argv", kOffPArgv}, {"msvcrt.dll", "__p___argc", kOffPArgc},
    {"msvcrt.dll", "__p___argv", kOffPArgv},

    // UCRT stdio accessors. `__p__commode` returns
    // &_commode for callers that want the default-file-mode
    // flags (every UCRT-linked program reads it during startup
    // to pick text vs binary I/O). `_callnewh` is the C++
    // new-handler trampoline; v0 always "no handler set" so
    // the caller throws bad_alloc or returns failure — aliased
    // to the shared return-zero stub.
    {"api-ms-win-crt-stdio-l1-1-0.dll", "__p__commode", kOffPCommode}, {"ucrtbase.dll", "__p__commode", kOffPCommode},
    {"msvcrt.dll", "__p__commode", kOffPCommode}, {"api-ms-win-crt-heap-l1-1-0.dll", "_callnewh", kOffCallnewhNoop},
    {"ucrtbase.dll", "_callnewh", kOffCallnewhNoop}, {"msvcrt.dll", "_callnewh", kOffCallnewhNoop},

    // CRT termination + init. 7za.exe (and most older MSVC PEs)
    // import these from msvcrt.dll directly. Without `exit`, the
    // entry function falls through `return 0;` and `ret`s to a
    // NULL stack-bottom RIP — the program faults with #PF at
    // rip=0 instead of exiting cleanly. Map to kOffExitProcess
    // (which forwards arg1 in RCX → SYS_EXIT(RDI=rc)) so the
    // exit code the program passes survives into the kernel —
    // kOffTerminate would clobber it with the std::terminate
    // sentinel value 3.
    {"msvcrt.dll", "exit", kOffExitProcess}, {"msvcrt.dll", "_exit", kOffExitProcess},
    // MSVCRT stdio — real SYS_WRITE to fd=1, ignore FILE*.
    {"msvcrt.dll", "fputs", kOffFputs}, {"msvcrt.dll", "puts", kOffFputs}, // close enough for the help-text path
    {"msvcrt.dll", "fwrite", kOffFwrite},
    {"msvcrt.dll", "fputc", kOffFputc}, // returns c (not 0) so help-print continues
    {"msvcrt.dll", "putchar", kOffFputc}, {"msvcrt.dll", "fflush", kOffPinReturn0},
    {"msvcrt.dll", "fgetc", kOffReturnMinus1}, // EOF
    // Same stdio surface registered under the modern UCRT
    // apiset DLL name + ucrtbase.dll. NASM (UCRT-based)
    // imports from the apiset; without these its `fputs(...)
    // stderr` for the no-args usage line NO-OP'd and the
    // program exited with rc=2 silently.
    {"api-ms-win-crt-stdio-l1-1-0.dll", "fputs", kOffFputs}, {"api-ms-win-crt-stdio-l1-1-0.dll", "puts", kOffFputs},
    {"api-ms-win-crt-stdio-l1-1-0.dll", "fwrite", kOffFwrite}, {"api-ms-win-crt-stdio-l1-1-0.dll", "fputc", kOffFputc},
    {"api-ms-win-crt-stdio-l1-1-0.dll", "putchar", kOffFputc},
    {"api-ms-win-crt-stdio-l1-1-0.dll", "fflush", kOffPinReturn0},
    {"api-ms-win-crt-stdio-l1-1-0.dll", "fgetc", kOffReturnMinus1},
    {"api-ms-win-crt-stdio-l1-1-0.dll", "feof", kOffPinReturn1},
    {"api-ms-win-crt-stdio-l1-1-0.dll", "ferror", kOffPinReturn0},
    {"api-ms-win-crt-stdio-l1-1-0.dll", "fclose", kOffPinReturn0},
    {"api-ms-win-crt-stdio-l1-1-0.dll", "fread", kOffPinReturn0},
    {"api-ms-win-crt-stdio-l1-1-0.dll", "getc", kOffReturnMinus1}, {"ucrtbase.dll", "fputs", kOffFputs},
    {"ucrtbase.dll", "puts", kOffFputs}, {"ucrtbase.dll", "fwrite", kOffFwrite}, {"ucrtbase.dll", "fputc", kOffFputc},
    {"ucrtbase.dll", "putchar", kOffFputc}, {"ucrtbase.dll", "fflush", kOffPinReturn0},
    {"ucrtbase.dll", "fgetc", kOffReturnMinus1}, {"msvcrt.dll", "_cexit", kOffPinReturn0}, // CRT cleanup; safe to no-op
    {"msvcrt.dll", "_c_exit", kOffPinReturn0}, // CRT cleanup (no exit); no-op
    // _initterm walks an array of function pointers calling each
    // non-null entry — used for static-init dispatch. We can't
    // run real ctors yet (no static-init runtime), but a ret-only
    // stub is correct: any program that depends on its ctors
    // running won't get them, but at least won't fault here.
    {"msvcrt.dll", "_initterm", kOffInitterm}, {"msvcrt.dll", "_initterm_e", kOffInittermE},
    // __getmainargs / __wgetmainargs: populate argc/argv/env from
    // proc-env so the CRT's argv-parsing path doesn't deref NULL.
    // ReturnZero stub left a NULL argv in place and busybox-w32
    // faulted at the first cmdline-walk step (cr2=1).
    {"msvcrt.dll", "__getmainargs", kOffGetMainArgs}, {"msvcrt.dll", "__wgetmainargs", kOffGetMainArgs},
    {"ucrtbase.dll", "__getmainargs", kOffGetMainArgs},
    {"api-ms-win-crt-runtime-l1-1-0.dll", "__getmainargs", kOffGetMainArgs},

    // _errno: thread-errno accessor. Shares one scratch slot in
    // v0 (proc-env data-miss pad). Without this NASM crashes
    // at the first stdio call: `call _errno; mov eax, [rax]`
    // → mov eax, [0] when _errno returns 0.
    {"api-ms-win-crt-runtime-l1-1-0.dll", "_errno", kOffPErrno}, {"ucrtbase.dll", "_errno", kOffPErrno},
    {"msvcrt.dll", "_errno", kOffPErrno}, {"msvcrt.dll", "__set_app_type", kOffPinReturn0},
    {"msvcrt.dll", "__setusermatherr", kOffSetUsermatherr}, {"msvcrt.dll", "_XcptFilter", kOffPinReturn0},
    {"msvcrt.dll", "_onexit", kOffPinReturn0}, {"msvcrt.dll", "__dllonexit", kOffPinReturn0},

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
    {"MSVCP140.dll", "?sputc@?$basic_streambuf@DU?$char_traits@D@std@@@std@@QEAAHD@Z", kOffPinReturn0},

    // put → returns *this (chainable). Doesn't actually emit
    // the char in v0 — the call still does its real work if
    // the caller reads a buffer pointer off the return value
    // (nobody does).
    {"MSVCP140.dll", "?put@?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAAAEAV12@D@Z", kOffReturnThis},

    // flush → returns *this. No buffers to drain in v0.
    {"MSVCP140.dll", "?flush@?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAAAEAV12@XZ", kOffReturnThis},

    // _Osfx (sentry epilog) → void, no-op.
    {"MSVCP140.dll", "?_Osfx@?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAAXXZ", kOffPinVoidNop},

    // setstate → void, no-op. (Silently drops the bits; any
    // code that inspects rdstate() later sees goodbit.)
    {"MSVCP140.dll", "?setstate@?$basic_ios@DU?$char_traits@D@std@@@std@@QEAAXH_N@Z", kOffPinVoidNop},

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
    {"D3D12.dll", "D3D12CreateDevice", kOffD3d12CreateStub}, {"dxgi.dll", "CreateDXGIFactory", kOffDxgiCreateStub},
    {"dxgi.dll", "CreateDXGIFactory1", kOffDxgiCreateStub}, {"dxgi.dll", "CreateDXGIFactory2", kOffDxgiCreateStub},
    {"DXGI.dll", "CreateDXGIFactory", kOffDxgiCreateStub}, {"DXGI.dll", "CreateDXGIFactory1", kOffDxgiCreateStub},
    {"DXGI.dll", "CreateDXGIFactory2", kOffDxgiCreateStub},
    // d3d9 predates HRESULT-first API — it returns an interface
    // pointer, NULL = failure. Alias to the shared return-zero
    // stub rather than E_FAIL.
    {"d3d9.dll", "Direct3DCreate9", kOffPinReturn0}, {"d3d9.dll", "Direct3DCreate9Ex", kOffHresultEFail},

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
    {"kernel32.dll", "IsValidLocale", kOffPinReturn1}, {"kernel32.dll", "GetCPInfo", kOffPinReturn1},
    {"kernel32.dll", "GetCPInfoExA", kOffPinReturn1}, {"kernel32.dll", "GetCPInfoExW", kOffPinReturn1},

    // winmm: multimedia-timer — fake a valid timer ID + silent kill.
    {"winmm.dll", "timeSetEvent", kOffPinReturn1}, {"winmm.dll", "timeKillEvent", kOffPinReturn0},

    // user32: window class + window lifecycle. The kernel's
    // window manager hosts the real surface, but these exports
    // are pinned to the v0 contracts the wiki tracks — most
    // CreateWindowExW / RegisterClassExW callers only care that
    // the return is non-zero (a fake HWND/ATOM) so the program
    // proceeds into its message loop, which IS wired through
    // kOffGetMessageA / kOffDispatchMessageA below.
    {"user32.dll", "RegisterClassA", kOffPinReturn1}, {"user32.dll", "RegisterClassW", kOffPinReturn1},
    {"user32.dll", "RegisterClassExA", kOffPinReturn1}, {"user32.dll", "RegisterClassExW", kOffPinReturn1},
    {"user32.dll", "UnregisterClassA", kOffPinReturn1}, {"user32.dll", "UnregisterClassW", kOffPinReturn1},
    {"user32.dll", "CreateWindowExA", kOffPinReturn1}, {"user32.dll", "CreateWindowExW", kOffPinReturn1},
    {"user32.dll", "DestroyWindow", kOffPinReturn1}, {"user32.dll", "DefWindowProcA", kOffPinReturn0},
    {"user32.dll", "DefWindowProcW", kOffPinReturn0}, {"user32.dll", "CallWindowProcA", kOffPinReturn0},
    {"user32.dll", "CallWindowProcW", kOffPinReturn0}, {"user32.dll", "ShowWindow", kOffPinReturn0},
    {"user32.dll", "UpdateWindow", kOffWinUpdateWindow}, {"user32.dll", "GetClientRect", kOffPinReturn1},
    {"user32.dll", "GetWindowRect", kOffPinReturn1}, {"user32.dll", "MoveWindow", kOffPinReturn1},
    {"user32.dll", "SetWindowPos", kOffPinReturn1}, {"user32.dll", "InvalidateRect", kOffWinInvalidateRect},
    {"user32.dll", "BeginPaint", kOffWinBeginPaint}, {"user32.dll", "EndPaint", kOffWinEndPaint},
    {"user32.dll", "GetDC", kOffWinGetDC}, {"user32.dll", "ReleaseDC", kOffWinReleaseDC},

    // user32: message loop. GetMessage returns 0 so the canonical
    // `while (GetMessage(...)) DispatchMessage(...)` loop sees
    // WM_QUIT on the first iteration and exits cleanly. PeekMessage
    // returns 0 (no message available) for the variant that spins.
    {"user32.dll", "GetMessageA", kOffGetMessageA}, {"user32.dll", "GetMessageW", kOffGetMessageA},
    {"user32.dll", "PeekMessageA", kOffPeekMessageA}, {"user32.dll", "PeekMessageW", kOffPeekMessageA},
    {"user32.dll", "DispatchMessageA", kOffDispatchMessageA}, {"user32.dll", "DispatchMessageW", kOffDispatchMessageA},
    {"user32.dll", "TranslateMessage", kOffPinReturn0}, {"user32.dll", "TranslateAcceleratorA", kOffPinReturn0},
    {"user32.dll", "TranslateAcceleratorW", kOffPinReturn0}, {"user32.dll", "PostMessageA", kOffPinReturn1},
    {"user32.dll", "PostMessageW", kOffPinReturn1}, {"user32.dll", "SendMessageA", kOffPinReturn0},
    {"user32.dll", "SendMessageW", kOffPinReturn0}, {"user32.dll", "PostQuitMessage", kOffPinReturn0},
    {"user32.dll", "PostThreadMessageA", kOffPinReturn1}, {"user32.dll", "PostThreadMessageW", kOffPinReturn1},

    // user32: resource loaders — fake non-zero HICON/HCURSOR/HBITMAP.
    {"user32.dll", "LoadIconA", kOffPinReturn1}, {"user32.dll", "LoadIconW", kOffPinReturn1},
    {"user32.dll", "LoadCursorA", kOffPinReturn1}, {"user32.dll", "LoadCursorW", kOffPinReturn1},
    {"user32.dll", "LoadImageA", kOffPinReturn1}, {"user32.dll", "LoadImageW", kOffPinReturn1},
    {"user32.dll", "LoadBitmapA", kOffPinReturn1}, {"user32.dll", "LoadBitmapW", kOffPinReturn1},
    {"user32.dll", "LoadMenuA", kOffPinReturn1}, {"user32.dll", "LoadMenuW", kOffPinReturn1},
    {"user32.dll", "LoadAcceleratorsA", kOffPinReturn1}, {"user32.dll", "LoadAcceleratorsW", kOffPinReturn1},
    {"user32.dll", "LoadStringA", kOffPinReturn0}, {"user32.dll", "LoadStringW", kOffPinReturn0},

    // user32: cursor + caret + misc — most callers treat non-zero
    // as "ok, previous state returned".
    {"user32.dll", "SetCursor", kOffPinReturn0}, {"user32.dll", "ShowCursor", kOffPinReturn0},
    {"user32.dll", "GetCursorPos", kOffPinReturn1}, {"user32.dll", "SetCursorPos", kOffPinReturn1},
    {"user32.dll", "ClipCursor", kOffPinReturn1}, {"user32.dll", "GetSystemMetrics", kOffPinReturn0},
    {"user32.dll", "MessageBoxA", kOffPinReturn1}, {"user32.dll", "MessageBoxW", kOffPinReturn1},
    {"user32.dll", "MessageBoxExA", kOffPinReturn1}, {"user32.dll", "MessageBoxExW", kOffPinReturn1},

    // gdi32: device contexts — DC-less entry points still return a
    // non-zero fake handle; CreateCompatibleDC / DeleteDC go through
    // the real GDI object table so memory DCs are real.
    {"gdi32.dll", "GetDC", kOffPinReturn1}, {"gdi32.dll", "GetWindowDC", kOffPinReturn1},
    {"gdi32.dll", "ReleaseDC", kOffPinReturn1}, {"gdi32.dll", "CreateCompatibleDC", kOffGdiCreateCompatDC},
    {"gdi32.dll", "DeleteDC", kOffGdiDeleteDC}, {"gdi32.dll", "SaveDC", kOffPinReturn1},
    {"gdi32.dll", "RestoreDC", kOffPinReturn1},

    // gdi32: object table — real handle registry. SelectObject
    // tracks the currently-selected HBITMAP per memory DC; stock
    // + solid brushes live in the brush registry.
    {"gdi32.dll", "SelectObject", kOffGdiSelectObject}, {"gdi32.dll", "DeleteObject", kOffGdiDeleteObject},
    {"gdi32.dll", "GetStockObject", kOffGdiGetStockObject}, {"gdi32.dll", "GetObjectA", kOffPinReturn1},
    {"gdi32.dll", "GetObjectW", kOffPinReturn1},

    // gdi32: bitmap + brush creation. CompatibleBitmap + SolidBrush
    // allocate real kernel state; the rest remain dummies until we
    // need them.
    {"gdi32.dll", "CreateBitmap", kOffPinReturn1}, {"gdi32.dll", "CreateCompatibleBitmap", kOffGdiCreateCompatBmp},
    {"gdi32.dll", "CreateDIBitmap", kOffPinReturn1}, {"gdi32.dll", "CreateDIBSection", kOffPinReturn1},
    {"gdi32.dll", "CreateSolidBrush", kOffGdiCreateSolidBrush}, {"gdi32.dll", "CreateBrushIndirect", kOffPinReturn1},
    {"gdi32.dll", "CreatePen", kOffGdiCreatePen}, {"gdi32.dll", "CreateFontA", kOffPinReturn1},
    {"gdi32.dll", "CreateFontW", kOffPinReturn1}, {"gdi32.dll", "CreateFontIndirectA", kOffPinReturn1},
    {"gdi32.dll", "CreateFontIndirectW", kOffPinReturn1},

    // gdi32: drawing primitives — all boolean, return TRUE so the
    // caller's "draw succeeded" flag is set.
    {"gdi32.dll", "BitBlt", kOffGdiBitBltDC}, {"gdi32.dll", "StretchBlt", kOffGdiStretchBltDC},
    {"gdi32.dll", "MoveToEx", kOffGdiMoveToEx}, {"gdi32.dll", "LineTo", kOffGdiLineTo},
    // Rectangle / Ellipse now default to the filled variants (which
    // match Win32's fill-with-current-brush + outline-with-current-
    // pen semantics). The outline-only offsets stay around for
    // callers that want them explicitly.
    {"gdi32.dll", "Rectangle", kOffGdiRectangleFilled}, {"gdi32.dll", "Ellipse", kOffGdiEllipseFilled},
    {"gdi32.dll", "SetPixel", kOffGdiSetPixel}, {"gdi32.dll", "SetPixelV", kOffGdiSetPixel},
    {"gdi32.dll", "PatBlt", kOffGdiPatBlt}, {"gdi32.dll", "Polygon", kOffPinReturn1},
    {"gdi32.dll", "Polyline", kOffPinReturn1},
    // FillRect is technically a user32 export (not gdi32) in real
    // Windows, but we honour whichever DLL a PE imports it from.
    {"gdi32.dll", "FillRect", kOffGdiFillRectUser}, {"user32.dll", "FillRect", kOffGdiFillRectUser},
    {"gdi32.dll", "FrameRect", kOffPinReturn1}, {"gdi32.dll", "TextOutA", kOffGdiTextOutA},
    {"gdi32.dll", "TextOutW", kOffGdiTextOutW}, {"gdi32.dll", "ExtTextOutA", kOffPinReturn1},
    {"gdi32.dll", "ExtTextOutW", kOffPinReturn1}, {"gdi32.dll", "DrawTextA", kOffGdiDrawTextA},
    {"user32.dll", "DrawTextA", kOffGdiDrawTextA}, {"gdi32.dll", "DrawTextW", kOffGdiDrawTextW},
    {"user32.dll", "DrawTextW", kOffGdiDrawTextW}, {"gdi32.dll", "SetBkMode", kOffGdiSetBkMode},
    {"gdi32.dll", "SetBkColor", kOffGdiSetBkColor}, {"gdi32.dll", "SetTextColor", kOffGdiSetTextColor},
    {"gdi32.dll", "SetMapMode", kOffPinReturn1}, {"gdi32.dll", "SetTextAlign", kOffPinReturn0},

    // -----------------------------------------------------------------
    // Real stubs for pointer-output time APIs — the ones
    // deliberately skipped by the prior GUI bindings because a 0/1
    // return leaves their caller-allocated output struct
    // uninitialised. These bridge Win64 ABI -> int 0x80 with the
    // new SYS_GETTIME_ST / SYS_ST_TO_FT / SYS_FT_TO_ST syscalls
    // (40..42).
    // -----------------------------------------------------------------
    {"kernel32.dll", "GetSystemTime", kOffGetSystemTimeSt}, {"kernel32.dll", "GetLocalTime", kOffGetSystemTimeSt},
    {"kernel32.dll", "SystemTimeToFileTime", kOffSystemTimeToFileTime},
    {"kernel32.dll", "FileTimeToSystemTime", kOffFileTimeToSystemTime},

    // -----------------------------------------------------------------
    // Batched NO-OP routings.
    //
    // Every entry below points an unresolved import surfaced by a
    // real-world Windows PE bring-up (7-Zip 23.01, busybox-w32,
    // NASM 2.16.03) at the closest-shape constant returner so the
    // catch-all NO-OP / data-miss zero pad doesn't fire. The
    // semantics are wrong-but-not-fatal: the program sees a plausible
    // success/failure value, the runtime doesn't crash trying to
    // dereference a NULL function pointer or a stub-page address.
    //
    // What "closest shape" means in practice:
    //   - kOffReturnZero  -> BOOL FALSE / DWORD 0 / handle-NULL / errcode 0
    //                        (success codes for "not found" / "no events").
    //                        Also for `void` returns where the contract
    //                        says nothing about the return register.
    //   - kOffReturnOne   -> BOOL TRUE  / DWORD 1 / "yes I did it".
    //   - kOffReturnMinus1-> -1 / EOF / INVALID_HANDLE_VALUE / SOCKET_ERROR.
    //   - kOffReturnTwo   -> 2  (ERROR_FILE_NOT_FOUND).
    //   - kOffStrcmp      -> case-sensitive substitute for stricmp/strnicmp
    //                        (different semantics; works for ASCII compares
    //                        that happen to match case).
    //   - kOffPErrno      -> returns proc-env writable scratch — used for
    //                        any `__p_*` / `__acrt_iob_func` accessor whose
    //                        callers do `*p = value` or `value = *p`.
    //   - kOffCritSecNop  -> bare `ret` for void-returning init/teardown
    //                        helpers whose sole job is bookkeeping.
    //
    // Promote any entry to a real thunk the moment a real consumer
    // depends on the actual semantics. Everything here is "shaped
    // like the truth"; nothing here is the truth.
    // -----------------------------------------------------------------

    // ---- KERNEL32 file / directory / volume ----
    {"kernel32.dll", "AreFileApisANSI", kOffPinReturn1},    // ANSI assumed
    {"kernel32.dll", "CreateFileA", kOffReturnMinus1},      // INVALID_HANDLE_VALUE
    {"kernel32.dll", "CreateFileW", kOffReturnMinus1},      // belt-and-suspenders
    {"kernel32.dll", "FindFirstFileExW", kOffReturnMinus1}, // INVALID_HANDLE_VALUE
    {"kernel32.dll", "FindFirstFileExA", kOffReturnMinus1}, {"kernel32.dll", "FindResourceW", kOffPinReturn0},
    {"kernel32.dll", "FindResourceA", kOffPinReturn0}, {"kernel32.dll", "FindResourceExW", kOffPinReturn0},
    {"kernel32.dll", "FindVolumeClose", kOffPinReturn1}, {"kernel32.dll", "FindFirstVolumeW", kOffReturnMinus1},
    {"kernel32.dll", "FindNextVolumeW", kOffPinReturn0},
    {"kernel32.dll", "GetCompressedFileSizeA", kOffReturnMinus1}, // INVALID_FILE_SIZE
    {"kernel32.dll", "GetCompressedFileSizeW", kOffReturnMinus1},
    {"kernel32.dll", "GetDiskFreeSpaceExA", kOffPinReturn1}, {"kernel32.dll", "GetDiskFreeSpaceA", kOffPinReturn1},
    {"kernel32.dll", "GetFileAttributesExA", kOffPinReturn0}, {"kernel32.dll", "GetFileAttributesExW", kOffPinReturn0},
    {"kernel32.dll", "GetFullPathNameA", kOffPinReturn0}, // 0 = caller's buf too small / error
    {"kernel32.dll", "GetVolumeInformationA", kOffPinReturn1},
    {"kernel32.dll", "GetVolumeInformationW", kOffPinReturn1}, {"kernel32.dll", "MoveFileExA", kOffPinReturn1},
    {"kernel32.dll", "MoveFileExW", kOffPinReturn1}, {"kernel32.dll", "MoveFileA", kOffPinReturn1},
    {"kernel32.dll", "ReadDirectoryChangesW", kOffPinReturn0},
    {"kernel32.dll", "DeviceIoControl", kOffPinReturn0}, // FALSE — not supported
    {"kernel32.dll", "SetFileTime", kOffPinReturn1}, {"kernel32.dll", "SetSystemTime", kOffPinReturn1},
    {"kernel32.dll", "SizeofResource", kOffPinReturn0}, {"kernel32.dll", "LoadResource", kOffPinReturn0},
    {"kernel32.dll", "LockResource", kOffPinReturn0}, {"kernel32.dll", "VirtualLock", kOffPinReturn1},
    {"kernel32.dll", "VirtualUnlock", kOffPinReturn1}, {"kernel32.dll", "HeapCompact", kOffPinReturn0},

    // ---- KERNEL32 console alt-screen-buffer / input ----
    {"kernel32.dll", "CreateConsoleScreenBuffer", kOffReturnMinus1},
    {"kernel32.dll", "FlushConsoleInputBuffer", kOffPinReturn1}, {"kernel32.dll", "ReadConsoleInputA", kOffPinReturn0},
    {"kernel32.dll", "ReadConsoleInputW", kOffPinReturn0}, {"kernel32.dll", "ReadConsoleA", kOffPinReturn0},
    {"kernel32.dll", "ReadConsoleW", kOffPinReturn0}, {"kernel32.dll", "SetConsoleActiveScreenBuffer", kOffPinReturn1},
    {"kernel32.dll", "SetConsoleScreenBufferSize", kOffPinReturn1},
    {"kernel32.dll", "SetConsoleCursorPosition", kOffPinReturn1},
    {"kernel32.dll", "SetConsoleTextAttribute", kOffPinReturn1},
    {"kernel32.dll", "FillConsoleOutputAttribute", kOffPinReturn1},
    {"kernel32.dll", "FillConsoleOutputCharacterA", kOffPinReturn1},
    {"kernel32.dll", "FillConsoleOutputCharacterW", kOffPinReturn1},
    {"kernel32.dll", "GetNumberOfConsoleInputEvents", kOffPinReturn1},

    // ---- KERNEL32 misc helpers ----
    // IsBadXPtr family: pin "not bad" (0). v0 has no way to probe
    // a pointer without faulting, so the safe documented answer is
    // 0 — a real bad dereference faults cleanly at the next access.
    // (Microsoft has deprecated this family for the same reason.)
    {"kernel32.dll", "IsBadWritePtr", kOffPinBadPtrSafe}, // FALSE — pointer is good
    {"kernel32.dll", "IsBadReadPtr", kOffPinBadPtrSafe}, {"kernel32.dll", "IsBadStringPtrA", kOffPinBadPtrSafe},
    {"kernel32.dll", "IsBadStringPtrW", kOffPinBadPtrSafe}, {"kernel32.dll", "IsBadCodePtr", kOffPinBadPtrSafe},
    {"kernel32.dll", "ReadProcessMemory", kOffPinReturn0},  // FALSE — not allowed
    {"kernel32.dll", "WriteProcessMemory", kOffPinReturn0}, // FALSE — not allowed
    {"kernel32.dll", "MsgWaitForMultipleObjects", kOffPinReturn0},
    {"kernel32.dll", "MsgWaitForMultipleObjectsEx", kOffPinReturn0},

    // ---- KERNEL32 file-pointer (legacy form). The 64-bit form
    //      kOffSetFilePtrEx is real; the 32-bit form returns the
    //      low-DWORD-of-position. Returning 0 = "rewind to start".
    {"kernel32.dll", "SetFilePointer", kOffPinReturn0},

    // ---- ADVAPI32 security / token / event tracing ----
    {"advapi32.dll", "AccessCheck", kOffPinReturn1}, // grant access
    {"advapi32.dll", "CheckTokenMembership", kOffPinReturn1},
    {"advapi32.dll", "OpenServiceW", kOffPinReturn0}, // NULL handle
    {"advapi32.dll", "OpenServiceA", kOffPinReturn0},
    {"advapi32.dll", "GetSecurityInfo", kOffPinReturn0}, // ERROR_SUCCESS
    {"advapi32.dll", "SetSecurityInfo", kOffPinReturn0},
    {"advapi32.dll", "RegFlushKey", kOffPinReturn0}, // ERROR_SUCCESS
    {"advapi32.dll", "SaferComputeTokenFromLevel", kOffPinReturn0},
    {"advapi32.dll", "SaferCreateLevel", kOffPinReturn0}, {"advapi32.dll", "SaferCloseLevel", kOffPinReturn1},
    {"advapi32.dll", "EventRegister", kOffPinReturn0}, // ERROR_SUCCESS
    {"advapi32.dll", "EventUnregister", kOffPinReturn0}, {"advapi32.dll", "EventWrite", kOffPinReturn0},
    {"advapi32.dll", "EventWriteTransfer", kOffPinReturn0}, {"advapi32.dll", "EventEnabled", kOffPinReturn0}, // FALSE
    {"advapi32.dll", "EventActivityIdControl", kOffPinReturn0},
    {"advapi32.dll", "CryptAcquireContextA", kOffPinReturn0}, // FALSE — no provider
    {"advapi32.dll", "CryptReleaseContext", kOffPinReturn1}, {"advapi32.dll", "CryptCreateHash", kOffPinReturn0},
    {"advapi32.dll", "CryptDestroyHash", kOffPinReturn1}, {"advapi32.dll", "CryptHashData", kOffPinReturn0},
    {"advapi32.dll", "CryptGetHashParam", kOffPinReturn0},

    // ---- USER32 query / clipboard / window state ----
    {"user32.dll", "AnyPopup", kOffPinReturn0},                                                // FALSE
    {"user32.dll", "BlockInput", kOffPinReturn0}, {"user32.dll", "GetCursor", kOffPinReturn0}, // NULL
    {"user32.dll", "GetSystemMenu", kOffPinReturn0}, {"user32.dll", "IsClipboardFormatAvailable", kOffPinReturn0},
    {"user32.dll", "CountClipboardFormats", kOffPinReturn0}, {"user32.dll", "EnumClipboardFormats", kOffPinReturn0},
    {"user32.dll", "IsWindowEnabled", kOffPinReturn1}, {"user32.dll", "IsWindowVisible", kOffPinReturn1},
    {"user32.dll", "IsIconic", kOffPinReturn0}, {"user32.dll", "IsZoomed", kOffPinReturn0},
    {"user32.dll", "EnableWindow", kOffPinReturn0}, // returns prior state = FALSE
    {"user32.dll", "FlashWindow", kOffPinReturn0}, {"user32.dll", "FlashWindowEx", kOffPinReturn0},

    // ---- WS2_32 socket events / async ----
    {"ws2_32.dll", "WSAEnumNetworkEvents", kOffPinReturn0}, // success, no events
    {"ws2_32.dll", "WSAEventSelect", kOffPinReturn0}, {"ws2_32.dll", "WSAAsyncSelect", kOffPinReturn0},
    {"ws2_32.dll", "WSASocketA", kOffReturnMinus1}, // INVALID_SOCKET
    {"ws2_32.dll", "WSASocketW", kOffReturnMinus1}, {"ws2_32.dll", "WSAWaitForMultipleEvents", kOffPinReturn0},
    {"ws2_32.dll", "WSARecv", kOffPinReturn0}, {"ws2_32.dll", "WSASend", kOffPinReturn0},

    // ---- GDIPLUS lifecycle (no real GDI+) ----
    {"gdiplus.dll", "GdiplusStartup", kOffPinReturn0}, // Status::Ok
    {"gdiplus.dll", "GdiplusShutdown", kOffPinVoidNop},

    // ---- SHLWAPI string helpers ----
    {"shlwapi.dll", "StrCmpIW", kOffStrcmp}, // case-sensitive substitute
    {"shlwapi.dll", "StrCmpIA", kOffStrcmp}, {"shlwapi.dll", "StrCmpNIW", kOffStrcmp},
    {"shlwapi.dll", "StrCmpNIA", kOffStrcmp},

    // ---- UXTHEME (we have no theming engine) ----
    {"uxtheme.dll", "GetThemeAppProperties", kOffPinReturn0}, {"uxtheme.dll", "SetThemeAppProperties", kOffPinVoidNop},
    {"uxtheme.dll", "BufferedPaintInit", kOffPinReturn0}, {"uxtheme.dll", "BufferedPaintUnInit", kOffPinReturn0},

    // ---- UCRT data accessors (`__p_*`) — return scratch ptr.
    //      Callers do `*__p_xxx() = value;` (write) or
    //      `value = *__p_xxx();` (read) — both work against the
    //      shared proc-env writable pad.
    {"api-ms-win-crt-runtime-l1-1-0.dll", "__p__fmode", kOffPErrno},
    {"api-ms-win-crt-runtime-l1-1-0.dll", "__p__commode", kOffPCommode}, // real slot
    {"api-ms-win-crt-runtime-l1-1-0.dll", "__p__environ", kOffPErrno},
    {"api-ms-win-crt-runtime-l1-1-0.dll", "__p__wenviron", kOffPErrno},
    {"api-ms-win-crt-runtime-l1-1-0.dll", "__p___argc", kOffPArgc},
    {"api-ms-win-crt-runtime-l1-1-0.dll", "__p___argv", kOffPArgv},
    {"api-ms-win-crt-runtime-l1-1-0.dll", "__p___wargv", kOffPErrno}, {"ucrtbase.dll", "__p__fmode", kOffPErrno},
    {"ucrtbase.dll", "__p__environ", kOffPErrno}, {"ucrtbase.dll", "__p__wenviron", kOffPErrno},
    {"ucrtbase.dll", "__p___wargv", kOffPErrno}, {"msvcrt.dll", "__p__fmode", kOffPErrno},
    {"msvcrt.dll", "__p__environ", kOffPErrno}, {"msvcrt.dll", "__p__wenviron", kOffPErrno},
    {"msvcrt.dll", "__p___wargv", kOffPErrno},
    // __acrt_iob_func(idx) -> FILE*. We hand back the writable pad;
    // callers' fwrite(stream, ...) ends up storing transient buf-ptr
    // state in scratch, then our fwrite/fputs thunks ignore the FILE*
    // entirely and write to fd=1 directly.
    {"api-ms-win-crt-stdio-l1-1-0.dll", "__acrt_iob_func", kOffPErrno}, {"ucrtbase.dll", "__acrt_iob_func", kOffPErrno},
    // ___mb_cur_max_func returns int (= 1 in v0 single-byte locale).
    {"api-ms-win-crt-locale-l1-1-0.dll", "___mb_cur_max_func", kOffPinReturn1},
    {"ucrtbase.dll", "___mb_cur_max_func", kOffPinReturn1}, {"msvcrt.dll", "___mb_cur_max_func", kOffPinReturn1},
    {"msvcrt.dll", "__mb_cur_max_func", kOffPinReturn1},

    // ---- UCRT formatted I/O (real impl deferred — see plan) ----
    // __stdio_common_vfprintf(opts, stream, fmt, locale, va_list)
    // returns count written. We can't format yet; return 0 ("wrote 0").
    {"api-ms-win-crt-stdio-l1-1-0.dll", "__stdio_common_vfprintf", kOffPinReturn0},
    {"api-ms-win-crt-stdio-l1-1-0.dll", "__stdio_common_vfwprintf", kOffPinReturn0},
    {"api-ms-win-crt-stdio-l1-1-0.dll", "__stdio_common_vsprintf", kOffPinReturn0},
    {"api-ms-win-crt-stdio-l1-1-0.dll", "__stdio_common_vsnprintf_s", kOffPinReturn0},
    {"api-ms-win-crt-stdio-l1-1-0.dll", "__stdio_common_vsscanf", kOffPinReturn0},
    {"ucrtbase.dll", "__stdio_common_vfprintf", kOffPinReturn0},
    {"ucrtbase.dll", "__stdio_common_vfwprintf", kOffPinReturn0},

    // ---- UCRT stdio / file handle helpers ----
    {"api-ms-win-crt-stdio-l1-1-0.dll", "_chsize_s", kOffPinReturn0},
    {"api-ms-win-crt-stdio-l1-1-0.dll", "_fileno", kOffReturnMinus1},
    {"api-ms-win-crt-stdio-l1-1-0.dll", "_fseeki64", kOffPinReturn0},
    {"api-ms-win-crt-stdio-l1-1-0.dll", "_ftelli64", kOffReturnMinus1},
    {"api-ms-win-crt-stdio-l1-1-0.dll", "_setmode", kOffPinReturn0}, // returns prior mode (= 0 = O_TEXT)
    {"api-ms-win-crt-stdio-l1-1-0.dll", "ungetc", kOffReturnMinus1},
    {"api-ms-win-crt-stdio-l1-1-0.dll", "setvbuf", kOffPinReturn0}, // 0 success
    {"api-ms-win-crt-stdio-l1-1-0.dll", "_lock_file", kOffPinVoidNop},
    {"api-ms-win-crt-stdio-l1-1-0.dll", "_unlock_file", kOffPinVoidNop},
    {"api-ms-win-crt-stdio-l1-1-0.dll", "_wfopen", kOffPinReturn0},
    {"api-ms-win-crt-stdio-l1-1-0.dll", "fgets", kOffPinReturn0}, {"ucrtbase.dll", "_fileno", kOffReturnMinus1},
    {"ucrtbase.dll", "_fseeki64", kOffPinReturn0}, {"ucrtbase.dll", "_ftelli64", kOffReturnMinus1},
    {"ucrtbase.dll", "_setmode", kOffPinReturn0}, {"ucrtbase.dll", "_wfopen", kOffPinReturn0},

    // ---- UCRT runtime / abort / errno / FP state ----
    {"api-ms-win-crt-runtime-l1-1-0.dll", "abort", kOffTerminate},
    {"api-ms-win-crt-runtime-l1-1-0.dll", "_set_invalid_parameter_handler", kOffPinReturn0},
    {"api-ms-win-crt-runtime-l1-1-0.dll", "_get_invalid_parameter_handler", kOffPinReturn0},
    {"api-ms-win-crt-runtime-l1-1-0.dll", "_clearfp", kOffPinReturn0},
    {"api-ms-win-crt-runtime-l1-1-0.dll", "_statusfp", kOffPinReturn0},
    {"api-ms-win-crt-runtime-l1-1-0.dll", "_controlfp", kOffPinReturn0},
    {"api-ms-win-crt-runtime-l1-1-0.dll", "_controlfp_s", kOffPinReturn0},
    {"api-ms-win-crt-runtime-l1-1-0.dll", "_crt_at_quick_exit", kOffPinReturn0},
    {"api-ms-win-crt-runtime-l1-1-0.dll", "_configure_wide_argv", kOffPinReturn0},
    {"api-ms-win-crt-runtime-l1-1-0.dll", "_initialize_wide_environment", kOffPinReturn0},
    {"api-ms-win-crt-runtime-l1-1-0.dll", "_get_initial_wide_environment", kOffPinReturn0},
    {"api-ms-win-crt-runtime-l1-1-0.dll", "__C_specific_handler", kOffPinReturn0}, // ExceptionContinueSearch
    {"ucrtbase.dll", "abort", kOffTerminate}, {"ucrtbase.dll", "_set_invalid_parameter_handler", kOffPinReturn0},
    {"ucrtbase.dll", "_clearfp", kOffPinReturn0}, {"ucrtbase.dll", "_statusfp", kOffPinReturn0},
    {"ucrtbase.dll", "__C_specific_handler", kOffPinReturn0},
    {"vcruntime140.dll", "__C_specific_handler", kOffPinReturn0}, {"msvcrt.dll", "abort", kOffTerminate},
    {"msvcrt.dll", "_set_invalid_parameter_handler", kOffPinReturn0}, {"msvcrt.dll", "_clearfp", kOffPinReturn0},
    {"msvcrt.dll", "_statusfp", kOffPinReturn0}, {"msvcrt.dll", "_controlfp", kOffPinReturn0},

    // ---- UCRT string helpers (case-insensitive -> case-sensitive sub) ----
    {"api-ms-win-crt-string-l1-1-0.dll", "_stricmp", kOffStrcmp},
    {"api-ms-win-crt-string-l1-1-0.dll", "_strnicmp", kOffStrcmp},
    {"api-ms-win-crt-string-l1-1-0.dll", "_wcsicmp", kOffStrcmp},
    {"api-ms-win-crt-string-l1-1-0.dll", "_wcsnicmp", kOffStrcmp}, {"ucrtbase.dll", "_stricmp", kOffStrcmp},
    {"ucrtbase.dll", "_strnicmp", kOffStrcmp}, {"msvcrt.dll", "_stricmp", kOffStrcmp},
    {"msvcrt.dll", "_strnicmp", kOffStrcmp},

    // ---- UCRT character classifiers (ctype). All return 0 = "not in
    //      class". Lossy for parsers that want isspace/isalpha; safe
    //      for code that uses them as filters that will call other
    //      thunks downstream.
    {"api-ms-win-crt-string-l1-1-0.dll", "isalpha", kOffPinReturn0},
    {"api-ms-win-crt-string-l1-1-0.dll", "iscntrl", kOffPinReturn0},
    {"api-ms-win-crt-string-l1-1-0.dll", "ispunct", kOffPinReturn0},
    {"api-ms-win-crt-string-l1-1-0.dll", "isspace", kOffPinReturn0},
    {"api-ms-win-crt-string-l1-1-0.dll", "isxdigit", kOffPinReturn0},
    {"api-ms-win-crt-string-l1-1-0.dll", "isalnum", kOffPinReturn0},
    {"api-ms-win-crt-string-l1-1-0.dll", "isdigit", kOffPinReturn0},
    {"api-ms-win-crt-string-l1-1-0.dll", "islower", kOffPinReturn0},
    {"api-ms-win-crt-string-l1-1-0.dll", "isupper", kOffPinReturn0},
    {"api-ms-win-crt-string-l1-1-0.dll", "isprint", kOffPinReturn0},
    {"api-ms-win-crt-string-l1-1-0.dll", "tolower", kOffPinReturn0},
    {"api-ms-win-crt-string-l1-1-0.dll", "toupper", kOffPinReturn0},
    {"api-ms-win-crt-string-l1-1-0.dll", "iswalpha", kOffPinReturn0},
    {"api-ms-win-crt-string-l1-1-0.dll", "iswspace", kOffPinReturn0},
    {"api-ms-win-crt-string-l1-1-0.dll", "iswdigit", kOffPinReturn0},

    // ---- UCRT environment / time ----
    {"api-ms-win-crt-environment-l1-1-0.dll", "getenv", kOffPinReturn0}, // NULL — env var not found
    {"api-ms-win-crt-environment-l1-1-0.dll", "_wgetenv", kOffPinReturn0},
    {"api-ms-win-crt-environment-l1-1-0.dll", "_putenv", kOffPinReturn0}, {"ucrtbase.dll", "getenv", kOffPinReturn0},
    {"msvcrt.dll", "getenv", kOffPinReturn0}, {"api-ms-win-crt-time-l1-1-0.dll", "_time64", kOffPinReturn0}, // epoch 0
    {"api-ms-win-crt-time-l1-1-0.dll", "_gmtime64", kOffPinReturn0},
    {"api-ms-win-crt-time-l1-1-0.dll", "_localtime64", kOffPinReturn0},
    {"api-ms-win-crt-time-l1-1-0.dll", "_tzset", kOffPinVoidNop},
    {"api-ms-win-crt-time-l1-1-0.dll", "clock", kOffPinReturn0},

    // ---- UCRT filesystem / stat ----
    {"api-ms-win-crt-filesystem-l1-1-0.dll", "_waccess", kOffReturnMinus1},
    {"api-ms-win-crt-filesystem-l1-1-0.dll", "_access", kOffReturnMinus1},
    {"api-ms-win-crt-filesystem-l1-1-0.dll", "_wstat64", kOffReturnMinus1},
    {"api-ms-win-crt-filesystem-l1-1-0.dll", "_stat64", kOffReturnMinus1},
    {"api-ms-win-crt-filesystem-l1-1-0.dll", "_fstat64", kOffReturnMinus1},
    {"api-ms-win-crt-filesystem-l1-1-0.dll", "_fullpath", kOffPinReturn0},
    {"api-ms-win-crt-filesystem-l1-1-0.dll", "_unlink", kOffReturnMinus1},
    {"api-ms-win-crt-filesystem-l1-1-0.dll", "_wunlink", kOffReturnMinus1},
    {"api-ms-win-crt-filesystem-l1-1-0.dll", "remove", kOffReturnMinus1},

    // ---- UCRT private (locale internals) ----
    {"api-ms-win-crt-private-l1-1-0.dll", "_initialize_onexit_table", kOffPinReturn0},
    {"api-ms-win-crt-private-l1-1-0.dll", "_register_onexit_function", kOffPinReturn0},
    {"api-ms-win-crt-private-l1-1-0.dll", "_execute_onexit_table", kOffPinReturn0},
    {"api-ms-win-crt-locale-l1-1-0.dll", "localeconv", kOffPinReturn0},
    {"api-ms-win-crt-locale-l1-1-0.dll", "setlocale", kOffPinReturn0},
    {"api-ms-win-crt-locale-l1-1-0.dll", "_create_locale", kOffPinReturn0},
    {"api-ms-win-crt-locale-l1-1-0.dll", "_free_locale", kOffPinVoidNop},

    // ---- UCRT convert (atoi etc — already handled for msvcrt) ----
    {"api-ms-win-crt-convert-l1-1-0.dll", "atoi", kOffPinReturn0},
    {"api-ms-win-crt-convert-l1-1-0.dll", "atol", kOffPinReturn0},
    {"api-ms-win-crt-convert-l1-1-0.dll", "atoll", kOffPinReturn0},
    {"api-ms-win-crt-convert-l1-1-0.dll", "strtol", kOffPinReturn0},
    {"api-ms-win-crt-convert-l1-1-0.dll", "strtoul", kOffStrtoulNoop},
    {"api-ms-win-crt-convert-l1-1-0.dll", "strtoll", kOffPinReturn0},
    {"api-ms-win-crt-convert-l1-1-0.dll", "strtoull", kOffPinReturn0},
    {"api-ms-win-crt-convert-l1-1-0.dll", "wcstol", kOffPinReturn0},
    {"api-ms-win-crt-convert-l1-1-0.dll", "_atoi64", kOffPinReturn0},

    // ---- UCRT utility / heap details ----
    {"api-ms-win-crt-utility-l1-1-0.dll", "qsort", kOffPinVoidNop}, // pretend "sorted in-place"
    {"api-ms-win-crt-heap-l1-1-0.dll", "_msize", kOffPinReturn0}, {"ucrtbase.dll", "_msize", kOffPinReturn0},
    {"msvcrt.dll", "_msize", kOffPinReturn0}, {"api-ms-win-crt-heap-l1-1-0.dll", "_aligned_malloc", kOffMalloc},
    {"api-ms-win-crt-heap-l1-1-0.dll", "_aligned_free", kOffFree}, {"ucrtbase.dll", "_aligned_malloc", kOffMalloc},
    {"ucrtbase.dll", "_aligned_free", kOffFree},

    // ---- UCRT math (real engine deferred; constant returners) ----
    {"api-ms-win-crt-math-l1-1-0.dll", "_dclass", kOffPinReturn0}, // FP_NORMAL
    {"api-ms-win-crt-math-l1-1-0.dll", "_finite", kOffPinReturn1},
    {"api-ms-win-crt-math-l1-1-0.dll", "_isnan", kOffPinReturn0},

    // ---- UCRT runtime — wide-env helpers + alias names ----
    {"ucrtbase.dll", "_initterm", kOffInitterm}, {"ucrtbase.dll", "_initterm_e", kOffInittermE},
    {"ucrtbase.dll", "_register_thread_local_exe_atexit_callback", kOffRegThreadLocalAtexit},
    {"ucrtbase.dll", "_seh_filter_exe", kOffSehFilterExe},

    // ---- vcruntime140 — exception-handler aliases ----
    {"vcruntime140.dll", "_purecall", kOffTerminate}, // pure-virtual call -> abort
    {"vcruntime140.dll", "memchr", kOffPinReturn0},   // not-found
