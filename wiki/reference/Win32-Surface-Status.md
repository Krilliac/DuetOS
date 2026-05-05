# Win32 / DirectX Surface — Implementation Status

> **Audience:** anyone who wants to know "is X implemented?" or
> "what's the next thing to fill in?" — without grepping the tree.
>
> **Maturity:** living document. Every row is dated by the slice
> that last touched it. Update in the same commit as the work.

This document is the live inventory of what DuetOS ships on its
Windows-PE-facing surface, what's a real implementation vs. a
return-NULL stub, and what's missing entirely. It exists because
[`wiki/subsystems/Win32-DLLs.md`](../subsystems/Win32-DLLs.md)
catalogs the DLLs that exist, but doesn't drill into method-level
status — and we kept rediscovering "I thought we shipped that, but
it's a stub" the hard way.

## How to read this

Each DLL row has a one-line status, then per-feature drilldown.
Per-method status uses one of:

- **REAL** — body does the documented job for the v0 happy path
  (handles the cases the smoke PE / dx_demo exercises).
- **GAP: ...** — works for the happy path; one or more documented
  edge cases unimplemented. Usually paired with a `// GAP:` source
  marker.
- **STUB** — returns a constant / sentinel / wrong value. Real
  callers along the path WILL see incorrect behaviour. Usually
  paired with a `// STUB:` source marker.
- **MISSING** — not exported at all. Imports of this name would
  fail at PE load.

For COM-shaped DLLs we also list per-vtable-slot status, because
the export's job is to *return a COM object* and the user mostly
cares whether the methods work — not whether `D2D1CreateFactory`
itself returns success.

## How to update

When a slice lands real semantics behind something previously
marked STUB / GAP / MISSING:

1. Flip the row in this doc.
2. Update the smoke / dx_demo coverage if there's a new code path
   to verify.
3. If the slice removed an entire `// STUB:` or `// GAP:` source
   marker, the next session-start `git grep` will see the count
   drop — that's the cross-check.

When a slice ADDS a new DLL or new method:

1. Add the row here with the right status.
2. Surface it in the corresponding subsystem wiki page (`wiki/
   subsystems/Win32-DLLs.md` for shipping DLLs).

## Summary counts (2026-05-04)

- **Shipping DLLs:** 38 (Win32 user-mode + DirectX peripheral)
- **Approximate exports:** ~1100 across all shipping DLLs
- **Source LOC across `userland/libs/`:** ~38 000
- **Live STUB / GAP markers** (`git grep -nE "// (STUB|GAP):"`): 4
- **Win32 PE smoke coverage:** 127 PE smoke apps boot-tested per run

The marker count is a lower bound on known-stub paths — most stubs
are inline (one-liners that return E_NOTIMPL or zero-fill an out
parameter) and don't carry the marker. The doc below is the
authoritative list.

---

## 1. Foundation DLLs

### ntdll.dll  (~6 480 LOC, ~600 exports)

> **Status:** real backing for every primitive the Win32 NT layer
> calls, plus a wide layer of `NtReturnNotImpl` aliases for the
> rest of the canonical NT surface.

The strategic decision is "we own the NT syscall ABI for the calls
we route through, and we publish the names without behaviour for
the rest so PE imports always resolve." The kernel side
(`kernel/subsystems/win32/`) is the source of truth for which Nt*
calls have backing.

**Real implementations (selected):**
- `NtClose` / `NtYieldExecution` / `NtDelayExecution`
- `NtQueryPerformanceCounter`, `NtQuerySystemTime`
- `NtTerminateProcess`, `NtTerminateThread`, `NtContinue`
- `NtAllocateVirtualMemory`, `NtFreeVirtualMemory`,
  `NtProtectVirtualMemory`
- `NtCreateEvent` / `NtOpenEvent` / `NtSetEvent` /
  `NtResetEvent` / `NtWaitForSingleObject`
- `NtCreateMutant` / `NtOpenMutant` / `NtReleaseMutant`
- `NtOpenKey` / `NtOpenKeyEx` / `NtQueryValueKey` /
  `NtEnumerateKey` / `NtEnumerateValueKey`
- `NtOpenProcess`, `NtOpenThread`
- `RtlNtStatusToDosError`, `RtlInitUnicodeString`,
  `RtlEnterCriticalSection`, `RtlLeaveCriticalSection`,
  `RtlInitializeCriticalSection`,
  `RtlGetVersion`, `RtlGetCurrentDirectory_U`
- `__chkstk` (no-op — PeLoad maps the stack up front)

**STUB / NOT_IMPL (covered by `NtReturnNotImpl` alias chain):**
the long tail of NT (NtCreateFile, NtReadFile, NtWriteFile,
NtCreateSection, NtMapViewOfSection, the IoControl families,
the LPC/ALPC families, NtCreateUserProcess, NtCreateThreadEx,
the security-token families, NtAccessCheck, the WoW64 emulation
calls, every Tdh* / Etw* event-tracing call). Imports resolve;
calls return STATUS_NOT_IMPLEMENTED (0xC00000BB).

**Zw* aliases:** every Nt* exports a Zw* twin via the build
script's `/export:Zw…=Nt…` flag. PEs that import either name
land on the same body.

**Cross-reference:** see `kernel/subsystems/win32/nt_coverage.cpp`
for the kernel-side coverage table; the smoke test prints a final
"`[win32] ntdll bedrock coverage: N/M`" line so a regression in
syscall routing shows up immediately.

### kernel32.dll  (~5 080 LOC, ~320 exports)

> **Status:** the most mature Win32 DLL. Thread / process /
> file-handle / memory / timer / synchronization paths are real
> and exercised by the boot smoke.

**Real implementations:**
- File: `CreateFileA/W`, `ReadFile`, `WriteFile`,
  `SetFilePointer{,Ex}`, `GetFileSize{,Ex}`, `GetFileAttributes{A,W}`,
  `CloseHandle`, `FindFirstFileW`, `FindNextFileW`, `FindClose`,
  `GetCurrentDirectoryW`, `GetFullPathNameW`,
  `DeleteFileW`, `MoveFileExW`, `CopyFileW`,
  `CreateDirectoryW`, `RemoveDirectoryW`, `GetTempPathW`,
  `GetSystemDirectoryA/W`, `GetWindowsDirectoryW`
- Process: `GetCurrentProcess`, `GetCurrentProcessId`,
  `GetCurrentThreadId`, `ExitProcess`, `ExitThread`,
  `GetCommandLineA/W`, `GetEnvironmentVariableA/W`,
  `GetEnvironmentStringsW`, `FreeEnvironmentStringsW`,
  `GetSystemInfo`, `GetVersionExW`, `GetComputerNameW`,
  `GetUserNameA/W`, `GetStdHandle`, `WriteConsoleA/W`,
  `OutputDebugStringA/W`
- Threading: `CreateThread`, `WaitForSingleObject`,
  `WaitForMultipleObjects`, `Sleep`, `SleepEx`,
  `CreateEventW`, `SetEvent`, `ResetEvent`, `PulseEvent`,
  `CreateMutexW`, `ReleaseMutex`, `CreateSemaphoreW`,
  `ReleaseSemaphore`, `EnterCriticalSection`,
  `LeaveCriticalSection`, `InitializeCriticalSection`,
  `DeleteCriticalSection`, `TryEnterCriticalSection`,
  `InitializeSRWLock`, `AcquireSRWLockExclusive` /
  `Shared`, `ReleaseSRWLockExclusive` / `Shared`
- TLS: `TlsAlloc`, `TlsFree`, `TlsGetValue`, `TlsSetValue`
- Memory: `VirtualAlloc`, `VirtualFree`, `VirtualProtect`,
  `VirtualQuery`, `HeapCreate`, `HeapDestroy`, `HeapAlloc`,
  `HeapFree`, `HeapSize`, `HeapReAlloc`, `GetProcessHeap`,
  `GlobalAlloc`, `GlobalFree`, `GlobalLock`, `GlobalUnlock`,
  `LocalAlloc`, `LocalFree`
- Time: `GetTickCount`, `GetTickCount64`, `GetSystemTimeAsFileTime`,
  `QueryPerformanceCounter`, `QueryPerformanceFrequency`,
  `Sleep`, `GetSystemTime`, `GetLocalTime`,
  `SystemTimeToFileTime`, `FileTimeToSystemTime`,
  `FileTimeToLocalFileTime`, `LocalFileTimeToFileTime`
- Module: `LoadLibraryA/W`, `LoadLibraryExW`, `FreeLibrary`,
  `GetProcAddress`, `GetModuleHandleA/W`,
  `GetModuleFileNameA/W`, `GetModuleHandleExA/W`
- Codepage: `MultiByteToWideChar`, `WideCharToMultiByte`,
  `IsDBCSLeadByte`, `GetACP`, `GetOEMCP`, `GetCPInfo`,
  `IsValidCodePage`, `GetCPInfoExW`
- String: `lstrlenA/W`, `lstrcmpA/W`, `lstrcmpiA/W`,
  `lstrcpyA/W`, `lstrcatA/W`, `lstrcpynA/W`,
  `CompareStringW`, `CompareStringEx`,
  `CharLowerA/W`, `CharUpperA/W`,
  `IsCharAlphaA/W`, `IsCharAlphaNumericA/W`
- Registry-style: handled via advapi32 (this DLL forwards a few)
- Console: `WriteConsoleA/W`, `ReadConsoleA/W`,
  `GetConsoleMode`, `SetConsoleMode`,
  `GetStdHandle`, `SetStdHandle`,
  `AllocConsole`, `FreeConsole`, `AttachConsole`,
  `GetConsoleScreenBufferInfo` (basic),
  `SetConsoleTextAttribute`, `SetConsoleCursorPosition`

**STUB / GAP:**
- File: `LockFile`, `UnlockFile`, `LockFileEx`, `UnlockFileEx`
  return success without locking (no FS write contention in v0)
- Process: `CreateProcessA/W` is structurally working but
  `STARTUPINFO` is mostly ignored; `CreateProcessAsUserW` always
  fails (no token impersonation)
- IPC: `CreateNamedPipeW`, `ConnectNamedPipe`, anonymous pipe
  helpers — pipes work, named pipes are STUB
- Job objects (`CreateJobObjectW`, `SetInformationJobObject`,
  `AssignProcessToJobObject`) — STUB
- Fiber API (`CreateFiber`, `SwitchToFiber`, `DeleteFiber`)
  is GAP: switches but no per-fiber FLS
- Profiling (`QueryProcessCycleTime`, etc.) — STUB
- DPI awareness (`SetProcessDPIAware`, `GetDpiForSystem`) —
  return constant 96 DPI

### kernelbase.dll  (~17 LOC, single export)

Tiny shim — its real exports either forward to kernel32 (via the
linker) or expose primitives the OS uses internally. Not the
focus of any current slice.

### advapi32.dll  (~1 650 LOC, ~150 exports)

> **Status:** real registry, real ACL bookkeeping, real services
> facade. Auth crypto / LSA are stubs.

**Real implementations:**
- Registry (Reg*): `RegOpenKeyExA/W`, `RegOpenKeyExA`,
  `RegCloseKey`, `RegQueryValueExA/W`, `RegSetValueExA/W`,
  `RegEnumKeyExA/W`, `RegEnumValueA/W`, `RegQueryInfoKeyA/W`,
  `RegCreateKeyExW`, `RegDeleteKeyW`, `RegDeleteValueW`,
  `RegFlushKey`, `RegSaveKeyW`, `RegLoadKeyW`
- Token / SID basics: `OpenProcessToken`,
  `GetTokenInformation` (TokenUser / TokenStatistics),
  `LookupAccountSidA/W`, `ConvertSidToStringSidW`,
  `ConvertStringSidToSidW`, `IsValidSid`, `EqualSid`,
  `AllocateAndInitializeSid`, `FreeSid`,
  `GetLengthSid`, `CopySid`
- ACL/security descriptor scaffolding: real layout, queries
  return canned ACL bits. `SetSecurityDescriptorOwner` etc.
  store but don't enforce.
- Event log facade: `RegisterEventSourceA/W`,
  `DeregisterEventSource`, `ReportEventA/W` —
  collect in serial log, no real EVTX.
- Service control:
  `OpenSCManagerA/W`, `CloseServiceHandle`,
  `OpenServiceA/W`, `QueryServiceStatus{,Ex}`,
  `EnumServicesStatusA/W`,
  `StartServiceA/W`, `ControlService` —
  read against the in-kernel service registry; writes log but
  don't actually start services.
- BCrypt-equivalents: `CryptAcquireContextA/W`,
  `CryptGenRandom` — back into bcrypt's RNG.

**STUB / GAP:**
- LSA: `LsaOpenPolicy`, `LsaQueryInformationPolicy`,
  `LsaLookupSids`, `LsaLookupNames` — all STUB
- Security: `AccessCheck`, `PrivilegeCheck` always return
  ALLOWED — STUB (kCap* gating in the kernel is the real check)
- Crypto containers: `CryptCreateHash` (advapi-side,
  legacy CAPI) — GAP for non-SHA2 algorithms
- Eventing: `EvtOpenLog`, `EvtNext`, etc. — STUB
- WMI client: every Wmi* call — STUB

### msvcrt.dll  (~860 LOC, ~150 exports)

> **Status:** the C runtime functions PE binaries actually link
> against. Exit / heap / stdio / string / time work; floating
> point and locale are stubbed-or-minimal.

**Real implementations:**
- Lifecycle: `_initterm`, `_initterm_e`,
  `__C_specific_handler` (no-op return),
  `_amsg_exit`, `_set_app_type`, `__wgetmainargs`,
  `__set_app_type`, `_cexit`, `exit`, `_exit`
- Heap: `malloc`, `calloc`, `realloc`, `free`,
  `_msize`, `_aligned_malloc`, `_aligned_free`
- String: `strlen`, `strcmp`, `strncmp`, `strcpy`,
  `strncpy`, `strcat`, `strncat`, `strchr`, `strrchr`,
  `strstr`, `strpbrk`, `strspn`, `strcspn`,
  `wcslen`, `wcscmp`, `wcscpy`, `wcsstr`,
  `memcpy`, `memmove`, `memset`, `memcmp`, `memchr`
- Conversion: `atoi`, `atol`, `atof`, `_atoi64`,
  `strtol`, `strtoul`, `wcstol`, `wcstoul`,
  `_itoa`, `_ltoa`, `_ultoa`, `_itow`,
  `sprintf`, `_snprintf`, `_vsnprintf`, `swprintf`
- File: `fopen`, `fclose`, `fread`, `fwrite`,
  `fseek`, `ftell`, `fprintf`, `fputs`, `fgets`
  (delegate to kernel32 file APIs)
- Time: `time`, `clock`, `_strtime`, `_strdate`
- Errno: `_errno`, `errno`, `_get_errno`
- Math wrappers (forwards to ucrtbase math)

**STUB / GAP:**
- Locale: `setlocale`, `localeconv`, the `_l`-suffixed family
  — STUB returning C locale
- Wide-stdio: `_wfopen`, `wprintf`, `fwprintf` — GAP (UTF-16
  flow only — no MBCS conversion)
- Signal: `signal`, `raise` — STUB
- C++ exception layer (`_CxxThrowException`,
  `__cxa_*`) — STUB; lives in vcruntime instead

### vcruntime140.dll  (~210 LOC)

Stack-frame / SEH unwind primitives for MSVC-built code.
`__C_specific_handler`, `__std_terminate`,
`memcpy` / `memset` / `memmove` aliases, `__chkstk`.
Mostly real because the bodies are tiny.

### msvcp140.dll  (~93 LOC)

C++ stdlib stubs. `?uncaught_exception@std@@YA_NXZ`,
`?_Xbad_alloc@std@@YAXXZ`, etc. **STUB**: every body returns
the safest default (false / no-throw / null). Real STL
containers do work because their methods are inline-templated
in the PE and don't actually call back here.

### ucrtbase.dll  (~1 480 LOC, ~250 exports)

> **Status:** the modern UCRT split. Heap / stdio / formatting /
> floating-point math implemented; locale / threading deferred.

**Real:** the entire heap (`_malloc_base`, `_free_base`,
`_msize_base`, `_calloc_base`, `_realloc_base`),
the printf/scanf family (vsnprintf with %d %s %x %f basics),
str* / wcs* mirrors of msvcrt, fopen/fread/fwrite/fclose,
math (sqrt, pow, exp, log, sin, cos, tan via Taylor series).

**STUB / GAP:**
- Multi-byte conversion: `mbtowc`, `wctomb` — STUB ASCII passthrough
- Locale-aware printf (`_l` family) — STUB returns same as non-_l
- Threading: `_beginthread`, `_beginthreadex`, `_endthread`,
  `_endthreadex` — REAL via SYS_THREAD_CREATE / SYS_EXIT
  (both flavours route to the same kernel surface; the
  signature difference is purely C-level — kernel doesn't
  care about the start function's return type)
- Atomic helpers — real (forward to compiler intrinsics)

### dbghelp.dll  (~490 LOC, ~30 exports)

> **Status:** symbol-table walker for the boot kernel's own
> symbols. PE-side stack walks return canned data.

**Real:** `SymInitialize`, `SymCleanup`, `SymFromAddr`,
`SymGetLineFromAddr64`, `MiniDumpWriteDump` (writes to
SYS_MINIDUMP), `SymSetOptions`, `SymGetOptions`.

**STUB:** `StackWalk64`, `EnumerateLoadedModules64`, the
WinDbg client API, `SymLoadModuleEx`.

---

## 2. Windowing / GDI / theming

### user32.dll  (~2 230 LOC, ~140 exports)

> **Status:** core message pump + window lifecycle work; menus
> / dialogs / clipboard real-but-narrow; common controls
> (comctl32) are mostly stubs.

**Real:**
- Lifecycle: `RegisterClassA/W`, `RegisterClassExA/W`,
  `UnregisterClassA/W`, `CreateWindowExA/W`,
  `DestroyWindow`, `ShowWindow`, `MoveWindow`,
  `SetWindowPos`, `IsWindow`, `IsWindowVisible`,
  `IsWindowEnabled`, `GetParent`, `SetParent`,
  `GetActiveWindow`, `SetActiveWindow`,
  `GetForegroundWindow`, `SetForegroundWindow`,
  `GetDesktopWindow`, `EnumWindows`, `FindWindowA/W`,
  `FindWindowExA/W`, `GetClassInfoExW`
- Message pump: `GetMessageA/W`, `PeekMessageA/W`,
  `DispatchMessageA/W`, `TranslateMessage`,
  `SendMessageA/W`, `PostMessageA/W`,
  `PostQuitMessage`, `DefWindowProcA/W`,
  `CallWindowProcA/W`, `SendNotifyMessageA/W`
- Window properties: `GetWindowLongA/W`,
  `SetWindowLongA/W`, `GetWindowLongPtrA/W`,
  `SetWindowLongPtrA/W` (USERDATA + STYLE round-trip),
  `GetWindowRect`, `GetClientRect`,
  `GetWindowTextA/W`, `SetWindowTextA/W`,
  `ScreenToClient`, `ClientToScreen`,
  `InvalidateRect`, `ValidateRect`, `UpdateWindow`
- Paint: `BeginPaint`, `EndPaint`, `GetDC`,
  `ReleaseDC`, `GetWindowDC`
- Input: `GetAsyncKeyState`, `GetKeyState`,
  `GetCursorPos`, `SetCursorPos`, `ShowCursor`,
  `LoadCursorA/W`, `SetCursor`,
  `GetCapture`, `SetCapture`, `ReleaseCapture`,
  `GetFocus`, `SetFocus`,
  `ClipCursor`, `GetSysColor`,
  `GetSystemMetrics`
- Timers: `SetTimer`, `KillTimer`
- MessageBox: `MessageBoxA/W`, `MessageBoxExA/W`
- Caret: `CreateCaret`, `DestroyCaret`,
  `ShowCaret`, `HideCaret`, `SetCaretPos`,
  `SetCaretBlinkTime`, `GetCaretBlinkTime`
- Multimon: `EnumDisplayMonitors`, `MonitorFromWindow`,
  `MonitorFromPoint`, `GetMonitorInfoW`,
  `EnumDisplayDevicesW`, `EnumDisplaySettingsW`
- DPI: `GetDpiForSystem`, `GetDpiForWindow` — return 96
- Beep: `Beep`, `MessageBeep`

**STUB / GAP:**
- Clipboard: `OpenClipboard`, `CloseClipboard`,
  `EmptyClipboard`, `GetClipboardData`, `SetClipboardData`
  — GAP: format conversion is text-only, no CF_DIB / CF_HDROP
- Accelerators: `LoadAcceleratorsW`, `TranslateAccelerator`
  — GAP: tables load but TranslateAccelerator only handles
  ASCII keys
- Menus: `LoadMenuW`, `GetSystemMenu` — STUB (return canned
  empty handle)
- Modal dialogs: `DialogBoxParamA/W`, `EndDialog` — MISSING
- Hooks: `SetWindowsHookExA/W`, `UnhookWindowsHookEx`,
  `CallNextHookEx` — STUB
- Subclassing: `SetWindowSubclass` lives in comctl32 — STUB
- DDE: `DdeInitializeA/W`, `DdeCreateStringHandleA/W`,
  `DdeFreeStringHandle`, `DdeUninitialize` — STUB
- Scrollbars (`SetScrollInfo` etc.) — STUB

### gdi32.dll  (~830 LOC, ~50 exports)

> **Status:** GDI primitives that show up in the compositor's
> display list (FillRect, Rectangle, Ellipse, Line, TextOut,
> SetPixel, BitBlt) are real. Bitmap creation / DC management
> have minimal but working bookkeeping. Brushes/pens/fonts
> are tag-based handles. **No anti-aliasing, no outline fonts,
> no path API.**

**Real:**
- DC: `GetDC`, `ReleaseDC`, `CreateCompatibleDC`,
  `DeleteDC`, `SaveDC`, `RestoreDC`, `GetWindowDC`
- Objects: `CreateSolidBrush`, `CreateBrushIndirect`,
  `CreatePen`, `CreateFontA/W`, `CreateFontIndirectA/W`,
  `CreateBitmap`, `CreateCompatibleBitmap`,
  `CreateDIBSection`, `CreateDIBitmap`, `GetStockObject`,
  `SelectObject`, `DeleteObject`, `GetObjectA/W`
- Drawing: `FillRect`, `FrameRect`, `Rectangle`,
  `Ellipse`, `LineTo`, `MoveToEx`,
  `Polygon`, `Polyline`, `BitBlt`, `StretchBlt`,
  `SetPixel`, `SetPixelV`, `GetPixel`,
  `TextOutA/W`, `ExtTextOutA/W` (honours `ETO_CLIPPED` + the
  `lprc` clip-rect by trimming the (text, x) pair to the
  visible columns at the kernel font's 8 px cell width;
  `ETO_OPAQUE` still STUB), `DrawTextA/W`
- State: `SetBkColor`, `SetBkMode`, `SetMapMode`,
  `SetTextColor`, `SetTextAlign`

**STUB / GAP:**
- Path API: `BeginPath`, `EndPath`, `StrokePath` — STUB
- Region API: `CreateRectRgn`, `CombineRgn`, etc. — STUB
- Metafiles: `CreateMetaFile`, `PlayMetaFile` — STUB
- Outline / TrueType fonts: `EnumFontsW`, `GetGlyphOutline`
  — STUB (we render only the kernel's 8x8 bitmap font)
- Color management: `SetICMMode`, `GetICMProfile` — STUB
- Printer DC: `CreateDCW("WINSPOOL\\…")` — STUB

### comctl32.dll  (~430 LOC, ~50 exports)

> **Status:** every common control is STUB. PEs that probe for
> the controls' existence (which most do at startup) succeed;
> PEs that try to use them get nothing.

`InitCommonControls` / `InitCommonControlsEx` — return success.
`ImageList_*` — return canned handles. `PropertySheetA/W`,
`TaskDialog`, `TaskDialogIndirect` — STUB.
`SetWindowSubclass` / `RemoveWindowSubclass` /
`DefSubclassProc` — STUB but callable.

### comdlg32.dll  (~160 LOC, ~20 exports)

> **Status:** every common dialog is STUB. Real dialogs need
> the modal-dialog framework which we don't have.

`GetOpenFileNameA/W`, `GetSaveFileNameA/W`,
`ChooseColorA/W`, `ChooseFontA/W`,
`PrintDlgA/W`, `PageSetupDlgA/W`,
`FindTextA/W`, `ReplaceTextA/W` — all STUB return FALSE.

### dwmapi.dll  (~300 LOC, ~25 exports)

DWM (Desktop Window Manager) facade. Every export is STUB:
`DwmIsCompositionEnabled` returns TRUE,
`DwmFlush` is a no-op, `DwmGetWindowAttribute` zero-fills.

### uxtheme.dll  (~550 LOC, ~40 exports)

Theming facade. `OpenThemeData` returns a canned handle that
every other call accepts. `IsThemeActive` returns TRUE.
`DrawThemeBackground` / `DrawThemeText` — STUB no-op.
`BufferedPaint*` — STUB but tracks paint scope.

---

## 3. Path / shell / version helpers

### shlwapi.dll  (~790 LOC, ~40 exports)

> **Status:** path manipulation is REAL. String comparison /
> regex (`PathMatchSpecW`) is REAL with limited glob support.

`Path*`, `Str*`, `PathMatchSpecW` — all REAL for the v0
inventory above. `PathCanonicalizeW` is GAP for `..` walks
above the drive root.

### shell32.dll  (~410 LOC, ~13 exports)

`CommandLineToArgvW` — REAL. `SHGetFolderPathW` /
`SHGetFolderPathA` / `SHGetSpecialFolderPathW` /
`SHGetSpecialFolderPathA` — REAL: dispatch the masked
CSIDL value (`CSIDL_FLAG_MASK = 0xFF00`) against a per-CSIDL
path table covering APPDATA / LOCAL\_APPDATA / PROGRAM\_FILES /
PROGRAM\_FILES\_COMMON / WINDOWS / SYSTEM / FONTS / DESKTOP /
PERSONAL / MYMUSIC / MYVIDEO / MYPICTURES / FAVORITES /
PROFILE / COMMON\_APPDATA (= ProgramData) and the Start-Menu /
Recent / SendTo / Templates / Cookies / History / INetCache
sub-trees, all rooted at `X:\Users\duetos` to match the
USERPROFILE convention in `userenv.c`. Unrecognised CSIDLs
fall through to the profile root. `SHGetKnownFolderPath` is
still STUB — it returns `E_FAIL` because the API allocates
the path through `CoTaskMemAlloc`, which shell32 doesn't
import; modern callers should fall back to
`SHGetFolderPathW`. `ShellExecuteW`, `ShellExecuteExW`,
`SHFileOperationW` — STUB.

### version.dll  (~290 LOC, ~16 exports)

`GetFileVersionInfoSizeW`, `GetFileVersionInfoW`, `VerQueryValueW`
— REAL: parse the PE's VS_VERSION_INFO resource.
`VerLanguageNameW`, `VerFindFileW`, `VerInstallFileW` — STUB.

### setupapi.dll  (~470 LOC, ~50 exports)

INF / device-installation API. `SetupOpenInfFileW`,
`SetupFindFirstLineA`, `SetupGetLineByIndexA` — REAL for
INI-style INFs. `SetupDi*` (device-info-set families) — STUB.
`CM_*` (configuration manager) — STUB.

### userenv.dll  (~300 LOC, ~30 exports)

`GetUserProfileDirectoryW`, `GetAllUsersProfileDirectoryW`,
`CreateEnvironmentBlock`, `DestroyEnvironmentBlock` — REAL
(thin wrappers over kernel32 env strings).
`LoadUserProfileW`, `RefreshPolicy`, `GetGPOListW` — STUB.

### wtsapi32.dll  (~390 LOC, ~25 exports)

Terminal Services facade. `WTSGetActiveConsoleSessionId` — REAL
(returns 1). `WTSQuerySessionInformationA/W` — GAP (returns
canned values for username / domain / station). The rest STUB.

### psapi.dll  (~440 LOC, ~50 exports)

> **Status:** process / module enumeration REAL — backed by
> the kernel's process table. Working set / performance
> queries STUB.

`EnumProcesses`, `EnumProcessModules`, `GetModuleBaseNameW`,
`GetModuleFileNameExW`, `GetProcessImageFileNameW`,
`GetProcessMemoryInfo`, `QueryFullProcessImageNameW` — REAL.
`QueryWorkingSet`, `EmptyWorkingSet`, `GetWsChanges`,
`GetPerformanceInfo` — STUB.

---

## 4. Networking

### ws2_32.dll  (~660 LOC, ~50 exports)

> **Status:** synchronous BSD-socket subset is REAL. WSA event-
> based / overlapped / completion-port async surface is STUB.

**Real:**
- `WSAStartup`, `WSACleanup`, `WSAGetLastError`,
  `WSASetLastError`
- `socket`, `closesocket`, `bind`, `listen`, `connect`,
  `accept`, `send`, `recv`, `sendto`, `recvfrom`, `shutdown`
- `setsockopt`, `getsockopt`, `select`, `__WSAFDIsSet`,
  `ioctlsocket`, `getsockname`, `getpeername`
- Byte order: `htons`, `htonl`, `ntohs`, `ntohl`,
  `htonll`, `ntohll`
- Address: `inet_addr`, `inet_ntoa`, `inet_pton`, `inet_ntop`,
  `gethostname`, `gethostbyname`, `getaddrinfo`,
  `freeaddrinfo`, `getnameinfo`

**STUB:**
- `WSAEventSelect`, `WSACreateEvent`, `WSACloseEvent`,
  `WSASetEvent`, `WSAResetEvent` — exist but never fire
- `WSARecv`, `WSASend`, `WSARecvFrom`, `WSASendTo` — STUB
  (no overlapped I/O)
- `WSAIoctl` — GAP (only SIO_GET_INTERFACE_LIST)
- IPv6 socket API — GAP (sockets create but bind fails)

### iphlpapi.dll  (~640 LOC, ~60 exports)

> **Status:** read-side adapter / TCP / UDP enumeration REAL.
> ICMP echo REAL via SYS_NET_PING. Modify-side (route / IP
> table mutation) STUB.

`GetAdaptersInfo`, `GetAdaptersAddresses`, `GetIfTable`,
`GetIpAddrTable`, `GetTcpTable`, `GetUdpTable`,
`GetNetworkParams`, `IcmpSendEcho{,2}`, `IcmpCreateFile`,
`Icmp6CreateFile`, `IcmpCloseHandle`, `SendARP` — REAL.

`AddIPAddress`, `DeleteIPAddress`, `CreateIpForwardEntry`,
`DeleteIpForwardEntry`, `SetTcpEntry`,
`NotifyAddrChange`, `NotifyRouteChange`,
`SetIpInterfaceEntry` — STUB.

### wininet.dll  (~1100 LOC, ~50 exports)

> **Status:** HTTP/1.0 GET works end-to-end (mini_browser PE
> uses it). Cookies REAL via in-process LRU table. RFC 1123
> time format / parse REAL. FTP / cache / async — STUB.

`InternetOpenA/W`, `InternetOpenUrlA/W`, `InternetReadFile`,
`InternetCloseHandle`, `HttpQueryInfoA`, `InternetQueryDataAvailable`
— REAL for HTTP/1.0 + simple Content-Length flow.
`InternetTimeFromSystemTimeA/W`, `InternetTimeToSystemTimeA/W`
— REAL: RFC 1123 format / parse round-trip ("Sun, 06 Nov 1994
08:49:37 GMT"). Day-of-week is recomputed via Zeller on parse
so a wrong dow input still parses; format always emits the
Zeller-correct dow.

`InternetWriteFile` — GAP (no chunked POST). FTP family — STUB.
Cookie family (`InternetGetCookieA/W` /
`InternetSetCookieA/W` / their `Ex*` variants) — REAL via a
small in-process cookie store: a 16-entry LRU table of
`(host, name, value)` triples, host extracted from the URL by
parsing `scheme://[userinfo@]host[:port]/...`, host compare
case-insensitive per RFC 6265. `InternetGetCookieA/W` with
NULL `name` walks every matching host entry and concatenates
them as `name1=value1; name2=value2; ...` — the canonical
HTTP `Cookie:` header form. Path / domain / Secure /
HttpOnly / SameSite attributes are dropped — Set just stashes
the triple. Cleared at process exit (no on-disk
persistence).

### winhttp.dll  (~690 LOC, ~35 exports)

> **Status:** session / connect / open-request / send-request
> / read-data REAL. WebSocket / async I/O STUB.

`WinHttpOpen`, `WinHttpConnect`, `WinHttpOpenRequest`,
`WinHttpSendRequest`, `WinHttpReceiveResponse`,
`WinHttpReadData`, `WinHttpQueryDataAvailable`,
`WinHttpQueryHeaders`, `WinHttpAddRequestHeaders`,
`WinHttpCloseHandle` — REAL.

`WinHttpWebSocket*`, `WinHttpSetStatusCallback`,
`WinHttpQueryAuthSchemes`, `WinHttpSetCredentials` — STUB.

### crypt32.dll  (~1 330 LOC, ~50 exports)

> **Status:** thin certificate-store wrapper. PFX parsing is
> partial. Certificate-chain validation is STUB.

`CertOpenStore`, `CertCloseStore`,
`CertFindCertificateInStore`, `CertEnumCertificatesInStore`,
`CertFreeCertificateContext` — REAL for an in-memory store.
`CryptStringToBinaryA/W`, `CryptBinaryToStringA/W` —
REAL (Base64 + hex encodings).
`CryptDecodeObject{,Ex}`, `CryptEncodeObject{,Ex}` — REAL for
a small ASN.1 subset (X.509 fields).

`CertGetCertificateChain`, `CertVerifyCertificateChainPolicy`
— STUB. PFX import / export — STUB.
`CryptSignAndEncryptMessage`, `CryptDecryptAndVerifyMessageSignature`
— STUB.

### secur32.dll  (~380 LOC, ~30 exports)

SSPI facade. `AcquireCredentialsHandleA/W`,
`InitializeSecurityContextA/W`, `EncryptMessage`, `DecryptMessage`
— STUB returning success but not actually wrapping data.
`GetUserNameExA/W` — REAL (returns "DUETOS\admin").
`LsaLogonUser`, `LsaCallAuthenticationPackage` — STUB.

---

## 5. Crypto / RNG

### bcrypt.dll  (~870 LOC, ~10 exports)

> **Status:** REAL for the algorithm set most callers want.
> Backed by the kernel's `SYS_RANDOM_BYTES` and the in-tree
> SHA-256 / SHA-384 / SHA-512 / SHA-1 / MD5 / AES hash + cipher
> cores.

`BCryptOpenAlgorithmProvider`, `BCryptCloseAlgorithmProvider`,
`BCryptCreateHash`, `BCryptHashData`, `BCryptFinishHash`,
`BCryptDestroyHash`, `BCryptGetProperty`, `BCryptGenRandom`
— REAL for SHA-256, SHA-384, SHA-512, SHA-1, MD5, RNG.
SHA-384 and SHA-512 share one FIPS 180-4 §6.4 core; SHA-384
differs only in the eight initial-hash values and the
truncated 48-byte output.

`BCryptGenerateSymmetricKey`, `BCryptDestroyKey`,
`BCryptSetProperty`, `BCryptEncrypt`, `BCryptDecrypt` — REAL
for AES-128 + AES-256 in CBC and ECB modes via a FIPS 197
reference core. `SetProperty(BCRYPT_CHAINING_MODE, "...CBC"
| "...ECB")` flips the chaining; `Encrypt` / `Decrypt`
require a 16-byte IV in CBC mode. Verified against FIPS 197
Appendix B (AES-128 KAT) and NIST AES-256 KAT — both match
on first-block + round-trip.

GAP: `BCryptHashData` slots and the AES key slot are
single-threaded (one global of each), so concurrent hashing
or encryption breaks.

MISSING: AES-GCM (no AEAD wrapper), PKCS#7 padding (caller
must pre-pad to 16-byte boundary), RSA / ECC key import /
sign / verify, key derivation (`BCryptDeriveKeyPBKDF2` etc.).

---

## 6. Multimedia

### winmm.dll  (~170 LOC, ~10 exports)

`timeGetTime`, `timeBeginPeriod`, `timeEndPeriod`,
`timeGetDevCaps` — REAL.
`timeSetEvent`, `timeKillEvent` — REAL (multimedia timer
maps to `SetTimer`).
`PlaySoundW` — STUB silent. `mciSendStringW` — STUB.

### dsound.dll, ddraw.dll, xaudio2_8.dll, xinput1_4.dll

Covered under DirectX peripheral DLLs in §7.

---

## 7. DirectX surface (peer-of-Win32, ~7 000 LOC)

> **Status:** real COM-vtable shapes at canonical Win SDK ABI
> slots; software rasterizer behind D3D9 / D3D11 / D3D12;
> no real GPU; no shader execution; no Z-buffer.
> See [`wiki/subsystems/DirectX.md`](../subsystems/DirectX.md)
> for the live narrative.

### d3d9.dll  (~980 LOC) — `Direct3DCreate9{,Ex}`,
                                  `DuetOS_D3D9_PeekBackBuffer`

**IDirect3D9** vtable slots — REAL: 0..2 IUnknown, 4
GetAdapterCount, 16 CreateDevice. STUB: 5 GetAdapterIdentifier,
6..15 (everything else).

**IDirect3DDevice9** vtable slots (canonical d3d9.h order) —
REAL: 0..2 IUnknown, 17 Present, 23 CreateTexture (BGRA8 backing
storage), 26 CreateVertexBuffer, 27 CreateIndexBuffer, 41
BeginScene, 42 EndScene, 43 Clear, 44 SetTransform, 45
GetTransform, 47 SetViewport, 57 SetRenderState, 58
GetRenderState, 65 SetTexture (no-op), 81 DrawPrimitive,
82 DrawIndexedPrimitive, 83 DrawPrimitiveUP, 89 SetFVF, 90
GetFVF, 100 SetStreamSource, 104 SetIndices.

STUB: every other slot (Reset, GetSwapChain, GetBackBuffer,
SetMaterial, lighting, clip planes, vertex shaders 91..99,
pixel shaders 106..114, queries 118).

### d3d11.dll  (~1 855 LOC) — `D3D11CreateDevice`, `D3D11CreateDeviceAndSwapChain`

**ID3D11Device** vtable slots — REAL: 0..2 IUnknown, 3
CreateBuffer, 5 CreateTexture2D, 9 CreateRenderTargetView,
11 CreateInputLayout, 12 CreateVertexShader, 15
CreatePixelShader, 20 CreateBlendState, 21
CreateDepthStencilState, 22 CreateRasterizerState, 23
CreateSamplerState, 29 CheckFormatSupport, 30
CheckMultisampleQualityLevels, 33 CheckFeatureSupport, 37
GetFeatureLevel, 40 GetImmediateContext.

STUB: 4 CreateTexture1D, 6 CreateTexture3D, 7
CreateShaderResourceView, 8 CreateUnorderedAccessView,
10 CreateDepthStencilView, 13 CreateGeometryShader,
14 CreateGeometryShaderWithStreamOutput, 16 CreateHullShader,
17 CreateDomainShader, 18 CreateComputeShader, 19
CreateClassLinkage, 24 CreateQuery, 25 CreatePredicate, 26
CreateCounter, 27 CreateDeferredContext, 28 OpenSharedResource.

**ID3D11DeviceContext** (canonical d3d11.h order) — REAL: 0..2
IUnknown, 9 PSSetShader, 11 VSSetShader, 12 DrawIndexed, 13
Draw, 14 Map (validates `map_type` ∈ {READ, WRITE, READ\_WRITE,
WRITE\_DISCARD, WRITE\_NO\_OVERWRITE}; routes WRITE\_NO\_OVERWRITE
on buffers to the same backing storage; rejects
WRITE\_NO\_OVERWRITE on textures with `E_INVALIDARG`; records
the last map\_type per buffer for read-back via
`DuetOS_D3D11_PeekBufferMapType`), 15 Unmap, 17
IASetInputLayout, 18
IASetVertexBuffers, 19 IASetIndexBuffer, 20
DrawIndexedInstanced, 21 DrawInstanced, 24
IASetPrimitiveTopology, 33 OMSetRenderTargets, 35
OMSetBlendState (no-op), 36 OMSetDepthStencilState (no-op),
43 RSSetState (no-op), 44 RSSetViewports, 45
RSSetScissorRects (no-op), 48 UpdateSubresource, 50
ClearRenderTargetView, 110 Flush, 113 GetType.

STUB: every other slot (constant buffers, shader resource
views, samplers, predication, geometry/hull/domain stages,
async queries, indirect draws, dispatch, copy operations,
SOSetTargets, OMSetRenderTargetsAndUnorderedAccessViews,
ClearUnorderedAccessView*, ClearState, ResolveSubresource).

### d3d12.dll  (~1 904 LOC) — `D3D12CreateDevice`, `D3D12GetDebugInterface`, `D3D12SerializeRootSignature`

**ID3D12Device** (canonical d3d12.h order) — REAL: 0..2
IUnknown, 7 GetNodeCount, 8 CreateCommandQueue, 9
CreateCommandAllocator, 10 CreateGraphicsPipelineState
(input layout extracted from PSO desc), 11
CreateComputePipelineState (topology-undef PSO), 12
CreateCommandList, 13 CheckFeatureSupport, 14
CreateDescriptorHeap, 15 GetDescriptorHandleIncrementSize,
16 CreateRootSignature, 20 CreateRenderTargetView, 27
CreateCommittedResource (BUFFER + TEXTURE2D dimensions),
36 CreateFence, 37 GetDeviceRemovedReason.

STUB: 17..19 CreateConstantBufferView / SRV / UAV, 21
CreateDepthStencilView, 22 CreateSampler, 23..26
CopyDescriptors{,Simple} / GetResourceAllocationInfo /
GetCustomHeapProperties, 28..35 CreateHeap /
CreatePlacedResource / CreateReservedResource /
CreateSharedHandle / OpenSharedHandle{,ByName} / MakeResident /
Evict, 38..43 GetCopyableFootprints / CreateQueryHeap /
SetStablePowerState / CreateCommandSignature /
GetResourceTiling / GetAdapterLuid.

**ID3D12GraphicsCommandList** (canonical d3d12.h order) —
REAL: 0..2 IUnknown, 8 GetType, 9 Close, 10 Reset, 12
DrawInstanced, 13 DrawIndexedInstanced, 20
IASetPrimitiveTopology, 21 RSSetViewports, 22
RSSetScissorRects (no-op), 25 SetPipelineState, 26
ResourceBarrier (records `current_state` per resource —
TRANSITION barriers update it AND validate StateBefore
matches the recorded state, bumping a per-list mismatch
counter (`DuetOS_D3D12_PeekBarrierMismatchCount`) and
emitting one `[d3d12] ResourceBarrier StateBefore mismatch:
recorded=… declared=… after=…` line via SYS_DEBUG_PRINT for
the first three mismatches; ALIASING / UAV are no-op
success), 29 SetComputeRootSignature (no-op),
30 SetGraphicsRootSignature, 43 IASetIndexBuffer, 44
IASetVertexBuffers (walks `n` views from `start_slot`,
populating each of the 32 IA slots independently so the
PSO's per-element InputSlot can pick the right VB per
attribute), 46 OMSetRenderTargets, 47
ClearDepthStencilView (no-op), 48 ClearRenderTargetView.

STUB: every other slot (all root-table / root-32-bit /
root-CBV/SRV/UAV setters at slots 31..42, ExecuteBundle,
SetDescriptorHeaps, every Begin/End-Query and predicate slot,
ClearUnorderedAccessView*, DiscardResource, SetMarker,
ExecuteIndirect, OMSetBlendFactor, OMSetStencilRef,
SOSetTargets, the Dispatch / CopyBufferRegion / CopyResource /
CopyTiles / ResolveSubresource family).

**ID3D12CommandQueue** — REAL: ExecuteCommandLists, Signal, Wait,
GetTimestampFrequency. STUB: UpdateTileMappings,
CopyTileMappings, GetClockCalibration, GetDesc.

**ID3D12Resource** — REAL: Map, Unmap, GetDesc,
GetGPUVirtualAddress. STUB: WriteToSubresource,
ReadFromSubresource, GetHeapProperties.

**ID3D12Fence** — REAL: GetCompletedValue, SetEventOnCompletion,
Signal.

**ID3D12RootSignature** / **ID3D12PipelineState** — opaque
handles; QueryInterface + Release work; methods are STUB.

### dxgi.dll  (~795 LOC) — `CreateDXGIFactory{,1,2}`, `DXGIGetDebugInterface{,1}`, `DXGIDeclareAdapterRemovalSupport`

**IDXGIFactory / IDXGIFactory1 / IDXGIFactory2** — REAL:
IUnknown, EnumAdapters, EnumAdapters1, CreateSwapChain,
CreateSwapChainForHwnd, IsCurrent, IsWindowedStereoEnabled.
STUB: MakeWindowAssociation, GetWindowAssociation,
CreateSoftwareAdapter, the stereo / occlusion / shared-resource
families, CreateSwapChainForCoreWindow,
CreateSwapChainForComposition.

**IDXGIAdapter / IDXGIAdapter1** — REAL: GetDesc, GetDesc1,
EnumOutputs. STUB: CheckInterfaceSupport,
GetSharedResourceAdapterLuid.

**IDXGIOutput** — REAL: GetDesc, GetDisplayModeList (1280×720
@60Hz), FindClosestMatchingMode, WaitForVBlank (immediate).
STUB: gamma controls, ownership, GetDisplaySurfaceData,
GetFrameStatistics.

**IDXGISwapChain / IDXGISwapChain1** — REAL: Present, GetBuffer,
GetDesc, ResizeBuffers. STUB: SetFullscreenState,
GetFullscreenState, ResizeTarget, GetContainingOutput,
GetFrameStatistics, GetLastPresentCount.

### d2d1.dll  (~620 LOC) — `D2D1CreateFactory`

**ID2D1Factory** — REAL: CreateHwndRenderTarget. STUB:
ReloadSystemMetrics, GetDesktopDpi, the rectangle / rounded-
rectangle / ellipse / geometry / stroke-style factory methods,
CreateDxgiSurfaceRenderTarget, CreateDCRenderTarget.

**ID2D1HwndRenderTarget** — REAL: BeginDraw, EndDraw, Clear,
CreateSolidColorBrush, FillRectangle, DrawRectangle,
FillEllipse, DrawEllipse, DrawLine, FillTriangles, GetSize,
SetTransform, GetTransform, Resize. STUB: every text / glyph
method (DrawText, DrawTextLayout, DrawGlyphRun), every gradient
brush, every bitmap method, layers, clip rectangles.

**ID2D1SolidColorBrush** — REAL: AddRef / Release / vtable
shape. Brush colour mutate / opacity / transform are STUB
(callers re-create the brush).

### dwrite.dll  (~330 LOC) — `DWriteCreateFactory`

**IDWriteFactory** — REAL: CreateTextFormat, CreateTextLayout
(returns object; doesn't actually shape glyphs). STUB:
CreateFontFileReference, CreateFontFace,
CreateTextAnalyzer, the rendering-parameter family.

**IDWriteTextLayout** — REAL: GetMaxWidth (slot 42),
GetMaxHeight (slot 43), GetMetrics (slot 60 — monospace
approximation, fixed cell sizes derived from the requested
font size), HitTestPoint (slot 64 — single-line monospace,
returns column = floor(pointX / cell\_w), trailing-half flag,
inside-bounds flag, and a populated DWRITE\_HIT\_TEST\_METRICS).
STUB: GetClusterMetrics, HitTestTextPosition,
HitTestTextRange, every range-property setter.

### dinput8.dll  (~545 LOC) — `DirectInput8Create`

**IDirectInput8W/A** — REAL: CreateDevice (keyboard / mouse via
GUID match), EnumDevices. **IDirectInputDevice8W** — REAL:
SetDataFormat (recognises mouse / keyboard formats), Acquire,
Unacquire, GetDeviceState (routes to SYS_WIN_GET_KEYSTATE /
SYS_WIN_GET_CURSOR / SYS_WIN_GET_MOUSE_DELTA). STUB: joystick /
gamepad enumeration, force-feedback effects, polling on
unacquired devices.

### xinput1_4.dll  (~85 LOC) — `XInputGetState`, `XInputSetState`, `XInputGetCapabilities`, `XInputGetBatteryInformation`, `XInputGetKeystroke`, `XInputEnable`

REAL for "no controllers connected" — every slot returns
ERROR_DEVICE_NOT_CONNECTED. Real gamepad support depends on
the USB HID stack.

### xaudio2_8.dll  (~315 LOC) — `XAudio2Create`, `CreateAudioReverb`, `CreateAudioVolumeMeter`

**IXAudio2** vtable — REAL: CreateMasteringVoice,
CreateSourceVoice, StartEngine, StopEngine. **IXAudio2Voice**
— REAL: SetVolume, GetVolume, Start, Stop, DestroyVoice. STUB:
audio actually plays (HDA mixer not wired).

### dsound.dll  (~370 LOC) — `DirectSoundCreate{,8}`, `DirectSoundEnumerateA/W`, `GetDeviceID`

**IDirectSound8** vtable — REAL: SetCooperativeLevel,
CreateSoundBuffer. **IDirectSoundBuffer** — REAL: Lock, Unlock,
Play, Stop, GetCurrentPosition. STUB: audio actually plays
(same gating as XAudio2).

### ddraw.dll  (~380 LOC) — `DirectDrawCreate{,Ex}`, `DirectDrawEnumerateA/W`

**IDirectDraw7** vtable — REAL: SetCooperativeLevel,
SetDisplayMode (recorded but ignored), CreateSurface.
**IDirectDrawSurface7** — REAL: Lock, Unlock, Blt (COLORFILL).
STUB: hardware overlay, video memory paging, palette.

---

## 8. COM / automation

### ole32.dll  (~440 LOC, ~30 exports)

> **Status:** facade-only. CoInitialize / CoUninitialize update
> a per-thread counter; CoCreateInstance returns NULL.

`CoInitialize{,Ex}`, `CoUninitialize`, `OleInitialize`,
`OleUninitialize` — REAL counters. `CoTaskMemAlloc`,
`CoTaskMemFree`, `CoTaskMemRealloc` — REAL (forward to
HeapAlloc / HeapFree).
`CLSIDFromString`, `IIDFromString`, `StringFromCLSID`,
`StringFromGUID2` — REAL.
`CoCreateInstance{,Ex}`, `CoGetClassObject` — STUB return
REGDB_E_CLASSNOTREG.
`CoRegisterClassObject`, `CoRevokeClassObject`,
`CoGetMalloc`, `GetRunningObjectTable`,
`RegisterDragDrop`, `RevokeDragDrop` — STUB.

**MISSING entirely:** apartments / threading models, RPC
marshalling, OBJREFs, monikers, structured storage
(StgCreateStorageEx, etc.), persistent COM, classic OLE
embedding.

### oleaut32.dll  (~190 LOC, ~10 exports)

`VariantInit`, `VariantClear`, `VariantCopy` — REAL for
basic variant types (VT_I4, VT_BSTR, VT_UI1).
`SysAllocString`, `SysAllocStringLen`,
`SysAllocStringByteLen`, `SysReAllocString`, `SysFreeString`,
`SysStringLen`, `SysStringByteLen` — REAL.

**MISSING:** type library API (LoadTypeLib, ITypeInfo),
IDispatch interface support, safe-array API beyond basics.

---

## 9. Major DLLs we don't ship at all

A real Windows app reaches into far more DLLs than the 38 we
ship. Here's what's missing — grouped by what would unlock if we
did. PE imports of these names fail at PeLoad today.

### Graphics / media

- **opengl32.dll** — OpenGL 1.1+. Common in older games and
  CAD apps. Needs an ICD model + GLSL compiler.
- **vulkan-1.dll** — modern GPU API. Real Vulkan ICDs are
  the same scale as D3D. Some apps fall back to D3D11 if
  vulkan-1 isn't there.
- **mfplat.dll** / **mf.dll** / **mfreadwrite.dll** — Media
  Foundation (video / audio playback, capture). Needed for
  any modern video app.
- **wmvcore.dll** — Windows Media legacy.
- **wic.dll** / **windowscodecs.dll** — Windows Imaging
  Component (PNG / JPEG / TIFF / GIF / HEIF decode/encode
  pipeline). Photo viewers + most image-loading apps.
- **d3d10.dll** / **d3d10core.dll** / **d3d10_1.dll** —
  Direct3D 10. Mostly subsumed by D3D11 callers but a few
  legacy apps still link these.
- **d3dcompiler_47.dll** — HLSL compiler. The single biggest
  missing piece for "real DX apps."
- **d3dx*.dll** (d3dx9_43, d3dx10_43, d3dx11_43) — utility
  helpers (mesh loaders, texture loaders, math helpers).
  Many older games still depend on a specific d3dx version.
- **dxva2.dll** / **directxmath**-style helpers — STUB.
- **directcomposition.dll** — DComp surface tree. Modern
  Windows apps + Edge.
- **dwmcore.dll** — DWM internal helpers (we have dwmapi
  but not dwmcore).
- **opencl.dll** — OpenCL ICD loader.
- **gdiplus.dll** — GDI+ (managed-style 2D). Lots of older
  C# apps + System.Drawing back-end.
- **printui.dll**, **winspool.drv**, **winspool.dll** —
  printing. Anyone calling PrintDocument loses.

### Audio / video runtime

- **mmdevapi.dll** — modern audio device enumeration.
- **avrt.dll** — AVRT / MMCSS for low-latency audio threads.
- **api-ms-win-mediafoundation-*.dll** — MF API set.
- **dxva2.dll** / **dxgi1_2..6** — newer DXGI revisions
  beyond what we wrap.
- **xinput9_1_0.dll**, **xinput1_3.dll**, **xinput1_2.dll**
  — older XInput revisions; we ship 1_4 only.

### Networking

- **mswsock.dll** — Winsock SPI provider, completion-port
  primitives (AcceptEx, ConnectEx, TransmitFile).
- **netapi32.dll** — SMB / NetBIOS / Net API.
- **dnsapi.dll** — Win32 DNS resolver.
- **wsock32.dll** — legacy Winsock 1.1.
- **rpcrt4.dll** — RPC runtime. Without it COM is dead.
- **fwpuclnt.dll** — Windows Filtering Platform.
- **iertutil.dll**, **urlmon.dll** — IE / shell URL helpers.
- **bits.dll** — Background Intelligent Transfer Service.

### Identity / security

- **ntdsapi.dll** — Active Directory client.
- **adsiext.dll**, **activeds.dll** — ADSI (Directory Services).
- **schannel.dll** / **ncrypt.dll** — TLS provider, modern
  crypto. We have crypt32 / bcrypt but not the SChannel
  SSPI provider.
- **netlogon.dll**, **kerberos.dll**, **msv1_0.dll** —
  domain auth.

### System / management

- **wbemcomn.dll**, **wbemprox.dll**, **wbemdisp.dll** —
  WMI client + provider. Lots of admin tooling.
- **mmcndmgr.dll**, **wmiprvse** — MMC + WMI host.
- **msi.dll** — Windows Installer. .msi packages can't run.
- **wuapi.dll**, **wuaueng.dll** — Windows Update.
- **sxs.dll** — side-by-side assembly resolution
  (fusion / WinSxS manifests). Without it, manifests
  pointing to specific common-controls versions resolve
  to nothing.
- **dbghelp.dll** — we have a stub-shaped one (§1).

### Shell / UX

- **shdocvw.dll**, **shdoc.dll** — IE shell hosting.
- **explorerframe.dll**, **propsys.dll** — Explorer.
- **mshtml.dll** — Trident HTML engine.
- **edgehtml.dll** / **chakra.dll** — Edge legacy.
- **windows.ui.xaml.dll**, **xaml.dll**, **TwinAPI.dll**,
  **windowsudk.dll** — UWP / WinUI / WinRT layer.
  Without these, every modern Windows app fails to start.

### Speech / accessibility / IME

- **sapi.dll** — SAPI5.
- **oleacc.dll**, **uiautomationcore.dll** — accessibility.
- **imm32.dll** — Input Method Manager (CJK IME).
- **msctf.dll** — Text Services Framework.

### Storage / removable / device

- **fltlib.dll** — filter manager.
- **virtdisk.dll** — VHD/VHDX support.
- **devmgr.dll** — Device Manager.
- **portabledeviceapi.dll** — Windows Portable Devices.

### Misc commonly-imported

- **cabinet.dll** — CAB compression.
- **cryptui.dll**, **wintrust.dll** — Authenticode UI / cert
  trust verification (without wintrust, no signed-PE check).
- **mscoree.dll** — .NET Framework runtime entry. Without it
  no managed (CLR) executables run.
- **clr.dll**, **mscorlib.dll**, **System.dll** — .NET BCL
  pieces; same gating.
- **vbscript.dll**, **jscript.dll** / **jscript9.dll** — WSH
  script engines.
- **scrobj.dll** — script-component runtime.
- **pdh.dll**, **pdhui.dll** — Performance Counters.
- **wevtapi.dll** — Windows Event Log API.
- **dxgidebug.dll** — DXGI debug runtime (we expose
  DXGIGetDebugInterface but the real debug DLL is separate).
- **api-ms-win-crt-*-l1-1-0.dll** — UCRT API-Set DLLs. We
  have a single ucrtbase.dll; real Windows ships ~30 API-set
  shims that all forward into ucrtbase. Some PEs import
  through the API-set names rather than ucrtbase directly.

---

## 10. Major Win32 features missing

### Foundational

- **HLSL / DXC compiler** — `D3DCompile`, `D3DCompileFromFile`,
  the full DXIL toolchain. No shader code runs — the closest
  we get is the FF transform pipeline in D3D9.
- **Real GPU drivers** — DXGK / WDDM, vendor-specific kernel
  miniports (NVIDIA, AMD, Intel). Our "GPU" is a CPU
  rasterizer.
- **Full COM apartments** — STA / MTA / NTA models, message
  filtering, marshalling, OBJREFs, SCM activation.
- **RPC** — Microsoft RPC runtime, MIDL-generated stubs,
  ALPC transport. Without RPC, most Windows IPC dies.
- **NT Kernel APC / DPC mechanisms** — we have a different
  kernel; the NT-shaped APC API is a STUB.
- **Object Manager / NT namespace** — `\??`, `\Device`, `\KernelObjects`
  paths. Most NtCreate* calls don't actually traverse these.
- **PE manifest / SxS resolution** — multi-version DLL
  resolution. Apps that depend on a specific common-controls
  manifest fall back silently to v5.

### Graphics specifics

- **Z-buffer** — D3D depth-stencil binding + test.
- **Texture sampling** — D3D shader resource views,
  sampler states applied in raster.
- **Render-target formats beyond BGRA8** — no R8 / R16F /
  RGBA16F / depth formats.
- **MSAA / anti-aliasing** — every triangle is integer-pixel
  fill.
- **Blending** — `OMSetBlendState` is a no-op; alpha blending
  not honoured by the rasterizer.
- **Compute** — `Dispatch`, UAVs, structured buffers — STUB.
- **Indirect draws** — `DrawInstancedIndirect` etc. — STUB.
- **Multi-stream input layouts** — both D3D11 and D3D12 honour
  all 32 slots: the PSO / input-layout records each element's
  `InputSlot`, the command list / context keeps a 32-entry
  `current_vb_address / size / stride` array, and `Draw*` /
  `DrawIndexed*` route each attribute to the right VB. The
  dx\_demo's `test_d3d12_multistream` covers POSITION on slot 0
  + COLOR on slot 3 end-to-end.
- **Tessellation** — hull / domain / GS shaders not run.

### Process / threading

- **Job objects** — STUB.
- **Token impersonation / RestrictedSids** — STUB.
- **DACL / SACL enforcement** — `AccessCheck` always returns
  ALLOWED; the kCap* kernel gate is the real ACL.
- **Async I/O** — `OVERLAPPED`, `IOCompletionPort`, the
  Wait-for-overlapped family — STUB.
- **APC delivery** — `QueueUserAPC` / `WaitForSingleObjectEx`
  alertable wait — STUB.
- **CreateProcessAsUser** / `CreateProcessWithLogon` — STUB.
- **Conditional variables** — `SleepConditionVariableSRW`
  and `WakeConditionVariable` — STUB.
- **Thread pools** — `TpAllocPool`, `TpAllocWork`, the whole
  vista-era thread-pool API — STUB.

### File system / device

- **File-system filters / minifilters** — STUB.
- **Reparse points / symbolic links** — STUB.
- **Mount points** — STUB.
- **Volume Shadow Copy Service** (VSS) — STUB.
- **Transactional NTFS** — STUB.
- **Sparse files** — STUB.

### Networking

- **Overlapped sockets / IOCP** — STUB.
- **WSAEventSelect** event mode — STUB.
- **TLS via SChannel** — MISSING (we have OpenSSL-style
  primitives in bcrypt but no SSPI provider).
- **HTTP/2**, **HTTP/3** — STUB.
- **WebSocket** beyond the WinHTTP shape — STUB.
- **Network adapter mutate** — STUB.
- **NDIS protocol drivers / WFP filtering** — STUB.

### Audio / video

- **Real audio output** (HDA mixer) — STUB silent.
- **Audio capture** — STUB.
- **MIDI** — STUB.
- **Webcam / WIA / MediaCapture** — STUB.
- **Hardware video decode** (DXVA2 / D3D11 video) — STUB.

### .NET / WinRT

- **CLR runtime** — MISSING entirely. Managed PEs don't load.
- **WinRT activation** — MISSING. UWP apps don't load.
- **WinUI / XAML** — MISSING.
- **API Sets** — partially: ucrtbase exists but the
  api-ms-win-* forwarders don't.

### Window manager / desktop

- **Modal dialogs** — `DialogBoxParam`, `EndDialog` — MISSING.
- **Menus** — `LoadMenu`, `TrackPopupMenu`, the menu API —
  STUB shells.
- **MDI** (multiple-document interface) — STUB.
- **Hooks** (CBT, mouse, keyboard, journal) — STUB.
- **Drag and drop** (`DoDragDrop`, IDropTarget) — STUB.
- **Common controls v6** (ListView, TreeView, Toolbar,
  Rebar, etc.) — STUB.
- **Real outline fonts / DirectWrite glyph runs** — STUB
  (we render only the kernel's 8x8 bitmap font).
- **System tray / shell notification icons** — STUB.

### Identity / policy

- **LSA / Kerberos / NTLM / Negotiate** — STUB.
- **Group Policy** — STUB.
- **Active Directory client** — MISSING.
- **CredUI** — STUB.
- **Smart card / PIV** — MISSING.
- **Cert chain validation** — STUB.
- **UAC** — STUB (everything runs in the same security
  context; kCap* gating is per-process).

### Tooling / instrumentation

- **ETW (Event Tracing for Windows)** — `EventRegister`,
  `EventWrite`, all of `tdh.h` — STUB.
- **PerfMon** — STUB.
- **WMI** — STUB.
- **Windows Error Reporting** — STUB.

---

## 11. NT subsystem / kernel-side gaps

This doc focuses on the user-mode DLL surface. The kernel-side
NT subsystem (`kernel/subsystems/win32/`) has its own gap list;
see [`wiki/subsystems/Win32-PE-Subsystem.md`](../subsystems/Win32-PE-Subsystem.md)
and the live counter:

```
[win32] ntdll bedrock coverage: 50 / 292 (generated table = 50)
[win32] ntdll full-table entries: 489
```

The 489 is "every NT syscall on the target Windows version";
50 is the count of Nt* calls with real kernel-side routing
through `nt_coverage.cpp`. The rest return
STATUS_NOT_IMPLEMENTED via `NtReturnNotImpl`.

The split is intentional: every Nt* name resolves at PE load
(import never fails), but only the 50 reach a real syscall
handler. Filling out NT coverage is a long-tail track —
rolling rows from "STATUS_NOT_IMPLEMENTED" to "real" is what
slowly closes the gap with real Windows.

---

## 12. Where to start filling things in

If you're picking up this doc and want a task: scan the STUB
rows above for ones whose **callers exist on disk**. Today's
short list:

1. **`SymGetLineFromAddr64`** in dbghelp — would let
   `process_smoke` print real source-line crash dumps.
2. **`ws2_32!WSAEventSelect`** — back into our message-
   queue + waitable-event primitives.
3. **`d2d1!DrawText`** — wire DWrite's monospace metrics
   into the existing FillRect path so single-line text
   renders.

Each row is a small slice that flips one STUB / GAP to REAL
and adds a smoke / dx_demo coverage probe.

---

## 13. Cross-references

- [Win32 DLLs subsystem page](../subsystems/Win32-DLLs.md) —
  per-DLL narratives
- [DirectX page](../subsystems/DirectX.md) — DirectX-specific
  status + ASCII render dump
- [Win32 PE subsystem page](../subsystems/Win32-PE-Subsystem.md)
  — kernel-side NT routing
- [Roadmap](Roadmap.md) — multi-slice tracks
- [Design Decisions](Design-Decisions.md) — why specific
  things look the way they do
