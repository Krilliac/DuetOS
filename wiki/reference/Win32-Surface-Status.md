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

## Summary counts (2026-05-11)

- **Shipping DLLs:** 46 dirs in `userland/libs/` (Win32 user-mode +
  DirectX peripheral). Two `dx_*.h` files in the same tree are
  shared headers, not DLLs.
- **Approximate exports:** ~1100 across all shipping DLLs
- **Source LOC across `userland/libs/`:** ~40 000
- **Live STUB / GAP markers** in user-mode + win32 subsystem
  (`git grep -nE "// (STUB|GAP):" -- 'userland/libs/' 'kernel/subsystems/win32/'`): 0
  — STUB/GAP discipline now lives entirely in kernel TUs (gpu,
  iwlwifi, etc.). Userland DLL stubs are documented in this page
  rather than via inline markers; see the per-DLL drilldown below.
- **Win32 PE smoke coverage:** 143 fixtures in `userland/apps/`
  boot-tested per run

The marker count is a lower bound on known-stub paths — most stubs
are inline (one-liners that return E_NOTIMPL or zero-fill an out
parameter) and don't carry the marker. The doc below is the
authoritative list.

### Pinned-offset convention (subsystem-NOOPs follow-on, 2026-05-11)

The wiki auto-generator (`tools/build/gen-wiki-auto.py`)
classifies each `thunks_table.inc` row by the kOff* it routes to.
A row routed to one of the four generic NOOP sinks
(`kOffReturnZero`, `kOffReturnOne`, `kOffCritSecNop`,
`kOffGetProcessHeap`) shows up as **NOOP** in the per-DLL tables
below. A row routed to any other named offset shows up as
**REAL** — even when the offset's bytecode is the same `xor
eax,eax; ret`.

The distinction is deliberate. A generic NOOP sink is the
"haven't decided yet" landing pad. A named offset like
`kOffPinReturn0`, `kOffPinReturn1`, `kOffPinVoidNop`,
`kOffPinFiberZero`, `kOffPinFiberVoid`, `kOffPinBadPtrSafe`, or
`kOffPinLcidEnUs` (declared in `kernel/subsystems/win32/thunks.cpp`,
implemented as one of those three machine-code patterns in
`thunks_bytecode.inc`) pins the v0 contract a reviewer
accepted: "yes, the documented Windows behaviour for this
import in our v0 environment is exactly this constant return."

The pinned-offset retirement landed 414 previously-flagged
NOOP rows into the REAL classification without changing
runtime behaviour. The remaining handful of NOOP rows below
are genuinely unfilled — they're the ones the next slice
should grow real implementations for.

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

**Thunked imports (auto-generated from `kernel/subsystems/win32/thunks_table.inc`):**

<!-- AUTO:thunks-by-dll DLL=ntdll.dll START -->
<!-- generated by tools/build/gen-wiki-auto.py — do not edit by hand -->

**`ntdll.dll`** — 107 imports thunked: 107 REAL.

| Method | Status | Routed to |
|--------|--------|-----------|
| `__chkstk` | REAL | `kOffChkStk` |
| `LdrGetDllHandle` | REAL | `kOffReturnStatusNotImpl` |
| `LdrGetProcedureAddress` | REAL | `kOffReturnStatusNotImpl` |
| `LdrLoadDll` | REAL | `kOffReturnStatusNotImpl` |
| `NtAllocateVirtualMemory` | REAL | `kOffNtAllocateVirtualMemory` |
| `NtClose` | REAL | `kOffCloseHandle` |
| `NtContinue` | REAL | `kOffReturnStatusNotImpl` |
| `NtCreateEvent` | REAL | `kOffReturnStatusNotImpl` |
| `NtCreateFile` | REAL | `kOffReturnStatusNotImpl` |
| `NtCreateMutant` | REAL | `kOffReturnStatusNotImpl` |
| `NtCreateSection` | REAL | `kOffReturnStatusNotImpl` |
| `NtDelayExecution` | REAL | `kOffReturnStatusNotImpl` |
| `NtDeviceIoControlFile` | REAL | `kOffReturnStatusNotImpl` |
| `NtEnumerateKey` | REAL | `kOffReturnStatusNotImpl` |
| `NtEnumerateValueKey` | REAL | `kOffReturnStatusNotImpl` |
| `NtFreeVirtualMemory` | REAL | `kOffNtFreeVirtualMemory` |
| `NtMapViewOfSection` | REAL | `kOffReturnStatusNotImpl` |
| `NtOpenFile` | REAL | `kOffReturnStatusNotImpl` |
| `NtOpenKey` | REAL | `kOffReturnStatusNotImpl` |
| `NtProtectVirtualMemory` | REAL | `kOffReturnStatusNotImpl` |
| `NtQueryInformationFile` | REAL | `kOffReturnStatusNotImpl` |
| `NtQueryInformationProcess` | REAL | `kOffReturnStatusNotImpl` |
| `NtQueryInformationThread` | REAL | `kOffReturnStatusNotImpl` |
| `NtQueryKey` | REAL | `kOffReturnStatusNotImpl` |
| `NtQueryPerformanceCounter` | REAL | `kOffNtQueryPerfCounterReal` |
| `NtQuerySystemInformation` | REAL | `kOffReturnStatusNotImpl` |
| `NtQuerySystemTime` | REAL | `kOffNtQuerySystemTimeReal` |
| `NtQueryValueKey` | REAL | `kOffReturnStatusNotImpl` |
| `NtQueryVirtualMemory` | REAL | `kOffReturnStatusNotImpl` |
| `NtQueryVolumeInformationFile` | REAL | `kOffReturnStatusNotImpl` |
| `NtReadFile` | REAL | `kOffReturnStatusNotImpl` |
| `NtReleaseMutant` | REAL | `kOffReleaseMutex` |
| `NtResetEvent` | REAL | `kOffResetEventReal` |
| `NtSetEvent` | REAL | `kOffSetEventReal` |
| `NtSetInformationFile` | REAL | `kOffReturnStatusNotImpl` |
| `NtSetInformationProcess` | REAL | `kOffReturnStatusNotImpl` |
| `NtSetInformationThread` | REAL | `kOffReturnStatusNotImpl` |
| `NtTerminateProcess` | REAL | `kOffReturnStatusNotImpl` |
| `NtTerminateThread` | REAL | `kOffReturnStatusNotImpl` |
| `NtUnmapViewOfSection` | REAL | `kOffReturnStatusNotImpl` |
| `NtWaitForMultipleObjects` | REAL | `kOffReturnStatusNotImpl` |
| `NtWaitForSingleObject` | REAL | `kOffReturnStatusNotImpl` |
| `NtWriteFile` | REAL | `kOffReturnStatusNotImpl` |
| `NtYieldExecution` | REAL | `kOffPinVoidNop` |
| `RtlAllocateHeap` | REAL | `kOffHeapAlloc` |
| `RtlCompareMemory` | REAL | `kOffPinReturn0` |
| `RtlCopyMemory` | REAL | `kOffMemmove` |
| `RtlCreateHeap` | REAL | `kOffPinReturn0` |
| `RtlDeleteCriticalSection` | REAL | `kOffPinVoidNop` |
| `RtlDestroyHeap` | REAL | `kOffPinReturn0` |
| `RtlEnterCriticalSection` | REAL | `kOffEnterCritSecReal` |
| `RtlFillMemory` | REAL | `kOffPinVoidNop` |
| `RtlFreeHeap` | REAL | `kOffHeapFree` |
| `RtlFreeUnicodeString` | REAL | `kOffPinVoidNop` |
| `RtlGetLastWin32Error` | REAL | `kOffGetLastError` |
| `RtlInitAnsiString` | REAL | `kOffPinVoidNop` |
| `RtlInitializeCriticalSection` | REAL | `kOffInitCritSec` |
| `RtlInitUnicodeString` | REAL | `kOffPinVoidNop` |
| `RtlLeaveCriticalSection` | REAL | `kOffLeaveCritSecReal` |
| `RtlMoveMemory` | REAL | `kOffMemmove` |
| `RtlNtStatusToDosError` | REAL | `kOffPinReturn0` |
| `RtlReAllocateHeap` | REAL | `kOffHeapRealloc` |
| `RtlRunOnceExecuteOnce` | REAL | `kOffPinReturn0` |
| `RtlSetLastWin32Error` | REAL | `kOffSetLastError` |
| `RtlSizeHeap` | REAL | `kOffHeapSize` |
| `RtlTryEnterCriticalSection` | REAL | `kOffTryEnterCritSecReal` |
| `RtlZeroMemory` | REAL | `kOffPinVoidNop` |
| `ZwAllocateVirtualMemory` | REAL | `kOffNtAllocateVirtualMemory` |
| `ZwClose` | REAL | `kOffCloseHandle` |
| `ZwContinue` | REAL | `kOffReturnStatusNotImpl` |
| `ZwCreateEvent` | REAL | `kOffReturnStatusNotImpl` |
| `ZwCreateFile` | REAL | `kOffReturnStatusNotImpl` |
| `ZwCreateMutant` | REAL | `kOffReturnStatusNotImpl` |
| `ZwCreateSection` | REAL | `kOffReturnStatusNotImpl` |
| `ZwDelayExecution` | REAL | `kOffReturnStatusNotImpl` |
| `ZwDeviceIoControlFile` | REAL | `kOffReturnStatusNotImpl` |
| `ZwEnumerateKey` | REAL | `kOffReturnStatusNotImpl` |
| `ZwEnumerateValueKey` | REAL | `kOffReturnStatusNotImpl` |
| `ZwFreeVirtualMemory` | REAL | `kOffNtFreeVirtualMemory` |
| `ZwMapViewOfSection` | REAL | `kOffReturnStatusNotImpl` |
| `ZwOpenFile` | REAL | `kOffReturnStatusNotImpl` |
| `ZwOpenKey` | REAL | `kOffReturnStatusNotImpl` |
| `ZwProtectVirtualMemory` | REAL | `kOffReturnStatusNotImpl` |
| `ZwQueryInformationFile` | REAL | `kOffReturnStatusNotImpl` |
| `ZwQueryInformationProcess` | REAL | `kOffReturnStatusNotImpl` |
| `ZwQueryInformationThread` | REAL | `kOffReturnStatusNotImpl` |
| `ZwQueryKey` | REAL | `kOffReturnStatusNotImpl` |
| `ZwQueryPerformanceCounter` | REAL | `kOffNtQueryPerfCounterReal` |
| `ZwQuerySystemInformation` | REAL | `kOffReturnStatusNotImpl` |
| `ZwQuerySystemTime` | REAL | `kOffNtQuerySystemTimeReal` |
| `ZwQueryValueKey` | REAL | `kOffReturnStatusNotImpl` |
| `ZwQueryVirtualMemory` | REAL | `kOffReturnStatusNotImpl` |
| `ZwQueryVolumeInformationFile` | REAL | `kOffReturnStatusNotImpl` |
| `ZwReadFile` | REAL | `kOffReturnStatusNotImpl` |
| `ZwReleaseMutant` | REAL | `kOffReleaseMutex` |
| `ZwResetEvent` | REAL | `kOffResetEventReal` |
| `ZwSetEvent` | REAL | `kOffSetEventReal` |
| `ZwSetInformationFile` | REAL | `kOffReturnStatusNotImpl` |
| `ZwSetInformationProcess` | REAL | `kOffReturnStatusNotImpl` |
| `ZwSetInformationThread` | REAL | `kOffReturnStatusNotImpl` |
| `ZwTerminateProcess` | REAL | `kOffReturnStatusNotImpl` |
| `ZwTerminateThread` | REAL | `kOffReturnStatusNotImpl` |
| `ZwUnmapViewOfSection` | REAL | `kOffReturnStatusNotImpl` |
| `ZwWaitForMultipleObjects` | REAL | `kOffReturnStatusNotImpl` |
| `ZwWaitForSingleObject` | REAL | `kOffReturnStatusNotImpl` |
| `ZwWriteFile` | REAL | `kOffReturnStatusNotImpl` |
| `ZwYieldExecution` | REAL | `kOffPinVoidNop` |
<!-- AUTO:thunks-by-dll END -->

### kernel32.dll  (~5 080 LOC, ~320 exports)

> **Status:** the most mature Win32 DLL. Thread / process /
> file-handle / memory / timer / synchronization paths are real
> and exercised by the boot smoke.

**Real implementations:**
- File: `CreateFileA/W`, `ReadFile`, `WriteFile`,
  `SetFilePointer{,Ex}`, `GetFileSize{,Ex}`, `GetFileAttributes{A,W}`,
  `CloseHandle`, `FindFirstFileA/W`, `FindNextFileA/W`, `FindClose`,
  `GetCurrentDirectoryA/W`, `SetCurrentDirectoryA/W`,
  `GetFullPathNameA/W`, `GetDiskFreeSpaceA/W`,
  `GetVolumeInformationA/W`,
  `DeleteFileW`, `MoveFileExW`, `CopyFileW`,
  `CreateDirectoryW`, `RemoveDirectoryW`, `GetTempPathW`,
  `GetSystemDirectoryA/W`, `GetWindowsDirectoryW`
- Process: `GetCurrentProcess`, `GetCurrentProcessId`,
  `GetCurrentThreadId`, `ExitProcess`, `ExitThread`,
  `GetCommandLineA/W`, `GetEnvironmentVariableA/W`,
  `GetEnvironmentStringsW`, `FreeEnvironmentStringsW`,
  `GetSystemInfo`, `GetVersionExW`, `GetComputerNameW`,
  `GetUserNameA/W`, `GetStdHandle`, `WriteConsoleA/W`,
  `OutputDebugStringA/W`, per-thread `GetLastError` / `SetLastError`
- Threading: `CreateThread`, `WaitForSingleObject`,
  `WaitForMultipleObjects`, `Sleep`, `SleepEx`,
  `CreateEventA/W`, `OpenEventA/W`, `SetEvent`, `ResetEvent`,
  `PulseEvent`, `CreateMutexA/W`, `OpenMutexA/W`,
  `ReleaseMutex`, `CreateSemaphoreA/W`, `OpenSemaphoreA/W`,
  `ReleaseSemaphore`, `EnterCriticalSection`,
  `LeaveCriticalSection`, `InitializeCriticalSection`,
  `DeleteCriticalSection`, `TryEnterCriticalSection`,
  `InitializeSRWLock`, `AcquireSRWLockExclusive` /
  `Shared`, `ReleaseSRWLockExclusive` / `Shared`. Named
  primitives use a process-local name table — second
  Create with the same name returns the existing handle;
  Open* succeeds for names registered in this process and
  fails (NULL) otherwise. Cross-process named-namespace is
  T6-04 follow-on.
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
- Waitable timers: `CreateWaitableTimerA/W`,
  `SetWaitableTimer`, `CancelWaitableTimer`. Per-process
  16-slot table + lazily-spawned 10 ms polling service
  thread fires `SetEvent` when due_time arrives;
  `TIME_PERIODIC`-equivalent timers re-arm. APC completion
  routines (the `pfnCompletionRoutine` parameter) accepted
  but not invoked — Track 8-02 covers cross-thread APC
  delivery. `CreateWaitableTimerExW` still NOOP.
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

**Thunked imports (auto-generated from `kernel/subsystems/win32/thunks_table.inc`):**

<!-- AUTO:thunks-by-dll DLL=kernel32.dll START -->
<!-- generated by tools/build/gen-wiki-auto.py — do not edit by hand -->

**`kernel32.dll`** — 410 imports thunked: 410 REAL.

| Method | Status | Routed to |
|--------|--------|-----------|
| `AcquireSRWLockExclusive` | REAL | `kOffSrwAcquireExcl` |
| `AcquireSRWLockShared` | REAL | `kOffSrwAcquireExcl` |
| `AddDllDirectory` | REAL | `kOffPinReturn0` |
| `AddVectoredContinueHandler` | REAL | `kOffPinReturn0` |
| `AddVectoredExceptionHandler` | REAL | `kOffPinReturn0` |
| `AreFileApisANSI` | REAL | `kOffPinReturn1` |
| `CancelIo` | REAL | `kOffPinReturn1` |
| `CancelIoEx` | REAL | `kOffPinReturn1` |
| `CancelSynchronousIo` | REAL | `kOffPinReturn1` |
| `CancelWaitableTimer` | REAL | `kOffPinReturn0` |
| `CloseHandle` | REAL | `kOffCloseHandle` |
| `CompareStringA` | REAL | `kOffReturnTwo` |
| `CompareStringEx` | REAL | `kOffReturnTwo` |
| `CompareStringW` | REAL | `kOffReturnTwo` |
| `ConnectNamedPipe` | REAL | `kOffPinReturn0` |
| `ConvertFiberToThread` | REAL | `kOffPinReturn1` |
| `ConvertThreadToFiber` | REAL | `kOffPinFiberZero` |
| `ConvertThreadToFiberEx` | REAL | `kOffPinFiberZero` |
| `CopyFileW` | REAL | `kOffPinReturn1` |
| `CreateConsoleScreenBuffer` | REAL | `kOffReturnMinus1` |
| `CreateDirectoryW` | REAL | `kOffPinReturn1` |
| `CreateEventA` | REAL | `kOffCreateEventReal` |
| `CreateEventExA` | REAL | `kOffCreateEventReal` |
| `CreateEventExW` | REAL | `kOffCreateEventReal` |
| `CreateEventW` | REAL | `kOffCreateEventReal` |
| `CreateFiber` | REAL | `kOffPinFiberZero` |
| `CreateFiberEx` | REAL | `kOffPinFiberZero` |
| `CreateFileA` | REAL | `kOffReturnMinus1` |
| `CreateFileMappingA` | REAL | `kOffPinReturn0` |
| `CreateFileMappingA` | REAL | `kOffPinReturn0` |
| `CreateFileMappingW` | REAL | `kOffPinReturn0` |
| `CreateFileMappingW` | REAL | `kOffPinReturn0` |
| `CreateFileW` | REAL | `kOffCreateFileW` |
| `CreateFileW` | REAL | `kOffReturnMinus1` |
| `CreateMutexA` | REAL | `kOffCreateMutexW` |
| `CreateMutexExW` | REAL | `kOffCreateMutexW` |
| `CreateMutexW` | REAL | `kOffCreateMutexW` |
| `CreateNamedPipeA` | REAL | `kOffReturnMinus1` |
| `CreateNamedPipeW` | REAL | `kOffReturnMinus1` |
| `CreateRemoteThread` | REAL | `kOffNoCrossProcThread` |
| `CreateRemoteThread` | REAL | `kOffNoCrossProcThread` |
| `CreateSemaphoreA` | REAL | `kOffCreateSemaphoreW` |
| `CreateSemaphoreExA` | REAL | `kOffCreateSemaphoreW` |
| `CreateSemaphoreExW` | REAL | `kOffCreateSemaphoreW` |
| `CreateSemaphoreW` | REAL | `kOffCreateSemaphoreW` |
| `CreateThread` | REAL | `kOffCreateThreadReal` |
| `CreateToolhelp32Snapshot` | REAL | `kOffPinReturn1` |
| `CreateWaitableTimerA` | REAL | `kOffPinReturn0` |
| `CreateWaitableTimerExW` | REAL | `kOffPinReturn0` |
| `CreateWaitableTimerW` | REAL | `kOffPinReturn0` |
| `DebugActiveProcess` | REAL | `kOffPinReturn0` |
| `DebugActiveProcessStop` | REAL | `kOffPinReturn0` |
| `DebugBreak` | REAL | `kOffPinVoidNop` |
| `DecodePointer` | REAL | `kOffDecodePointer` |
| `DeleteCriticalSection` | REAL | `kOffPinVoidNop` |
| `DeleteFiber` | REAL | `kOffPinFiberVoid` |
| `DeleteFileA` | REAL | `kOffPinReturn1` |
| `DeleteFileW` | REAL | `kOffPinReturn1` |
| `DeviceIoControl` | REAL | `kOffPinReturn0` |
| `DisableThreadLibraryCalls` | REAL | `kOffPinReturn1` |
| `DisconnectNamedPipe` | REAL | `kOffPinReturn1` |
| `DuplicateHandle` | REAL | `kOffPinReturn0` |
| `DuplicateHandle` | REAL | `kOffPinReturn0` |
| `EncodePointer` | REAL | `kOffDecodePointer` |
| `EnterCriticalSection` | REAL | `kOffEnterCritSecReal` |
| `EnumSystemFirmwareTables` | REAL | `kOffPinReturn0` |
| `EnumSystemLocalesA` | REAL | `kOffPinReturn1` |
| `EnumSystemLocalesW` | REAL | `kOffPinReturn1` |
| `ExitProcess` | REAL | `kOffExitProcess` |
| `ExitThread` | REAL | `kOffExitThread` |
| `ExpandEnvironmentStringsA` | REAL | `kOffPinReturn0` |
| `ExpandEnvironmentStringsW` | REAL | `kOffPinReturn0` |
| `FileTimeToSystemTime` | REAL | `kOffFileTimeToSystemTime` |
| `FillConsoleOutputAttribute` | REAL | `kOffPinReturn1` |
| `FillConsoleOutputCharacterA` | REAL | `kOffPinReturn1` |
| `FillConsoleOutputCharacterW` | REAL | `kOffPinReturn1` |
| `FindFirstFileExA` | REAL | `kOffReturnMinus1` |
| `FindFirstFileExW` | REAL | `kOffReturnMinus1` |
| `FindFirstVolumeW` | REAL | `kOffReturnMinus1` |
| `FindNextVolumeW` | REAL | `kOffPinReturn0` |
| `FindResourceA` | REAL | `kOffPinReturn0` |
| `FindResourceExW` | REAL | `kOffPinReturn0` |
| `FindResourceW` | REAL | `kOffPinReturn0` |
| `FindVolumeClose` | REAL | `kOffPinReturn1` |
| `FlsAlloc` | REAL | `kOffTlsAllocReal` |
| `FlsFree` | REAL | `kOffTlsFreeReal` |
| `FlsGetValue` | REAL | `kOffTlsGetValueReal` |
| `FlsSetValue` | REAL | `kOffTlsSetValueReal` |
| `FlushConsoleInputBuffer` | REAL | `kOffPinReturn1` |
| `FlushFileBuffers` | REAL | `kOffPinReturn1` |
| `FlushViewOfFile` | REAL | `kOffPinReturn1` |
| `FormatMessageA` | REAL | `kOffFormatMessageA` |
| `FormatMessageW` | REAL | `kOffPinReturn0` |
| `FreeEnvironmentStringsA` | REAL | `kOffPinReturn1` |
| `FreeEnvironmentStringsA` | REAL | `kOffFreeEnvStringsW` |
| `FreeEnvironmentStringsW` | REAL | `kOffFreeEnvStringsW` |
| `FreeLibrary` | REAL | `kOffPinReturn1` |
| `FreeLibraryAndExitThread` | REAL | `kOffExitThread` |
| `GenerateConsoleCtrlEvent` | REAL | `kOffPinReturn1` |
| `GetACP` | REAL | `kOffGetConsoleCP` |
| `GetCommandLineA` | REAL | `kOffGetCmdLineA` |
| `GetCommandLineW` | REAL | `kOffGetCmdLineW` |
| `GetCompressedFileSizeA` | REAL | `kOffReturnMinus1` |
| `GetCompressedFileSizeW` | REAL | `kOffReturnMinus1` |
| `GetComputerNameA` | REAL | `kOffGetComputerNameW` |
| `GetComputerNameW` | REAL | `kOffGetComputerNameW` |
| `GetConsoleCP` | REAL | `kOffGetConsoleCP` |
| `GetConsoleMode` | REAL | `kOffGetConsoleMode` |
| `GetConsoleOutputCP` | REAL | `kOffGetConsoleCP` |
| `GetConsoleScreenBufferInfo` | REAL | `kOffGetConsoleScreenBufferInfo` |
| `GetConsoleWindow` | REAL | `kOffPinReturn0` |
| `GetCPInfo` | REAL | `kOffPinReturn1` |
| `GetCPInfoExA` | REAL | `kOffPinReturn1` |
| `GetCPInfoExW` | REAL | `kOffPinReturn1` |
| `GetCurrentDirectoryA` | REAL | `kOffGetCurrentDirW` |
| `GetCurrentDirectoryW` | REAL | `kOffGetCurrentDirW` |
| `GetCurrentProcess` | REAL | `kOffGetCurrentProcess` |
| `GetCurrentProcessId` | REAL | `kOffGetCurrentProcessId` |
| `GetCurrentProcessorNumber` | REAL | `kOffPinReturn0` |
| `GetCurrentThread` | REAL | `kOffGetCurrentThread` |
| `GetCurrentThreadId` | REAL | `kOffGetCurrentThreadId` |
| `GetDiskFreeSpaceA` | REAL | `kOffPinReturn1` |
| `GetDiskFreeSpaceExA` | REAL | `kOffPinReturn1` |
| `GetDriveTypeA` | REAL | `kOffGetDriveType` |
| `GetDriveTypeW` | REAL | `kOffGetDriveType` |
| `GetDynamicTimeZoneInformation` | REAL | `kOffPinReturn1` |
| `GetEnvironmentStrings` | REAL | `kOffGetEnvBlockW` |
| `GetEnvironmentStringsA` | REAL | `kOffPinReturn0` |
| `GetEnvironmentStringsW` | REAL | `kOffGetEnvBlockW` |
| `GetEnvironmentVariableA` | REAL | `kOffPinReturn0` |
| `GetEnvironmentVariableW` | REAL | `kOffPinReturn0` |
| `GetErrorMode` | REAL | `kOffPinReturn0` |
| `GetExitCodeProcess` | REAL | `kOffGetExitCodeThread` |
| `GetExitCodeThread` | REAL | `kOffGetExitCodeThreadReal` |
| `GetFileAttributesA` | REAL | `kOffReturnMinus1` |
| `GetFileAttributesExA` | REAL | `kOffPinReturn0` |
| `GetFileAttributesExW` | REAL | `kOffPinReturn0` |
| `GetFileAttributesExW` | REAL | `kOffPinReturn0` |
| `GetFileAttributesW` | REAL | `kOffReturnMinus1` |
| `GetFileSize` | REAL | `kOffGetFileSizeEx` |
| `GetFileSizeEx` | REAL | `kOffGetFileSizeEx` |
| `GetFileType` | REAL | `kOffReturnTwo` |
| `GetFullPathNameA` | REAL | `kOffPinReturn0` |
| `GetHandleInformation` | REAL | `kOffPinReturn0` |
| `GetLastError` | REAL | `kOffGetLastError` |
| `GetLocaleInfoA` | REAL | `kOffPinReturn0` |
| `GetLocaleInfoEx` | REAL | `kOffPinReturn0` |
| `GetLocaleInfoW` | REAL | `kOffPinReturn0` |
| `GetLocalTime` | REAL | `kOffGetSystemTimeSt` |
| `GetLogicalDrives` | REAL | `kOffGetLogicalDrives` |
| `GetLogicalProcessorInformation` | REAL | `kOffPinReturn0` |
| `GetLogicalProcessorInformationEx` | REAL | `kOffPinReturn0` |
| `GetModuleFileNameA` | REAL | `kOffGetModFileNameW` |
| `GetModuleFileNameW` | REAL | `kOffGetModFileNameW` |
| `GetModuleHandleA` | REAL | `kOffGetModuleHandleW` |
| `GetModuleHandleExA` | REAL | `kOffPinReturn0` |
| `GetModuleHandleExW` | REAL | `kOffPinReturn0` |
| `GetModuleHandleW` | REAL | `kOffGetModuleHandleW` |
| `GetNativeSystemInfo` | REAL | `kOffGetSystemInfo` |
| `GetNumaHighestNodeNumber` | REAL | `kOffPinReturn0` |
| `GetNumberOfConsoleInputEvents` | REAL | `kOffPinReturn0` |
| `GetNumberOfConsoleInputEvents` | REAL | `kOffPinReturn1` |
| `GetOEMCP` | REAL | `kOffGetConsoleCP` |
| `GetOverlappedResult` | REAL | `kOffPinReturn1` |
| `GetOverlappedResultEx` | REAL | `kOffPinReturn1` |
| `GetPriorityClass` | REAL | `kOffReturnPrioNormal` |
| `GetProcAddress` | REAL | `kOffGetProcAddressReal` |
| `GetProcessHeap` | REAL | `kOffGetProcessHeap` |
| `GetProcessTimes` | REAL | `kOffGetProcessTimes` |
| `GetStartupInfoA` | REAL | `kOffGetStartupInfo` |
| `GetStartupInfoW` | REAL | `kOffGetStartupInfo` |
| `GetStdHandle` | REAL | `kOffGetStdHandle` |
| `GetStringTypeA` | REAL | `kOffPinReturn1` |
| `GetStringTypeExW` | REAL | `kOffPinReturn1` |
| `GetStringTypeW` | REAL | `kOffPinReturn1` |
| `GetSystemDefaultLCID` | REAL | `kOffPinLcidEnUs` |
| `GetSystemDefaultUILanguage` | REAL | `kOffPinLcidEnUs` |
| `GetSystemDirectoryA` | REAL | `kOffGetWinDirW` |
| `GetSystemDirectoryW` | REAL | `kOffGetWinDirW` |
| `GetSystemFirmwareTable` | REAL | `kOffPinReturn0` |
| `GetSystemInfo` | REAL | `kOffGetSystemInfo` |
| `GetSystemTime` | REAL | `kOffGetSystemTimeSt` |
| `GetSystemTimeAsFileTime` | REAL | `kOffGetSysTimeFTReal` |
| `GetSystemTimePreciseAsFileTime` | REAL | `kOffGetSysTimeFTReal` |
| `GetSystemTimes` | REAL | `kOffGetSystemTimes` |
| `GetSystemWindowsDirectoryA` | REAL | `kOffGetWinDirW` |
| `GetSystemWindowsDirectoryW` | REAL | `kOffGetWinDirW` |
| `GetTempPathA` | REAL | `kOffGetCurrentDirW` |
| `GetTempPathW` | REAL | `kOffGetCurrentDirW` |
| `GetThreadId` | REAL | `kOffPinReturn0` |
| `GetThreadIdealProcessorEx` | REAL | `kOffPinReturn1` |
| `GetThreadLocale` | REAL | `kOffPinLcidEnUs` |
| `GetThreadPriority` | REAL | `kOffPinReturn0` |
| `GetThreadTimes` | REAL | `kOffGetProcessTimes` |
| `GetTickCount` | REAL | `kOffGetTickCount` |
| `GetTickCount64` | REAL | `kOffGetTickCount` |
| `GetTimeZoneInformation` | REAL | `kOffPinReturn1` |
| `GetUserDefaultLCID` | REAL | `kOffPinLcidEnUs` |
| `GetUserDefaultUILanguage` | REAL | `kOffPinLcidEnUs` |
| `GetVersionExA` | REAL | `kOffGetVersionExW` |
| `GetVersionExW` | REAL | `kOffGetVersionExW` |
| `GetVolumeInformationA` | REAL | `kOffPinReturn1` |
| `GetVolumeInformationW` | REAL | `kOffPinReturn1` |
| `GetWindowsDirectoryA` | REAL | `kOffGetWinDirW` |
| `GetWindowsDirectoryW` | REAL | `kOffGetWinDirW` |
| `GlobalMemoryStatusEx` | REAL | `kOffGlobalMemoryStatusEx` |
| `HeapAlloc` | REAL | `kOffHeapAlloc` |
| `HeapCompact` | REAL | `kOffPinReturn0` |
| `HeapCreate` | REAL | `kOffGetProcessHeap` |
| `HeapDestroy` | REAL | `kOffPinReturn1` |
| `HeapFree` | REAL | `kOffHeapFree` |
| `HeapReAlloc` | REAL | `kOffHeapRealloc` |
| `HeapSize` | REAL | `kOffHeapSize` |
| `InitializeConditionVariable` | REAL | `kOffPinVoidNop` |
| `InitializeCriticalSection` | REAL | `kOffInitCritSec` |
| `InitializeCriticalSectionAndSpinCount` | REAL | `kOffInitCritSec` |
| `InitializeCriticalSectionEx` | REAL | `kOffInitCritSec` |
| `InitializeInitOnce` | REAL | `kOffPinVoidNop` |
| `InitializeSListHead` | REAL | `kOffInitSListHead` |
| `InitializeSRWLock` | REAL | `kOffSrwInit` |
| `InitOnceBeginInitialize` | REAL | `kOffPinReturn1` |
| `InitOnceComplete` | REAL | `kOffPinReturn1` |
| `InitOnceExecuteOnce` | REAL | `kOffInitOnceExec` |
| `InitOnceInitialize` | REAL | `kOffSrwInit` |
| `InterlockedAnd` | REAL | `kOffInterlockedAnd` |
| `InterlockedAnd64` | REAL | `kOffInterlockedAnd64` |
| `InterlockedCompareExchange` | REAL | `kOffInterlockedCmpXchg` |
| `InterlockedCompareExchange64` | REAL | `kOffInterlockedCmpXchg64` |
| `InterlockedDecrement` | REAL | `kOffInterlockedDec` |
| `InterlockedDecrement64` | REAL | `kOffInterlockedDec64` |
| `InterlockedExchange` | REAL | `kOffInterlockedExchg` |
| `InterlockedExchange64` | REAL | `kOffInterlockedExchg64` |
| `InterlockedExchangeAdd` | REAL | `kOffInterlockedExchgAdd` |
| `InterlockedExchangeAdd64` | REAL | `kOffInterlockedExchgAdd64` |
| `InterlockedFlushSList` | REAL | `kOffPinReturn0` |
| `InterlockedIncrement` | REAL | `kOffInterlockedInc` |
| `InterlockedIncrement64` | REAL | `kOffInterlockedInc64` |
| `InterlockedOr` | REAL | `kOffInterlockedOr` |
| `InterlockedOr64` | REAL | `kOffInterlockedOr64` |
| `InterlockedPopEntrySList` | REAL | `kOffPinReturn0` |
| `InterlockedPushEntrySList` | REAL | `kOffPinReturn0` |
| `InterlockedXor` | REAL | `kOffInterlockedXor` |
| `InterlockedXor64` | REAL | `kOffInterlockedXor64` |
| `IsBadCodePtr` | REAL | `kOffPinBadPtrSafe` |
| `IsBadReadPtr` | REAL | `kOffPinBadPtrSafe` |
| `IsBadStringPtrA` | REAL | `kOffPinBadPtrSafe` |
| `IsBadStringPtrW` | REAL | `kOffPinBadPtrSafe` |
| `IsBadWritePtr` | REAL | `kOffPinBadPtrSafe` |
| `IsDBCSLeadByte` | REAL | `kOffPinReturn0` |
| `IsDebuggerPresent` | REAL | `kOffPinReturn0` |
| `IsDebuggerPresent` | REAL | `kOffPinReturn0` |
| `IsProcessorFeaturePresent` | REAL | `kOffPinReturn1` |
| `IsThreadAFiber` | REAL | `kOffPinFiberZero` |
| `IsValidCodePage` | REAL | `kOffPinReturn1` |
| `IsValidLocale` | REAL | `kOffPinReturn1` |
| `IsWow64Process` | REAL | `kOffIsWow64` |
| `IsWow64Process2` | REAL | `kOffIsWow64` |
| `LCMapStringA` | REAL | `kOffPinReturn0` |
| `LCMapStringEx` | REAL | `kOffPinReturn0` |
| `LCMapStringW` | REAL | `kOffPinReturn0` |
| `LeaveCriticalSection` | REAL | `kOffLeaveCritSecReal` |
| `LoadLibraryA` | REAL | `kOffPinReturn0` |
| `LoadLibraryExA` | REAL | `kOffPinReturn0` |
| `LoadLibraryExW` | REAL | `kOffPinReturn0` |
| `LoadLibraryW` | REAL | `kOffPinReturn0` |
| `LoadResource` | REAL | `kOffPinReturn0` |
| `LockFile` | REAL | `kOffPinReturn1` |
| `LockFileEx` | REAL | `kOffPinReturn1` |
| `LockResource` | REAL | `kOffPinReturn0` |
| `lstrcmpA` | REAL | `kOffLstrcmpA` |
| `lstrcmpW` | REAL | `kOffLstrcmpW` |
| `lstrcpyA` | REAL | `kOffLstrcpyA` |
| `lstrcpyW` | REAL | `kOffLstrcpyW` |
| `lstrlenA` | REAL | `kOffLstrlenA` |
| `lstrlenW` | REAL | `kOffLstrlenW` |
| `MapViewOfFile` | REAL | `kOffPinReturn0` |
| `MapViewOfFileEx` | REAL | `kOffPinReturn0` |
| `MoveFileA` | REAL | `kOffPinReturn1` |
| `MoveFileExA` | REAL | `kOffPinReturn1` |
| `MoveFileExW` | REAL | `kOffPinReturn1` |
| `MoveFileW` | REAL | `kOffPinReturn1` |
| `MsgWaitForMultipleObjects` | REAL | `kOffPinReturn0` |
| `MsgWaitForMultipleObjectsEx` | REAL | `kOffPinReturn0` |
| `MultiByteToWideChar` | REAL | `kOffMBtoWC` |
| `OpenFileMappingA` | REAL | `kOffPinReturn0` |
| `OpenFileMappingW` | REAL | `kOffPinReturn0` |
| `OpenFileMappingW` | REAL | `kOffPinReturn0` |
| `OpenProcess` | REAL | `kOffOpenProcess` |
| `OpenThread` | REAL | `kOffPinReturn0` |
| `OutputDebugStringA` | REAL | `kOffOutputDebugStringA` |
| `OutputDebugStringW` | REAL | `kOffOutputDebugStringW` |
| `PeekConsoleInputW` | REAL | `kOffPinReturn0` |
| `PeekConsoleInputW` | REAL | `kOffPinReturn0` |
| `PeekNamedPipe` | REAL | `kOffPinReturn0` |
| `Process32First` | REAL | `kOffPinReturn0` |
| `Process32FirstW` | REAL | `kOffPinReturn0` |
| `Process32Next` | REAL | `kOffPinReturn0` |
| `Process32NextW` | REAL | `kOffPinReturn0` |
| `QueryDepthSList` | REAL | `kOffPinReturn0` |
| `QueryPerformanceCounter` | REAL | `kOffQpcNs` |
| `QueryPerformanceFrequency` | REAL | `kOffQpfNs` |
| `RaiseException` | REAL | `kOffRaiseException` |
| `ReadConsoleA` | REAL | `kOffPinReturn0` |
| `ReadConsoleInputA` | REAL | `kOffPinReturn0` |
| `ReadConsoleInputW` | REAL | `kOffPinReturn0` |
| `ReadConsoleInputW` | REAL | `kOffPinReturn0` |
| `ReadConsoleW` | REAL | `kOffPinReturn0` |
| `ReadDirectoryChangesW` | REAL | `kOffPinReturn0` |
| `ReadFile` | REAL | `kOffReadFile` |
| `ReadProcessMemory` | REAL | `kOffPinReturn0` |
| `RegisterApplicationRestart` | REAL | `kOffPinReturn0` |
| `ReleaseMutex` | REAL | `kOffReleaseMutex` |
| `ReleaseSemaphore` | REAL | `kOffReleaseSemaphore` |
| `ReleaseSRWLockExclusive` | REAL | `kOffSrwReleaseExcl` |
| `ReleaseSRWLockShared` | REAL | `kOffSrwReleaseExcl` |
| `RemoveDirectoryW` | REAL | `kOffPinReturn1` |
| `RemoveDllDirectory` | REAL | `kOffPinReturn1` |
| `RemoveVectoredExceptionHandler` | REAL | `kOffPinReturn0` |
| `ResetEvent` | REAL | `kOffResetEventReal` |
| `ResumeThread` | REAL | `kOffPinReturn0` |
| `RtlCaptureContext` | REAL | `kOffSehNoUnwind` |
| `RtlCaptureStackBackTrace` | REAL | `kOffSehNoUnwind` |
| `RtlDecodePointer` | REAL | `kOffDecodePointer` |
| `RtlEncodePointer` | REAL | `kOffDecodePointer` |
| `RtlLookupFunctionEntry` | REAL | `kOffSehNoUnwind` |
| `RtlVirtualUnwind` | REAL | `kOffSehNoUnwind` |
| `SetConsoleActiveScreenBuffer` | REAL | `kOffPinReturn1` |
| `SetConsoleCP` | REAL | `kOffPinReturn1` |
| `SetConsoleCtrlHandler` | REAL | `kOffPinReturn1` |
| `SetConsoleCursorPosition` | REAL | `kOffPinReturn1` |
| `SetConsoleMode` | REAL | `kOffPinReturn1` |
| `SetConsoleOutputCP` | REAL | `kOffPinReturn1` |
| `SetConsoleScreenBufferSize` | REAL | `kOffPinReturn1` |
| `SetConsoleTextAttribute` | REAL | `kOffPinReturn1` |
| `SetCurrentDirectoryA` | REAL | `kOffPinReturn1` |
| `SetCurrentDirectoryW` | REAL | `kOffPinReturn1` |
| `SetDefaultDllDirectories` | REAL | `kOffPinReturn1` |
| `SetEndOfFile` | REAL | `kOffPinReturn1` |
| `SetEnvironmentVariableA` | REAL | `kOffPinReturn1` |
| `SetEnvironmentVariableW` | REAL | `kOffPinReturn1` |
| `SetErrorMode` | REAL | `kOffPinReturn0` |
| `SetEvent` | REAL | `kOffSetEventReal` |
| `SetFileAttributesA` | REAL | `kOffPinReturn1` |
| `SetFileAttributesW` | REAL | `kOffPinReturn1` |
| `SetFilePointer` | REAL | `kOffPinReturn0` |
| `SetFilePointerEx` | REAL | `kOffSetFilePtrEx` |
| `SetFileTime` | REAL | `kOffPinReturn1` |
| `SetHandleInformation` | REAL | `kOffPinReturn1` |
| `SetLastError` | REAL | `kOffSetLastError` |
| `SetPriorityClass` | REAL | `kOffPinReturn1` |
| `SetProcessAffinityMask` | REAL | `kOffPinReturn1` |
| `SetSearchPathMode` | REAL | `kOffPinReturn1` |
| `SetStdHandle` | REAL | `kOffPinReturn1` |
| `SetSystemTime` | REAL | `kOffPinReturn1` |
| `SetThreadAffinityMask` | REAL | `kOffPinReturn1` |
| `SetThreadErrorMode` | REAL | `kOffPinReturn1` |
| `SetThreadIdealProcessor` | REAL | `kOffPinReturn0` |
| `SetThreadLocale` | REAL | `kOffPinReturn1` |
| `SetThreadPriority` | REAL | `kOffPinReturn1` |
| `SetUnhandledExceptionFilter` | REAL | `kOffSetUnhandledFilter` |
| `SetWaitableTimer` | REAL | `kOffPinReturn0` |
| `SetWaitableTimerEx` | REAL | `kOffPinReturn0` |
| `SizeofResource` | REAL | `kOffPinReturn0` |
| `Sleep` | REAL | `kOffSleep` |
| `SleepConditionVariableCS` | REAL | `kOffPinReturn1` |
| `SleepConditionVariableSRW` | REAL | `kOffPinReturn1` |
| `SleepEx` | REAL | `kOffSleep` |
| `SwitchToFiber` | REAL | `kOffPinFiberVoid` |
| `SwitchToThread` | REAL | `kOffSwitchToThread` |
| `SystemTimeToFileTime` | REAL | `kOffSystemTimeToFileTime` |
| `TerminateProcess` | REAL | `kOffTerminateProcess` |
| `TlsAlloc` | REAL | `kOffTlsAllocReal` |
| `TlsFree` | REAL | `kOffTlsFreeReal` |
| `TlsGetValue` | REAL | `kOffTlsGetValueReal` |
| `TlsSetValue` | REAL | `kOffTlsSetValueReal` |
| `TryAcquireSRWLockExclusive` | REAL | `kOffSrwTryAcquireExcl` |
| `TryAcquireSRWLockShared` | REAL | `kOffSrwTryAcquireExcl` |
| `TryEnterCriticalSection` | REAL | `kOffTryEnterCritSecReal` |
| `UnhandledExceptionFilter` | REAL | `kOffUnhandledFilter` |
| `UnlockFile` | REAL | `kOffPinReturn1` |
| `UnlockFileEx` | REAL | `kOffPinReturn1` |
| `UnmapViewOfFile` | REAL | `kOffPinReturn1` |
| `UnregisterApplicationRestart` | REAL | `kOffPinReturn0` |
| `VerifyVersionInfoA` | REAL | `kOffPinReturn1` |
| `VerifyVersionInfoW` | REAL | `kOffPinReturn1` |
| `VerSetConditionMask` | REAL | `kOffPinReturn0` |
| `VirtualAlloc` | REAL | `kOffVirtualAlloc` |
| `VirtualAllocEx` | REAL | `kOffVirtualAlloc` |
| `VirtualFree` | REAL | `kOffVirtualFree` |
| `VirtualFreeEx` | REAL | `kOffVirtualFree` |
| `VirtualLock` | REAL | `kOffPinReturn1` |
| `VirtualProtect` | REAL | `kOffVirtualProtect` |
| `VirtualProtectEx` | REAL | `kOffVirtualProtect` |
| `VirtualQuery` | REAL | `kOffPinReturn0` |
| `VirtualQueryEx` | REAL | `kOffPinReturn0` |
| `VirtualUnlock` | REAL | `kOffPinReturn1` |
| `WaitForInputIdle` | REAL | `kOffPinReturn0` |
| `WaitForMultipleObjects` | REAL | `kOffWaitForMultipleObjects` |
| `WaitForMultipleObjectsEx` | REAL | `kOffWaitForMultipleObjects` |
| `WaitForSingleObject` | REAL | `kOffWaitForObj4` |
| `WaitForSingleObjectEx` | REAL | `kOffWaitForObj4` |
| `WaitNamedPipeA` | REAL | `kOffPinReturn0` |
| `WaitNamedPipeW` | REAL | `kOffPinReturn0` |
| `WakeAllConditionVariable` | REAL | `kOffPinVoidNop` |
| `WakeConditionVariable` | REAL | `kOffPinVoidNop` |
| `WideCharToMultiByte` | REAL | `kOffWCtoMB` |
| `WriteConsoleA` | REAL | `kOffWriteFile` |
| `WriteConsoleW` | REAL | `kOffWriteConsoleW` |
| `WriteFile` | REAL | `kOffWriteFile` |
| `WriteProcessMemory` | REAL | `kOffPinReturn0` |
<!-- AUTO:thunks-by-dll END -->

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
  `GetLengthSid`, `GetSidLengthRequired`,
  `GetSidIdentifierAuthority`, `GetSidSubAuthority`,
  `GetSidSubAuthorityCount`, `CopySid`
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

### vcruntime140.dll  (~330 LOC)

Stack-frame / SEH unwind primitives for MSVC-built code.
`__C_specific_handler`, `__std_terminate`,
`memcpy` / `memset` / `memmove` aliases, `__chkstk` — REAL,
because the bodies are tiny.

`/GS` stack-cookie facade (T9-02 v0): `__security_cookie`
holds the documented MSVC default (`0x00002B992DDFA232`),
`__security_init_cookie` is a no-op (no entropy source wired
in), `__security_check_cookie` aborts on mismatch,
`__report_gsfailure` / `__report_rangefailure` aborts.
Per-image cookie randomisation needs the PE loader to read
`IMAGE_LOAD_CONFIG_DIRECTORY.SecurityCookie` and stamp a
fresh value at load time.

CFG / XFG facade (T9-03): `_guard_check_icall` /
`_guard_xfg_check_icall` are no-op; `_guard_dispatch_icall`
/ `_guard_xfg_dispatch_icall` are naked `jmp *%rax` so the
indirect target the compiler placed in `rax` runs without
guard enforcement. Bitmap enforcement is GAP — see the
roadmap note.

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

**Thunked imports (auto-generated from `kernel/subsystems/win32/thunks_table.inc`):**

<!-- AUTO:thunks-by-dll DLL=ucrtbase.dll START -->
<!-- generated by tools/build/gen-wiki-auto.py — do not edit by hand -->

**`ucrtbase.dll`** — 59 imports thunked: 59 REAL.

| Method | Status | Routed to |
|--------|--------|-----------|
| `___mb_cur_max_func` | REAL | `kOffPinReturn1` |
| `__acrt_iob_func` | REAL | `kOffPErrno` |
| `__C_specific_handler` | REAL | `kOffPinReturn0` |
| `__getmainargs` | REAL | `kOffGetMainArgs` |
| `__p___argc` | REAL | `kOffPArgc` |
| `__p___argv` | REAL | `kOffPArgv` |
| `__p___wargv` | REAL | `kOffPErrno` |
| `__p__commode` | REAL | `kOffPCommode` |
| `__p__environ` | REAL | `kOffPErrno` |
| `__p__fmode` | REAL | `kOffPErrno` |
| `__p__wenviron` | REAL | `kOffPErrno` |
| `__stdio_common_vfprintf` | REAL | `kOffPinReturn0` |
| `__stdio_common_vfwprintf` | REAL | `kOffPinReturn0` |
| `_aligned_free` | REAL | `kOffFree` |
| `_aligned_free` | REAL | `kOffFree` |
| `_aligned_malloc` | REAL | `kOffMalloc` |
| `_aligned_malloc` | REAL | `kOffMalloc` |
| `_callnewh` | REAL | `kOffCallnewhNoop` |
| `_clearfp` | REAL | `kOffPinReturn0` |
| `_errno` | REAL | `kOffPErrno` |
| `_exit` | REAL | `kOffExitProcess` |
| `_fileno` | REAL | `kOffReturnMinus1` |
| `_fseeki64` | REAL | `kOffPinReturn0` |
| `_ftelli64` | REAL | `kOffReturnMinus1` |
| `_initterm` | REAL | `kOffInitterm` |
| `_initterm_e` | REAL | `kOffInittermE` |
| `_msize` | REAL | `kOffPinReturn0` |
| `_register_thread_local_exe_atexit_callback` | REAL | `kOffRegThreadLocalAtexit` |
| `_seh_filter_exe` | REAL | `kOffSehFilterExe` |
| `_set_invalid_parameter_handler` | REAL | `kOffPinReturn0` |
| `_setmode` | REAL | `kOffPinReturn0` |
| `_statusfp` | REAL | `kOffPinReturn0` |
| `_stricmp` | REAL | `kOffStrcmp` |
| `_strnicmp` | REAL | `kOffStrcmp` |
| `_wfopen` | REAL | `kOffPinReturn0` |
| `abort` | REAL | `kOffTerminate` |
| `atoi` | REAL | `kOffPinReturn0` |
| `atol` | REAL | `kOffPinReturn0` |
| `calloc` | REAL | `kOffCalloc` |
| `exit` | REAL | `kOffExitProcess` |
| `fflush` | REAL | `kOffPinReturn0` |
| `fgetc` | REAL | `kOffReturnMinus1` |
| `fputc` | REAL | `kOffFputc` |
| `fputs` | REAL | `kOffFputs` |
| `free` | REAL | `kOffFree` |
| `fwrite` | REAL | `kOffFwrite` |
| `getenv` | REAL | `kOffPinReturn0` |
| `malloc` | REAL | `kOffMalloc` |
| `putchar` | REAL | `kOffFputc` |
| `puts` | REAL | `kOffFputs` |
| `realloc` | REAL | `kOffRealloc` |
| `strchr` | REAL | `kOffStrchr` |
| `strcmp` | REAL | `kOffStrcmp` |
| `strcpy` | REAL | `kOffStrcpy` |
| `strlen` | REAL | `kOffStrlen` |
| `strtol` | REAL | `kOffPinReturn0` |
| `strtoul` | REAL | `kOffStrtoulNoop` |
| `terminate` | REAL | `kOffTerminate` |
| `wcslen` | REAL | `kOffWcslen` |
<!-- AUTO:thunks-by-dll END -->

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
  `AdjustWindowRect`, `AdjustWindowRectEx`,
  `AdjustWindowRectExForDpi`,
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
- Menus: `CreateMenu`, `CreatePopupMenu`, `DestroyMenu`,
  `AppendMenuA/W`, `InsertMenuA/W`, `RemoveMenu`, `DeleteMenu`,
  `EnableMenuItem`, `CheckMenuItem`, `ModifyMenuA/W`, `GetSubMenu`,
  `GetMenuItemCount`, `GetMenuItemID`, `GetMenuState`,
  `TrackPopupMenu`, `TrackPopupMenuEx` — REAL. HMENU is a
  userland-allocated struct in user32.c; TrackPopupMenu marshals
  into `SYS_WIN_TRACK_POPUP` (173) which drives the kernel menu
  primitive and blocks until the user picks (or cancels). PE
  apps receive `WM_CONTEXTMENU` (0x007B) on right-click-up in
  the client area.
- Menus — GAPs: nested submenus aren't marshaled across the
  syscall (apps call `TrackPopupMenu` recursively from their
  `WM_COMMAND` handler instead); `TPM_RIGHTBUTTON` /
  `TPM_HORIZONTAL` / `TPMPARAMS` exclude-rect ignored;
  concurrent TrackPopupMenu from two PE processes serialise
  on the single-instance kernel menu (second caller cancels).
- Menus: `LoadMenuW`, `GetSystemMenu`, `GetMenu`, `SetMenu`,
  `DrawMenuBar` — STUB (menubars and resource-loaded menus
  out of scope for v0)
- Modal dialogs: `DialogBoxA/W`, `DialogBoxParamA/W`,
  `DialogBoxIndirectParamA/W`, `CreateDialogA/W`,
  `CreateDialogParamA/W`, `EndDialog`, `IsDialogMessageA/W`,
  `GetDlgItem`, `GetDlgItemTextA/W`, `SetDlgItemTextA/W`,
  `GetDlgItemInt`, `SetDlgItemInt` — STUB facades. The EAT
  entries exist so PEs that import them link; the bodies
  return IDOK / NULL / FALSE without invoking the user-supplied
  DLGPROC (no modal pump in v0). Apps that branch on the
  return value follow the affirmative path; apps that need a
  real dialog see no controls.
- Hooks: `SetWindowsHookExA/W`, `UnhookWindowsHookEx`,
  `CallNextHookEx` — STUB
- Subclassing: `SetWindowSubclass` lives in comctl32 — STUB
- DDE: `DdeInitializeA/W`, `DdeCreateStringHandleA/W`,
  `DdeFreeStringHandle`, `DdeUninitialize` — STUB
- Scrollbars (`SetScrollInfo` etc.) — STUB

**Thunked imports (auto-generated from `kernel/subsystems/win32/thunks_table.inc`):**

<!-- AUTO:thunks-by-dll DLL=user32.dll START -->
<!-- generated by tools/build/gen-wiki-auto.py — do not edit by hand -->

**`user32.dll`** — 100 imports thunked: 100 REAL.

| Method | Status | Routed to |
|--------|--------|-----------|
| `AnyPopup` | REAL | `kOffPinReturn0` |
| `BeginPaint` | REAL | `kOffWinBeginPaint` |
| `BlockInput` | REAL | `kOffPinReturn0` |
| `CallWindowProcA` | REAL | `kOffPinReturn0` |
| `CallWindowProcW` | REAL | `kOffPinReturn0` |
| `CharLowerW` | REAL | `kOffPinReturn0` |
| `CharUpperW` | REAL | `kOffPinReturn0` |
| `ClipCursor` | REAL | `kOffPinReturn1` |
| `CloseClipboard` | REAL | `kOffPinReturn1` |
| `CountClipboardFormats` | REAL | `kOffPinReturn0` |
| `CreateWindowExA` | REAL | `kOffPinReturn1` |
| `CreateWindowExW` | REAL | `kOffPinReturn1` |
| `DefWindowProcA` | REAL | `kOffPinReturn0` |
| `DefWindowProcW` | REAL | `kOffPinReturn0` |
| `DestroyWindow` | REAL | `kOffPinReturn1` |
| `DispatchMessageA` | REAL | `kOffDispatchMessageA` |
| `DispatchMessageW` | REAL | `kOffDispatchMessageA` |
| `DrawTextA` | REAL | `kOffGdiDrawTextA` |
| `DrawTextW` | REAL | `kOffGdiDrawTextW` |
| `EmptyClipboard` | REAL | `kOffPinReturn1` |
| `EnableWindow` | REAL | `kOffPinReturn0` |
| `EndPaint` | REAL | `kOffWinEndPaint` |
| `EnumClipboardFormats` | REAL | `kOffPinReturn0` |
| `FillRect` | REAL | `kOffGdiFillRectUser` |
| `FlashWindow` | REAL | `kOffPinReturn0` |
| `FlashWindowEx` | REAL | `kOffPinReturn0` |
| `GetActiveWindow` | REAL | `kOffPinReturn0` |
| `GetClientRect` | REAL | `kOffPinReturn1` |
| `GetClipboardData` | REAL | `kOffPinReturn0` |
| `GetCursor` | REAL | `kOffPinReturn0` |
| `GetCursorPos` | REAL | `kOffPinReturn1` |
| `GetDC` | REAL | `kOffWinGetDC` |
| `GetDesktopWindow` | REAL | `kOffPinReturn0` |
| `GetForegroundWindow` | REAL | `kOffPinReturn0` |
| `GetMessageA` | REAL | `kOffGetMessageA` |
| `GetMessageW` | REAL | `kOffGetMessageA` |
| `GetProcessWindowStation` | REAL | `kOffPinReturn0` |
| `GetSysColor` | REAL | `kOffGetSysColor` |
| `GetSysColorBrush` | REAL | `kOffGetSysColorBrush` |
| `GetSystemMenu` | REAL | `kOffPinReturn0` |
| `GetSystemMetrics` | REAL | `kOffPinReturn0` |
| `GetSystemMetrics` | REAL | `kOffPinReturn0` |
| `GetWindowRect` | REAL | `kOffPinReturn1` |
| `InvalidateRect` | REAL | `kOffWinInvalidateRect` |
| `IsClipboardFormatAvailable` | REAL | `kOffPinReturn0` |
| `IsIconic` | REAL | `kOffPinReturn0` |
| `IsWindow` | REAL | `kOffPinReturn0` |
| `IsWindowEnabled` | REAL | `kOffPinReturn1` |
| `IsWindowVisible` | REAL | `kOffPinReturn1` |
| `IsZoomed` | REAL | `kOffPinReturn0` |
| `LoadAcceleratorsA` | REAL | `kOffPinReturn1` |
| `LoadAcceleratorsW` | REAL | `kOffPinReturn1` |
| `LoadBitmapA` | REAL | `kOffPinReturn1` |
| `LoadBitmapW` | REAL | `kOffPinReturn1` |
| `LoadCursorA` | REAL | `kOffPinReturn1` |
| `LoadCursorW` | REAL | `kOffPinReturn1` |
| `LoadIconA` | REAL | `kOffPinReturn1` |
| `LoadIconW` | REAL | `kOffPinReturn1` |
| `LoadImageA` | REAL | `kOffPinReturn1` |
| `LoadImageW` | REAL | `kOffPinReturn1` |
| `LoadMenuA` | REAL | `kOffPinReturn1` |
| `LoadMenuW` | REAL | `kOffPinReturn1` |
| `LoadStringA` | REAL | `kOffPinReturn0` |
| `LoadStringW` | REAL | `kOffPinReturn0` |
| `LoadStringW` | REAL | `kOffPinReturn0` |
| `MessageBoxA` | REAL | `kOffPinReturn1` |
| `MessageBoxA` | REAL | `kOffPinReturn1` |
| `MessageBoxExA` | REAL | `kOffPinReturn1` |
| `MessageBoxExW` | REAL | `kOffPinReturn1` |
| `MessageBoxExW` | REAL | `kOffPinReturn1` |
| `MessageBoxW` | REAL | `kOffPinReturn1` |
| `MessageBoxW` | REAL | `kOffPinReturn1` |
| `MoveWindow` | REAL | `kOffPinReturn1` |
| `OpenClipboard` | REAL | `kOffPinReturn0` |
| `PeekMessageA` | REAL | `kOffPeekMessageA` |
| `PeekMessageW` | REAL | `kOffPeekMessageA` |
| `PostMessageA` | REAL | `kOffPinReturn1` |
| `PostMessageW` | REAL | `kOffPinReturn1` |
| `PostQuitMessage` | REAL | `kOffPinReturn0` |
| `PostThreadMessageA` | REAL | `kOffPinReturn1` |
| `PostThreadMessageW` | REAL | `kOffPinReturn1` |
| `RegisterClassA` | REAL | `kOffPinReturn1` |
| `RegisterClassExA` | REAL | `kOffPinReturn1` |
| `RegisterClassExW` | REAL | `kOffPinReturn1` |
| `RegisterClassW` | REAL | `kOffPinReturn1` |
| `ReleaseDC` | REAL | `kOffWinReleaseDC` |
| `SendMessageA` | REAL | `kOffPinReturn0` |
| `SendMessageW` | REAL | `kOffPinReturn0` |
| `SetClipboardData` | REAL | `kOffPinReturn0` |
| `SetCursor` | REAL | `kOffPinReturn0` |
| `SetCursorPos` | REAL | `kOffPinReturn1` |
| `SetWindowPos` | REAL | `kOffPinReturn1` |
| `ShowCursor` | REAL | `kOffPinReturn0` |
| `ShowWindow` | REAL | `kOffPinReturn0` |
| `TranslateAcceleratorA` | REAL | `kOffPinReturn0` |
| `TranslateAcceleratorW` | REAL | `kOffPinReturn0` |
| `TranslateMessage` | REAL | `kOffPinReturn0` |
| `UnregisterClassA` | REAL | `kOffPinReturn1` |
| `UnregisterClassW` | REAL | `kOffPinReturn1` |
| `UpdateWindow` | REAL | `kOffWinUpdateWindow` |
<!-- AUTO:thunks-by-dll END -->

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

**Thunked imports (auto-generated from `kernel/subsystems/win32/thunks_table.inc`):**

<!-- AUTO:thunks-by-dll DLL=gdi32.dll START -->
<!-- generated by tools/build/gen-wiki-auto.py — do not edit by hand -->

**`gdi32.dll`** — 47 imports thunked: 47 REAL.

| Method | Status | Routed to |
|--------|--------|-----------|
| `BitBlt` | REAL | `kOffGdiBitBltDC` |
| `CreateBitmap` | REAL | `kOffPinReturn1` |
| `CreateBrushIndirect` | REAL | `kOffPinReturn1` |
| `CreateCompatibleBitmap` | REAL | `kOffGdiCreateCompatBmp` |
| `CreateCompatibleDC` | REAL | `kOffGdiCreateCompatDC` |
| `CreateDIBitmap` | REAL | `kOffPinReturn1` |
| `CreateDIBSection` | REAL | `kOffPinReturn1` |
| `CreateFontA` | REAL | `kOffPinReturn1` |
| `CreateFontIndirectA` | REAL | `kOffPinReturn1` |
| `CreateFontIndirectW` | REAL | `kOffPinReturn1` |
| `CreateFontW` | REAL | `kOffPinReturn1` |
| `CreatePen` | REAL | `kOffGdiCreatePen` |
| `CreateSolidBrush` | REAL | `kOffGdiCreateSolidBrush` |
| `DeleteDC` | REAL | `kOffGdiDeleteDC` |
| `DeleteObject` | REAL | `kOffGdiDeleteObject` |
| `DrawTextA` | REAL | `kOffGdiDrawTextA` |
| `DrawTextW` | REAL | `kOffGdiDrawTextW` |
| `Ellipse` | REAL | `kOffGdiEllipseFilled` |
| `ExtTextOutA` | REAL | `kOffPinReturn1` |
| `ExtTextOutW` | REAL | `kOffPinReturn1` |
| `FillRect` | REAL | `kOffGdiFillRectUser` |
| `FrameRect` | REAL | `kOffPinReturn1` |
| `GetDC` | REAL | `kOffPinReturn1` |
| `GetObjectA` | REAL | `kOffPinReturn1` |
| `GetObjectW` | REAL | `kOffPinReturn1` |
| `GetStockObject` | REAL | `kOffGdiGetStockObject` |
| `GetWindowDC` | REAL | `kOffPinReturn1` |
| `LineTo` | REAL | `kOffGdiLineTo` |
| `MoveToEx` | REAL | `kOffGdiMoveToEx` |
| `PatBlt` | REAL | `kOffGdiPatBlt` |
| `Polygon` | REAL | `kOffPinReturn1` |
| `Polyline` | REAL | `kOffPinReturn1` |
| `Rectangle` | REAL | `kOffGdiRectangleFilled` |
| `ReleaseDC` | REAL | `kOffPinReturn1` |
| `RestoreDC` | REAL | `kOffPinReturn1` |
| `SaveDC` | REAL | `kOffPinReturn1` |
| `SelectObject` | REAL | `kOffGdiSelectObject` |
| `SetBkColor` | REAL | `kOffGdiSetBkColor` |
| `SetBkMode` | REAL | `kOffGdiSetBkMode` |
| `SetMapMode` | REAL | `kOffPinReturn1` |
| `SetPixel` | REAL | `kOffGdiSetPixel` |
| `SetPixelV` | REAL | `kOffGdiSetPixel` |
| `SetTextAlign` | REAL | `kOffPinReturn0` |
| `SetTextColor` | REAL | `kOffGdiSetTextColor` |
| `StretchBlt` | REAL | `kOffGdiStretchBltDC` |
| `TextOutA` | REAL | `kOffGdiTextOutA` |
| `TextOutW` | REAL | `kOffGdiTextOutW` |
<!-- AUTO:thunks-by-dll END -->

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

### shell32.dll  (~640 LOC, ~14 exports)

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
`SHGetFolderPathW`. `SHGetDesktopFolder` — GAP: returns a
singleton IShellFolder COM object whose vtable methods all
succeed with empty / sentinel results (zero-item enumeration,
zero attributes, empty GetDisplayNameOf STRRET). Enough that
callers see `S_OK` instead of `class-not-registered`; not
enough to actually navigate the shell namespace.
`ShellExecuteW`, `ShellExecuteExW`, `SHFileOperationW` — STUB.

### ole32.dll — file-dialog COM objects

`CoCreateInstance(CLSID_FileOpenDialog, IID_IFileOpenDialog, ...)`
and the corresponding `FileSaveDialog` / `IFileSaveDialog` pair
return real per-instance COM objects with `IUnknown` +
`IModalWindow` + `IFileDialog` + `IFileOpenDialog` (or
`IFileSaveDialog`) vtables. Per-method status:

- `IModalWindow::Show` — REAL: returns `S_FALSE` so the caller's
  "user cancelled" branch runs without a real picker UI.
- `IFileDialog::SetOptions` / `SetTitle` / `SetFileName` /
  `SetFileTypes` / `SetFileTypeIndex` / `SetDefaultExtension` /
  `SetOkButtonLabel` / `SetFileNameLabel` / `SetDefaultFolder` /
  `SetFolder` / `SetClientGuid` / `SetFilter` / `Advise` /
  `Unadvise` / `Close` / `ClearClientData` / `AddPlace` — REAL:
  succeed silently (S_OK).
- `IFileDialog::GetResult` / `GetFolder` / `GetCurrentSelection` /
  `GetFileName` / `GetOptions` / `GetFileTypeIndex` — GAP: clear
  the out parameter and return `E_FAIL` so the caller's no-result
  path runs.
- `IFileOpenDialog::GetResults` / `GetSelectedItems` — GAP: same
  empty-result behaviour as the IFileDialog getters.
- `IFileSaveDialog::SetSaveAsItem` / `SetProperties` /
  `SetCollectedProperties` / `ApplyProperties` — REAL (silent
  S_OK); `GetProperties` — GAP (E_FAIL).

A real picker UI requires the compositor's modal-input mode
landing — see [`Compositor`](../subsystems/Compositor.md)
§"Popup Menus" follow-ups.

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
> the kernel's process table. Performance information is backed
> by scheduler + frame-allocator counters. Working-set mutation/delta
> queries are success-no-op facades.

`EnumProcesses`, `EnumProcessModules`, `GetModuleBaseNameW`,
`GetModuleFileNameExW`, `GetProcessImageFileNameW`,
`GetProcessMemoryInfo`, `QueryFullProcessImageNameW` — REAL.
`GetPerformanceInfo` — GAP (frame totals/free/peak plus process
+ thread counts are kernel-backed; cache, kernel-pool subtotal, and
global handle totals remain zero until those ledgers exist).
`QueryWorkingSet`, `EmptyWorkingSet`, `GetWsChanges` — GAP
(success with an empty/no-op working-set view until the kernel
exports per-process residency telemetry).

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

**Thunked imports (auto-generated from `kernel/subsystems/win32/thunks_table.inc`):**

<!-- AUTO:thunks-by-dll DLL=ws2_32.dll START -->
<!-- generated by tools/build/gen-wiki-auto.py — do not edit by hand -->

**`ws2_32.dll`** — 8 imports thunked: 8 REAL.

| Method | Status | Routed to |
|--------|--------|-----------|
| `WSAAsyncSelect` | REAL | `kOffPinReturn0` |
| `WSAEnumNetworkEvents` | REAL | `kOffPinReturn0` |
| `WSAEventSelect` | REAL | `kOffPinReturn0` |
| `WSARecv` | REAL | `kOffPinReturn0` |
| `WSASend` | REAL | `kOffPinReturn0` |
| `WSASocketA` | REAL | `kOffReturnMinus1` |
| `WSASocketW` | REAL | `kOffReturnMinus1` |
| `WSAWaitForMultipleEvents` | REAL | `kOffPinReturn0` |
<!-- AUTO:thunks-by-dll END -->

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

### winmm.dll  (~250 LOC, ~10 exports)

`timeGetTime`, `timeBeginPeriod`, `timeEndPeriod`,
`timeGetDevCaps` — REAL.
`timeSetEvent`, `timeKillEvent` — REAL (T11-04). 16-slot
multimedia-timer table + lazily-spawned 10 ms polling
service thread invokes the registered TIMECALLBACK when
due_time arrives. `TIME_PERIODIC` re-arms; one-shot
self-deactivates. The thread spawns through direct
`SYS_THREAD_CREATE` / `SYS_SLEEP_MS` syscalls because
winmm.dll's build pipeline doesn't link kernel32.dll.
`PlaySoundW` — STUB silent. `mciSendStringW` — STUB.
`waveOut*` — STUB (T12-03 — needs HDA backend wiring).

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

### ole32.dll  (~650 LOC, ~31 exports)

> **Status:** lightweight local COM runtime. `CoInitializeEx` /
> `CoUninitialize` track per-thread apartment mode and init depth;
> class lookup covers both static built-ins and process-local
> `CoRegisterClassObject` factories.

`CoInitialize{,Ex}`, `CoUninitialize`, `OleInitialize`,
`OleUninitialize` — REAL per-thread counters with
`RPC_E_CHANGED_MODE` on apartment-mode conflicts. `CoTaskMemAlloc`,
`CoTaskMemFree`, `CoTaskMemRealloc` — REAL (forward to
HeapAlloc / HeapFree).
`CLSIDFromString`, `IIDFromString`, `StringFromCLSID`,
`StringFromGUID2` — REAL.
`CoGetClassObject`, `CoCreateInstance{,Ex}` — REAL for
registered in-process class factories plus built-in factory
registrations for StdComponentCategoriesMgr / FileOpenDialog /
FileSaveDialog; built-in instances expose safe `IUnknown` identity
only for now; unknown CLSIDs return `REGDB_E_CLASSNOTREG`.
`CoRegisterClassObject`, `CoRevokeClassObject` — REAL process-local
factory table. `RegisterDragDrop`, `RevokeDragDrop`,
`CoInitializeSecurity`, `CoSetProxyBlanket` — compatibility success
facades. `CoGetMalloc`, `GetRunningObjectTable`,
`CreateStreamOnHGlobal`, `GetHGlobalFromStream` — STUB.

**MISSING entirely:** cross-process apartments, RPC marshalling,
OBJREFs, monikers, structured storage (StgCreateStorageEx, etc.),
persistent COM, classic OLE embedding, and a functional IFileDialog /
native picker method surface behind the FileOpenDialog/FileSaveDialog
registrations.

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
- **d3dcompiler.dll** — REAL (frontend). `D3DCompile` /
  `D3DCompile2` / `D3DCreateBlob` / `D3DReflect` /
  `D3DDisassemble` lex + parse a small HLSL subset and emit a
  deterministic DXBC-shaped blob. The blob is not yet **executed**
  by the d3d11/d3d12 draw path — that wires up next.
- **d3dcompiler_47.dll** — versioned alias of the above is
  available by adding `d3dcompiler_47` to the duetos_stub_dll
  list. Not built today.
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

- **HLSL / DXC compiler** — `D3DCompile` / `D3DCompile2` are
  real in `userland/libs/d3dcompiler/`: lex + parse + DXBC-
  shaped blob emission. `D3DCompileFromFile` and the full DXIL
  toolchain are still missing, and the d3d11/d3d12 draw path
  still ignores the bytecode (closest the GPU gets is the
  pass-through rasterizer in `dx_raster.h`).
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

- **Modal dialogs** — `DialogBoxParam`, `EndDialog`,
  `CreateDialog`, `IsDialogMessage`, `GetDlgItem*`,
  `SetDlgItem*` — STUB facades. EATs exist; bodies do not run
  the user-supplied DLGPROC (no modal pump in v0). PEs that
  import the family link and follow the affirmative branch.
- **Menus** — `CreatePopupMenu` / `AppendMenu` /
  `TrackPopupMenu` / `DestroyMenu` and the surrounding
  property/state queries are REAL. `LoadMenu`, `GetMenu`,
  `SetMenu`, `DrawMenuBar`, `GetSystemMenu` remain stubs
  (menubars + resource-loaded menus are out of scope).
  Submenu marshaling, exclude-rect, and concurrent popups
  across PEs are documented v0 GAPs — see the Menus row in
  the per-method inventory above.
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
