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

## Summary counts (2026-05-26)

- **Shipping DLLs:** 60 dirs in `userland/libs/` — 44 production
  PE64 DLLs, 13 PE32 i386 variants (`*_32`) for cross-bitness
  imports, and 2 `customdll*` test fixtures (44 + 13 + 2 = 59; the
  60th dir is `ws2_32`, a production PE64 DLL whose name happens to
  end `_32`). Two `dx_*.h` files in the same tree are shared
  headers, not DLLs.
- **Approximate exports:** ~1100 across all shipping DLLs
- **Source LOC across `userland/libs/`:** ~40 000
- **Live STUB / GAP markers** in user-mode + win32 subsystem
  (`git grep -nE "// (STUB|GAP):" -- 'userland/libs/' 'kernel/subsystems/win32/'`): 0
  — STUB/GAP discipline now lives entirely in kernel TUs (gpu,
  iwlwifi, etc.). Userland DLL stubs are documented in this page
  rather than via inline markers; see the per-DLL drilldown below.
- **Win32 PE smoke coverage:** 154 fixtures in `userland/apps/`
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
- `__chkstk` (REAL — page-by-page probe in `userland/libs/ntdll/chkstk.S`; mirrors the kernel-side bytecode thunk `kOffChkStk`)

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

**`ntdll.dll`** — 111 imports thunked: 107 REAL, 4 STUB.

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
| `NtRaiseException` | STUB | `kOffMissLogger` |
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
| `RtlCaptureContext` | STUB | `kOffMissLogger` |
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
| `RtlLookupFunctionEntry` | STUB | `kOffMissLogger` |
| `RtlMoveMemory` | REAL | `kOffMemmove` |
| `RtlNtStatusToDosError` | REAL | `kOffPinReturn0` |
| `RtlReAllocateHeap` | REAL | `kOffHeapRealloc` |
| `RtlRunOnceExecuteOnce` | REAL | `kOffPinReturn0` |
| `RtlSetLastWin32Error` | REAL | `kOffSetLastError` |
| `RtlSizeHeap` | REAL | `kOffHeapSize` |
| `RtlTryEnterCriticalSection` | REAL | `kOffTryEnterCritSecReal` |
| `RtlUnwindEx` | STUB | `kOffMissLogger` |
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
>
> Twenty-six x64 imports have crossed the fail-closed retirement gate.
> Wave 1 moved `CreateThread`, `ExitThread`,
> `FreeLibraryAndExitThread`, and `GetExitCodeThread`; wave 2 moved
> `GetCurrentProcess`, `GetCurrentThread`, `GetCurrentProcessId`,
> `GetCurrentThreadId`, `GetLastError`, and `SetLastError`; wave 3 moved
> `InterlockedExchangeAdd`, `InterlockedAnd`, `InterlockedOr`, and
> `InterlockedXor`; wave 4 moved `QueryPerformanceCounter`,
> `QueryPerformanceFrequency`, `GetTickCount`, and `GetTickCount64`;
> wave 5 moved `InterlockedIncrement`, `InterlockedDecrement`,
> `InterlockedExchange`, and `InterlockedCompareExchange`; wave 6 moved
> `TlsAlloc`, `TlsFree`, `TlsGetValue`, and `TlsSetValue`.
> Callers
> must bind the verified user-mode kernel32 exports and cannot fall
> back to legacy kernel thunk rows.

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
  `GetCurrentThread`, `GetCurrentThreadId`, `ExitProcess`, `ExitThread`,
  `FreeLibraryAndExitThread`,
  `GetCommandLineA/W`, `GetEnvironmentVariableA/W`,
  `GetEnvironmentStringsW`, `FreeEnvironmentStringsW`,
  `GetSystemInfo`, `GetVersionExW`, `GetComputerNameW`,
  `GetUserNameA/W`, `GetStdHandle`, `WriteConsoleA/W`,
  `OutputDebugStringA/W`, per-thread `GetLastError` / `SetLastError`
- Threading: `CreateThread`, `GetExitCodeThread`, `WaitForSingleObject`,
  `WaitForMultipleObjects`, `Sleep`, `SleepEx`,
  `CreateEventA/W`, `OpenEventA/W`, `SetEvent`, `ResetEvent`,
  `PulseEvent`, `CreateMutexA/W`, `OpenMutexA/W`,
  `ReleaseMutex`, `CreateSemaphoreA/W`, `OpenSemaphoreA/W`,
  `ReleaseSemaphore`, `EnterCriticalSection`,
  `LeaveCriticalSection`, `InitializeCriticalSection`,
  `DeleteCriticalSection`, `TryEnterCriticalSection`,
  `InitializeSRWLock`, `AcquireSRWLockExclusive` /
  `Shared`, `ReleaseSRWLockExclusive` / `Shared`.
  Condition variables (`InitializeConditionVariable`,
  `SleepConditionVariableCS` / `SRW`, `WakeConditionVariable`,
  `WakeAllConditionVariable`), address-keyed wait
  (`WaitOnAddress`, `WakeByAddressSingle` / `All`) and the
  explicit one-time-init form (`InitOnceBeginInitialize`,
  `InitOnceComplete`) are real, built on the kernel
  `SYS_WAIT_ON_ADDRESS` / `SYS_WAKE_BY_ADDRESS` futex
  (`kernel/subsystems/win32/waitaddr_syscall.cpp`,
  address-hashed wait queues; bucket collisions degrade to
  spurious wakeups, never lost ones). The condition-variable
  sleep samples the sequence under the lock before releasing,
  so a wake in the gap returns immediately — no lost wakeup.
  These bind via the api-set host resolver. The resolver is a
  two-tier lookup: a static curated contract→host table
  (`kernel/loader/apiset_static.cpp`, ~70 entries spanning the
  core / crt / security / service surfaces) is consulted first;
  contracts the table doesn't yet cover fall through to the
  original "first preloaded export by name" heuristic. The boot
  log emits `via-apiset-table` vs `via-apiset-heuristic` so new
  contracts are grep-able and can be promoted into the table.
  Verified by
  `userland/apps/sync_smoke` (`smoke=pe-hello`): a
  cross-thread CV producer/consumer, a WaitOnAddress handshake
  and the two-call InitOnce all PASS. SRW shared still aliases
  exclusive in v0. Named
  Create with the same name returns the existing handle;
  Open* succeeds for names registered in this process and
  fails (NULL) otherwise. Cross-process named-namespace is
  T6-04 follow-on.
- TLS: `TlsAlloc`, `TlsFree`, `TlsGetValue`, `TlsSetValue`
- Memory: `VirtualAlloc`, `VirtualFree`, `VirtualProtect`,
  `VirtualQuery`, `HeapCreate`, `HeapDestroy`, `HeapAlloc`,
  <!-- 2026-07-28 -->
  **`VirtualProtect` covers every mapped user page**, not only
  `VirtualAlloc` regions. Until 2026-07-28 it resolved solely through
  the per-process vmap region table, so the loaded image, the thread
  stack and preloaded DLLs all returned FALSE — which stopped the MSVC
  UCRT dead, since it brackets each write to its cached Win32 thunk
  table with `VirtualProtect(PAGE_READWRITE)`/`(PAGE_READONLY)` and
  aborts startup if either fails. Non-region addresses now re-protect
  through the address space, gated to the user half and to already-
  mapped pages, and still refuse every `PAGE_EXECUTE_*` (W^X) and
  `PAGE_GUARD` outside a region.
  <!-- 2026-07-29 -->
  **`PAGE_GUARD` exception delivery (T5-01):** writing to a guard page
  now delivers `STATUS_GUARD_PAGE_VIOLATION` (0x80000001) to the PE's
  SEH/VEH chain before the instruction retries, matching Windows
  behaviour. The guard is still one-shot (cleared on first access).
  GAP: reads to a guard page do not trigger the exception (the v0
  guard implementation strips writability, not accessibility).
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
- NLS formatting (en-US/invariant tables only; pure cores live in
  `kernel32_nls_format.h`, pinned by the hosted test
  `tests/host/test_kernel32_nls.cpp`): `GetNumberFormatA/W` and
  `GetCurrencyFormatA/W` honour the full NUMBERFMT / CURRENCYFMT
  struct (half-up rounding, digit-stack grouping, NegativeOrder,
  the LOCALE_ICURRENCY / LOCALE_INEGCURR currency order tables and
  custom symbol); the W paths carry wide separators / symbols
  end-to-end via sentinel substitution (`nls_widen_expand`), so
  non-ASCII NUMBERFMTW/CURRENCYFMTW separators round-trip.
  `GetDateFormatA/W` / `GetTimeFormatA/W` format pictures are real.
  `LCMapStringW` maps case, treats standalone `NORM_IGNORECASE` as
  a case-fold, and emits `LCMAP_SORTKEY` upcased-ordinal byte keys
  (GAP: no Unicode collation table — code points above 0xFF all
  weigh the same).
- Registry-style: handled via advapi32 (this DLL forwards a few)
- Console: `WriteConsoleA/W`, `ReadConsoleA/W`,
  `GetConsoleMode`, `SetConsoleMode`,
  `GetStdHandle`, `SetStdHandle`,
  `AllocConsole`, `FreeConsole`, `AttachConsole`,
  `GetConsoleScreenBufferInfo` (basic),
  `SetConsoleTextAttribute`, `SetConsoleCursorPosition`
- App-compat: `IsDebuggerPresent`,
  `SetThreadStackGuarantee` — both consult the per-process
  compat sidecar via the cached `SYS_COMPAT_QUERY = 206`
  syscall. `IsDebuggerPresent` returns FALSE either way today
  (no debugger surface); `SetThreadStackGuarantee` returns TRUE
  iff `fake_ok_stack_guarantee=1` is set on the sidecar,
  otherwise FALSE + `ERROR_INVALID_PARAMETER`.
- Path resolution: `SearchPathW` walks the documented safe search
  order (EXE dir, cwd, system dir, Windows dir, then each `PATH`
  element; an explicit `lpPath` replaces the walk) probing with
  `GetFileAttributesW`, appends `lpExt` only when the name has no
  extension of its own, and fills `lpFilePart`. `GetVolumePathNameW`
  returns the drive root that owns a path. `GetLongPathNameW`
  validates existence and returns the path — correct on a
  filesystem with no 8.3 alias namespace (GAP: a short name
  authored on a Windows volume round-trips unchanged).
- Local time: `FileTimeToLocalFileTime` and
  `SystemTimeToTzSpecificLocalTime` apply `Bias + StandardBias`
  exactly, over the caller's `TIME_ZONE_INFORMATION` or the active
  one (GAP: DST transition rules are not evaluated, so the result
  is always the zone's *standard* time).
- `CompareStringOrdinal` — code-unit comparison with invariant
  upper-case folding. Ordinal is exactly the contract, so this one
  carries no collation caveat.
- `LCIDToLocaleName` / `SetThreadUILanguage` — en-US and the
  invariant / neutral / system-default pseudo-LCIDs resolve;
  anything else fails with `ERROR_INVALID_PARAMETER`.
  `SetThreadUILanguage` returns the LANGID actually in effect,
  which is always en-US (the single installed UI language) — the
  same shape Windows shows on a single-language install.
- Threadpool timers: `CreateThreadpoolTimer`, `SetThreadpoolTimer`,
  `WaitForThreadpoolTimerCallbacks`, `CloseThreadpoolTimer` are
  backed by a real 32-slot table plus a lazily-spawned 10 ms
  polling service thread that *invokes the caller's callback* —
  not a fake handle. Close/Wait drain an in-flight callback before
  returning, so the caller's context is safe to free. GAP: one
  shared service thread runs every callback (a blocking callback
  delays the others), 10 ms is the resolution floor, and
  `TP_CALLBACK_ENVIRON` is accepted but not honoured.
- `QueryFullProcessImageNameW` — real, via `GetModuleFileNameW`.
  The `K32GetModuleFileNameExW` / `K32GetProcessImageFileNameA/W`
  family now routes through the same source instead of returning
  three divergent canned strings (`C:\bin\ring3.exe` vs
  `X:\bin\ring3.exe` vs the bare base name `ring3`).
- `GetFileInformationByHandleEx` — `FileStandardInfo` (sizes from
  the real `GetFileSizeEx`) and `FileBasicInfo`. Every other
  `FILE_INFO_BY_HANDLE_CLASS` fails with
  `ERROR_INVALID_PARAMETER` rather than returning zeroes a caller
  would consume as data.

**STUB / GAP:**
- `SetFileInformationByHandle` — STUB. Every class returns FALSE +
  `ERROR_NOT_SUPPORTED` (unknown classes `ERROR_INVALID_PARAMETER`):
  there is no by-handle truncate, set-times or delete-on-close
  syscall to route a write to.
- `HeapSetInformation` — GAP. Both documented classes
  (`HeapCompatibilityInformation`,
  `HeapEnableTerminationOnCorruption`) are accepted and recorded
  nowhere; the heap has neither an LFH tier nor block-header
  corruption detection. Unknown classes are refused.
- `GetProductInfo` — GAP. DuetOS has no edition concept; reports
  `PRODUCT_PROFESSIONAL`, consistent with the version
  `GetVersionExW` already reports.
- Deliberately **not** provided (absent is more honest than
  present): `ResolveDelayLoadedAPI` / `DelayLoadFailureHook` —
  resolution needs `GetProcAddress`, which lives only in the
  kernel thunk page and is not linkable from `kernel32.dll`; a
  version that loaded the library but could not bind the export
  would hand back a bogus pointer and crash at the call site.
  This costs nothing in practice: the PE loader binds
  `IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT` eagerly at load
  ([`PE-Loader.md`](../subsystems/PE-Loader.md#delay-load-imports)),
  so an image's own `__delayLoadHelper2` — the only caller these
  two entry points have — never runs.
  `RtlUnwind` — the real unwinder is `ntdll!RtlUnwindEx`;
  `kernel32.dll` links `/nodefaultlib` with no import table, so it
  cannot forward, and a kernel32-local copy would be a second
  divergent unwinder.
- File: `LockFile`, `UnlockFile`, `LockFileEx`, `UnlockFileEx`
  return success without locking (no FS write contention in v0)
- Process: `CreateProcessA/W` is structurally working but
  `STARTUPINFO` is mostly ignored; `CreateProcessAsUserW` always
  fails (no token impersonation)
- IPC: anonymous pipes (`CreatePipe`) + named pipes
  (`CreateNamedPipeA/W`, `CreateFileA/W` against `\\.\pipe\NAME`,
  `ConnectNamedPipe`, `DisconnectNamedPipe`, `WaitNamedPipeA/W`)
  ship in v0. Named pipes back onto the kernel `ipc::named_pipes`
  registry + the existing pipe pool. `PIPE_ACCESS_INBOUND` and
  `PIPE_ACCESS_OUTBOUND` are honoured; `PIPE_ACCESS_DUPLEX` is
  rejected (sub-GAP — needs two pool slots). `ConnectNamedPipe`
  is a synchronous no-op that succeeds (no overlapped wait —
  sub-GAP). `PIPE_TYPE_MESSAGE` accepted but reads behave as
  `PIPE_TYPE_BYTE` (no message framing — sub-GAP).
- Job objects are a bounded v0 implementation. Unnamed
  `CreateJobObjectW`, `AssignProcessToJobObject`, `IsProcessInJob`,
  `TerminateJobObject`, `QueryInformationJobObject`, and Job
  `CloseHandle` route through `ntdll` to the native Job syscalls.
  Queries implement basic accounting (class 1), the process-ID list
  (class 3, including header-only/partial buffers), and basic plus I/O
  accounting (class 8; I/O fields are currently zero). Handles carry a
  generation, and closing the last user handle does not sever live
  membership. Named Jobs, security attributes, `OpenJobObject`,
  `SetInformationJobObject`, limits/kill-on-close, and nested Jobs remain
  GAP. Child termination, 33-cycle member-slot reuse, and inherited
  child/grandchild membership still require the dedicated QEMU runtime
  profile in `userland/apps/jobobj_smoke/JOB_RUNTIME_QEMU_TODO.md`.
- Fiber API (`CreateFiber`, `SwitchToFiber`, `DeleteFiber`)
  is GAP: switches but no per-fiber FLS
- Profiling (`QueryProcessCycleTime`, etc.) — STUB
- DPI awareness (`SetProcessDPIAware`, `GetDpiForSystem`) —
  return constant 96 DPI. Manifest-declared DPI awareness is now
  parsed from RT_MANIFEST at load time and stored on
  `Process::manifest.dpi_awareness` (2026-07-30).
  GAP: thunks (`IsProcessDPIAware`, `GetProcessDPIAwareness`) do
  not yet read the parsed value — still return constant 96.
- Resources — REAL as of 2026-07-28. `FindResourceW/A/ExW/ExA`,
  `LoadResource`, `LockResource`, `SizeofResource`, `FreeResource`,
  `EnumResourceTypesW` and `EnumResourceNamesW` walk the module's
  real `.rsrc` through `userland/libs/common/pe_resources.h`, on
  both bitnesses. See
  [`wiki/subsystems/PE-Resources.md`](../subsystems/PE-Resources.md).
  **The auto-generated table below still lists these names against
  `kOffPinReturn0`, and that is accurate but no longer what runs:**
  `ResolveImports` prefers a preloaded DLL's export table over the
  kernel thunk page, so the real `kernel32.dll` export wins and the
  thunk row is now a dead fallback. The rows stay because the table
  is generated from `thunks_table.inc`, which still contains them.

**Thunked imports (auto-generated from `kernel/subsystems/win32/thunks_table.inc`):**

<!-- AUTO:thunks-by-dll DLL=kernel32.dll START -->
<!-- generated by tools/build/gen-wiki-auto.py — do not edit by hand -->

**`kernel32.dll`** — 382 imports thunked: 382 REAL.

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
| `FreeEnvironmentStringsA` | REAL | `kOffFreeEnvStringsW` |
| `FreeEnvironmentStringsW` | REAL | `kOffFreeEnvStringsW` |
| `FreeLibrary` | REAL | `kOffPinReturn1` |
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
| `GetCurrentProcessorNumber` | REAL | `kOffPinReturn0` |
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
| `GetExitCodeProcess` | REAL | `kernel32_sync.c` -> `NtQueryInformationProcess(0)` |
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
| `InterlockedAnd64` | REAL | `kOffInterlockedAnd64` |
| `InterlockedCompareExchange64` | REAL | `kOffInterlockedCmpXchg64` |
| `InterlockedDecrement64` | REAL | `kOffInterlockedDec64` |
| `InterlockedExchange64` | REAL | `kOffInterlockedExchg64` |
| `InterlockedExchangeAdd64` | REAL | `kOffInterlockedExchgAdd64` |
| `InterlockedFlushSList` | REAL | `kOffPinReturn0` |
| `InterlockedIncrement64` | REAL | `kOffInterlockedInc64` |
| `InterlockedOr64` | REAL | `kOffInterlockedOr64` |
| `InterlockedPopEntrySList` | REAL | `kOffPinReturn0` |
| `InterlockedPushEntrySList` | REAL | `kOffPinReturn0` |
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
| `RtlPcToFileHeader` | REAL | `kOffPcToFileHeaderNull` |
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
| `SetThreadStackGuarantee` | REAL | `kOffPinReturn0` |
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
  `RegCreateKeyExA/W`, `RegDeleteKeyW`, `RegDeleteValueW`,
  `RegFlushKey`, `RegSaveKeyW`, `RegLoadKeyW`
- `RegGetValueW` — open + query + `RRF_RT_*` type check in one
  call, and it delivers the three guarantees `RegQueryValueExW`
  does not: an empty `lpSubKey` queries the key itself, returned
  `REG_SZ` / `REG_EXPAND_SZ` / `REG_MULTI_SZ` data is always
  null-terminated even when the stored bytes are not, and
  `*pcbData` reports the terminated length.  `RRF_ZEROONFAILURE`
  is honoured on a type mismatch.
- `RegDeleteTreeW` — deletes a volatile key and the values it owns
  inline. GAP: volatile descendants are stored as independent
  full-path slots with no child index, so a grandchild survives
  its parent's deletion; static (const-tree) keys are not
  deletable at all and report the Win32-idempotent success.
- Token / SID basics: `OpenProcessToken`,
  `GetTokenInformation` (**TokenUser only** — returns a real
  `TOKEN_USER` whose `Sid` points at a well-formed
  `S-1-5-21-1-1-1-1000`; every other class is STUB, see below),
  `OpenThreadToken` (FALSE + `ERROR_NO_TOKEN` — DuetOS never
  impersonates, which is the correct Win32 answer and puts callers
  on their `OpenProcessToken` fallback), `IsValidSid`, `EqualSid`,
  `AllocateAndInitializeSid`, `FreeSid`, `GetLengthSid`,
  `GetSidLengthRequired`, `GetSidIdentifierAuthority`,
  `GetSidSubAuthority`, `GetSidSubAuthorityCount`, `CopySid`
- `CreateWellKnownSid` — a well-known SID is a constant defined by
  the spec, not a fact about the machine, so the 20-entry table
  emits byte-for-byte the SIDs Windows emits (`S-1-1-0`,
  `S-1-5-18`, `S-1-5-32-544`, …). GAP: the domain-relative types
  (`>= WinAccountAdministratorSid`) are refused — DuetOS is not
  domain-joined.
- `LookupAccountSidW` / `LookupAccountNameW` — resolve the single
  local user and every well-known SID both directions, with the
  canonical `NT AUTHORITY` / `BUILTIN` domain names and
  `SID_NAME_USE`. Anything else is `ERROR_NONE_MAPPED`, the
  correct answer for a SID this machine does not know.
- Security-descriptor field accessors:
  `SetSecurityDescriptorDacl`, `GetSecurityDescriptorDacl`,
  `SetSecurityDescriptorOwner`, `GetAce`. The stores, loads and
  `SE_DACL_PRESENT` / `SE_*_DEFAULTED` control bits are exact and
  round-trip; `GetAce` walks real ACE headers by `AceSize`.
  **They store, and nothing enforces** — see the security note
  below.
- ETW / WMI trace provider surface: `RegisterTraceGuidsW`,
  `UnregisterTraceGuids`, `GetTraceEnableLevel`,
  `GetTraceEnableFlags`, `GetTraceLoggerHandle`, `TraceMessage`,
  `EventSetInformation`. DuetOS has no trace session
  infrastructure, and "no session enabled" is a state these APIs
  are *specified* for: register succeeds with a zero registration
  handle, enable level and flags are 0, and providers therefore
  take exactly the code path they take on a Windows box with no
  session running. GAP: nothing can ever enable a provider here.
  The one thing this must never do is claim a session IS enabled.

> **Security note — why the descriptor/ACL block cannot be a
> privilege-escalation path.** None of it is an access-control
> decision. DuetOS authority is kernel-owned (durable capabilities
> plus unexpired broker leases, masked by a monotonic grant
> ceiling, evaluated inside the kernel), and the kernel never reads
> a userland `SECURITY_DESCRIPTOR`. A descriptor built here is
> inert caller-owned memory, so a PE cannot widen its own authority
> by writing a permissive DACL nor narrow anyone else's by writing
> a restrictive one — which is what makes the permissive fallbacks
> safe. The corollary is the rule: **if a future slice makes the
> kernel consult one of these structures, these functions stop
> being facades and the parsing has to become real first.**
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
- `GetTokenInformation` for **every class except TokenUser** —
  STUB. Groups, privileges, integrity level and elevation state
  are kernel-owned in DuetOS and have no Win32-token projection,
  so a caller reading those fields reads zeroes, not this
  process's real authority.
- `ConvertStringSecurityDescriptorToSecurityDescriptorW` — STUB.
  The SDDL string is **not parsed**; the descriptor returned is a
  valid, initialised `SECURITY_DESCRIPTOR` with no DACL that a
  caller can round-trip and free, but it does not express what the
  caller asked for. Cannot escalate (see the security note above),
  but a caller that believes it built a restrictive DACL is wrong.
- `SetEntriesInAclW` — STUB. Returns `ERROR_NOT_SUPPORTED` and a
  NULL ACL. Deliberately the loud answer: a caller that checks the
  return value learns its ACL was not built, rather than attaching
  an empty ACL it believes carries its entries.
- `RegNotifyChangeKeyValue` — STUB. Returns
  `ERROR_INVALID_FUNCTION`; there is no registry change-
  notification channel, so signalling `hEvent` is impossible and
  reporting success would strand the caller waiting forever.

**Thunked imports (auto-generated from `kernel/subsystems/win32/thunks_table.inc`):**

<!-- AUTO:thunks-by-dll DLL=advapi32.dll START -->
<!-- generated by tools/build/gen-wiki-auto.py — do not edit by hand -->

**`advapi32.dll`** — 51 imports thunked: 51 REAL.

| Method | Status | Routed to |
|--------|--------|-----------|
| `AccessCheck` | REAL | `kOffPinReturn1` |
| `AdjustTokenPrivileges` | REAL | `kOffPinReturn1` |
| `AdjustTokenPrivileges` | REAL | `kOffPinReturn1` |
| `CheckTokenMembership` | REAL | `kOffPinReturn1` |
| `CryptAcquireContextA` | REAL | `kOffPinReturn0` |
| `CryptCreateHash` | REAL | `kOffPinReturn0` |
| `CryptDestroyHash` | REAL | `kOffPinReturn1` |
| `CryptGetHashParam` | REAL | `kOffPinReturn0` |
| `CryptHashData` | REAL | `kOffPinReturn0` |
| `CryptReleaseContext` | REAL | `kOffPinReturn1` |
| `EventActivityIdControl` | REAL | `kOffPinReturn0` |
| `EventEnabled` | REAL | `kOffPinReturn0` |
| `EventRegister` | REAL | `kOffPinReturn0` |
| `EventUnregister` | REAL | `kOffPinReturn0` |
| `EventWrite` | REAL | `kOffPinReturn0` |
| `EventWriteTransfer` | REAL | `kOffPinReturn0` |
| `GetSecurityInfo` | REAL | `kOffPinReturn0` |
| `GetUserNameA` | REAL | `kOffGetUserNameW` |
| `GetUserNameW` | REAL | `kOffGetUserNameW` |
| `LookupPrivilegeValueA` | REAL | `kOffLookupPrivVal` |
| `LookupPrivilegeValueA` | REAL | `kOffLookupPrivVal` |
| `LookupPrivilegeValueW` | REAL | `kOffLookupPrivVal` |
| `LookupPrivilegeValueW` | REAL | `kOffLookupPrivVal` |
| `OpenProcessToken` | REAL | `kOffOpenProcessToken` |
| `OpenProcessToken` | REAL | `kOffOpenProcessToken` |
| `OpenServiceA` | REAL | `kOffPinReturn0` |
| `OpenServiceW` | REAL | `kOffPinReturn0` |
| `RegCloseKey` | REAL | `kOffPinReturn0` |
| `RegCreateKeyExW` | REAL | `kOffPinReturn0` |
| `RegCreateKeyW` | REAL | `kOffPinReturn0` |
| `RegDeleteKeyW` | REAL | `kOffPinReturn0` |
| `RegDeleteValueW` | REAL | `kOffPinReturn0` |
| `RegEnumKeyExW` | REAL | `kOffReturnTwo` |
| `RegEnumKeyW` | REAL | `kOffReturnTwo` |
| `RegEnumValueW` | REAL | `kOffReturnTwo` |
| `RegFlushKey` | REAL | `kOffPinReturn0` |
| `RegOpenKeyA` | REAL | `kOffReturnTwo` |
| `RegOpenKeyExA` | REAL | `kOffReturnTwo` |
| `RegOpenKeyExW` | REAL | `kOffReturnTwo` |
| `RegOpenKeyW` | REAL | `kOffReturnTwo` |
| `RegQueryValueA` | REAL | `kOffReturnTwo` |
| `RegQueryValueExA` | REAL | `kOffReturnTwo` |
| `RegQueryValueExW` | REAL | `kOffReturnTwo` |
| `RegQueryValueW` | REAL | `kOffReturnTwo` |
| `RegSetValueExW` | REAL | `kOffPinReturn0` |
| `RegSetValueW` | REAL | `kOffPinReturn0` |
| `SaferCloseLevel` | REAL | `kOffPinReturn1` |
| `SaferComputeTokenFromLevel` | REAL | `kOffPinReturn0` |
| `SaferCreateLevel` | REAL | `kOffPinReturn0` |
| `SetSecurityInfo` | REAL | `kOffPinReturn0` |
| `SystemFunction036` | REAL | `kOffPinReturn1` |
<!-- AUTO:thunks-by-dll END -->

### msvcrt.dll  (~860 LOC, ~150 exports)

> **Status:** the C runtime functions PE binaries actually link
> against. Exit / heap / stdio / string / time work; floating
> point and locale are stubbed-or-minimal.

**Real implementations:**
- Lifecycle: `_initterm`, `_initterm_e`,
  `__C_specific_handler` (forwards to ntdll's real walker),
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
- C++ exception layer — `_CxxThrowException` and the two
  `__CxxFrameHandler` personalities are PE forwarders to
  vcruntime140's real implementations (one engine, reachable from
  either import name); `__cxa_*` is still STUB

**Reading the auto-table below.** Its REAL/NOOP classifier only
flags the four bare generic sinks, so a *named* pin counts as REAL
even when the contract behind it is deliberately partial. For the
x64 CRT rows the honest split is:

- **Real** — `??3@YAXPEAX@Z` (operator delete → `free`),
  `?terminate@@YAXXZ`, `_purecall` (both abort, as on Windows),
  `memcpy_s` / `memmove_s` / `wcscpy_s` (bounded copies with the
  Annex K `errno_t` returns).
- **Real** (2026-07-28) — the C++ / SEH personality surface.
  `msvcrt.dll` publishes `__CxxFrameHandler3` /
  `__CxxFrameHandler4` / `_CxxThrowException` as PE forwarders to
  `vcruntime140` and `__C_specific_handler` as one to `ntdll`, so a
  PE that links its EH surface against msvcrt reaches the same
  engine as one that links vcruntime140 or ntdll directly. They
  previously returned `ExceptionContinueSearch` (silently: the
  handler claims "not my frame" and the exception walks past every
  catch block) or terminated.
- **STUB** — the `exception` constructors leave the object
  uninitialised and `?what@` always reports `""`. `_lock` /
  `_unlock` provide no mutual exclusion, so concurrent CRT calls
  race.
- **GAP** — `_wcsicmp` / `_wcsnicmp` are ordinal (no case folding,
  and `_wcsnicmp` ignores its length); `_amsg_exit` exits without
  the CRT diagnostic; `_ismbblead` always answers "not a lead
  byte", correct for every single-byte code page we expose.

**Thunked imports (auto-generated from `kernel/subsystems/win32/thunks_table.inc`):**

<!-- AUTO:thunks-by-dll DLL=msvcrt.dll START -->
<!-- generated by tools/build/gen-wiki-auto.py — do not edit by hand -->

**`msvcrt.dll`** — 75 imports thunked: 75 REAL.

| Method | Status | Routed to |
|--------|--------|-----------|
| `??0exception@@QEAA@AEBQEBD@Z` | REAL | `kOffReturnThis` |
| `??0exception@@QEAA@AEBQEBDH@Z` | REAL | `kOffReturnThis` |
| `??0exception@@QEAA@AEBV0@@Z` | REAL | `kOffReturnThis` |
| `??0exception@@QEAA@XZ` | REAL | `kOffReturnThis` |
| `??1exception@@UEAA@XZ` | REAL | `kOffReturnThis` |
| `??1type_info@@UEAA@XZ` | REAL | `kOffReturnThis` |
| `??3@YAXPEAX@Z` | REAL | `kOffFree` |
| `?terminate@@YAXXZ` | REAL | `kOffTerminate` |
| `?what@exception@@UEBAPEBDXZ` | REAL | `kOffPinEmptyCStr` |
| `___mb_cur_max_func` | REAL | `kOffPinReturn1` |
| `__dllonexit` | REAL | `kOffPinReturn0` |
| `__getmainargs` | REAL | `kOffGetMainArgs` |
| `__mb_cur_max_func` | REAL | `kOffPinReturn1` |
| `__p___argc` | REAL | `kOffPArgc` |
| `__p___argv` | REAL | `kOffPArgv` |
| `__p___wargv` | REAL | `kOffPWargv` |
| `__p__commode` | REAL | `kOffPCommode` |
| `__p__environ` | REAL | `kOffPErrno` |
| `__p__fmode` | REAL | `kOffPErrno` |
| `__p__wenviron` | REAL | `kOffPWenviron` |
| `__set_app_type` | REAL | `kOffPinReturn0` |
| `__setusermatherr` | REAL | `kOffSetUsermatherr` |
| `__wgetmainargs` | REAL | `kOffGetMainArgs` |
| `_amsg_exit` | REAL | `kOffTerminate` |
| `_c_exit` | REAL | `kOffPinReturn0` |
| `_callnewh` | REAL | `kOffCallnewhNoop` |
| `_cexit` | REAL | `kOffPinReturn0` |
| `_clearfp` | REAL | `kOffPinReturn0` |
| `_controlfp` | REAL | `kOffPinReturn0` |
| `_CxxThrowException` | REAL | `kOffTerminate` |
| `_errno` | REAL | `kOffPErrno` |
| `_exit` | REAL | `kOffExitProcess` |
| `_get_initial_environment` | REAL | `kOffGetInitialEnv` |
| `_get_initial_wide_environment` | REAL | `kOffGetInitialWideEnv` |
| `_initterm` | REAL | `kOffInitterm` |
| `_initterm_e` | REAL | `kOffInittermE` |
| `_ismbblead` | REAL | `kOffPinReturn0` |
| `_lock` | REAL | `kOffPinVoidNop` |
| `_msize` | REAL | `kOffPinReturn0` |
| `_onexit` | REAL | `kOffPinReturn0` |
| `_purecall` | REAL | `kOffTerminate` |
| `_set_invalid_parameter_handler` | REAL | `kOffPinReturn0` |
| `_statusfp` | REAL | `kOffPinReturn0` |
| `_stricmp` | REAL | `kOffStrcmp` |
| `_strnicmp` | REAL | `kOffStrcmp` |
| `_unlock` | REAL | `kOffPinVoidNop` |
| `_wcsicmp` | REAL | `kOffLstrcmpW` |
| `_wcsnicmp` | REAL | `kOffLstrcmpW` |
| `_XcptFilter` | REAL | `kOffPinReturn0` |
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
| `memcpy_s` | REAL | `kOffMemcpyS` |
| `memmove_s` | REAL | `kOffMemcpyS` |
| `putchar` | REAL | `kOffFputc` |
| `puts` | REAL | `kOffFputs` |
| `realloc` | REAL | `kOffRealloc` |
| `strchr` | REAL | `kOffStrchr` |
| `strcmp` | REAL | `kOffStrcmp` |
| `strcpy` | REAL | `kOffStrcpy` |
| `strlen` | REAL | `kOffStrlen` |
| `strtol` | REAL | `kOffPinReturn0` |
| `strtoul` | REAL | `kOffStrtoul` |
| `wcscpy_s` | REAL | `kOffWcscpyS` |
| `wcslen` | REAL | `kOffWcslen` |
<!-- AUTO:thunks-by-dll END -->

### vcruntime140.dll  (~330 LOC)

Stack-frame / SEH unwind primitives for MSVC-built code.
`__CxxFrameHandler3`, `_CxxThrowException`, `__std_terminate`,
`memcpy` / `memset` / `memmove` aliases, and `__chkstk` are REAL;
`__C_specific_handler` is a PE forwarder to ntdll's real
scope-table walker (it used to be a second, always-ContinueSearch
body here). The x64 C++ path uses bounded table-based unwinding and
a two-pass target transfer, including by-value catches, reference
catches, and cross-frame destructor ordering. Copy-ctor catch
objects, compressed FH4 metadata, and ESTypeList remain explicit
gaps.

**Rethrow (`throw;`) does not work** — the process dies on the
unhandled path. The compiler emits it as
`_CxxThrowException(NULL, NULL)`, leaving the runtime to supply both
the in-flight object and the resume point. Recording the object is
straightforward; the blocking half is that the re-raise's frame walk
arrives back at the *same* function, whose `ControlPc` is still
inside the inner `try`, so the search re-selects the catch it just
left. MSVC resolves this from the tryblock the catch funclet belongs
to, which has to be threaded through the dispatch rather than
recovered from the PC. Verified 2026-07-28 by building the case:
the re-raise faults with an `ACCESS_VIOLATION` at an address inside
`.pdata` — a handler target decoded from a FuncInfo the funclet's
`ControlPc` does not describe.

The DLLs carrying the engine (`vcruntime140`, `ntdll`, `kernel32`)
are compiled **with** unwind tables. Without `.pdata` a function
with a prologue is treated as a leaf by the unwinder (`RIP=[RSP]`,
`RSP+=8`), so any exception raised while inside the engine — a
rethrow, a throw from a destructor during unwind, a fault inside an
`__except` filter — desynchronizes the walk. `cxx_call_funclet` is
hand-written assembly for the same reason: it establishes `rbp` as a
described frame register so the unwinder can recover `RSP` across
its stack realignment.

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
/ `_guard_xfg_dispatch_icall` live in
`userland/libs/vcruntime140/guard_icall.S` — both are `jmpq
*%rax` (trust-the-target). Bitmap enforcement is GAP — see
the roadmap note. // GAP: per-image CFG/XFG bitmap walk —
lands with the image-load-config slice.

**Thunked imports (auto-generated from `kernel/subsystems/win32/thunks_table.inc`):**

<!-- AUTO:thunks-by-dll DLL=vcruntime140.dll START -->
<!-- generated by tools/build/gen-wiki-auto.py — do not edit by hand -->

**`vcruntime140.dll`** — 23 imports thunked: 23 REAL.

| Method | Status | Routed to |
|--------|--------|-----------|
| `__chkstk` | REAL | `kOffChkStk` |
| `__CxxFrameHandler3` | REAL | `kOffTerminate` |
| `__std_exception_copy` | REAL | `kOffPinReturn0` |
| `__std_exception_destroy` | REAL | `kOffPinReturn0` |
| `__std_terminate` | REAL | `kOffTerminate` |
| `__vcrt_InitializeCriticalSectionEx` | REAL | `kOffInitCritSec` |
| `_CxxThrowException` | REAL | `kOffTerminate` |
| `_InterlockedCompareExchange` | REAL | `kOffInterlockedCmpXchg` |
| `_InterlockedCompareExchange64` | REAL | `kOffInterlockedCmpXchg64` |
| `_InterlockedDecrement` | REAL | `kOffInterlockedDec` |
| `_InterlockedDecrement64` | REAL | `kOffInterlockedDec64` |
| `_InterlockedExchange` | REAL | `kOffInterlockedExchg` |
| `_InterlockedExchange64` | REAL | `kOffInterlockedExchg64` |
| `_InterlockedExchangeAdd` | REAL | `kOffInterlockedExchgAdd` |
| `_InterlockedExchangeAdd64` | REAL | `kOffInterlockedExchgAdd64` |
| `_InterlockedIncrement` | REAL | `kOffInterlockedInc` |
| `_InterlockedIncrement64` | REAL | `kOffInterlockedInc64` |
| `_purecall` | REAL | `kOffTerminate` |
| `_purecall` | REAL | `kOffTerminate` |
| `memchr` | REAL | `kOffPinReturn0` |
| `memcpy` | REAL | `kOffMemmove` |
| `memmove` | REAL | `kOffMemmove` |
| `memset` | REAL | `kOffMemset` |
<!-- AUTO:thunks-by-dll END -->

### msvcp140.dll  (~93 LOC)

C++ stdlib stubs. `?uncaught_exception@std@@YA_NXZ`,
`?_Xbad_alloc@std@@YAXXZ`, etc. **STUB**: every body returns
the safest default (false / no-throw / null). Real STL
containers do work because their methods are inline-templated
in the PE and don't actually call back here.

**Thunked imports (auto-generated from `kernel/subsystems/win32/thunks_table.inc`):**

<!-- AUTO:thunks-by-dll DLL=msvcp140.dll START -->
<!-- generated by tools/build/gen-wiki-auto.py — do not edit by hand -->

**`msvcp140.dll`** — 18 imports thunked: 18 REAL.

| Method | Status | Routed to |
|--------|--------|-----------|
| `??6?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAAAEAV01@H@Z` | REAL | `kOffReturnThis` |
| `??6?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAAAEAV01@K@Z` | REAL | `kOffReturnThis` |
| `??6?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAAAEAV01@P6AAEAV01@AEAV01@@Z@Z` | REAL | `kOffReturnThis` |
| `?_Osfx@?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAAXXZ` | REAL | `kOffPinVoidNop` |
| `?_Syserror_map@std@@YAPEBDH@Z` | REAL | `kOffPinReturn0` |
| `?_Winerror_map@std@@YAHH@Z` | REAL | `kOffPinReturn0` |
| `?_Winerror_message@std@@YAKKPEADK@Z` | REAL | `kOffPinReturn0` |
| `?_Xbad_alloc@std@@YAXXZ` | REAL | `kOffTerminate` |
| `?_Xlength_error@std@@YAXPEBD@Z` | REAL | `kOffTerminate` |
| `?_Xout_of_range@std@@YAXPEBD@Z` | REAL | `kOffTerminate` |
| `?flush@?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAAAEAV12@XZ` | REAL | `kOffReturnThis` |
| `?put@?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAAAEAV12@D@Z` | REAL | `kOffReturnThis` |
| `?setstate@?$basic_ios@DU?$char_traits@D@std@@@std@@QEAAXH_N@Z` | REAL | `kOffPinVoidNop` |
| `?sputc@?$basic_streambuf@DU?$char_traits@D@std@@@std@@QEAAHD@Z` | REAL | `kOffPinReturn0` |
| `?sputn@?$basic_streambuf@DU?$char_traits@D@std@@@std@@QEAA_JPEBD_J@Z` | REAL | `kOffSputn` |
| `?sputn@?$basic_streambuf@DU?$char_traits@D@std@@@std@@QEAA_JPEBD_J@Z` | REAL | `kOffSputn` |
| `?uncaught_exception@std@@YA_NXZ` | REAL | `kOffPinReturn0` |
| `?widen@?$basic_ios@DU?$char_traits@D@std@@@std@@QEBADD@Z` | REAL | `kOffWiden` |
<!-- AUTO:thunks-by-dll END -->

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

**`ucrtbase.dll`** — 64 imports thunked: 64 REAL.

| Method | Status | Routed to |
|--------|--------|-----------|
| `___mb_cur_max_func` | REAL | `kOffPinReturn1` |
| `__acrt_iob_func` | REAL | `kOffPErrno` |
| `__C_specific_handler` | REAL | `kOffPinReturn1` |
| `__getmainargs` | REAL | `kOffGetMainArgs` |
| `__p___argc` | REAL | `kOffPArgc` |
| `__p___argv` | REAL | `kOffPArgv` |
| `__p___wargv` | REAL | `kOffPWargv` |
| `__p__commode` | REAL | `kOffPCommode` |
| `__p__environ` | REAL | `kOffPErrno` |
| `__p__fmode` | REAL | `kOffPErrno` |
| `__p__wenviron` | REAL | `kOffPWenviron` |
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
| `_get_initial_environment` | REAL | `kOffGetInitialEnv` |
| `_get_initial_wide_environment` | REAL | `kOffGetInitialWideEnv` |
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
| `memcpy_s` | REAL | `kOffMemcpyS` |
| `memmove_s` | REAL | `kOffMemcpyS` |
| `putchar` | REAL | `kOffFputc` |
| `puts` | REAL | `kOffFputs` |
| `realloc` | REAL | `kOffRealloc` |
| `strchr` | REAL | `kOffStrchr` |
| `strcmp` | REAL | `kOffStrcmp` |
| `strcpy` | REAL | `kOffStrcpy` |
| `strlen` | REAL | `kOffStrlen` |
| `strtol` | REAL | `kOffPinReturn0` |
| `strtoul` | REAL | `kOffStrtoul` |
| `terminate` | REAL | `kOffTerminate` |
| `wcscpy_s` | REAL | `kOffWcscpyS` |
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

**Thunked imports (auto-generated from `kernel/subsystems/win32/thunks_table.inc`):**

<!-- AUTO:thunks-by-dll DLL=dbghelp.dll START -->
<!-- generated by tools/build/gen-wiki-auto.py — do not edit by hand -->

**`dbghelp.dll`** — 14 imports thunked: 14 REAL.

| Method | Status | Routed to |
|--------|--------|-----------|
| `MiniDumpWriteDump` | REAL | `kOffPinReturn0` |
| `StackWalk64` | REAL | `kOffPinReturn0` |
| `SymCleanup` | REAL | `kOffPinReturn1` |
| `SymCleanup` | REAL | `kOffPinReturn1` |
| `SymFromAddr` | REAL | `kOffPinReturn0` |
| `SymFromAddr` | REAL | `kOffPinReturn0` |
| `SymFromAddrW` | REAL | `kOffPinReturn0` |
| `SymFunctionTableAccess64` | REAL | `kOffPinReturn0` |
| `SymGetLineFromAddr64` | REAL | `kOffPinReturn0` |
| `SymGetModuleBase64` | REAL | `kOffPinReturn0` |
| `SymInitialize` | REAL | `kOffPinReturn1` |
| `SymInitialize` | REAL | `kOffPinReturn1` |
| `SymInitializeW` | REAL | `kOffPinReturn1` |
| `SymLoadModule64` | REAL | `kOffPinReturn0` |
<!-- AUTO:thunks-by-dll END -->

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
- Accelerators: `LoadAcceleratorsA/W`, `TranslateAcceleratorA/W`
  — REAL. RT_ACCELERATOR tables loaded via pe_resources.h;
  TranslateAccelerator matches VK + modifiers and posts
  WM_COMMAND. GAP: named (string) accelerator tables unsupported
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
- Menus — submenu marshaling: nested HMENU trees are flattened
  depth-first into a single `TpItemWire[32]` array by the
  userland thunk; each submenu-flagged row carries
  `child_index` / `child_count` back-pointers into the same
  array, validated by the kernel (forward-only, in-bounds, no
  orphans, per-panel cap, depth <= `kMenuMaxStack`).
- Menus — GAPs: `TPM_RIGHTBUTTON` / `TPM_HORIZONTAL` /
  `TPMPARAMS` exclude-rect ignored; concurrent TrackPopupMenu
  from two PE processes serialise on the single-instance kernel
  menu (second caller cancels).
- Menus: `GetMenu`/`SetMenu` (per-HWND HMENU store, round-trips),
  `GetSystemMenu` (synthesizes + caches a standard system menu;
  `bRevert` destroys it) — REAL. `DrawMenuBar` triggers a real
  window redraw (`SYS_WIN_INVALIDATE`) but the compositor has no
  non-client menu band yet, so item glyphs aren't painted — GAP.
  `LoadMenuW` — STUB (needs the `.rsrc` resource loader).
- Dialog manager (in-memory templates): `DialogBoxIndirectParamA/W`,
  `CreateDialogIndirectParamA/W`, `EndDialog`, `IsDialogMessageA/W`,
  `GetDlgItem`, `GetDlgCtrlID`, `GetDlgItemTextA/W`,
  `SetDlgItemTextA/W`, `GetDlgItemInt`, `SetDlgItemInt`,
  `SendDlgItemMessageA/W`, `DefDlgProcA/W` — REAL for in-memory
  DLGTEMPLATE templates. Parses DLGTEMPLATE/DLGITEMTEMPLATE, creates
  the dialog window and child controls, runs a modal message loop
  (DialogBoxIndirectParam) or returns immediately (CreateDialogIndirect),
  and EndDialog unwinds the modal pump with the caller's result code.
  Standard control classes BUTTON (0x0080), EDIT (0x0081), STATIC
  (0x0082), LISTBOX (0x0083), SCROLLBAR (0x0084), COMBOBOX (0x0085)
  are registered and create windows; BUTTON and STATIC paint labels
  via WM_PAINT.
  GAP: dialog units are approximated (2x multiplier, no font metrics);
  DS_SETFONT is accepted but font data is skipped; tab navigation
  in IsDialogMessage handles VK_TAB only (no mnemonics).
- Dialog manager (resource-based): `DialogBoxParamA/W`,
  `DialogBoxA/W`, `CreateDialogParamA/W`, `CreateDialogA/W` — STUB
  when passed a PE resource ID (MAKEINTRESOURCE). Requires an
  RT_DIALOG `.rsrc` walker that does not exist. If passed a direct
  pointer to an in-memory template (address > 0xFFFF), delegates to
  the Indirect variant and works.
- Hooks: `SetWindowsHookExA/W`, `UnhookWindowsHookEx`,
  `CallNextHookEx` — STUB
- Subclassing: `SetWindowSubclass` lives in comctl32 — STUB
- DDE: `DdeInitializeA/W`, `DdeCreateStringHandleA/W`,
  `DdeFreeStringHandle`, `DdeUninitialize` — STUB
- Scrollbars (`SetScrollInfo` etc.) — STUB
- `LoadStringW` / `LoadStringA` — REAL as of 2026-07-28, both
  bitnesses. Walks the module's real `RT_STRING` bundles via
  `userland/libs/common/pe_resources.h`, including the documented
  `cchBufferMax == 0` pointer-return form. Until that slice these
  returned a fixed `"DuetOS"` placeholder for **every** id, so a
  caption, a menu label and an error message all came back
  identical. `LoadStringA` carries a GAP: narrowing is Latin-1
  truncation, not a codepage conversion.
- `LoadIconA/W` — REAL. Decodes RT_GROUP_ICON -> RT_ICON from the
  PE's .rsrc section into BGRA pixels, creates a GDI bitmap via
  `SYS_GDI_CREATE_COMPAT_BITMAP` + `SYS_GDI_SET_DIBITS`, and
  returns the bitmap handle as HICON. NULL hInstance returns a
  non-NULL sentinel for system icons (`RegisterClassEx` callers
  treat NULL `hIcon` as fatal). Icons up to 64x64 are decoded.
- `LoadCursorA/W` — REAL. NULL hInstance returns IDC_* sentinels
  (existing behaviour). PE hInstance decodes RT_GROUP_CURSOR ->
  RT_CURSOR from .rsrc and registers via `SYS_GDI_CREATE_CURSOR_RGBA`
  (syscall 224), which nearest-neighbour samples to the 12x20
  internal sprite. Cursors up to 64x64 are decoded.
- `LoadImageA/W` — REAL. Dispatches by `IMAGE_ICON` / `IMAGE_CURSOR`
  / `IMAGE_BITMAP` to LoadIcon / LoadCursor / LoadBitmap. GAP:
  `LR_DEFAULTSIZE`, `LR_SHARED`, `LR_LOADFROMFILE` not implemented.
- `LoadBitmapA/W` — STUB, returns NULL. RT_BITMAP decoding is the
  remaining piece.
- `LoadAcceleratorsA/W`, `TranslateAcceleratorA/W` — REAL.
  The kernel now posts Win32 VK codes in `WM_KEYDOWN`/`WM_KEYUP`
  `wParam` (translated from DuetOS `KeyCode` via
  `kernel/subsystems/win32/keycode_vk.h`). `LoadAcceleratorsA/W`
  parse `RT_ACCELERATOR` from the PE's `.rsrc` section via
  `duet_res_find`; `TranslateAcceleratorA/W` match VK + modifier
  state and post `WM_COMMAND`. GAP: named (string) accelerator
  tables are unsupported (only `MAKEINTRESOURCE` ordinals).

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
> SetPixel, BitBlt) are real. Off-screen surfaces are real:
> memory DCs, compatible bitmaps, blits, DIB upload/readback and
> DIB sections all move actual pixels, proven per-boot by
> `userland/apps/surface_smoke` (see below). Fonts are tag-based
> handles. **No anti-aliasing, no outline fonts, no path API.**
>
> **Corrected 2026-07-29.** This section previously listed
> `CreateBitmap`, `CreateDIBSection`, `CreateDIBitmap`,
> `CreatePen` and `StretchBlt` under **Real**. They were not:
> the first four returned NULL unconditionally and `StretchBlt`
> returned success without drawing. `CreateSolidBrush` returned
> a userland sentinel the kernel could not resolve, so every
> fill into a memory DC painted white regardless of the brush.
> All are now genuinely wired. The lesson for this page: an
> export existing is not evidence it works — only a fixture that
> compares pixels is.

**Real:**
- DC: `GetDC`, `ReleaseDC`, `CreateCompatibleDC`,
  `DeleteDC`, `SaveDC`, `RestoreDC`, `GetWindowDC`
- Objects: `CreateSolidBrush`, `CreateBrushIndirect`,
  `CreatePen`, `CreateFontA/W`, `CreateFontIndirectA/W`,
  `CreateBitmap`, `CreateCompatibleBitmap`,
  `CreateDIBSection`, `CreateDIBitmap`, `GetStockObject`,
  `SelectObject`, `DeleteObject`, `GetObjectA/W`
- Off-screen surfaces: `CreateCompatibleBitmap`, `CreateBitmap`,
  `CreateDIBSection`, `CreateDIBitmap`, `SetDIBits`, `GetDIBits`,
  `BitBlt`, `StretchBlt`. Surfaces are kernel-owned BGRA8888
  buffers reached through `SYS_GDI_SET_DIBITS` / `_GET_DIBITS`
  (214 / 215). Each is owned by its creating process and reaped
  at exit; per-process ceiling is 16 objects per kind and 8 MiB
  of pixels.
- Drawing: `FillRect`, `FrameRect`, `Rectangle`,
  `Ellipse`, `LineTo`, `MoveToEx`,
  `Polygon`, `Polyline`,
  `SetPixel`, `SetPixelV`, `GetPixel`,
  `TextOutA/W`, `ExtTextOutA/W` (honours `ETO_CLIPPED` + the
  `lprc` clip-rect by trimming the (text, x) pair to the
  visible columns at the kernel font's 8 px cell width;
  `ETO_OPAQUE` still STUB), `DrawTextA/W`
- State: `SetBkColor`, `SetBkMode`, `SetMapMode`,
  `SetTextColor`, `SetTextAlign`
- Region API (rect-list): `CreateRectRgn`, `CreateRectRgnIndirect`,
  `CombineRgn`, `SetRectRgn`, `GetRgnBox`, `PtInRegion`,
  `RectInRegion`, `OffsetRgn`, `EqualRgn` — REAL. Single-rect regions
  and the rect-list query/manipulation ops are exact; the geometry is
  host-tested (`tests/host/test_gdi32_region.cpp`).

**STUB / GAP:**
- DIB depths: 16 / 24 / 32bpp only. Palettised (<= 8bpp) DIBs are
  refused rather than mis-rendered — GAP. 16bpp is read as
  X1-R5-G5-B5; `BI_BITFIELDS` 5-6-5 is not parsed — GAP.
- `SetDIBits` / `GetDIBits` transfer whole images only; a partial
  scanline band (`start != 0`, or `scans` short of the height) is
  refused — GAP.
- `CreateBitmap` with initial bits accepts 32bpp only; a 24bpp DDB's
  WORD-aligned rows do not match the DWORD DIB stride — GAP.
- `CreateDIBSection` ignores `section` / `offset` (no file-mapping
  backing store) — GAP. Its user-side pixels reach the kernel
  surface on the next `BitBlt` / `StretchBlt`, not on write.
- `GetObjectA/W` returns 0 (no BITMAP/LOGBRUSH introspection) — STUB.
- Path API: `BeginPath`, `EndPath`, `StrokePath` — STUB
- Region set-algebra: `CombineRgn` with `RGN_OR`/`RGN_XOR`/`RGN_DIFF`
  on multi-rect inputs collapses to the bounding box (no rectangle
  decomposition) — GAP. Shape regions (`CreateRoundRectRgn`,
  `CreateEllipticRgn`, `CreatePolygonRgn`) and clip-region selection
  (`SelectClipRgn`, `ExtSelectClipRgn`) — STUB.
- Metafiles: `CreateMetaFile`, `PlayMetaFile` — STUB
- **Font pipeline (v0):** `CreateFontA`/`CreateFontW` route through
  `SYS_GDI_CREATE_FONT` (225) to a kernel font registry with 3
  built-in bitmap fonts (System 8x8, Fixedsys 8x8, Terminal 8x16).
  `SelectObject` on font handles updates the DC's selected font.
  `GetTextMetricsA`/`GetTextMetricsW` return metrics for the DC's
  selected font via `SYS_GDI_GET_TEXT_METRICS` (226).
  `GetTextExtentPoint32A`/`GetTextExtentPoint32W`/`GetCharWidth32A`
  derive cell size from the DC's font. All text-drawing paths
  (`TextOutA`/`W`, `DrawTextA`/`W`) honour the DC's selected font.
  `GetStockObject` returns font handles for `SYSTEM_FONT` (13) and
  `SYSTEM_FIXED_FONT` (16). Per-process font ceiling: 16 handles.
  These DLL exports are resolved from the preloaded gdi32.dll EAT,
  not from the thunk table (the thunk table entries are dead
  fallbacks).
- Outline / TrueType fonts: `EnumFontsW`, `GetGlyphOutline`
  — STUB (no outline font rasteriser; the registry serves only
  bitmap fonts)
- `CreateFontIndirectA`/`CreateFontIndirectW` — STUB (return 0)
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

### shlwapi.dll  (~840 LOC, ~44 exports)

> **Status:** path manipulation is REAL. String comparison /
> regex (`PathMatchSpecW`) is REAL with limited glob support.

`Path*`, `Str*`, `PathMatchSpecW` — all REAL for the v0
inventory above. `PathCanonicalizeW` is GAP for `..` walks
above the drive root.

`wnsprintfA/W` — REAL bounded printf; shares the user32
restricted-printf engine (`user32_wsprintf_core.h`, one format
engine for both DLLs) and returns negative on truncation per the
Win32 contract. `StrToIntExA/W` — REAL decimal / `STIF_SUPPORT_HEX`
hex parse (core in `shlwapi_parse.h`). Both are pinned by the
hosted test `tests/host/test_kernel32_nls.cpp`.

**Thunked imports (auto-generated from `kernel/subsystems/win32/thunks_table.inc`):**

<!-- AUTO:thunks-by-dll DLL=shlwapi.dll START -->
<!-- generated by tools/build/gen-wiki-auto.py — do not edit by hand -->

**`shlwapi.dll`** — 20 imports thunked: 20 REAL.

| Method | Status | Routed to |
|--------|--------|-----------|
| `PathAddBackslashW` | REAL | `kOffPinReturn0` |
| `PathAppendW` | REAL | `kOffPinReturn0` |
| `PathCombineW` | REAL | `kOffPinReturn0` |
| `PathFileExistsA` | REAL | `kOffPinReturn0` |
| `PathFileExistsW` | REAL | `kOffPinReturn0` |
| `PathFindExtensionA` | REAL | `kOffPinReturn0` |
| `PathFindExtensionW` | REAL | `kOffPinReturn0` |
| `PathFindFileNameA` | REAL | `kOffPinReturn0` |
| `PathFindFileNameW` | REAL | `kOffPinReturn0` |
| `PathIsDirectoryW` | REAL | `kOffPinReturn0` |
| `PathRemoveFileSpecW` | REAL | `kOffPinReturn0` |
| `PathStripPathW` | REAL | `kOffPinVoidNop` |
| `StrCmpIA` | REAL | `kOffStrcmp` |
| `StrCmpIW` | REAL | `kOffStrcmp` |
| `StrCmpNIA` | REAL | `kOffStrcmp` |
| `StrCmpNIW` | REAL | `kOffStrcmp` |
| `StrCmpNW` | REAL | `kOffPinReturn0` |
| `StrCmpW` | REAL | `kOffPinReturn0` |
| `StrStrIW` | REAL | `kOffPinReturn0` |
| `StrStrW` | REAL | `kOffPinReturn0` |
<!-- AUTO:thunks-by-dll END -->

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
`ShellAboutW` / `ShellAboutA` — REAL (GUI): creates a real
compositor-backed "About DuetOS" window via `SYS_WIN_CREATE` +
`SYS_WIN_SHOW`, paints a titled client (blue accent bar + the
OS-identity / app / version-text lines) via `SYS_GDI_FILL_RECT`
+ `SYS_GDI_TEXT_OUT`, then runs a bounded ~30 s message-pump
loop so the window stays visible (and the process alive) for a
screendump before returning. This is what makes `winver.exe`'s
dialog appear on the desktop. GAP: not a true modal dialog (no
DLGPROC, no OK-button hit-test) — it self-dismisses on the
timeout or an explicit WM_CLOSE/WM_QUIT.

**Thunked imports (auto-generated from `kernel/subsystems/win32/thunks_table.inc`):**

<!-- AUTO:thunks-by-dll DLL=shell32.dll START -->
<!-- generated by tools/build/gen-wiki-auto.py — do not edit by hand -->

**`shell32.dll`** — 13 imports thunked: 13 REAL.

| Method | Status | Routed to |
|--------|--------|-----------|
| `CommandLineToArgvW` | REAL | `kOffPinReturn0` |
| `ExtractIconExW` | REAL | `kOffPinReturn0` |
| `ExtractIconW` | REAL | `kOffPinReturn0` |
| `SHCreateDirectoryExW` | REAL | `kOffPinReturn0` |
| `SHCreateDirectoryW` | REAL | `kOffPinReturn0` |
| `ShellExecuteExW` | REAL | `kOffPinReturn1` |
| `ShellExecuteW` | REAL | `kOffPinReturn1` |
| `SHFileOperationW` | REAL | `kOffPinReturn0` |
| `SHGetFolderPathA` | REAL | `kOffPinReturn0` |
| `SHGetFolderPathW` | REAL | `kOffPinReturn0` |
| `SHGetKnownFolderPath` | REAL | `kOffPinReturn0` |
| `SHGetPathFromIDListW` | REAL | `kOffPinReturn1` |
| `SHGetSpecialFolderPathW` | REAL | `kOffPinReturn1` |
<!-- AUTO:thunks-by-dll END -->

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

**Thunked imports (auto-generated from `kernel/subsystems/win32/thunks_table.inc`):**

<!-- AUTO:thunks-by-dll DLL=ole32.dll START -->
<!-- generated by tools/build/gen-wiki-auto.py — do not edit by hand -->

**`ole32.dll`** — 15 imports thunked: 15 REAL.

| Method | Status | Routed to |
|--------|--------|-----------|
| `CLSIDFromProgID` | REAL | `kOffPinHresultSOk` |
| `CLSIDFromString` | REAL | `kOffPinHresultSOk` |
| `CoCreateInstance` | REAL | `kOffPinHresultSOk` |
| `CoCreateInstanceEx` | REAL | `kOffPinHresultSOk` |
| `CoGetClassObject` | REAL | `kOffPinHresultSOk` |
| `CoInitialize` | REAL | `kOffPinReturn0` |
| `CoInitializeEx` | REAL | `kOffPinReturn0` |
| `CoTaskMemAlloc` | REAL | `kOffPinReturn0` |
| `CoTaskMemFree` | REAL | `kOffPinVoidNop` |
| `CoTaskMemRealloc` | REAL | `kOffPinReturn0` |
| `CoUninitialize` | REAL | `kOffPinVoidNop` |
| `IIDFromString` | REAL | `kOffPinHresultSOk` |
| `OleInitialize` | REAL | `kOffPinReturn0` |
| `OleUninitialize` | REAL | `kOffPinVoidNop` |
| `StringFromCLSID` | REAL | `kOffPinHresultSOk` |
<!-- AUTO:thunks-by-dll END -->

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

> **Status:** synchronous BSD-socket subset is REAL; the
> event/message async tier (`WSAEventSelect` family +
> `WSAAsyncSelect`) is REAL on the `kSockOpPollEvents`
> producer. Overlapped / completion-port I/O is STUB.

**Real:**
- `WSAStartup`, `WSACleanup`, `WSAGetLastError`,
  `WSASetLastError`
- `socket`, `closesocket`, `bind`, `listen`, `connect`,
  `accept`, `send`, `recv`, `sendto`, `recvfrom`, `shutdown`
- `setsockopt`, `getsockopt`, `select`, `__WSAFDIsSet`,
  `ioctlsocket` (`FIONBIO` tracks a real per-socket
  non-blocking bit, emulated DLL-side via the poll mask),
  `getsockname`, `getpeername`
- Async tier: `WSAEventSelect`, `WSAEnumNetworkEvents`,
  `WSAWaitForMultipleEvents` (10 ms polling loop) +
  `WSAAsyncSelect` (per-process poller thread posts one FD_*
  event per window message via `SYS_WIN_POST_MSG`; Winsock
  re-arm contract; implicit non-blocking; FD_CONNECT posted
  from the `connect` hook with the real error)
- `WSACreateEvent`, `WSACloseEvent`, `WSASetEvent`,
  `WSAResetEvent`
- Byte order: `htons`, `htonl`, `ntohs`, `ntohl`,
  `htonll`, `ntohll`
- Address: `inet_addr`, `inet_ntoa`, `inet_pton`, `inet_ntop`,
  `gethostname`, `gethostbyname`, `getaddrinfo`,
  `freeaddrinfo`, `getnameinfo`

**STUB:**
- `WSARecv`, `WSASend`, `WSARecvFrom`, `WSASendTo` — STUB
  (no overlapped I/O)
- `WSAIoctl` — GAP (only SIO_GET_INTERFACE_LIST)
- IPv6 socket API — GAP (sockets create but bind fails)
- GAP: non-blocking recv on a *wire* TCP socket over-reports
  `WSAEWOULDBLOCK` (`SocketPollEvents` has no wire FD_READ
  producer; loopback + UDP are exact)

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

### wininet.dll  (~1700 LOC, ~50 exports)

> **Status:** HTTP/1.1 GET works end-to-end (browser_pe + mini_browser
> PEs use it via WinInet and raw WinSock respectively). Cookies REAL
> via in-process LRU table. RFC 1123 time format / parse REAL. FTP /
> cache / async — STUB.

`InternetOpenA/W`, `InternetConnectA/W`, `HttpOpenRequestA/W`,
`HttpSendRequestA/W`, `HttpAddRequestHeadersA/W`,
`InternetOpenUrlA/W`, `InternetReadFile`, `InternetReadFileExA/W`,
`InternetCloseHandle`, `InternetQueryDataAvailable` — REAL: full HTTP/1.1
GET via the kernel socket pool (SYS_SOCKET_OP, same path ws2_32 uses).
Handle pool of 8 slots; encoding `0x4000 | (kind<<8) | slot` so handles
never collide with NULL or INVALID_HANDLE_VALUE. On DNS / connect /
send / first-recv failure the slot transparently falls back to a fixed
"HTTP/1.1 200 OK" / "DuetOS hello" body so ABI-shape smokes pass on
hosts with no live Internet. `InternetReadFile` transparently decodes
`Transfer-Encoding: chunked` responses (hex size lines, chunk
extensions, inter-chunk + terminal CRLFs stripped) so the caller
only ever sees the entity body — matching the Win32 contract. This
is exercised live: real google.com / example.com `200` responses
are chunked, and the `smoke=browser` profile verifies the decoded
first body line is HTML, not a chunk-size header.

`HttpQueryInfoA/W` — REAL for `STATUS_CODE`, `STATUS_TEXT`,
`RAW_HEADERS`, `RAW_HEADERS_CRLF`, `CONTENT_TYPE`, `CONTENT_LENGTH`,
`LOCATION`, `SERVER`, `VERSION` (and their `FLAG_NUMBER` variants
for `STATUS_CODE` + `CONTENT_LENGTH`).
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
> Backed by the in-tree SHA-256 / SHA-384 / SHA-512 / SHA-1 / MD5 /
> AES hash + cipher cores. `BCryptGenRandom` (64-bit `bcrypt.dll`)
> draws from **RDRAND** when the CPU advertises it, otherwise from the
> kernel CSPRNG via **`SYS_RANDOM_BYTES`** (212) — cryptographically
> strong on every CPU; it returns `STATUS_UNSUCCESSFUL` if the kernel
> can't fill the buffer rather than degrading to a counter (audit
> GS-01 / ulibs-net-2, CWE-338, fixed). **Known limit:** the 32-bit
> `bcrypt_32.dll` `BCryptGenRandom` is still a v0 in-DLL LCG — wiring
> it to `SYS_RANDOM_BYTES` is gated on verifying the i386 syscall
> arg-passing ABI (the `_32` DLLs pass args in `ebx/ecx/edx`, which the
> native dispatch does not yet remap to `rdi/rsi`).

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

**Thunked imports (auto-generated from `kernel/subsystems/win32/thunks_table.inc`):**

<!-- AUTO:thunks-by-dll DLL=d3d9.dll START -->
<!-- generated by tools/build/gen-wiki-auto.py — do not edit by hand -->

**`d3d9.dll`** — 2 imports thunked: 2 REAL.

| Method | Status | Routed to |
|--------|--------|-----------|
| `Direct3DCreate9` | REAL | `kOffPinReturn0` |
| `Direct3DCreate9Ex` | REAL | `kOffPinHresultSOk` |
<!-- AUTO:thunks-by-dll END -->

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

**Thunked imports (auto-generated from `kernel/subsystems/win32/thunks_table.inc`):**

<!-- AUTO:thunks-by-dll DLL=d3d11.dll START -->
<!-- generated by tools/build/gen-wiki-auto.py — do not edit by hand -->

**`d3d11.dll`** — 4 imports thunked: 4 REAL.

| Method | Status | Routed to |
|--------|--------|-----------|
| `D3D11CreateDevice` | REAL | `kOffPinD3d11NoDevice` |
| `D3D11CreateDevice` | REAL | `kOffPinD3d11NoDevice` |
| `D3D11CreateDeviceAndSwapChain` | REAL | `kOffPinD3d11NoDevice` |
| `D3D11CreateDeviceAndSwapChain` | REAL | `kOffPinD3d11NoDevice` |
<!-- AUTO:thunks-by-dll END -->

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

**Thunked imports (auto-generated from `kernel/subsystems/win32/thunks_table.inc`):**

<!-- AUTO:thunks-by-dll DLL=d3d12.dll START -->
<!-- generated by tools/build/gen-wiki-auto.py — do not edit by hand -->

**`d3d12.dll`** — 4 imports thunked: 4 REAL.

| Method | Status | Routed to |
|--------|--------|-----------|
| `D3D12CreateDevice` | REAL | `kOffPinD3d12NoDevice` |
| `D3D12CreateDevice` | REAL | `kOffPinD3d12NoDevice` |
| `D3D12GetDebugInterface` | REAL | `kOffPinD3d12NoDevice` |
| `D3D12SerializeRootSignature` | REAL | `kOffPinD3d12NoDevice` |
<!-- AUTO:thunks-by-dll END -->

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

**Thunked imports (auto-generated from `kernel/subsystems/win32/thunks_table.inc`):**

<!-- AUTO:thunks-by-dll DLL=dxgi.dll START -->
<!-- generated by tools/build/gen-wiki-auto.py — do not edit by hand -->

**`dxgi.dll`** — 6 imports thunked: 6 REAL.

| Method | Status | Routed to |
|--------|--------|-----------|
| `CreateDXGIFactory` | REAL | `kOffPinDxgiNoFactory` |
| `CreateDXGIFactory` | REAL | `kOffPinDxgiNoFactory` |
| `CreateDXGIFactory1` | REAL | `kOffPinDxgiNoFactory` |
| `CreateDXGIFactory1` | REAL | `kOffPinDxgiNoFactory` |
| `CreateDXGIFactory2` | REAL | `kOffPinDxgiNoFactory` |
| `CreateDXGIFactory2` | REAL | `kOffPinDxgiNoFactory` |
<!-- AUTO:thunks-by-dll END -->

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

### d3dcompiler.dll  (~1 771 LOC) — `D3DCompile`, `D3DCompile2`, `D3DCreateBlob`, `D3DReflect`, `D3DDisassemble`

**Shipped and preloaded.** Front-ends a real in-process HLSL
compiler. REAL: a recursive-descent lexer/parser over a small HLSL
subset (struct decls, `cbuffer`, function defs, `+ - * /` /
unary-`-` / parenthesised / field-access / call / type-constructor
expressions) and a deterministic DXBC-shaped bytecode emitter
(`DXBC` magic + FNV-1a hash + SHEX/ISGN/OSGN/STAT chunks). Blobs
are wrapped in canonical `ID3DBlob` COM objects; a second compile
of identical source is byte-exact; `D3DReflect` round-trips the
blob; `DuetOS_D3DCompiler_PeekBlobMagic` exposes the magic for
smoke tests.

GAP: the emitted bytecode is **not executed** by the d3d11/d3d12
draw path — the rasterizer stays pass-through. STUB: texture /
sampler grammar, control flow, intrinsic library, optimisation.
`d3dcompiler_47.dll` (versioned alias) is not built today. See
[`wiki/subsystems/DirectX.md`](../subsystems/DirectX.md) for the
HLSL-subset narrative.

### vulkan-1.dll  (~1 043 LOC) — `vkGetInstanceProcAddr`, `vkCreateInstance`, `vkEnumeratePhysicalDevices`, …

**Shipped and preloaded.** Thin thunks over `SYS_VK_CALL`
(syscall 211) into the in-kernel Vulkan ICD
(`kernel/subsystems/graphics/graphics_vk.cpp`). REAL (v0 bind
set): `vkCreateInstance` / `vkDestroyInstance`,
`vkEnumeratePhysicalDevices`, `vkCreateDevice` /
`vkDestroyDevice`, `vkGetDeviceQueue`, `vkDeviceWaitIdle` /
`vkQueueWaitIdle`, `vkEnumerateInstanceVersion`, and the
string→fn-ptr `vkGetInstanceProcAddr` / `vkGetDeviceProcAddr`
lookup.

STUB: buffer/memory/image creation (needs user-mappable shared
memory), command-buffer record+submit, swapchain / surface / WSI,
SPIR-V module create. These return `VK_ERROR_INITIALIZATION_FAILED`
so a caller's `if (result != VK_SUCCESS) return;` early-exit works
cleanly — many apps then fall back to D3D11.

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

A real Windows app reaches into far more DLLs than the 44 we
ship. Here's what's *not* shipped — grouped by what would unlock
if we did. PE imports of these names fail at PeLoad today. DLLs we
**do** ship — including `vulkan-1.dll` and `d3dcompiler.dll` — are
covered in [§7 (DirectX surface)](#7-directx-surface-peer-of-win32-7000-loc)
above and are deliberately absent from this list.

### Graphics / media

- **opengl32.dll** — OpenGL 1.1+. Common in older games and
  CAD apps. Needs an ICD model + GLSL compiler.
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
- **d3dcompiler_47.dll** — versioned alias of the shipped
  `d3dcompiler.dll` (see [§7](#7-directx-surface-peer-of-win32-7000-loc));
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
  (fusion / WinSxS manifests). **Partially addressed
  (2026-07-30):** RT_MANIFEST resources are now parsed at
  PE load time (execution level, DPI awareness, SxS dependency
  names stored on `Process::manifest`). The runtime DLL
  resolution part (version-specific WinSxS directory lookup)
  is still missing — manifests pointing to specific
  common-controls versions still resolve via the flat SxS
  directory rather than version-keyed paths.
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
- **PE manifest / SxS resolution** — **parsing landed
  (2026-07-30):** RT_MANIFEST is extracted and parsed at PE load
  time; execution level, DPI awareness, long-path-aware, and SxS
  dependency names stored on `Process::manifest`. Multi-version DLL
  resolution (version-keyed WinSxS directory lookup) is still
  missing; apps that depend on a specific common-controls manifest
  fall back silently to v5.

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

- **Job objects** — PARTIAL. The unnamed v0 create/assign/query/
  membership/terminate/close path is real; named/opened Jobs, security,
  configured limits, kill-on-close, nesting, and a verdict-bearing
  multi-process QEMU profile are still GAP.
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
  property/state queries are REAL. `GetMenu` / `SetMenu`
  (per-HWND HMENU store) and `GetSystemMenu` (synthesized +
  cached standard system menu) are now REAL; `DrawMenuBar`
  triggers a real window redraw but the compositor paints no
  non-client menu band yet (item glyphs unpainted — GAP).
  `LoadMenu` remains a stub (needs the `.rsrc` loader).
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

## 11b. i386 (PE32) companion DLL set

The kernel preloads a parallel set of i386 (PE32, Machine=0x014C,
OptHdrMagic=0x10B) DLLs into every PE32 process's address space.
They are companions to the 44 PE32+ (x86_64) DLLs listed in section
1; the file basenames inside the build tree differ
(`<dll>_32.dll` source, `<dll>.dll` output, set via
`/out:` basename so the Export Directory's Name field matches the
i386 importer's descriptor). Sources live in
`userland/libs/<dll>_32/`.

Today's i386 surface (532 exports, 13 DLLs) — counted from the
`.def` EXPORTS sections, not estimated:

| DLL          | Exports | Source                                |
|--------------|---------|---------------------------------------|
| kernel32     | 121     | `userland/libs/kernel32_32/`         |
| msvcrt       | 74      | `userland/libs/msvcrt_32/`           |
| user32       | 155     | `userland/libs/user32_32/`           |
| gdi32        | 46      | `userland/libs/gdi32_32/`            |
| advapi32     | 71      | `userland/libs/advapi32_32/`         |
| comctl32     | 5       | `userland/libs/comctl32_32/`         |
| comdlg32     | 1       | `userland/libs/comdlg32_32/`         |
| crypt32      | 10      | `userland/libs/crypt32_32/`          |
| iphlpapi     | 4       | `userland/libs/iphlpapi_32/`         |
| shell32      | 2       | `userland/libs/shell32_32/`          |
| shlwapi      | 1       | `userland/libs/shlwapi_32/`          |
| ws2_32       | 41      | `userland/libs/ws2_32_32/`           |
| bcrypt       | 1       | `userland/libs/bcrypt_32/`           |

The set was sized to cover NetSurf 3.11's 446-import surface; the
function-level audit lives in the git log entry for that slice.

Most exports are safe-ignore stubs. The non-trivial real
implementations:

- `ws2_32_32` drives the kernel socket pool via SYS_SOCKET_OP
  (the same path the PE32+ ws2_32 uses), so PE32 callers get
  real DNS / TCP. `htons` / `ntohs` / `htonl` / `ntohl` are
  real bit-swaps. `inet_addr` / `inet_ntoa` parse real dotted-
  quad strings.
- `kernel32_32` covers full process / thread / heap / time /
  module surface with real syscall trampolines for the
  syscall-backed entries (GetCurrentProcessId, GetTickCount,
  Sleep, etc.) and sentinel returns for the pseudo-handles.
  The static-MSVC-CRT startup path is now covered (added
  2026-06-17, driven by a real 32-bit PE32 application running
  to its CRT): `OutputDebugStringA` (→ debug sink),
  `GetVersionExA` (XP/NT), `Tls{Alloc,Free,GetValue,SetValue}`,
  `GetACP`/`GetOEMCP`/`GetCPInfo`/`IsValidCodePage`,
  `HeapCreate`/`HeapDestroy` (alias the process heap),
  `GetEnvironmentVariableA`, `GetModuleFileNameA`,
  `VirtualQuery` (synthetic MBI), `FlushInstructionCache`.
  Same slice fixed `GetModuleHandleA`, which had been wired to
  the wrong syscall (79 = SYS_WIN_SET_CURSOR instead of 172 =
  SYS_DLL_BASE_BY_NAME) and returned a garbage base — it now
  returns the real EXE/DLL image base, also fixing
  `GetModuleHandleW`/`LoadLibraryA`/`LoadLibraryW`. With this
  surface a static-CRT PE32 clears heap/TLS/locale/SEH-directory
  init and reaches its own application code.
- `kernel32_32` **heap / timing / module resolution were calling the
  wrong syscalls entirely** until 2026-07-26. Six literals across the
  32-bit and 64-bit kernel32 named one syscall in a comment and called
  another:

  | export | called | which is | now |
  |---|---|---|---|
  | `Sleep` | 11 | `SYS_HEAP_ALLOC` | `SYS_SLEEP_MS` 19 |
  | `GetTickCount` | 70 | `SYS_WIN_GET_RECT` | `SYS_PERF_COUNTER` 13 |
  | `HeapAlloc` | 71 | `SYS_WIN_SET_TEXT` | `SYS_HEAPEX_ALLOC` 194 |
  | `HeapFree` | 72 | `SYS_WIN_TIMER_SET` | `SYS_HEAPEX_FREE` 195 |
  | `GetProcAddress` | 80 | `SYS_WIN_SET_CAPTURE` | `SYS_DLL_PROC_ADDRESS` 57 |
  | `CreateWaitableTimerW` (64-bit) | 33 | `SYS_EVENT_WAIT` | `SYS_EVENT_CREATE` 30 |

  None failed loudly — `Sleep` returned instantly while leaking an
  `ms`-byte allocation per call, `GetTickCount` returned a status flag
  rather than a time, and `GetProcAddress` returned a captured-window
  handle cast to `FARPROC`. `GetProcessHeap` also returned a made-up
  `0x12340000` sentinel that `Win32HeapResolveHandle` rejects; it
  returns `0x50000000` now, matching the 64-bit sibling. The heap uses
  the handle-aware **HEAPEX** family (194-197), not the legacy
  `SYS_HEAP_ALLOC`/`FREE` pair, because only HEAPEX carries the heap
  handle the static MSVC CRT allocates through. `HeapSize` (was a
  hardcoded 0) and `HeapReAlloc` (allocated fresh and **did not copy**,
  silently losing data on every CRT realloc) are real now too.

  Guarded by the `win32_syscall_numbers` hosted CTest — see below.
- `kernel32_32` **file I/O is REAL** (added 2026-07-26, the next
  rung after CRT startup — an application that reaches its own
  code opens its own data files). `userland/libs/kernel32_32/`
  `kernel32_32_fs.c` translates `CreateFileA`/`CreateFileW`
  (SYS_FILE_OPEN 20 / SYS_FILE_CREATE 44), `ReadFile` (21),
  `SetFilePointer` (23), `GetFileSize`/`GetFileSizeEx` (24) and
  `GetFileAttributesA`/`W` (SYS_FILE_QUERY_ATTRIBUTES 151) onto the
  same cap-gated syscalls the 64-bit `kernel32_io.c` uses;
  `WriteFile` routes opaque kernel file handles (low tag 0x100..0x10F,
  generation bits 12..30) to
  SYS_FILE_WRITE (43) and `GetFileType` reports FILE_TYPE_DISK for
  them. `CreateFile*` honours `dwCreationDisposition` against the
  two primitives the kernel provides, which is more than the 64-bit
  `CreateFileW` does today (it ignores the disposition and always
  opens). Same slice fixed `CloseHandle`, which dispatched syscall
  4 — SYS_STAT, not SYS_CLOSE (there is no SYS_CLOSE) — so every
  close stat'ed a wild pointer, returned FALSE, and leaked the
  handle slot until process exit; it is SYS_FILE_CLOSE (22) now.
  Per-entry-point GAPs (truncation, 64-bit offsets, overlapped
  I/O, UTF-16 transcode) are listed below and marked in-source.
- `user32_32` and `gdi32_32` are **REAL** as of 2026-07-28 — the
  USER32 rung of the PE32 ladder. Before that slice, every export in
  both files returned a constant and **neither file issued a single
  syscall**: `RegisterClassA` discarded `lpfnWndProc` and returned a
  fake atom 1, `CreateWindowExA` returned NULL, and `GetMessageA`
  returned 0 forever. A PE32 that cleared CRT startup created no
  window, received no message, and spun quietly without ever
  faulting. A present-but-lying export is worse than a missing one:
  a missing import leaves a debuggable `[win32-32miss]` sentinel,
  this left silence.

  Both now drive the same ~40 `SYS_WIN_*` / `SYS_GDI_*` handlers
  (58..100, 65-68/74-76) their 64-bit siblings do. `user32_32` splits
  across `user32_32.c` (class table, window lifecycle, message pump,
  long slots) and `user32_32_misc.c` (geometry, paint, focus, input,
  caret, clipboard, timers); `gdi32_32` gained the objects and draw
  calls. What is real: class registration storing a live WNDPROC,
  window create/destroy/show/move, the full pump (Get / Peek / Post /
  Dispatch / Send / PostQuitMessage), per-window long slots,
  invalidate/validate + BeginPaint/EndPaint, rects and metrics from
  the compositor, focus/activation, key state, cursor, capture,
  timers, clipboard, and the fill / frame / rect / ellipse / line /
  polyline / text / pixel primitives. The remaining STUBs — icon and
  cursor resources, memory DCs, bitmaps, blits, DIB sections, fonts,
  arcs, regions — are marked in-source and all trace to one missing
  thing: an off-screen surface the compositor's display list has no
  concept of.

  Three i386-specific traps this port had to get right, each a
  silent-corruption bug if missed:

  1. **`MSG` is 28 bytes on i386; the kernel's wire struct is 32.**
     `CopyMsgToUser` blind-writes all 32 bytes to whatever pointer it
     is handed, so passing the caller's real `MSG*` through misaligns
     every field AND scribbles 4 bytes past the end of the caller's
     struct. Both pump entrypoints pass a local wire buffer and
     repack. `pe32_window` plants a canary immediately after its MSG
     and re-checks it on every drain iteration.
  2. **`WNDCLASS` and `WNDCLASSEX` have different i386 offsets.** On
     x86_64 the prepended `cbSize` shares the first 8-byte slot with
     `style`, so `lpfnWndProc` lands at offset 8 in both and the
     64-bit `RegisterClassExW` can legitimately forward to
     `RegisterClassW`. With 4-byte pointers there is no such padding:
     `cbSize` shifts every subsequent field by 4. The 32-bit port
     carries two structs.
  3. **`FillRect`, `FrameRect`, `DrawText`, `GetDC` and `BeginPaint`
     are USER32 exports, not GDI32.** Windows splits the drawing
     surface across the two DLLs by history, not by layer, and an
     importer resolves against whichever DLL Windows homes the symbol
     in. `FillRect` living only in `gdi32_32` sent `pe32_window`'s
     import to the NO-OP catch-all. Both DLLs now speak the shared
     handle ABI in `userland/libs/common/duet32_gdi_abi.h` — one
     definition of the HDC / brush / pen encodings, because both
     sides mint AND consume them.

  The WndProc callback needs no kernel mechanism, despite what
  `window_syscall.cpp`'s file header used to claim: the kernel stores
  the pointer in the `GWLP_WNDPROC` long slot and hands it back, and
  `DispatchMessage` makes a plain in-process indirect call in ring 3.
  That stale comment is corrected.
- `advapi32_32`'s **registry family is REAL** as of 2026-07-28, and it
  is the first Win32 front-end to reach the kernel-owned registry
  instead of carrying its own tree. Before this slice the DLL shipped
  four registry exports and all four were constant-returners:
  `RegOpenKeyExA` always reported ERROR_FILE_NOT_FOUND,
  `RegQueryValueExA` always reported a zero-byte REG_NONE, and
  `RegEnumKeyExA` always reported ERROR_NO_MORE_ITEMS. A PE32 that
  keeps settings in the registry saw an empty, unwritable hive.

  All 28 `Reg*` entry points now drive **SYS_REGISTRY (130)** —
  open / close / flush, query / set / delete value, key enumeration,
  value enumeration, and `RegQueryInfoKey`, in both A and W flavours,
  plus the `RegGetValue` convenience wrapper. That is the kernel's
  mutable tree: values persist through the sidecar pool to
  `REGISTRY.HIV`, and every mutation is cap-gated on `kCapFsWrite`
  inside `DoSetValue` / `DoDeleteValue`, so a sandboxed PE32 gets
  ERROR_ACCESS_DENIED rather than a silent write.

  Note this deliberately does NOT follow the PE32+
  `userland/libs/advapi32/advapi32.c`, which carries a private static
  registry that `kernel/subsystems/win32/registry.cpp` is kept in sync
  with by hand. CLAUDE.md's "one source of truth per resource" rule
  and the kernel tree's extra capabilities (mutability, persistence,
  cap-gating) both argue for the syscall; growing a third copy of the
  tree would have been the wrong direction. Unifying the 64-bit
  sibling onto SYS_REGISTRY is the obvious follow-on.

  Three limits, all marked in-source:

  1. **The kernel stores REG_SZ as NARROW ASCII** (`kRegKeys` spells
     `"DuetOS\0"` as 7 bytes, not 14). The W entry points therefore
     transcode on both edges — wide in on set, wide out on query — so
     an A caller and a W caller each see their own encoding and the
     stored form stays uniform. Non-ASCII is lossy. The 64-bit
     `RegQueryValueExW` hands its narrow bytes straight to a W caller
     and does not do this.
  2. **No key creation or deletion.** `registry.h` states NtCreateKey /
     NtDeleteKey are unimplemented — only VALUES on existing keys are
     mutable. `RegCreateKeyEx` degrades to an open (reporting
     `REG_OPENED_EXISTING_KEY` when the well-known key exists) and
     otherwise fails with ERROR_ACCESS_DENIED rather than inventing a
     handle. An app writing values under an existing well-known key
     works end to end; one that wants its own new subkey does not.
  3. **Eight open keys per process** (`Process::kWin32RegistryCap`).
     A caller that closes what it opens is unaffected.

  An i386 codegen trap is pinned in the source and is worth knowing
  before touching any six-argument syscall site in a `_32` DLL: an
  `unsigned long long` local wants 8-byte alignment, the incoming
  `__stdcall` frame guarantees only 4, and clang realigns the stack —
  which pins EBP as a frame pointer. `duet_syscall6` needs EBP for
  arg6 once EAX/EBX/ECX/EDX/ESI/EDI are bound, so the whole TU fails
  to compile with "inline assembly requires more registers than
  available". Every u64 the kernel writes is staged as a pair of
  4-byte-aligned u32s instead; the kernel copies those slots with
  `CopyToUser`, which is a byte copy with no alignment expectation.
- `advapi32_32`'s **token / SID tier is a deliberate facade**, and the
  reasons are written into `advapi32_32_sec.c`'s header rather than
  left to be re-derived. One call touches real authority:
  `AdjustTokenPrivileges` hands the caller's TOKEN_PRIVILEGES blob
  verbatim to **SYS_TOKEN_ADJUST (169)**, which maps privilege LUIDs
  to caps and refuses to ADD a cap the process does not hold — so the
  only directions it can move authority are "no change" and "less".
  `LookupPrivilegeValue` is a real name-to-LUID table whose values are
  the same ones `token_syscall.cpp`'s `LuidLowToCap` switches on.
  (The PE32+ sibling's `AdjustTokenPrivileges` returns TRUE without
  calling anything, and its `LookupPrivilegeValueW` returns LUID 1 for
  every name; the 32-bit pair is the more honest of the two.)

  Everything that would REPORT authority answers in the direction that
  cannot be parlayed into any: `GetTokenInformation` reports not
  elevated / TokenElevationTypeDefault and fails outright on
  TokenIntegrityLevel, and `CheckTokenMembership` always reports not a
  member. `OpenProcessToken` / `OpenThreadToken` hand back the same
  `0x1000` sentinel the 64-bit sibling uses. The SID and ACL builders
  (`AllocateAndInitializeSid` from a bounded 8-slot pool, `FreeSid`,
  `GetLengthSid`, `IsValidSid`, `EqualSid`, `InitializeAcl`, …) are
  exact structure work on caller memory — nothing in DuetOS consumes a
  SID or an ACL to grant authority, so building one is a data
  operation, not a privilege operation. ETW (`EventRegister` /
  `EventWriteTransfer` / …) succeeds and drops every event; there is
  no trace sink.
- `user32_32` grew the **computation + window-query tier** in the same
  2026-07-28 batch (155 exports, up from 87). Real: the `Char*`
  family, the whole RECT algebra (`PtInRect`, `IntersectRect`,
  `UnionRect`, …), `GetSysColor` / `GetSysColorBrush`, `IsWindow`,
  `GetWindow` (→ SYS_WIN_GET_RELATED), `FindWindowA/W` (→
  SYS_WIN_FIND), `SetParent` (→ SYS_WIN_SET_PARENT),
  `MapWindowPoints`, and `SystemParametersInfo`'s SPI_GETWORKAREA.
  `CreateWindowEx` now installs the real parent link instead of
  discarding its `hWndParent`.

  `GetWindowText` / `GetClassName` / `GetDlgItem` are backed by a new
  per-window record table, because the compositor stores a title but
  exposes no read-back op and has no class concept at all. The table
  also records a child's control id — `CreateWindowEx`'s `hMenu`
  argument under WS_CHILD — which makes the **dialog ITEM surface
  real**: `GetDlgItem`, `SetDlgItemText`, `GetDlgItemText`,
  `SendDlgItemMessage`, `CheckDlgButton`, `IsDlgButtonChecked`,
  `CheckRadioButton`, `SetDlgItemInt`, `GetDlgItemInt`,
  `GetDlgCtrlID`. GAP: the records are per-process, so a title set by
  another process reads back empty.

  The dividing line for the dialog surface, stated once: **anything
  that needs a resource TEMPLATE is stubbed; anything that needs only
  a CONTROL ID is real.** `DialogBoxParam`, `CreateDialogParam`,
  `EndDialog` and `TranslateAccelerator` are STUBs returning the
  documented Win32 failure value, and `LoadStringW` / `LoadImageW` are
  **not exported at all** rather than faked. All of them block on the
  same missing thing — see the `.rsrc` note below.

  `EnableWindow` / `IsWindowEnabled` round-trip a per-window flag and
  fire WM_ENABLE, but the compositor does not consult it: a disabled
  window still receives input. Closing that needs an enabled bit in
  the kernel window record and a check in the input router.

  One ABI trap: `GetSysColorBrush` must NOT call
  SYS_GDI_GET_SYS_COLOR_BRUSH (128). That op returns a handle from the
  kernel's GDI object table, which is what the PE32+ `gdi32` consumes;
  the i386 pair uses the self-describing encoding in
  `userland/libs/common/duet32_gdi_abi.h`, where a brush IS its
  colour. Handing an i386 caller a kernel-table handle would make
  `FillRect` decode a garbage colour. The brush is minted locally from
  the palette colour returned by SYS_GDI_GET_SYS_COLOR (127).
- **No PE resource (`.rsrc`) parser exists anywhere in the tree** —
  nothing under `kernel/loader/` or `userland/libs/` walks
  `IMAGE_DIRECTORY_ENTRY_RESOURCE`. That single gap blocks, across
  both the 32- and 64-bit surfaces: `LoadStringW` (the single
  highest-demand user32 import measured across SysWOW64 binaries),
  `LoadImageW`, `LoadIcon` / `LoadCursor` returning real pixels,
  `TranslateAccelerator`, and the entire template half of the dialog
  manager (`DialogBoxParam` / `CreateDialogParam`). The 64-bit
  `user32.c` fakes `LoadStringW` with a `"DuetOS"` placeholder behind
  a GAP marker; the 32-bit port does not, on the grounds that a
  present-but-lying export is worse than a missing one.

  The parser itself is tractable **entirely in user space** and needs
  no kernel change: `pe_loader.cpp` maps the PE headers read-only at
  ImageBase (`MapHeaders`) and maps every section, `.rsrc` included,
  so a DLL can walk DOS header → PE header → data directory[2] →
  `IMAGE_RESOURCE_DIRECTORY` with plain pointer arithmetic against a
  base it gets from `GetModuleHandle`. That is the next rung.
- `msvcrt_32` provides real string + memory intrinsics
  (memcpy / strlen / strcmp / etc.) and a bump-allocator
  malloc / free until the proper heap port lands.
- **The CRT-startup cluster and the sync / time / NLS surface landed
  2026-07-28**, sized off the measured demand across every 32-bit
  `.exe` under a stock `C:\Windows\SysWOW64` (count = distinct
  binaries importing a symbol the i386 set did not provide). The
  five heaviest are all CRT startup — `_except_handler4_common`,
  `_cexit`, `_XcptFilter`, `_controlfp` and `?terminate@@YAXXZ`, at
  ~228 importers each — and nothing 32-bit reaches `main()` without
  them. Because the kernel's flat Win32 thunk page is NOT mapped for
  PE32 images (`spawn.cpp` maps it for x86_64 only), the `_32` DLLs
  cannot alias a thunk; each of these is real code in the DLL.

  REAL (implements its contract):
  - `msvcrt_32`: `_cexit` / `_c_exit` walk a DLL-local LIFO atexit
    table that `_onexit` / `__dllonexit` / `atexit` register into
    (the x86_64 msvcrt thunk rows pin return-0, i.e. registration
    always fails, so `_cexit` had nothing to walk); `_lock` /
    `_unlock` are a 64-slot recursive TID-keyed spin lock;
    `?terminate@@YAXXZ` and `_purecall` abort; `_callnewh` reports
    "no new-handler"; `__wgetmainargs`; `_wcmdln`; `__iob_func`;
    `wcslen` / `wcschr` / `wcsrchr` / `_wcsicmp` / `_wcsnicmp` /
    `_ismbblead`; `memcpy_s` / `memmove_s` (including the
    zero-the-destination-on-violation half most reimplementations
    drop).
  - `kernel32_32`: `GetSystemTime` / `GetSystemTimeAsFileTime`;
    `QueryPerformanceCounter` / `QueryPerformanceFrequency`;
    `LocalAlloc` / `LocalFree`; the mutex / event / semaphore /
    wait set; real recursive `CRITICAL_SECTION` and `SRWLOCK`
    primitives (previously `Enter`/`LeaveCriticalSection` were
    no-ops); `CreateThread`; `MultiByteToWideChar` /
    `WideCharToMultiByte` / `CompareStringW`; `FindClose`;
    `GetModuleHandleEx{A,W}` / `GetModuleFileNameW` /
    `LoadLibraryEx{A,W}` / `OutputDebugStringW`.

  STUB (marked `// STUB:` in-tree, and deliberate — an import the
  loader cannot bind is wired to a stub that SYS_EXITs on first
  call, so a defined export that reports failure is what buys the
  caller its own error branch):
  - `msvcrt_32::_except_handler4_common` returns
    `ExceptionContinueSearch` with no SEH4 scope-table walk, no
    cookie validation and no filter / finally execution. MSVC emits
    the IAT slot in static data for every 32-bit image with a
    try/finally, so the symbol must exist whether or not an
    exception is ever raised — but a guest's `try/except` blocks do
    not run. Needs a kernel-side 32-bit exception dispatcher first.
  - `kernel32_32::RaiseException` terminates the process carrying
    the exception code because there is nothing to dispatch to. The
    x86_64 sibling no longer does this — it builds a real
    `EXCEPTION_RECORD` and enters ntdll's two-pass engine — but that
    engine is x64-shaped (an x64 `CONTEXT`, `.pdata` unwind tables,
    an x64 resume entry point). i386 SEH uses the `fs:[0]`
    registration chain instead, so none of it is reusable and the
    32-bit path stays blocked on its own dispatcher.
  - `kernel32_32::LoadResource` returns NULL — no PE
    resource-directory walker on the i386 path.

  GAP (correct on the happy path, documented limit):
  - `QueryPerformanceCounter` reports nanoseconds with a 1 GHz
    frequency, matching the x86_64 sibling, but the i386 syscall
    return path is 32 bits wide: `exceptions.S` hands a compat-mode
    caller back only `eax`, so `SYS_NOW_NS`'s 64-bit counter arrives
    truncated and wraps every ~4.295 s. `kernel32_32_qpc.h` rebuilds
    the high half in user space; the sequence is always monotonic
    and exact while the caller polls faster than the wrap period,
    but a process that lets more than ~4.295 s pass between two QPC
    calls under-reports by 4.295 s per missed wrap. Host-tested:
    `tests/host/test_kernel32_32_time.cpp`.
  - `GetSystemTimeAsFileTime` avoids the same truncation by NOT
    using `SYS_GETTIME_FT` (17), whose whole payload is in `rax`.
    It goes through `SYS_GETTIME_ST` (40) + `SYS_ST_TO_FT` (41),
    which move their payload through user pointers, so all 64 bits
    survive. This is the general rule for the i386 set: **a syscall
    that returns a 64-bit value in `rax` is unusable from PE32; use
    the out-pointer form or the value silently truncates.**
  - Named semaphores are process-local on i386.
    `SYS_NAMED_KOBJ_OPEN_OR_CREATE` (185) reads its `init` word as a
    u64 and the semaphore encoding packs `maximum` in the HIGH half;
    arg4 arrives zero-extended from `esi`, so a named semaphore
    created that way would have `max_count == 0` and reject every
    release. `CreateSemaphore*` therefore takes the unnamed
    `SYS_SEM_CREATE` (51) path plus a 16-entry process-local name
    table. Named mutexes and events (32-bit init words) do reach
    the kernel namespace and are shared across processes correctly.
  - `_controlfp` tracks the control word so the CRT's read-back is
    coherent but does not reprogram the x87 / SSE registers;
    `_XcptFilter` selects the caller's terminate path without
    running any unhandled-exception reporting; `HeapSetInformation`
    accepts and ignores the policy; `DebugBreak` is a no-op (no
    `int3` — the trap would be unhandled and kill the guest, which
    is also what the x86_64 thunk table chose);
    `WaitForSingleObjectEx` ignores `bAlertable` (no 32-bit
    `QueueUserAPC` exists to be alerted by); `_vsnwprintf` consumes
    but does not render `%f` / `%e` / `%g`.

  **i386 struct-layout hazard, stated for the whole `_32` set.**
  Every caller-owned Win32 lock struct is half the size on i386
  because its fields are pointer-sized: `CRITICAL_SECTION` is 24
  bytes (40 on x86_64), `SRWLOCK` and `INIT_ONCE` are 4 bytes (8 on
  x86_64). The x86_64 siblings keep their private bookkeeping in
  `long long` slots; copying that shape would write 8 bytes into a
  4-byte `SRWLOCK` and corrupt whatever the guest placed after it —
  compiling clean and surfacing later as a wild fault. Every slot in
  `kernel32_32_sync.c` is a 32-bit `int`. This is the same class as
  the `MSG` (28 vs 32) and `WNDCLASSEX` offset traps recorded for
  `user32_32` above.
- `shlwapi_32::PathAppendA` walks the path and appends a
  separator — the only non-stub in the rest of the surface.
- `advapi32_32::SystemFunction036` and `bcrypt_32::BCryptGenRandom`
  return LCG entropy so consumers see non-zero bytes.

Live verification: `userland/apps/pe32_rich/pe32_rich.c` imports
one or two functions from each i386 DLL and prints a per-DLL
`[pe32-rich] <name> ok` line. Every ring3 boot exercises the
full chain.

Most of those lines only prove the IAT resolved. The
`[pe32-rich] kernel32-fileio ok` line is the exception: it asserts
observable kernel state end-to-end against `/etc/version` — the
returned handle is in the Win32 handle band, `GetFileType` says
FILE_TYPE_DISK, a backwards `SetFilePointer(-4, FILE_END)` lands
where it claims (proved by the following short read, not by the
return value alone), a negative seek from FILE_BEGIN is rejected,
and a read on the closed handle fails, which is what pins the
`CloseHandle` fix. A failure emits
`[ring3-pe32-rich] FAIL kernel32-fileio` plus a `step=NN` line
naming the assertion, and the PE-compat verdict scanner counts it.

Static checks (both run on any host, no cross-toolchain needed, and
both are registered in hosted CTest):

`python3 tools/test/check-syscall-numbers.py` parses the syscall enum
and verifies every literal in `userland/libs` that NAMES the syscall it
means, plus every `SYS_FOO = N` assertion in those sources. Against the
pre-2026-07-26 tree it reports 10 errors covering 7 of the 8 known
historical instances; against the current tree, 0. It deliberately does
not flag bare `SYS_FOO` mentions — prose legitimately names wildcards
(`SYS_WIN_*`) and syscalls that do not exist yet by design — and it
checks the number, not the argument registers.

`python3 tools/test/check-dll-def-exports.py`
cross-checks every `userland/libs/*/*.def` against the definitions
beside it, so an export added without an implementation is caught on
any host, with no cross-toolchain installed. The focused
`kernel32_32_exports_complete` CTest also runs the reverse-direction
check in strict mode for the DLL changed here, catching an implementation
that never reaches its export table. Hosted unit tests for the i386
pure cores: `tests/host/test_kernel32_32_paths.cpp` (path /
seek-resolution), `tests/host/test_kernel32_32_time.cpp` (the QPC
wrap-epoch extension in `kernel32_32_qpc.h`) and
`tests/host/test_kernel32_32_nls.cpp` (the code-page / collation core
in `kernel32_32_nls.h`).

Both i386 companion builders (`tools/build/build-kernel32-32-dll.sh`,
`build-msvcrt-32-dll.sh`) now glob every `.c` in their directory
rather than enumerating two sources, matching the generic
`build-stub-32-dll.sh`. Adding a TU to either DLL needs no
build-system edit; before this, a new TU compiled nowhere and every
export it defined came back as an `lld-link` "undefined symbol". The
CMake `DEPENDS` lists are globbed with `CONFIGURE_DEPENDS` for the
same reason — an enumerated dependency list would let an incremental
build keep a stale DLL, which is a quieter failure than a link error.

What's still GAP for the i386 set:

- No 32-bit Win32 thunks page. Unresolved PE32 imports point at
  the 64-bit catch-all VA (kWin32ThunksVa = 0x60000000), which
  is **unmapped** in PE32 ASs — so the call faults visibly.
  Adequate as a "loud fail" v0; a real 32-bit thunks page lets
  PE32s survive their first unresolved import.
- No 32-bit TEB. PE32 callers that dereference `fs:[0x18]` (TEB
  self-pointer) / `fs:[0x30]` (PEB) fault — fs base is the
  hidden GDT descriptor base, currently zero for PE32 user
  data.
- 32-bit `_chkstk` / `__chkstk` / `_alloca_probe` are REAL —
  `userland/libs/msvcrt_32/chkstk.S` walks ESP page by page,
  probes each page, then adjusts ESP per MSVC's canonical
  i386 chkstk algorithm.
- `kernel32_32` file I/O is REAL (above); the remaining known
  limits, each carrying a `// GAP:` marker in
  `kernel32_32_fs.c`:
  - **No truncation primitive.** `CREATE_ALWAYS` and
    `TRUNCATE_EXISTING` open the existing file instead of zeroing
    it, so a caller rewriting a shorter payload sees the old
    tail. Needs a kernel `SYS_FILE_TRUNCATE` (or an O_TRUNC flag
    on SYS_FILE_OPEN); the 64-bit path has the same hole.
  - **Offsets limited to 0..INT_MAX.** The i386 `int $0x80`
    wrapper returns a signed `int`, so a cursor with bit 31 set is
    indistinguishable from negative errno. The argument registers also
    cannot carry a 64-bit distance, so
    `SetFilePointer` rejects a non-zero
    `lpDistanceToMoveHigh` with ERROR_INVALID_PARAMETER and
    returns the new position's high dword as 0.
    `GetFileSize`/`GetFileSizeEx` are unaffected — the size comes
    back through a caller-supplied u64 slot, not a register.
    First bites on the multi-GB bundled-data rung.
  - **No overlapped I/O.** `ReadFile` / `WriteFile` reject a
    non-NULL `lpOverlapped` rather than silently behaving
    synchronously; the 32-bit set has no IOCP surface.
  - **UTF-16 paths narrow by low byte**, so a `CreateFileW` with
    non-Latin-1 characters gets a mangled name and an honest
    miss. Same as the 64-bit `CreateFileW`.
  - **`GetFileAttributes*` is FAT32-only**, because the kernel
    routes SYS_FILE_QUERY_ATTRIBUTES through
    `fs::routing::StatPathForProcess`. A ramfs path returns
    INVALID_FILE_ATTRIBUTES even though `CreateFileA` opens it.
    Fixed kernel-side, not here; identical on 64-bit.
- `msvcrt_32`'s stdio (`fopen` / `fread` / …) is still stubbed —
  it has not been rebased onto the now-real `kernel32_32`
  file surface. That is the natural next 32-bit FS slice.

## 12. Where to start filling things in

If you're picking up this doc and want a task: scan the STUB
rows above for ones whose **callers exist on disk**. Today's
short list:

1. **`SymGetLineFromAddr64`** in dbghelp — would let
   `process_smoke` print real source-line crash dumps.
2. **`ws2_32!WSARecv` overlapped path** — needs the IOCP
   slice (see Roadmap "IOCP for sockets").
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
