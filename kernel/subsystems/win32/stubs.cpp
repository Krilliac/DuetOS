#include "stubs.h"

#include "../../arch/x86_64/serial.h"
#include "nt_syscall_table_generated.h"

namespace duetos::win32
{

namespace
{

// ---------------------------------------------------------------
// Stub bytecode.
//
// Each entry is a handful of raw x86-64 instructions, packed
// back-to-back. The layout is:
//
//   offset 0x00:  ExitProcess stub  (9 bytes)
//
// Future entries append at the current end. IAT slots point
// at (kWin32StubsVa + entry.offset), so stable offsets matter
// only within a single boot — we regenerate + re-map the page
// per process anyway, no persistence between runs.
//
// The assembly is hand-assembled rather than emitted from a
// .S file because (a) it's trivial, (b) a .S file would be
// position-dependent and we want to drop these bytes into a
// runtime-allocated frame, (c) a .S file would mean a second
// user-mode target in the build which is a premature
// abstraction for v0.
// ---------------------------------------------------------------

// Stub offsets. Kept as named constants so the table below
// stays readable and so two exports (WriteFile + WriteConsoleA)
// can alias to the same offset without duplicating the code.
constexpr u32 kOffExitProcess = 0x00;                    // batch 1 — 9 bytes
constexpr u32 kOffGetStdHandle = 0x09;                   // batch 1 — 3 bytes
constexpr u32 kOffWriteFile = 0x0C;                      // batch 1 — 44 bytes
constexpr u32 kOffGetCurrentProcess = 0x38;              // batch 2 — 8 bytes
constexpr u32 kOffGetCurrentThread = 0x40;               // batch 2 — 8 bytes
constexpr u32 kOffGetCurrentProcessId = 0x48;            // batch 2 — 8 bytes
constexpr u32 kOffGetCurrentThreadId = 0x50;             // batch 2 — 8 bytes
constexpr u32 kOffTerminateProcess = 0x58;               // batch 2 — 9 bytes
constexpr u32 kOffGetLastError = 0x61;                   // batch 3 — 8 bytes
constexpr u32 kOffSetLastError = 0x69;                   // batch 3 — 10 bytes
constexpr u32 kOffInitCritSec = 0x74;                    // batch 4 — 18 bytes
constexpr u32 kOffCritSecNop = 0x86;                     // batch 4 — 1 byte (ret)
constexpr u32 kOffMemmove = 0x87;                        // batch 5 — 45 bytes (memcpy aliases)
constexpr u32 kOffMemset = 0xB4;                         // batch 5 — 19 bytes
constexpr u32 kOffReturnZero = 0xC7;                     // batch 6 — 3 bytes  (shared "xor eax,eax; ret")
constexpr u32 kOffTerminate = 0xCA;                      // batch 6 — 11 bytes (SYS_EXIT(3))
constexpr u32 kOffInvalidParam = 0xD5;                   // batch 6 — 11 bytes (SYS_EXIT(0xC0000417))
constexpr u32 kOffStrcmp = 0xE0;                         // batch 7 — 29 bytes
constexpr u32 kOffStrlen = 0xFD;                         // batch 7 — 17 bytes
constexpr u32 kOffWcslen = 0x10E;                        // batch 7 — 22 bytes
constexpr u32 kOffStrchr = 0x124;                        // batch 7 — 23 bytes
constexpr u32 kOffStrcpy = 0x13B;                        // batch 7 — 23 bytes
constexpr u32 kOffReturnOne = 0x152;                     // batch 8 — 6 bytes (shared "mov eax, 1; ret")
constexpr u32 kOffHeapAlloc = 0x158;                     // batch 9 — 11 bytes
constexpr u32 kOffHeapFree = 0x163;                      // batch 9 — 16 bytes
constexpr u32 kOffGetProcessHeap = 0x173;                // batch 9 — 8 bytes
constexpr u32 kOffMalloc = 0x17B;                        // batch 9 — 11 bytes
constexpr u32 kOffFree = 0x186;                          // batch 9 — 11 bytes
constexpr u32 kOffCalloc = 0x191;                        // batch 9 — 35 bytes
constexpr u32 kOffOpenProcessToken = 0x1B4;              // batch 10 — 13 bytes
constexpr u32 kOffLookupPrivVal = 0x1C1;                 // batch 10 — 13 bytes
constexpr u32 kOffInitSListHead = 0x1CE;                 // batch 10 — 16 bytes
[[maybe_unused]] constexpr u32 kOffGetSysTimeFT = 0x1DE; // batch 10 — 8 bytes (superseded by kOffGetSysTimeFTReal)
constexpr u32 kOffOpenProcess = 0x1E6;                   // batch 10 — 4 bytes
constexpr u32 kOffGetExitCodeThread = 0x1EA;             // batch 10 — 12 bytes
[[maybe_unused]] constexpr u32 kOffQueryPerfCounter = 0x1F6; // batch 11 — 16 bytes (superseded by kOffQpcNs)
[[maybe_unused]] constexpr u32 kOffQueryPerfFreq = 0x206;    // batch 11 — 13 bytes (superseded by kOffQpfNs)
constexpr u32 kOffGetTickCount = 0x213;                      // batch 11 — 12 bytes (shared w/ GetTickCount64)
constexpr u32 kOffHeapSize = 0x21F;                          // batch 14 — 11 bytes
constexpr u32 kOffHeapRealloc = 0x22A;                       // batch 14 — 16 bytes
constexpr u32 kOffRealloc = 0x23A;                           // batch 14 — 16 bytes
constexpr u32 kOffMissLogger = 0x24A;                        // batch 15 — 41 bytes
constexpr u32 kOffPArgc = 0x273;                             // batch 16 —  6 bytes
constexpr u32 kOffPArgv = 0x279;                             // batch 16 —  6 bytes
constexpr u32 kOffPCommode = 0x27F;                          // batch 17 —  6 bytes
constexpr u32 kOffSputn = 0x285;                             // batch 18 — 19 bytes
constexpr u32 kOffReturnThis = 0x298;                        // batch 18 —  4 bytes
constexpr u32 kOffWiden = 0x29C;                             // batch 18 —  4 bytes
constexpr u32 kOffHresultEFail = 0x2A0;                      // batch 19 —  6 bytes
constexpr u32 kOffGetSysTimeFTReal = 0x2A6;                  // batch 20 — 13 bytes
constexpr u32 kOffQpcNs = 0x2B3;                             // batch 21 — 13 bytes
constexpr u32 kOffQpfNs = 0x2C0;                             // batch 21 — 10 bytes
constexpr u32 kOffSleep = 0x2CF;                             // batch 22 — 12 bytes (push/pop rdi)
constexpr u32 kOffSwitchToThread = 0x2DB;                    // batch 22 — 10 bytes
constexpr u32 kOffGetCmdLineW = 0x2E5;                       // batch 23 — 6 bytes
constexpr u32 kOffGetCmdLineA = 0x2EB;                       // batch 23 — 6 bytes
constexpr u32 kOffGetEnvBlockW = 0x2F1;                      // batch 23 — 6 bytes
constexpr u32 kOffCreateFileW = 0x2F7;                       // batch 24 — 59 bytes (UTF-16 strip + open)
constexpr u32 kOffReadFile = 0x332;                          // batch 24 — 46 bytes
constexpr u32 kOffCloseHandle = 0x360;                       // batch 24 — 15 bytes
constexpr u32 kOffSetFilePtrEx = 0x36F;                      // batch 24 — 38 bytes
constexpr u32 kOffGetFileSizeEx = 0x395;                     // batch 25 — 29 bytes
constexpr u32 kOffGetModuleHandleW = 0x3B2;                  // batch 25 — 17 bytes
constexpr u32 kOffCreateMutexW = 0x3C3;                      // batch 26 — 13 bytes
[[maybe_unused]] constexpr u32 kOffWaitForObj =
    0x3D0;                                       // batch 26 — 38 bytes (mutex-aware, reserved for direct WFMO inline)
constexpr u32 kOffReleaseMutex = 0x3F6;          // batch 26 — 24 bytes
constexpr u32 kOffWriteConsoleW = 0x40E;         // batch 27 — 96 bytes (UTF-16 strip + SYS_WRITE)
constexpr u32 kOffGetConsoleMode = 0x46E;        // batch 27 — 12 bytes
constexpr u32 kOffGetConsoleCP = 0x47A;          // batch 27 — 6 bytes
constexpr u32 kOffVirtualAlloc = 0x480;          // batch 28 — 13 bytes
constexpr u32 kOffVirtualFree = 0x48D;           // batch 28 — 29 bytes
constexpr u32 kOffVirtualProtect = 0x4AA;        // batch 28 — 18 bytes
constexpr u32 kOffLstrlenW = 0x4BC;              // batch 29 — 15 bytes
constexpr u32 kOffLstrcmpW = 0x4CB;              // batch 29 — 37 bytes
constexpr u32 kOffLstrcpyW = 0x4F0;              // batch 29 — 27 bytes
constexpr u32 kOffIsWow64 = 0x50B;               // batch 30 — 17 bytes
constexpr u32 kOffGetVersionExW = 0x51C;         // batch 30 — 34 bytes
constexpr u32 kOffLstrlenA = 0x53E;              // batch 31 — 14 bytes
constexpr u32 kOffLstrcmpA = 0x54C;              // batch 31 — 37 bytes
constexpr u32 kOffLstrcpyA = 0x571;              // batch 31 — 26 bytes
constexpr u32 kOffGetModFileNameW = 0x58B;       // batch 32 — 24 bytes
constexpr u32 kOffGetCurrentDirW = 0x5A3;        // batch 32 — 31 bytes
constexpr u32 kOffMBtoWC = 0x5C2;                // batch 33 — 49 bytes
constexpr u32 kOffWCtoMB = 0x5F3;                // batch 33 — 48 bytes
constexpr u32 kOffGetUserNameW = 0x623;          // batch 34 — 47 bytes
constexpr u32 kOffGetComputerNameW = 0x652;      // batch 34 — 61 bytes
constexpr u32 kOffGetWinDirW = 0x68F;            // batch 35 — 30 bytes (buf-first sig)
constexpr u32 kOffGetLogicalDrives = 0x6AD;      // batch 36 — 6 bytes (returns 0x00800000, X: drive)
constexpr u32 kOffGetDriveType = 0x6B3;          // batch 36 — 6 bytes (returns 3 = DRIVE_FIXED)
constexpr u32 kOffReturnTwo = 0x6B9;             // batch 37 — 6 bytes (ERROR_FILE_NOT_FOUND / stream pos)
constexpr u32 kOffReturnMinus1 = 0x6BF;          // batch 37 — 6 bytes (INVALID_FILE_ATTRIBUTES)
constexpr u32 kOffReturnPrioNormal = 0x6C5;      // batch 39 — 6 bytes (0x20 = NORMAL_PRIORITY_CLASS)
constexpr u32 kOffInterlockedInc = 0x6CB;        // batch 40 — 12 bytes
constexpr u32 kOffInterlockedDec = 0x6D7;        // batch 40 — 12 bytes
constexpr u32 kOffInterlockedCmpXchg = 0x6E3;    // batch 40 —  8 bytes
constexpr u32 kOffInterlockedExchg = 0x6EB;      // batch 40 —  5 bytes
constexpr u32 kOffInterlockedExchgAdd = 0x6F0;   // batch 40 —  7 bytes
constexpr u32 kOffInterlockedInc64 = 0x6F7;      // batch 41 — 14 bytes
constexpr u32 kOffInterlockedDec64 = 0x705;      // batch 41 — 16 bytes
constexpr u32 kOffInterlockedCmpXchg64 = 0x715;  // batch 41 —  9 bytes
constexpr u32 kOffInterlockedExchg64 = 0x71E;    // batch 41 —  7 bytes
constexpr u32 kOffInterlockedExchgAdd64 = 0x725; // batch 41 —  9 bytes
constexpr u32 kOffReturnStatusNotImpl = 0x72E;   // batch 42 —  6 bytes (STATUS_NOT_IMPLEMENTED)
constexpr u32 kOffCreateEventReal = 0x734;       // batch 45 — 18 bytes (real event-backed)
constexpr u32 kOffSetEventReal = 0x746;          // batch 45 — 15 bytes
constexpr u32 kOffResetEventReal = 0x755;        // batch 45 — 15 bytes
// NOTE: kOffWaitForObj2 is retired as of batch 54. All imports
// now route through kOffWaitForObj3 which adds the semaphore
// range. The v2 bytes remain inside kStubsBytes (dead code) for
// a future slice that wants to diff the two; unused constant is
// marked [[maybe_unused]] to suppress the warning.
[[maybe_unused]] constexpr u32 kOffWaitForObj2 = 0x764; // batch 45 — 66 bytes (mutex+event-aware)
constexpr u32 kOffTlsAllocReal = 0x7A6;                 // batch 46 —  8 bytes
constexpr u32 kOffTlsFreeReal = 0x7AE;                  // batch 46 — 24 bytes
constexpr u32 kOffTlsGetValueReal = 0x7C6;              // batch 46 — 13 bytes
constexpr u32 kOffTlsSetValueReal = 0x7D3;              // batch 46 — 20 bytes
constexpr u32 kOffNtAllocateVirtualMemory = 0x7E7;      // batch 47 — 36 bytes
constexpr u32 kOffNtFreeVirtualMemory = 0x80B;          // batch 47 — 33 bytes
constexpr u32 kOffGetSystemTimeSt = 0x82C;              // batch 48 — 11 bytes
constexpr u32 kOffSystemTimeToFileTime = 0x837;         // batch 48 — 14 bytes
constexpr u32 kOffFileTimeToSystemTime = 0x845;         // batch 48 — 14 bytes
constexpr u32 kOffNtQuerySystemTimeReal = 0x853;        // batch 49 — 16 bytes
constexpr u32 kOffNtQueryPerfCounterReal = 0x863;       // batch 49 — 28 bytes
constexpr u32 kOffCreateThreadReal = 0x87F;             // batch 50 — 39 bytes (saves rdi+rsi)
// ThreadExitTramp: offset 0x8A6, 6 bytes. Public VA exported as
// duetos::win32::kWin32ThreadExitTrampVa in stubs.h — keep in sync.

// === Batch 51: ExitThread + OutputDebugStringA + GetProcessTimes
// + GetThreadTimes + GetSystemTimes + GlobalMemoryStatusEx +
// WaitForMultipleObjects.
constexpr u32 kOffExitThread = 0x8AC;             // batch 51 — 9 bytes (noreturn, no save)
constexpr u32 kOffOutputDebugStringA = 0x8B5;     // batch 51 — 13 bytes (saves rdi)
constexpr u32 kOffGetProcessTimes = 0x8C2;        // batch 51 — 44 bytes (also GetThreadTimes)
constexpr u32 kOffGetSystemTimes = 0x8EE;         // batch 51 — 30 bytes
constexpr u32 kOffGlobalMemoryStatusEx = 0x90C;   // batch 51 — 16 bytes (saves rdi)
constexpr u32 kOffWaitForMultipleObjects = 0x91C; // batch 51 — 24 bytes (saves rdi+rsi)

// === Batch 52: GetSystemInfo / OutputDebugStringW / FormatMessageA /
// GetConsoleScreenBufferInfo.
constexpr u32 kOffGetSystemInfo = 0x934;              // batch 52 — 13 bytes (saves rdi)
constexpr u32 kOffOutputDebugStringW = 0x941;         // batch 52 — 13 bytes (saves rdi)
constexpr u32 kOffFormatMessageA = 0x94E;             // batch 52 — 32 bytes
constexpr u32 kOffGetConsoleScreenBufferInfo = 0x96E; // batch 52 — 54 bytes

// === Batch 53: RaiseException / DecodePointer / EncodePointer.
constexpr u32 kOffRaiseException = 0x9A4; // batch 53 — 9 bytes (noreturn)
constexpr u32 kOffDecodePointer = 0x9AD;  // batch 53 — 4 bytes (identity)

// === Batch 54: Semaphore family + upgraded WaitForSingleObject v3.
constexpr u32 kOffCreateSemaphoreW = 0x9B1;             // batch 54 — 27 bytes (saves rdi+rsi)
constexpr u32 kOffReleaseSemaphore = 0x9CC;             // batch 54 — 29 bytes (saves rdi+rsi)
[[maybe_unused]] constexpr u32 kOffWaitForObj3 = 0x9E9; // batch 54 — 94 bytes
                                                        // Retired in batch 57 — see kOffWaitForObj4.

// === Batch 57: real thread-handle wait + 4-range WaitForSingleObject v4.
constexpr u32 kOffWaitForObj4 = 0xA47; // batch 57 — 122 bytes
                                       // (v3 + thread range 0x400..0x407 → SYS_THREAD_WAIT)

// === Batch 58: real GetStartupInfo stub.
constexpr u32 kOffGetStartupInfo = 0xAC1; // batch 58 — 24 bytes (zero-fill + cb=104)

// === Batch 59: real GetExitCodeThread (exit-code tracking).
constexpr u32 kOffGetExitCodeThreadReal = 0xAD9; // batch 59 — 20 bytes (saves rdi)

// === Batch 60: Interlocked{And,Or,Xor} (+64-bit). LOCK CMPXCHG
// loops so SMP future-proofing + timer-tick preemption safety
// hold today.
constexpr u32 kOffInterlockedAnd = 0xAED;   // batch 60 — 16 bytes
constexpr u32 kOffInterlockedOr = 0xAFD;    // batch 60 — 16 bytes
constexpr u32 kOffInterlockedXor = 0xB0D;   // batch 60 — 16 bytes
constexpr u32 kOffInterlockedAnd64 = 0xB1D; // batch 60 — 17 bytes
constexpr u32 kOffInterlockedOr64 = 0xB2E;  // batch 60 — 17 bytes
constexpr u32 kOffInterlockedXor64 = 0xB3F; // batch 60 — 17 bytes

// === Batch 61: real critical sections ======================
// Until now EnterCriticalSection / LeaveCriticalSection were
// single-byte `ret`s — safe while each process ran single-threaded,
// but with SYS_THREAD_CREATE live every call is a latent race.
// These stubs lay an owner-TID + recursion-count lock over the
// existing 40-byte CRITICAL_SECTION struct (InitializeCriticalSection
// already zero-fills it). The acquire uses `lock cmpxchg`; on
// contention we SYS_YIELD and retry.
constexpr u32 kOffEnterCritSecReal = 0xB50; // batch 61 — 49 bytes
constexpr u32 kOffLeaveCritSecReal = 0xB81; // batch 61 — 14 bytes

// === Batch 62: real SRWLOCKs (exclusive-only; shared aliases to exclusive) ===
// Win32 SRWLOCK is a single pointer-sized (8 byte) word. Layout
// we impose: [rcx+0] u64 owner_tid (0 = unheld). Acquire/release
// is a straight `lock cmpxchg` on the slot; shared operations
// degrade to exclusive because we don't track reader counts yet.
// That's suboptimal for reader-heavy workloads but preserves
// correctness — the prior binding (NO-OP for shared) allowed
// readers to observe mid-write state.
constexpr u32 kOffSrwInit = 0xB8F;           // batch 62 — 6 bytes
constexpr u32 kOffSrwAcquireExcl = 0xB95;    // batch 62 — 30 bytes
constexpr u32 kOffSrwReleaseExcl = 0xBB3;    // batch 62 — 6 bytes
constexpr u32 kOffSrwTryAcquireExcl = 0xBB9; // batch 62 — 22 bytes

// === Batch 63: correctness fixes for two always-returning stubs ===
// RtlTryEnterCriticalSection was bound to kOffReturnOne (always
// "got it"), which actively lied to callers — a genuinely held
// lock was reported as free and the caller proceeded into a
// mid-write region. IsProcessorFeaturePresent was bound to
// kOffReturnZero (always "not present"), forcing programs onto
// scalar fallback paths when the real CPU has SSE2/AVX/etc.
// Only TryEnter needs new bytecode; the other fix is a rebind
// to the existing kOffReturnOne.
constexpr u32 kOffTryEnterCritSecReal = 0xBCF; // batch 63 — 56 bytes

// === Batch 64: real SetUnhandledExceptionFilter round-trip ===
// The old bindings were kOffReturnZero for both — SetUnhandled
// always claimed "no previous filter" and UnhandledException
// always returned 0 (EXCEPTION_CONTINUE_SEARCH), which is the
// wrong default. Now we stash the caller-supplied filter in a
// per-process proc-env slot (kProcEnvUnhandledFilterOff) and
// tail-call it on invocation; if the slot is zero we return
// EXCEPTION_EXECUTE_HANDLER (1) — the Windows-default when no
// top-level filter was ever installed.
constexpr u32 kOffSetUnhandledFilter = 0xC07; // batch 64 — 12 bytes
constexpr u32 kOffUnhandledFilter = 0xC13;    // batch 64 — 21 bytes

// === Batch 65: real InitOnce (thread-safe lazy init) =========
// InitOnceInitialize just zero-fills an 8-byte slot; we reuse
// kOffSrwInit for it. InitOnceExecuteOnce does the actual
// call-once state machine: CAS 0->1 picks the initialiser,
// CAS-losers wait for the slot to reach 2 via SYS_YIELD spin.
constexpr u32 kOffInitOnceExec = 0xC28; // batch 65 — 87 bytes

// === Stage-2 slice 4: real GetProcAddress via SYS_DLL_PROC_ADDRESS =======
// Win32: FARPROC GetProcAddress(HMODULE hModule=rcx, LPCSTR lpProcName=rdx).
// DuetOS: SYS_DLL_PROC_ADDRESS (57) with rdi=hmod, rsi=name.
// Returns exported VA or 0 (= miss). rdi + rsi are callee-saved in
// the Win32 x64 ABI, so save/restore across the syscall.
constexpr u32 kOffGetProcAddressReal = 0xC7F; // stage-2 slice 4 — 18 bytes

// Render/drivers: D3D11 / D3D12 / DXGI IAT landing pads. Each stub
// issues SYS_GFX_D3D_STUB (101) with a per-kind `rdi` — the kernel
// syscall handler routes to `subsystems::graphics::D3D*CreateStub`
// so the graphics ICD's handle-table counters tick. Returned rax
// is HRESULT E_FAIL (0x80004005). 13 bytes each.
constexpr u32 kOffD3d11CreateStub = 0xC91; // render/drivers — 13 bytes
constexpr u32 kOffD3d12CreateStub = 0xC9E; // render/drivers — 13 bytes
constexpr u32 kOffDxgiCreateStub = 0xCAB;  // render/drivers — 13 bytes

// Paint lifecycle + FillRect — real implementations routing through
// dedicated syscalls. See core/syscall.h for the per-syscall ABI.
constexpr u32 kOffWinBeginPaint = 0xCB8;     // render/drivers — 14 bytes
constexpr u32 kOffWinEndPaint = 0xCC6;       // render/drivers — 11 bytes
constexpr u32 kOffWinInvalidateRect = 0xCD1; // render/drivers — 14 bytes
constexpr u32 kOffWinUpdateWindow = 0xCDF;   // render/drivers — 13 bytes
constexpr u32 kOffWinGetDC = 0xCEC;          // render/drivers —  4 bytes
constexpr u32 kOffWinReleaseDC = 0xCF0;      // render/drivers —  6 bytes
constexpr u32 kOffGdiFillRectUser = 0xCF6;   // render/drivers — 17 bytes
constexpr u32 kOffGdiTextOutA = 0xD07;       // render/drivers — 31 bytes

// GDI object handle table — real handle-returning stubs.
constexpr u32 kOffGdiCreateCompatDC = 0xD26;   // render/drivers — 11 bytes
constexpr u32 kOffGdiCreateCompatBmp = 0xD31;  // render/drivers — 17 bytes
constexpr u32 kOffGdiCreateSolidBrush = 0xD42; // render/drivers — 11 bytes
constexpr u32 kOffGdiGetStockObject = 0xD4D;   // render/drivers — 11 bytes
constexpr u32 kOffGdiSelectObject = 0xD58;     // render/drivers — 14 bytes
constexpr u32 kOffGdiDeleteDC = 0xD66;         // render/drivers — 11 bytes
constexpr u32 kOffGdiDeleteObject = 0xD71;     // render/drivers — 11 bytes
constexpr u32 kOffGdiBitBltDC = 0xD7C;         // render/drivers — 103 bytes

constexpr u8 kStubsBytes[] = {
    // --- ExitProcess (offset 0x00, 9 bytes) --------------------
    // Windows x64 ABI: first arg (uExitCode) in RCX.
    // DuetOS native ABI: syscall # in RAX, first arg in RDI,
    // SYS_EXIT = 0.
    0x48, 0x89, 0xCF, // 0x00 mov rdi, rcx      ; code
    0x31, 0xC0,       // 0x03 xor eax, eax      ; rax = 0 = SYS_EXIT
    0xCD, 0x80,       // 0x05 int 0x80
    0x0F, 0x0B,       // 0x07 ud2               ; [[noreturn]]

    // --- GetStdHandle (offset 0x09, 3 bytes) -------------------
    // Win32: HANDLE GetStdHandle(DWORD nStdHandle).
    // nStdHandle is STD_INPUT_HANDLE (-10), STD_OUTPUT_HANDLE
    // (-11), or STD_ERROR_HANDLE (-12), each represented as
    // the low 32 bits of a DWORD (e.g. 0xFFFFFFF5).
    //
    // v0 semantic: pass the DWORD through as the HANDLE. The
    // downstream WriteFile stub ignores the handle and always
    // routes to SYS_WRITE(fd=1). This is correct for any
    // program whose only use of GetStdHandle is to pass the
    // result to WriteFile / WriteConsoleA — which is every
    // console "hello world" we care about.
    //
    // `mov eax, ecx` zero-extends ecx into rax (x86-64 32-bit
    // op clears upper 32 bits), so STD_OUTPUT_HANDLE's
    // 0xFFFFFFF5 becomes 0x00000000FFFFFFF5 as a HANDLE.
    0x89, 0xC8, // 0x09 mov eax, ecx
    0xC3,       // 0x0B ret

    // --- WriteFile / WriteConsoleA (offset 0x0C, 44 bytes) -----
    // Win32 signatures (identical shape, that's why we alias):
    //   BOOL WriteFile(HANDLE hFile,        rcx
    //                  LPCVOID lpBuffer,    rdx
    //                  DWORD nBytes,        r8
    //                  LPDWORD lpWritten,   r9
    //                  LPOVERLAPPED ovl);   [rsp+0x28]
    //   BOOL WriteConsoleA(HANDLE hConsoleOutput, rcx
    //                      LPCVOID lpBuffer,      rdx
    //                      DWORD nChars,          r8
    //                      LPDWORD lpCharsOut,    r9
    //                      LPVOID lpReserved);    [rsp+0x28]
    //
    // v0 semantic: ignore the handle + the trailing reserved/
    // overlapped arg, issue SYS_WRITE(1, buf, n), and store
    // the result count back into *lpWritten (clamped to 0 on
    // syscall error). Return BOOL = (rax >= 0).
    //
    // Win64 ABI fix: rdi + rsi are callee-saved. Original stub
    // wrote `mov edi, 1` / `mov rsi, rdx` directly — clobbered
    // the caller's values. Now saved + restored via push/pop.
    // `mov eax, 2` + `mov edi, 1` each compress to push-imm8 +
    // pop-reg (3 bytes instead of 5), freeing 4 bytes to cover
    // the 4-byte push/pop rdi+rsi cost. Stub stays at 44 bytes.
    //
    // int 0x80 preserves all registers except RAX, so r9 (the
    // lpWritten pointer) survives the syscall and we can use
    // it to store the output count without saving.
    0x56,             // 0x0C push rsi
    0x57,             // 0x0D push rdi
    0x48, 0x89, 0xD6, // 0x0E mov rsi, rdx         ; buf
    0x4C, 0x89, 0xC2, // 0x11 mov rdx, r8          ; n
    0x6A, 0x01,       // 0x14 push 1
    0x5F,             // 0x16 pop rdi              ; fd = 1 (stdout)
    0x6A, 0x02,       // 0x17 push 2
    0x58,             // 0x19 pop rax              ; SYS_WRITE
    0xCD, 0x80,       // 0x1A int 0x80             ; rax = n or -1

    // If lpWritten (r9) != NULL, store max(rax, 0) as DWORD.
    0x4D, 0x85, 0xC9, // 0x1C test r9, r9
    0x74, 0x0B,       // 0x1F je +0x0B -> 0x2C
    0x31, 0xC9,       // 0x21 xor ecx, ecx
    0x48, 0x85, 0xC0, // 0x23 test rax, rax
    0x0F, 0x49, 0xC8, // 0x26 cmovns ecx, eax  ; ecx = rax if rax>=0, else 0
    0x41, 0x89, 0x09, // 0x29 mov [r9], ecx

    // BOOL return: 1 if rax >= 0, else 0. Restore rdi + rsi
    // (Win64 callee-saved) before returning.
    0x48, 0x85, 0xC0, // 0x2C test rax, rax
    0x0F, 0x99, 0xC0, // 0x2F setns al
    0x0F, 0xB6, 0xC0, // 0x32 movzx eax, al
    0x5F,             // 0x35 pop rdi
    0x5E,             // 0x36 pop rsi
    0xC3,             // 0x37 ret

    // === Batch 2: process/thread lifecycle ====================

    // --- GetCurrentProcess (offset 0x38, 8 bytes) --------------
    // Win32: HANDLE GetCurrentProcess(void). Returns the
    // pseudo-handle (HANDLE)(-1) = 0xFFFFFFFFFFFFFFFF. Any
    // function that receives this value treats it as "the
    // current process" without going through the real handle
    // table. Mirrors the literal Windows behavior — OpenProcess
    // on this pseudo-handle never opens anything.
    0x48, 0xC7, 0xC0, 0xFF, 0xFF, 0xFF, 0xFF, // 0x38 mov rax, -1
    0xC3,                                     // 0x3F ret

    // --- GetCurrentThread (offset 0x40, 8 bytes) ---------------
    // Win32: HANDLE GetCurrentThread(void). Pseudo-handle
    // (HANDLE)(-2) = 0xFFFFFFFFFFFFFFFE.
    0x48, 0xC7, 0xC0, 0xFE, 0xFF, 0xFF, 0xFF, // 0x40 mov rax, -2
    0xC3,                                     // 0x47 ret

    // --- GetCurrentProcessId (offset 0x48, 8 bytes) ------------
    // Win32: DWORD GetCurrentProcessId(void). Maps to
    // SYS_GETPROCID = 8 which returns CurrentProcess()->pid.
    // Return value in rax (low 32 bits → DWORD).
    0xB8, 0x08, 0x00, 0x00, 0x00, // 0x48 mov eax, 8 (SYS_GETPROCID)
    0xCD, 0x80,                   // 0x4D int 0x80
    0xC3,                         // 0x4F ret

    // --- GetCurrentThreadId (offset 0x50, 8 bytes) -------------
    // Win32: DWORD GetCurrentThreadId(void). Maps to
    // SYS_GETPID = 1 which returns the scheduler task id.
    // Distinct value from the process id — the kernel log's
    // `[sched] created task id=N` is this value.
    0xB8, 0x01, 0x00, 0x00, 0x00, // 0x50 mov eax, 1 (SYS_GETPID)
    0xCD, 0x80,                   // 0x55 int 0x80
    0xC3,                         // 0x57 ret

    // --- TerminateProcess (offset 0x58, 9 bytes) ---------------
    // Win32: BOOL TerminateProcess(HANDLE hProcess, UINT
    // uExitCode). The hProcess arg (rcx) is ignored in v0 —
    // we always terminate the calling process. Real Windows
    // would walk the handle table and kill the target; for
    // our single-process model this reduces to ExitProcess
    // with the exit code coming from rdx instead of rcx.
    //
    // Bytes identical in shape to ExitProcess but with rdx
    // as the source register for the exit code.
    0x48, 0x89, 0xD7, // 0x58 mov rdi, rdx          ; code
    0x31, 0xC0,       // 0x5B xor eax, eax          ; SYS_EXIT
    0xCD, 0x80,       // 0x5D int 0x80
    0x0F, 0x0B,       // 0x5F ud2                   ; [[noreturn]]

    // === Batch 3: last-error slot =============================

    // --- GetLastError (offset 0x61, 8 bytes) -------------------
    // Win32: DWORD GetLastError(void). Returns
    // Process.win32_last_error via SYS_GETLASTERROR = 9.
    0xB8, 0x09, 0x00, 0x00, 0x00, // 0x61 mov eax, 9 (SYS_GETLASTERROR)
    0xCD, 0x80,                   // 0x66 int 0x80
    0xC3,                         // 0x68 ret

    // --- SetLastError (offset 0x69, 11 bytes) ------------------
    // Win32: void SetLastError(DWORD dwErrCode). Forwards
    // the code to SYS_SETLASTERROR = 10 via rdi. No return
    // value to massage — the Win32 prototype is void, so
    // whatever the syscall leaves in rax is fine.
    //
    // Win64 ABI fix: save/restore rdi. `push 10; pop rax`
    // (3 bytes) replaces `mov eax, 10` (5 bytes) to free the
    // 2 bytes needed for push rdi / pop rdi.
    0x57,             // 0x69 push rdi
    0x48, 0x89, 0xCF, // 0x6A mov rdi, rcx
    0x6A, 0x0A,       // 0x6D push 10
    0x58,             // 0x6F pop rax
    0xCD, 0x80,       // 0x70 int 0x80
    0x5F,             // 0x72 pop rdi
    0xC3,             // 0x73 ret

    // === Batch 4: critical sections (v0 no-ops) ===============

    // --- InitializeCriticalSection (offset 0x74, 18 bytes) -----
    // Aliased by InitializeCriticalSectionEx and
    // InitializeCriticalSectionAndSpinCount. Zero out the
    // 40-byte CRITICAL_SECTION at [rcx], return BOOL TRUE.
    //
    // v0 is single-task per process, so a critical section
    // with no recursion tracking, no owning-thread check, and
    // no semaphore is semantically correct — there's nothing
    // to serialize against. A future slice will replace this
    // when a multi-threading model lands.
    //
    // Assumes DF=0 on entry (Win64 ABI contract). Uses rdi
    // (scratch in SysV, but CALLEE-SAVED in Win64 — push/pop
    // rdi around the rep stosb so the caller's rdi survives).
    // `mov ecx, 40` compresses to `push 40; pop rcx` to free
    // 2 bytes for the push/pop rdi pair; stub stays at 18
    // bytes.
    0x57,                         // 0x74 push rdi
    0x48, 0x89, 0xCF,             // 0x75 mov rdi, rcx
    0x6A, 0x28,                   // 0x78 push 40
    0x59,                         // 0x7A pop rcx
    0x31, 0xC0,                   // 0x7B xor eax, eax
    0xF3, 0xAA,                   // 0x7D rep stosb
    0x5F,                         // 0x7F pop rdi
    0xB8, 0x01, 0x00, 0x00, 0x00, // 0x80 mov eax, 1 (BOOL TRUE for Ex variants)
    0xC3,                         // 0x85 ret

    // --- CritSec nop (offset 0x86, 1 byte) ---------------------
    // Shared stub for EnterCriticalSection / LeaveCriticalSection
    // / DeleteCriticalSection. All three are `void(LPCS)`;
    // with no contention to handle they collapse to a single
    // return.
    0xC3, // 0x86 ret

    // === Batch 5: vcruntime140 memory intrinsics ==============
    //
    // CRITICAL ABI NOTE: the Microsoft x64 ABI marks RDI, RSI,
    // RBX, RBP, R12-R15 as NONVOLATILE (callee-saved) — the
    // opposite of the SysV convention where rdi/rsi are
    // scratch. A stub that uses rdi as a scratch register
    // (e.g. as the destination of rep movsb) MUST save and
    // restore it, or the caller's rdi is silently trashed
    // across the call. Every stub here pushes the nonvolatile
    // registers it touches and pops them before ret.

    // --- memmove (offset 0x87, 45 bytes) -----------------------
    // Signature: void* memmove(void* dst=rcx, const void* src=rdx, size_t n=r8).
    // memcpy aliases to this — memmove is a strict superset
    // (handles overlapping regions) and produces the same
    // result as memcpy when regions don't overlap, so aliasing
    // is safe. Returns the original dst in rax.
    //
    // Strategy: if dst <= src (non-overlap or src above dst)
    // forward-copy with rep movsb. Otherwise backward-copy
    // with DF=1 + adjusted start pointers, then restore DF=0
    // (Win64 ABI contract).
    //
    // Saves nonvolatile rsi, rdi around the work.
    0x56,             // 0x87 push rsi
    0x57,             // 0x88 push rdi
    0x49, 0x89, 0xC9, // 0x89 mov r9, rcx     ; save dst for return
    0x48, 0x89, 0xCF, // 0x8C mov rdi, rcx    ; dst
    0x48, 0x89, 0xD6, // 0x8F mov rsi, rdx    ; src
    0x4C, 0x89, 0xC1, // 0x92 mov rcx, r8     ; n
    0x48, 0x39, 0xF7, // 0x95 cmp rdi, rsi
    0x76, 0x12,       // 0x98 jbe +18 -> 0xAC (forward path)
    // backward-copy path (dst > src, overlap-safe)
    0x48, 0x01, 0xCF, // 0x9A add rdi, rcx
    0x48, 0xFF, 0xCF, // 0x9D dec rdi
    0x48, 0x01, 0xCE, // 0xA0 add rsi, rcx
    0x48, 0xFF, 0xCE, // 0xA3 dec rsi
    0xFD,             // 0xA6 std
    0xF3, 0xA4,       // 0xA7 rep movsb
    0xFC,             // 0xA9 cld
    0xEB, 0x02,       // 0xAA jmp +2 -> 0xAE (skip forward's rep movsb)
    // forward-copy path
    0xF3, 0xA4, // 0xAC rep movsb
    // common epilogue
    0x4C, 0x89, 0xC8, // 0xAE mov rax, r9     ; return dst
    0x5F,             // 0xB1 pop rdi
    0x5E,             // 0xB2 pop rsi
    0xC3,             // 0xB3 ret

    // --- memset (offset 0xB4, 19 bytes) ------------------------
    // Signature: void* memset(void* dst=rcx, int c=rdx, size_t n=r8).
    // Byte value is the low 8 bits of c (edx). Returns dst.
    // Saves nonvolatile rdi.
    0x57,             // 0xB4 push rdi
    0x49, 0x89, 0xC9, // 0xB5 mov r9, rcx     ; save dst for return
    0x48, 0x89, 0xCF, // 0xB8 mov rdi, rcx    ; dst
    0x89, 0xD0,       // 0xBB mov eax, edx    ; al = c
    0x4C, 0x89, 0xC1, // 0xBD mov rcx, r8     ; n
    0xF3, 0xAA,       // 0xC0 rep stosb
    0x4C, 0x89, 0xC8, // 0xC2 mov rax, r9     ; return dst
    0x5F,             // 0xC5 pop rdi
    0xC3,             // 0xC6 ret

    // === Batch 6: UCRT CRT-startup shims ======================

    // --- Return-zero (offset 0xC7, 3 bytes) --------------------
    // Shared stub for every apiset/ucrt function whose v0
    // semantic is "report success, do nothing". In the
    // Windows x64 ABI a function that returns int/LONG/BOOL
    // writes to eax; zero-extended to rax; the caller reads
    // eax. `xor eax, eax` produces 0 in rax too.
    //
    // Used by: _configure_narrow_argv,
    // _initialize_narrow_environment, _configthreadlocale,
    // _set_new_mode, _set_fmode, _crt_atexit,
    // _register_onexit_function, _initialize_onexit_table,
    // _seh_filter_exe, _register_thread_local_exe_atexit_callback,
    // _initterm_e, _get_initial_narrow_environment (returns
    // char** — null pointer is semantically "empty env").
    0x31, 0xC0, // 0xC7 xor eax, eax
    0xC3,       // 0xC9 ret

    // --- terminate (offset 0xCA, 11 bytes) ---------------------
    // std::terminate semantics: [[noreturn]] abort. Exit
    // with code 3 (same as POSIX SIGABRT-ish — 3 is the
    // conventional abort exit in the CRT).
    0xBF, 0x03, 0x00, 0x00, 0x00, // 0xCA mov edi, 3
    0x31, 0xC0,                   // 0xCF xor eax, eax   ; SYS_EXIT
    0xCD, 0x80,                   // 0xD1 int 0x80
    0x0F, 0x0B,                   // 0xD3 ud2

    // --- _invalid_parameter_noinfo_noreturn (offset 0xD5, 11) --
    // UCRT's "caller violated a contract" bailout. Windows
    // returns STATUS_INVALID_CRT_PARAMETER (0xC0000417). We
    // exit with that so the code is observable in the serial
    // log.
    0xBF, 0x17, 0x04, 0x00, 0xC0, // 0xD5 mov edi, 0xC0000417
    0x31, 0xC0,                   // 0xDA xor eax, eax   ; SYS_EXIT
    0xCD, 0x80,                   // 0xDC int 0x80
    0x0F, 0x0B,                   // 0xDE ud2

    // === Batch 7: CRT string intrinsics =======================

    // --- strcmp (offset 0xE0, 29 bytes) ------------------------
    // int strcmp(const char* a=rcx, const char* b=rdx).
    // Returns (int)(unsigned)*a - (int)(unsigned)*b at first
    // mismatch, or 0 if both reach NUL simultaneously.
    // Byte-at-a-time loop; doesn't touch any nonvolatile
    // register (rcx, rdx, rax are all caller-saved).
    0x8A, 0x01,       // 0xE0 mov al, [rcx]
    0x8A, 0x12,       // 0xE2 mov dl, [rdx]
    0x38, 0xD0,       // 0xE4 cmp al, dl
    0x75, 0x0C,       // 0xE6 jne +12 -> 0xF4 .done
    0x84, 0xC0,       // 0xE8 test al, al
    0x74, 0x08,       // 0xEA je +8 -> 0xF4 .done
    0x48, 0xFF, 0xC1, // 0xEC inc rcx
    0x48, 0xFF, 0xC2, // 0xEF inc rdx
    0xEB, 0xEC,       // 0xF2 jmp -20 -> 0xE0 .loop
    // .done:
    0x0F, 0xB6, 0xC0, // 0xF4 movzx eax, al
    0x0F, 0xB6, 0xD2, // 0xF7 movzx edx, dl
    0x29, 0xD0,       // 0xFA sub eax, edx
    0xC3,             // 0xFC ret

    // --- strlen (offset 0xFD, 17 bytes) ------------------------
    // size_t strlen(const char* s=rcx). Walks until NUL,
    // returns byte count.
    0x48, 0x89, 0xC8, // 0xFD mov rax, rcx    ; save start
    0x80, 0x38, 0x00, // 0x100 cmp byte [rax], 0
    0x74, 0x05,       // 0x103 je +5 -> 0x10A .done
    0x48, 0xFF, 0xC0, // 0x105 inc rax
    0xEB, 0xF6,       // 0x108 jmp -10 -> 0x100 .loop
    // .done:
    0x48, 0x29, 0xC8, // 0x10A sub rax, rcx   ; length = end - start
    0xC3,             // 0x10D ret

    // --- wcslen (offset 0x10E, 22 bytes) -----------------------
    // size_t wcslen(const wchar_t* s=rcx). Identical shape
    // to strlen but 2-byte stride and the final length is
    // divided by 2 (UTF-16 char count).
    0x48, 0x89, 0xC8,       // 0x10E mov rax, rcx
    0x66, 0x83, 0x38, 0x00, // 0x111 cmp word [rax], 0
    0x74, 0x06,             // 0x115 je +6 -> 0x11D .done
    0x48, 0x83, 0xC0, 0x02, // 0x117 add rax, 2
    0xEB, 0xF4,             // 0x11B jmp -12 -> 0x111 .loop
    // .done:
    0x48, 0x29, 0xC8, // 0x11D sub rax, rcx
    0x48, 0xD1, 0xE8, // 0x120 shr rax, 1     ; byte count / 2 = chars
    0xC3,             // 0x123 ret

    // --- strchr (offset 0x124, 23 bytes) -----------------------
    // char* strchr(const char* s=rcx, int c=rdx).
    // Returns pointer to first byte matching (char)c,
    // including the terminating NUL, or nullptr if not
    // found. Matches Win32/ISO C semantics.
    0x88, 0xD0,       // 0x124 mov al, dl      ; byte to find
    0x38, 0x01,       // 0x126 cmp [rcx], al
    0x74, 0x0A,       // 0x128 je +10 -> 0x134 .found
    0x80, 0x39, 0x00, // 0x12A cmp byte [rcx], 0
    0x74, 0x09,       // 0x12D je +9 -> 0x138 .notfound
    0x48, 0xFF, 0xC1, // 0x12F inc rcx
    0xEB, 0xF2,       // 0x132 jmp -14 -> 0x126 .loop
    // .found:
    0x48, 0x89, 0xC8, // 0x134 mov rax, rcx
    0xC3,             // 0x137 ret
    // .notfound:
    0x31, 0xC0, // 0x138 xor eax, eax
    0xC3,       // 0x13A ret

    // --- strcpy (offset 0x13B, 23 bytes) -----------------------
    // char* strcpy(char* dst=rcx, const char* src=rdx).
    // Copies bytes including NUL terminator, returns dst.
    // Uses r8b (scratch byte, caller-saved) as the transfer
    // register — can't use dl since rdx is the source
    // pointer.
    0x48, 0x89, 0xC8, // 0x13B mov rax, rcx    ; save dst
    0x44, 0x8A, 0x02, // 0x13E mov r8b, [rdx]
    0x44, 0x88, 0x01, // 0x141 mov [rcx], r8b
    0x45, 0x84, 0xC0, // 0x144 test r8b, r8b
    0x74, 0x08,       // 0x147 je +8 -> 0x151 .done
    0x48, 0xFF, 0xC1, // 0x149 inc rcx
    0x48, 0xFF, 0xC2, // 0x14C inc rdx
    0xEB, 0xED,       // 0x14F jmp -19 -> 0x13E .loop
    // .done:
    0xC3, // 0x151 ret

    // === Batch 8: kernel32 safe-ignore shims ==================

    // --- Return-one (offset 0x152, 6 bytes) --------------------
    // Shared stub for Win32 functions whose v0 semantic is
    // "report success, do nothing". Mostly BOOL-returning
    // functions where TRUE (1) means "succeeded" — e.g.
    // CloseHandle, SetConsoleCtrlHandler. Some callers
    // branch on the BOOL, so 1 is the safe default.
    0xB8, 0x01, 0x00, 0x00, 0x00, // 0x152 mov eax, 1
    0xC3,                         // 0x157 ret

    // === Batch 9: Win32 process heap ==========================
    //
    // Per-process heap backed by SYS_HEAP_ALLOC / SYS_HEAP_FREE,
    // serviced by kernel/subsystems/win32/heap.cpp against the
    // 16-page region mapped at 0x50000000 during PeLoad.
    //
    // Flag arguments (dwFlags on HeapAlloc / HeapFree) are
    // IGNORED in v0. Notable consequence: HEAP_ZERO_MEMORY
    // (0x8) is not honoured — callers that need zeroed memory
    // must use calloc (which zeros explicitly) or memset
    // afterwards. HEAP_GENERATE_EXCEPTIONS (0x4) is also
    // ignored — OOM returns NULL, never raises.

    // --- HeapAlloc (offset 0x158, 11 bytes) --------------------
    // LPVOID HeapAlloc(HANDLE hHeap=rcx, DWORD dwFlags=rdx, SIZE_T dwBytes=r8).
    // v0: ignore hHeap + dwFlags. Pass dwBytes through to
    // SYS_HEAP_ALLOC. rax = returned VA or 0 on OOM.
    //
    // Win64 ABI: rdi is callee-saved. Must save + restore
    // around the `mov rdi, r8`. Fits in same 11 bytes by
    // compressing `mov eax, 11` (5 bytes) to `push 11; pop rax`
    // (3 bytes), freeing 2 bytes for the push/pop rdi pair.
    0x57,             // 0x158 push rdi
    0x4C, 0x89, 0xC7, // 0x159 mov rdi, r8
    0x6A, 0x0B,       // 0x15C push 11
    0x58,             // 0x15E pop rax
    0xCD, 0x80,       // 0x15F int 0x80
    0x5F,             // 0x161 pop rdi
    0xC3,             // 0x162 ret

    // --- HeapFree (offset 0x163, 16 bytes) ---------------------
    // BOOL HeapFree(HANDLE hHeap=rcx, DWORD dwFlags=rdx, LPVOID lpMem=r8).
    // v0: ignore hHeap + dwFlags. Pass lpMem to SYS_HEAP_FREE.
    // Always return TRUE — the kernel side silently ignores
    // null/out-of-range pointers (Win32 contract: free(NULL)
    // is legal and should not fail).
    //
    // Win64 ABI fix: save/restore rdi around the `mov rdi, r8`.
    // `mov eax, 12` compresses to `push 12; pop rax` (3 bytes,
    // saves 2) which covers the 2-byte push rdi / pop rdi pair.
    // Keeps total size at 16.
    0x57,                         // 0x163 push rdi
    0x4C, 0x89, 0xC7,             // 0x164 mov rdi, r8
    0x6A, 0x0C,                   // 0x167 push 12
    0x58,                         // 0x169 pop rax
    0xCD, 0x80,                   // 0x16A int 0x80
    0x5F,                         // 0x16C pop rdi
    0xB8, 0x01, 0x00, 0x00, 0x00, // 0x16D mov eax, 1       ; BOOL TRUE
    0xC3,                         // 0x172 ret

    // --- GetProcessHeap (offset 0x173, 8 bytes) ----------------
    // HANDLE GetProcessHeap(void). Returns the heap base VA
    // as an opaque handle. v0 collapses all heap handles to
    // the same value; HeapAlloc's stub ignores it.
    0x48, 0xC7, 0xC0, 0x00, 0x00, 0x00, 0x50, // 0x173 mov rax, 0x50000000
    0xC3,                                     // 0x17A ret

    // --- malloc (offset 0x17B, 11 bytes) -----------------------
    // void* malloc(size_t size=rcx).
    // Identical to HeapAlloc but takes size in rcx (x64 ABI
    // first arg position) instead of r8. Same Win64 ABI fix:
    // save/restore rdi; compress `mov eax, 11` to fit.
    0x57,             // 0x17B push rdi
    0x48, 0x89, 0xCF, // 0x17C mov rdi, rcx
    0x6A, 0x0B,       // 0x17F push 11
    0x58,             // 0x181 pop rax
    0xCD, 0x80,       // 0x182 int 0x80
    0x5F,             // 0x184 pop rdi
    0xC3,             // 0x185 ret

    // --- free (offset 0x186, 11 bytes) -------------------------
    // void free(void* ptr=rcx).
    // No return value; rax left as syscall result (0) which
    // is fine — C "void" discards it. Win64 ABI fix: preserve
    // rdi across the `mov rdi, rcx`.
    //
    // CRITICAL: this stub was the root cause of the batch 48
    // stress-test crash. A caller allocates rdi to hold the
    // malloc IAT pointer, calls malloc, then calls free (which
    // clobbered rdi), then tries to call malloc again via rdi —
    // jumping to the freed block address (0x5000xxxx range).
    0x57,             // 0x186 push rdi
    0x48, 0x89, 0xCF, // 0x187 mov rdi, rcx
    0x6A, 0x0C,       // 0x18A push 12
    0x58,             // 0x18C pop rax
    0xCD, 0x80,       // 0x18D int 0x80
    0x5F,             // 0x18F pop rdi
    0xC3,             // 0x190 ret

    // --- calloc (offset 0x191, 35 bytes) -----------------------
    // void* calloc(size_t count=rcx, size_t size=rdx).
    // Allocate count*size bytes and zero-fill. Zero on OOM.
    //
    // Implementation:
    //   rcx = count * size (imul is nonzero-trashing, rdx is
    //         only read; after imul, rdx is untouched)
    //   r9  = saved count*size (for the stosb loop)
    //   SYS_HEAP_ALLOC preserves r9 (int 0x80 only writes rax).
    //   On success: rep stosb zeros [rdi, rdi+rcx); push/pop
    //   rax around the loop because stosb destroys rdi, rcx.
    //
    // Win64 ABI fix: save/restore rdi (callee-saved). Compressed
    // `mov eax, 11` frees 2 bytes for push/pop rdi; stub stays
    // at 35 bytes. The fail-path jz still skips 12 bytes (the
    // zero-fill sequence) to land on the shared `pop rdi; ret`.
    0x57,                   // 0x191 push rdi
    0x48, 0x0F, 0xAF, 0xCA, // 0x192 imul rcx, rdx       ; rcx = count*size
    0x48, 0x89, 0xCF,       // 0x196 mov rdi, rcx        ; arg: size
    0x49, 0x89, 0xC9,       // 0x199 mov r9, rcx         ; save size for stosb
    0x6A, 0x0B,             // 0x19C push 11 (SYS_HEAP_ALLOC)
    0x58,                   // 0x19E pop rax
    0xCD, 0x80,             // 0x19F int 0x80            ; rax = ptr or 0
    0x48, 0x85, 0xC0,       // 0x1A1 test rax, rax
    0x74, 0x0C,             // 0x1A4 jz +12 -> 0x1B2 (pop rdi; ret)
    0x48, 0x89, 0xC7,       // 0x1A6 mov rdi, rax        ; dst
    0x4C, 0x89, 0xC9,       // 0x1A9 mov rcx, r9         ; count
    0x50,                   // 0x1AC push rax            ; preserve return
    0x30, 0xC0,             // 0x1AD xor al, al          ; zero byte
    0xF3, 0xAA,             // 0x1AF rep stosb
    0x58,                   // 0x1B1 pop rax
    0x5F,                   // 0x1B2 pop rdi
    0xC3,                   // 0x1B3 ret

    // === Batch 10: advapi32 + kernel32 safe-ignore expansion ==
    //
    // advapi32 token/privilege dance: every caller of these
    // expects BOOL return + out-params filled in with
    // "something plausible". v0 gives them all 1s so the
    // setup code path proceeds to the eventual privileged
    // operation (which we can't actually perform anyway).

    // --- OpenProcessToken (offset 0x1B4, 13 bytes) -------------
    // Win32: BOOL OpenProcessToken(HANDLE Process=rcx,
    //                              DWORD DesiredAccess=rdx,
    //                              PHANDLE TokenHandle=r8).
    // Out-param: *TokenHandle = 1 (non-null fake handle).
    // Return TRUE.
    0x49, 0xC7, 0x00, 0x01, 0x00, 0x00, 0x00, // 0x1B4 mov qword [r8], 1
    0xB8, 0x01, 0x00, 0x00, 0x00,             // 0x1BB mov eax, 1
    0xC3,                                     // 0x1C0 ret

    // --- LookupPrivilegeValueW (offset 0x1C1, 13 bytes) --------
    // Win32: BOOL LookupPrivilegeValueW(LPCWSTR System=rcx,
    //                                   LPCWSTR Name=rdx,
    //                                   PLUID Luid=r8).
    // Out-param: *Luid = {LowPart=1, HighPart=0} (LUID is a
    // pair of 32-bit fields in one u64). Non-zero so
    // AdjustTokenPrivileges doesn't treat it as invalid.
    0x49, 0xC7, 0x00, 0x01, 0x00, 0x00, 0x00, // 0x1C1 mov qword [r8], 1
    0xB8, 0x01, 0x00, 0x00, 0x00,             // 0x1C8 mov eax, 1
    0xC3,                                     // 0x1CD ret

    // --- InitializeSListHead (offset 0x1CE, 16 bytes) ----------
    // Win32: void InitializeSListHead(PSLIST_HEADER=rcx).
    // SLIST_HEADER is 16 bytes on x64 (two pointers / atomic
    // state). Zeroing is the correct initialisation — an
    // empty interlocked SList is all-zero.
    0x48, 0xC7, 0x01, 0x00, 0x00, 0x00, 0x00,       // 0x1CE mov qword [rcx], 0
    0x48, 0xC7, 0x41, 0x08, 0x00, 0x00, 0x00, 0x00, // 0x1D5 mov qword [rcx+8], 0
    0xC3,                                           // 0x1DD ret

    // --- GetSystemTimeAsFileTime (offset 0x1DE, 8 bytes) -------
    // Win32: void GetSystemTimeAsFileTime(LPFILETIME=rcx).
    // Superseded — the IAT binding table now routes
    // GetSystemTimeAsFileTime to kOffGetSysTimeFTReal (batch 20,
    // offset 0x2A6) which issues SYS_GETTIME_FT to sample the
    // CMOS RTC and return a real FILETIME. The zero-writing
    // bytes below remain so the layout of earlier batches stays
    // frozen; no import lands here.
    0x48, 0xC7, 0x01, 0x00, 0x00, 0x00, 0x00, // 0x1DE mov qword [rcx], 0
    0xC3,                                     // 0x1E5 ret

    // --- OpenProcess (offset 0x1E6, 4 bytes) -------------------
    // Win32: HANDLE OpenProcess(DWORD Access=rcx,
    //                           BOOL Inherit=rdx,
    //                           DWORD ProcessId=r8).
    // Return the PID itself as the handle. Any later call
    // that receives this handle (e.g. GetExitCodeProcess)
    // can still identify the process if we ever wire up
    // real process-handle tables. For now it's just a
    // non-null value derived from the input so programs
    // that sanity-check "same PID in == same handle out"
    // still work.
    0x4C, 0x89, 0xC0, // 0x1E6 mov rax, r8
    0xC3,             // 0x1E9 ret

    // --- GetExitCodeThread (offset 0x1EA, 12 bytes) ------------
    // Win32: BOOL GetExitCodeThread(HANDLE=rcx, LPDWORD Exit=rdx).
    // Out-param: *Exit = STILL_ACTIVE (0x103). Tells the
    // caller "the thread is still running" — the safe answer
    // for a hosted environment with no real thread exit
    // codes. Return TRUE.
    0xC7, 0x02, 0x03, 0x01, 0x00, 0x00, // 0x1EA mov dword [rdx], 0x103
    0xB8, 0x01, 0x00, 0x00, 0x00,       // 0x1F0 mov eax, 1
    0xC3,                               // 0x1F5 ret

    // === Batch 11: performance counters + tick count =========
    //
    // Backed by SYS_PERF_COUNTER (13), which returns the
    // kernel's tick counter from arch::TimerTicks(). 100 Hz =
    // 10 ms per tick; the stubs convert to Win32's semantic
    // appropriately (raw u64 counter for QPC, ticks*10 for
    // GetTickCount).

    // --- QueryPerformanceCounter (offset 0x1F6, 16 bytes) ------
    // Win32: BOOL QueryPerformanceCounter(LARGE_INTEGER* ctr=rcx).
    // Out-param: *ctr = current tick count (u64).
    // Return TRUE.
    0xB8, 0x0D, 0x00, 0x00, 0x00, // 0x1F6 mov eax, 13 (SYS_PERF_COUNTER)
    0xCD, 0x80,                   // 0x1FB int 0x80           ; rax = ticks
    0x48, 0x89, 0x01,             // 0x1FD mov [rcx], rax
    0xB8, 0x01, 0x00, 0x00, 0x00, // 0x200 mov eax, 1
    0xC3,                         // 0x205 ret

    // --- QueryPerformanceFrequency (offset 0x206, 13 bytes) ----
    // Win32: BOOL QueryPerformanceFrequency(LARGE_INTEGER* freq=rcx).
    // Out-param: *freq = 100 (Hz). Matches the kernel tick
    // frequency so (counter_end - counter_start) / freq
    // gives seconds correctly.
    // Return TRUE.
    0x48, 0xC7, 0x01, 0x64, 0x00, 0x00, 0x00, // 0x206 mov qword [rcx], 100
    0xB8, 0x01, 0x00, 0x00, 0x00,             // 0x20D mov eax, 1
    0xC3,                                     // 0x212 ret

    // --- GetTickCount / GetTickCount64 (offset 0x213, 12 bytes) -
    // Win32: DWORD GetTickCount(void), ULONGLONG GetTickCount64(void).
    // Both return milliseconds since boot. We scale the 100 Hz
    // tick counter by 10 to convert to ms.
    //   * GetTickCount truncates to 32 bits — caller reads
    //     only EAX; upper half of RAX is ignored.
    //   * GetTickCount64 returns the full RAX.
    // Same implementation either way.
    0xB8, 0x0D, 0x00, 0x00, 0x00, // 0x213 mov eax, 13 (SYS_PERF_COUNTER)
    0xCD, 0x80,                   // 0x218 int 0x80
    0x48, 0x6B, 0xC0, 0x0A,       // 0x21A imul rax, rax, 10 ; ticks -> ms
    0xC3,                         // 0x21E ret

    // === Batch 14: real HeapSize + HeapReAlloc ================
    //
    // Upgrades the v0 "return 0" stubs from batch 9 to real
    // syscalls backed by kernel/subsystems/win32/heap.cpp.
    // Payload-capacity tracking falls out for free from the
    // 16-byte block header the allocator already writes — the
    // kernel reads `header.size` and subtracts kHeaderSize.

    // --- HeapSize (offset 0x21F, 11 bytes) ---------------------
    // Win32: SIZE_T HeapSize(HANDLE hHeap=rcx, DWORD dwFlags=rdx, LPCVOID lpMem=r8).
    // Ignores hHeap + dwFlags (v0 has one heap per process).
    // Pass lpMem through rdi to SYS_HEAP_SIZE = 14; kernel
    // returns the block's payload capacity in rax.
    //
    // Win64 ABI fix: save/restore rdi; compress mov eax imm.
    0x57,             // 0x21F push rdi
    0x4C, 0x89, 0xC7, // 0x220 mov rdi, r8
    0x6A, 0x0E,       // 0x223 push 14
    0x58,             // 0x225 pop rax
    0xCD, 0x80,       // 0x226 int 0x80
    0x5F,             // 0x228 pop rdi
    0xC3,             // 0x229 ret

    // --- HeapReAlloc (offset 0x22A, 16 bytes) ------------------
    // Win32: LPVOID HeapReAlloc(HANDLE hHeap=rcx, DWORD dwFlags=rdx,
    //                           LPVOID lpMem=r8, SIZE_T dwBytes=r9).
    // Translate to the two-arg SYS_HEAP_REALLOC = 15: rdi =
    // lpMem (r8), rsi = dwBytes (r9). hHeap + dwFlags ignored.
    // Return value in rax (new VA, or 0 on failure).
    //
    // Win64 ABI fix: save/restore rdi AND rsi (both callee-saved).
    // Compression of `mov eax, 15` covers only one of the two
    // push/pop pairs; stub grows by +2 bytes (14 → 16).
    0x57,             // 0x22A push rdi
    0x56,             // 0x22B push rsi
    0x4C, 0x89, 0xC7, // 0x22C mov rdi, r8
    0x4C, 0x89, 0xCE, // 0x22F mov rsi, r9
    0x6A, 0x0F,       // 0x232 push 15
    0x58,             // 0x234 pop rax
    0xCD, 0x80,       // 0x235 int 0x80
    0x5E,             // 0x237 pop rsi
    0x5F,             // 0x238 pop rdi
    0xC3,             // 0x239 ret

    // --- realloc (offset 0x23A, 16 bytes) ----------------------
    // Win32/ucrt: void* realloc(void* ptr=rcx, size_t size=rdx).
    // Same syscall as HeapReAlloc but arguments come from
    // rcx / rdx (standard C calling convention position) —
    // shuffle into rdi / rsi and invoke.
    //
    // Same Win64 ABI fix as HeapReAlloc. +2 bytes (14 → 16).
    0x57,             // 0x23A push rdi
    0x56,             // 0x23B push rsi
    0x48, 0x89, 0xCF, // 0x23C mov rdi, rcx
    0x48, 0x89, 0xD6, // 0x23F mov rsi, rdx
    0x6A, 0x0F,       // 0x242 push 15
    0x58,             // 0x244 pop rax
    0xCD, 0x80,       // 0x245 int 0x80
    0x5E,             // 0x247 pop rsi
    0x5F,             // 0x248 pop rdi
    0xC3,             // 0x249 ret

    // --- miss-logger (offset 0x24A, 41 bytes) -----------------
    // Catch-all trampoline for every unresolved import. Two-step
    // decode of the caller's control flow so we recover the IAT
    // slot VA that matches what the PE loader staged:
    //
    //   step A  (caller's `call qword [rip+rel32]` is actually
    //            `call rel32` because MSVC emits 5-byte direct
    //            CALLs to tiny 6-byte import "thunks", not the
    //            `call [IAT]` pattern). So [rsp] - 4 gives the
    //            rel32 of the CALL; adding it to [rsp] yields
    //            the thunk's VA (e.g. 0x140004F4E).
    //
    //   step B  At the thunk, bytes are `FF 25 rel32_2` — an
    //            indirect `jmp qword [rip+rel32_2]`. rel32_2 is
    //            relative to the byte after the jmp, so
    //            IAT_slot_VA = thunk + 6 + rel32_2.
    //
    // The kernel side looks up IAT_slot_VA in the per-process
    // miss table populated at load time and logs the function
    // name. Each call still returns 0 (same as the old stub).
    //
    // Guard: before decoding, check that the byte immediately
    // preceding the return address is `0xE8` (the `call rel32`
    // opcode). If not, the caller used an indirect call pattern
    // (`call rax`, `call [reg+disp]`, vtable dispatch, etc.);
    // the decode would alias whatever bytes happen to sit there,
    // yielding a plausible-looking but entirely wrong slot VA
    // that surfaces as `<unmapped>`. Skipping the syscall in
    // that case keeps the log honest — "no legible call
    // pattern" becomes silence rather than fake data.
    //
    // Regs: we clobber rax, rcx, rdi — all caller-saved under
    // any Win64 callable we'd be substituted for, and the syscall
    // path preserves the rest. No save/restore needed.
    0x48, 0x8B, 0x04, 0x24,       // 0x24A mov rax, [rsp]               ; return addr
    0x80, 0x78, 0xFB, 0xE8,       // 0x24E cmp byte [rax-5], 0xE8        ; CALL rel32?
    0x75, 0x1C,                   // 0x252 jne +28 -> 0x270              ; skip decode+syscall
    0x48, 0x63, 0x48, 0xFC,       // 0x254 movsxd rcx, dword [rax-4]    ; CALL rel32
    0x48, 0x01, 0xC1,             // 0x258 add rcx, rax                 ; rcx = thunk VA
    0x48, 0x63, 0x41, 0x02,       // 0x25B movsxd rax, dword [rcx+2]    ; thunk's JMP rel32
    0x48, 0x01, 0xC8,             // 0x25F add rax, rcx                 ; rax = thunk + rel32
    0x48, 0x83, 0xC0, 0x06,       // 0x262 add rax, 6                   ; rax = IAT slot VA
    0x48, 0x89, 0xC7,             // 0x266 mov rdi, rax                 ; arg0 = IAT slot VA
    0xB8, 0x10, 0x00, 0x00, 0x00, // 0x269 mov eax, 16 (SYS_WIN32_MISS_LOG)
    0xCD, 0x80,                   // 0x26E int 0x80
    // .skip target — common epilogue returns 0 for both paths.
    0x31, 0xC0, // 0x270 xor eax, eax
    0xC3,       // 0x272 ret

    // === Batch 16: CRT argc / argv accessors ==================
    //
    // The MSVC CRT's `__scrt_common_main_seh` reads argc/argv via
    // two accessor functions rather than touching globals directly:
    //
    //   int*     __p___argc(void);
    //   char***  __p___argv(void);
    //
    // They return addresses into a process-wide storage block the
    // CRT initialises during startup. In DuetOS that storage is
    // the "proc-env" page at `kProcEnvVa` (0x65000000), populated
    // by `Win32ProcEnvPopulate` during PE load with argc=1 and
    // argv=[program_name, NULL].
    //
    // The absolute address fits in 32 bits (0x65000000 < 2^32), so
    // `mov eax, imm32; ret` is 6 bytes — the upper 32 bits of RAX
    // are zeroed by the x86-64 ABI for any 32-bit dest op, giving
    // us the right 64-bit pointer without a 10-byte movabs.

    // --- __p___argc (offset 0x273, 6 bytes) --------------------
    // Returns &argc (int*). argc lives at kProcEnvVa + 0x00.
    0xB8, 0x00, 0x00, 0x00, 0x65, // 0x273 mov eax, 0x65000000
    0xC3,                         // 0x278 ret

    // --- __p___argv (offset 0x279, 6 bytes) --------------------
    // Returns &argv (char***). argv (a char**) lives at
    // kProcEnvVa + 0x08.
    0xB8, 0x08, 0x00, 0x00, 0x65, // 0x279 mov eax, 0x65000008
    0xC3,                         // 0x27E ret

    // === Batch 17: UCRT stdio accessors =======================

    // --- __p__commode (offset 0x27F, 6 bytes) ------------------
    // int* __p__commode(void) — returns a pointer to the
    // `_commode` global, which encodes the default file-mode
    // flags (0 = O_TEXT, _O_BINARY = 0x4000, …). Callers of
    // _fmode / __p__commode read this value to pick buffered
    // vs. line-buffered vs. binary I/O; they never write it
    // in v0 workloads. We point at a zero int in the proc-env
    // page — "default text mode" — which is what UCRT itself
    // initialises it to.
    0xB8, 0x00, 0x02, 0x00, 0x65, // 0x27F mov eax, 0x65000200
    0xC3,                         // 0x284 ret

    // === Batch 18: C++ iostream output ========================
    //
    // MSVCP140 virtual methods that would normally sit behind
    // `std::cout.rdbuf()->sputn(...)` / `std::cout << x` virtual
    // dispatch. When a PE imports these BY NAME (rather than
    // through vtables loaded from MSVCP140 at runtime), these
    // IAT-direct stubs let the output actually reach serial.
    //
    // Coverage note: winkill's own std::cout path today goes
    // via virtual dispatch through a zero vtable (from the
    // fake-object data-miss pad), so these stubs aren't called
    // by winkill's current execution path. They unblock any
    // future slice that constructs a real `std::cout` whose
    // streambuf vtable points at kOffSputn etc., and they work
    // immediately for programs that take the method's address
    // directly (e.g. `auto f = &basic_streambuf::sputn`).

    // --- sputn (offset 0x285, 19 bytes) ------------------------
    // `streamsize basic_streambuf<char>::sputn(const char* s, streamsize n)`.
    // Args: rcx=this (ignored), rdx=s, r8=n. Returns count in rax.
    // Direct SYS_WRITE(1, s, n); kernel caps at kSyscallWriteMax
    // (256) and returns the actual count — so the caller's
    // count-check (`rv == n`) will match for small buffers and
    // trip on larger ones, which is the honest behaviour.
    //
    // Win64 ABI fix: save/restore rdi + rsi. Compressed imm8
    // loads free the 4 bytes needed for 2 push/pop pairs;
    // stub stays at 19 bytes.
    0x56,             // 0x285 push rsi
    0x57,             // 0x286 push rdi
    0x48, 0x89, 0xD6, // 0x287 mov rsi, rdx        ; buf
    0x4C, 0x89, 0xC2, // 0x28A mov rdx, r8         ; n
    0x6A, 0x01,       // 0x28D push 1
    0x5F,             // 0x28F pop rdi             ; fd = stdout
    0x6A, 0x02,       // 0x290 push 2
    0x58,             // 0x292 pop rax             ; SYS_WRITE
    0xCD, 0x80,       // 0x293 int 0x80
    0x5F,             // 0x295 pop rdi
    0x5E,             // 0x296 pop rsi
    0xC3,             // 0x297 ret                 ; rax = count

    // --- return-this (offset 0x298, 4 bytes) -------------------
    // `basic_ostream& basic_ostream::flush()` and any Win32
    // method whose contract is "do nothing, return *this".
    // Args: rcx=this. Returns rcx.
    0x48, 0x89, 0xC8, // 0x298 mov rax, rcx
    0xC3,             // 0x29B ret

    // --- widen (offset 0x29C, 4 bytes) -------------------------
    // `char basic_ios<char>::widen(char c)`. Identity on char.
    // Args: rcx=this (ignored), dl=c. Returns c in al.
    0x0F, 0xB6, 0xC2, // 0x29C movzx eax, dl
    0xC3,             // 0x29F ret

    // === Batch 19: D3D / DXGI — HRESULT E_FAIL ================
    //
    // Any PE that imports d3d11 / d3d12 / dxgi entry points
    // lands on this stub. Returns HRESULT E_FAIL
    // (0x80004005) so the caller's "no graphics available"
    // fallback path activates cleanly. Prevents the caller
    // from treating the miss-logger's 0-return as success
    // (HRESULT S_OK == 0), which would lead to a null-deref
    // on the returned IDirect3D*/ID3D11*/IDXGI* interface.
    //
    // Wire-up target: a future slice redirects this IAT
    // landing through a syscall to
    // subsystems::graphics::D3D11CreateDeviceStub etc., so the
    // kernel log records exactly which D3D entry point got
    // called. For v0, returning E_FAIL is enough to make the
    // caller's fallback branch fire.

    // --- HRESULT E_FAIL (offset 0x2A0, 6 bytes) ----------------
    // `mov eax, 0x80004005; ret`. The 32-bit form zero-extends
    // to rax; HRESULT is 32-bit so upper bits don't matter.
    0xB8, 0x05, 0x40, 0x00, 0x80, // 0x2A0 mov eax, 0x80004005
    0xC3,                         // 0x2A5 ret

    // === Batch 20: real GetSystemTimeAsFileTime ===============
    //
    // Replaces the old `0x1DE` stub (which wrote 0 into *rcx).
    // Issues SYS_GETTIME_FT (17) which samples the CMOS RTC and
    // returns a Windows FILETIME (100 ns ticks since 1601-01-01).
    // Then stores the result into *rcx (the caller's LPFILETIME).
    //
    // Register discipline:
    //   - rcx must survive the int 0x80 so we can write *rcx at
    //     the end. int 0x80 preserves all GPRs except rax, so we
    //     don't need to save/restore rcx, but we push it anyway
    //     as paranoia for any future syscall that might clobber
    //     arguments.
    //   - Nothing else matters (caller-saved under Win64 ABI).
    //
    // 13 bytes total.
    0x51,                         // 0x2A6 push rcx
    0xB8, 0x11, 0x00, 0x00, 0x00, // 0x2A7 mov eax, 17 (SYS_GETTIME_FT)
    0xCD, 0x80,                   // 0x2AC int 0x80                ; rax = FILETIME
    0x59,                         // 0x2AE pop rcx
    0x48, 0x89, 0x01,             // 0x2AF mov [rcx], rax
    0xC3,                         // 0x2B2 ret

    // === Batch 21: HPET-backed QueryPerformance{Counter,Frequency} ===
    //
    // The old QPC at 0x1F6 returned LAPIC tick counter (100 Hz)
    // and the old QPF at 0x206 returned 100. Replacing both so
    // QPC returns nanoseconds since boot (via SYS_NOW_NS → HPET)
    // and QPF returns 1 GHz (= 1e9, matching nanoseconds).
    //
    // Any (counter_end - counter_start) / frequency computation
    // a caller does now yields real seconds with ~70 ns granularity.
    // The old 0x1F6 and 0x206 stubs stay as dead page bytes.

    // --- QPC via SYS_NOW_NS (offset 0x2B3, 15 bytes) -----------
    // Win32: BOOL QueryPerformanceCounter(LARGE_INTEGER* ctr=rcx).
    0x51,                         // 0x2B3 push rcx
    0xB8, 0x12, 0x00, 0x00, 0x00, // 0x2B4 mov eax, 18 (SYS_NOW_NS)
    0xCD, 0x80,                   // 0x2B9 int 0x80         ; rax = ns since boot
    0x59,                         // 0x2BB pop rcx
    0x48, 0x89, 0x01,             // 0x2BC mov [rcx], rax
    0xB0, 0x01,                   // 0x2BF mov al, 1        ; BOOL TRUE (low byte)
    0xC3,                         // 0x2C1 ret

    // --- QPF via constant 1'000'000'000 (offset 0x2C2, 13 bytes) --
    // Win32: BOOL QueryPerformanceFrequency(LARGE_INTEGER* freq=rcx).
    // 1e9 = 0x3B9ACA00 fits in a positive imm32, so the
    // `mov qword [rcx], imm32` encoding sign-extends to
    // 0x00000000_3B9ACA00 — exactly the 64-bit value we want.
    0x48, 0xC7, 0x01, 0x00, 0xCA, 0x9A, 0x3B, // 0x2C2 mov qword [rcx], 0x3B9ACA00
    0xB8, 0x01, 0x00, 0x00, 0x00,             // 0x2C9 mov eax, 1 (BOOL TRUE)
    0xC3,                                     // 0x2CE ret

    // --- Sleep (offset 0x2CF, 12 bytes) ------------------------
    // Win32: void Sleep(DWORD dwMilliseconds=ecx). Routes to
    // SYS_SLEEP_MS. The kernel handles the ms==0 special case
    // (yield instead of sleep) so we just forward the value.
    //
    // CRITICAL: RDI is CALLEE-SAVED in the Win32 x64 ABI. We
    // clobber it to set up the SYS_SLEEP_MS arg, so we MUST
    // push/pop it across the syscall — otherwise the caller's
    // RDI-resident local (often a pointer or function pointer
    // by MSVC/clang's register allocator) survives Sleep with
    // value `dwMilliseconds`, and the next deref/call through
    // that "pointer" #PFs at cr2 = ms. (Hit live during the
    // Batch 22 bring-up: Sleep(50) → cr2=0x32.)
    //
    // `mov edi, ecx` is a 32-bit move — x86_64 zero-extends the
    // upper half of rdi automatically, so a DWORD `ms` becomes a
    // u64 with the high bits cleared, matching what SYS_SLEEP_MS
    // expects in rdi.
    0x57,                         // 0x2CF push rdi            ; save callee-saved
    0x89, 0xCF,                   // 0x2D0 mov edi, ecx        ; ms -> rdi
    0xB8, 0x13, 0x00, 0x00, 0x00, // 0x2D2 mov eax, 19         ; SYS_SLEEP_MS
    0xCD, 0x80,                   // 0x2D7 int 0x80
    0x5F,                         // 0x2D9 pop rdi             ; restore
    0xC3,                         // 0x2DA ret

    // --- SwitchToThread (offset 0x2DB, 10 bytes) ---------------
    // Win32: BOOL SwitchToThread(void). Returns nonzero if a
    // thread switch happened, 0 if no other ready thread was
    // available. Maps to SYS_YIELD; we return 1 (TRUE)
    // optimistically — callers use the return as a hint, not a
    // strict assertion of "another thread ran". The real check
    // would require comparing scheduler tick counters before
    // and after, which isn't worth the kernel-side complexity.
    //
    // No callee-saved regs touched — only RAX (caller-saved).
    0xB8, 0x03, 0x00, 0x00, 0x00, // 0x2DB mov eax, 3          ; SYS_YIELD
    0xCD, 0x80,                   // 0x2E0 int 0x80
    0xB0, 0x01,                   // 0x2E2 mov al, 1           ; BOOL TRUE
    0xC3,                         // 0x2E4 ret

    // === Batch 23: command line + environment ================
    //
    // Each of these stubs returns a pointer into the proc-env
    // page. The destination addresses live in the low 4 GiB
    // (kProcEnvVa = 0x65000000), so a 32-bit `mov eax, imm32`
    // followed by `ret` is enough — x86_64 zero-extends the
    // upper half of rax automatically.
    //
    // Win32 contract: GetCommandLineW returns a non-NULL
    // pointer to a wide cmdline string for the lifetime of the
    // process. The CRT calls this exactly once during startup
    // to populate __wargv; downstream callers see argv via
    // __p___argv (already wired in batch 16).

    // --- GetCommandLineW (offset 0x2E5, 6 bytes) ---------------
    // Returns LPCWSTR = kProcEnvVa + kProcEnvCmdlineWOff
    //                 = 0x65000300 (low 4 GiB).
    0xB8, 0x00, 0x03, 0x00, 0x65, // 0x2E5 mov eax, 0x65000300
    0xC3,                         // 0x2EA ret

    // --- GetCommandLineA (offset 0x2EB, 6 bytes) ---------------
    // Returns LPCSTR = kProcEnvVa + kProcEnvCmdlineAOff
    //                = 0x65000380.
    0xB8, 0x80, 0x03, 0x00, 0x65, // 0x2EB mov eax, 0x65000380
    0xC3,                         // 0x2F0 ret

    // --- GetEnvironmentStringsW (offset 0x2F1, 6 bytes) --------
    // Returns LPWCH = kProcEnvVa + kProcEnvEnvBlockWOff
    //               = 0x65000400. The block is two NUL bytes
    // (an empty env), so any caller that walks it stops
    // immediately. FreeEnvironmentStringsW is a Win32 cleanup
    // hook — registered as a no-op (returns TRUE) below.
    0xB8, 0x00, 0x04, 0x00, 0x65, // 0x2F1 mov eax, 0x65000400
    0xC3,                         // 0x2F6 ret

    // === Batch 24: file I/O ===================================
    //
    // Win32 handle table lives on Process; SYS_FILE_OPEN /
    // SYS_FILE_READ / SYS_FILE_CLOSE / SYS_FILE_SEEK route in.
    // Handles returned to user mode are 0x100..0x10F (so they
    // never collide with INVALID_HANDLE_VALUE = -1).

    // --- CreateFileW (offset 0x2F7, 59 bytes) -----------------
    // Win32: HANDLE CreateFileW(LPCWSTR lpFileName=rcx, DWORD
    //          dwDesiredAccess, DWORD dwShareMode,
    //          LPSECURITY_ATTRIBUTES lpSec, DWORD dwCreate,
    //          DWORD dwFlags, HANDLE hTemplate);
    //
    // v0 ignores every flag — opens read-only no matter what.
    // The wide path in rcx gets stripped to ASCII on a stack-
    // local 256-byte buffer, then SYS_FILE_OPEN routes it to
    // the kernel.
    //
    // RDI / RSI are CALLEE-SAVED in the Win32 x64 ABI — same
    // bug class that bit Sleep in batch 22; both are saved+
    // restored across the syscall.
    0x57,                                     // 0x2F7 push rdi
    0x56,                                     // 0x2F8 push rsi
    0x48, 0x81, 0xEC, 0x08, 0x01, 0x00, 0x00, // 0x2F9 sub rsp, 0x108  ; 264-byte ASCII buf
    0x48, 0x89, 0xE7,                         // 0x300 mov rdi, rsp    ; rdi = ASCII dst
    0x31, 0xD2,                               // 0x303 xor edx, edx    ; idx = 0
    // .loop:
    0x83, 0xFA, 0xFF,       // 0x305 cmp edx, 0xFF    ; cap at 255
    0x73, 0x10,             // 0x308 jae +0x10 (.done)
    0x0F, 0xB7, 0x04, 0x51, // 0x30A movzx eax, word [rcx+rdx*2]  ; load wide char
    0x66, 0x85, 0xC0,       // 0x30E test ax, ax      ; NUL?
    0x74, 0x07,             // 0x311 jz +0x07 (.done)
    0x88, 0x04, 0x17,       // 0x313 mov [rdi+rdx], al ; ASCII low byte
    0xFF, 0xC2,             // 0x316 inc edx
    0xEB, 0xEB,             // 0x318 jmp .loop (-0x15)
    // .done:
    0xC6, 0x04, 0x17, 0x00,                   // 0x31A mov byte [rdi+rdx], 0  ; NUL terminate
    0x48, 0x89, 0xD6,                         // 0x31E mov rsi, rdx    ; len -> rsi (arg 1)
    0xB8, 0x14, 0x00, 0x00, 0x00,             // 0x321 mov eax, 20     ; SYS_FILE_OPEN
    0xCD, 0x80,                               // 0x326 int 0x80
    0x48, 0x81, 0xC4, 0x08, 0x01, 0x00, 0x00, // 0x328 add rsp, 0x108  ; restore stack
    0x5E,                                     // 0x32F pop rsi
    0x5F,                                     // 0x330 pop rdi
    0xC3,                                     // 0x331 ret

    // --- ReadFile (offset 0x332, 46 bytes) --------------------
    // Win32: BOOL ReadFile(HANDLE rcx, LPVOID buf=rdx,
    //          DWORD count=r8, LPDWORD lpRead=r9, LPOVERLAPPED).
    // Maps to SYS_FILE_READ; stores byte count in *lpRead if
    // non-NULL; returns TRUE on success (rax >= 0).
    0x57,                         // 0x332 push rdi
    0x56,                         // 0x333 push rsi
    0x48, 0x89, 0xCF,             // 0x334 mov rdi, rcx     ; handle
    0x48, 0x89, 0xD6,             // 0x337 mov rsi, rdx     ; buf
    0x4C, 0x89, 0xC2,             // 0x33A mov rdx, r8      ; count
    0xB8, 0x15, 0x00, 0x00, 0x00, // 0x33D mov eax, 21      ; SYS_FILE_READ
    0xCD, 0x80,                   // 0x342 int 0x80
    // *lpRead = max(rax, 0) if r9 != NULL
    0x4D, 0x85, 0xC9, // 0x344 test r9, r9
    0x74, 0x0B,       // 0x347 jz +0x0B
    0x31, 0xC9,       // 0x349 xor ecx, ecx
    0x48, 0x85, 0xC0, // 0x34B test rax, rax
    0x0F, 0x49, 0xC8, // 0x34E cmovns ecx, eax
    0x41, 0x89, 0x09, // 0x351 mov [r9], ecx
    // BOOL = (rax >= 0)
    0x48, 0x85, 0xC0, // 0x354 test rax, rax
    0x0F, 0x99, 0xC0, // 0x357 setns al
    0x0F, 0xB6, 0xC0, // 0x35A movzx eax, al
    0x5E,             // 0x35D pop rsi
    0x5F,             // 0x35E pop rdi
    0xC3,             // 0x35F ret

    // --- CloseHandle (offset 0x360, 15 bytes) -----------------
    // Win32: BOOL CloseHandle(HANDLE rcx). SYS_FILE_CLOSE
    // tolerates non-file handles (no-op + return 0), so this
    // also harmlessly handles the historical no-op CloseHandle
    // call sites (e.g. CreateEventW pseudo-handles).
    0x57,                         // 0x360 push rdi
    0x48, 0x89, 0xCF,             // 0x361 mov rdi, rcx
    0xB8, 0x16, 0x00, 0x00, 0x00, // 0x364 mov eax, 22      ; SYS_FILE_CLOSE
    0xCD, 0x80,                   // 0x369 int 0x80
    0xB0, 0x01,                   // 0x36B mov al, 1        ; BOOL TRUE
    0x5F,                         // 0x36D pop rdi
    0xC3,                         // 0x36E ret

    // --- SetFilePointerEx (offset 0x36F, 38 bytes) ------------
    // Win32: BOOL SetFilePointerEx(HANDLE rcx,
    //          LARGE_INTEGER off=rdx, LARGE_INTEGER* newPos=r8,
    //          DWORD dwMoveMethod=r9).
    // Maps to SYS_FILE_SEEK; writes new position to *r8 if
    // non-NULL; returns TRUE iff rax >= 0.
    0x57,                         // 0x36F push rdi
    0x56,                         // 0x370 push rsi
    0x48, 0x89, 0xCF,             // 0x371 mov rdi, rcx     ; handle
    0x48, 0x89, 0xD6,             // 0x374 mov rsi, rdx     ; offset
    0x4C, 0x89, 0xCA,             // 0x377 mov rdx, r9      ; whence
    0xB8, 0x17, 0x00, 0x00, 0x00, // 0x37A mov eax, 23      ; SYS_FILE_SEEK
    0xCD, 0x80,                   // 0x37F int 0x80
    0x4D, 0x85, 0xC0,             // 0x381 test r8, r8
    0x74, 0x03,                   // 0x384 jz +0x03
    0x49, 0x89, 0x00,             // 0x386 mov [r8], rax
    0x48, 0x85, 0xC0,             // 0x389 test rax, rax
    0x0F, 0x99, 0xC0,             // 0x38C setns al
    0x0F, 0xB6, 0xC0,             // 0x38F movzx eax, al
    0x5E,                         // 0x392 pop rsi
    0x5F,                         // 0x393 pop rdi
    0xC3,                         // 0x394 ret

    // === Batch 25: file stat + module lookup ==================

    // --- GetFileSizeEx (offset 0x395, 29 bytes) ---------------
    // Win32: BOOL GetFileSizeEx(HANDLE rcx, LARGE_INTEGER* rdx).
    // Maps to SYS_FILE_FSTAT — non-destructive size query that
    // doesn't perturb the read cursor (vs. SEEK_END which
    // would).
    0x57,                         // 0x395 push rdi
    0x56,                         // 0x396 push rsi
    0x48, 0x89, 0xCF,             // 0x397 mov rdi, rcx     ; handle
    0x48, 0x89, 0xD6,             // 0x39A mov rsi, rdx     ; out ptr
    0xB8, 0x18, 0x00, 0x00, 0x00, // 0x39D mov eax, 24      ; SYS_FILE_FSTAT
    0xCD, 0x80,                   // 0x3A2 int 0x80
    0x31, 0xC9,                   // 0x3A4 xor ecx, ecx
    0x48, 0x85, 0xC0,             // 0x3A6 test rax, rax    ; ZF=1 iff success (rax==0)
    0x0F, 0x94, 0xC1,             // 0x3A9 sete cl
    0x0F, 0xB6, 0xC1,             // 0x3AC movzx eax, cl
    0x5E,                         // 0x3AF pop rsi
    0x5F,                         // 0x3B0 pop rdi
    0xC3,                         // 0x3B1 ret

    // --- GetModuleHandleW (offset 0x3B2, 17 bytes) ------------
    // Win32: HMODULE GetModuleHandleW(LPCWSTR lpModuleName=rcx).
    //
    // v0 supports exactly the lpModuleName == NULL form (returns
    // the EXE's own HMODULE) — that's what the CRT calls during
    // startup to populate __ImageBase. Any non-NULL name returns
    // 0 (= "module not in our process" → caller's GetLastError
    // path runs). The EXE's image base lives in the proc-env
    // page at kProcEnvVa + kProcEnvModuleBaseOff (= 0x65000500),
    // populated by Win32ProcEnvPopulate from the PE loader.
    0x48, 0x85, 0xC9,                               // 0x3B2 test rcx, rcx
    0x75, 0x09,                                     // 0x3B5 jne +0x09 -> .not_null
    0x48, 0x8B, 0x04, 0x25, 0x00, 0x05, 0x00, 0x65, // 0x3B7 mov rax, [0x65000500]
    0xC3,                                           // 0x3BF ret
    // .not_null:
    0x31, 0xC0, // 0x3C0 xor eax, eax
    0xC3,       // 0x3C2 ret

    // === Batch 26: Win32 mutex (real waitqueue-backed) =========

    // --- CreateMutexW (offset 0x3C3, 13 bytes) ----------------
    // Win32: HANDLE CreateMutexW(LPSECURITY_ATTRIBUTES rcx,
    //          BOOL bInitialOwner=rdx, LPCWSTR lpName=r8).
    // Ignores attrs + name; forwards bInitialOwner to
    // SYS_MUTEX_CREATE which returns the kWin32MutexBase + slot
    // pseudo-handle directly.
    0x57,                         // 0x3C3 push rdi
    0x48, 0x89, 0xD7,             // 0x3C4 mov rdi, rdx       ; bInitialOwner
    0xB8, 0x19, 0x00, 0x00, 0x00, // 0x3C7 mov eax, 25        ; SYS_MUTEX_CREATE
    0xCD, 0x80,                   // 0x3CC int 0x80
    0x5F,                         // 0x3CE pop rdi
    0xC3,                         // 0x3CF ret

    // --- WaitForSingleObject (offset 0x3D0, 38 bytes) ---------
    // Win32: DWORD WaitForSingleObject(HANDLE rcx, DWORD timeout=rdx).
    //
    // Dispatches by handle range:
    //   * Mutex range (0x200..0x207): SYS_MUTEX_WAIT.
    //   * Anything else: pseudo-signal (return 0 = WAIT_OBJECT_0)
    //     to preserve the slice-10 batch-10 behaviour for events,
    //     thread handles, etc., that the v0 stubs don't track.
    //
    // RDI / RSI saved+restored — Win32 ABI callee-saved.
    0x57,                               // 0x3D0 push rdi
    0x56,                               // 0x3D1 push rsi
    0x48, 0x89, 0xC8,                   // 0x3D2 mov rax, rcx       ; handle
    0x48, 0x2D, 0x00, 0x02, 0x00, 0x00, // 0x3D5 sub rax, 0x200     ; rax -= base
    0x48, 0x83, 0xF8, 0x08,             // 0x3DB cmp rax, 8         ; in mutex range?
    0x73, 0x10,                         // 0x3DF jae .pseudo (+0x10)
    0x48, 0x89, 0xCF,                   // 0x3E1 mov rdi, rcx       ; handle
    0x48, 0x89, 0xD6,                   // 0x3E4 mov rsi, rdx       ; timeout_ms
    0xB8, 0x1A, 0x00, 0x00, 0x00,       // 0x3E7 mov eax, 26        ; SYS_MUTEX_WAIT
    0xCD, 0x80,                         // 0x3EC int 0x80
    0x5E,                               // 0x3EE pop rsi
    0x5F,                               // 0x3EF pop rdi
    0xC3,                               // 0x3F0 ret
    // .pseudo:
    0x31, 0xC0, // 0x3F1 xor eax, eax       ; WAIT_OBJECT_0 = 0
    0x5E,       // 0x3F3 pop rsi
    0x5F,       // 0x3F4 pop rdi
    0xC3,       // 0x3F5 ret

    // --- ReleaseMutex (offset 0x3F6, 24 bytes) ----------------
    // Win32: BOOL ReleaseMutex(HANDLE rcx).
    // SYS_MUTEX_RELEASE returns 0 on success, -1 on failure;
    // BOOL = (rax == 0).
    0x57,                         // 0x3F6 push rdi
    0x48, 0x89, 0xCF,             // 0x3F7 mov rdi, rcx
    0xB8, 0x1B, 0x00, 0x00, 0x00, // 0x3FA mov eax, 27         ; SYS_MUTEX_RELEASE
    0xCD, 0x80,                   // 0x3FF int 0x80
    0x31, 0xC9,                   // 0x401 xor ecx, ecx
    0x48, 0x85, 0xC0,             // 0x403 test rax, rax
    0x0F, 0x94, 0xC1,             // 0x406 sete cl
    0x0F, 0xB6, 0xC1,             // 0x409 movzx eax, cl
    0x5F,                         // 0x40C pop rdi
    0xC3,                         // 0x40D ret

    // === Batch 27: console APIs ================================

    // --- WriteConsoleW (offset 0x40E, 96 bytes) ---------------
    // Win32: BOOL WriteConsoleW(HANDLE rcx, const void* rdx,
    //          DWORD nChars=r8, LPDWORD lpCharsOut=r9,
    //          LPVOID lpReserved=[rsp+0x28]).
    //
    // Strips UTF-16LE to low-byte ASCII on a 512-byte stack
    // buffer (capped — longer writes truncate), then routes
    // through SYS_WRITE(fd=1). Stores wide-char count to
    // *lpCharsOut if non-NULL. Returns TRUE always — SYS_WRITE
    // to stdout is gated only by kCapSerialConsole, and a
    // denial there is flagged upstream via the denial counter.
    //
    // Saves RDI / RSI / R12 / R13 — all callee-saved in Win32
    // x64 ABI. R12/R13 used as scratch for count + out-ptr
    // preservation across the syscall.
    0x57,                                     // 0x40E push rdi
    0x56,                                     // 0x40F push rsi
    0x41, 0x54,                               // 0x410 push r12
    0x41, 0x55,                               // 0x412 push r13
    0x48, 0x81, 0xEC, 0x08, 0x02, 0x00, 0x00, // 0x414 sub rsp, 0x208  ; 512-byte ASCII buf + 8 pad
    0x48, 0x89, 0xE7,                         // 0x41B mov rdi, rsp    ; dst
    0x48, 0x89, 0xD6,                         // 0x41E mov rsi, rdx    ; src (wide)
    0x4D, 0x89, 0xC4,                         // 0x421 mov r12, r8     ; nChars (save)
    0x4D, 0x89, 0xCD,                         // 0x424 mov r13, r9     ; lpCharsOut (save)
    0x31, 0xC9,                               // 0x427 xor ecx, ecx    ; i = 0
    // .loop:
    0x4C, 0x39, 0xE1,                         // 0x429 cmp rcx, r12    ; i < count?
    0x73, 0x15,                               // 0x42C jae .done (+0x15)
    0x48, 0x81, 0xF9, 0x00, 0x02, 0x00, 0x00, // 0x42E cmp rcx, 0x200  ; i < 512?
    0x73, 0x0C,                               // 0x435 jae .done (+0x0C)
    0x0F, 0xB7, 0x04, 0x4E,                   // 0x437 movzx eax, word [rsi+rcx*2]
    0x88, 0x04, 0x0F,                         // 0x43B mov [rdi+rcx], al
    0x48, 0xFF, 0xC1,                         // 0x43E inc rcx
    0xEB, 0xE6,                               // 0x441 jmp .loop (-0x1A)
    // .done: rcx = actual ASCII byte count
    0x48, 0x89, 0xCA,             // 0x443 mov rdx, rcx    ; len for SYS_WRITE
    0x48, 0x89, 0xFE,             // 0x446 mov rsi, rdi    ; buf = ASCII dst
    0xBF, 0x01, 0x00, 0x00, 0x00, // 0x449 mov edi, 1      ; fd = stdout
    0xB8, 0x02, 0x00, 0x00, 0x00, // 0x44E mov eax, 2      ; SYS_WRITE
    0xCD, 0x80,                   // 0x453 int 0x80
    0x4D, 0x85, 0xED,             // 0x455 test r13, r13   ; lpCharsOut != NULL?
    0x74, 0x04,                   // 0x458 jz .skip (+4)
    0x45, 0x89, 0x65, 0x00,       // 0x45A mov [r13+0], r12d   ; store wide-char count
    // .skip:
    0x48, 0x81, 0xC4, 0x08, 0x02, 0x00, 0x00, // 0x45E add rsp, 0x208
    0x41, 0x5D,                               // 0x465 pop r13
    0x41, 0x5C,                               // 0x467 pop r12
    0x5E,                                     // 0x469 pop rsi
    0x5F,                                     // 0x46A pop rdi
    0xB0, 0x01,                               // 0x46B mov al, 1       ; BOOL TRUE
    0xC3,                                     // 0x46D ret

    // --- GetConsoleMode (offset 0x46E, 12 bytes) --------------
    // Win32: BOOL GetConsoleMode(HANDLE rcx, DWORD* rdx).
    // Returns a plausible flag combination —
    //   ENABLE_PROCESSED_OUTPUT (0x1) | ENABLE_WRAP_AT_EOL (0x2) |
    //   ENABLE_VIRTUAL_TERMINAL_PROCESSING (0x4) = 0x7.
    // Callers that query-then-modify + SetConsoleMode round-trip
    // see the mode they set (SetConsoleMode is kOffReturnOne, so
    // the write is a no-op; the next Get returns the same
    // constant). Good enough for v0 — modern terminal-aware
    // tools see "VT processing is on, so emit escape codes" and
    // that's what our serial sink wants anyway.
    0xC7, 0x02, 0x07, 0x00, 0x00, 0x00, // 0x46E mov dword [rdx], 7
    0xB8, 0x01, 0x00, 0x00, 0x00,       // 0x474 mov eax, 1 (BOOL TRUE)
    0xC3,                               // 0x479 ret

    // --- GetConsoleCP / GetConsoleOutputCP (offset 0x47A, 6 bytes) --
    // Win32: UINT GetConsoleCP(void). Returns the input code page.
    // We report CP_UTF8 = 65001 = 0xFDE9, which matches modern
    // Windows default (post-2019 "beta: use UTF-8") and tells
    // callers their wide-char strings have already been decoded
    // on our side. Aliased for GetConsoleOutputCP below.
    0xB8, 0xE9, 0xFD, 0x00, 0x00, // 0x47A mov eax, 65001 (CP_UTF8)
    0xC3,                         // 0x47F ret

    // === Batch 28: virtual memory (VirtualAlloc/Free/Protect) ==

    // --- VirtualAlloc (offset 0x480, 13 bytes) ----------------
    // Win32: LPVOID VirtualAlloc(LPVOID rcx, SIZE_T rdx,
    //          DWORD flAllocationType=r8, DWORD flProtect=r9).
    // v0 ignores rcx (caller's preferred address), r8, r9 —
    // just forwards the size to SYS_VMAP which bump-allocates
    // RW+NX+User pages. Kernel returns the VA; stub returns it
    // verbatim (or 0 on arena exhaustion).
    0x57,                         // 0x480 push rdi
    0x48, 0x89, 0xD7,             // 0x481 mov rdi, rdx       ; size
    0xB8, 0x1C, 0x00, 0x00, 0x00, // 0x484 mov eax, 28        ; SYS_VMAP
    0xCD, 0x80,                   // 0x489 int 0x80
    0x5F,                         // 0x48B pop rdi
    0xC3,                         // 0x48C ret

    // --- VirtualFree (offset 0x48D, 29 bytes) -----------------
    // Win32: BOOL VirtualFree(LPVOID rcx, SIZE_T rdx,
    //          DWORD dwFreeType=r8).
    // v0: no-op with range validation. Ignores rdx + r8;
    // SYS_VUNMAP returns 0 if the VA is in the vmap arena, -1
    // otherwise. BOOL = (rax == 0).
    0x57,                         // 0x48D push rdi
    0x56,                         // 0x48E push rsi
    0x48, 0x89, 0xCF,             // 0x48F mov rdi, rcx       ; va
    0x48, 0x89, 0xD6,             // 0x492 mov rsi, rdx       ; size
    0xB8, 0x1D, 0x00, 0x00, 0x00, // 0x495 mov eax, 29        ; SYS_VUNMAP
    0xCD, 0x80,                   // 0x49A int 0x80
    0x31, 0xC9,                   // 0x49C xor ecx, ecx
    0x48, 0x85, 0xC0,             // 0x49E test rax, rax
    0x0F, 0x94, 0xC1,             // 0x4A1 sete cl
    0x0F, 0xB6, 0xC1,             // 0x4A4 movzx eax, cl
    0x5E,                         // 0x4A7 pop rsi
    0x5F,                         // 0x4A8 pop rdi
    0xC3,                         // 0x4A9 ret

    // --- VirtualProtect (offset 0x4AA, 18 bytes) --------------
    // Win32: BOOL VirtualProtect(LPVOID rcx, SIZE_T rdx,
    //          DWORD flNewProtect=r8, PDWORD lpflOldProtect=r9).
    // v0 is a no-op: every vmap page is RW+NX by construction
    // (W^X policy — no W+X). If r9 is non-NULL we write
    // PAGE_READWRITE (0x04) back as the "old" protection so
    // MSVC CRT's VirtualProtect-probe round-trip sees a
    // plausible value. Return TRUE.
    0x4D, 0x85, 0xC9,                         // 0x4AA test r9, r9
    0x74, 0x07,                               // 0x4AD jz .skip (+7)
    0x41, 0xC7, 0x01, 0x04, 0x00, 0x00, 0x00, // 0x4AF mov dword [r9], 4 (PAGE_READWRITE)
    // .skip:
    0xB8, 0x01, 0x00, 0x00, 0x00, // 0x4B6 mov eax, 1 (BOOL TRUE)
    0xC3,                         // 0x4BB ret

    // === Batch 29: wide-string helpers =========================

    // --- lstrlenW (offset 0x4BC, 15 bytes) --------------------
    // Win32: int lstrlenW(LPCWSTR rcx). Scans for a u16 zero and
    // returns the wide-char count. No SEH, no CP check — just
    // the classic strlen shape on 16-bit elements.
    0x31, 0xC0, // 0x4BC xor eax, eax
    // .loop:
    0x66, 0x83, 0x3C, 0x41, 0x00, // 0x4BE cmp word [rcx + rax*2], 0
    0x74, 0x05,                   // 0x4C3 je .done (+5)
    0x48, 0xFF, 0xC0,             // 0x4C5 inc rax
    0xEB, 0xF4,                   // 0x4C8 jmp .loop (-12)
    // .done:
    0xC3, // 0x4CA ret

    // --- lstrcmpW (offset 0x4CB, 37 bytes) --------------------
    // Win32: int lstrcmpW(LPCWSTR rcx, LPCWSTR rdx).
    // Returns 0 if equal, negative if s1 < s2, positive if s1 > s2.
    // Pure compute — no locale folding (lstrcmpW is ordinal
    // compare; lstrcmpiW would case-fold, which we don't stub).
    0x31, 0xC0, // 0x4CB xor eax, eax      ; i = 0
    // .loop:
    0x44, 0x0F, 0xB7, 0x04, 0x41, // 0x4CD movzx r8d, word [rcx+rax*2]
    0x44, 0x0F, 0xB7, 0x0C, 0x42, // 0x4D2 movzx r9d, word [rdx+rax*2]
    0x45, 0x39, 0xC8,             // 0x4D7 cmp r8d, r9d
    0x75, 0x0D,                   // 0x4DA jne .diff (+0x0D)
    0x45, 0x85, 0xC0,             // 0x4DC test r8d, r8d       ; both NUL?
    0x74, 0x05,                   // 0x4DF je .equal (+5)
    0x48, 0xFF, 0xC0,             // 0x4E1 inc rax
    0xEB, 0xE7,                   // 0x4E4 jmp .loop (-0x19)
    // .equal:
    0x31, 0xC0, // 0x4E6 xor eax, eax
    0xC3,       // 0x4E8 ret
    // .diff:
    0x44, 0x89, 0xC0, // 0x4E9 mov eax, r8d     ; signed diff
    0x44, 0x29, 0xC8, // 0x4EC sub eax, r9d
    0xC3,             // 0x4EF ret

    // --- lstrcpyW (offset 0x4F0, 27 bytes) --------------------
    // Win32: LPWSTR lstrcpyW(LPWSTR rcx, LPCWSTR rdx).
    // Returns the destination pointer (rcx). Copies wide chars
    // including the terminating NUL. Classic strcpy shape on
    // 16-bit elements — no length check, caller's responsibility
    // to size the destination.
    0x48, 0x89, 0xC8, // 0x4F0 mov rax, rcx    ; save dst for return
    0x45, 0x31, 0xC0, // 0x4F3 xor r8d, r8d    ; i = 0
    // .loop:
    0x46, 0x0F, 0xB7, 0x0C, 0x42, // 0x4F6 movzx r9d, word [rdx+r8*2]
    0x66, 0x46, 0x89, 0x0C, 0x41, // 0x4FB mov word [rcx+r8*2], r9w
    0x45, 0x85, 0xC9,             // 0x500 test r9d, r9d   ; copied NUL?
    0x74, 0x05,                   // 0x503 je .done (+5)
    0x49, 0xFF, 0xC0,             // 0x505 inc r8
    0xEB, 0xEC,                   // 0x508 jmp .loop (-0x14)
    // .done:
    0xC3, // 0x50A ret

    // === Batch 30: system-info probes ==========================

    // --- IsWow64Process (offset 0x50B, 17 bytes) --------------
    // Win32: BOOL IsWow64Process(HANDLE rcx, PBOOL rdx).
    // Writes FALSE to *Wow64Process (we're a native x64 process;
    // there's no 32-bit emulation subsystem in v0 anyway) and
    // returns TRUE. If the out-ptr is NULL we skip the write —
    // real Windows also tolerates this.
    0x48, 0x85, 0xD2,                   // 0x50B test rdx, rdx
    0x74, 0x06,                         // 0x50E jz .skip (+6)
    0xC7, 0x02, 0x00, 0x00, 0x00, 0x00, // 0x510 mov dword [rdx], 0 (FALSE)
    // .skip:
    0xB8, 0x01, 0x00, 0x00, 0x00, // 0x516 mov eax, 1 (BOOL TRUE)
    0xC3,                         // 0x51B ret

    // --- GetVersionExW (offset 0x51C, 34 bytes) ---------------
    // Win32: BOOL GetVersionExW(POSVERSIONINFOW rcx).
    //
    // Layout of OSVERSIONINFOW:
    //   0x00  dwOSVersionInfoSize  <- caller-set; we leave alone
    //   0x04  dwMajorVersion       <- we write 10 (Win10)
    //   0x08  dwMinorVersion       <- we write 0
    //   0x0C  dwBuildNumber        <- we write 19041 (Win10 2004)
    //   0x10  dwPlatformId         <- we write 2 (VER_PLATFORM_WIN32_NT)
    //   0x14  szCSDVersion[128]    <- leave caller's zero-init
    //
    // 19041 = 0x4A61; fits in imm32 signed. Picked to look like a
    // recent-ish Windows 10 build so feature-gate probes see a
    // plausible "new enough" version.
    //
    // GetVersionEx (ANSI) aliases to this — the first five DWORDs
    // are layout-identical; only szCSDVersion differs (ANSI vs
    // wide), which we don't touch.
    0xC7, 0x41, 0x04, 0x0A, 0x00, 0x00, 0x00, // 0x51C mov dword [rcx+0x04], 10    (major)
    0xC7, 0x41, 0x08, 0x00, 0x00, 0x00, 0x00, // 0x523 mov dword [rcx+0x08], 0     (minor)
    0xC7, 0x41, 0x0C, 0x61, 0x4A, 0x00, 0x00, // 0x52A mov dword [rcx+0x0C], 19041 (build)
    0xC7, 0x41, 0x10, 0x02, 0x00, 0x00, 0x00, // 0x531 mov dword [rcx+0x10], 2     (NT platform)
    0xB8, 0x01, 0x00, 0x00, 0x00,             // 0x538 mov eax, 1 (BOOL TRUE)
    0xC3,                                     // 0x53D ret

    // === Batch 31: ANSI-byte string helpers ====================
    // Symmetric to batch 29 but for single-byte LPCSTR inputs.

    // --- lstrlenA (offset 0x53E, 14 bytes) --------------------
    // Win32: int lstrlenA(LPCSTR rcx). Byte-strlen.
    0x31, 0xC0, // 0x53E xor eax, eax
    // .loop:
    0x80, 0x3C, 0x01, 0x00, // 0x540 cmp byte [rcx+rax*1], 0
    0x74, 0x05,             // 0x544 je .done (+5)
    0x48, 0xFF, 0xC0,       // 0x546 inc rax
    0xEB, 0xF5,             // 0x549 jmp .loop (-11)
    // .done:
    0xC3, // 0x54B ret

    // --- lstrcmpA (offset 0x54C, 37 bytes) --------------------
    // Win32: int lstrcmpA(LPCSTR rcx, LPCSTR rdx). Byte-strcmp
    // (ordinal — no locale fold). 0 / negative / positive per
    // classic strcmp contract.
    0x31, 0xC0, // 0x54C xor eax, eax
    // .loop:
    0x44, 0x0F, 0xB6, 0x04, 0x01, // 0x54E movzx r8d, byte [rcx+rax]
    0x44, 0x0F, 0xB6, 0x0C, 0x02, // 0x553 movzx r9d, byte [rdx+rax]
    0x45, 0x39, 0xC8,             // 0x558 cmp r8d, r9d
    0x75, 0x0D,                   // 0x55B jne .diff (+0x0D)
    0x45, 0x85, 0xC0,             // 0x55D test r8d, r8d
    0x74, 0x05,                   // 0x560 je .equal (+5)
    0x48, 0xFF, 0xC0,             // 0x562 inc rax
    0xEB, 0xE7,                   // 0x565 jmp .loop (-0x19)
    // .equal:
    0x31, 0xC0, // 0x567 xor eax, eax
    0xC3,       // 0x569 ret
    // .diff:
    0x44, 0x89, 0xC0, // 0x56A mov eax, r8d
    0x44, 0x29, 0xC8, // 0x56D sub eax, r9d
    0xC3,             // 0x570 ret

    // --- lstrcpyA (offset 0x571, 26 bytes) --------------------
    // Win32: LPSTR lstrcpyA(LPSTR rcx, LPCSTR rdx). Byte-strcpy,
    // returns dst (rcx).
    0x48, 0x89, 0xC8, // 0x571 mov rax, rcx   ; save dst for return
    0x45, 0x31, 0xC0, // 0x574 xor r8d, r8d   ; i = 0
    // .loop:
    0x46, 0x0F, 0xB6, 0x0C, 0x02, // 0x577 movzx r9d, byte [rdx+r8]
    0x46, 0x88, 0x0C, 0x01,       // 0x57C mov byte [rcx+r8], r9b
    0x45, 0x85, 0xC9,             // 0x580 test r9d, r9d
    0x74, 0x05,                   // 0x583 je .done (+5)
    0x49, 0xFF, 0xC0,             // 0x585 inc r8
    0xEB, 0xED,                   // 0x588 jmp .loop (-0x13)
    // .done:
    0xC3, // 0x58A ret

    // === Batch 32: path-query stubs ============================
    //
    // All v0 paths report a single fixed "X:\" — the minimum
    // legal Windows drive-qualified absolute path. Consumers
    // that do literal path comparisons (DllMain "am I in
    // System32?") see a non-NULL, well-formed path and don't
    // crash; consumers that actually try to open the returned
    // path get a normal not-found result from our VFS. Future
    // slices can plumb the real PE path through when spawn
    // actually knows it.
    //
    // Encoding: "X:\" is 3 wide chars + NUL = 8 bytes = 2 dwords:
    //   dword 0 : 0x003A 0x0058 (': X' little-endian) = 0x003A0058
    //   dword 1 : 0x0000 0x005C ('\0 \\' LE)          = 0x0000005C

    // --- GetModuleFileNameW (offset 0x58B, 24 bytes) ----------
    // Win32: DWORD GetModuleFileNameW(HMODULE rcx, LPWSTR rdx, DWORD r8).
    // Writes "X:\\\0" to rdx if r8 > 0, returns 3 (chars w/o NUL).
    0x45, 0x85, 0xC0,                         // 0x58B test r8d, r8d
    0x74, 0x0D,                               // 0x58E jz .skip (+0x0D) — past both mov-dword writes (6+7=13)
    0xC7, 0x02, 0x58, 0x00, 0x3A, 0x00,       // 0x590 mov dword [rdx], 0x003A0058 (L'X:')
    0xC7, 0x42, 0x04, 0x5C, 0x00, 0x00, 0x00, // 0x596 mov dword [rdx+4], 0x0000005C (L'\\\0')
    // .skip:
    0xB8, 0x03, 0x00, 0x00, 0x00, // 0x59D mov eax, 3
    0xC3,                         // 0x5A2 ret

    // --- GetCurrentDirectoryW (offset 0x5A3, 31 bytes) --------
    // Win32: DWORD GetCurrentDirectoryW(DWORD nBufferLength=rcx, LPWSTR lpBuffer=rdx).
    // Returns 3 chars written (w/o NUL) if rcx >= 4; else returns
    // 4 (required size INCLUDING NUL) without writing — standard
    // Win32 convention for "buffer too small".
    0x48, 0x83, 0xF9, 0x04,       // 0x5A3 cmp rcx, 4
    0x73, 0x06,                   // 0x5A7 jae .copy (+6)
    0xB8, 0x04, 0x00, 0x00, 0x00, // 0x5A9 mov eax, 4 (required incl. NUL)
    0xC3,                         // 0x5AE ret
    // .copy:
    0xC7, 0x02, 0x58, 0x00, 0x3A, 0x00,       // 0x5AF mov dword [rdx], 0x003A0058
    0xC7, 0x42, 0x04, 0x5C, 0x00, 0x00, 0x00, // 0x5B5 mov dword [rdx+4], 0x0000005C
    0xB8, 0x03, 0x00, 0x00, 0x00,             // 0x5BC mov eax, 3
    0xC3,                                     // 0x5C1 ret

    // === Batch 33: encoding converters =========================
    //
    // v0 treats both directions as simple byte-extend / byte-
    // truncate. That's correct for 7-bit ASCII under any of the
    // standard single-byte code pages + CP_UTF8 (which is itself
    // ASCII-compatible for the low 128 code points). Non-ASCII
    // UTF-8 sequences would need real decoding — not implemented,
    // documented as v0 limitation.
    //
    // Stack-arg layout at entry, after `push rdi; push rsi`:
    //   [rsp+0]   saved rsi
    //   [rsp+8]   saved rdi
    //   [rsp+16]  return address
    //   [rsp+24]  shadow arg 1 (rcx spill slot)
    //   [rsp+32]  shadow arg 2 (rdx spill slot)
    //   [rsp+40]  shadow arg 3 (r8 spill slot)
    //   [rsp+48]  shadow arg 4 (r9 spill slot)
    //   [rsp+56]  arg 5 = output pointer
    //   [rsp+64]  arg 6 = output capacity

    // --- MultiByteToWideChar (offset 0x5C2, 49 bytes) ---------
    // Win32: int MultiByteToWideChar(UINT CP=rcx, DWORD flags=rdx,
    //          LPCCH lpMultiByteStr=r8, int cbMultiByte=r9,
    //          LPWSTR dst=[rsp+0x28], int cchWideChar=[rsp+0x30]).
    //
    // v0 routes each source byte through `movzx r16, byte` and
    // stores as wide char. Copies min(cbMultiByte, cchWideChar)
    // chars, returns count written. If cchWideChar == 0, returns
    // cbMultiByte (size-query mode). Caller is expected to pass
    // an actual byte count (not -1); future slice handles the
    // NUL-terminated variant.
    0x57,                         // 0x5C2 push rdi
    0x56,                         // 0x5C3 push rsi
    0x48, 0x8B, 0x7C, 0x24, 0x38, // 0x5C4 mov rdi, [rsp+0x38]   ; dst (LPWSTR)
    0x8B, 0x4C, 0x24, 0x40,       // 0x5C9 mov ecx, [rsp+0x40]   ; cchWideChar (dst_cap)
    0x44, 0x89, 0xCE,             // 0x5CD mov esi, r9d          ; cbMultiByte (src_len)
    0x85, 0xC9,                   // 0x5D0 test ecx, ecx
    0x74, 0x1A,                   // 0x5D2 jz .size_query (+0x1A)
    0x31, 0xC0,                   // 0x5D4 xor eax, eax
    // .loop:
    0x39, 0xF0,                   // 0x5D6 cmp eax, esi
    0x73, 0x11,                   // 0x5D8 jae .done (+0x11)
    0x39, 0xC8,                   // 0x5DA cmp eax, ecx
    0x73, 0x0D,                   // 0x5DC jae .done (+0x0D)
    0x41, 0x0F, 0xB6, 0x14, 0x00, // 0x5DE movzx edx, byte [r8+rax*1]
    0x66, 0x89, 0x14, 0x47,       // 0x5E3 mov [rdi+rax*2], dx
    0xFF, 0xC0,                   // 0x5E7 inc eax
    0xEB, 0xEB,                   // 0x5E9 jmp .loop (-0x15)
    // .done:
    0x5E, // 0x5EB pop rsi
    0x5F, // 0x5EC pop rdi
    0xC3, // 0x5ED ret
    // .size_query:
    0x89, 0xF0, // 0x5EE mov eax, esi
    0x5E,       // 0x5F0 pop rsi
    0x5F,       // 0x5F1 pop rdi
    0xC3,       // 0x5F2 ret

    // --- WideCharToMultiByte (offset 0x5F3, 48 bytes) ---------
    // Win32: int WideCharToMultiByte(UINT CP=rcx, DWORD flags=rdx,
    //          LPCWCH lpWideCharStr=r8, int cchWideChar=r9,
    //          LPSTR dst=[rsp+0x28], int cbMultiByte=[rsp+0x30],
    //          LPCCH lpDefaultChar=[rsp+0x38]  (ignored),
    //          LPBOOL lpUsedDefaultChar=[rsp+0x40]  (ignored)).
    //
    // v0 truncates each wide char to its low byte — correct for
    // ASCII-range content, loses high-plane data otherwise.
    0x57,                         // 0x5F3 push rdi
    0x56,                         // 0x5F4 push rsi
    0x48, 0x8B, 0x7C, 0x24, 0x38, // 0x5F5 mov rdi, [rsp+0x38]   ; dst (LPSTR)
    0x8B, 0x4C, 0x24, 0x40,       // 0x5FA mov ecx, [rsp+0x40]   ; cbMultiByte (dst_cap)
    0x44, 0x89, 0xCE,             // 0x5FE mov esi, r9d          ; cchWideChar (src_len)
    0x85, 0xC9,                   // 0x601 test ecx, ecx
    0x74, 0x19,                   // 0x603 jz .size_query (+0x19)
    0x31, 0xC0,                   // 0x605 xor eax, eax
    // .loop:
    0x39, 0xF0,                   // 0x607 cmp eax, esi
    0x73, 0x10,                   // 0x609 jae .done (+0x10)
    0x39, 0xC8,                   // 0x60B cmp eax, ecx
    0x73, 0x0C,                   // 0x60D jae .done (+0x0C)
    0x41, 0x0F, 0xB7, 0x14, 0x40, // 0x60F movzx edx, word [r8+rax*2]
    0x88, 0x14, 0x07,             // 0x614 mov [rdi+rax*1], dl
    0xFF, 0xC0,                   // 0x617 inc eax
    0xEB, 0xEC,                   // 0x619 jmp .loop (-0x14)
    // .done:
    0x5E, // 0x61B pop rsi
    0x5F, // 0x61C pop rdi
    0xC3, // 0x61D ret
    // .size_query:
    0x89, 0xF0, // 0x61E mov eax, esi
    0x5E,       // 0x620 pop rsi
    0x5F,       // 0x621 pop rdi
    0xC3,       // 0x622 ret

    // === Batch 34: identity queries ============================
    //
    // Fixed-string probes for "who am I on this machine?"
    // queries. Real Windows writes the NetBIOS name / SAM user.
    // v0 hands back constants: user = "user" (4 chars), computer
    // = "DuetOS" (8 chars). Both follow the same in/out-size
    // shape: *pcchSize is capacity on entry, chars-written-
    // including-NUL on exit.

    // --- GetUserNameW (offset 0x623, 47 bytes) ----------------
    // Win32: BOOL GetUserNameW(LPWSTR rcx, LPDWORD rdx).
    //   If *rdx >= 5, write L"user\0", *rdx = 5, return TRUE.
    //   Else, *rdx = 5 (required), return FALSE.
    0x8B, 0x02,                               // 0x623 mov eax, [rdx]  (capacity in wide chars)
    0x83, 0xF8, 0x05,                         // 0x625 cmp eax, 5
    0x72, 0x1F,                               // 0x628 jb .small (+0x1F = 31)
    0xC7, 0x01, 0x75, 0x00, 0x73, 0x00,       // 0x62A mov dword [rcx], 0x00730075 (L"us")
    0xC7, 0x41, 0x04, 0x65, 0x00, 0x72, 0x00, // 0x630 mov dword [rcx+4], 0x00720065 (L"er")
    0x66, 0xC7, 0x41, 0x08, 0x00, 0x00,       // 0x637 mov word [rcx+8], 0 (NUL)
    0xC7, 0x02, 0x05, 0x00, 0x00, 0x00,       // 0x63D mov dword [rdx], 5 (chars incl NUL)
    0xB8, 0x01, 0x00, 0x00, 0x00,             // 0x643 mov eax, 1 (BOOL TRUE)
    0xC3,                                     // 0x648 ret
    // .small:
    0xC7, 0x02, 0x05, 0x00, 0x00, 0x00, // 0x649 mov dword [rdx], 5 (required)
    0x31, 0xC0,                         // 0x64F xor eax, eax (BOOL FALSE)
    0xC3,                               // 0x651 ret

    // --- GetComputerNameW (offset 0x652, 61 bytes) ------------
    // Win32: BOOL GetComputerNameW(LPWSTR rcx, LPDWORD rdx).
    //   Writes L"DuetOS\0" (9 wide chars incl NUL) if buffer
    //   has room. Same size-convention as GetUserNameW.
    0x8B, 0x02,                               // 0x652 mov eax, [rdx]
    0x83, 0xF8, 0x09,                         // 0x654 cmp eax, 9
    0x72, 0x2D,                               // 0x657 jb .small (+0x2D = 45)
    0xC7, 0x01, 0x43, 0x00, 0x75, 0x00,       // 0x659 mov dword [rcx], 0x00750043 (L"Cu")
    0xC7, 0x41, 0x04, 0x73, 0x00, 0x74, 0x00, // 0x65F mov dword [rcx+4], 0x00740073 (L"st")
    0xC7, 0x41, 0x08, 0x6F, 0x00, 0x6D, 0x00, // 0x666 mov dword [rcx+8], 0x006D006F (L"om")
    0xC7, 0x41, 0x0C, 0x4F, 0x00, 0x53, 0x00, // 0x66D mov dword [rcx+12], 0x0053004F (L"OS")
    0x66, 0xC7, 0x41, 0x10, 0x00, 0x00,       // 0x674 mov word [rcx+16], 0 (NUL)
    0xC7, 0x02, 0x09, 0x00, 0x00, 0x00,       // 0x67A mov dword [rdx], 9
    0xB8, 0x01, 0x00, 0x00, 0x00,             // 0x680 mov eax, 1
    0xC3,                                     // 0x685 ret
    // .small:
    0xC7, 0x02, 0x09, 0x00, 0x00, 0x00, // 0x686 mov dword [rdx], 9 (required)
    0x31, 0xC0,                         // 0x68C xor eax, eax
    0xC3,                               // 0x68E ret

    // === Batch 35: system-directory queries ====================
    //
    // GetWindowsDirectoryW / GetSystemDirectoryW have buffer-
    // first signatures (rcx = buffer, rdx = size). We report
    // the minimal "X:\\" path for both — same content as
    // GetCurrentDirectoryW, but the args are in opposite order
    // so a separate stub is needed. GetTempPathW has the SAME
    // sig as GetCurrentDirectoryW (size first, buffer second),
    // so it aliases to kOffGetCurrentDirW below.

    // --- GetWindowsDirectoryW / GetSystemDirectoryW (offset 0x68F, 30 bytes) ---
    // Win32: UINT GetWindowsDirectoryW(LPWSTR rcx, UINT rdx).
    // UINT GetSystemDirectoryW(LPWSTR rcx, UINT rdx).
    // Buffer-first sig: writes L"X:\\\0" if rdx >= 4, returns 3.
    // Else returns 4 (required size incl NUL). Same content for
    // both — DuetOS has no filesystem distinction between
    // "Windows" dir and "System32" dir.
    0x83, 0xFA, 0x04,                         // 0x68F cmp edx, 4
    0x72, 0x13,                               // 0x692 jb .small (+0x13 = 19)
    0xC7, 0x01, 0x58, 0x00, 0x3A, 0x00,       // 0x694 mov dword [rcx], 0x003A0058
    0xC7, 0x41, 0x04, 0x5C, 0x00, 0x00, 0x00, // 0x69A mov dword [rcx+4], 0x0000005C
    0xB8, 0x03, 0x00, 0x00, 0x00,             // 0x6A1 mov eax, 3
    0xC3,                                     // 0x6A6 ret
    // .small:
    0xB8, 0x04, 0x00, 0x00, 0x00, // 0x6A7 mov eax, 4 (required incl NUL)
    0xC3,                         // 0x6AC ret

    // === Batch 36: misc — drives + error mode + format msg ====

    // --- GetLogicalDrives (offset 0x6AD, 6 bytes) -------------
    // Win32: DWORD GetLogicalDrives(void). Returns a bitmap of
    // drive letters (bit 0 = A:, bit 23 = X:). v0 reports only
    // X: — matches our single fixed path.
    0xB8, 0x00, 0x00, 0x80, 0x00, // 0x6AD mov eax, 0x00800000 (bit 23 = X:)
    0xC3,                         // 0x6B2 ret

    // --- GetDriveType (offset 0x6B3, 6 bytes) -----------------
    // Win32: UINT GetDriveType{A,W}(LPCxSTR rcx). Returns the
    // drive type. v0 always returns 3 (DRIVE_FIXED) — X: is a
    // "fixed" logical drive in DuetOS land.
    0xB8, 0x03, 0x00, 0x00, 0x00, // 0x6B3 mov eax, 3 (DRIVE_FIXED)
    0xC3,                         // 0x6B8 ret

    // === Batch 37: registry + file-attributes constant stubs ==

    // --- return-two (offset 0x6B9, 6 bytes) -------------------
    // Win32: typed as LSTATUS / LONG. Reg* APIs return
    // ERROR_FILE_NOT_FOUND (2) when a key / value doesn't exist.
    // Shared stub for all v0 registry queries.
    0xB8, 0x02, 0x00, 0x00, 0x00, // 0x6B9 mov eax, 2
    0xC3,                         // 0x6BE ret

    // --- return-minus-1 (offset 0x6BF, 6 bytes) ---------------
    // Win32 GetFileAttributesW returns INVALID_FILE_ATTRIBUTES
    // (= 0xFFFFFFFF) when the path doesn't exist — caller's
    // "file not present" fallback kicks in. Shared stub for any
    // DWORD-returning API that signals "not found" with -1.
    0xB8, 0xFF, 0xFF, 0xFF, 0xFF, // 0x6BF mov eax, 0xFFFFFFFF
    0xC3,                         // 0x6C4 ret

    // --- return-priority-normal (offset 0x6C5, 6 bytes) -------
    // Win32 GetPriorityClass returns a priority-class constant.
    // NORMAL_PRIORITY_CLASS = 0x20. Most apps probe this
    // value; reporting "normal" means they don't try to bump
    // themselves to REALTIME (which would fail anyway).
    0xB8, 0x20, 0x00, 0x00, 0x00, // 0x6C5 mov eax, 0x20 (NORMAL_PRIORITY_CLASS)
    0xC3,                         // 0x6CA ret

    // === Batch 40: Interlocked* atomic operations ==============
    //
    // Real hardware LOCK-prefix instructions — these are correct
    // atomic semantics, not no-ops. v0 is effectively single-CPU
    // from ring 3's perspective (preemption but not SMP-ring-3
    // yet), but LOCK prefixes are cheap on UP and required for
    // future SMP ring-3 correctness, so we emit them now.

    // --- InterlockedIncrement (offset 0x6CB, 12 bytes) --------
    // Win32: LONG InterlockedIncrement(LONG volatile *rcx).
    // Returns NEW value. Implementation: xadd eax=1, then inc.
    0xB8, 0x01, 0x00, 0x00, 0x00, // 0x6CB mov eax, 1
    0xF0, 0x0F, 0xC1, 0x01,       // 0x6D0 lock xadd [rcx], eax    ; eax=old, [rcx]+=1
    0xFF, 0xC0,                   // 0x6D4 inc eax                  ; eax = new
    0xC3,                         // 0x6D6 ret

    // --- InterlockedDecrement (offset 0x6D7, 12 bytes) --------
    // Win32: LONG InterlockedDecrement(LONG volatile *rcx).
    0xB8, 0xFF, 0xFF, 0xFF, 0xFF, // 0x6D7 mov eax, -1
    0xF0, 0x0F, 0xC1, 0x01,       // 0x6DC lock xadd [rcx], eax    ; eax=old, [rcx]+=-1
    0xFF, 0xC8,                   // 0x6E0 dec eax                  ; eax = new
    0xC3,                         // 0x6E2 ret

    // --- InterlockedCompareExchange (offset 0x6E3, 8 bytes) ---
    // Win32: LONG InterlockedCompareExchange(LONG* rcx,
    //          LONG exchange=rdx, LONG compare=r8).
    // If *rcx == compare: *rcx = exchange; return compare.
    // Else: return *rcx (unchanged). LOCK CMPXCHG does this
    // atomically; compare arg is loaded into EAX so CMPXCHG
    // compares against it, and on success stores EDX.
    0x44, 0x89, 0xC0,       // 0x6E3 mov eax, r8d          ; compare -> EAX
    0xF0, 0x0F, 0xB1, 0x11, // 0x6E6 lock cmpxchg [rcx], edx
    0xC3,                   // 0x6EA ret

    // --- InterlockedExchange (offset 0x6EB, 5 bytes) ----------
    // Win32: LONG InterlockedExchange(LONG* rcx, LONG val=rdx).
    // Atomic XCHG reg/mem is implicitly locked — no LOCK prefix
    // needed. Returns the OLD value.
    0x89, 0xD0, // 0x6EB mov eax, edx        ; val -> EAX
    0x87, 0x01, // 0x6ED xchg [rcx], eax     ; EAX = old, [rcx] = val
    0xC3,       // 0x6EF ret

    // --- InterlockedExchangeAdd (offset 0x6F0, 7 bytes) -------
    // Win32: LONG InterlockedExchangeAdd(LONG* rcx, LONG add=rdx).
    // Returns the OLD value; *rcx += add.
    0x89, 0xD0,             // 0x6F0 mov eax, edx        ; add -> EAX
    0xF0, 0x0F, 0xC1, 0x01, // 0x6F2 lock xadd [rcx], eax ; EAX = old, [rcx] += add
    0xC3,                   // 0x6F6 ret

    // === Batch 41: 64-bit Interlocked atomics ==================
    //
    // 64-bit counterparts to batch 40. REX.W prefix (0x48) makes
    // the ops 64-bit wide. `mov rax, -1` uses the full 7-byte
    // sign-extended form — `mov eax, -1` would zero-extend to
    // 0x00000000FFFFFFFF which is NOT -1 in 64-bit.

    // --- InterlockedIncrement64 (offset 0x6F7, 14 bytes) ------
    // Win32: LONGLONG InterlockedIncrement64(LONGLONG* rcx).
    // mov eax, 1 zero-extends to rax = 1. Returns NEW value.
    0xB8, 0x01, 0x00, 0x00, 0x00, // 0x6F7 mov eax, 1
    0xF0, 0x48, 0x0F, 0xC1, 0x01, // 0x6FC lock xadd [rcx], rax
    0x48, 0xFF, 0xC0,             // 0x701 inc rax
    0xC3,                         // 0x704 ret

    // --- InterlockedDecrement64 (offset 0x705, 16 bytes) ------
    // Win32: LONGLONG InterlockedDecrement64(LONGLONG* rcx).
    // `mov rax, -1` sign-extends imm32 0xFFFFFFFF to rax = -1.
    0x48, 0xC7, 0xC0, 0xFF, 0xFF, 0xFF, 0xFF, // 0x705 mov rax, -1
    0xF0, 0x48, 0x0F, 0xC1, 0x01,             // 0x70C lock xadd [rcx], rax
    0x48, 0xFF, 0xC8,                         // 0x711 dec rax
    0xC3,                                     // 0x714 ret

    // --- InterlockedCompareExchange64 (offset 0x715, 9 bytes) -
    // Win32: LONGLONG InterlockedCompareExchange64(LONGLONG* rcx,
    //          LONGLONG exchange=rdx, LONGLONG compare=r8).
    0x4C, 0x89, 0xC0,             // 0x715 mov rax, r8        ; compare -> RAX
    0xF0, 0x48, 0x0F, 0xB1, 0x11, // 0x718 lock cmpxchg [rcx], rdx
    0xC3,                         // 0x71D ret

    // --- InterlockedExchange64 (offset 0x71E, 7 bytes) --------
    // Win32: LONGLONG InterlockedExchange64(LONGLONG* rcx,
    //          LONGLONG val=rdx). XCHG with memory implicitly LOCKs.
    0x48, 0x89, 0xD0, // 0x71E mov rax, rdx
    0x48, 0x87, 0x01, // 0x721 xchg [rcx], rax
    0xC3,             // 0x724 ret

    // --- InterlockedExchangeAdd64 (offset 0x725, 9 bytes) -----
    // Win32: LONGLONG InterlockedExchangeAdd64(LONGLONG* rcx,
    //          LONGLONG add=rdx). Returns OLD value.
    0x48, 0x89, 0xD0,             // 0x725 mov rax, rdx
    0xF0, 0x48, 0x0F, 0xC1, 0x01, // 0x728 lock xadd [rcx], rax
    0xC3,                         // 0x72D ret

    // --- return-status-not-implemented (offset 0x72E, 6 bytes) --
    // NT-layer (ntdll) functions return NTSTATUS codes. 0xC00000BB
    // = STATUS_NOT_IMPLEMENTED is the documented "this function
    // isn't supported" code — callers either fall back or
    // propagate the status up. Shared stub for ntdll bindings
    // where v0 has no real impl.
    0xB8, 0xBB, 0x00, 0x00, 0xC0, // 0x72E mov eax, 0xC00000BB
    0xC3,                         // 0x733 ret

    // === Batch 45: real event handles ==========================
    //
    // Replaces the slice-10 kOffReturnOne CreateEventW no-op
    // with genuine per-process event state. Infrastructure
    // parallels batch 26's mutex layer. Events have no owner,
    // no recursion — just a signaled flag + waitqueue. Manual-
    // vs. auto-reset differ only in whether SetEvent wakes all
    // or one, and whether a successful wait clears the signal.

    // --- CreateEventW (offset 0x734, 18 bytes) ----------------
    // Win32: HANDLE CreateEventW(LPSECURITY_ATTRIBUTES rcx,
    //          BOOL bManualReset=rdx, BOOL bInitialState=r8,
    //          LPCWSTR lpName=r9).
    // Attrs + name ignored in v0. Forwards bManualReset/
    // bInitialState to SYS_EVENT_CREATE.
    0x57,                         // 0x734 push rdi
    0x56,                         // 0x735 push rsi
    0x48, 0x89, 0xD7,             // 0x736 mov rdi, rdx       ; bManualReset
    0x4C, 0x89, 0xC6,             // 0x739 mov rsi, r8        ; bInitialState
    0xB8, 0x1E, 0x00, 0x00, 0x00, // 0x73C mov eax, 30        ; SYS_EVENT_CREATE
    0xCD, 0x80,                   // 0x741 int 0x80
    0x5E,                         // 0x743 pop rsi
    0x5F,                         // 0x744 pop rdi
    0xC3,                         // 0x745 ret

    // --- SetEvent (offset 0x746, 15 bytes) --------------------
    // Win32: BOOL SetEvent(HANDLE rcx). Routes to SYS_EVENT_SET.
    // Returns TRUE (SYS_EVENT_SET succeeds for any valid handle).
    0x57,                         // 0x746 push rdi
    0x48, 0x89, 0xCF,             // 0x747 mov rdi, rcx
    0xB8, 0x1F, 0x00, 0x00, 0x00, // 0x74A mov eax, 31        ; SYS_EVENT_SET
    0xCD, 0x80,                   // 0x74F int 0x80
    0xB0, 0x01,                   // 0x751 mov al, 1          ; BOOL TRUE
    0x5F,                         // 0x753 pop rdi
    0xC3,                         // 0x754 ret

    // --- ResetEvent (offset 0x755, 15 bytes) ------------------
    // Win32: BOOL ResetEvent(HANDLE rcx).
    0x57,                         // 0x755 push rdi
    0x48, 0x89, 0xCF,             // 0x756 mov rdi, rcx
    0xB8, 0x20, 0x00, 0x00, 0x00, // 0x759 mov eax, 32        ; SYS_EVENT_RESET
    0xCD, 0x80,                   // 0x75E int 0x80
    0xB0, 0x01,                   // 0x760 mov al, 1
    0x5F,                         // 0x762 pop rdi
    0xC3,                         // 0x763 ret

    // --- WaitForSingleObject v2 (offset 0x764, 66 bytes) ------
    // Upgraded version of batch 26's WaitForSingleObject that
    // dispatches THREE ranges:
    //   * Mutex range (0x200..0x207): SYS_MUTEX_WAIT.
    //   * Event range (0x300..0x307): SYS_EVENT_WAIT.
    //   * Anything else: pseudo-signal (return WAIT_OBJECT_0),
    //     preserving slice-10's "unknown handle is already
    //     signaled" contract for batch 10's CreateEventW no-op
    //     return value (= 1, outside both ranges).
    //
    // RDI / RSI saved + restored — Win32 ABI callee-saved.
    0x57,                               // 0x764 push rdi
    0x56,                               // 0x765 push rsi
    0x48, 0x89, 0xC8,                   // 0x766 mov rax, rcx
    0x48, 0x2D, 0x00, 0x02, 0x00, 0x00, // 0x769 sub rax, 0x200
    0x48, 0x83, 0xF8, 0x08,             // 0x76F cmp rax, 8
    0x72, 0x11,                         // 0x773 jb .mutex (+0x11 = 17)
    0x48, 0x2D, 0x00, 0x01, 0x00, 0x00, // 0x775 sub rax, 0x100 (now 0x300..0x307 -> 0..7)
    0x48, 0x83, 0xF8, 0x08,             // 0x77B cmp rax, 8
    0x72, 0x15,                         // 0x77F jb .event (+0x15 = 21)
    // .pseudo:
    0x31, 0xC0, // 0x781 xor eax, eax (WAIT_OBJECT_0)
    0x5E,       // 0x783 pop rsi
    0x5F,       // 0x784 pop rdi
    0xC3,       // 0x785 ret
    // .mutex:
    0x48, 0x89, 0xCF,             // 0x786 mov rdi, rcx
    0x48, 0x89, 0xD6,             // 0x789 mov rsi, rdx
    0xB8, 0x1A, 0x00, 0x00, 0x00, // 0x78C mov eax, 26 (SYS_MUTEX_WAIT)
    0xCD, 0x80,                   // 0x791 int 0x80
    0x5E,                         // 0x793 pop rsi
    0x5F,                         // 0x794 pop rdi
    0xC3,                         // 0x795 ret
    // .event:
    0x48, 0x89, 0xCF,             // 0x796 mov rdi, rcx
    0x48, 0x89, 0xD6,             // 0x799 mov rsi, rdx
    0xB8, 0x21, 0x00, 0x00, 0x00, // 0x79C mov eax, 33 (SYS_EVENT_WAIT)
    0xCD, 0x80,                   // 0x7A1 int 0x80
    0x5E,                         // 0x7A3 pop rsi
    0x5F,                         // 0x7A4 pop rdi
    0xC3,                         // 0x7A5 ret

    // === Batch 46: real TLS (persistent slot storage) ==========
    //
    // Per-process 64-slot table with u64 storage per slot + a
    // 64-bit bitmap for in-use tracking. Supersedes batch 39's
    // alias-to-kOffReturnMinus1 TlsAlloc which always claimed
    // TLS_OUT_OF_INDEXES. Single-threaded process in v0 means
    // "thread-local" == "process-local" — but the CRT uses TLS
    // for errno / locale / exception state without caring about
    // multi-thread semantics, so the storage is what matters.

    // --- TlsAlloc (offset 0x7A6, 8 bytes) ---------------------
    // Win32: DWORD TlsAlloc(void). Returns slot 0..63 or -1.
    0xB8, 0x22, 0x00, 0x00, 0x00, // 0x7A6 mov eax, 34 (SYS_TLS_ALLOC)
    0xCD, 0x80,                   // 0x7AB int 0x80
    0xC3,                         // 0x7AD ret

    // --- TlsFree (offset 0x7AE, 24 bytes) ---------------------
    // Win32: BOOL TlsFree(DWORD rcx). Returns TRUE on success.
    0x57,                         // 0x7AE push rdi
    0x48, 0x89, 0xCF,             // 0x7AF mov rdi, rcx
    0xB8, 0x23, 0x00, 0x00, 0x00, // 0x7B2 mov eax, 35 (SYS_TLS_FREE)
    0xCD, 0x80,                   // 0x7B7 int 0x80
    0x31, 0xC9,                   // 0x7B9 xor ecx, ecx
    0x48, 0x85, 0xC0,             // 0x7BB test rax, rax
    0x0F, 0x94, 0xC1,             // 0x7BE sete cl
    0x0F, 0xB6, 0xC1,             // 0x7C1 movzx eax, cl
    0x5F,                         // 0x7C4 pop rdi
    0xC3,                         // 0x7C5 ret

    // --- TlsGetValue (offset 0x7C6, 13 bytes) -----------------
    // Win32: LPVOID TlsGetValue(DWORD rcx). Returns stored
    // value (or 0 on bad index).
    0x57,                         // 0x7C6 push rdi
    0x48, 0x89, 0xCF,             // 0x7C7 mov rdi, rcx
    0xB8, 0x24, 0x00, 0x00, 0x00, // 0x7CA mov eax, 36 (SYS_TLS_GET)
    0xCD, 0x80,                   // 0x7CF int 0x80
    0x5F,                         // 0x7D1 pop rdi
    0xC3,                         // 0x7D2 ret

    // --- TlsSetValue (offset 0x7D3, 20 bytes) -----------------
    // Win32: BOOL TlsSetValue(DWORD rcx, LPVOID rdx).
    0x57,                         // 0x7D3 push rdi
    0x56,                         // 0x7D4 push rsi
    0x48, 0x89, 0xCF,             // 0x7D5 mov rdi, rcx
    0x48, 0x89, 0xD6,             // 0x7D8 mov rsi, rdx
    0xB8, 0x25, 0x00, 0x00, 0x00, // 0x7DB mov eax, 37 (SYS_TLS_SET)
    0xCD, 0x80,                   // 0x7E0 int 0x80
    0xB0, 0x01,                   // 0x7E2 mov al, 1 (BOOL TRUE)
    0x5E,                         // 0x7E4 pop rsi
    0x5F,                         // 0x7E5 pop rdi
    0xC3,                         // 0x7E6 ret

    // === Batch 47: ntdll virtual-memory primitives =============
    //
    // Until this batch, the import resolver mapped both
    // `ntdll!NtAllocateVirtualMemory` and `NtFreeVirtualMemory`
    // to `kOffReturnStatusNotImpl` — a 6-byte stub returning
    // `STATUS_NOT_IMPLEMENTED`. PE binaries that bypass kernel32
    // (CRT internals, anti-debug, JITs) and call the Nt
    // primitives directly would fail. Now they actually allocate
    // and free pages by routing through the same SYS_VMAP /
    // SYS_VUNMAP that backs `kernel32!VirtualAlloc` / `VirtualFree`.
    //
    // Win64 ABI for both: rcx, rdx, r8, r9 are arg regs; rsi
    // and rdi are callee-saved (so we push/pop them).
    // STATUS_NOT_IMPLEMENTED is 0xC00000BB; STATUS_NO_MEMORY is
    // 0xC0000017; STATUS_INVALID_PARAMETER is 0xC000000D.

    // --- NtAllocateVirtualMemory (offset 0x7E7, 36 bytes) ----
    // Win64: NTSTATUS NtAllocateVirtualMemory(
    //          HANDLE       rcx,        // ProcessHandle (ignored — must be self)
    //          PVOID*       rdx,        // BaseAddress (in/out)
    //          ULONG_PTR    r8,         // ZeroBits (ignored)
    //          PSIZE_T      r9,         // RegionSize (in/out)
    //          ULONG        [rsp+0x28], // AllocationType (ignored — always commit)
    //          ULONG        [rsp+0x30]) // Protect (ignored — RW+NX)
    //
    // Stub semantics: read *RegionSize, hand it to SYS_VMAP,
    // write the returned VA to *BaseAddress, leave *RegionSize
    // alone (kernel rounds up internally; v0 reports the
    // requested size). Returns STATUS_SUCCESS or STATUS_NO_MEMORY.
    0x57,                         // 0x7E7 push rdi
    0x56,                         // 0x7E8 push rsi
    0x49, 0x8B, 0x39,             // 0x7E9 mov rdi, [r9]      ; size from *RegionSize
    0xB8, 0x1C, 0x00, 0x00, 0x00, // 0x7EC mov eax, 28        ; SYS_VMAP
    0xCD, 0x80,                   // 0x7F1 int 0x80
    0x48, 0x85, 0xC0,             // 0x7F3 test rax, rax      ; 0 = OOM
    0x74, 0x0B,                   // 0x7F6 jz .fail (+11)
    0x48, 0x89, 0x02,             // 0x7F8 mov [rdx], rax     ; *BaseAddress = VA
    0x49, 0x89, 0x39,             // 0x7FB mov [r9], rdi      ; echo size back
    0x31, 0xC0,                   // 0x7FE xor eax, eax       ; STATUS_SUCCESS
    0x5E,                         // 0x800 pop rsi
    0x5F,                         // 0x801 pop rdi
    0xC3,                         // 0x802 ret
    // .fail:
    0xB8, 0x17, 0x00, 0x00, 0xC0, // 0x803 mov eax, 0xC0000017 ; STATUS_NO_MEMORY
    0x5E,                         // 0x808 pop rsi
    0x5F,                         // 0x809 pop rdi
    0xC3,                         // 0x80A ret

    // --- NtFreeVirtualMemory (offset 0x80B, 33 bytes) --------
    // Win64: NTSTATUS NtFreeVirtualMemory(
    //          HANDLE       rcx,    // ProcessHandle (ignored)
    //          PVOID*       rdx,    // BaseAddress (in/out)
    //          PSIZE_T      r8,     // RegionSize (in/out)
    //          ULONG        r9)     // FreeType (ignored — always release)
    //
    // Stub semantics: read *BaseAddress and *RegionSize, hand
    // them to SYS_VUNMAP. Kernel returns 0 on success or non-
    // zero if the VA isn't in the per-process vmap arena.
    0x57,                         // 0x80B push rdi
    0x56,                         // 0x80C push rsi
    0x48, 0x8B, 0x3A,             // 0x80D mov rdi, [rdx]     ; VA from *BaseAddress
    0x49, 0x8B, 0x30,             // 0x810 mov rsi, [r8]      ; size from *RegionSize
    0xB8, 0x1D, 0x00, 0x00, 0x00, // 0x813 mov eax, 29        ; SYS_VUNMAP
    0xCD, 0x80,                   // 0x818 int 0x80
    0x48, 0x85, 0xC0,             // 0x81A test rax, rax
    0x75, 0x05,                   // 0x81D jnz .fail (+5)
    0x31, 0xC0,                   // 0x81F xor eax, eax       ; STATUS_SUCCESS
    0x5E,                         // 0x821 pop rsi
    0x5F,                         // 0x822 pop rdi
    0xC3,                         // 0x823 ret
    // .fail:
    0xB8, 0x0D, 0x00, 0x00, 0xC0, // 0x824 mov eax, 0xC000000D ; STATUS_INVALID_PARAMETER
    0x5E,                         // 0x829 pop rsi
    0x5F,                         // 0x82A pop rdi
    0xC3,                         // 0x82B ret

    // === Batch 48: SYSTEMTIME / FILETIME pointer-output APIs =====
    //
    // The previous commit (8a8ce9b) deliberately skipped these:
    // a `mov eax,1; ret` stub leaves a caller-allocated SYSTEMTIME
    // uninitialised, and CRTs that consume it treat year=0 as a
    // sentinel that breaks date math. Real stub bytes now bridge
    // the Win64 calling convention (rcx, rdx) to our kernel
    // syscall ABI (rdi, rsi) via int 0x80 with SYS_GETTIME_ST (40),
    // SYS_ST_TO_FT (41), SYS_FT_TO_ST (42).

    // --- GetSystemTime / GetLocalTime (offset 0x82C, 11 bytes) -----
    // Win32 ABI: void GetSystemTime(LPSYSTEMTIME=rcx).
    //   GetLocalTime aliases to the same stub — we have no timezone
    //   database yet, so local == UTC.
    0x48, 0x89, 0xCF,             // 0x82C mov rdi, rcx   ; SYSTEMTIME* out
    0xB8, 0x28, 0x00, 0x00, 0x00, // 0x82F mov eax, 40    ; SYS_GETTIME_ST
    0xCD, 0x80,                   // 0x834 int 0x80
    0xC3,                         // 0x836 ret

    // --- SystemTimeToFileTime (offset 0x837, 14 bytes) -----------
    // Win32 ABI: BOOL SystemTimeToFileTime(const SYSTEMTIME* = rcx,
    //                                       LPFILETIME        = rdx).
    // Kernel returns 0 on success in rax — matches Win32 TRUE
    // (non-zero). On EFAULT or invalid input, kernel writes
    // u64(-1) which is also non-zero; the caller can't tell the
    // difference at v0 granularity, but a well-behaved input
    // always succeeds.
    0x48, 0x89, 0xCF,             // 0x837 mov rdi, rcx
    0x48, 0x89, 0xD6,             // 0x83A mov rsi, rdx
    0xB8, 0x29, 0x00, 0x00, 0x00, // 0x83D mov eax, 41    ; SYS_ST_TO_FT
    0xCD, 0x80,                   // 0x842 int 0x80
    0xC3,                         // 0x844 ret

    // --- FileTimeToSystemTime (offset 0x845, 14 bytes) -----------
    // Win32 ABI: BOOL FileTimeToSystemTime(const FILETIME* = rcx,
    //                                       LPSYSTEMTIME   = rdx).
    0x48, 0x89, 0xCF,             // 0x845 mov rdi, rcx
    0x48, 0x89, 0xD6,             // 0x848 mov rsi, rdx
    0xB8, 0x2A, 0x00, 0x00, 0x00, // 0x84B mov eax, 42    ; SYS_FT_TO_ST
    0xCD, 0x80,                   // 0x850 int 0x80
    0xC3,                         // 0x852 ret

    // === Batch 49: real NTSTATUS-returning ntdll time/perf =========
    //
    // Unlike kernel32's BOOL-returning APIs, NtQuerySystemTime /
    // NtQueryPerformanceCounter return NTSTATUS (0 on success).
    // These dedicated stubs keep that contract exact.

    // --- NtQuerySystemTime (offset 0x853, 16 bytes) --------------
    // NT ABI: NTSTATUS NtQuerySystemTime(PLARGE_INTEGER out=rcx).
    // Fill *out via SYS_GETTIME_FT and return STATUS_SUCCESS (0).
    0x48, 0x89, 0xCF,             // 0x853 mov rdi, rcx
    0xB8, 0x11, 0x00, 0x00, 0x00, // 0x856 mov eax, 17    ; SYS_GETTIME_FT
    0xCD, 0x80,                   // 0x85B int 0x80        ; rax = FILETIME ticks
    0x48, 0x89, 0x01,             // 0x85D mov [rcx], rax
    0x31, 0xC0,                   // 0x860 xor eax, eax    ; STATUS_SUCCESS
    0xC3,                         // 0x862 ret

    // --- NtQueryPerformanceCounter (offset 0x863, 28 bytes) ------
    // NT ABI:
    //   NTSTATUS NtQueryPerformanceCounter(
    //       PLARGE_INTEGER Counter=rcx, PLARGE_INTEGER Freq=rdx)
    // Counter is mandatory; Frequency is optional.
    0x48, 0x89, 0xCF,                         // 0x863 mov rdi, rcx
    0xB8, 0x12, 0x00, 0x00, 0x00,             // 0x866 mov eax, 18    ; SYS_NOW_NS
    0xCD, 0x80,                               // 0x86B int 0x80        ; rax = ns
    0x48, 0x89, 0x01,                         // 0x86D mov [rcx], rax
    0x48, 0x85, 0xD2,                         // 0x870 test rdx, rdx
    0x74, 0x07,                               // 0x873 jz .done
    0x48, 0xC7, 0x02, 0x00, 0xCA, 0x9A, 0x3B, // 0x875 mov qword [rdx], 1_000_000_000
    // .done:
    0x31, 0xC0, // 0x87C xor eax, eax   ; STATUS_SUCCESS
    0xC3,       // 0x87E ret

    // === Batch 50: real CreateThread via SYS_THREAD_CREATE =====
    //
    // Win32: HANDLE CreateThread(
    //     LPSECURITY_ATTRIBUTES  lpThreadAttributes,  // rcx  (ignored)
    //     SIZE_T                 dwStackSize,          // rdx  (ignored — kernel picks)
    //     LPTHREAD_START_ROUTINE lpStartAddress,       // r8
    //     LPVOID                 lpParameter,          // r9
    //     DWORD                  dwCreationFlags,      // [rsp+0x28]  (ignored — always-run)
    //     LPDWORD                lpThreadId);          // [rsp+0x30]  (optional out)
    //
    // DuetOS: SYS_THREAD_CREATE (45) with start_va in rdi,
    // param in rsi. Returns handle or 0xFFFFFFFFFFFFFFFF on
    // failure. The Win32 contract is "handle or NULL on fail" —
    // we translate -1 to 0 at the tail.
    //
    // --- CreateThread (offset 0x87F, 39 bytes) -----------------
    // Win64 ABI: rdi + rsi are callee-saved — save/restore around
    // the syscall so callers that hold IAT slots in rdi (which
    // MSVC's code generator routinely does) survive the call.
    // Added after syscall_stress.exe hit a latent bug from batch 50
    // where rdi was clobbered and main jumped through the wrecked
    // rdi into the thread proc directly.
    0x57,                         // 0x87F push rdi
    0x56,                         // 0x880 push rsi
    0x4C, 0x89, 0xC7,             // 0x881 mov rdi, r8          ; start
    0x4C, 0x89, 0xCE,             // 0x884 mov rsi, r9          ; param
    0xB8, 0x2D, 0x00, 0x00, 0x00, // 0x887 mov eax, 45          ; SYS_THREAD_CREATE
    0xCD, 0x80,                   // 0x88C int 0x80             ; rax = handle or -1
    // We pushed 16 bytes, so lpThreadId (originally at [rsp+0x30])
    // is now at [rsp+0x40].
    0x48, 0x8B, 0x4C, 0x24, 0x40, // 0x88E mov rcx, [rsp+0x40]
    0x48, 0x85, 0xC9,             // 0x893 test rcx, rcx
    0x74, 0x02,                   // 0x896 je  +2 -> 0x89A
    0x89, 0x01,                   // 0x898 mov [rcx], eax
    // Translate -1 (any high bits set) to 0 for Win32 "NULL" handle
    // semantics.
    0x48, 0x83, 0xF8, 0xFF, // 0x89A cmp rax, -1
    0x75, 0x03,             // 0x89E jne +3 -> 0x8A3
    0x31, 0xC0,             // 0x8A0 xor eax, eax
    0x90,                   // 0x8A2 nop (padding so cmp/jne/xor lands exactly 3 bytes)
    0x5E,                   // 0x8A3 pop rsi
    0x5F,                   // 0x8A4 pop rdi
    0xC3,                   // 0x8A5 ret

    // --- ThreadExitTramp (offset 0x8A6, 6 bytes) ---------------
    // Landing site when a Win32 thread proc returns. DoThreadCreate
    // writes (kWin32StubsVa + 0x8A2) to [stack_top - 8] so the
    // thread proc's final `ret` pops this VA into RIP. The thread
    // proc's return value is still in EAX (Win32 __stdcall). We
    // copy it to EDI (SYS_EXIT's first arg) then issue SYS_EXIT(0).
    // SYS_EXIT kills just this task — the process's other threads
    // (e.g. main waiting on the event) are unaffected. Noreturn.
    0x89, 0xC7, // 0x8A6 mov edi, eax     ; thread retcode
    0x31, 0xC0, // 0x8A8 xor eax, eax    ; SYS_EXIT = 0
    0xCD, 0x80, // 0x8AA int 0x80        ; noreturn

    // === Batch 51 =============================================

    // --- ExitThread (offset 0x8AC, 9 bytes) -------------------
    // Win32: void ExitThread(DWORD dwExitCode).  rcx = exit code.
    // Maps to SYS_EXIT — kills only the calling task (just like
    // the ThreadExitTramp fallback) without disturbing the rest
    // of the process.
    0x48, 0x89, 0xCF, // 0x8AC mov rdi, rcx       ; exit code
    0x31, 0xC0,       // 0x8AF xor eax, eax       ; SYS_EXIT
    0xCD, 0x80,       // 0x8B1 int 0x80
    0x0F, 0x0B,       // 0x8B3 ud2                ; [[noreturn]]

    // --- OutputDebugStringA (offset 0x8B5, 13 bytes) ----------
    // Win32: void OutputDebugStringA(LPCSTR lpOutputString).
    // rcx = NUL-terminated ASCII string. Maps to SYS_DEBUG_PRINT
    // which does the strlen + bounce + serial emit kernel-side.
    // Win64 ABI: rdi is callee-saved — push/pop around the
    // syscall to preserve the caller's rdi.
    0x57,                         // 0x8B5 push rdi
    0x48, 0x89, 0xCF,             // 0x8B6 mov rdi, rcx      ; str
    0xB8, 0x2E, 0x00, 0x00, 0x00, // 0x8B9 mov eax, 46       ; SYS_DEBUG_PRINT
    0xCD, 0x80,                   // 0x8BE int 0x80
    0x5F,                         // 0x8C0 pop rdi
    0xC3,                         // 0x8C1 ret

    // --- GetProcessTimes (offset 0x8C2, 44 bytes) -------------
    // Win32:
    //   BOOL GetProcessTimes(HANDLE hProcess,             // rcx ignored
    //                        LPFILETIME CreationTime,     // rdx
    //                        LPFILETIME ExitTime,         // r8
    //                        LPFILETIME KernelTime,       // r9
    //                        LPFILETIME UserTime);        // [rsp+0x28]
    // Aliased by GetThreadTimes (same shape). v0 just zeros all
    // four FILETIMEs and returns BOOL TRUE — callers that only
    // want to detect "API exists" proceed cleanly, callers that
    // divide-by-zero get the same garbage they'd get from a real
    // machine that hadn't run long enough.
    // Assumes each output pointer is non-NULL (Win32 doesn't spec
    // NULL-tolerance on these args); real callers always pass
    // valid FILETIMEs.
    0x48, 0xC7, 0x02, 0x00, 0x00, 0x00, 0x00, // 0x8C2 mov qword [rdx], 0
    0x49, 0xC7, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x8C9 mov qword [r8], 0
    0x49, 0xC7, 0x01, 0x00, 0x00, 0x00, 0x00, // 0x8D0 mov qword [r9], 0
    0x48, 0x8B, 0x4C, 0x24, 0x28,             // 0x8D7 mov rcx, [rsp+0x28]
    0x48, 0x85, 0xC9,                         // 0x8DC test rcx, rcx
    0x74, 0x07,                               // 0x8DF je +7  -> 0x8E8
    0x48, 0xC7, 0x01, 0x00, 0x00, 0x00, 0x00, // 0x8E1 mov qword [rcx], 0
    0xB8, 0x01, 0x00, 0x00, 0x00,             // 0x8E8 mov eax, 1 (BOOL TRUE)
    0xC3,                                     // 0x8ED ret

    // --- GetSystemTimes (offset 0x8EE, 30 bytes) --------------
    // Win32:
    //   BOOL GetSystemTimes(PFILETIME IdleTime,       // rcx
    //                       PFILETIME KernelTime,     // rdx
    //                       PFILETIME UserTime);      // r8
    // v0 zeros rcx and rdx pointers when non-null, returns BOOL
    // TRUE. r8 (UserTime) is left untouched — stub-size budget,
    // and UserTime is less commonly consulted than Idle/Kernel.
    0x48, 0x85, 0xC9,                         // 0x8EE test rcx, rcx
    0x74, 0x07,                               // 0x8F1 je +7 -> 0x8FA
    0x48, 0xC7, 0x01, 0x00, 0x00, 0x00, 0x00, // 0x8F3 mov qword [rcx], 0
    0x48, 0x85, 0xD2,                         // 0x8FA test rdx, rdx
    0x74, 0x07,                               // 0x8FD je +7 -> 0x906
    0x48, 0xC7, 0x02, 0x00, 0x00, 0x00, 0x00, // 0x8FF mov qword [rdx], 0
    0xB8, 0x01, 0x00, 0x00, 0x00,             // 0x906 mov eax, 1 (BOOL TRUE)
    0xC3,                                     // 0x90B ret

    // --- GlobalMemoryStatusEx (offset 0x90C, 16 bytes) --------
    // Win32: BOOL GlobalMemoryStatusEx(LPMEMORYSTATUSEX lpBuffer).
    // rcx = user pointer. Maps to SYS_MEM_STATUS which does the
    // struct validation + populate server-side. Returns BOOL
    // TRUE on syscall success (rax=0), FALSE on failure (rax=-1).
    // The `inc rax` flips 0↔1 and -1↔0, which is exactly the
    // Win32 BOOL mapping we want. Saves rdi across the syscall
    // (callee-saved in Win64 ABI).
    0x57,                         // 0x90C push rdi
    0x48, 0x89, 0xCF,             // 0x90D mov rdi, rcx
    0xB8, 0x2F, 0x00, 0x00, 0x00, // 0x910 mov eax, 47 ; SYS_MEM_STATUS
    0xCD, 0x80,                   // 0x915 int 0x80
    0x48, 0xFF, 0xC0,             // 0x917 inc rax     ; 0→1, -1→0
    0x5F,                         // 0x91A pop rdi
    0xC3,                         // 0x91B ret

    // --- WaitForMultipleObjects (offset 0x91C, 24 bytes) ------
    // Win32:
    //   DWORD WaitForMultipleObjects(DWORD nCount,       // rcx
    //                                const HANDLE *,     // rdx
    //                                BOOL bWaitAll,      // r8
    //                                DWORD dwMs);        // r9
    // DuetOS: SYS_WAIT_MULTI with count=rdi, arr=rsi,
    // waitAll=rdx, timeout_ms=r10. Saves rdi+rsi across the
    // syscall (both callee-saved in Win64 ABI).
    0x57,                         // 0x91C push rdi
    0x56,                         // 0x91D push rsi
    0x48, 0x89, 0xCF,             // 0x91E mov rdi, rcx  ; count
    0x48, 0x89, 0xD6,             // 0x921 mov rsi, rdx  ; handle array
    0x4C, 0x89, 0xC2,             // 0x924 mov rdx, r8   ; waitAll
    0x4D, 0x89, 0xCA,             // 0x927 mov r10, r9   ; timeout
    0xB8, 0x30, 0x00, 0x00, 0x00, // 0x92A mov eax, 48   ; SYS_WAIT_MULTI
    0xCD, 0x80,                   // 0x92F int 0x80
    0x5E,                         // 0x931 pop rsi
    0x5F,                         // 0x932 pop rdi
    0xC3,                         // 0x933 ret

    // === Batch 52 =============================================

    // --- GetSystemInfo (offset 0x934, 13 bytes) ---------------
    // Win32: void GetSystemInfo(LPSYSTEM_INFO lpSystemInfo).
    // rcx = user ptr. Maps to SYS_SYSTEM_INFO. Aliased by
    // GetNativeSystemInfo (same shape; WoW64 distinction doesn't
    // apply — we're native x86_64 already).
    0x57,                         // 0x934 push rdi
    0x48, 0x89, 0xCF,             // 0x935 mov rdi, rcx
    0xB8, 0x31, 0x00, 0x00, 0x00, // 0x938 mov eax, 49 ; SYS_SYSTEM_INFO
    0xCD, 0x80,                   // 0x93D int 0x80
    0x5F,                         // 0x93F pop rdi
    0xC3,                         // 0x940 ret

    // --- OutputDebugStringW (offset 0x941, 13 bytes) ---------
    // Win32: void OutputDebugStringW(LPCWSTR lpOutputString).
    // rcx = NUL-terminated UTF-16LE string. Maps to
    // SYS_DEBUG_PRINTW (kernel strips to ASCII + emits).
    0x57,                         // 0x941 push rdi
    0x48, 0x89, 0xCF,             // 0x942 mov rdi, rcx
    0xB8, 0x32, 0x00, 0x00, 0x00, // 0x945 mov eax, 50 ; SYS_DEBUG_PRINTW
    0xCD, 0x80,                   // 0x94A int 0x80
    0x5F,                         // 0x94C pop rdi
    0xC3,                         // 0x94D ret

    // --- FormatMessageA (offset 0x94E, 32 bytes) --------------
    // Win32:
    //   DWORD FormatMessageA(DWORD flags, LPCVOID src, DWORD msgId,
    //                        DWORD lang, LPSTR buf, DWORD nSize,
    //                        va_list *args);
    // v0: writes "Error.\n\0" (7 chars + NUL) into lpBuffer if
    // non-NULL, returns 7. If lpBuffer is NULL, returns 0.
    // This lets callers that print the buffer see a stable
    // placeholder instead of random memory, and callers that
    // gate on "non-zero return means message decoded" take the
    // happy path. No flag handling — a follow-up can add
    // FORMAT_MESSAGE_ALLOCATE_BUFFER + hex-formatting of msgId.
    0x48, 0x8B, 0x44, 0x24, 0x28, // 0x94E mov rax, [rsp+0x28]   ; lpBuffer
    0x48, 0x85, 0xC0,             // 0x953 test rax, rax
    0x74, 0x13,                   // 0x956 je +19 -> 0x96B (null_buf)
    // Write "Erro" (0x6F727245) then "r.\n\0" (0x000A2E72) at [rax+4]
    0xC7, 0x00, 0x45, 0x72, 0x72, 0x6F,       // 0x958 mov dword [rax], 0x6F727245
    0xC7, 0x40, 0x04, 0x72, 0x2E, 0x0A, 0x00, // 0x95E mov dword [rax+4], 0x000A2E72
    0xB8, 0x07, 0x00, 0x00, 0x00,             // 0x965 mov eax, 7 (chars written)
    0xC3,                                     // 0x96A ret
    // null_buf path
    0x31, 0xC0, // 0x96B xor eax, eax
    0xC3,       // 0x96D ret

    // --- GetConsoleScreenBufferInfo (offset 0x96E, 54 bytes) --
    // Win32:
    //   BOOL GetConsoleScreenBufferInfo(HANDLE hOut,
    //                                    PCONSOLE_SCREEN_BUFFER_INFO p);
    // rdx = buffer. 22-byte layout:
    //   0x00 COORD dwSize (80, 25)
    //   0x04 COORD dwCursorPosition (0, 0)
    //   0x08 WORD  wAttributes (0x07 white-on-black)
    //   0x0A SMALL_RECT srWindow (L=0, T=0, R=79, B=24)
    //   0x12 COORD dwMaximumWindowSize (80, 25)
    // Returns TRUE unless rdx is NULL.
    0x48, 0x85, 0xD2, // 0x96E test rdx, rdx
    0x74, 0x2E,       // 0x971 je +46 -> 0x9A1 (fail)
    // dwSize at [rdx] = (X=80, Y=25) -> 0x00190050
    0xC7, 0x02, 0x50, 0x00, 0x19, 0x00, // 0x973 mov dword [rdx], 0x00190050
    // dwCursorPosition at [rdx+4] = 0
    0xC7, 0x42, 0x04, 0x00, 0x00, 0x00, 0x00, // 0x979 mov dword [rdx+4], 0
    // wAttributes at [rdx+8] = 0x0007
    0x66, 0xC7, 0x42, 0x08, 0x07, 0x00, // 0x980 mov word [rdx+8], 7
    // srWindow L,T at [rdx+10] = 0
    0xC7, 0x42, 0x0A, 0x00, 0x00, 0x00, 0x00, // 0x986 mov dword [rdx+10], 0
    // srWindow R,B at [rdx+14] = (79, 24) -> 0x0018004F
    0xC7, 0x42, 0x0E, 0x4F, 0x00, 0x18, 0x00, // 0x98D mov dword [rdx+14], 0x0018004F
    // dwMaximumWindowSize at [rdx+18] = (80, 25) -> 0x00190050
    0xC7, 0x42, 0x12, 0x50, 0x00, 0x19, 0x00, // 0x994 mov dword [rdx+18], 0x00190050
    0xB8, 0x01, 0x00, 0x00, 0x00,             // 0x99B mov eax, 1 (BOOL TRUE)
    0xC3,                                     // 0x9A0 ret
    0x31, 0xC0,                               // 0x9A1 xor eax, eax
    0xC3,                                     // 0x9A3 ret

    // === Batch 53 =============================================

    // --- RaiseException (offset 0x9A4, 9 bytes) ---------------
    // Win32:
    //   void RaiseException(DWORD dwExceptionCode, DWORD flags,
    //                       DWORD nArgs, const ULONG_PTR *args);
    // v0 has no SEH, so any RaiseException is fatal — route to
    // SYS_EXIT with rcx (exception code) as the exit code.
    0x48, 0x89, 0xCF, // 0x9A4 mov rdi, rcx
    0x31, 0xC0,       // 0x9A7 xor eax, eax
    0xCD, 0x80,       // 0x9A9 int 0x80
    0x0F, 0x0B,       // 0x9AB ud2 ; [[noreturn]]

    // --- DecodePointer / EncodePointer (offset 0x9AD, 4 bytes) --
    // Win32: PVOID DecodePointer(PVOID Ptr); EncodePointer same.
    // Windows uses these for process-wide XOR-with-a-secret
    // obfuscation of function pointers (ASLR defense-in-depth).
    // v0 has no process-wide secret → identity preserves the
    // Encode/Decode round-trip used by MSVC's CRT.
    0x48, 0x89, 0xC8, // 0x9AD mov rax, rcx
    0xC3,             // 0x9B0 ret

    // === Batch 54 =============================================

    // --- CreateSemaphoreW (offset 0x9B1, 27 bytes) ------------
    // Win32:
    //   HANDLE CreateSemaphoreW(LPSECURITY_ATTRIBUTES, // rcx (ignored)
    //                            LONG lInitial,        // rdx
    //                            LONG lMaximum,        // r8
    //                            LPCWSTR lpName);      // r9 (ignored)
    // Maps to SYS_SEM_CREATE(initial, max). Translates kernel
    // -1 to Win32 NULL handle. CreateSemaphoreA + CreateSemaphoreExW
    // are wired to the same stub.
    0x57,                         // 0x9B1 push rdi
    0x56,                         // 0x9B2 push rsi
    0x48, 0x89, 0xD7,             // 0x9B3 mov rdi, rdx     ; initial
    0x4C, 0x89, 0xC6,             // 0x9B6 mov rsi, r8      ; max
    0xB8, 0x33, 0x00, 0x00, 0x00, // 0x9B9 mov eax, 51      ; SYS_SEM_CREATE
    0xCD, 0x80,                   // 0x9BE int 0x80
    0x48, 0x83, 0xF8, 0xFF,       // 0x9C0 cmp rax, -1
    0x75, 0x03,                   // 0x9C4 jne +3 -> 0x9C9 (pop rsi)
    0x31, 0xC0,                   // 0x9C6 xor eax, eax
    0x90,                         // 0x9C8 nop (padding so jne target lands at 0x9C9)
    0x5E,                         // 0x9C9 pop rsi
    0x5F,                         // 0x9CA pop rdi
    0xC3,                         // 0x9CB ret

    // --- ReleaseSemaphore (offset 0x9CC, 29 bytes) ------------
    // Win32:
    //   BOOL ReleaseSemaphore(HANDLE hSem,           // rcx
    //                          LONG lReleaseCount,    // rdx
    //                          LPLONG lpPreviousCount // r8 (optional)
    //                          );
    // int 0x80 preserves r8 (isr_common pushes/pops all GPRs)
    // so we can still read it after the syscall without a save.
    0x57,                         // 0x9CC push rdi
    0x56,                         // 0x9CD push rsi
    0x48, 0x89, 0xCF,             // 0x9CE mov rdi, rcx
    0x48, 0x89, 0xD6,             // 0x9D1 mov rsi, rdx
    0xB8, 0x34, 0x00, 0x00, 0x00, // 0x9D4 mov eax, 52      ; SYS_SEM_RELEASE
    0xCD, 0x80,                   // 0x9D9 int 0x80
    0x4D, 0x85, 0xC0,             // 0x9DB test r8, r8      ; lpPreviousCount != NULL?
    0x74, 0x03,                   // 0x9DE je +3 -> 0x9E3 (inc rax)
    0x41, 0x89, 0x00,             // 0x9E0 mov [r8], eax
    0x48, 0xFF, 0xC0,             // 0x9E3 inc rax          ; -1 -> 0 FALSE; prev -> prev+1 TRUE
    0x5E,                         // 0x9E6 pop rsi
    0x5F,                         // 0x9E7 pop rdi
    0xC3,                         // 0x9E8 ret

    // --- WaitForSingleObject v3 (offset 0x9E9, 94 bytes) ------
    // v2 + semaphore range (0x500..0x507 → SYS_SEM_WAIT).
    // Bumps the `kOffWaitForObj2` aliases over to v3 via the
    // import table so every caller gets semaphore-aware wait.
    0x57,                               // 0x9E9 push rdi
    0x56,                               // 0x9EA push rsi
    0x48, 0x89, 0xC8,                   // 0x9EB mov rax, rcx
    0x48, 0x2D, 0x00, 0x02, 0x00, 0x00, // 0x9EE sub rax, 0x200
    0x48, 0x83, 0xF8, 0x08,             // 0x9F4 cmp rax, 8
    0x72, 0x1D,                         // 0x9F8 jb .mutex (+29 -> 0xA17)
    0x48, 0x2D, 0x00, 0x01, 0x00, 0x00, // 0x9FA sub rax, 0x100 (total 0x300 relative)
    0x48, 0x83, 0xF8, 0x08,             // 0xA00 cmp rax, 8
    0x72, 0x21,                         // 0xA04 jb .event (+33 -> 0xA27)
    0x48, 0x2D, 0x00, 0x02, 0x00, 0x00, // 0xA06 sub rax, 0x200 (total 0x500 relative)
    0x48, 0x83, 0xF8, 0x08,             // 0xA0C cmp rax, 8
    0x72, 0x25,                         // 0xA10 jb .sem (+37 -> 0xA37)
    // .pseudo path (handle not in any known range)
    0x31, 0xC0, // 0xA12 xor eax, eax   ; WAIT_OBJECT_0 for unknown
    0x5E,       // 0xA14 pop rsi
    0x5F,       // 0xA15 pop rdi
    0xC3,       // 0xA16 ret
    // .mutex (offset 0xA17)
    0x48, 0x89, 0xCF,             // 0xA17 mov rdi, rcx
    0x48, 0x89, 0xD6,             // 0xA1A mov rsi, rdx
    0xB8, 0x1A, 0x00, 0x00, 0x00, // 0xA1D mov eax, 26 (SYS_MUTEX_WAIT)
    0xCD, 0x80,                   // 0xA22 int 0x80
    0x5E,                         // 0xA24 pop rsi
    0x5F,                         // 0xA25 pop rdi
    0xC3,                         // 0xA26 ret
    // .event (offset 0xA27)
    0x48, 0x89, 0xCF,             // 0xA27 mov rdi, rcx
    0x48, 0x89, 0xD6,             // 0xA2A mov rsi, rdx
    0xB8, 0x21, 0x00, 0x00, 0x00, // 0xA2D mov eax, 33 (SYS_EVENT_WAIT)
    0xCD, 0x80,                   // 0xA32 int 0x80
    0x5E,                         // 0xA34 pop rsi
    0x5F,                         // 0xA35 pop rdi
    0xC3,                         // 0xA36 ret
    // .sem (offset 0xA37)
    0x48, 0x89, 0xCF,             // 0xA37 mov rdi, rcx
    0x48, 0x89, 0xD6,             // 0xA3A mov rsi, rdx
    0xB8, 0x35, 0x00, 0x00, 0x00, // 0xA3D mov eax, 53 (SYS_SEM_WAIT)
    0xCD, 0x80,                   // 0xA42 int 0x80
    0x5E,                         // 0xA44 pop rsi
    0x5F,                         // 0xA45 pop rdi
    0xC3,                         // 0xA46 ret

    // === Batch 57 =============================================

    // --- WaitForSingleObject v4 (offset 0xA47, 122 bytes) -----
    // v3 + a fourth range (0x400..0x407, thread handles) that
    // dispatches to SYS_THREAD_WAIT. Now WaitForSingleObject on
    // a CreateThread handle actually blocks until the thread
    // exits rather than the v3 pseudo-signaled fast path.
    //
    // Dispatch order is still "cheapest first": mutex, event,
    // thread, semaphore. Unknown handles fall through to the
    // pseudo-signaled path for backward compatibility.
    0x57,                               // 0xA47 push rdi
    0x56,                               // 0xA48 push rsi
    0x48, 0x89, 0xC8,                   // 0xA49 mov rax, rcx
    0x48, 0x2D, 0x00, 0x02, 0x00, 0x00, // 0xA4C sub rax, 0x200
    0x48, 0x83, 0xF8, 0x08,             // 0xA52 cmp rax, 8
    0x72, 0x29,                         // 0xA56 jb .mutex (+41 -> 0xA81)
    0x48, 0x2D, 0x00, 0x01, 0x00, 0x00, // 0xA58 sub rax, 0x100 (H - 0x300)
    0x48, 0x83, 0xF8, 0x08,             // 0xA5E cmp rax, 8
    0x72, 0x2D,                         // 0xA62 jb .event (+45 -> 0xA91)
    0x48, 0x2D, 0x00, 0x01, 0x00, 0x00, // 0xA64 sub rax, 0x100 (H - 0x400)
    0x48, 0x83, 0xF8, 0x08,             // 0xA6A cmp rax, 8
    0x72, 0x31,                         // 0xA6E jb .thread (+49 -> 0xAA1)
    0x48, 0x2D, 0x00, 0x01, 0x00, 0x00, // 0xA70 sub rax, 0x100 (H - 0x500)
    0x48, 0x83, 0xF8, 0x08,             // 0xA76 cmp rax, 8
    0x72, 0x35,                         // 0xA7A jb .sem (+53 -> 0xAB1)
    // .pseudo: unknown handle -> WAIT_OBJECT_0
    0x31, 0xC0, // 0xA7C xor eax, eax
    0x5E,       // 0xA7E pop rsi
    0x5F,       // 0xA7F pop rdi
    0xC3,       // 0xA80 ret
    // .mutex (offset 0xA81)
    0x48, 0x89, 0xCF,             // 0xA81 mov rdi, rcx
    0x48, 0x89, 0xD6,             // 0xA84 mov rsi, rdx
    0xB8, 0x1A, 0x00, 0x00, 0x00, // 0xA87 mov eax, 26 (SYS_MUTEX_WAIT)
    0xCD, 0x80,                   // 0xA8C int 0x80
    0x5E,                         // 0xA8E pop rsi
    0x5F,                         // 0xA8F pop rdi
    0xC3,                         // 0xA90 ret
    // .event (offset 0xA91)
    0x48, 0x89, 0xCF,             // 0xA91 mov rdi, rcx
    0x48, 0x89, 0xD6,             // 0xA94 mov rsi, rdx
    0xB8, 0x21, 0x00, 0x00, 0x00, // 0xA97 mov eax, 33 (SYS_EVENT_WAIT)
    0xCD, 0x80,                   // 0xA9C int 0x80
    0x5E,                         // 0xA9E pop rsi
    0x5F,                         // 0xA9F pop rdi
    0xC3,                         // 0xAA0 ret
    // .thread (offset 0xAA1)
    0x48, 0x89, 0xCF,             // 0xAA1 mov rdi, rcx
    0x48, 0x89, 0xD6,             // 0xAA4 mov rsi, rdx
    0xB8, 0x36, 0x00, 0x00, 0x00, // 0xAA7 mov eax, 54 (SYS_THREAD_WAIT)
    0xCD, 0x80,                   // 0xAAC int 0x80
    0x5E,                         // 0xAAE pop rsi
    0x5F,                         // 0xAAF pop rdi
    0xC3,                         // 0xAB0 ret
    // .sem (offset 0xAB1)
    0x48, 0x89, 0xCF,             // 0xAB1 mov rdi, rcx
    0x48, 0x89, 0xD6,             // 0xAB4 mov rsi, rdx
    0xB8, 0x35, 0x00, 0x00, 0x00, // 0xAB7 mov eax, 53 (SYS_SEM_WAIT)
    0xCD, 0x80,                   // 0xABC int 0x80
    0x5E,                         // 0xABE pop rsi
    0x5F,                         // 0xABF pop rdi
    0xC3,                         // 0xAC0 ret

    // === Batch 58 =============================================

    // --- GetStartupInfo{W,A} (offset 0xAC1, 24 bytes) ---------
    // Win32: void GetStartupInfo{A,W}(LPSTARTUPINFO{A,W} p).
    // STARTUPINFO is 104 bytes (both A and W) with cb at offset
    // 0. v0 populates a zero-filled struct with cb = 104 and
    // leaves every other field zero — programs that gate reads
    // on dwFlags (= 0 → no STARTF_USESTDHANDLES, etc.) see a
    // consistent "no startup info" state and don't read stale
    // stack memory. Previously aliased to kOffCritSecNop which
    // left the caller's buffer uninitialised — real Windows
    // code crashes reading lpDesktop / hStdInput as a wild
    // pointer.
    //
    // Win64: rdi is callee-saved; saved + restored around the
    // rep stosq. rcx is caller-saved, but we pop it back into
    // rcx after the rep stosq so [rcx] can write cb — cheaper
    // than holding it in rsi.
    0x57,                               // 0xAC1 push rdi
    0x48, 0x89, 0xCF,                   // 0xAC2 mov rdi, rcx
    0x51,                               // 0xAC5 push rcx
    0x31, 0xC0,                         // 0xAC6 xor eax, eax
    0xB9, 0x0D, 0x00, 0x00, 0x00,       // 0xAC8 mov ecx, 13  ; 104/8 qwords
    0xF3, 0x48, 0xAB,                   // 0xACD rep stosq
    0x59,                               // 0xAD0 pop rcx
    0xC7, 0x01, 0x68, 0x00, 0x00, 0x00, // 0xAD1 mov dword [rcx], 104 (cb)
    0x5F,                               // 0xAD7 pop rdi
    0xC3,                               // 0xAD8 ret

    // === Batch 59 =============================================

    // --- GetExitCodeThread real (offset 0xAD9, 20 bytes) ------
    // Win32: BOOL GetExitCodeThread(HANDLE=rcx, LPDWORD Exit=rdx).
    // Supersedes the batch-10 stub at kOffGetExitCodeThread which
    // hard-coded STILL_ACTIVE. Routes to SYS_THREAD_EXIT_CODE
    // which reads Process.win32_threads[slot].exit_code — kept
    // at STILL_ACTIVE (0x103) until the task's SYS_EXIT path
    // stashes the real rdi value there.
    //
    // Returns BOOL TRUE always. If the handle is invalid the
    // syscall returns -1 and we write -1 into *Exit — callers
    // that interpret the BOOL will succeed, callers that look at
    // the numeric exit code will see 0xFFFFFFFF (bogus but
    // non-fatal).
    0x57,                         // 0xAD9 push rdi
    0x48, 0x89, 0xCF,             // 0xADA mov rdi, rcx
    0xB8, 0x37, 0x00, 0x00, 0x00, // 0xADD mov eax, 55 (SYS_THREAD_EXIT_CODE)
    0xCD, 0x80,                   // 0xAE2 int 0x80
    0x89, 0x02,                   // 0xAE4 mov [rdx], eax
    0xB8, 0x01, 0x00, 0x00, 0x00, // 0xAE6 mov eax, 1 (BOOL TRUE)
    0x5F,                         // 0xAEB pop rdi
    0xC3,                         // 0xAEC ret

    // === Batch 60 =============================================

    // --- InterlockedAnd (offset 0xAED, 16 bytes) --------------
    // Win32: LONG InterlockedAnd(LONG volatile *Target=rcx,
    //                             LONG Value=edx).
    // Returns the ORIGINAL value of *Target. Standard CAS loop:
    //   do { old = *t; new = old & v; } while (!cas(t, old, new));
    // LOCK CMPXCHG is serialised across CPUs and acts as a full
    // barrier — correct under both SMP and single-CPU with a
    // preemptive timer interrupt.
    0x8B, 0x01,                   // 0xAED mov eax, [rcx]       ; old
    0x41, 0x89, 0xC0,             // 0xAEF mov r8d, eax         ; new = old
    0x41, 0x21, 0xD0,             // 0xAF2 and r8d, edx         ; new &= value
    0xF0, 0x44, 0x0F, 0xB1, 0x01, // 0xAF5 lock cmpxchg [rcx], r8d
    0x75, 0xF1,                   // 0xAFA jne -15 -> 0xAED (retry)
    0xC3,                         // 0xAFC ret

    // --- InterlockedOr (offset 0xAFD, 16 bytes) ---------------
    0x8B, 0x01,                   // 0xAFD mov eax, [rcx]
    0x41, 0x89, 0xC0,             // 0xAFF mov r8d, eax
    0x41, 0x09, 0xD0,             // 0xB02 or r8d, edx
    0xF0, 0x44, 0x0F, 0xB1, 0x01, // 0xB05 lock cmpxchg [rcx], r8d
    0x75, 0xF1,                   // 0xB0A jne -15 -> 0xAFD
    0xC3,                         // 0xB0C ret

    // --- InterlockedXor (offset 0xB0D, 16 bytes) --------------
    0x8B, 0x01,                   // 0xB0D mov eax, [rcx]
    0x41, 0x89, 0xC0,             // 0xB0F mov r8d, eax
    0x41, 0x31, 0xD0,             // 0xB12 xor r8d, edx
    0xF0, 0x44, 0x0F, 0xB1, 0x01, // 0xB15 lock cmpxchg [rcx], r8d
    0x75, 0xF1,                   // 0xB1A jne -15 -> 0xB0D
    0xC3,                         // 0xB1C ret

    // --- InterlockedAnd64 (offset 0xB1D, 17 bytes) ------------
    // 64-bit operand — REX.W on all four instructions.
    0x48, 0x8B, 0x01,             // 0xB1D mov rax, [rcx]
    0x49, 0x89, 0xC0,             // 0xB20 mov r8, rax
    0x49, 0x21, 0xD0,             // 0xB23 and r8, rdx
    0xF0, 0x4C, 0x0F, 0xB1, 0x01, // 0xB26 lock cmpxchg [rcx], r8
    0x75, 0xF0,                   // 0xB2B jne -16 -> 0xB1D
    0xC3,                         // 0xB2D ret

    // --- InterlockedOr64 (offset 0xB2E, 17 bytes) -------------
    0x48, 0x8B, 0x01,             // 0xB2E mov rax, [rcx]
    0x49, 0x89, 0xC0,             // 0xB31 mov r8, rax
    0x49, 0x09, 0xD0,             // 0xB34 or r8, rdx
    0xF0, 0x4C, 0x0F, 0xB1, 0x01, // 0xB37 lock cmpxchg [rcx], r8
    0x75, 0xF0,                   // 0xB3C jne -16 -> 0xB2E
    0xC3,                         // 0xB3E ret

    // --- InterlockedXor64 (offset 0xB3F, 17 bytes) ------------
    0x48, 0x8B, 0x01,             // 0xB3F mov rax, [rcx]
    0x49, 0x89, 0xC0,             // 0xB42 mov r8, rax
    0x49, 0x31, 0xD0,             // 0xB45 xor r8, rdx
    0xF0, 0x4C, 0x0F, 0xB1, 0x01, // 0xB48 lock cmpxchg [rcx], r8
    0x75, 0xF0,                   // 0xB4D jne -16 -> 0xB3F
    0xC3,                         // 0xB4F ret

    // === Batch 61 ==============================================

    // --- EnterCriticalSection (offset 0xB50, 50 bytes) --------
    // Win32: void EnterCriticalSection(LPCRITICAL_SECTION = rcx).
    //
    // CRITICAL_SECTION layout we impose on the caller's 40-byte
    // struct (InitializeCriticalSection already zero-fills it):
    //   [rcx+0x00] u64 owner_tid    (0 = unheld)
    //   [rcx+0x08] u64 recursion
    //   [rcx+0x10..0x28]            unused
    //
    // Algorithm:
    //   1. rbx <- rcx   (rbx is callee-saved in Win64; we need a
    //                   register that survives int 0x80).
    //   2. r8  <- our task id via SYS_GETPID.
    //   3. lock cmpxchg: if owner == 0, owner := r8. ZF=1 -> took.
    //   4. If not, check owner == r8 (recursive acquire).
    //   5. Otherwise SYS_YIELD and retry.
    //
    // Win64 ABI: rbx and rsi/rdi are callee-saved; the int 0x80
    // syscall path preserves all but rax. We push/pop rbx around
    // the body.
    0x53,             // 0xB50 push rbx
    0x48, 0x89, 0xCB, // 0xB51 mov rbx, rcx            ; save lpcs
    0x6A, 0x01,       // 0xB54 push 1
    0x58,             // 0xB56 pop rax                 ; rax = SYS_GETPID
    0xCD, 0x80,       // 0xB57 int 0x80                ; rax = TID
    0x49, 0x89, 0xC0, // 0xB59 mov r8, rax             ; r8 = our TID
    // .retry (abs 0xB5C):
    0x31, 0xC0,                   // 0xB5C xor eax, eax            ; expected = 0
    0xF0, 0x4C, 0x0F, 0xB1, 0x03, // 0xB5E lock cmpxchg [rbx], r8
    0x74, 0x0C,                   // 0xB63 je .took (+0x0C -> 0xB71)
    0x4C, 0x39, 0x03,             // 0xB65 cmp [rbx], r8           ; owner == us?
    0x74, 0x11,                   // 0xB68 je .recursive (+0x11 -> 0xB7B)
    0x6A, 0x03,                   // 0xB6A push 3
    0x58,                         // 0xB6C pop rax                 ; rax = SYS_YIELD
    0xCD, 0x80,                   // 0xB6D int 0x80
    0xEB, 0xEB,                   // 0xB6F jmp .retry (-0x15 -> 0xB5C)
    // .took (abs 0xB71): first acquire — recursion := 1.
    0x48, 0xC7, 0x43, 0x08, 0x01, 0x00, 0x00, 0x00, // 0xB71 mov qword [rbx+8], 1
    0x5B,                                           // 0xB79 pop rbx
    0xC3,                                           // 0xB7A ret
    // .recursive (abs 0xB7B): already held by us — bump.
    0x48, 0xFF, 0x43, 0x08, // 0xB7B inc qword [rbx+8]
    0x5B,                   // 0xB7F pop rbx
    0xC3,                   // 0xB80 ret

    // --- LeaveCriticalSection (offset 0xB81, 14 bytes) --------
    // Win32: void LeaveCriticalSection(LPCRITICAL_SECTION = rcx).
    // Decrement recursion; on zero, clear owner so the next
    // acquire wins the cmpxchg. Caller is assumed to hold — a
    // bogus caller underflows recursion and never re-zeroes
    // owner (matches Windows: "bad things happen").
    0x48, 0xFF, 0x49, 0x08,                   // 0xB81 dec qword [rcx+8]
    0x75, 0x07,                               // 0xB85 jnz .done (+7 -> 0xB8E)
    0x48, 0xC7, 0x01, 0x00, 0x00, 0x00, 0x00, // 0xB87 mov qword [rcx], 0
    // .done (abs 0xB8E):
    0xC3, // 0xB8E ret

    // === Batch 62 ==============================================

    // --- InitializeSRWLock (offset 0xB8F, 6 bytes) ------------
    // Win32: void InitializeSRWLock(PSRWLOCK = rcx). Zero the
    // 8-byte slot. Critical even though SRWLOCKs are sometimes
    // static-init'd to zero — stack-allocated SRWLOCKs hold
    // garbage until explicitly initialised.
    0x31, 0xC0,       // 0xB8F xor eax, eax
    0x48, 0x89, 0x01, // 0xB91 mov qword [rcx], rax
    0xC3,             // 0xB94 ret

    // --- AcquireSRWLockExclusive (offset 0xB95, 30 bytes) -----
    // Win32: void AcquireSRWLockExclusive(PSRWLOCK = rcx). Same
    // spin-yield pattern as EnterCriticalSection but no
    // recursion tracking — SRW locks are NOT reentrant. If a
    // thread tries to acquire the same SRWLOCK twice the second
    // call deadlocks. That's the documented Win32 contract.
    0x53,             // 0xB95 push rbx
    0x48, 0x89, 0xCB, // 0xB96 mov rbx, rcx
    0x6A, 0x01,       // 0xB99 push 1
    0x58,             // 0xB9B pop rax                 ; SYS_GETPID
    0xCD, 0x80,       // 0xB9C int 0x80                ; rax = TID
    0x49, 0x89, 0xC0, // 0xB9E mov r8, rax             ; r8 = our TID
    // .retry (abs 0xBA1):
    0x31, 0xC0,                   // 0xBA1 xor eax, eax            ; expected = 0
    0xF0, 0x4C, 0x0F, 0xB1, 0x03, // 0xBA3 lock cmpxchg [rbx], r8
    0x74, 0x07,                   // 0xBA8 je .done (+7 -> 0xBB1)
    0x6A, 0x03,                   // 0xBAA push 3
    0x58,                         // 0xBAC pop rax                 ; SYS_YIELD
    0xCD, 0x80,                   // 0xBAD int 0x80
    0xEB, 0xF0,                   // 0xBAF jmp .retry (-16 -> 0xBA1)
    // .done (abs 0xBB1):
    0x5B, // 0xBB1 pop rbx
    0xC3, // 0xBB2 ret

    // --- ReleaseSRWLockExclusive (offset 0xBB3, 6 bytes) ------
    // Win32: void ReleaseSRWLockExclusive(PSRWLOCK = rcx). Zero
    // the slot so the next acquirer wins the cmpxchg. `mov` is
    // atomic on aligned 8-byte stores on x86_64; no `lock`
    // prefix needed.
    0x31, 0xC0,       // 0xBB3 xor eax, eax
    0x48, 0x89, 0x01, // 0xBB5 mov qword [rcx], rax
    0xC3,             // 0xBB8 ret

    // --- TryAcquireSRWLockExclusive (offset 0xBB9, 22 bytes) --
    // Win32: BOOLEAN TryAcquireSRWLockExclusive(PSRWLOCK = rcx).
    // Single cmpxchg; no spin. Returns 1 on success, 0 on
    // contention. Uses setz to materialise ZF as the low byte of
    // rax; the existing binding to kOffReturnOne (always 1) was
    // dishonest and masked real contention.
    0x6A, 0x01,                   // 0xBB9 push 1
    0x58,                         // 0xBBB pop rax                 ; SYS_GETPID
    0xCD, 0x80,                   // 0xBBC int 0x80                ; rax = TID
    0x49, 0x89, 0xC0,             // 0xBBE mov r8, rax             ; r8 = our TID
    0x31, 0xC0,                   // 0xBC1 xor eax, eax            ; expected = 0
    0xF0, 0x4C, 0x0F, 0xB1, 0x01, // 0xBC3 lock cmpxchg [rcx], r8
    0x0F, 0x94, 0xC0,             // 0xBC8 setz al                 ; al = ZF
    0x0F, 0xB6, 0xC0,             // 0xBCB movzx eax, al           ; eax = BOOL
    0xC3,                         // 0xBCE ret

    // === Batch 63 ==============================================

    // --- RtlTryEnterCriticalSection (offset 0xBCF, 56 bytes) --
    // Win32: BOOL TryEnterCriticalSection(LPCRITICAL_SECTION = rcx).
    // Same CRITICAL_SECTION layout as EnterCriticalSection. Try
    // acquire once; on success (including recursive re-acquire)
    // return 1, otherwise return 0 WITHOUT blocking. Previously
    // bound to kOffReturnOne which always claimed success.
    0x53,                         // 0xBCF push rbx
    0x48, 0x89, 0xCB,             // 0xBD0 mov rbx, rcx
    0x6A, 0x01,                   // 0xBD3 push 1
    0x58,                         // 0xBD5 pop rax                 ; SYS_GETPID
    0xCD, 0x80,                   // 0xBD6 int 0x80                ; rax = TID
    0x49, 0x89, 0xC0,             // 0xBD8 mov r8, rax             ; r8 = TID
    0x31, 0xC0,                   // 0xBDB xor eax, eax            ; expected = 0
    0xF0, 0x4C, 0x0F, 0xB1, 0x03, // 0xBDD lock cmpxchg [rbx], r8
    0x74, 0x09,                   // 0xBE2 je .took (+9 -> 0xBED)
    0x4C, 0x39, 0x03,             // 0xBE4 cmp [rbx], r8
    0x74, 0x13,                   // 0xBE7 je .recursive (+0x13 -> 0xBFC)
    0x31, 0xC0,                   // 0xBE9 xor eax, eax            ; not-taken: return 0
    0x5B,                         // 0xBEB pop rbx
    0xC3,                         // 0xBEC ret
    // .took (abs 0xBED):
    0x48, 0xC7, 0x43, 0x08, 0x01, 0x00, 0x00, 0x00, // 0xBED mov qword [rbx+8], 1
    0xB8, 0x01, 0x00, 0x00, 0x00,                   // 0xBF5 mov eax, 1
    0x5B,                                           // 0xBFA pop rbx
    0xC3,                                           // 0xBFB ret
    // .recursive (abs 0xBFC):
    0x48, 0xFF, 0x43, 0x08,       // 0xBFC inc qword [rbx+8]
    0xB8, 0x01, 0x00, 0x00, 0x00, // 0xC00 mov eax, 1
    0x5B,                         // 0xC05 pop rbx
    0xC3,                         // 0xC06 ret

    // === Batch 64 ==============================================

    // --- SetUnhandledExceptionFilter (offset 0xC07, 12 bytes) -
    // Win32: LPTOP_LEVEL_EXCEPTION_FILTER SetUnhandledExceptionFilter(
    //          LPTOP_LEVEL_EXCEPTION_FILTER newFilter = rcx);
    // Returns the previous filter. xchg on a memory operand is
    // implicitly `lock`ed on x86, so this is a single atomic swap:
    // caller's rcx lands in the proc-env slot; the previous value
    // ends up in rcx, which we copy into rax to return.
    //
    // The imm32 0x65000600 fits in 32 bits and `mov eax, imm32`
    // zero-extends to rax — saves 5 bytes vs `mov rax, imm64`.
    0xB8, 0x00, 0x06, 0x00, 0x65, // 0xC07 mov eax, 0x65000600 ; &proc_env.unhandled
    0x48, 0x87, 0x08,             // 0xC0C xchg qword [rax], rcx
    0x48, 0x89, 0xC8,             // 0xC0F mov rax, rcx          ; return old
    0xC3,                         // 0xC12 ret

    // --- UnhandledExceptionFilter (offset 0xC13, 21 bytes) ----
    // Win32: LONG UnhandledExceptionFilter(EXCEPTION_POINTERS* = rcx).
    // Load the stored filter; if non-null, TAIL-call it (the
    // filter's signature matches ours exactly, and tail-call
    // inherits our caller's shadow space + doesn't grow the
    // stack). If null, return EXCEPTION_EXECUTE_HANDLER (= 1),
    // Windows's documented "no top-level filter" default — the
    // caller (CRT's _seh_filter_exe or similar) then proceeds
    // to terminate the process via the standard SEH path.
    0xB8, 0x00, 0x06, 0x00, 0x65, // 0xC13 mov eax, 0x65000600
    0x48, 0x8B, 0x00,             // 0xC18 mov rax, [rax]        ; load filter
    0x48, 0x85, 0xC0,             // 0xC1B test rax, rax
    0x74, 0x02,                   // 0xC1E jz .default (+2 -> 0xC22)
    0xFF, 0xE0,                   // 0xC20 jmp rax              ; tail-call filter
    // .default (abs 0xC22):
    0xB8, 0x01, 0x00, 0x00, 0x00, // 0xC22 mov eax, 1           ; EXCEPTION_EXECUTE_HANDLER
    0xC3,                         // 0xC27 ret

    // === Batch 65 ==============================================

    // --- InitOnceExecuteOnce (offset 0xC28, 87 bytes) ---------
    // Win32: BOOL InitOnceExecuteOnce(
    //          PINIT_ONCE InitOnce = rcx,
    //          PINIT_ONCE_FN InitFn = rdx,
    //          PVOID Parameter = r8,
    //          LPVOID *Context = r9);
    //
    // INIT_ONCE is an 8-byte slot we interpret as:
    //   0 = untouched
    //   1 = initialiser running
    //   2 = done
    //
    // Single atomic CAS 0->1 picks exactly one thread as the
    // initialiser. Losers spin-yield on the slot until it reaches
    // 2. The InitFn signature matches the arg-shifted version of
    // ours: BOOL InitFn(PINIT_ONCE=rcx, PVOID Parameter=rdx,
    // PVOID* Context=r8). Our rdx/r8/r9 shift one slot left into
    // rcx/rdx/r8 before the call. We hold InitOnce in rbx, InitFn
    // in rdi (both callee-saved) so the shuffle doesn't lose
    // state.
    //
    // Null-InitFn fast path: legitimately used as "mark this
    // INIT_ONCE complete without running anything." Skipping the
    // call also avoids CALL-to-0 #PF-killing the task, which is
    // how syscall-stress's `InitOnceExecuteOnce(&io, 0, 0, 0)`
    // test uses it.
    0x53,                         // 0xC28 push rbx
    0x57,                         // 0xC29 push rdi
    0x48, 0x89, 0xCB,             // 0xC2A mov rbx, rcx          ; rbx = InitOnce
    0x48, 0x89, 0xD7,             // 0xC2D mov rdi, rdx          ; rdi = InitFn
    0x31, 0xC0,                   // 0xC30 xor eax, eax          ; expected = 0
    0xBA, 0x01, 0x00, 0x00, 0x00, // 0xC32 mov edx, 1            ; new = 1
    0xF0, 0x48, 0x0F, 0xB1, 0x13, // 0xC37 lock cmpxchg [rbx], rdx
    0x75, 0x29,                   // 0xC3C jnz .wait (+0x29 -> 0xC67)
    // We won the CAS.
    0x48, 0x85, 0xFF,       // 0xC3E test rdi, rdi        ; null InitFn?
    0x74, 0x15,             // 0xC41 jz .null (+0x15 -> 0xC58)
    0x48, 0x89, 0xD9,       // 0xC43 mov rcx, rbx         ; arg1 = InitOnce
    0x4C, 0x89, 0xC2,       // 0xC46 mov rdx, r8          ; arg2 = Parameter
    0x4D, 0x89, 0xC8,       // 0xC49 mov r8, r9           ; arg3 = Context
    0x48, 0x83, 0xEC, 0x20, // 0xC4C sub rsp, 32          ; shadow space
    0xFF, 0xD7,             // 0xC50 call rdi             ; InitFn(...)
    0x48, 0x83, 0xC4, 0x20, // 0xC52 add rsp, 32
    0xEB, 0x05,             // 0xC56 jmp .finish (+5 -> 0xC5D)
    // .null (abs 0xC58): skipped InitFn — return TRUE.
    0xB8, 0x01, 0x00, 0x00, 0x00, // 0xC58 mov eax, 1
    // .finish (abs 0xC5D):
    0x48, 0xC7, 0x03, 0x02, 0x00, 0x00, 0x00, // 0xC5D mov qword [rbx], 2   ; done
    0x5F,                                     // 0xC64 pop rdi
    0x5B,                                     // 0xC65 pop rbx
    0xC3,                                     // 0xC66 ret                  ; eax = call result or 1
    // .wait (abs 0xC67): CAS lost; slot is 1 or 2. Spin-yield
    // until it reaches 2 (done).
    0x48, 0x8B, 0x03,       // 0xC67 mov rax, [rbx]
    0x48, 0x83, 0xF8, 0x02, // 0xC6A cmp rax, 2
    0x74, 0x07,             // 0xC6E je .wait_done (+7 -> 0xC77)
    0x6A, 0x03,             // 0xC70 push 3
    0x58,                   // 0xC72 pop rax                ; SYS_YIELD
    0xCD, 0x80,             // 0xC73 int 0x80
    0xEB, 0xF0,             // 0xC75 jmp .wait (-0x10 -> 0xC67)
    // .wait_done (abs 0xC77): the initialiser finished. Return 1
    // (pretend success — we don't track the initialiser's BOOL
    // across threads).
    0xB8, 0x01, 0x00, 0x00, 0x00, // 0xC77 mov eax, 1
    0x5F,                         // 0xC7C pop rdi
    0x5B,                         // 0xC7D pop rbx
    0xC3,                         // 0xC7E ret

    // === Stage-2 slice 4: real GetProcAddress =====================

    // --- GetProcAddress (offset 0xC7F, 18 bytes) ------------------
    // Win32: FARPROC GetProcAddress(HMODULE hModule=rcx, LPCSTR name=rdx).
    // DuetOS: SYS_DLL_PROC_ADDRESS (57) with rdi=hmod, rsi=name.
    // Returns the exported VA or 0 on miss — same miss contract as
    // the old kOffReturnZero stub. rdi + rsi are callee-saved in the
    // Win32 x64 ABI; save/restore across the syscall.
    0x57,                         // 0xC7F push rdi
    0x56,                         // 0xC80 push rsi
    0x48, 0x89, 0xCF,             // 0xC81 mov rdi, rcx     ; hModule
    0x48, 0x89, 0xD6,             // 0xC84 mov rsi, rdx     ; name ptr
    0xB8, 0x39, 0x00, 0x00, 0x00, // 0xC87 mov eax, 57      ; SYS_DLL_PROC_ADDRESS
    0xCD, 0x80,                   // 0xC8C int 0x80
    0x5E,                         // 0xC8E pop rsi
    0x5F,                         // 0xC8F pop rdi
    0xC3,                         // 0xC90 ret

    // === Render/drivers: D3D11 / D3D12 / DXGI IAT landing pads ===

    // --- D3D11CreateDevice (offset 0xC91, 13 bytes) --------------
    // rax = HRESULT E_FAIL (returned by the syscall). Kind=1.
    0xBF, 0x01, 0x00, 0x00, 0x00, // 0xC91 mov edi, 1       ; kind = D3D11
    0xB8, 0x65, 0x00, 0x00, 0x00, // 0xC96 mov eax, 101     ; SYS_GFX_D3D_STUB
    0xCD, 0x80,                   // 0xC9B int 0x80
    0xC3,                         // 0xC9D ret

    // --- D3D12CreateDevice (offset 0xC9E, 13 bytes) --------------
    0xBF, 0x02, 0x00, 0x00, 0x00, // 0xC9E mov edi, 2       ; kind = D3D12
    0xB8, 0x65, 0x00, 0x00, 0x00, // 0xCA3 mov eax, 101     ; SYS_GFX_D3D_STUB
    0xCD, 0x80,                   // 0xCA8 int 0x80
    0xC3,                         // 0xCAA ret

    // --- CreateDXGIFactory (offset 0xCAB, 13 bytes) --------------
    0xBF, 0x03, 0x00, 0x00, 0x00, // 0xCAB mov edi, 3       ; kind = DXGI
    0xB8, 0x65, 0x00, 0x00, 0x00, // 0xCB0 mov eax, 101     ; SYS_GFX_D3D_STUB
    0xCD, 0x80,                   // 0xCB5 int 0x80
    0xC3,                         // 0xCB7 ret

    // === Render/drivers: real paint-lifecycle + FillRect =========

    // --- BeginPaint (offset 0xCB8, 14 bytes) ---------------------
    // Win32: HDC BeginPaint(HWND hwnd=rcx, LPPAINTSTRUCT lpPaint=rdx).
    // DuetOS: SYS_WIN_BEGIN_PAINT (103) with rdi=hwnd, rsi=ps ptr.
    // Kernel fills the 72-B PAINTSTRUCT + validates dirty.
    0x48, 0x89, 0xCF,             // 0xCB8 mov rdi, rcx     ; hwnd
    0x48, 0x89, 0xD6,             // 0xCBB mov rsi, rdx     ; PAINTSTRUCT*
    0xB8, 0x67, 0x00, 0x00, 0x00, // 0xCBE mov eax, 103     ; SYS_WIN_BEGIN_PAINT
    0xCD, 0x80,                   // 0xCC3 int 0x80
    0xC3,                         // 0xCC5 ret

    // --- EndPaint (offset 0xCC6, 11 bytes) -----------------------
    // Win32: BOOL EndPaint(HWND=rcx, const PAINTSTRUCT*=rdx).
    // DuetOS: SYS_WIN_END_PAINT (104). No-op + returns 1.
    0x48, 0x89, 0xCF,             // 0xCC6 mov rdi, rcx     ; hwnd
    0xB8, 0x68, 0x00, 0x00, 0x00, // 0xCC9 mov eax, 104     ; SYS_WIN_END_PAINT
    0xCD, 0x80,                   // 0xCCE int 0x80
    0xC3,                         // 0xCD0 ret

    // --- InvalidateRect (offset 0xCD1, 14 bytes) -----------------
    // Win32: BOOL InvalidateRect(HWND=rcx, RECT*=rdx, BOOL bErase=r8).
    // DuetOS: SYS_WIN_INVALIDATE (87). lpRect is ignored in v1 —
    // the whole client repaints on every compose.
    0x48, 0x89, 0xCF,             // 0xCD1 mov rdi, rcx     ; hwnd
    0x4C, 0x89, 0xC6,             // 0xCD4 mov rsi, r8      ; bErase
    0xB8, 0x57, 0x00, 0x00, 0x00, // 0xCD7 mov eax, 87      ; SYS_WIN_INVALIDATE
    0xCD, 0x80,                   // 0xCDC int 0x80
    0xC3,                         // 0xCDE ret

    // --- UpdateWindow (offset 0xCDF, 13 bytes) -------------------
    // Win32: BOOL UpdateWindow(HWND=rcx). Posts WM_PAINT if dirty.
    // DuetOS: SYS_WIN_INVALIDATE (87) with bErase=0 — same drain
    // path as InvalidateRect.
    0x48, 0x89, 0xCF,             // 0xCDF mov rdi, rcx     ; hwnd
    0x31, 0xF6,                   // 0xCE2 xor esi, esi     ; bErase = 0
    0xB8, 0x57, 0x00, 0x00, 0x00, // 0xCE4 mov eax, 87      ; SYS_WIN_INVALIDATE
    0xCD, 0x80,                   // 0xCE9 int 0x80
    0xC3,                         // 0xCEB ret

    // --- GetDC (offset 0xCEC, 4 bytes) ---------------------------
    // Win32: HDC GetDC(HWND=rcx). We alias HDC to HWND — the only
    // GDI entry points we route through syscalls take the hwnd
    // back, so a pass-through return is semantically correct.
    0x48, 0x89, 0xC8, // 0xCEC mov rax, rcx     ; HDC = HWND
    0xC3,             // 0xCEF ret

    // --- ReleaseDC (offset 0xCF0, 6 bytes) -----------------------
    // Win32: int ReleaseDC(HWND, HDC). No state to release — always
    // returns 1 (success).
    0xB8, 0x01, 0x00, 0x00, 0x00, // 0xCF0 mov eax, 1
    0xC3,                         // 0xCF5 ret

    // --- FillRect (offset 0xCF6, 17 bytes) -----------------------
    // Win32: int FillRect(HDC hdc=rcx, const RECT*=rdx, HBRUSH=r8).
    // DuetOS: SYS_GDI_FILL_RECT_USER (105) — rdi=hwnd/hdc,
    // rsi=user RECT*, rdx=brush (treated as COLORREF).
    0x48, 0x89, 0xCF,             // 0xCF6 mov rdi, rcx     ; hdc/hwnd
    0x48, 0x89, 0xD6,             // 0xCF9 mov rsi, rdx     ; RECT*
    0x4C, 0x89, 0xC2,             // 0xCFC mov rdx, r8      ; brush → colour
    0xB8, 0x69, 0x00, 0x00, 0x00, // 0xCFF mov eax, 105     ; SYS_GDI_FILL_RECT_USER
    0xCD, 0x80,                   // 0xD04 int 0x80
    0xC3,                         // 0xD06 ret

    // --- TextOutA (offset 0xD07, 31 bytes) -----------------------
    // Win32: BOOL TextOutA(HDC hdc=rcx, int x=edx, int y=r8d,
    //                      LPCSTR=r9, int cchString=[rsp+0x28]).
    // 5th arg is on the stack (above the 32 B shadow space + 8 B
    // return address = [rsp+0x28]).
    // DuetOS: SYS_GDI_TEXT_OUT (66) — rdi=hwnd, rsi=x, rdx=y,
    // r10=text ptr, r8=len, r9=colour. We default the colour to
    // white (0xFFFFFF) because TextOutA doesn't carry one in its
    // signature (real Windows uses SetTextColor on the DC, which
    // we don't track yet).
    0x48, 0x89, 0xCF,             // 0xD07 mov rdi, rcx     ; hwnd
    0x48, 0x89, 0xD6,             // 0xD0A mov rsi, rdx     ; x
    0x4C, 0x89, 0xC2,             // 0xD0D mov rdx, r8      ; y
    0x4D, 0x89, 0xCA,             // 0xD10 mov r10, r9      ; text ptr
    0x44, 0x8B, 0x44, 0x24, 0x28, // 0xD13 mov r8d, [rsp+40]; cchString
    0x41, 0xB9, 0xFF, 0xFF, 0xFF, // 0xD18 mov r9d, 0xFFFFFF; default colour
    0x00,                         //       (imm32 continuation)
    0xB8, 0x42, 0x00, 0x00, 0x00, // 0xD1E mov eax, 66      ; SYS_GDI_TEXT_OUT
    0xCD, 0x80,                   // 0xD23 int 0x80
    0xC3,                         // 0xD25 ret

    // === GDI object handle-table stubs ===========================

    // --- CreateCompatibleDC (offset 0xD26, 11 bytes) -------------
    0x48, 0x89, 0xCF,             // 0xD26 mov rdi, rcx     ; hdc_src
    0xB8, 0x6A, 0x00, 0x00, 0x00, // 0xD29 mov eax, 106
    0xCD, 0x80,                   // 0xD2E int 0x80
    0xC3,                         // 0xD30 ret

    // --- CreateCompatibleBitmap (offset 0xD31, 17 bytes) ---------
    0x48, 0x89, 0xCF,             // 0xD31 mov rdi, rcx     ; hdc
    0x48, 0x89, 0xD6,             // 0xD34 mov rsi, rdx     ; width
    0x4C, 0x89, 0xC2,             // 0xD37 mov rdx, r8      ; height
    0xB8, 0x6B, 0x00, 0x00, 0x00, // 0xD3A mov eax, 107
    0xCD, 0x80,                   // 0xD3F int 0x80
    0xC3,                         // 0xD41 ret

    // --- CreateSolidBrush (offset 0xD42, 11 bytes) ---------------
    0x48, 0x89, 0xCF,             // 0xD42 mov rdi, rcx     ; COLORREF
    0xB8, 0x6C, 0x00, 0x00, 0x00, // 0xD45 mov eax, 108
    0xCD, 0x80,                   // 0xD4A int 0x80
    0xC3,                         // 0xD4C ret

    // --- GetStockObject (offset 0xD4D, 11 bytes) -----------------
    0x48, 0x89, 0xCF,             // 0xD4D mov rdi, rcx     ; index
    0xB8, 0x6D, 0x00, 0x00, 0x00, // 0xD50 mov eax, 109
    0xCD, 0x80,                   // 0xD55 int 0x80
    0xC3,                         // 0xD57 ret

    // --- SelectObject (offset 0xD58, 14 bytes) -------------------
    0x48, 0x89, 0xCF,             // 0xD58 mov rdi, rcx     ; hdc
    0x48, 0x89, 0xD6,             // 0xD5B mov rsi, rdx     ; hobj
    0xB8, 0x6E, 0x00, 0x00, 0x00, // 0xD5E mov eax, 110
    0xCD, 0x80,                   // 0xD63 int 0x80
    0xC3,                         // 0xD65 ret

    // --- DeleteDC (offset 0xD66, 11 bytes) -----------------------
    0x48, 0x89, 0xCF,             // 0xD66 mov rdi, rcx     ; hdc
    0xB8, 0x6F, 0x00, 0x00, 0x00, // 0xD69 mov eax, 111
    0xCD, 0x80,                   // 0xD6E int 0x80
    0xC3,                         // 0xD70 ret

    // --- DeleteObject (offset 0xD71, 11 bytes) -------------------
    0x48, 0x89, 0xCF,             // 0xD71 mov rdi, rcx     ; hobj
    0xB8, 0x70, 0x00, 0x00, 0x00, // 0xD74 mov eax, 112
    0xCD, 0x80,                   // 0xD79 int 0x80
    0xC3,                         // 0xD7B ret

    // --- BitBlt (offset 0xD7C, 103 bytes) ------------------------
    // Win32: BOOL BitBlt(HDC hdcDest=rcx, int x=edx, int y=r8d,
    //                    int cx=r9d, int cy=[rsp+40],
    //                    HDC hdcSrc=[rsp+48], int x1=[rsp+56],
    //                    int y1=[rsp+64], DWORD rop=[rsp+72]).
    // Build a 9 * u64 args struct on our own stack (pre-sub 72
    // bytes), pass the pointer via rdi into SYS_GDI_BITBLT_DC (113).
    // Only the low 32 bits of each int slot are meaningful; the
    // kernel ignores the upper 32.
    //
    // After `sub rsp, 72`:
    //   [rsp+0..71]  = our 9-slot struct
    //   [rsp+72]     = return address
    //   [rsp+80..111]= caller's 32 B shadow space
    //   [rsp+112]    = cy
    //   [rsp+120]    = hdcSrc
    //   [rsp+128]    = x1
    //   [rsp+136]    = y1
    //   [rsp+144]    = rop
    0x48, 0x83, 0xEC, 0x48,             // 0xD7C sub rsp, 72
    0x48, 0x89, 0x0C, 0x24,             // 0xD80 mov [rsp+0], rcx       ; hdcDst
    0x48, 0x89, 0x54, 0x24, 0x08,       // 0xD84 mov [rsp+8], rdx       ; x
    0x4C, 0x89, 0x44, 0x24, 0x10,       // 0xD89 mov [rsp+16], r8       ; y
    0x4C, 0x89, 0x4C, 0x24, 0x18,       // 0xD8E mov [rsp+24], r9       ; cx
    0x48, 0x8B, 0x84, 0x24, 0x70, 0x00, // 0xD93 mov rax, [rsp+112]     ; cy
    0x00, 0x00,                         //
    0x48, 0x89, 0x44, 0x24, 0x20,       // 0xD9B mov [rsp+32], rax
    0x48, 0x8B, 0x84, 0x24, 0x78, 0x00, // 0xDA0 mov rax, [rsp+120]     ; hdcSrc
    0x00, 0x00,                         //
    0x48, 0x89, 0x44, 0x24, 0x28,       // 0xDA8 mov [rsp+40], rax
    0x48, 0x8B, 0x84, 0x24, 0x80, 0x00, // 0xDAD mov rax, [rsp+128]     ; x1
    0x00, 0x00,                         //
    0x48, 0x89, 0x44, 0x24, 0x30,       // 0xDB5 mov [rsp+48], rax
    0x48, 0x8B, 0x84, 0x24, 0x88, 0x00, // 0xDBA mov rax, [rsp+136]     ; y1
    0x00, 0x00,                         //
    0x48, 0x89, 0x44, 0x24, 0x38,       // 0xDC2 mov [rsp+56], rax
    0x48, 0x8B, 0x84, 0x24, 0x90, 0x00, // 0xDC7 mov rax, [rsp+144]     ; rop
    0x00, 0x00,                         //
    0x48, 0x89, 0x44, 0x24, 0x40,       // 0xDCF mov [rsp+64], rax
    0x48, 0x89, 0xE7,                   // 0xDD4 mov rdi, rsp
    0xB8, 0x71, 0x00, 0x00, 0x00,       // 0xDD7 mov eax, 113           ; SYS_GDI_BITBLT_DC
    0xCD, 0x80,                         // 0xDDC int 0x80
    0x48, 0x83, 0xC4, 0x48,             // 0xDDE add rsp, 72
    0xC3,                               // 0xDE2 ret
};

static_assert(sizeof(kStubsBytes) <= 4096, "Win32 stubs page fits in one 4 KiB page");
static_assert(sizeof(kStubsBytes) == 0xDE3, "stub layout drifted; update kOff* constants");
// Keep the hand-assembled __p___argc / __p___argv addresses in
// sync with the public proc-env layout constants. The stub
// bytes encode 0x65000000 and 0x65000008 directly; if stubs.h
// moves the page VA or the argc / argv-ptr offsets, these
// bytes must follow.
static_assert(kProcEnvVa == 0x65000000ULL, "proc-env page VA no longer matches __p___argc stub bytes");
static_assert(kProcEnvArgcOff == 0x00, "argc offset no longer matches __p___argc stub bytes");
static_assert(kProcEnvArgvPtrOff == 0x08, "argv-ptr offset no longer matches __p___argv stub bytes");
static_assert(kProcEnvCommodeOff == 0x200, "commode offset no longer matches __p__commode stub bytes");
static_assert(kProcEnvUnhandledFilterOff == 0x600,
              "unhandled-filter offset no longer matches SetUnhandledExceptionFilter stub bytes");

struct StubEntry
{
    const char* dll;
    const char* func;
    u32 offset;
};

constexpr StubEntry kStubsTable[] = {
    // Batch 1 — console I/O
    {"kernel32.dll", "ExitProcess", kOffExitProcess},
    {"kernel32.dll", "GetStdHandle", kOffGetStdHandle},
    // WriteFile and WriteConsoleA share the same stub — both
    // take the same 5-arg shape and we ignore the handle +
    // trailing arg anyway. Aliasing keeps the stubs page
    // small and means any improvement (clamping, error
    // codes, real handle dispatch) lands in both at once.
    {"kernel32.dll", "WriteFile", kOffWriteFile},
    {"kernel32.dll", "WriteConsoleA", kOffWriteFile},
    // Batch 2 — process/thread lifecycle
    {"kernel32.dll", "GetCurrentProcess", kOffGetCurrentProcess},
    {"kernel32.dll", "GetCurrentThread", kOffGetCurrentThread},
    {"kernel32.dll", "GetCurrentProcessId", kOffGetCurrentProcessId},
    {"kernel32.dll", "GetCurrentThreadId", kOffGetCurrentThreadId},
    {"kernel32.dll", "TerminateProcess", kOffTerminateProcess},
    // Batch 3 — last-error slot
    {"kernel32.dll", "GetLastError", kOffGetLastError},
    {"kernel32.dll", "SetLastError", kOffSetLastError},
    // Batch 4 — critical sections (v0 no-ops)
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
    // Batch 5 — vcruntime140 memory intrinsics
    {"vcruntime140.dll", "memmove", kOffMemmove},
    // memcpy is safe to alias to memmove — memmove is a strict
    // superset (handles overlap), same return value contract.
    {"vcruntime140.dll", "memcpy", kOffMemmove},
    {"vcruntime140.dll", "memset", kOffMemset},

    // Batch 6 — UCRT CRT-startup shims.
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

    // Batch 7 — CRT string intrinsics. Pure functions; no
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

    // Batch 8 — kernel32 "safe ignore" shims. These functions
    // do real work on Windows but can safely return a sentinel
    // value in v0 without causing the caller to immediately
    // crash. Most of them surface in the windows-kill.exe
    // import list; this batch narrows that gap.
    //
    // Return-zero family (returns NULL / FALSE / 0):
    //   GetModuleHandle* — NULL means "module not found"
    //     (or, for NULL arg, a default that's fine to be 0).
    //   GetProcAddress   — NULL means "symbol not exported";
    //     caller falls back.
    //   IsDebuggerPresent          — FALSE = not debugged.
    //   IsProcessorFeaturePresent  — FALSE = feature absent;
    //     caller uses non-SIMD fallback path.
    //   SetUnhandledExceptionFilter — NULL = no previous filter.
    //   UnhandledExceptionFilter    — 0 = EXCEPTION_CONTINUE_SEARCH.
    // GetModuleHandleA / GetModuleHandleW / GetProcAddress moved to
    // batch 25 below — GetModuleHandleW(NULL) now returns the EXE
    // image base instead of always-zero. The Win32StubsLookup walk
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
    //   SetConsoleCtrlHandler — pretend we registered.
    {"kernel32.dll", "SetConsoleCtrlHandler", kOffReturnOne},

    // Batch 24 — file I/O. Real handle table on Process,
    // backed by SYS_FILE_OPEN / SYS_FILE_READ / SYS_FILE_CLOSE
    // / SYS_FILE_SEEK. CloseHandle is the file-close path —
    // also harmlessly handles non-file handles (the kernel
    // SYS_FILE_CLOSE returns 0 for an unrecognised handle).
    {"kernel32.dll", "CreateFileW", kOffCreateFileW},
    {"kernel32.dll", "ReadFile", kOffReadFile},
    {"kernel32.dll", "CloseHandle", kOffCloseHandle},
    {"kernel32.dll", "SetFilePointerEx", kOffSetFilePtrEx},

    // Batch 25 — file stat + module lookup. GetFileSizeEx is
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
    // as of stage-2 slice 4. Returns the exported VA out of the
    // process's DLL image table, or 0 on miss (= same contract
    // the old return-zero stub honoured, so existing callers that
    // GetProcAddress an optional API and NULL-check gracefully fall
    // back either way).
    {"kernel32.dll", "GetProcAddress", kOffGetProcAddressReal},

    // Batch 26 — Win32 mutex (real waitqueue-backed semantics).
    // CreateMutexW allocates a per-process slot returning a 0x200+
    // pseudo-handle. WaitForSingleObject dispatches by handle range
    // — mutex handles route to SYS_MUTEX_WAIT, anything else
    // pseudo-signals as before. ReleaseMutex routes to
    // SYS_MUTEX_RELEASE. All three are recursive (Win32 contract).
    // CloseHandle (batch 24) handles mutex slots too via range
    // dispatch in SYS_FILE_CLOSE.
    {"kernel32.dll", "CreateMutexW", kOffCreateMutexW},
    {"kernel32.dll", "CreateMutexA", kOffCreateMutexW},
    {"kernel32.dll", "CreateMutexExW", kOffCreateMutexW},     // ignores extra Ex args
    {"kernel32.dll", "WaitForSingleObject", kOffWaitForObj4}, // batch 54 upgrade
    {"kernel32.dll", "WaitForSingleObjectEx", kOffWaitForObj4},
    {"kernel32.dll", "ReleaseMutex", kOffReleaseMutex},

    // Batch 45 — real event handles. Replaces the kOffReturnOne
    // no-op CreateEventW / SetEvent / ResetEvent from slice 10.
    // Per-process event table at 0x300..0x307.
    {"kernel32.dll", "CreateEventW", kOffCreateEventReal},
    {"kernel32.dll", "CreateEventA", kOffCreateEventReal},
    {"kernel32.dll", "CreateEventExW", kOffCreateEventReal}, // ignores extra Ex args
    {"kernel32.dll", "CreateEventExA", kOffCreateEventReal},
    {"kernel32.dll", "SetEvent", kOffSetEventReal},
    {"kernel32.dll", "ResetEvent", kOffResetEventReal},

    // Batch 46 — real TLS. Replaces batch 39's alias-to-
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

    // Batch 27 — console APIs. WriteConsoleW is the major
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
    // Batch 51: OutputDebugStringA → real kernel debug-print syscall.
    // OutputDebugStringW unchanged for now (UTF-16 → ASCII strip in
    // a follow-up; most real callers use the A form).
    {"kernel32.dll", "OutputDebugStringW", kOffOutputDebugStringW},
    {"kernel32.dll", "OutputDebugStringA", kOffOutputDebugStringA},

    // Batch 28 — virtual memory. VirtualAlloc is the single
    // most-requested Win32 memory primitive for non-trivial
    // PEs (JIT, CoreCLR, TLS setup, custom allocators). Bump-
    // only arena at 0x40000000..+512KiB per process.
    // VirtualFree is a no-op (range-check only). VirtualProtect
    // no-ops and echoes PAGE_READWRITE back — W^X forbids the
    // RWX pages a JIT would actually want, so a second slice
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

    // Batch 29 — wide-string helpers. Pure-compute primitives
    // heavily used by multilingual PEs and MSVC CRT. lstrcmpW
    // is ordinal compare (no locale fold — lstrcmpiW would
    // case-fold, not stubbed). lstrlen has a hard cap of
    // effectively "until NUL" — a wild unterminated string
    // scans forever, matching the documented Win32 behaviour.
    {"kernel32.dll", "lstrlenW", kOffLstrlenW},
    {"kernel32.dll", "lstrcmpW", kOffLstrcmpW},
    {"kernel32.dll", "lstrcpyW", kOffLstrcpyW},

    // Batch 30 — system-info probes. IsWow64Process returns FALSE
    // (native x64 process, no 32-bit emulation). GetVersionEx*
    // reports Windows 10 build 19041 (2004 / 20H1) — a modern-
    // enough version to pass most feature-gate checks without
    // triggering "too new, not yet supported" fallbacks apps
    // have for very recent builds.
    {"kernel32.dll", "IsWow64Process", kOffIsWow64},
    {"kernel32.dll", "IsWow64Process2", kOffIsWow64}, // fills similar PBOOL
    {"kernel32.dll", "GetVersionExW", kOffGetVersionExW},
    {"kernel32.dll", "GetVersionExA", kOffGetVersionExW}, // ASCII CSD left untouched

    // Batch 31 — ANSI-byte string helpers. Symmetric to batch 29
    // but for LPCSTR. Pure compute, no syscalls.
    {"kernel32.dll", "lstrlenA", kOffLstrlenA},
    {"kernel32.dll", "lstrcmpA", kOffLstrcmpA},
    {"kernel32.dll", "lstrcpyA", kOffLstrcpyA},

    // Batch 32 — path-query stubs. All v0 paths report a single
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

    // Batch 33 — encoding converters. v0 handles ASCII-range
    // content perfectly (byte-extend / byte-truncate); non-ASCII
    // UTF-8 sequences lose high-plane data.
    {"kernel32.dll", "MultiByteToWideChar", kOffMBtoWC},
    {"kernel32.dll", "WideCharToMultiByte", kOffWCtoMB},

    // Batch 34 — identity queries. Fixed-string stubs.
    // kernel32 hosts GetComputerNameW; advapi32 hosts
    // GetUserNameW (on real Windows it's an advapi32 export
    // that delegates to LsaQueryInformationPolicy). Both land
    // on our same in/out-size stub pattern.
    {"advapi32.dll", "GetUserNameW", kOffGetUserNameW},
    {"advapi32.dll", "GetUserNameA", kOffGetUserNameW}, // ASCII caller gets ASCII-range bytes OK
    {"kernel32.dll", "GetComputerNameW", kOffGetComputerNameW},
    {"kernel32.dll", "GetComputerNameA", kOffGetComputerNameW},

    // Batch 35 — system-directory queries. GetTempPathW shares
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

    // Batch 36 — drives, error modes, format messages.
    //   GetLogicalDrives returns bit 23 set (only X: mounted).
    //   GetDriveType*   returns 3 (DRIVE_FIXED) for any input.
    //   SetErrorMode / GetErrorMode return 0 (no special mode).
    //   FormatMessage{W,A} returns 0 — callers usually fall
    //     back to their own format-by-code path.
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

    // Batch 37 — registry + file-attribute no-op stubs.
    //   Reg open / read family returns ERROR_FILE_NOT_FOUND (2),
    //     the standard "key doesn't exist" status.
    //   Reg write / close family returns ERROR_SUCCESS (0).
    //   GetFileAttributesW returns INVALID_FILE_ATTRIBUTES (-1)
    //     — caller treats as "file not present".
    //   SetFileAttributesW returns TRUE (pretend success).
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

    // Batch 38 — locale / processor / time-zone probes. All
    // aliases to existing constant-returning stubs; zero new
    // stub bytes needed.
    //   GetACP / GetOEMCP -> 65001 (CP_UTF8) via kOffGetConsoleCP.
    //   IsValidCodePage -> TRUE.
    //   GetThreadLocale / *DefaultLCID -> 0 (LOCALE_INVARIANT).
    //   GetTimeZoneInformation -> 1 (TIME_ZONE_ID_STANDARD).
    //   GetProcessTimes / GetThreadTimes -> FALSE ("couldn't
    //     query — use fallback"), safer than TRUE + uninit out.
    //   GetStartupInfoW -> kOffCritSecNop (void return, 1-byte ret).
    //   VerifyVersionInfoW -> TRUE (version probe passes).
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
    // Batch 51: GetProcessTimes / GetThreadTimes → zero-fill stubs.
    {"kernel32.dll", "GetProcessTimes", kOffGetProcessTimes},
    {"kernel32.dll", "GetThreadTimes", kOffGetProcessTimes}, // same shape
    // Batch 58: GetStartupInfo{W,A} now zero-fill the caller's
    // 104-byte STARTUPINFO and set cb = 104 (the nop previously
    // here left the buffer uninitialised — callers read a wild
    // pointer from lpDesktop / hStdInput and faulted).
    {"kernel32.dll", "GetStartupInfoW", kOffGetStartupInfo},
    {"kernel32.dll", "GetStartupInfoA", kOffGetStartupInfo},
    {"kernel32.dll", "VerSetConditionMask", kOffReturnZero},
    {"kernel32.dll", "VerifyVersionInfoW", kOffReturnOne},
    {"kernel32.dll", "VerifyVersionInfoA", kOffReturnOne},
    // Paired with batch 10's InitializeSListHead — more InterlockedX
    // SList ops all no-op (return NULL = empty list).
    {"kernel32.dll", "InterlockedPushEntrySList", kOffReturnZero},
    {"kernel32.dll", "InterlockedPopEntrySList", kOffReturnZero},
    {"kernel32.dll", "InterlockedFlushSList", kOffReturnZero},
    {"kernel32.dll", "QueryDepthSList", kOffReturnZero},
    // Misc memory / CPU / numa probes.
    // Batch 51: GlobalMemoryStatusEx → real SYS_MEM_STATUS;
    // GetSystemTimes → zero-fill stub.
    {"kernel32.dll", "GlobalMemoryStatusEx", kOffGlobalMemoryStatusEx},
    {"kernel32.dll", "GetSystemTimes", kOffGetSystemTimes},
    // Batch 52: GetSystemInfo / GetNativeSystemInfo populate a
    // Win32 SYSTEM_INFO struct with x86_64 constants.
    {"kernel32.dll", "GetSystemInfo", kOffGetSystemInfo},
    {"kernel32.dll", "GetNativeSystemInfo", kOffGetSystemInfo},
    {"kernel32.dll", "GetNumaHighestNodeNumber", kOffReturnZero},

    // Batch 39 — process priority / TLS / file-type aliases.
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
    {"kernel32.dll", "CreateThread", kOffCreateThreadReal}, // batch 50 — real spawn via SYS_THREAD_CREATE
    {"kernel32.dll", "CreateRemoteThread", kOffReturnZero}, // batch-24 fallback stays (no cross-proc v0)
    // Batch 51: ExitThread routes to SYS_EXIT (kills just this
    // task). FreeLibraryAndExitThread aliases to ExitThread — the
    // FreeLibrary half is a no-op in v0 (no DLL unload path).
    {"kernel32.dll", "ExitThread", kOffExitThread},
    {"kernel32.dll", "FreeLibraryAndExitThread", kOffExitThread},
    // Batch 51: WaitForMultipleObjects via SYS_WAIT_MULTI.
    {"kernel32.dll", "WaitForMultipleObjects", kOffWaitForMultipleObjects},
    {"kernel32.dll", "WaitForMultipleObjectsEx", kOffWaitForMultipleObjects},
    // Batch 53: RaiseException → SYS_EXIT. DecodePointer /
    // EncodePointer → identity (round-trip preserved).
    {"kernel32.dll", "RaiseException", kOffRaiseException},
    {"kernel32.dll", "DecodePointer", kOffDecodePointer},
    {"kernel32.dll", "EncodePointer", kOffDecodePointer},
    {"kernel32.dll", "RtlDecodePointer", kOffDecodePointer},
    {"kernel32.dll", "RtlEncodePointer", kOffDecodePointer},
    // Batch 54: Semaphore family — CreateSemaphore(W/A/ExW) route
    // through SYS_SEM_CREATE; ReleaseSemaphore through SYS_SEM_RELEASE;
    // WaitForSingleObject on a semaphore handle is dispatched by
    // the new v3 stub to SYS_SEM_WAIT.
    {"kernel32.dll", "CreateSemaphoreW", kOffCreateSemaphoreW},
    {"kernel32.dll", "CreateSemaphoreA", kOffCreateSemaphoreW},
    {"kernel32.dll", "CreateSemaphoreExW", kOffCreateSemaphoreW},
    {"kernel32.dll", "CreateSemaphoreExA", kOffCreateSemaphoreW},
    {"kernel32.dll", "ReleaseSemaphore", kOffReleaseSemaphore},
    // === Batch 55: SRW locks, condition variables, one-time
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

    // === Batch 56: File I/O + thread/fiber + debug + precise time.
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
    // moved to batch 46 below.
    {"kernel32.dll", "SetEndOfFile", kOffReturnOne},
    {"kernel32.dll", "FlushFileBuffers", kOffReturnOne}, // pretend fsync
    {"kernel32.dll", "GetFileType", kOffReturnTwo},      // 2 = FILE_TYPE_CHAR (console-ish)
    {"kernel32.dll", "GetConsoleWindow", kOffReturnZero},
    {"kernel32.dll", "AddVectoredExceptionHandler", kOffReturnZero},
    {"kernel32.dll", "RemoveVectoredExceptionHandler", kOffReturnZero},
    {"kernel32.dll", "AddVectoredContinueHandler", kOffReturnZero},

    // Batch 40 — Interlocked atomics. Real LOCK-prefixed instr
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
    // 64-bit variants (batch 41)
    {"kernel32.dll", "InterlockedIncrement64", kOffInterlockedInc64},
    {"kernel32.dll", "InterlockedDecrement64", kOffInterlockedDec64},
    {"kernel32.dll", "InterlockedCompareExchange64", kOffInterlockedCmpXchg64},
    {"kernel32.dll", "InterlockedExchange64", kOffInterlockedExchg64},
    {"kernel32.dll", "InterlockedExchangeAdd64", kOffInterlockedExchgAdd64},
    // Batch 60: Interlocked{And,Or,Xor} 32 + 64. CAS-loop stubs
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

    // === Batch 42 — ntdll.dll coverage =========================
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
    //   * NtClose(HANDLE rcx) matches CloseHandle(HANDLE rcx),
    //     so we alias to kOffCloseHandle — NtClose actually works.
    //   * NtYieldExecution() takes no args; reuse kOffCritSecNop
    //     (1-byte ret) since the return value (NTSTATUS 0 =
    //     STATUS_SUCCESS) is what we'd emit anyway.
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
    // batch 47: real NtAllocateVirtualMemory / NtFreeVirtualMemory
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
    // Dedicated NTSTATUS-returning stubs (batch 49), so ntdll
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

    // === Batch 43 — UI / locale / clipboard / mapping ==========
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
    {"user32.dll", "GetSysColor", kOffReturnZero},
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

    // === Batch 44 — shell32 / ole32 / winmm / shlwapi / psapi ==
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

    // === Batch 47 — kernelbase / bcrypt / dbghelp / extended ntdll ===
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

    // Batch 9 — Win32 process heap, backed by the per-process
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
    // SYS_HEAP_SIZE as of batch 14 — block header carries the
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

    // Batch 10 — advapi32 privilege/token + kernel32 event /
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
    // event infrastructure — moved to batch 45 below.

    // kernel32 — wait (v0: immediate return with
    // WaitForSingleObject moved to batch 26 below — now mutex-aware.
    // The stub still pseudo-signals (returns 0 = WAIT_OBJECT_0) for
    // non-mutex handles, preserving the original batch-10 contract
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
    // Batch 59: real GetExitCodeThread backed by per-handle
    // exit_code storage updated at SYS_EXIT time.
    {"kernel32.dll", "GetExitCodeThread", kOffGetExitCodeThreadReal},
    {"kernel32.dll", "GenerateConsoleCtrlEvent", kOffReturnOne},

    // Batch 11 — performance counters, tick count, and the
    // Rtl*/Toolhelp32/thread-management clusters. The perf
    // counter family is REAL — backed by SYS_PERF_COUNTER
    // and the kernel 100 Hz tick. The rest are safe no-ops
    // that let callers proceed without crashing:
    //   * Rtl* unwind family returns 0 — "no function entry
    //     found" / "no frames captured". Code that uses
    //     these for crash-report formatting gets an empty
    //     report but doesn't fault.
    //   * Toolhelp32 snapshot returns 1 (non-null handle)
    //     but Process32First returns FALSE — program sees
    //     an empty process list.
    //   * CreateRemoteThread returns 0 (NULL) — the target
    //     program handles failure gracefully per the Win32
    //     contract (GetLastError returns the last set
    //     error; our stub stack doesn't populate that yet).
    // QueryPerformance{Counter,Frequency} upgraded (batch 21) to
    // HPET-backed nanosecond resolution. The old stubs at 0x1F6
    // / 0x206 stay in the page as dead bytes.
    {"kernel32.dll", "QueryPerformanceCounter", kOffQpcNs},
    {"kernel32.dll", "QueryPerformanceFrequency", kOffQpfNs},
    {"kernel32.dll", "GetTickCount", kOffGetTickCount},
    {"kernel32.dll", "GetTickCount64", kOffGetTickCount},

    // Batch 22 — Sleep + SwitchToThread (timer + voluntary yield).
    // Sleep routes to SYS_SLEEP_MS; SwitchToThread routes to
    // SYS_YIELD. SleepEx ignores its bAlertable arg and aliases
    // to Sleep — no APC delivery in v0, so the alertable form
    // would never actually fire user-mode APCs anyway.
    {"kernel32.dll", "Sleep", kOffSleep},
    {"kernel32.dll", "SleepEx", kOffSleep},
    {"kernel32.dll", "SwitchToThread", kOffSwitchToThread},

    // Batch 23 — command line + environment (proc-env page reads).
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

    // Batch 12 — dbghelp + vcruntime SEH + UCRT convert.
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

    // Batch 13a — MSVCP140 throw helpers + small-return
    // helpers. All aliases. The `?_X*_error` + `?_Xbad_alloc`
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
    // windows-kill.exe's next UNRESOLVED after this batch
    // lands will be in that group.
    {"MSVCP140.dll", "?_Xbad_alloc@std@@YAXXZ", kOffTerminate},
    {"MSVCP140.dll", "?_Xlength_error@std@@YAXPEBD@Z", kOffTerminate},
    {"MSVCP140.dll", "?_Xout_of_range@std@@YAXPEBD@Z", kOffTerminate},
    {"MSVCP140.dll", "?_Syserror_map@std@@YAPEBDH@Z", kOffReturnZero},
    {"MSVCP140.dll", "?_Winerror_map@std@@YAHH@Z", kOffReturnZero},
    {"MSVCP140.dll", "?_Winerror_message@std@@YAKKPEADK@Z", kOffReturnZero},
    {"MSVCP140.dll", "?uncaught_exception@std@@YA_NXZ", kOffReturnZero},

    // Batch 16 — MSVC CRT argc / argv accessors. These are the
    // first real-valued reads the CRT's __scrt_common_main_seh
    // makes during startup: `argc = *__p___argc()` and
    // `argv = *__p___argv()`. Prior to this batch they landed on
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

    // Batch 17 — UCRT stdio accessors. `__p__commode` returns
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

    // Batch 18 — MSVCP140 iostream methods. Direct-call paths
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

    // Batch 19 — D3D / DXGI create-device family. Returning
    // HRESULT E_FAIL lets a caller's "no graphics" fallback
    // kick in. Covers the entry points DXVK / vkd3d-proton
    // intercept at the top of their translation chain:
    //
    //   D3D11CreateDevice / D3D11CreateDeviceAndSwapChain
    //     — MSVC d3d11.dll direct
    //   D3D12CreateDevice
    //     — MSVC d3d12.dll direct
    //   CreateDXGIFactory / CreateDXGIFactory1 / CreateDXGIFactory2
    //     — dxgi.dll, prerequisite for D3D device creation
    //   Direct3DCreate9 / Direct3DCreate9Ex
    //     — legacy d3d9.dll entry
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
    // new stub bytes land; the file's static_assert on kStubsBytes
    // size stays valid.
    //
    // Semantics chosen per MSDN so a well-behaved PE sees "call
    // succeeded but nothing happened":
    //   - CreateWindowExW -> non-zero (caller treats 0 as failure).
    //   - GetMessageW     -> 0 (signals WM_QUIT; main loop exits
    //                         cleanly instead of spinning forever).
    //   - DefWindowProc*  -> 0 (most messages ignore the return).
    //   - GDI object/DC handles -> non-zero so SelectObject /
    //                         DeleteObject later don't hit ERROR_
    //                         INVALID_HANDLE paths.
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
    {"user32.dll", "GetMessageA", kOffReturnZero},
    {"user32.dll", "GetMessageW", kOffReturnZero},
    {"user32.dll", "PeekMessageA", kOffReturnZero},
    {"user32.dll", "PeekMessageW", kOffReturnZero},
    {"user32.dll", "DispatchMessageA", kOffReturnZero},
    {"user32.dll", "DispatchMessageW", kOffReturnZero},
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
    {"gdi32.dll", "CreatePen", kOffReturnOne},
    {"gdi32.dll", "CreateFontA", kOffReturnOne},
    {"gdi32.dll", "CreateFontW", kOffReturnOne},
    {"gdi32.dll", "CreateFontIndirectA", kOffReturnOne},
    {"gdi32.dll", "CreateFontIndirectW", kOffReturnOne},

    // gdi32: drawing primitives — all boolean, return TRUE so the
    // caller's "draw succeeded" flag is set.
    {"gdi32.dll", "BitBlt", kOffGdiBitBltDC},
    {"gdi32.dll", "StretchBlt", kOffReturnOne},
    {"gdi32.dll", "MoveToEx", kOffReturnOne},
    {"gdi32.dll", "LineTo", kOffReturnOne},
    {"gdi32.dll", "Rectangle", kOffReturnOne},
    {"gdi32.dll", "Ellipse", kOffReturnOne},
    {"gdi32.dll", "Polygon", kOffReturnOne},
    {"gdi32.dll", "Polyline", kOffReturnOne},
    // FillRect is technically a user32 export (not gdi32) in real
    // Windows, but we honour whichever DLL a PE imports it from.
    {"gdi32.dll", "FillRect", kOffGdiFillRectUser},
    {"user32.dll", "FillRect", kOffGdiFillRectUser},
    {"gdi32.dll", "FrameRect", kOffReturnOne},
    {"gdi32.dll", "TextOutA", kOffGdiTextOutA},
    {"gdi32.dll", "TextOutW", kOffReturnOne},
    {"gdi32.dll", "ExtTextOutA", kOffReturnOne},
    {"gdi32.dll", "ExtTextOutW", kOffReturnOne},
    {"gdi32.dll", "DrawTextA", kOffReturnOne},
    {"gdi32.dll", "DrawTextW", kOffReturnOne},
    {"gdi32.dll", "SetBkMode", kOffReturnOne},
    {"gdi32.dll", "SetBkColor", kOffReturnZero},
    {"gdi32.dll", "SetTextColor", kOffReturnZero},
    {"gdi32.dll", "SetMapMode", kOffReturnOne},
    {"gdi32.dll", "SetTextAlign", kOffReturnZero},

    // -----------------------------------------------------------------
    // Batch 48: real stubs for pointer-output time APIs — the ones
    // deliberately skipped by the previous GUI batch because a 0/1
    // return leaves their caller-allocated output struct
    // uninitialised. These bridge Win64 ABI -> int 0x80 with the
    // new SYS_GETTIME_ST / SYS_ST_TO_FT / SYS_FT_TO_ST syscalls
    // (40..42).
    // -----------------------------------------------------------------
    {"kernel32.dll", "GetSystemTime", kOffGetSystemTimeSt},
    {"kernel32.dll", "GetLocalTime", kOffGetSystemTimeSt},
    {"kernel32.dll", "SystemTimeToFileTime", kOffSystemTimeToFileTime},
    {"kernel32.dll", "FileTimeToSystemTime", kOffFileTimeToSystemTime},
};

struct StubHashEntry
{
    u64 key_hash;
    u32 stub_index;
};

constexpr char AsciiToLower(char c)
{
    if (c >= 'A' && c <= 'Z')
        return static_cast<char>(c - 'A' + 'a');
    return c;
}

constexpr u64 Fnv1a64Append(u64 hash, char c)
{
    constexpr u64 kFnvPrime = 1099511628211ULL;
    return (hash ^ static_cast<u8>(c)) * kFnvPrime;
}

constexpr u64 StubLookupHash(const char* dll, const char* func)
{
    constexpr u64 kFnvOffsetBasis = 14695981039346656037ULL;
    u64 hash = kFnvOffsetBasis;
    if (dll != nullptr)
    {
        for (u64 i = 0; dll[i] != '\0'; ++i)
            hash = Fnv1a64Append(hash, AsciiToLower(dll[i]));
    }
    hash = Fnv1a64Append(hash, '!');
    if (func != nullptr)
    {
        for (u64 i = 0; func[i] != '\0'; ++i)
            hash = Fnv1a64Append(hash, func[i]);
    }
    return hash;
}

template <u64 N> struct StubHashTable
{
    StubHashEntry entries[N];
};

template <u64 N> consteval StubHashTable<N> BuildStubHashTable(const StubEntry (&table)[N])
{
    StubHashTable<N> sorted{};
    for (u64 i = 0; i < N; ++i)
    {
        sorted.entries[i].key_hash = StubLookupHash(table[i].dll, table[i].func);
        sorted.entries[i].stub_index = static_cast<u32>(i);
    }

    // Small-table insertion sort at compile time keeps runtime lookup
    // branch-light and cache-friendly.
    for (u64 i = 1; i < N; ++i)
    {
        StubHashEntry value = sorted.entries[i];
        u64 j = i;
        while (j > 0 && sorted.entries[j - 1].key_hash > value.key_hash)
        {
            sorted.entries[j] = sorted.entries[j - 1];
            --j;
        }
        sorted.entries[j] = value;
    }
    return sorted;
}

constexpr auto kSortedStubHashes = BuildStubHashTable(kStubsTable);
constexpr u64 kSortedStubHashCount = sizeof(kSortedStubHashes.entries) / sizeof(kSortedStubHashes.entries[0]);
static_assert(kSortedStubHashCount == (sizeof(kStubsTable) / sizeof(kStubsTable[0])), "hash table size mismatch");

// Case-insensitive strcmp for ASCII. Win32 DLL name
// capitalisation is inconsistent (lld-link writes
// "kernel32.dll", MSVC's linker writes "KERNEL32.dll"); we
// match either.
bool AsciiCaseEqual(const char* a, const char* b)
{
    if (a == nullptr || b == nullptr)
        return false;
    while (*a != 0 && *b != 0)
    {
        char ca = *a++;
        char cb = *b++;
        if (ca >= 'A' && ca <= 'Z')
            ca = static_cast<char>(ca - 'A' + 'a');
        if (cb >= 'A' && cb <= 'Z')
            cb = static_cast<char>(cb - 'A' + 'a');
        if (ca != cb)
            return false;
    }
    return *a == 0 && *b == 0;
}

bool AsciiEqual(const char* a, const char* b)
{
    if (a == nullptr || b == nullptr)
        return false;
    while (*a != 0 && *b != 0)
    {
        if (*a++ != *b++)
            return false;
    }
    return *a == 0 && *b == 0;
}

#if defined(DUETOS_WIN32_STUBS_VALIDATE_LINEAR)
bool Win32StubsLookupLinear(const char* dll, const char* func, u64* out_va, bool* out_is_noop)
{
    for (const StubEntry& e : kStubsTable)
    {
        if (!AsciiCaseEqual(e.dll, dll))
            continue;
        if (!AsciiEqual(e.func, func))
            continue;
        *out_va = kWin32StubsVa + e.offset;
        if (out_is_noop != nullptr)
        {
            *out_is_noop = (e.offset == kOffReturnZero) || (e.offset == kOffReturnOne) ||
                           (e.offset == kOffCritSecNop) || (e.offset == kOffGetProcessHeap);
        }
        return true;
    }
    return false;
}
#endif

bool Win32StubsLookupHashed(const char* dll, const char* func, u64* out_va, bool* out_is_noop)
{
    const u64 key_hash = StubLookupHash(dll, func);
    u64 lo = 0;
    u64 hi = kSortedStubHashCount;
    while (lo < hi)
    {
        const u64 mid = lo + ((hi - lo) / 2);
        if (kSortedStubHashes.entries[mid].key_hash < key_hash)
            lo = mid + 1;
        else
            hi = mid;
    }

    for (u64 i = lo; i < kSortedStubHashCount; ++i)
    {
        const StubHashEntry& probe = kSortedStubHashes.entries[i];
        if (probe.key_hash != key_hash)
            break;
        const StubEntry& e = kStubsTable[probe.stub_index];
        if (!AsciiCaseEqual(e.dll, dll) || !AsciiEqual(e.func, func))
            continue;
        *out_va = kWin32StubsVa + e.offset;
        if (out_is_noop != nullptr)
        {
            *out_is_noop = (e.offset == kOffReturnZero) || (e.offset == kOffReturnOne) ||
                           (e.offset == kOffCritSecNop) || (e.offset == kOffGetProcessHeap);
        }
        return true;
    }
    return false;
}

} // namespace

void Win32StubsPopulate(u8* dst)
{
    if (dst == nullptr)
        return;
    for (u64 i = 0; i < sizeof(kStubsBytes); ++i)
        dst[i] = kStubsBytes[i];
}

namespace
{
// Write a little-endian u64 at `dst`.
inline void StoreLeU64(u8* dst, u64 value)
{
    for (u64 b = 0; b < 8; ++b)
        dst[b] = static_cast<u8>((value >> (b * 8)) & 0xFFULL);
}
} // namespace

void Win32ProcEnvPopulate(u8* proc_env_page, const char* program_name, u64 module_base)
{
    if (proc_env_page == nullptr)
        return;

    // Caller is expected to have zeroed the frame, but be
    // defensive — populate only the specific fields we own,
    // leaving the rest at its incoming value.
    u8* const page = proc_env_page;

    // EXE module base — what GetModuleHandleW(NULL) hands back.
    // u64, little-endian. Read directly by the GetModuleHandleW
    // stub; no syscall on the hot path.
    StoreLeU64(page + kProcEnvModuleBaseOff, module_base);

    // argc = 1. Stored as a little-endian u32 at offset 0.
    page[kProcEnvArgcOff + 0] = 0x01;
    page[kProcEnvArgcOff + 1] = 0x00;
    page[kProcEnvArgcOff + 2] = 0x00;
    page[kProcEnvArgcOff + 3] = 0x00;

    // argv = &proc_env_page[kProcEnvArgvArrayOff] expressed in
    // user VA. Little-endian u64 at offset 0x08.
    const u64 argv_user_va = kProcEnvVa + kProcEnvArgvArrayOff;
    StoreLeU64(page + kProcEnvArgvPtrOff, argv_user_va);

    // Copy program_name into the string area (offset 0x40). Cap
    // at kProcEnvStringBudget - 1 to guarantee NUL termination.
    // A null / empty name becomes "a.exe" — Windows convention
    // for a program with no recorded argv[0].
    const char* name = (program_name != nullptr && program_name[0] != '\0') ? program_name : "a.exe";
    u64 copied = 0;
    while (copied + 1 < kProcEnvStringBudget)
    {
        const char c = name[copied];
        if (c == '\0')
            break;
        page[kProcEnvStringOff + copied] = static_cast<u8>(c);
        ++copied;
    }
    page[kProcEnvStringOff + copied] = 0;

    // argv[0] = &proc_env_page[kProcEnvStringOff] in user VA.
    const u64 argv0_user_va = kProcEnvVa + kProcEnvStringOff;
    StoreLeU64(page + kProcEnvArgvArrayOff, argv0_user_va);
    // argv[1] = NULL — already zero, but set explicitly so the
    // contract is visible in the page dump. Any callers that
    // walk argv until NULL (Win32 CRT + most Unix main())
    // stop here.
    StoreLeU64(page + kProcEnvArgvArrayOff + 8, 0);

    // Wide + ANSI command line. Both forms hold just the
    // program name; multi-arg cmdlines arrive when a real spawn
    // API plumbs argv through. Wide form is UTF-16LE — every
    // ASCII byte becomes the same byte followed by a 0x00
    // high-half byte; that covers every name we'd plausibly
    // emit for a v0 PE.
    {
        u8* const w = page + kProcEnvCmdlineWOff;
        u8* const a = page + kProcEnvCmdlineAOff;
        for (u64 i = 0; i < copied; ++i)
        {
            // Both buffers fit comfortably (256 / 128 wide chars,
            // 128 ascii); kProcEnvStringBudget already capped
            // `copied` at 255 so neither overflows.
            w[2 * i + 0] = static_cast<u8>(name[i]);
            w[2 * i + 1] = 0;
            a[i] = static_cast<u8>(name[i]);
        }
        // Wide NUL = 2 bytes of 0; ANSI NUL = 1 byte. Both
        // already-zeroed by caller, but write explicitly for
        // page-dump readability.
        w[2 * copied + 0] = 0;
        w[2 * copied + 1] = 0;
        a[copied] = 0;
    }

    // Empty wide environment block. An env block is a
    // contiguous run of UTF-16LE `KEY=VALUE\0` entries, plus a
    // final extra NUL terminating the list. The minimum legal
    // empty block is two zero bytes (`\0\0`). Already zeroed
    // — touch nothing.
    (void)kProcEnvEnvBlockWOff; // documented; no init needed for empty form

    // Data-miss "fake object". PE data imports whose names the
    // stub table doesn't know (e.g. std::cout) get an IAT slot
    // of `kProcEnvVa + kProcEnvDataMissOff`. Dereferenced as
    // `mov rax, [cout_iat]`, the caller reads the u64 stored
    // here — which we set to `kProcEnvVa + kProcEnvDataMissOff
    // + 8`, a pointer into the same page, 8 bytes further in,
    // where everything remains zero.
    //
    // The MSVC virtual-dispatch idiom (`mov rax, [this]; movslq
    // rcx, [rax+4]; mov rdi, [rcx+this+0x48]; test rdi, rdi;
    // jle ...`) then walks:
    //
    //   rax = [data_miss] = data_miss + 8     ; mapped
    //   rcx = [rax + 4]   = 0                 ; zero-read
    //   rdi = [this + 0x48] = 0               ; zero-read
    //   test rdi, rdi -> jle TAKEN
    //
    // The caller takes its "uninitialised / empty-stream" error
    // branch instead of faulting. Good enough for the first pass
    // past an unstubbed `std::cout` — it doesn't print, but it
    // stops crashing.
    const u64 fake_obj_va = kProcEnvVa + kProcEnvDataMissOff + 8;
    StoreLeU64(page + kProcEnvDataMissOff, fake_obj_va);
}

bool Win32StubsLookup(const char* dll, const char* func, u64* out_va)
{
    return Win32StubsLookupKind(dll, func, out_va, nullptr);
}

bool Win32StubsLookupCatchAll(u64* out_va)
{
    if (out_va == nullptr)
        return false;
    // Route through the miss-logger rather than the bare
    // "xor eax,eax; ret" stub. Behaviourally identical at the
    // call site (returns 0), but each call emits a
    // [win32-miss] line so the boot log identifies, in real
    // time, exactly which unstubbed import the PE just reached.
    *out_va = kWin32StubsVa + kOffMissLogger;
    return true;
}

bool Win32StubsLookupDataCatchAll(u64* out_va)
{
    if (out_va == nullptr)
        return false;
    // Point at a fixed offset inside the proc-env page, guaranteed
    // to be zero-filled (Win32ProcEnvPopulate touches only
    // 0x00..0x140). `mov rax, [data_iat]` then reads 0 instead of
    // the miss-logger's opcode bytes.
    *out_va = kProcEnvVa + kProcEnvDataMissOff;
    return true;
}

bool IsLikelyDataImport(const char* func)
{
    if (func == nullptr || func[0] != '?')
        return false;
    // MSVC mangling for a static/global data symbol is
    //   ?<name>@[<scope>@...]@@3<type-spec>[<type-modifiers>]
    // The `3` after `@@` is the storage-class letter for
    // "static data / global". Functions use storage classes
    // like Q (public non-static), A/B (access), or encode the
    // calling convention after `@@` — none of those is `3`.
    //
    // Walk to the first `@@` (end of qualified name) and inspect
    // the byte that follows. Cap the scan at a defensive 256
    // chars so a malformed name can't run off the end.
    for (u64 i = 1; i < 256; ++i)
    {
        const char c0 = func[i];
        if (c0 == '\0')
            return false;
        if (c0 != '@')
            continue;
        if (func[i + 1] != '@')
            continue;
        return func[i + 2] == '3';
    }
    return false;
}

bool Win32StubsLookupKind(const char* dll, const char* func, u64* out_va, bool* out_is_noop)
{
    if (dll == nullptr || func == nullptr || out_va == nullptr)
        return false;
    const bool found_hashed = Win32StubsLookupHashed(dll, func, out_va, out_is_noop);
#if defined(DUETOS_WIN32_STUBS_VALIDATE_LINEAR)
    u64 linear_va = 0;
    bool linear_noop = false;
    const bool found_linear = Win32StubsLookupLinear(dll, func, &linear_va, &linear_noop);
    if (found_hashed != found_linear ||
        (found_hashed && ((*out_va != linear_va) || ((out_is_noop != nullptr) && (*out_is_noop != linear_noop)))))
    {
        arch::SerialWrite("[win32] lookup mismatch hash-vs-linear for ");
        arch::SerialWrite(dll);
        arch::SerialWrite("!");
        arch::SerialWrite(func);
        arch::SerialWrite("\n");
        if (found_linear)
        {
            *out_va = linear_va;
            if (out_is_noop != nullptr)
                *out_is_noop = linear_noop;
        }
        return found_linear;
    }
#endif
    return found_hashed;
}

void Win32LogNtCoverage()
{
    // Re-walk the generated tables at boot to print the scoreboard.
    // The compile-time `kBedrockNtSyscallsCovered` already has the
    // count, but doing one runtime sweep here also confirms the
    // tables linked correctly into the kernel binary (catches a
    // future "header included but not referenced anywhere" rot).
    using namespace ::duetos::subsystems::win32;
    u32 covered = 0;
    for (u32 i = 0; i < kBedrockNtSyscallCount; ++i)
    {
        if (kBedrockNtSyscalls[i].duetos_sys != kSysNtNotImpl)
            ++covered;
    }
    arch::SerialWrite("[win32] ntdll bedrock coverage: ");
    arch::SerialWriteHex(covered);
    arch::SerialWrite(" / ");
    arch::SerialWriteHex(kBedrockNtSyscallCount);
    arch::SerialWrite(" (generated table = ");
    arch::SerialWriteHex(kBedrockNtSyscallsCovered);
    arch::SerialWrite(")\n");
    arch::SerialWrite("[win32] ntdll full-table entries: ");
    arch::SerialWriteHex(kAllNtSyscallCount);
    arch::SerialWrite(" (every NT syscall known on the target Windows version)\n");
}

} // namespace duetos::win32
