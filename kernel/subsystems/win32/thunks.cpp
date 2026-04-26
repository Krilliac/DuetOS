#include "subsystems/win32/thunks.h"

#include "arch/x86_64/serial.h"
#include "subsystems/win32/proc_env.h"

namespace duetos::win32
{

namespace
{

// ---------------------------------------------------------------
// Thunk bytecode.
//
// See `thunks.h` for the architectural overview — what a thunk
// is, why the bytes are hand-assembled into a single contiguous
// `constexpr u8[]`, and how IAT slots are wired to offsets in
// this array.
//
// Each entry below is a handful of raw x86-64 instructions,
// packed back-to-back. The layout is:
//
// offset 0x00: ExitProcess thunk (9 bytes)
//
// Future entries append at the current end. IAT slots point
// at (kWin32ThunksVa + entry.offset), so stable offsets matter
// only within a single boot — we regenerate + re-map the page
// per process anyway, no persistence between runs.
//
// The assembly is hand-assembled rather than emitted from a
// .S file because (a) it's trivial, (b) a .S file would be
// position-dependent and we want to drop these bytes into a
// runtime-allocated frame, (c) a .S file would mean a second
// user-mode target in the build which is a premature
// abstraction for v0.
//
// Reading the file: each `kOff<Name>` is the offset of a thunk
// inside `kThunksBytes`; the byte rows that follow with `// 0x<addr>`
// comments are the disassembly of that thunk, with the Win32 ABI
// → DuetOS ABI translation written out in inline comments.
// ---------------------------------------------------------------

// Thunk offsets. Kept as named constants so the table below
// stays readable and so two exports (WriteFile + WriteConsoleA)
// can alias to the same offset without duplicating the code.
//
// Names containing `Return*` / `MissLogger` / `CritSecNop` flag
// the genuine no-op stubs (constant returners, miss loggers,
// single-byte `ret`s). Everything else is a real ABI-translation
// thunk.
constexpr u32 kOffExitProcess = 0x00;                        // 9 bytes
constexpr u32 kOffGetStdHandle = 0x09;                       // 3 bytes
constexpr u32 kOffWriteFile = 0x0C;                          // 44 bytes
constexpr u32 kOffGetCurrentProcess = 0x38;                  // 8 bytes
constexpr u32 kOffGetCurrentThread = 0x40;                   // 8 bytes
constexpr u32 kOffGetCurrentProcessId = 0x48;                // 8 bytes
constexpr u32 kOffGetCurrentThreadId = 0x50;                 // 8 bytes
constexpr u32 kOffTerminateProcess = 0x58;                   // 9 bytes
constexpr u32 kOffGetLastError = 0x61;                       // 8 bytes
constexpr u32 kOffSetLastError = 0x69;                       // 10 bytes
constexpr u32 kOffInitCritSec = 0x74;                        // 18 bytes
constexpr u32 kOffCritSecNop = 0x86;                         // 1 byte (ret)
constexpr u32 kOffMemmove = 0x87;                            // 45 bytes (memcpy aliases)
constexpr u32 kOffMemset = 0xB4;                             // 19 bytes
constexpr u32 kOffReturnZero = 0xC7;                         // 3 bytes (shared "xor eax,eax; ret")
constexpr u32 kOffTerminate = 0xCA;                          // 11 bytes (SYS_EXIT(3))
constexpr u32 kOffInvalidParam = 0xD5;                       // 11 bytes (SYS_EXIT(0xC0000417))
constexpr u32 kOffStrcmp = 0xE0;                             // 29 bytes
constexpr u32 kOffStrlen = 0xFD;                             // 17 bytes
constexpr u32 kOffWcslen = 0x10E;                            // 22 bytes
constexpr u32 kOffStrchr = 0x124;                            // 23 bytes
constexpr u32 kOffStrcpy = 0x13B;                            // 23 bytes
constexpr u32 kOffReturnOne = 0x152;                         // 6 bytes (shared "mov eax, 1; ret")
constexpr u32 kOffHeapAlloc = 0x158;                         // 11 bytes
constexpr u32 kOffHeapFree = 0x163;                          // 16 bytes
constexpr u32 kOffGetProcessHeap = 0x173;                    // 8 bytes
constexpr u32 kOffMalloc = 0x17B;                            // 11 bytes
constexpr u32 kOffFree = 0x186;                              // 11 bytes
constexpr u32 kOffCalloc = 0x191;                            // 35 bytes
constexpr u32 kOffOpenProcessToken = 0x1B4;                  // 13 bytes
constexpr u32 kOffLookupPrivVal = 0x1C1;                     // 13 bytes
constexpr u32 kOffInitSListHead = 0x1CE;                     // 16 bytes
[[maybe_unused]] constexpr u32 kOffGetSysTimeFT = 0x1DE;     // 8 bytes (superseded by kOffGetSysTimeFTReal)
constexpr u32 kOffOpenProcess = 0x1E6;                       // 4 bytes
constexpr u32 kOffGetExitCodeThread = 0x1EA;                 // 12 bytes
[[maybe_unused]] constexpr u32 kOffQueryPerfCounter = 0x1F6; // 16 bytes (superseded by kOffQpcNs)
[[maybe_unused]] constexpr u32 kOffQueryPerfFreq = 0x206;    // 13 bytes (superseded by kOffQpfNs)
constexpr u32 kOffGetTickCount = 0x213;                      // 12 bytes (shared w/ GetTickCount64)
constexpr u32 kOffHeapSize = 0x21F;                          // 11 bytes
constexpr u32 kOffHeapRealloc = 0x22A;                       // 16 bytes
constexpr u32 kOffRealloc = 0x23A;                           // 16 bytes
constexpr u32 kOffMissLogger = 0x24A;                        // 41 bytes
constexpr u32 kOffPArgc = 0x273;                             // 6 bytes
constexpr u32 kOffPArgv = 0x279;                             // 6 bytes
constexpr u32 kOffPCommode = 0x27F;                          // 6 bytes
constexpr u32 kOffSputn = 0x285;                             // 19 bytes
constexpr u32 kOffReturnThis = 0x298;                        // 4 bytes
constexpr u32 kOffWiden = 0x29C;                             // 4 bytes
constexpr u32 kOffHresultEFail = 0x2A0;                      // 6 bytes
constexpr u32 kOffGetSysTimeFTReal = 0x2A6;                  // 13 bytes
constexpr u32 kOffQpcNs = 0x2B3;                             // 13 bytes
constexpr u32 kOffQpfNs = 0x2C0;                             // 10 bytes
constexpr u32 kOffSleep = 0x2CF;                             // 12 bytes (push/pop rdi)
constexpr u32 kOffSwitchToThread = 0x2DB;                    // 10 bytes
constexpr u32 kOffGetCmdLineW = 0x2E5;                       // 6 bytes
constexpr u32 kOffGetCmdLineA = 0x2EB;                       // 6 bytes
constexpr u32 kOffGetEnvBlockW = 0x2F1;                      // 6 bytes
constexpr u32 kOffCreateFileW = 0x2F7;                       // 59 bytes (UTF-16 strip + open)
constexpr u32 kOffReadFile = 0x332;                          // 46 bytes
constexpr u32 kOffCloseHandle = 0x360;                       // 15 bytes
constexpr u32 kOffSetFilePtrEx = 0x36F;                      // 38 bytes
constexpr u32 kOffGetFileSizeEx = 0x395;                     // 29 bytes
constexpr u32 kOffGetModuleHandleW = 0x3B2;                  // 17 bytes
constexpr u32 kOffCreateMutexW = 0x3C3;                      // 13 bytes
[[maybe_unused]] constexpr u32 kOffWaitForObj = 0x3D0;       // 38 bytes (mutex-aware, reserved for direct WFMO inline)
constexpr u32 kOffReleaseMutex = 0x3F6;                      // 24 bytes
constexpr u32 kOffWriteConsoleW = 0x40E;                     // 96 bytes (UTF-16 strip + SYS_WRITE)
constexpr u32 kOffGetConsoleMode = 0x46E;                    // 12 bytes
constexpr u32 kOffGetConsoleCP = 0x47A;                      // 6 bytes
constexpr u32 kOffVirtualAlloc = 0x480;                      // 13 bytes
constexpr u32 kOffVirtualFree = 0x48D;                       // 29 bytes
constexpr u32 kOffVirtualProtect = 0x4AA;                    // 18 bytes
constexpr u32 kOffLstrlenW = 0x4BC;                          // 15 bytes
constexpr u32 kOffLstrcmpW = 0x4CB;                          // 37 bytes
constexpr u32 kOffLstrcpyW = 0x4F0;                          // 27 bytes
constexpr u32 kOffIsWow64 = 0x50B;                           // 17 bytes
constexpr u32 kOffGetVersionExW = 0x51C;                     // 34 bytes
constexpr u32 kOffLstrlenA = 0x53E;                          // 14 bytes
constexpr u32 kOffLstrcmpA = 0x54C;                          // 37 bytes
constexpr u32 kOffLstrcpyA = 0x571;                          // 26 bytes
constexpr u32 kOffGetModFileNameW = 0x58B;                   // 24 bytes
constexpr u32 kOffGetCurrentDirW = 0x5A3;                    // 31 bytes
constexpr u32 kOffMBtoWC = 0x5C2;                            // 49 bytes
constexpr u32 kOffWCtoMB = 0x5F3;                            // 48 bytes
constexpr u32 kOffGetUserNameW = 0x623;                      // 47 bytes
constexpr u32 kOffGetComputerNameW = 0x652;                  // 61 bytes
constexpr u32 kOffGetWinDirW = 0x68F;                        // 30 bytes (buf-first sig)
constexpr u32 kOffGetLogicalDrives = 0x6AD;                  // 6 bytes (returns 0x00800000, X: drive)
constexpr u32 kOffGetDriveType = 0x6B3;                      // 6 bytes (returns 3 = DRIVE_FIXED)
constexpr u32 kOffReturnTwo = 0x6B9;                         // 6 bytes (ERROR_FILE_NOT_FOUND / stream pos)
constexpr u32 kOffReturnMinus1 = 0x6BF;                      // 6 bytes (INVALID_FILE_ATTRIBUTES)
constexpr u32 kOffReturnPrioNormal = 0x6C5;                  // 6 bytes (0x20 = NORMAL_PRIORITY_CLASS)
constexpr u32 kOffInterlockedInc = 0x6CB;                    // 12 bytes
constexpr u32 kOffInterlockedDec = 0x6D7;                    // 12 bytes
constexpr u32 kOffInterlockedCmpXchg = 0x6E3;                // 8 bytes
constexpr u32 kOffInterlockedExchg = 0x6EB;                  // 5 bytes
constexpr u32 kOffInterlockedExchgAdd = 0x6F0;               // 7 bytes
constexpr u32 kOffInterlockedInc64 = 0x6F7;                  // 14 bytes
constexpr u32 kOffInterlockedDec64 = 0x705;                  // 16 bytes
constexpr u32 kOffInterlockedCmpXchg64 = 0x715;              // 9 bytes
constexpr u32 kOffInterlockedExchg64 = 0x71E;                // 7 bytes
constexpr u32 kOffInterlockedExchgAdd64 = 0x725;             // 9 bytes
constexpr u32 kOffReturnStatusNotImpl = 0x72E;               // 6 bytes (STATUS_NOT_IMPLEMENTED)
constexpr u32 kOffCreateEventReal = 0x734;                   // 18 bytes (real event-backed)
constexpr u32 kOffSetEventReal = 0x746;                      // 15 bytes
constexpr u32 kOffResetEventReal = 0x755;                    // 15 bytes
// NOTE: kOffWaitForObj2 is retired as of . All imports
// now route through kOffWaitForObj3 which adds the semaphore
// range. The v2 bytes remain inside kThunksBytes (dead code) for
// a follow-up that wants to diff the two; unused constant is
// marked [[maybe_unused]] to suppress the warning.
[[maybe_unused]] constexpr u32 kOffWaitForObj2 = 0x764; // 66 bytes (mutex+event-aware)
constexpr u32 kOffTlsAllocReal = 0x7A6;                 // 8 bytes
constexpr u32 kOffTlsFreeReal = 0x7AE;                  // 24 bytes
constexpr u32 kOffTlsGetValueReal = 0x7C6;              // 13 bytes
constexpr u32 kOffTlsSetValueReal = 0x7D3;              // 20 bytes
constexpr u32 kOffNtAllocateVirtualMemory = 0x7E7;      // 36 bytes
constexpr u32 kOffNtFreeVirtualMemory = 0x80B;          // 33 bytes
constexpr u32 kOffGetSystemTimeSt = 0x82C;              // 11 bytes
constexpr u32 kOffSystemTimeToFileTime = 0x837;         // 14 bytes
constexpr u32 kOffFileTimeToSystemTime = 0x845;         // 14 bytes
constexpr u32 kOffNtQuerySystemTimeReal = 0x853;        // 16 bytes
constexpr u32 kOffNtQueryPerfCounterReal = 0x863;       // 28 bytes
constexpr u32 kOffCreateThreadReal = 0x87F;             // 39 bytes (saves rdi+rsi)
// ThreadExitTramp: offset 0x8A6, 6 bytes. Public VA exported as
// duetos::win32::kWin32ThreadExitTrampVa in thunks.h — keep in sync.

// === ExitThread + OutputDebugStringA + GetProcessTimes
// + GetThreadTimes + GetSystemTimes + GlobalMemoryStatusEx +
// WaitForMultipleObjects.
constexpr u32 kOffExitThread = 0x8AC;             // 9 bytes (noreturn, no save)
constexpr u32 kOffOutputDebugStringA = 0x8B5;     // 13 bytes (saves rdi)
constexpr u32 kOffGetProcessTimes = 0x8C2;        // 44 bytes (also GetThreadTimes)
constexpr u32 kOffGetSystemTimes = 0x8EE;         // 30 bytes
constexpr u32 kOffGlobalMemoryStatusEx = 0x90C;   // 16 bytes (saves rdi)
constexpr u32 kOffWaitForMultipleObjects = 0x91C; // 24 bytes (saves rdi+rsi)

// === GetSystemInfo / OutputDebugStringW / FormatMessageA /
// GetConsoleScreenBufferInfo.
constexpr u32 kOffGetSystemInfo = 0x934;              // 13 bytes (saves rdi)
constexpr u32 kOffOutputDebugStringW = 0x941;         // 13 bytes (saves rdi)
constexpr u32 kOffFormatMessageA = 0x94E;             // 32 bytes
constexpr u32 kOffGetConsoleScreenBufferInfo = 0x96E; // 54 bytes

// === RaiseException / DecodePointer / EncodePointer.
constexpr u32 kOffRaiseException = 0x9A4; // 9 bytes (noreturn)
constexpr u32 kOffDecodePointer = 0x9AD;  // 4 bytes (identity)

// === Semaphore family + upgraded WaitForSingleObject v3.
constexpr u32 kOffCreateSemaphoreW = 0x9B1;             // 27 bytes (saves rdi+rsi)
constexpr u32 kOffReleaseSemaphore = 0x9CC;             // 29 bytes (saves rdi+rsi)
[[maybe_unused]] constexpr u32 kOffWaitForObj3 = 0x9E9; // 94 bytes
                                                        // Retired — see kOffWaitForObj4.

// === real thread-handle wait + 4-range WaitForSingleObject v4.
constexpr u32 kOffWaitForObj4 = 0xA47; // 122 bytes
                                       // (v3 + thread range 0x400..0x407 → SYS_THREAD_WAIT)

// === real GetStartupInfo stub.
constexpr u32 kOffGetStartupInfo = 0xAC1; // 24 bytes (zero-fill + cb=104)

// === real GetExitCodeThread (exit-code tracking).
constexpr u32 kOffGetExitCodeThreadReal = 0xAD9; // 20 bytes (saves rdi)

// === Interlocked{And,Or,Xor} (+64-bit). LOCK CMPXCHG
// loops so SMP future-proofing + timer-tick preemption safety
// hold today.
constexpr u32 kOffInterlockedAnd = 0xAED;   // 16 bytes
constexpr u32 kOffInterlockedOr = 0xAFD;    // 16 bytes
constexpr u32 kOffInterlockedXor = 0xB0D;   // 16 bytes
constexpr u32 kOffInterlockedAnd64 = 0xB1D; // 17 bytes
constexpr u32 kOffInterlockedOr64 = 0xB2E;  // 17 bytes
constexpr u32 kOffInterlockedXor64 = 0xB3F; // 17 bytes

// === real critical sections ======================
// Until now EnterCriticalSection / LeaveCriticalSection were
// single-byte `ret`s — safe while each process ran single-threaded,
// but with SYS_THREAD_CREATE live every call is a latent race.
// These stubs lay an owner-TID + recursion-count lock over the
// existing 40-byte CRITICAL_SECTION struct (InitializeCriticalSection
// already zero-fills it). The acquire uses `lock cmpxchg`; on
// contention we SYS_YIELD and retry.
constexpr u32 kOffEnterCritSecReal = 0xB50; // 49 bytes
constexpr u32 kOffLeaveCritSecReal = 0xB81; // 14 bytes

// === real SRWLOCKs (exclusive-only; shared aliases to exclusive) ===
// Win32 SRWLOCK is a single pointer-sized (8 byte) word. Layout
// we impose: [rcx+0] u64 owner_tid (0 = unheld). Acquire/release
// is a straight `lock cmpxchg` on the slot; shared operations
// degrade to exclusive because we don't track reader counts yet.
// That's suboptimal for reader-heavy workloads but preserves
// correctness — the prior binding (NO-OP for shared) allowed
// readers to observe mid-write state.
constexpr u32 kOffSrwInit = 0xB8F;           // 6 bytes
constexpr u32 kOffSrwAcquireExcl = 0xB95;    // 30 bytes
constexpr u32 kOffSrwReleaseExcl = 0xBB3;    // 6 bytes
constexpr u32 kOffSrwTryAcquireExcl = 0xBB9; // 22 bytes

// === correctness fixes for two always-returning stubs ===
// RtlTryEnterCriticalSection was bound to kOffReturnOne (always
// "got it"), which actively lied to callers — a genuinely held
// lock was reported as free and the caller proceeded into a
// mid-write region. IsProcessorFeaturePresent was bound to
// kOffReturnZero (always "not present"), forcing programs onto
// scalar fallback paths when the real CPU has SSE2/AVX/etc.
// Only TryEnter needs new bytecode; the other fix is a rebind
// to the existing kOffReturnOne.
constexpr u32 kOffTryEnterCritSecReal = 0xBCF; // 56 bytes

// === real SetUnhandledExceptionFilter round-trip ===
// The old bindings were kOffReturnZero for both — SetUnhandled
// always claimed "no previous filter" and UnhandledException
// always returned 0 (EXCEPTION_CONTINUE_SEARCH), which is the
// wrong default. Now we stash the caller-supplied filter in a
// per-process proc-env slot (kProcEnvUnhandledFilterOff) and
// tail-call it on invocation; if the slot is zero we return
// EXCEPTION_EXECUTE_HANDLER (1) — the Windows-default when no
// top-level filter was ever installed.
constexpr u32 kOffSetUnhandledFilter = 0xC07; // 12 bytes
constexpr u32 kOffUnhandledFilter = 0xC13;    // 21 bytes

// === real InitOnce (thread-safe lazy init) =========
// InitOnceInitialize just zero-fills an 8-byte slot; we reuse
// kOffSrwInit for it. InitOnceExecuteOnce does the actual
// call-once state machine: CAS 0->1 picks the initialiser,
// CAS-losers wait for the slot to reach 2 via SYS_YIELD spin.
constexpr u32 kOffInitOnceExec = 0xC28; // 87 bytes

// === real GetProcAddress via SYS_DLL_PROC_ADDRESS =======
// Win32: FARPROC GetProcAddress(HMODULE hModule=rcx, LPCSTR lpProcName=rdx).
// DuetOS: SYS_DLL_PROC_ADDRESS (57) with rdi=hmod, rsi=name.
// Returns exported VA or 0 (= miss). rdi + rsi are callee-saved in
// the Win32 x64 ABI, so save/restore across the syscall.
constexpr u32 kOffGetProcAddressReal = 0xC7F; // 18 bytes

// Render/drivers: D3D11 / D3D12 / DXGI IAT landing pads. Each stub
// issues SYS_GFX_D3D_STUB (101) with a per-kind `rdi` — the kernel
// syscall handler routes to `subsystems::graphics::D3D*CreateStub`
// so the graphics ICD's handle-table counters tick. Returned rax
// is HRESULT E_FAIL (0x80004005). 13 bytes each.
constexpr u32 kOffD3d11CreateStub = 0xC91; // render/drivers — 13 bytes
constexpr u32 kOffD3d12CreateStub = 0xC9E; // render/drivers — 13 bytes
constexpr u32 kOffDxgiCreateStub = 0xCAB;  // render/drivers — 13 bytes

// Paint lifecycle + FillRect — real implementations routing through
// dedicated syscalls. See syscall/syscall.h for the per-syscall ABI.
constexpr u32 kOffWinBeginPaint = 0xCB8;     // render/drivers — 14 bytes
constexpr u32 kOffWinEndPaint = 0xCC6;       // render/drivers — 11 bytes
constexpr u32 kOffWinInvalidateRect = 0xCD1; // render/drivers — 14 bytes
constexpr u32 kOffWinUpdateWindow = 0xCDF;   // render/drivers — 13 bytes
constexpr u32 kOffWinGetDC = 0xCEC;          // render/drivers — 4 bytes
constexpr u32 kOffWinReleaseDC = 0xCF0;      // render/drivers — 6 bytes
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

// DC colour state setters.
constexpr u32 kOffGdiSetTextColor = 0xDE3; // render/drivers — 14 bytes
constexpr u32 kOffGdiSetBkColor = 0xDF1;   // render/drivers — 14 bytes
constexpr u32 kOffGdiSetBkMode = 0xDFF;    // render/drivers — 14 bytes

constexpr u32 kOffGdiStretchBltDC = 0xE0D; // render/drivers — 129 bytes

// Rectangle / Ellipse / SetPixel — previously IAT-less wires into
// the existing SYS_GDI_* syscalls. Each stub repacks Win32 args
// into the kernel's (x,y,w,h,color) shape and sends the request
// on its way. No DC state is consulted today (default white
// outline).
// Outline-only Rectangle / Ellipse — retained for future explicit
// use; default IAT routes went to the filled variants in v6.
[[maybe_unused]] constexpr u32 kOffGdiRectangle = 0xE8E; // render/drivers — 40 bytes
[[maybe_unused]] constexpr u32 kOffGdiEllipse = 0xEB6;   // render/drivers — 40 bytes
constexpr u32 kOffGdiSetPixel = 0xEDE;                   // render/drivers — 20 bytes

// Pen + cursor (MoveToEx / LineTo) stubs — light up the
// outline-drawing primitives (line / rectangle / ellipse) with
// pen-aware colour state.
constexpr u32 kOffGdiCreatePen = 0xEF2; // render/drivers — 17 bytes
constexpr u32 kOffGdiMoveToEx = 0xF03;  // render/drivers — 20 bytes
constexpr u32 kOffGdiLineTo = 0xF17;    // render/drivers — 17 bytes

constexpr u32 kOffGdiDrawTextA = 0xF28; // render/drivers — 25 bytes

// Message-loop IAT stubs — the critical wire-up that takes a PE's
// `while(GetMessage) { TranslateMessage; DispatchMessage; }` loop
// from "exits immediately" (old kOffReturnZero) to "receives real
// input events + calls the WndProc." TranslateMessage stays at
// kOffReturnZero because our PS/2 path already synthesises WM_CHAR
// directly from WM_KEYDOWN; apps expect 0 when nothing translates.
constexpr u32 kOffGetMessageA = 0xF41;      // render/drivers — 14 bytes
constexpr u32 kOffPeekMessageA = 0xF4F;     // render/drivers — 18 bytes
constexpr u32 kOffDispatchMessageA = 0xF61; // render/drivers — 60 bytes

// Filled Rectangle / Ellipse / PatBlt — use the DC's selected
// brush + pen instead of a caller-supplied colour, matching Win32
// Rectangle / Ellipse / PatBlt semantics.
constexpr u32 kOffGdiRectangleFilled = 0xF9D; // render/drivers — 34 bytes
constexpr u32 kOffGdiEllipseFilled = 0xFBF;   // render/drivers — 34 bytes
constexpr u32 kOffGdiPatBlt = 0xFE1;          // render/drivers — 25 bytes

// UTF-16 text entry points. Stub page spans two 4 KiB pages now
// because these plus the filled-primitive stubs pushed us past
// 4 KiB; pe_loader.cpp allocates 2 contiguous frames and maps both.
constexpr u32 kOffGdiTextOutW = 0xFFA;   // render/drivers — 31 bytes
constexpr u32 kOffGdiDrawTextW = 0x1019; // render/drivers — 25 bytes

// System palette entry points.
constexpr u32 kOffGetSysColor = 0x1032;      // render/drivers — 11 bytes
constexpr u32 kOffGetSysColorBrush = 0x103D; // render/drivers — 11 bytes

constexpr u8 kThunksBytes[] = {
#include "subsystems/win32/thunks_bytecode.inc"
};

static_assert(sizeof(kThunksBytes) <= 8192, "Win32 thunks page fits in two 4 KiB pages");
static_assert(sizeof(kThunksBytes) == 0x1048, "thunk layout drifted; update kOff* constants");
// Keep the hand-assembled __p___argc / __p___argv addresses in
// sync with the public proc-env layout constants. The thunk
// bytes encode 0x65000000 and 0x65000008 directly; if proc_env.h
// moves the page VA or the argc / argv-ptr offsets, these
// bytes must follow.
static_assert(kProcEnvVa == 0x65000000ULL, "proc-env page VA no longer matches __p___argc thunk bytes");
static_assert(kProcEnvArgcOff == 0x00, "argc offset no longer matches __p___argc thunk bytes");
static_assert(kProcEnvArgvPtrOff == 0x08, "argv-ptr offset no longer matches __p___argv thunk bytes");
static_assert(kProcEnvCommodeOff == 0x200, "commode offset no longer matches __p__commode thunk bytes");
static_assert(kProcEnvUnhandledFilterOff == 0x600,
              "unhandled-filter offset no longer matches SetUnhandledExceptionFilter stub bytes");

struct ThunkEntry
{
    const char* dll;
    const char* func;
    u32 offset;
};

constexpr ThunkEntry kThunksTable[] = {
#include "subsystems/win32/thunks_table.inc"
};

struct ThunkHashEntry
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

constexpr u64 ThunkLookupHash(const char* dll, const char* func)
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

template <u64 N> struct ThunkHashTable
{
    ThunkHashEntry entries[N];
};

template <u64 N> consteval ThunkHashTable<N> BuildThunkHashTable(const ThunkEntry (&table)[N])
{
    ThunkHashTable<N> sorted{};
    for (u64 i = 0; i < N; ++i)
    {
        sorted.entries[i].key_hash = ThunkLookupHash(table[i].dll, table[i].func);
        sorted.entries[i].stub_index = static_cast<u32>(i);
    }

    // Small-table insertion sort at compile time keeps runtime lookup
    // branch-light and cache-friendly.
    for (u64 i = 1; i < N; ++i)
    {
        ThunkHashEntry value = sorted.entries[i];
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

constexpr auto kSortedThunkHashes = BuildThunkHashTable(kThunksTable);
constexpr u64 kSortedThunkHashCount = sizeof(kSortedThunkHashes.entries) / sizeof(kSortedThunkHashes.entries[0]);
static_assert(kSortedThunkHashCount == (sizeof(kThunksTable) / sizeof(kThunksTable[0])), "hash table size mismatch");

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

#if defined(DUETOS_WIN32_THUNKS_VALIDATE_LINEAR)
bool Win32ThunksLookupLinear(const char* dll, const char* func, u64* out_va, bool* out_is_noop)
{
    for (const ThunkEntry& e : kThunksTable)
    {
        if (!AsciiCaseEqual(e.dll, dll))
            continue;
        if (!AsciiEqual(e.func, func))
            continue;
        *out_va = kWin32ThunksVa + e.offset;
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

bool Win32ThunksLookupHashed(const char* dll, const char* func, u64* out_va, bool* out_is_noop)
{
    const u64 key_hash = ThunkLookupHash(dll, func);
    u64 lo = 0;
    u64 hi = kSortedThunkHashCount;
    while (lo < hi)
    {
        const u64 mid = lo + ((hi - lo) / 2);
        if (kSortedThunkHashes.entries[mid].key_hash < key_hash)
            lo = mid + 1;
        else
            hi = mid;
    }

    for (u64 i = lo; i < kSortedThunkHashCount; ++i)
    {
        const ThunkHashEntry& probe = kSortedThunkHashes.entries[i];
        if (probe.key_hash != key_hash)
            break;
        const ThunkEntry& e = kThunksTable[probe.stub_index];
        if (!AsciiCaseEqual(e.dll, dll) || !AsciiEqual(e.func, func))
            continue;
        *out_va = kWin32ThunksVa + e.offset;
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

void Win32ThunksPopulate(u8* dst)
{
    if (dst == nullptr)
        return;
    for (u64 i = 0; i < sizeof(kThunksBytes); ++i)
        dst[i] = kThunksBytes[i];
}

bool Win32ThunksLookup(const char* dll, const char* func, u64* out_va)
{
    return Win32ThunksLookupKind(dll, func, out_va, nullptr);
}

bool Win32ThunksLookupCatchAll(u64* out_va)
{
    if (out_va == nullptr)
        return false;
    // Route through the miss-logger rather than the bare
    // "xor eax,eax; ret" stub. Behaviourally identical at the
    // call site (returns 0), but each call emits a
    // [win32-miss] line so the boot log identifies, in real
    // time, exactly which unstubbed import the PE just reached.
    *out_va = kWin32ThunksVa + kOffMissLogger;
    return true;
}

bool Win32ThunksLookupDataCatchAll(u64* out_va)
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
    // ?<name>@[<scope>@...]@@3<type-spec>[<type-modifiers>]
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

bool Win32ThunksLookupKind(const char* dll, const char* func, u64* out_va, bool* out_is_noop)
{
    if (dll == nullptr || func == nullptr || out_va == nullptr)
        return false;
    const bool found_hashed = Win32ThunksLookupHashed(dll, func, out_va, out_is_noop);
#if defined(DUETOS_WIN32_THUNKS_VALIDATE_LINEAR)
    u64 linear_va = 0;
    bool linear_noop = false;
    const bool found_linear = Win32ThunksLookupLinear(dll, func, &linear_va, &linear_noop);
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

} // namespace duetos::win32
