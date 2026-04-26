#pragma once

#include "arch/x86_64/traps.h"
#include "util/types.h"

/*
 * DuetOS syscall gate — v0.
 *
 * One vector today: 0x80, reached from ring 3 via `int 0x80`. The gate
 * is a DPL=3 interrupt descriptor, so ring-3 code can issue the int
 * without #GP'ing; once delivered, the trap frame lands on the current
 * task's RSP0 kernel stack and isr_common calls into
 * `core::SyscallDispatch` via the main TrapDispatch.
 *
 * Calling convention (v0):
 *   - Syscall number in rax.
 *   - Args in rdi, rsi, rdx (up to three for the first pass — extend to
 *     r10, r8, r9 when a real consumer needs it).
 *   - Return value in rax. A syscall that never returns (SYS_exit)
 *     simply tail-calls sched::SchedExit from inside the dispatcher;
 *     the half-consumed trap frame is abandoned with its task.
 *
 * Syscall numbers are ABI — once published, NEVER renumber. Add new
 * numbers at the tail of the enum; retired numbers stay with a
 * `// reserved — do not reuse` comment.
 *
 * Context: kernel. `SyscallInit` runs once after IdtInit, before any
 * user task is spawned.
 */

namespace duetos::core
{

enum SyscallNumber : u64
{
    SYS_EXIT = 0,
    SYS_GETPID = 1,
    SYS_WRITE = 2,
    SYS_YIELD = 3,
    // SYS_STAT: rdi = user pointer to NUL-terminated path, rsi = user
    // pointer to a u64 output slot that receives the file size.
    // Returns 0 on success, -1 on any failure (path not found, path
    // out of jail, bad user pointer, or cap missing). Gated on
    // kCapFsRead. Path lookup is anchored at CurrentProcess()->root
    // — a sandboxed process's namespace is its subtree only.
    SYS_STAT = 4,
    // SYS_READ: rdi = user pointer to NUL-terminated path, rsi = user
    // pointer to destination buffer, rdx = buffer capacity in bytes.
    // Returns number of bytes actually written on success (≤ both
    // the file size and the buffer capacity), 0 for an empty file,
    // or -1 on failure (cap missing, path out of jail, not a file,
    // bad user pointers). Gated on kCapFsRead; lookup is anchored
    // at CurrentProcess()->root.
    SYS_READ = 5,
    // SYS_DROPCAPS: rdi = bitmask of caps to remove from the
    // calling process's CapSet. Always succeeds (dropping a cap
    // the process doesn't hold is a no-op). The drop is
    // irreversible — there's no SYS_GRANTCAPS. Useful pattern:
    // a process starts trusted, does trusted initialization,
    // then SYS_DROPCAPS'es down to a minimal set before parsing
    // untrusted input. Returns 0 always. No cap check on the
    // syscall itself (anyone can make themselves LESS
    // privileged).
    SYS_DROPCAPS = 6,
    // SYS_SPAWN: rdi = user pointer to NUL-terminated ELF path,
    // rsi = path length (caller-supplied to bound the CopyFromUser).
    // Returns the new child pid on success, or (u64)-1 on any
    // failure (cap missing, path out of jail, not a file, invalid
    // ELF, OOM). Gated on kCapFsRead (file-path access is the
    // observable primitive) — a sandbox without it can't name
    // a binary to spawn in the first place. The child inherits
    // the caller's CapSet + namespace root (POSIX fork+exec
    // shape: spawn-from-path, same privileges down).
    SYS_SPAWN = 7,
    // SYS_GETPROCID: no args. Returns CurrentProcess()->pid —
    // distinct from SYS_GETPID, which returns the scheduler's
    // task id. Win32's GetCurrentProcessId/GetCurrentThreadId
    // map to this pair: process id is the `Process` struct's
    // pid (what `[proc] create pid=N` logs); thread id is the
    // scheduler task id (what `[sched] created task id=N`
    // logs). In v0 each process has exactly one task, but the
    // two IDs already come from different counters — the
    // stubs in kernel/subsystems/win32 need to distinguish.
    SYS_GETPROCID = 8,
    // SYS_GETLASTERROR / SYS_SETLASTERROR: Win32 last-error
    // read/write. GetLastError takes no args, returns the
    // caller's Process.win32_last_error. SetLastError takes
    // rdi = new error code (low 32 bits), no return. Both
    // are unprivileged — a process's own error slot is not
    // cap-gated. In real Windows these live in the TEB at
    // offset 0x68; v0 parks them on the Process struct and
    // exposes them via syscalls until per-thread TEBs land.
    SYS_GETLASTERROR = 9,
    SYS_SETLASTERROR = 10,

    // SYS_HEAP_ALLOC / SYS_HEAP_FREE: Win32 process-heap
    // allocator backends. HEAP_ALLOC takes rdi = size in bytes,
    // returns the user VA of the allocation (0 on OOM).
    // HEAP_FREE takes rdi = pointer returned by a prior
    // HEAP_ALLOC, returns 0 (value ignored by the user stubs).
    //
    // Unprivileged: every Win32 process gets its own heap
    // region mapped at 0x50000000 when the PE loader stands
    // up the stubs page. The kernel32 stubs HeapAlloc /
    // HeapFree / malloc / free / calloc trampoline through
    // these syscalls. See kernel/subsystems/win32/heap.h.
    SYS_HEAP_ALLOC = 11,
    SYS_HEAP_FREE = 12,

    // SYS_PERF_COUNTER: no args. Returns the kernel tick
    // counter from arch::TimerTicks() — a monotonically
    // increasing u64, incremented at kTickFrequencyHz
    // (100 Hz → 10 ms resolution). Used by the Win32
    // QueryPerformanceCounter / GetTickCount stubs; the
    // kernel32 stub can convert ticks → ms or hand the raw
    // value through.
    //
    // Unprivileged — exposing the tick counter leaks boot
    // time and timing info, but so does any millisecond-
    // resolution clock; we accept it.
    SYS_PERF_COUNTER = 13,

    // SYS_HEAP_SIZE: rdi = user pointer previously returned
    // by SYS_HEAP_ALLOC. Returns the block's payload
    // capacity in bytes (the rounded-up allocation size
    // recorded in the block header, minus the 16-byte
    // header). Returns 0 for a null pointer or a pointer
    // outside the caller's heap region. Backs Win32
    // HeapSize.
    SYS_HEAP_SIZE = 14,

    // SYS_HEAP_REALLOC: rdi = existing user pointer (may be
    // 0 to request a fresh allocation), rsi = new requested
    // size in bytes. Returns the new user VA (possibly
    // equal to rdi if the existing block already fit) or 0
    // on failure. Semantics: if rdi == 0, equivalent to
    // SYS_HEAP_ALLOC(rsi). If rsi == 0, frees rdi and
    // returns 0 (ucrt-realloc convention). Otherwise, if
    // the existing block's payload is already >= rsi the
    // same pointer comes back unchanged; if not, a new
    // block is allocated, the old payload is copied across,
    // and the old block is freed. Backs Win32 HeapReAlloc,
    // ucrt realloc, msvcrt realloc.
    SYS_HEAP_REALLOC = 15,

    // SYS_WIN32_MISS_LOG: rdi = VA of the IAT slot that was just
    // called (produced by the miss-logger trampoline in the
    // Win32 stubs page, which reads its own `call [rip+disp32]`
    // return address to compute the slot). No arguments beyond
    // that; no meaningful return value (the trampoline zeroes
    // rax itself). The handler looks up the IAT slot VA in
    // `CurrentProcess()->win32_iat_misses` and emits a
    // `[win32-miss] called <fn>` line so the boot log tells us,
    // in real time, exactly which unstubbed import the PE just
    // reached. Unprivileged — the trampoline is our own code
    // and the lookup reads only this process's own table.
    SYS_WIN32_MISS_LOG = 16,

    // SYS_GETTIME_FT: returns the current wall-clock time as a
    // Windows FILETIME — a u64 count of 100-nanosecond intervals
    // since 1601-01-01 00:00:00 UTC. No arguments. Reads the
    // CMOS RTC, converts, returns in rax. Used by the Win32
    // `GetSystemTimeAsFileTime` stub to replace the old
    // "write 0 and return" placeholder with a real timestamp.
    SYS_GETTIME_FT = 17,

    // SYS_NOW_NS: returns nanoseconds since boot in rax. No args.
    // Backed by the HPET counter × femtosecond-period / 1e6 —
    // ~70 ns resolution on QEMU (14.318 MHz HPET), nanosecond
    // resolution on modern chipsets. Used by the Win32
    // QueryPerformanceCounter stub for a sub-millisecond
    // high-resolution clock.
    SYS_NOW_NS = 18,

    // SYS_SLEEP_MS: rdi = milliseconds to block. Returns 0 on
    // wake. Special-cased: rdi == 0 behaves like SYS_YIELD (drop
    // the current time slice, reschedule). Otherwise the caller
    // is moved to the sleep queue and woken by the timer tick
    // after at least `rdi` ms have elapsed.
    //
    // Resolution is bounded by the scheduler tick (100 Hz today
    // = 10 ms grain). A request for 5 ms still sleeps a full
    // tick — Sleep semantics are "at least", never "at most".
    // Backs Win32 `Sleep` and `SleepEx`.
    //
    // Unprivileged. The only resource consumed is a slot on the
    // sleep queue, which is per-process bounded by the existing
    // task budget.
    SYS_SLEEP_MS = 19,

    // SYS_FILE_OPEN: rdi = user pointer to NUL-terminated ASCII
    // path, rsi = path-length cap (caller-supplied to bound the
    // CopyFromUser). Returns a Win32-shaped handle
    // (Process::kWin32HandleBase + slot_idx, i.e. 0x100..0x10F)
    // on success, or u64(-1) on any failure (cap missing, path
    // out of jail, not a file, no free slot, bad user pointer).
    // Gated on kCapFsRead — same gate as SYS_READ / SYS_STAT.
    //
    // The handle stays valid until SYS_FILE_CLOSE; reads via
    // SYS_FILE_READ advance a per-handle cursor that starts at 0.
    // Backs Win32 CreateFileA. CreateFileW does its own UTF-16
    // → ASCII strip in the user-mode stub before issuing this
    // syscall.
    SYS_FILE_OPEN = 20,

    // SYS_FILE_READ: rdi = handle (Win32-shaped), rsi = user dst
    // buffer, rdx = byte count cap. Returns bytes actually
    // copied (≤ both `rdx` and remaining bytes in the file from
    // the cursor) on success, 0 at EOF, u64(-1) on failure
    // (closed handle, bad user pointer). Advances the per-handle
    // cursor by the returned count. Unprivileged — the caller
    // already proved cap ownership at SYS_FILE_OPEN.
    SYS_FILE_READ = 21,

    // SYS_FILE_CLOSE: rdi = handle. Returns 0 on success or no-op
    // (closing an already-closed / never-opened handle is a
    // documented no-op in the Win32 contract). Frees the slot
    // for re-use. Unprivileged.
    SYS_FILE_CLOSE = 22,

    // SYS_FILE_SEEK: rdi = handle, rsi = signed offset, rdx =
    // whence (0 = SET, 1 = CUR, 2 = END). Returns the new
    // cursor position (relative to file start) on success, or
    // u64(-1) on failure. v0 clamps the cursor to [0, file_size]
    // — seeking past EOF lands at file_size, seeking before
    // start lands at 0. Backs Win32 SetFilePointerEx.
    SYS_FILE_SEEK = 23,

    // SYS_FILE_FSTAT: rdi = handle, rsi = user pointer to a
    // u64 output slot that receives the file size in bytes.
    // Returns 0 on success, u64(-1) on bad handle / bad user
    // pointer. Does NOT modify the read cursor (unlike
    // SYS_FILE_SEEK with SEEK_END which would). Backs Win32
    // GetFileSizeEx + GetFileSize.
    SYS_FILE_FSTAT = 24,

    // SYS_MUTEX_CREATE: rdi = bInitialOwner (0 or 1).
    // Allocates a per-process mutex slot and returns a Win32
    // pseudo-handle (Process::kWin32MutexBase + slot_idx, i.e.
    // 0x200..0x207). On bInitialOwner=1 the calling task is
    // recorded as the owner with recursion=1 — subsequent
    // SYS_MUTEX_WAIT calls from the same task increment
    // recursion (Win32 mutexes are recursive). Returns u64(-1)
    // on slot exhaustion. Backs Win32 CreateMutexW / CreateMutexA.
    SYS_MUTEX_CREATE = 25,

    // SYS_MUTEX_WAIT: rdi = mutex handle, rsi = timeout in ms
    // (0xFFFFFFFF = INFINITE). Returns:
    //   0           — WAIT_OBJECT_0   (got the mutex)
    //   0x102       — WAIT_TIMEOUT    (woken by timer, not by release)
    //   u64(-1)     — WAIT_FAILED     (bad handle)
    // Recursive: if the owner is the calling task, recursion++ and
    // we return WAIT_OBJECT_0 immediately. Otherwise blocks on the
    // mutex's waitqueue with the given timeout. ReleaseMutex's
    // hand-off sets owner=us before waking, so the lock is already
    // ours on return. Backs Win32 WaitForSingleObject / WaitForSingleObjectEx
    // for mutex handles only — handles outside the mutex range
    // hit the user-mode stub's pseudo-signal path (return 0 for
    // events / threads / etc., preserving the semantics).
    SYS_MUTEX_WAIT = 26,

    // SYS_MUTEX_RELEASE: rdi = mutex handle. Returns 0 on
    // success, u64(-1) on bad handle or non-owner release
    // (ERROR_NOT_OWNER). Decrements recursion; on reaching 0,
    // clears owner and hands off to the longest-waiting blocker
    // (FIFO via WaitQueueWakeOne) — that waiter's SYS_MUTEX_WAIT
    // call returns WAIT_OBJECT_0 with the lock already theirs.
    // Backs Win32 ReleaseMutex.
    SYS_MUTEX_RELEASE = 27,

    // SYS_VMAP: rdi = byte size (rounded up to next page).
    // Allocates the next N = ceil(size / 4096) physical frames
    // via AllocateFrame and maps them RW + NX + User into the
    // caller's address space at Process::vmap_base +
    // vmap_pages_used * 4096, then bumps vmap_pages_used.
    // Returns the base VA of the allocation on success, or 0
    // on failure (arena exhausted / OOM).
    //
    // v0 is bump-only — SYS_VUNMAP is a documented leak so
    // there's no fragmentation/coalescing to worry about. A
    // second slice can replace this with a region tracker
    // when a workload genuinely needs reclaim.
    //
    // Unprivileged. Pages are mapped into the caller's own AS,
    // bounded by kWin32VmapCapPages (128 = 512 KiB per process).
    // Backs Win32 VirtualAlloc with flAllocationType covering
    // MEM_COMMIT | MEM_RESERVE; flProtect is silently coerced
    // to RW+NX (the DuetOS W^X policy — no W+X pages).
    SYS_VMAP = 28,

    // SYS_VUNMAP: rdi = VA, rsi = size. Returns 0 on success,
    // u64(-1) on failure. v0 is a NO-OP that validates the VA
    // falls inside the vmap arena + returns 0 — no physical
    // reclaim. A leak, logged as such, but deterministic: the
    // kernel's per-process frame budget eventually clamps a
    // runaway allocator. Backs Win32 VirtualFree.
    SYS_VUNMAP = 29,

    // SYS_EVENT_CREATE: rdi = bManualReset (0 or 1),
    // rsi = bInitialState (0 or 1). Allocates a per-process
    // event slot and returns Process::kWin32EventBase + slot
    // (= 0x300..0x307) on success, u64(-1) on slot exhaustion.
    //
    // Manual-reset events stay signaled after a wait succeeds;
    // auto-reset events clear the signal on successful wait.
    // Backs Win32 CreateEventW / CreateEventA / CreateEventExW.
    SYS_EVENT_CREATE = 30,

    // SYS_EVENT_SET: rdi = event handle. Marks the event
    // signaled and wakes waiters:
    //   * Manual-reset: wakes ALL waiters; signal stays set.
    //   * Auto-reset: wakes ONE waiter; auto-clears the signal
    //     if a waiter was woken (matches Win32 docs).
    // Returns 0 on success, u64(-1) on bad handle. Backs Win32
    // SetEvent.
    SYS_EVENT_SET = 31,

    // SYS_EVENT_RESET: rdi = event handle. Clears the signal.
    // Returns 0 on success, u64(-1) on bad handle. Backs Win32
    // ResetEvent. Mostly a no-op for auto-reset events (they
    // auto-clear anyway).
    SYS_EVENT_RESET = 32,

    // SYS_EVENT_WAIT: rdi = event handle, rsi = timeout_ms.
    // Returns WAIT_OBJECT_0 (0) on success, WAIT_TIMEOUT (0x102)
    // on timeout, or u64(-1) on bad handle. Same shape as
    // SYS_MUTEX_WAIT. Blocking semantics:
    //   * Already signaled: return immediately; auto-reset events
    //     clear the signal first.
    //   * Not signaled: block on the event's waitqueue; timeout
    //     via WaitQueueBlockTimeout.
    //   * INFINITE timeout (0xFFFFFFFF): block forever via
    //     WaitQueueBlock.
    SYS_EVENT_WAIT = 33,

    // SYS_TLS_ALLOC: no args. Returns the lowest unused TLS
    // slot index (0..63) or u64(-1) if all 64 slots are in use.
    // Sets the corresponding bit in Process::tls_slot_in_use.
    // Backs Win32 TlsAlloc (+FlsAlloc aliases).
    SYS_TLS_ALLOC = 34,

    // SYS_TLS_FREE: rdi = slot index. Returns 0 on success,
    // u64(-1) on bad index / unallocated slot. Clears the
    // in-use bit AND zeros the stored value. Backs Win32
    // TlsFree.
    SYS_TLS_FREE = 35,

    // SYS_TLS_GET: rdi = slot index. Returns the stored u64
    // value, or 0 if the index is invalid / unallocated
    // (Win32 TlsGetValue returns 0 + sets LastError to
    // ERROR_INVALID_PARAMETER in the bad-index case; v0 skips
    // the LastError side effect). Backs Win32 TlsGetValue.
    SYS_TLS_GET = 36,

    // SYS_TLS_SET: rdi = slot index, rsi = value. Returns 0
    // on success, u64(-1) on bad index. Silently succeeds
    // even if the slot was allocated and then freed — caller
    // is responsible for tracking which slots are live.
    // Backs Win32 TlsSetValue.
    SYS_TLS_SET = 37,

    // SYS_BP_INSTALL: install a hardware breakpoint on the
    // current task. rdi = va, rsi = BpKind (1=exec, 2=write,
    // 3=read/write) OR'd with flags (bit 4 = suspend-on-hit),
    // rdx = length (1/2/4/8). Returns a non-zero breakpoint id
    // on success, or u64(-1) on error. Requires kCapDebug on
    // the caller's process. The BP rides per-task DR state,
    // so context switches preserve it; other tasks running on
    // other CPUs don't see it.
    //
    // Suspend-on-hit (rsi |= 0x10): when this BP fires on a
    // ring-3 instruction, the hitting task is parked on a
    // wait-queue and the scheduler picks something else. An
    // operator drives resume/step/inspect via the `bp` shell
    // command (phase 3 has no ring-3 inspect syscall yet —
    // the caller either suspends itself and waits for an
    // external resumer, or a sibling task resumes it).
    SYS_BP_INSTALL = 38,

    // SYS_BP_REMOVE: remove a breakpoint previously returned
    // by SYS_BP_INSTALL. rdi = id. Returns 0 on success,
    // u64(-1) on unknown id. Requires kCapDebug. Removing a
    // BP that belongs to a different process returns -1
    // (BPs are scoped per-process).
    SYS_BP_REMOVE = 39,

    // SYS_GETTIME_ST: rdi = user pointer to a 16-byte SYSTEMTIME
    // struct. Samples the RTC and fills the struct in place with
    // year/month/dayOfWeek/day/hour/minute/second/milliseconds.
    // Returns 0 on success, u64(-1) on EFAULT.
    //
    // Companion to SYS_GETTIME_FT (17): FT returns a u64 FILETIME
    // in rax; ST writes a SYSTEMTIME into the caller's buffer.
    // The Win32 GetSystemTime / GetLocalTime stubs route through
    // this; LocalTime is the same as SystemTime until we have a
    // timezone database.
    SYS_GETTIME_ST = 40,

    // SYS_ST_TO_FT: rdi = user pointer to an input SYSTEMTIME,
    // rsi = user pointer to an output FILETIME. Converts the 8
    // WORD calendar fields to a 100-ns-tick count since
    // 1601-01-01 UTC. Returns 0 on success; u64(-1) on EFAULT
    // or on out-of-range input (year < 1601, month 0 or > 12,
    // day 0 or > 31). Backs Win32 SystemTimeToFileTime.
    SYS_ST_TO_FT = 41,

    // SYS_FT_TO_ST: rdi = user pointer to an input FILETIME,
    // rsi = user pointer to an output SYSTEMTIME. Reverse of
    // SYS_ST_TO_FT. Backs Win32 FileTimeToSystemTime.
    SYS_FT_TO_ST = 42,

    // SYS_FILE_WRITE: rdi = handle (Win32-shaped, 0x100..0x10F),
    // rsi = user pointer to source bytes, rdx = byte count.
    // Writes `rdx` bytes at the handle's current cursor and
    // advances the cursor by the bytes-written count. Returns
    // bytes written (0..rdx) or u64(-1) on bad handle / bad
    // user pointer / EOF-no-grow / I/O failure / cap denied.
    //
    // Cap-gated on kCapFsWrite. Backing dispatch:
    //   Ramfs  → -1 (ramfs is .rodata, refuses writes).
    //   Fat32  → Fat32WriteInPlace within [cursor..min(cursor+rdx,
    //            file_size)]. Past EOF the call fails — file
    //            growth requires SYS_FILE_CREATE / append paths
    //            that the routing layer hasn't exposed yet.
    //
    // Backs Win32 WriteFile / WriteFileEx for handle-based I/O.
    SYS_FILE_WRITE = 43,

    // SYS_FILE_CREATE: rdi = user pointer to NUL-terminated
    // ASCII path, rsi = path-buffer cap (bytes), rdx = user
    // pointer to initial bytes (may be 0/null for empty file),
    // r10 = initial byte count. Creates the file at `path` with
    // `r10` bytes of initial content; returns a Win32 pseudo-
    // handle (kWin32HandleBase + slot_idx) on success, u64(-1)
    // on failure (bad path / cap denied / parent-dir missing /
    // duplicate name / OOM / I/O failure).
    //
    // Cap-gated on kCapFsWrite. Path routing follows the same
    // /disk/<idx>/<rest> convention as SYS_FILE_OPEN; ramfs
    // paths fail (no create on read-only backing). Fat32 paths
    // call Fat32CreateAtPath under the hood, then look up the
    // freshly-planted entry and allocate a handle pointing at
    // it — so the caller can immediately write/read the new
    // file via the same handle.
    //
    // Backs Win32 CreateFileW with dwCreationDisposition =
    // CREATE_NEW or CREATE_ALWAYS.
    SYS_FILE_CREATE = 44,

    // SYS_THREAD_CREATE: rdi = user-mode start VA (thread
    // proc), rsi = user-mode parameter (passed as RCX on
    // thread entry per Win32 x64 calling convention). Spawns
    // a new Task sharing the caller's Process + AddressSpace +
    // cap set; allocates kV0ThreadStackPages of user stack at
    // the process's `thread_stack_cursor` and bumps it.
    //
    // Returns a Win32 pseudo-handle (kWin32ThreadBase +
    // slot_idx, i.e. 0x400..0x407) on success, u64(-1) on bad
    // start VA / cap denied / slot-table full / stack-arena
    // exhausted / Task-creation failure. Cap-gated on
    // kCapSpawnThread.
    //
    // v0 limitations documented at Process::Win32ThreadHandle.
    // Backs Win32 CreateThread / CreateRemoteThread-on-self.
    SYS_THREAD_CREATE = 45,

    // SYS_DEBUG_PRINT: rdi = user pointer to NUL-terminated ASCII
    // string. Emits "[odbg] ..." on serial. Cap-gated on
    // kCapSerialConsole. Backs Win32 OutputDebugStringA.
    SYS_DEBUG_PRINT = 46,

    // SYS_MEM_STATUS: rdi = user pointer to a 64-byte Win32
    // MEMORYSTATUSEX struct. Populates from frame allocator
    // stats. Backs Win32 GlobalMemoryStatusEx.
    SYS_MEM_STATUS = 47,

    // SYS_WAIT_MULTI: rdi = count, rsi = user pointer to handle
    // array, rdx = bWaitAll, r10 = timeout_ms. Returns
    // WAIT_OBJECT_0+i / WAIT_TIMEOUT / WAIT_FAILED.
    // Backs Win32 WaitForMultipleObjects.
    SYS_WAIT_MULTI = 48,

    // SYS_SYSTEM_INFO: rdi = user pointer to Win32 SYSTEM_INFO
    // (48 bytes). Populates with x86_64 constants. Backs
    // GetSystemInfo / GetNativeSystemInfo.
    SYS_SYSTEM_INFO = 49,

    // SYS_DEBUG_PRINTW: rdi = user pointer to NUL-terminated
    // UTF-16LE string. Strips to ASCII, emits "[odbgw] ...".
    // Backs Win32 OutputDebugStringW.
    SYS_DEBUG_PRINTW = 50,

    // SYS_SEM_CREATE: rdi = initial count, rsi = max count.
    // Returns Win32SemaphoreHandle (0x500..0x507) or -1.
    // Backs Win32 CreateSemaphoreW / CreateSemaphoreA.
    SYS_SEM_CREATE = 51,

    // SYS_SEM_RELEASE: rdi = handle, rsi = release count.
    // Returns PREVIOUS count on success. Wakes up to rsi
    // waiters. Backs Win32 ReleaseSemaphore.
    SYS_SEM_RELEASE = 52,

    // SYS_SEM_WAIT: rdi = handle, rsi = timeout_ms. Blocks
    // until count > 0, decrements, returns 0 (WAIT_OBJECT_0).
    // Dispatched by the semaphore range in WaitForSingleObject v3.
    SYS_SEM_WAIT = 53,

    // SYS_THREAD_WAIT: rdi = thread handle (0x400..0x407),
    // rsi = timeout_ms. Polls exit_code until != STILL_ACTIVE.
    // Dispatched by the thread range in WaitForSingleObject v4.
    SYS_THREAD_WAIT = 54,

    // SYS_THREAD_EXIT_CODE: rdi = thread handle (0x400..0x407).
    // Returns the recorded exit code (u32) as u64, or 0x103
    // (STILL_ACTIVE) if the thread is still running. Returns
    // u64(-1) on bad handle. The kernel writes this slot from
    // SYS_EXIT when a Win32 thread task dies.
    // Backs Win32 GetExitCodeThread.
    SYS_THREAD_EXIT_CODE = 55,

    // SYS_NT_INVOKE: Windows NT syscall forwarding gateway.
    // rdi = NT syscall number (e.g. 0x0F for NtClose).
    // rsi..r9 carry up to five NT-ABI arguments.
    // Returns the translated NTSTATUS in rax, or
    // STATUS_NOT_IMPLEMENTED (0xC0000002) for any NT number not
    // yet wired into the NT→Linux translator.
    //
    // Purpose: lets a user-mode ntdll.dll shim forward NT calls
    // into the kernel without every individual NT stub needing
    // its own SYS_* number. The kernel-side translator (in
    // subsystems/translation/translate.cpp::NtTranslateToLinux)
    // maps a small set of NT calls (NtClose, NtYieldExecution,
    // NtDelayExecution, NtQueryPerformanceCounter,
    // NtGetCurrentProcessorNumber, NtFlushBuffersFile,
    // NtGetTickCount, NtQuerySystemTime, NtTerminateThread,
    // NtTerminateProcess) onto matching Linux handlers in
    // subsystems/linux/syscall.cpp.
    //
    // This is the Windows→Linux fallback path: anything a Win32
    // subsystem needs that already has a Linux implementation
    // can be reached via this bridge rather than reinvented on
    // the native side.
    //
    // Moved to 56 from the original 46 during the merge of
    // claude/refactor-inspect-command into the win32 development
    // branch — the win32 work had already published 46..55.
    SYS_NT_INVOKE = 56,

    // SYS_DLL_PROC_ADDRESS: Win32 GetProcAddress, table-backed.
    // rdi = HMODULE (the DLL's load base VA; 0 = "any
    //       registered DLL", matches the common case where the
    //       caller already narrows to a specific DLL by name
    //       via our future GetModuleHandle path).
    // rsi = user pointer to a NUL-terminated ASCII function
    //       name. Bounded-copied via CopyFromUser.
    //
    // Returns the absolute VA of the exported function on hit,
    // or 0 on miss (module not in the process's DLL table,
    // name not exported, forwarder — forwarder chasing not yet
    // implemented).
    //
    // Part of the DLL-loader work. Replaces the
    // return-zero GetProcAddress stub. See
    // .claude/knowledge/pe-eat-dll-loader-v0.md.
    SYS_DLL_PROC_ADDRESS = 57,

    // Windowing family — bridge user32.dll's CreateWindowExA/W /
    // DestroyWindow / ShowWindow / MessageBox stubs into the
    // kernel-mode compositor + window registry that live in
    // kernel/drivers/video/widget.{h,cpp}. v0: ring-3 PEs can
    // register a rectangle with a title, have the compositor
    // paint it in z-order with the rest of the desktop, and tear
    // it down on exit. No message pump yet — GetMessage still
    // returns 0 (WM_QUIT). No keyboard/mouse dispatch to the
    // target window yet — input routes to the native console
    // as before.
    //
    // SYS_WIN_CREATE — register a window in the compositor.
    //   rdi = x (u32, framebuffer coord)
    //   rsi = y (u32)
    //   rdx = width (u32; clamped to framebuffer width)
    //   r10 = height (u32; clamped to framebuffer height)
    //   r8  = user pointer to NUL-terminated ASCII title
    //         (bounded copy, truncated to kWinTitleMax bytes).
    //         May be null → falls back to a generic "WINDOW"
    //         label so the chrome still has a visible title bar.
    //   rax = non-zero HWND on success (biased +1 so handle 0
    //         can continue to mean "failure" per Win32 convention).
    //         0 on failure (no free slots, OOM for the title copy,
    //         or fault on the title pointer).
    //
    // Cap-gated on kCapWindow — a future bit in CapSet; for v0
    // every process has the cap implicitly so the bridge works
    // out of the box.
    SYS_WIN_CREATE = 58,

    // SYS_WIN_DESTROY — tear down a window registered via
    // SYS_WIN_CREATE.
    //   rdi = HWND returned by SYS_WIN_CREATE (biased; kernel
    //         unbiases before touching the registry).
    //   rax = 1 on success, 0 on invalid handle.
    //
    // Triggers a DesktopCompose under the compositor lock so
    // the window visually disappears in the same call.
    SYS_WIN_DESTROY = 59,

    // SYS_WIN_SHOW — map Win32 ShowWindow(cmd) onto our
    // compositor. Only two behaviours matter for v0:
    //   cmd == 0 (SW_HIDE) → close the window (same as
    //     DESTROY, but the HWND stays allocated so a
    //     subsequent ShowWindow(SW_SHOW*) could in principle
    //     re-map — not implemented yet; hidden windows stay
    //     hidden for the process's lifetime).
    //   cmd != 0 (anything "show"-ish)            → raise +
    //     compose.
    //   rdi = HWND (biased)
    //   rsi = cmd
    //   rax = 0 (Win32 ShowWindow's "BOOL — was the window
    //         previously visible" is always reported as FALSE
    //         here; we don't track visibility history).
    SYS_WIN_SHOW = 60,

    // SYS_WIN_MSGBOX — synchronous message-box surrogate. No
    // modal dialog is drawn in v0; the text + caption are
    // emitted to the serial console as a single [msgbox]
    // record so the call is visible + debuggable, and IDOK is
    // returned so callers that branch on the result continue
    // along the "user clicked OK" path.
    //   rdi = user pointer to NUL-terminated ASCII text
    //         (bounded to kWinMsgBoxTextMax)
    //   rsi = user pointer to NUL-terminated ASCII caption
    //         (bounded to kWinTitleMax; nullable → "MessageBox")
    //   rax = 1 (IDOK)
    SYS_WIN_MSGBOX = 61,

    // SYS_WIN_PEEK_MSG — non-blocking dequeue of one pending
    // message for the current process.
    //   rdi = user pointer to a 4×u64 output slot:
    //         [hwnd_biased, message, wparam, lparam]
    //   rsi = HWND filter (biased) — 0 = any window owned by
    //         the caller's pid. Non-zero restricts to that one
    //         window's queue.
    //   rdx = bRemove (0 = peek only, non-zero = dequeue).
    //   rax = 1 if a message was available (and, if bRemove,
    //         removed from the queue), 0 if nothing pending.
    // Backs Win32 PeekMessageA / PeekMessageW.
    SYS_WIN_PEEK_MSG = 62,

    // SYS_WIN_GET_MSG — blocking dequeue of one pending message.
    //   rdi = user pointer to a 4×u64 output slot (same layout
    //         as PEEK_MSG).
    //   rsi = HWND filter (biased) — 0 = any.
    //   rax = 1 for a regular message, 0 if the message was
    //         WM_QUIT (caller breaks its message loop), u64(-1)
    //         on bad user pointer.
    // v0 implementation polls + SchedSleepTicks(1) when the
    // queue is empty — 10 ms latency to an incoming message.
    // Backs Win32 GetMessageA / GetMessageW.
    SYS_WIN_GET_MSG = 63,

    // SYS_WIN_POST_MSG — enqueue a message to a window.
    //   rdi = HWND (biased)
    //   rsi = message code (UINT — WM_* id)
    //   rdx = wParam
    //   r10 = lParam
    //   rax = 1 on success, 0 on invalid handle.
    // The message is appended to the target window's ring;
    // overflow drops the oldest and the call still reports
    // success (classic input-queue policy).
    // Backs Win32 PostMessageA / PostMessageW.
    SYS_WIN_POST_MSG = 64,

    // SYS_GDI_FILL_RECT — record a solid-fill primitive in a
    // window's client-area display list. The compositor replays
    // the list after chrome on every DesktopCompose.
    //   rdi = HWND (biased)
    //   rsi = x (i32 client-local)
    //   rdx = y (i32 client-local)
    //   r10 = w (i32)
    //   r8  = h (i32)
    //   r9  = COLORREF in Win32 0x00BBGGRR form; the kernel
    //         re-packs to the framebuffer's 0x00RRGGBB layout
    //         before storage.
    //   rax = 1 on success, 0 on invalid handle.
    // Backs Win32 gdi32 FillRect + Rectangle's fill path.
    SYS_GDI_FILL_RECT = 65,

    // SYS_GDI_TEXT_OUT — record an ASCII TextOut primitive.
    //   rdi = HWND (biased)
    //   rsi = x (i32 client-local)
    //   rdx = y (i32 client-local)
    //   r10 = user pointer to text (bounded to kWinTextOutMax
    //         bytes, non-ASCII stored as '?')
    //   r8  = text length (bytes; truncated to cap)
    //   r9  = COLORREF (0x00BBGGRR; repacked like FILL_RECT)
    //   rax = 1 on success, 0 on bad handle / bad user pointer.
    // Backs Win32 gdi32 TextOutA / TextOutW.
    SYS_GDI_TEXT_OUT = 66,

    // SYS_GDI_RECTANGLE — record a 1-px outline primitive.
    //   rdi..r9 same as SYS_GDI_FILL_RECT.
    // Backs Win32 gdi32 Rectangle (outline half only in v0 —
    // fill is the caller's job via FillRect first).
    SYS_GDI_RECTANGLE = 67,

    // SYS_GDI_CLEAR — drop every recorded primitive for a
    // window (backs WM_PAINT with bErase = TRUE +
    // InvalidateRect / BeginPaint reset).
    //   rdi = HWND (biased)
    //   rax = 1 on success, 0 on invalid handle.
    SYS_GDI_CLEAR = 68,

    // SYS_WIN_MOVE — reposition + optionally resize a window.
    //   rdi = HWND (biased)
    //   rsi = x (u32, framebuffer coord) — ignored if r9 bit 0
    //   rdx = y (u32)                     — ignored if r9 bit 0
    //   r10 = w (u32; 0 = "don't change")
    //   r8  = h (u32; 0 = "don't change")
    //   r9  = flags: bit 0 = nomove (SWP_NOMOVE), bit 1 = nosize
    //         (SWP_NOSIZE). Neither set = move + resize.
    //   rax = 1 on success, 0 on invalid handle.
    // Backs Win32 MoveWindow / SetWindowPos.
    SYS_WIN_MOVE = 69,

    // SYS_WIN_GET_RECT — read back a window's geometry.
    //   rdi = HWND (biased)
    //   rsi = rect selector: 0 = window rect (outer bounds,
    //         framebuffer coords), 1 = client rect (local,
    //         origin always 0,0; right/bottom = client w/h).
    //   rdx = user pointer to a 16-byte RECT (left, top, right,
    //         bottom; int32 each).
    //   rax = 1 on success, 0 on bad handle / bad user pointer.
    // Backs Win32 GetWindowRect + GetClientRect.
    SYS_WIN_GET_RECT = 70,

    // SYS_WIN_SET_TEXT — overwrite a window's title in place.
    //   rdi = HWND (biased)
    //   rsi = user pointer to ASCII text (NUL-terminated)
    //   rax = 1 on success, 0 on invalid handle / bad pointer.
    // Backs Win32 SetWindowTextA; SetWindowTextW does its own
    // UTF-16 → ASCII strip on the user side first.
    SYS_WIN_SET_TEXT = 71,

    // SYS_WIN_TIMER_SET — install or update a per-window timer.
    //   rdi = HWND (biased)
    //   rsi = timer_id (u32; caller-assigned)
    //   rdx = interval in ms (rounds up to scheduler ticks)
    //   rax = timer_id on success, 0 on failure (bad handle,
    //         timer table full, or interval == 0).
    // Backs Win32 SetTimer. Timer ticker posts WM_TIMER
    // (wParam = timer_id) to the window every interval.
    SYS_WIN_TIMER_SET = 72,

    // SYS_WIN_TIMER_KILL — remove a timer.
    //   rdi = HWND (biased)
    //   rsi = timer_id
    //   rax = 1 on success, 0 if unknown. Backs Win32 KillTimer.
    SYS_WIN_TIMER_KILL = 73,

    // SYS_GDI_LINE — record a Bresenham line primitive.
    //   rdi = HWND (biased)
    //   rsi = x0, rdx = y0, r10 = x1, r8 = y1 (i32 client-local)
    //   r9  = COLORREF. Backs Win32 LineTo + MoveToEx+LineTo.
    SYS_GDI_LINE = 74,

    // SYS_GDI_ELLIPSE — 1-px outline inside a bounding box.
    //   Same arg shape as SYS_GDI_FILL_RECT. Backs Win32 Ellipse.
    SYS_GDI_ELLIPSE = 75,

    // SYS_GDI_SET_PIXEL — single-pixel primitive.
    //   rdi = HWND, rsi = x, rdx = y, r10 = COLORREF.
    //   Backs Win32 SetPixel / SetPixelV.
    SYS_GDI_SET_PIXEL = 76,

    // SYS_WIN_GET_KEYSTATE — async keyboard state query.
    //   rdi = virtual-key / character code (low 8 bits used).
    //   rax = Win32-style short: high bit set iff currently
    //         held; low bit set iff toggled (v1: toggled bit
    //         not tracked — always 0). Backs Win32 GetKeyState
    //         + GetAsyncKeyState.
    SYS_WIN_GET_KEYSTATE = 77,

    // SYS_WIN_GET_CURSOR — read cursor position.
    //   rdi = user pointer to a 2×i32 POINT (x, y).
    //   rax = 1 on success, 0 on bad pointer. Backs
    //         GetCursorPos.
    SYS_WIN_GET_CURSOR = 78,

    // SYS_WIN_SET_CURSOR — move cursor.
    //   rdi = x, rsi = y (framebuffer coords; clamped).
    //   rax = 1 on success. Backs SetCursorPos.
    SYS_WIN_SET_CURSOR = 79,

    // SYS_WIN_SET_CAPTURE — grab mouse for `HWND`.
    //   rdi = HWND.
    //   rax = previously-captured HWND (biased; 0 if none).
    //         Backs Win32 SetCapture.
    SYS_WIN_SET_CAPTURE = 80,

    // SYS_WIN_RELEASE_CAPTURE — release capture. No args.
    //   rax = 1 always. Backs Win32 ReleaseCapture.
    SYS_WIN_RELEASE_CAPTURE = 81,

    // SYS_WIN_GET_CAPTURE — query captured HWND. No args.
    //   rax = biased HWND, or 0 if none. Backs Win32 GetCapture.
    SYS_WIN_GET_CAPTURE = 82,

    // SYS_WIN_CLIP_SET_TEXT — replace clipboard text.
    //   rdi = user pointer to NUL-terminated ASCII (nullable).
    //   rax = 1 always. Backs Win32 SetClipboardData(CF_TEXT)
    //         via the user32 wrapper.
    SYS_WIN_CLIP_SET_TEXT = 83,

    // SYS_WIN_CLIP_GET_TEXT — read clipboard text.
    //   rdi = user buffer pointer, rsi = buffer capacity.
    //   rax = stored length in bytes (0 if empty / bad
    //         pointer / zero cap). Backs Win32
    //         GetClipboardData(CF_TEXT).
    SYS_WIN_CLIP_GET_TEXT = 84,

    // SYS_WIN_GET_LONG — read a per-window long slot.
    //   rdi = HWND (biased)
    //   rsi = slot index (0=WNDPROC, 1=USERDATA, 2/3=extra)
    //   rax = 64-bit value, 0 on bad handle / index.
    // Backs Win32 GetWindowLongPtrA / SetWindowLongA / etc.
    SYS_WIN_GET_LONG = 85,

    // SYS_WIN_SET_LONG — write a per-window long slot.
    //   rdi = HWND, rsi = index, rdx = value.
    //   rax = previous value. Backs SetWindowLongPtrA.
    SYS_WIN_SET_LONG = 86,

    // SYS_WIN_INVALIDATE — mark a window client-dirty.
    //   rdi = HWND, rsi = bErase (ignored in v1; display-list
    //         replay always repaints the whole client).
    //   rax = 1 on success, 0 on bad handle.
    // Next pump-drain posts WM_PAINT. Backs Win32 InvalidateRect
    // (with nullptr rect and erase = FALSE).
    SYS_WIN_INVALIDATE = 87,

    // SYS_WIN_VALIDATE — clear dirty bit without painting.
    //   rdi = HWND. rax = 1 on success. Backs ValidateRect
    //   + the implicit validate inside EndPaint.
    SYS_WIN_VALIDATE = 88,

    // SYS_WIN_GET_ACTIVE — read the currently-active HWND.
    //   rax = biased HWND of the active window, or 0 if none.
    // Backs GetActiveWindow / GetForegroundWindow.
    SYS_WIN_GET_ACTIVE = 89,

    // SYS_WIN_SET_ACTIVE — make `HWND` the active + topmost.
    //   rdi = HWND. rax = previous active (biased; 0 if none).
    // Backs SetActiveWindow / SetForegroundWindow.
    SYS_WIN_SET_ACTIVE = 90,

    // SYS_WIN_GET_METRIC — read a GetSystemMetrics selector.
    //   rdi = SM_* index (see user32 stub).
    //   rax = integer metric; 0 for unknown indices. Matches
    //   Win32 (programs tolerate 0 for unsupported selectors).
    SYS_WIN_GET_METRIC = 91,

    // SYS_WIN_ENUM — fill an array with biased HWNDs of every
    // alive window in registration order.
    //   rdi = user pointer to u64[cap]
    //   rsi = cap (#entries)
    //   rax = actual count written (≤ cap).
    // Backs EnumWindows via a client-side loop that calls the
    // user callback per-HWND.
    SYS_WIN_ENUM = 92,

    // SYS_WIN_FIND — find a window by title.
    //   rdi = user pointer to ASCII title (NUL-terminated)
    //   rax = biased HWND of first match, or 0. Title compare
    //   is case-insensitive (Win32 convention). Backs
    //   FindWindowA / FindWindowW (W variant flattens client-
    //   side).
    SYS_WIN_FIND = 93,

    // SYS_WIN_SET_PARENT — set a window's parent HWND.
    //   rdi = HWND (child, biased), rsi = HWND (parent, biased;
    //         0 = clear/top-level).
    //   rax = previous parent (biased; 0 if none).
    // Backs Win32 SetParent.
    SYS_WIN_SET_PARENT = 94,

    // SYS_WIN_GET_PARENT — read a window's parent HWND.
    //   rdi = HWND. rax = biased parent or 0. Backs GetParent.
    SYS_WIN_GET_PARENT = 95,

    // SYS_WIN_GET_RELATED — walk the window relationship graph.
    //   rdi = HWND, rsi = rel kind (0=Next, 1=Prev, 2=First,
    //         3=Last, 4=Child, 5=Owner).
    //   rax = biased HWND, or 0. Backs Win32 GetWindow.
    SYS_WIN_GET_RELATED = 96,

    // SYS_WIN_SET_FOCUS — move keyboard focus to HWND.
    //   rdi = HWND (0 = clear focus).
    //   rax = biased HWND of previous focus, or 0.
    // Fires WM_KILLFOCUS on the old focus + WM_SETFOCUS on the
    // new. Backs Win32 SetFocus.
    SYS_WIN_SET_FOCUS = 97,

    // SYS_WIN_GET_FOCUS — read current focus HWND.
    //   rax = biased HWND of focus, or 0. Backs Win32 GetFocus.
    SYS_WIN_GET_FOCUS = 98,

    // SYS_WIN_CARET — combined caret control.
    //   rdi = op (0=Create, 1=Destroy, 2=SetPos, 3=Show, 4=Hide)
    //   rsi = arg1 (Create: width; SetPos: x; Show/Hide: 0)
    //   rdx = arg2 (Create: height; SetPos: y)
    //   r10 = arg3 (Create: HWND owner; else unused)
    //   rax = 1 on success, 0 on bad op. Backs Win32
    //         CreateCaret / DestroyCaret / SetCaretPos /
    //         ShowCaret / HideCaret.
    SYS_WIN_CARET = 99,

    // SYS_WIN_BEEP — sound the PC speaker (blocking).
    //   rdi = frequency in Hz (0 = use Win32 MB_OK default 800)
    //   rsi = duration in ms (0 = 100 ms default)
    //   rax = 1 if played, 0 if the speaker isn't usable.
    // Backs Win32 MessageBeep + Beep.
    SYS_WIN_BEEP = 100,

    // SYS_GFX_D3D_STUB — trace + return E_FAIL from a D3D/DXGI IAT
    // stub. rdi = kind:
    //   1 = D3D11CreateDevice / D3D11CreateDeviceAndSwapChain
    //   2 = D3D12CreateDevice / D3D12GetDebugInterface /
    //       D3D12SerializeRootSignature
    //   3 = CreateDXGIFactory / CreateDXGIFactory1 / 2
    // rax = HRESULT (0x80004005 for any valid kind; 0 on bad kind).
    // Routes to subsystems::graphics::D3D11CreateDeviceStub /
    // D3D12CreateDeviceStub / DxgiCreateFactoryStub so the graphics
    // ICD's handle-table counters tick every time a PE invokes one
    // of these entry points — visible via the `gfx` shell command.
    SYS_GFX_D3D_STUB = 101,

    // SYS_GDI_BITBLT — record a BitBlt into a window's display list.
    //   rdi = HWND (biased Win32 handle, same convention as the
    //         other SYS_GDI_* syscalls)
    //   rsi = dst_x (client-relative, i32)
    //   rdx = dst_y
    //   r10 = src_w (pixels, must be <= kWinBlitMaxPx / src_h)
    //   r8  = src_h
    //   r9  = user VA of `src_w * src_h` BGRA8888 pixels (row-major,
    //         no padding)
    // rax = 1 on success, 0 on bad handle / pool full / copy-from-
    // user fault / too large. Pixel data is copied into the kernel
    // compositor's per-window blit pool immediately; the user
    // buffer can be freed on return. Replayed by the compositor at
    // DesktopCompose time.
    SYS_GDI_BITBLT = 102,

    // SYS_WIN_BEGIN_PAINT — Win32 BeginPaint.
    //   rdi = HWND (biased)
    //   rsi = user VA of PAINTSTRUCT (72 B) to fill. Layout must
    //         match Win32:
    //             off 0 : HDC hdc (set to hwnd cast as HDC)
    //             off 8 : BOOL fErase (set to 1 if dirty)
    //             off 12: RECT rcPaint (set to client-rect
    //                     (0, 0, client_w, client_h))
    //             off 28: BOOL fRestore (zeroed)
    //             off 32: BOOL fIncUpdate (zeroed)
    //             off 36: BYTE rgbReserved[32] (zeroed)
    //   rax = HDC on success, 0 on bad handle / copy-to-user fault.
    // Side effect: clears the window's dirty flag (equivalent to an
    // implicit ValidateRect at BeginPaint time, matching Win32).
    SYS_WIN_BEGIN_PAINT = 103,

    // SYS_WIN_END_PAINT — Win32 EndPaint.
    //   rdi = HWND (biased). rsi = PAINTSTRUCT* (ignored).
    //   rax = 1. v0 no-op; dirty clear already happened at BeginPaint.
    SYS_WIN_END_PAINT = 104,

    // SYS_GDI_FILL_RECT_USER — Win32 FillRect equivalent with user-
    // mode RECT pointer.
    //   rdi = HWND (biased)
    //   rsi = user VA of RECT { i32 left, top, right, bottom }
    //   rdx = colour (treated as RGB u32; HBRUSH handles from
    //         GetStockObject map poorly but the rect still paints)
    //   rax = 1 on success, 0 on bad handle / copy-from-user fault.
    // Recomposes the desktop after recording.
    SYS_GDI_FILL_RECT_USER = 105,

    // SYS_GDI_CREATE_COMPAT_DC — CreateCompatibleDC. rdi = hdc_src
    // (ignored in v0). rax = new memory HDC (tagged handle) or 0.
    SYS_GDI_CREATE_COMPAT_DC = 106,

    // SYS_GDI_CREATE_COMPAT_BITMAP — CreateCompatibleBitmap.
    // rdi = hdc (ignored), rsi = width, rdx = height.
    // rax = HBITMAP (tagged) or 0. Pixels are KMalloc'd BGRA8888,
    // row-major, pitch = width*4.
    SYS_GDI_CREATE_COMPAT_BITMAP = 107,

    // SYS_GDI_CREATE_SOLID_BRUSH — CreateSolidBrush.
    // rdi = COLORREF (0x00BBGGRR Win32 layout). rax = HBRUSH.
    SYS_GDI_CREATE_SOLID_BRUSH = 108,

    // SYS_GDI_GET_STOCK_OBJECT — GetStockObject.
    // rdi = stock index (0..5 for brushes; others return 0 in v0).
    // rax = stable HBRUSH handle, or 0 for unsupported index.
    SYS_GDI_GET_STOCK_OBJECT = 109,

    // SYS_GDI_SELECT_OBJECT — SelectObject.
    // rdi = HDC, rsi = HGDIOBJ. Returns previously-selected object
    // in rax. For memory DCs we currently only track the selected
    // HBITMAP; brush/pen selections are a no-op pass-through (the
    // handle comes back unchanged).
    SYS_GDI_SELECT_OBJECT = 110,

    // SYS_GDI_DELETE_DC — DeleteDC.
    // rdi = HDC. Frees a memory DC; no-op (returns 1) on window DCs
    // or invalid handles. rax = 1/0.
    SYS_GDI_DELETE_DC = 111,

    // SYS_GDI_DELETE_OBJECT — DeleteObject.
    // rdi = HGDIOBJ. Frees a bitmap's pixel buffer or drops a
    // non-stock brush. Stock brushes are a safe no-op. rax = 1/0.
    SYS_GDI_DELETE_OBJECT = 112,

    // SYS_GDI_SET_TEXT_COLOR — SetTextColor on a memDC.
    //   rdi = HDC, rsi = COLORREF (0x00BBGGRR).
    //   rax = previous COLORREF. For window HDCs the call is a
    //   round-trip: returns `rsi` unchanged so SetTextColor /
    //   GetTextColor pairs keep their Win32 semantics, but the
    //   window-DC value doesn't actually take effect anywhere.
    SYS_GDI_SET_TEXT_COLOR = 114,

    // SYS_GDI_SET_BK_COLOR — SetBkColor. Same shape as SET_TEXT_COLOR.
    SYS_GDI_SET_BK_COLOR = 115,

    // SYS_GDI_SET_BK_MODE — SetBkMode. rdi = HDC, rsi = mode
    //   (1 = TRANSPARENT, 2 = OPAQUE). rax = previous mode.
    SYS_GDI_SET_BK_MODE = 116,

    // SYS_GDI_STRETCH_BLT_DC — Win32 StretchBlt (11-arg). `rdi`
    // points at a user-stack struct of 11 u64 slots in this order:
    //   +0x00 HDC hdcDst        +0x38 int src_x
    //   +0x08 int dst_x         +0x40 int src_y
    //   +0x10 int dst_y         +0x48 int src_w
    //   +0x18 int dst_w         +0x50 int src_h
    //   +0x20 int dst_h         +0x58 DWORD rop
    //   +0x28 HDC hdcSrc
    // Scales `src_w × src_h` down / up to `dst_w × dst_h` via
    // nearest-neighbor sampling. Capped at `kWinBlitMaxPx` on the
    // destination. SRCCOPY-equivalent; ROP ignored in v0.
    SYS_GDI_STRETCH_BLT_DC = 117,

    // SYS_GDI_CREATE_PEN — Win32 CreatePen.
    //   rdi = style (ignored in v0), rsi = width, rdx = COLORREF.
    //   rax = HPEN (tagged). v0 only supports solid pens.
    SYS_GDI_CREATE_PEN = 118,

    // SYS_GDI_MOVE_TO_EX — Win32 MoveToEx.
    //   rdi = HDC, rsi = x, rdx = y, r10 = user LPPOINT (may be 0).
    //   If `r10` != 0, writes the previous cur pos as { LONG, LONG }.
    //   rax = 1 on success, 0 on invalid HDC / copy-to-user fault.
    SYS_GDI_MOVE_TO_EX = 119,

    // SYS_GDI_LINE_TO — Win32 LineTo.
    //   rdi = HDC, rsi = x1 (end), rdx = y1. Reads DC cur pos,
    //   draws a 1-px line to (x1, y1) in the DC's selected pen
    //   colour (BLACK_PEN implicit if none), updates cur pos.
    //   Works on both memDCs (Bresenham into bitmap) and window
    //   HDCs (display-list line prim + recompose).
    SYS_GDI_LINE_TO = 120,

    // SYS_GDI_DRAW_TEXT_USER — Win32 DrawTextA.
    //   rdi = HDC
    //   rsi = user text pointer
    //   rdx = text length (-1 for NUL-terminated)
    //   r10 = user LPRECT (bounding RECT in client coords)
    //   r8  = format flags (DT_SINGLELINE / DT_CENTER / DT_VCENTER /
    //                       DT_RIGHT / DT_LEFT / DT_TOP)
    //   rax = height of the drawn text in pixels on success, or 0
    //         on bad handle / copy-from-user fault. Single-line
    //         only in v0.
    SYS_GDI_DRAW_TEXT_USER = 121,

    // SYS_GDI_RECTANGLE_FILLED — fill + outline a rect using the
    // DC's currently-selected brush (fill) + pen (outline).
    //   rdi = HDC, rsi = x, rdx = y, r10 = w, r8 = h.
    //   rax = 1 / 0. v0: window path records two display-list
    //   primitives (FillRect + Rectangle); memDC path paints
    //   bitmap + draws four Bresenham edges.
    SYS_GDI_RECTANGLE_FILLED = 122,

    // SYS_GDI_ELLIPSE_FILLED — Win32 Ellipse. Same arg shape as
    // SYS_GDI_RECTANGLE_FILLED. v0: memDC path fills via
    // bounding-box ellipse scan (integer math, no sqrt); window
    // path records the outline only (filled-ellipse display-list
    // prim is a future slice).
    SYS_GDI_ELLIPSE_FILLED = 123,

    // SYS_GDI_PAT_BLT — fill a rect with the DC's current brush.
    // ROP is ignored in v0 (treated as PATCOPY).
    //   rdi = HDC, rsi = x, rdx = y, r10 = w, r8 = h.
    SYS_GDI_PAT_BLT = 124,

    // SYS_GDI_TEXT_OUT_W — UTF-16 sibling of SYS_GDI_TEXT_OUT.
    // Same arg shape; `r8` is the length in wchar_t units (not
    // bytes). Kernel copies in, strips each u16 to ASCII (> 0x7F
    // becomes '?'), then feeds the ASCII path.
    SYS_GDI_TEXT_OUT_W = 125,

    // SYS_GDI_DRAW_TEXT_W — UTF-16 sibling of SYS_GDI_DRAW_TEXT_USER.
    // Same shape; `rdx` (len) is in wchar_ts (-1 = NUL-terminated).
    SYS_GDI_DRAW_TEXT_W = 126,

    // SYS_GDI_GET_SYS_COLOR — Win32 GetSysColor.
    //   rdi = nIndex (COLOR_WINDOW=5, COLOR_BTNFACE=15, etc.)
    //   rax = COLORREF for that palette slot, or 0x00C0C0C0
    //         (classic grey) for unknown indices.
    SYS_GDI_GET_SYS_COLOR = 127,

    // SYS_GDI_GET_SYS_COLOR_BRUSH — Win32 GetSysColorBrush.
    //   rdi = nIndex. rax = HBRUSH pre-registered at boot time
    //         for the matching colour, or 0 for unknown indices.
    // Never needs DeleteObject (stock-like — app must not free).
    SYS_GDI_GET_SYS_COLOR_BRUSH = 128,

    // SYS_GDI_BITBLT_DC — Win32 BitBlt (9-arg). `rdi` points at a
    // user-stack-resident struct of 9 u64 slots in this order:
    //   +0x00  HDC   hdcDst
    //   +0x08  int   x      (low 32 meaningful; upper ignored)
    //   +0x10  int   y
    //   +0x18  int   cx
    //   +0x20  int   cy
    //   +0x28  HDC   hdcSrc
    //   +0x30  int   x1
    //   +0x38  int   y1
    //   +0x40  DWORD rop    (treated as SRCCOPY for any value in v0)
    // Effect: the pixels from `hdcSrc`'s selected HBITMAP, subrect
    // `(x1, y1, cx, cy)`, are blitted into `hdcDst` (a window HWND)
    // at `(x, y)` as a Blit display-list primitive. Recomposes.
    // rax = 1 on success, 0 on any validation failure.
    // Capped at `kWinBlitMaxPx` total pixels per call.
    SYS_GDI_BITBLT_DC = 113,

    // SYS_WIN32_CUSTOM — multiplexed entry point for the Win32
    // subsystem's custom diagnostics + safety extensions. Sub-op
    // is in rdi (see win32::custom::kOp* constants); rsi/rdx/r10
    // are op-specific. Per-process state is lazy-allocated on the
    // first SetPolicy call and lives on Process::win32_custom_state.
    // Default policy = 0 — every feature is opt-in so apps that
    // probe Windows-buggy behaviour are unaffected.
    SYS_WIN32_CUSTOM = 129,

    // SYS_REGISTRY — multiplexed entry point for the kernel-side
    // Win32 registry. Sub-op in rdi (see
    // duetos::subsystems::win32::registry::kOp*); the rest of the
    // arg layout is per-op (registry.h documents each op).
    //
    // Backs ntdll.dll's NtOpenKey / NtQueryValueKey direct
    // syscalls — the Reg* family in advapi32.dll is unaffected
    // (advapi32 still serves its own well-known tree without
    // crossing the syscall boundary). The two trees are kept in
    // sync by hand, see kernel/subsystems/win32/registry.cpp's
    // header comment.
    //
    // Returns NTSTATUS in rax (kNtStatusSuccess = 0,
    // STATUS_OBJECT_NAME_NOT_FOUND = 0xC0000034, etc.) — the
    // registry surface is the only kernel syscall today that
    // reports NTSTATUS rather than -errno or 0/1, because every
    // caller (NtOpenKey, NtQueryValueKey) is bound to that
    // contract on the Win32 side.
    SYS_REGISTRY = 130,
};

/// Install the DPL=3 IDT gate for vector 0x80. Must run after IdtInit
/// (the IDT must already be loaded) and before any ring-3 entry.
/// Upper bound on path-argument length for SYS_STAT / SYS_FILE_OPEN
/// / SYS_READ etc. Bounds the on-kernel-stack bounce buffer the
/// copy-in path uses so there's no unbounded user-controlled copy.
inline constexpr u64 kSyscallPathMax = 256;

/// Upper bound on the NUL-terminated string SYS_DEBUG_PRINT will
/// scan/emit. Matches kSyscallWriteMax so the kernel-stack bounce
/// buffer reuses the same ceiling.
inline constexpr u64 kSyscallDebugPrintMax = 256;

/// Cap on the number of handles a single SYS_WAIT_MULTI call may
/// pass. Matches the Win32 MAXIMUM_WAIT_OBJECTS (64). Bounds the
/// kernel-stack bounce array the syscall uses.
inline constexpr u64 kSyscallWaitMultiMax = 64;

/// Bounded copy-in length for window titles (SYS_WIN_CREATE) and
/// MessageBox captions (SYS_WIN_MSGBOX). Keeps the on-kernel-stack
/// bounce buffer tiny. Titles longer than this are silently
/// truncated — Win32 already allows arbitrary UI truncation.
inline constexpr u64 kWinTitleMax = 64;

/// Bounded copy-in length for MessageBox body text. 256 bytes is a
/// comfortable single-line budget and keeps the serial record
/// human-readable.
inline constexpr u64 kWinMsgBoxTextMax = 256;

void SyscallInit();

/// Called from arch::TrapDispatch when frame->vector == 0x80. Examines
/// the trap frame's rax (syscall number) and dispatches. Returning
/// writes frame->rax with the syscall's return value; SYS_exit never
/// returns.
void SyscallDispatch(arch::TrapFrame* frame);

} // namespace duetos::core
