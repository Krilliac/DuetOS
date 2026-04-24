#pragma once

#include "../arch/x86_64/traps.h"
#include "types.h"

/*
 * CustomOS syscall gate — v0.
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

namespace customos::core
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
    // events / threads / etc., preserving the slice-10 semantics).
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
    // to RW+NX (the CustomOS W^X policy — no W+X pages).
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
    // string. No length arg — kernel scans up to
    // kSyscallDebugPrintMax bytes for the terminator. Emits a
    // single "[odbg] ..." line on the serial console. Returns 0
    // always (void-shaped in user space). Cap-gated on
    // kCapSerialConsole — the same gate SYS_WRITE uses for fd=1.
    //
    // Backs Win32 OutputDebugStringA. OutputDebugStringW converts
    // UTF-16 → ASCII in a user stub before calling this syscall
    // (or a future SYS_DEBUG_PRINTW).
    SYS_DEBUG_PRINT = 46,

    // SYS_MEM_STATUS: rdi = user pointer to a 64-byte Win32
    // MEMORYSTATUSEX struct. Kernel populates the fields with a
    // snapshot of the frame allocator's totals/free + a synthetic
    // virtual-address-space figure derived from the process's
    // mapped region count. Returns 0 on success, u64(-1) on
    // bad user pointer or wrong struct size (dwLength).
    //
    // Backs Win32 GlobalMemoryStatusEx. Unprivileged — every
    // process can observe its own memory envelope.
    SYS_MEM_STATUS = 47,

    // SYS_WAIT_MULTI: rdi = count, rsi = user pointer to a
    // count-sized array of Win32 handles (u64 each), rdx =
    // bWaitAll (0 = any, 1 = all), r10 = timeout_ms
    // (0xFFFFFFFF = INFINITE).
    //
    // Return values track Win32 WaitForMultipleObjects:
    //   WAIT_OBJECT_0 + i (0 + 0..count-1) — handle i signaled
    //                                         (wait-any) or all
    //                                         handles signaled
    //                                         (wait-all — returns
    //                                         WAIT_OBJECT_0)
    //   WAIT_TIMEOUT  (0x102)               — timeout elapsed
    //   WAIT_FAILED   (u64(-1))             — bad args / bad handle /
    //                                         count > kMaxObjects
    //
    // v0: poll-and-yield implementation. Loops through the handle
    // array inspecting each handle's signaled state; if the wait
    // isn't satisfied, issues SchedYield (or SchedSleepTicks for a
    // timed wait) and retries. Not wake-driven — adequate for the
    // common "wait on N events" pattern but spins a timeslice per
    // iteration under contention. A future slice will thread
    // multi-waiters through the event/mutex waitqueues directly.
    //
    // Unprivileged (same as the single-object waits).
    SYS_WAIT_MULTI = 48,

    // SYS_SYSTEM_INFO: rdi = user pointer to a Win32 SYSTEM_INFO
    // struct (48 bytes). Kernel populates with constants describing
    // the host CPU + address-space topology:
    //   wProcessorArchitecture   = 9 (PROCESSOR_ARCHITECTURE_AMD64)
    //   dwPageSize               = 4096
    //   lpMinimumApplicationAddress = 0x10000
    //   lpMaximumApplicationAddress = 0x7FFFFFFE0000
    //   dwActiveProcessorMask    = 1
    //   dwNumberOfProcessors     = 1
    //   dwProcessorType          = 8664 (PROCESSOR_AMD_X8664)
    //   dwAllocationGranularity  = 0x10000
    //   wProcessorLevel          = 6
    //   wProcessorRevision       = 0
    // Returns 0 on success, u64(-1) on bad user pointer. Backs
    // Win32 GetSystemInfo / GetNativeSystemInfo (WoW64 distinction
    // doesn't apply — we're native x86_64).
    SYS_SYSTEM_INFO = 49,

    // SYS_DEBUG_PRINTW: rdi = user pointer to NUL-terminated
    // UTF-16LE string. Kernel reads up to
    // kSyscallDebugPrintMax wide-characters (each 2 bytes), strips
    // high byte to produce ASCII (non-ASCII chars replaced with '?'),
    // and emits "[odbgw] ..." on serial. Returns 0. Cap-gated on
    // kCapSerialConsole (same as SYS_DEBUG_PRINT). Backs
    // Win32 OutputDebugStringW.
    SYS_DEBUG_PRINTW = 50,

    // SYS_SEM_CREATE: rdi = initial count, rsi = max count.
    // Allocates a per-process semaphore slot and returns
    // kWin32SemaphoreBase + slot (= 0x500..0x507) on success,
    // u64(-1) on slot exhaustion or bad args (initial > max).
    // Backs Win32 CreateSemaphoreW / CreateSemaphoreA.
    SYS_SEM_CREATE = 51,

    // SYS_SEM_RELEASE: rdi = handle, rsi = release count.
    // Bumps count by rsi, wakes up to rsi waiters (one per unit
    // of the bump). Returns the PREVIOUS count on success, or
    // u64(-1) on bad handle or if the bump would exceed
    // max_count. Backs Win32 ReleaseSemaphore.
    SYS_SEM_RELEASE = 52,

    // SYS_SEM_WAIT: rdi = handle, rsi = timeout_ms (INFINITE =
    // 0xFFFFFFFF). If count > 0, decrements and returns 0
    // (WAIT_OBJECT_0). If count == 0, blocks on the semaphore's
    // waitqueue with the given timeout. Returns WAIT_TIMEOUT
    // (0x102) on timeout, u64(-1) on bad handle. Dispatched by
    // the semaphore range in WaitForSingleObject v3.
    SYS_SEM_WAIT = 53,

    // SYS_THREAD_WAIT: rdi = handle (Win32ThreadHandle range,
    // 0x400..0x407), rsi = timeout_ms (0xFFFFFFFF = INFINITE).
    // Poll-and-yield wait for the task behind the handle to
    // reach TaskState::Dead. Returns 0 (WAIT_OBJECT_0) on exit,
    // 0x102 (WAIT_TIMEOUT) on timeout, u64(-1) on bad handle.
    // Dispatched by the thread range in WaitForSingleObject v4.
    // Unprivileged — the caller owns the thread.
    SYS_THREAD_WAIT = 54,

    // SYS_THREAD_EXIT_CODE: rdi = thread handle (0x400..0x407).
    // Returns the recorded exit code (u32) as u64, or 0x103
    // (STILL_ACTIVE) if the thread is still running. Returns
    // u64(-1) on bad handle. The kernel writes this slot from
    // SYS_EXIT when a Win32 thread task dies (batch 59).
    // Backs Win32 GetExitCodeThread.
    SYS_THREAD_EXIT_CODE = 55,
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

void SyscallInit();

/// Called from arch::TrapDispatch when frame->vector == 0x80. Examines
/// the trap frame's rax (syscall number) and dispatches. Returning
/// writes frame->rax with the syscall's return value; SYS_exit never
/// returns.
void SyscallDispatch(arch::TrapFrame* frame);

} // namespace customos::core
