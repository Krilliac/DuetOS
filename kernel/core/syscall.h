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
};

/// Install the DPL=3 IDT gate for vector 0x80. Must run after IdtInit
/// (the IDT must already be loaded) and before any ring-3 entry.
void SyscallInit();

/// Called from arch::TrapDispatch when frame->vector == 0x80. Examines
/// the trap frame's rax (syscall number) and dispatches. Returning
/// writes frame->rax with the syscall's return value; SYS_exit never
/// returns.
void SyscallDispatch(arch::TrapFrame* frame);

} // namespace customos::core
