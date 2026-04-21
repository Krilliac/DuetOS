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
