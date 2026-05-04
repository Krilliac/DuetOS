#pragma once

#include "util/types.h"

/*
 * Windows minidump emitter.
 *
 * Produces a self-contained .dmp file (Microsoft minidump
 * format) on the panic path. The file is shipped out of the
 * guest via the debugcon channel (port 0xE9 → host file
 * configured by QEMU's `-debugcon file:...`), so on every
 * panic the host gets a real binary .dmp directly — no
 * decoding, no extraction, no filesystem on the guest needed.
 *
 * What the dump contains (minimum viable for VS / WinDbg /
 * VSCode-cppvsdbg to load and walk):
 *   - SystemInfoStream     (CPU + version)
 *   - ExceptionStream      (RIP + exception code, ties to thread)
 *   - ThreadListStream     (single faulting thread + CONTEXT_X64)
 *   - ModuleListStream     (every loaded user PE / DLL the
 *                          current Process knows about)
 *   - MemoryListStream     (page around RIP + ~16 KiB of stack
 *                          around RSP — enough for VS to do
 *                          disassembly + a stack trace)
 *
 * Floating-point / SSE state is intentionally zero-filled — the
 * kernel runs `-mno-sse` and never touches XMM. Setting the
 * FLOATING_POINT bit in ContextFlags would lie to the debugger.
 *
 * Buffer is statically allocated (kMinidumpBufBytes); only one
 * CPU can panic at a time (peers are NMI-halted before the dump
 * starts) so the single global buffer is safe.
 *
 * Context: kernel. Allocation-free. Safe from panic / IRQ / trap
 * context. Bytes egress one at a time via `outb 0xE9, %al` —
 * slow on real hardware (where the OUTBs go nowhere) but
 * negligible in QEMU.
 */

namespace duetos::diag::minidump
{

inline constexpr u64 kMinidumpBufBytes = 256 * 1024;

/// Build and emit a complete minidump for the current panic.
///   - rip / rsp / rbp: the faulting context's frame.
///   - exception_code: NTSTATUS-shaped reason (e.g. STATUS_ACCESS_VIOLATION
///     0xC0000005 for a #PF, STATUS_ILLEGAL_INSTRUCTION 0xC000001D for
///     a #UD). Pass 0 for non-trap panics — the ExceptionStream
///     still emits, just with a generic STATUS_BREAKPOINT-shaped tag.
///
/// Reads the calling task's process for the module list. Captures
/// the current task's kernel stack page and the page around RIP
/// into MemoryListStream entries.
void EmitMinidump(u64 rip, u64 rsp, u64 rbp, u32 exception_code);

/// Boot-time check: build a minimal-content minidump into the
/// buffer, validate the header signature + stream directory
/// shape, then reset the cursor. Does NOT egress to debugcon.
/// Called from kernel_main alongside the other diag self-tests.
/// Panics on any structural mismatch.
void MinidumpSelfTest();

} // namespace duetos::diag::minidump
