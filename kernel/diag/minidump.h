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

namespace duetos::arch
{
struct TrapFrame;
}

namespace duetos::diag::minidump
{

inline constexpr u64 kMinidumpBufBytes = 256 * 1024;

/// Build and emit a complete minidump for a *soft* panic — i.e.
/// `core::Panic` / `core::PanicWithValue` where there is no
/// TrapFrame and only the call-site RIP / RSP / RBP are known.
/// All other GPRs are written as zero in the resulting CONTEXT
/// block. For trap-fired dumps prefer EmitMinidumpFromTrapFrame
/// below — it preserves rax..r15 + segment regs + rflags.
///
///   - exception_code: NTSTATUS-shaped reason (e.g. STATUS_ACCESS_VIOLATION
///     0xC0000005 for a #PF, STATUS_ILLEGAL_INSTRUCTION 0xC000001D for
///     a #UD). Pass 0 for non-trap panics — the ExceptionStream
///     still emits, just with a generic STATUS_BREAKPOINT-shaped tag.
///
/// Reads the calling task's process for the module list. Captures
/// the current task's kernel stack page and the page around RIP
/// into MemoryListStream entries.
void EmitMinidump(u64 rip, u64 rsp, u64 rbp, u32 exception_code);

/// TrapFrame-aware minidump emit. Used by the CPU-exception
/// dispatcher path so the resulting CONTEXT_X64 carries the full
/// 16-GPR register file + cs / ss segment selectors + rflags
/// the hardware pushed on entry — not just rip/rsp/rbp. With
/// this in place a `.dmp` from a trap shows real register
/// values to a debugger and the stackwalker can correlate
/// register-dependent faults (bad cr2 vs garbage rdi vs stale
/// vtable in r10, etc.) instead of seeing every non-control
/// register as zero.
void EmitMinidumpFromTrapFrame(const arch::TrapFrame* frame, u32 exception_code);

/// Boot-time check: build a minimal-content minidump into the
/// buffer, validate the header signature + stream directory
/// shape, then reset the cursor. Does NOT egress to debugcon.
/// Called from kernel_main alongside the other diag self-tests.
/// Panics on any structural mismatch.
void MinidumpSelfTest();

/// Disk-persist exercise — writes a synthetic dump through the
/// real NVMe panic path so a regression in
/// `NvmePanicWriteDump` surfaces in the boot log instead of
/// only at real-panic time. Idempotent; clears the
/// `g_last_dump_bytes` accessor so `lastdump` from the shell
/// still reports "no minidump emitted this boot" on a clean
/// run. Called AFTER NvmeInit. Skips silently if no NVMe
/// namespace is online.
void DiskPersistSelfTest();

/// Read-back accessor for the last successfully-built minidump's
/// byte range inside the static buffer. Used by future panic-time
/// persistence consumers (a reserved-LBA disk writer, a
/// network-pushed crash report, etc.) so the same bytes the
/// debugcon path emitted can be re-shipped without re-walking
/// the trap state.
///
/// Returns false (and clears `*out_*`) if no minidump has been
/// built yet this boot. The pointer is stable until the next
/// `EmitMinidump` / `EmitMinidumpFromTrapFrame` call — typical
/// callers run on the panic path between the emit and the next
/// reboot, so the lifetime is "uptime".
bool AccessLastMinidump(const u8** out_bytes, u64* out_len);

} // namespace duetos::diag::minidump
