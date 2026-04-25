#pragma once

#include "types.h"

/*
 * DuetOS — kernel-side hex / memory / instruction dump helpers.
 *
 * A small, self-contained toolkit for getting bytes out on the serial
 * line. Three use cases:
 *
 *   1. Trap dispatcher (crash time). Dump instruction bytes at the
 *      faulting RIP so the operator sees the literal opcode that
 *      #UD'd / #PF'd / #GP'd without asking objdump. Dump memory
 *      around CR2 on #PF to show the context the fault was reading
 *      / writing. Dump the TOS quads to show the live call frame.
 *
 *   2. Runtime invariant checker. Byte-level diff dumps on IDT / GDT
 *      / MSR drift already exist in runtime_checker.cpp; these
 *      helpers generalise the pattern so any subsystem can emit a
 *      labelled region dump on a found corruption.
 *
 *   3. Ad-hoc shell inspection during normal running. The `memdump`
 *      command hands (addr, len) to DumpHexRegionSafe so a
 *      developer at the shell can inspect arbitrary bytes without
 *      risking a #PF on an unmapped address.
 *
 * All output goes to COM1 via arch::SerialWrite. No allocation, no
 * lock. Safe from IRQ / trap / panic context.
 */

namespace duetos::core
{

/// Upper bound for a single-line instruction dump. x86_64 instructions
/// are at most 15 bytes; 32 covers two worst-case instructions on a
/// single line, which is what you want when a #UD lands between two
/// malformed opcodes. Requests for more are silently clamped.
inline constexpr u32 kMaxInstructionDumpBytes = 32;

/// Upper bound for a multi-line region dump. Protects the serial line
/// from a stuck / wild `len` (operator typo, corrupted argument). 4 KiB
/// = 256 lines; scrolling past that in a crash dump is useless. Larger
/// requests are clamped.
inline constexpr u32 kMaxRegionDumpBytes = 4096;

/// Cheap range check: is `va` in a region the kernel can safely read
/// right now? Returns true ONLY for the higher-half direct map + MMIO
/// arena. The low 1 GiB identity map is excluded — under SMAP, kernel
/// reads of pages mapped into the current ring-3 process trip a #PF,
/// so a user-mode RIP in the low half is NOT a safe address to deref
/// from the trap dispatcher. Used by the safe-dump variants to skip
/// known-bad addresses instead of risking a nested fault.
///
/// NOT a full page-walk — a VA that passes this check can still be
/// unmapped (the direct map covers only the first 1 GiB of RAM; a
/// plausible-looking VA past that is unmapped). The safe-dump variants
/// additionally skip any requested page when it equals `skip_page_va`
/// at the call site, so #PF consumers can dump around CR2 without
/// touching the page CR2 itself named.
bool PlausibleKernelAddress(u64 va);

/// Single-line instruction-byte dump. Emits:
///
///     [tag] instr@<addr> : XX XX XX XX XX XX XX XX XX XX XX XX XX XX XX XX
///
/// Up to `kMaxInstructionDumpBytes`. If `addr` is not a plausible
/// kernel address, emits a "<skipped>" line and returns. Use at crash
/// time with `frame->rip` to see the literal opcode.
void DumpInstructionBytes(const char* tag, u64 addr, u32 len);

/// Multi-line hex + ASCII dump, 16 bytes per line:
///
///     [tag] 0xFFFFFFFF80010000  8B 05 00 00 00 00 ...  |................|
///
/// `len` is clamped to `kMaxRegionDumpBytes`. Does NOT perform a page
/// walk — caller is responsible for confirming the range is mapped.
/// Use in code that already knows the VA is live (e.g. a struct
/// pointer it just dereferenced successfully).
void DumpHexRegion(const char* tag, u64 addr, u32 len);

/// Safe variant of DumpHexRegion. For each 16-byte line:
///   - If the line's address isn't plausible, emits "<unreadable>".
///   - If the line falls inside the 4 KiB page starting at
///     `skip_page_va` (pass 0 to disable), emits "<skipped: faulting page>".
///   - Otherwise dereferences and emits the line.
///
/// Intended for the trap dispatcher's CR2-window dump: the faulting
/// page is unmapped BY DEFINITION on #PF, so we want to show the
/// flanking pages without touching the one that would re-#PF.
void DumpHexRegionSafe(const char* tag, u64 addr, u32 len, u64 skip_page_va);

/// One-shot "stack window" dump. Emits up to `quad_count` 8-byte quads
/// starting at `rsp`, with a symbol-annotated value on each line so
/// saved return addresses auto-label. Guards each read against the
/// plausibility check so a crashed task with a wild RSP doesn't take
/// the kernel down while we're trying to diagnose it.
///
/// Complements `panic.cpp::DumpStack`, which uses the same
/// PlausibleStackPointer + symbol lookup. This variant is exposed for
/// trap / shell callers that don't want to drag the whole panic
/// diagnostics block.
void DumpStackWindow(const char* tag, u64 rsp, u32 quad_count);

/// Self-test for `PlausibleKernelAddress`. Pins the higher-half
/// boundary, the MMIO arena cap, the sentinel NULL rejection, and a
/// sweep of low-half addresses (which must always reject regardless
/// of how the userland map ends up wired). Plus a short call into
/// `DumpInstructionBytes` / `DumpHexRegion` against a known-mapped
/// region (a kernel symbol) so the formatter path runs.
///
/// Panics on any failure. Boot-time only.
void HexdumpSelfTest();

} // namespace duetos::core
