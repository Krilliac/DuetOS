#pragma once

#include "../core/types.h"
#include "syscall_scan.h"

/*
 * CustomOS — `inspect` umbrella: reverse-engineering + triage
 * tooling that the operator drives from the shell.
 *
 * Subcommands (see `kernel/core/shell.cpp` for dispatch):
 *
 *   inspect syscalls kernel | <path>
 *       Locate syscall-issuing idioms (syscall / int 0x80 /
 *       int 0x2E / sysenter), recover the `mov eax, imm32`
 *       preceding each site, cross-reference the recovered
 *       number against the NT / Linux / native tables.
 *       Backed by `kernel/debug/syscall_scan.*`.
 *
 *   inspect opcodes <path>
 *       Walk the executable section of a FAT32 file (PE / ELF /
 *       raw) and emit a first-byte opcode histogram plus
 *       instruction-class counters (jumps, calls, rets, ints,
 *       nops, rex / lock / rep prefixes, 0F-escape secondary
 *       table). Useful to answer "what's this blob made of"
 *       without pulling in a full disassembler.
 *
 *   inspect arm on | off | status
 *       One-shot "scan the next spawned executable" latch. When
 *       armed, the PE/ELF spawn paths call
 *       `InspectOnSpawn(name, bytes, len)` before creating the
 *       ring-3 process, which runs the opcodes scan on the
 *       in-memory image and then auto-disarms. Designed for
 *       "I'm about to run /bin/foo.exe — tell me everything
 *       before it goes live".
 *
 * All reports go to COM1. The shell only prints "see COM1"-
 * shaped acknowledgements because the report lines would
 * otherwise flood the 80x25 console.
 *
 * Intentional non-goals (bloat guard):
 *   - Not a full x86_64 disassembler. No REX / ModRM / SIB
 *     tracking, no instruction-boundary recovery. Scope is
 *     "pattern-match the bytes that matter for triage".
 *   - Not vendored. Zero third-party deps.
 *   - No live-process scanning. Today's scope is kernel text +
 *     on-disk files + in-memory spawn images.
 *
 * Operator-triggered only — nothing here runs unless the
 * operator typed a command (or armed the latch).
 */

namespace customos::debug
{

// ---------- Opcodes scanner ----------

/// Number of first-byte opcode slots reported by the histogram
/// "top N" line. The full 256-entry histogram is scanned but
/// printing all 256 rows drowns the log; the top N frequent
/// slots tell the triage story on their own.
inline constexpr u32 kOpcodeHistogramTopN = 16;

struct OpcodeScanReport
{
    u64 region_base_va;
    u64 region_size;

    // Per-class counters. Each site is counted in at most one
    // class — the decoder picks the most specific match and
    // skips ahead, so the classes sum to the count of
    // "interesting" opcode starts, not the raw byte count.
    u32 jump_near;     // E8 / E9 / EB / 0F 80..8F
    u32 call_near;     // E8, FF /2, FF /3 (approximate — no ModRM parse)
    u32 ret_near;      // C2 / C3 / CA / CB
    u32 int_imm;       // CD xx (excluding syscall-idiom 0x80 / 0x2E already counted)
    u32 nop;           // 0x90 and 0F 1F multi-byte NOPs
    u32 syscall_idiom; // aggregate: 0F 05 + CD 80 + CD 2E + 0F 34
    u32 rex_prefix;    // 0x40..0x4F (lone prefix byte)
    u32 lock_prefix;   // 0xF0
    u32 rep_prefix;    // 0xF2 / 0xF3
    u32 seg_prefix;    // 0x26 / 0x2E / 0x36 / 0x3E / 0x64 / 0x65
    u32 osz_prefix;    // 0x66 / 0x67

    // Histogram of first bytes. One counter per possible byte
    // value; `top_n_byte[i]` / `top_n_count[i]` are the top-N
    // ranking after the walk, most-frequent first.
    u32 first_byte[256];
    u8 top_n_byte[kOpcodeHistogramTopN];
    u32 top_n_count[kOpcodeHistogramTopN];
    u32 top_n_valid; // how many of the top-N slots have real data

    // Secondary histogram for 0F-escape opcodes. Indexed by the
    // byte that follows 0F. Useful to see "this PE is heavy on
    // 0F 1F (multi-byte NOP) and 0F 84 (JE rel32)".
    u32 esc_0f[256];
};

/// Scan a raw byte region as an opcode histogram + class
/// tally. `base_va` is the VA the first byte corresponds to
/// (used only for the log header). The report itself lives in
/// a file-scope buffer inside `inspect.cpp` and is written to
/// COM1 — no return value, because every observed caller just
/// discarded it and returning a 2 KiB struct forced a memcpy
/// against a freestanding kernel with no libc.
void OpcodeScanRegion(const u8* bytes, u64 size, u64 base_va);

/// Read a FAT32 file, auto-detect PE / ELF / raw, locate the
/// executable section, scan it. Logs an error and returns on
/// any parse / read failure.
void OpcodeScanFile(const char* path);

// ---------- Arm latch (one-shot spawn hook) ----------

/// True iff `inspect arm on` is currently pending.
bool InspectArmActive();

/// Set the arm latch. `inspect arm on` flips this true;
/// `inspect arm off` flips it false; `InspectOnSpawn` flips
/// it false after firing (one-shot semantics).
void InspectArmSet(bool on);

/// Called by the PE/ELF spawn paths before entering ring 3.
/// If `InspectArmActive()`, runs `OpcodeScanRegion` against
/// the in-memory image and disarms. No-op otherwise. The
/// `name` argument is only used for the log header.
void InspectOnSpawn(const char* name, const u8* bytes, u64 size);

// ---------- Shared loader helpers ----------
//
// Exposed here so `syscall_scan.cpp` and any future inspect
// subcommand can share one FAT32 reader + one PE/ELF header
// parser instead of each module copy-pasting its own.

/// {file_off, size, base_va} triple describing an executable
/// section located inside a file buffer.
struct InspectSection
{
    u64 file_off;
    u64 size;
    u64 base_va;
};

/// Scratch-buffer capacity used by file-reading inspect
/// subcommands. Anything larger is truncated with a log note.
inline constexpr u64 kInspectFileScratchCap = 128 * 1024;

/// Read `path` from FAT32 volume 0 into the shared scratch
/// buffer. On success writes `*out_bytes` (into the scratch)
/// and `*out_len`; returns false with a log line on any
/// failure. Path may start with a leading `/` or `/fat/` —
/// both are stripped.
bool InspectReadFatFile(const char* path, const u8** out_bytes, u64* out_len);

/// Locate the first executable section of a PE image. Returns
/// false if `file` is not a PE or no executable section is
/// found.
bool InspectFindPeText(const u8* file, u64 len, InspectSection* out);

/// Locate the first executable PT_LOAD of a 64-bit ELF. Returns
/// false if `file` is not an ELF64 or has no PT_LOAD with PF_X.
bool InspectFindElfText(const u8* file, u64 len, InspectSection* out);

} // namespace customos::debug
