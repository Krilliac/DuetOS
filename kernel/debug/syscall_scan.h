#pragma once

#include "../core/types.h"

/*
 * DuetOS — operator-driven syscall scanner.
 *
 * Walks a byte range looking for x86_64 syscall idioms
 * (`syscall`, `int 0x80`, `int 0x2E`, `sysenter`), decodes the
 * immediately-preceding `mov eax, imm32` when present to
 * recover the syscall number, and cross-references the number
 * against the NT / Linux / native DuetOS syscall tables for
 * naming + coverage status.
 *
 * This is NOT a full disassembler. It is a focused pattern
 * matcher sized for ~200 lines of decoder; the goal is
 * "tell me which syscalls this binary might issue and whether
 * we'd handle them" at triage time, not byte-perfect semantic
 * analysis.
 *
 * Trigger: operator types `inspect syscalls ...` at the shell
 * (see `kernel/debug/inspect.h` for the umbrella). Nothing runs
 * automatically unless the `inspect arm` latch is set, which
 * targets the opcodes scanner rather than this one.
 */

namespace duetos::debug
{

/// The kind of syscall-issuing instruction that was found.
enum class SyscallSiteKind : u8
{
    Unknown = 0,
    Syscall,  // `syscall`  (0F 05) — Linux / NT x86_64 ABI
    Int80,    // `int 0x80` (CD 80) — native DuetOS ABI
    Int2E,    // `int 0x2E` (CD 2E) — legacy NT ABI
    Sysenter, // `sysenter` (0F 34) — 32-bit fast path (rare)
};

/// Coverage flag set on a recovered syscall number.
struct SiteCoverage
{
    bool known_linux = false;  // Linux table has a name for this number
    bool known_nt = false;     // NT table has a name for this number
    bool known_native = false; // DuetOS native SYS_* has this number
    bool impl_linux = false;   // Linux primary dispatcher has a Do* handler
    bool impl_native = false;  // Matched a known native SYS_*
    const char* linux_name = nullptr;
    const char* nt_name = nullptr;
    const char* native_name = nullptr;
};

/// One located syscall site.
struct SyscallSite
{
    u64 va; // virtual address of the instruction byte
    SyscallSiteKind kind;
    bool nr_recovered; // true if a preceding `mov eax, imm32` was found
    u32 nr;            // recovered syscall number (valid iff nr_recovered)
    SiteCoverage coverage;
};

/// Aggregate report emitted at the end of a scan.
struct SyscallScanReport
{
    u64 region_base_va;
    u64 region_size;
    u32 total_sites;
    u32 recovered;   // sites with a recovered syscall number
    u32 known_linux; // recovered numbers that resolve in the Linux table
    u32 known_nt;
    u32 known_native;
    u32 impl_linux; // resolved and have a live handler
    u32 impl_native;
    u32 unknown; // recovered numbers that resolve in NOTHING
    u32 kind_syscall;
    u32 kind_int80;
    u32 kind_int2e;
    u32 kind_sysenter;
    u32 sites_dropped; // emitted-to-log cap exhausted (kMaxSitesLogged)
};

/// Maximum sites emitted as individual log lines per scan. Prevents
/// a pathological PE with thousands of syscall idioms from flooding
/// the serial log. The summary line still reports the true totals.
inline constexpr u32 kMaxSitesLogged = 64;

/// Scan a raw byte region. `base_va` is the virtual address the
/// first byte corresponds to (used for the VA column in the log).
/// Returns the aggregated report.
///
/// Safe to call from kernel context; reads the region sequentially,
/// so the caller must have already validated the memory is mapped.
SyscallScanReport SyscallScanRegion(const u8* bytes, u64 size, u64 base_va);

/// Scan the kernel's own .text section. Useful for "what syscall
/// sites does the kernel call through internally" — today that's
/// zero (the kernel doesn't issue syscalls), which is the right
/// baseline to confirm.
SyscallScanReport SyscallScanKernelText();

/// Read a file from FAT32 volume 0, auto-detect PE vs ELF vs raw,
/// locate the code section, and scan. Logs an error and returns
/// a zeroed report on any parse / read failure.
SyscallScanReport SyscallScanFile(const char* path);

} // namespace duetos::debug
