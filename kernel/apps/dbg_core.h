#pragma once

#include "util/types.h"
#include "debug/breakpoints.h"
#include "debug/disasm.h"

namespace duetos::arch
{
struct TrapFrame;
}

/*
 * DuetOS — debugger logic helpers, shared by the GUI app
 * (kernel/apps/dbg.*) and the kernel-shell `dbg` command
 * (kernel/shell/shell_dbg.cpp).
 *
 * Everything here is allocation-free, takes caller-supplied
 * buffers, and never holds any state of its own beyond the
 * watchlist (which is per-process bookkeeping the operator owns).
 *
 * Cap policy:
 *   - DbgEnumerateProcesses, DbgReadMem, DbgScanBytes,
 *     DbgScanNext, DbgDisasmRows, DbgRegsRead — read-only;
 *     callable without kCapDebug.
 *   - DbgWriteMem, DbgInstallBp, DbgRemoveBp, DbgResumeBp,
 *     DbgStepBp, DbgRegsWrite — mutating; the kernel-shell
 *     subcommand invoking them gates on `kCapDebug` (the GUI app
 *     itself runs in kernel and is implicitly trusted, but the
 *     gate stays here for the eventual ring-3 wrapper).
 */

namespace duetos::apps::dbg::core
{

/// Snapshot row produced by DbgEnumerateProcesses. Sized so a
/// 700-pixel window can render the full table without wrapping.
struct ProcInfo
{
    u64 pid;
    char name[32];
    u8 state;         // 0 = running, 1 = ready, 2 = blocked, 3 = zombie, 4 = unknown
    u64 ticks_used;   // total scheduler ticks consumed
    u16 region_count; // user VM regions installed
};

/// Watchlist row: one observed memory location + its rendered
/// value. The value field is refilled on every `DbgWatchRefresh`.
enum class WatchType : u8
{
    Bytes = 0, // raw hex of `len` bytes
    U8,
    U16,
    U32,
    U64,
    I32,
    I64,
};

inline constexpr u32 kWatchMax = 32;
inline constexpr u32 kWatchNameMax = 24;
inline constexpr u32 kWatchValueMax = 32;

struct WatchEntry
{
    bool used;
    u64 pid;
    u64 va;
    u8 len; // 1..16 for Bytes; ignored for typed entries
    WatchType type;
    char name[kWatchNameMax];
    char value[kWatchValueMax]; // last refreshed value, "n/a" if read failed
};

/// First-byte cap on a single scan. Bigger scans are partial — we
/// abort + report the count we got. Bounded so a runaway scanner
/// can't park the compositor for >50 ms.
inline constexpr u64 kScanResultCap = 256;

// ---- Process / memory ---------------------------------------

usize EnumerateProcesses(ProcInfo* out, usize cap);
bool LookupProcess(u64 pid, ProcInfo* out);

/// Read up to `len` bytes from `pid`'s user memory at `va`. If
/// the target task is currently parked on a breakpoint, this
/// delegates to BpReadMem (which uses the captured AS); for any
/// other live process, it walks the AS regions table directly.
/// Returns the number of bytes successfully copied (may be less
/// than `len` if the page is unmapped).
u64 ReadMem(u64 pid, u64 va, u8* out, u64 len);

/// Symmetric to ReadMem. Returns the number of bytes written.
/// Cross-AS write is via the kernel direct-map alias of the
/// target's backing frame; the target page must already be
/// present in the AS regions table. Cap-gated by the caller.
u64 WriteMem(u64 pid, u64 va, const u8* in, u64 len);

// ---- Scan ---------------------------------------------------

/// First-pass byte-pattern scan. Walks every region in the
/// target's AddressSpace that has a backing frame, matches
/// `needle` byte-by-byte. Hits are written to `hits` (capped at
/// kScanResultCap). Returns the count.
usize ScanBytes(u64 pid, const u8* needle, usize nlen, u64* hits, usize cap);

/// Filter pass: re-check every survivor in `prev_hits` and keep
/// only those that still match `needle`. Useful for Cheat-
/// Engine-style "value didn't change" iterative narrowing.
usize ScanNext(u64 pid, const u8* needle, usize nlen, const u64* prev_hits, usize prev_count, u64* out_hits, usize cap);

// ---- Disasm -------------------------------------------------

/// Read up to `byte_cap` bytes from `pid`@`va` and decode them
/// into `out` rows (max `row_cap`). Returns the number of rows
/// produced. Wraps ReadMem + disasm::DecodeStream so the caller
/// gets a single one-liner.
u64 DisasmRows(u64 pid, u64 va, debug::disasm::DecodedInsn* out, u64 row_cap);

// ---- Breakpoints --------------------------------------------

debug::BreakpointId InstallBp(u64 va, debug::BpKind kind, debug::BpLen len, u64 owner_pid, bool suspend,
                              debug::BpError* err);
debug::BpError RemoveBp(debug::BreakpointId id, u64 requester_pid);
debug::BpError ResumeBp(debug::BreakpointId id);
debug::BpError StepBp(debug::BreakpointId id);
usize ListBp(debug::BpInfo* out, usize cap);

// ---- Regs ---------------------------------------------------

bool RegsRead(debug::BreakpointId id, arch::TrapFrame* out);
debug::BpError RegsWrite(debug::BreakpointId id, const arch::TrapFrame* in);

// ---- Watch --------------------------------------------------

/// Append a watch entry. Returns the slot index on success or
/// 0xFFFFFFFFu when the table is full or `name` is empty.
u32 WatchAdd(u64 pid, u64 va, u8 len, WatchType type, const char* name);
bool WatchRemove(u32 slot);
void WatchRefresh();
const WatchEntry* WatchSlot(u32 slot);
usize WatchCount();

} // namespace duetos::apps::dbg::core
