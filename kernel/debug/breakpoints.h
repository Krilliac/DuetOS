#pragma once

#include "../arch/x86_64/traps.h"
#include "../core/types.h"

/*
 * CustomOS — kernel breakpoint subsystem (phase 1).
 *
 * Two flavours of breakpoint live here:
 *
 *   Software: an `int3` (0xCC) byte patched into kernel .text at a
 *             chosen VA. Fires a #BP (vector 3) when the CPU
 *             executes that byte. Uses the single-step-reinsert
 *             dance to resume through the original instruction
 *             and re-patch the byte for subsequent hits. Cost:
 *             one entry in a small table + one 0xCC byte in
 *             .text. Good for arbitrary-granularity code probes
 *             anywhere the linker lays out an instruction.
 *
 *   Hardware: a DR0..DR3 address register + DR7 enable/type/len
 *             bits. Fires a #DB (vector 1) on execute / write /
 *             read-write access at the chosen VA. Four slots
 *             per CPU; no memory patching, so it also works on
 *             .rodata, MMIO, device buffers, and user pages.
 *
 * Phase 1 scope (intentional cuts):
 *   * Single-CPU only. DR writes don't IPI-broadcast; software
 *     BP patching assumes nothing else is fetching the page.
 *     Asserted at install time.
 *   * Kernel .text only for software BPs. Process-image patching
 *     and per-task DR save/restore land in phase 2.
 *   * No ring-3 syscall API yet — install only via kernel code
 *     or the `bp` shell command. Capability gating also phase 2.
 *   * One-shot re-insertion; recursive BP hits during the
 *     single-step window are rejected (log + resume).
 *
 * Context: kernel. All entry points are safe from task context;
 * the trap-handler entry points are safe from IRQ / exception
 * context. All state is serialised by an internal spinlock.
 */

namespace customos::debug
{

// Opaque, stable identifier for an installed breakpoint. `value`
// is 0 for "none / uninstalled"; positive IDs are allocated by
// the manager and stay valid until BpRemove.
struct BreakpointId
{
    u32 value;
};

inline constexpr BreakpointId kBpIdNone = {0};

// What a hardware breakpoint fires on. Software BPs are always
// execute-only (int3 is an instruction byte).
enum class BpKind : u8
{
    Software,    // 0xCC patched into .text
    HwExecute,   // DR slot, R/W=00, LEN must be 1
    HwWrite,     // DR slot, R/W=01
    HwReadWrite, // DR slot, R/W=11 (never fetch)
};

// Data-breakpoint length. Must be 1, 2, 4, or 8 bytes on x86_64;
// `Eight` is valid only because we're in long mode. Ignored for
// Software / HwExecute (always 1).
enum class BpLen : u8
{
    One = 1,
    Two = 2,
    Four = 4,
    Eight = 8,
};

enum class BpError : u8
{
    None = 0,
    InvalidAddress, // not canonical / not aligned / outside .text
    TableFull,      // no free SW slot
    NoHwSlot,       // all 4 DR slots in use
    BadKind,        // HwExecute with len != 1, HwWrite with len 0, etc.
    NotInstalled,   // BpRemove(bogus id)
    SmpUnsupported, // phase 1 refuses multi-CPU installs
};

// Snapshot of one installed breakpoint, returned by BpList.
struct BpInfo
{
    BreakpointId id;
    BpKind kind;
    BpLen len;
    u64 address; // kernel VA
    u64 hit_count;
    u64 owner_pid; // 0 = kernel-owned (shell / self-test)
    u8 hw_slot;    // 0..3 for Hw*; 0xFF for Software
    u8 _pad[7];
};

/// One-time init. Zeroes all DR registers, writes the DR6 reset
/// value, and takes a snapshot of the .text range for the SW-BP
/// bounds check. Safe to call multiple times (subsequent calls
/// are no-ops).
void BpInit();

/// Install a software (int3) breakpoint at `kernel_va`. `kernel_va`
/// must lie inside the kernel .text range; the byte there is
/// saved and overwritten with 0xCC. Returns a stable ID on
/// success, or kBpIdNone + sets `*err` on failure.
BreakpointId BpInstallSoftware(u64 kernel_va, BpError* err);

/// Install a hardware breakpoint via the next free DR slot.
/// `va` may be any canonical VA — data breakpoints work on any
/// mapped page, execute breakpoints on any instruction address.
/// `owner_pid` stamps the BP with the installing process's pid
/// so BpRemove can reject cross-process removal; pass 0 for
/// kernel-owned BPs (shell, self-test).
BreakpointId BpInstallHardware(u64 va, BpKind kind, BpLen len, u64 owner_pid, BpError* err);

/// Remove a previously-installed breakpoint. `requester_pid` must
/// match the BP's owner_pid (or be 0 for kernel-privileged
/// removal — shell / panic paths). Cross-owner removals return
/// BpError::NotInstalled so a ring-3 debugger can't stomp on
/// another process's BPs.
BpError BpRemove(BreakpointId id, u64 requester_pid);

/// Snapshot up to `cap` entries into `out`. Returns the count
/// actually written. No allocation — caller supplies the buffer.
usize BpList(BpInfo* out, usize cap);

/// Called from the CPU trap dispatcher for vectors 1 (#DB) and
/// 3 (#BP). Returns true iff this subsystem claimed the trap
/// (matched a registered breakpoint); when true, the trap was
/// handled and the generic LogAndContinue path should NOT run.
/// Returns false for spurious hits (bare `int3` not in our table,
/// #DB with no matching DR bit) — caller falls through to the
/// default LogAndContinue log line.
bool BpHandleBreakpoint(arch::TrapFrame* frame); // #BP, vector 3
bool BpHandleDebug(arch::TrapFrame* frame);      // #DB, vector 1

/// Diagnostic: used by the `bp test` shell command. Installs a
/// software BP at an internal sentinel, invokes it, checks the
/// hit counter, removes the BP, then does the same dance with a
/// hardware execute BP. Returns true on success.
bool BpSelfTest();

} // namespace customos::debug
