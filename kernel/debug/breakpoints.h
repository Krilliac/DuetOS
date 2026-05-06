#pragma once

#include "arch/x86_64/traps.h"
#include "util/types.h"

/*
 * DuetOS — kernel breakpoint subsystem (phase 1).
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

namespace duetos::debug
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
    UnsafeZone,     // target lies inside the trap dispatcher / klog / heap /
                    // scheduler / panic / spinlock primitives — refused
                    // unless the operator passed BpInstallFlags::AllowUnsafe.
                    // See BpInit for the full unsafe-symbol list.
};

/// Operator-side install policy. Most callers pass `None`. The
/// `AllowUnsafe` bit overrides the safety blocklist that would
/// otherwise reject a BP whose target lies inside a kernel path
/// that the BP handler itself reaches (logging, scheduler,
/// allocator, trap dispatcher). Setting a BP in those zones
/// risks infinite recursion / SMP-wide hang / triple-fault — only
/// pass this when you know exactly what you're doing.
enum class BpInstallFlags : u8
{
    None = 0,
    AllowUnsafe = 1,
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
    u64 stopped_task_id;
    u8 hw_slot; // 0..3 for Hw*; 0xFF for Software
    bool suspend_on_hit;
    bool is_stopped; // a task is currently blocked on this BP's wait-queue
};

/// One-time init. Zeroes all DR registers, writes the DR6 reset
/// value, and takes a snapshot of the .text range for the SW-BP
/// bounds check. Safe to call multiple times (subsequent calls
/// are no-ops).
void BpInit();

/// Drive the subsystem to a clean, freshly-bootable state — disarms
/// every DR slot, drops every software / hardware breakpoint table
/// row, and resets the inited flag so the next `BpInit` runs the
/// table-init path. Idempotent. Used by the driver fault-domain
/// registry to restart the breakpoint subsystem without a reboot
/// (e.g. after a flaky GDB session left orphaned int3 traps).
void BpTeardown();

/// Trap-context callback fired AFTER the reinsert dance (for SW
/// BPs: original byte restored, RIP rolled back, RFLAGS.TF set;
/// for HW BPs: just the hit accounting). Runs on the CPU that
/// took the trap, with interrupts still disabled, before any
/// `suspend_on_hit` parking. Used by the GDB stub to enter its
/// stop loop in trap context — kernel-mode hits work this way
/// without needing the wait-queue suspend (which today rejects
/// ring-0 hits).
///
/// The callback may freely mutate `*frame` (RIP / RFLAGS / GPRs)
/// — those edits ride out via the iretq stack image when the
/// trap returns. Returning from the callback continues the
/// existing reinsert flow normally.
using BpHitCallback = void (*)(BreakpointId id, arch::TrapFrame* frame);

/// Install a software (int3) breakpoint at `kernel_va`. `kernel_va`
/// must lie inside the kernel .text range; the byte there is
/// saved and overwritten with 0xCC. Returns a stable ID on
/// success, or kBpIdNone + sets `*err` on failure.
///
/// `suspend_on_hit` — when true, the task that hits this BP is
/// parked on the BP's wait-queue and the scheduler picks another
/// ready task. Use `BpResume` / `BpStep` to unblock. Only applies
/// to user-mode hits today (kernel-mode hits are hard to suspend
/// safely without an IRQ-depth accessor, which is still stubbed);
/// a kernel hit with suspend_on_hit set logs + resumes with a
/// "suspend rejected" warning.
///
/// `on_hit` — optional trap-context callback (see BpHitCallback
/// above). nullptr = no callback (default behaviour).
BreakpointId BpInstallSoftware(u64 kernel_va, bool suspend_on_hit, BpError* err, BpHitCallback on_hit = nullptr,
                               BpInstallFlags flags = BpInstallFlags::None);

/// Install a hardware breakpoint via the next free DR slot.
/// `va` may be any canonical VA — data breakpoints work on any
/// mapped page, execute breakpoints on any instruction address.
/// `owner_pid` stamps the BP with the installing process's pid
/// so BpRemove can reject cross-process removal; pass 0 for
/// kernel-owned BPs (shell, self-test).
///
/// `suspend_on_hit` — see BpInstallSoftware; same semantics,
/// same kernel-safety fallback.
///
/// `on_hit` — optional trap-context callback (see BpHitCallback
/// above). nullptr = no callback (default behaviour).
BreakpointId BpInstallHardware(u64 va, BpKind kind, BpLen len, u64 owner_pid, bool suspend_on_hit, BpError* err,
                               BpHitCallback on_hit = nullptr, BpInstallFlags flags = BpInstallFlags::None);

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

/// True iff `va` lies inside one of the unsafe ranges populated
/// by BpInit. Exposed so a shell-side diagnostic can explain
/// WHY an install was rejected, and so an operator GUI can grey
/// out the "Add" button when the cursor is on a hot path.
bool BpAddressInUnsafeZone(u64 va);

/// Snapshot of one unsafe range (for `dbg bp unsafe-zones` and
/// equivalent diagnostics). `name` is borrowed from the embedded
/// `.symtab` and is stable for the kernel's lifetime.
struct BpUnsafeRange
{
    u64 lo;
    u64 hi;
    const char* name;
};

/// Snapshot up to `cap` unsafe-range entries into `out`. Returns
/// the count actually written. No allocation.
usize BpUnsafeRangesList(BpUnsafeRange* out, usize cap);

/// Diagnostic: used by the `bp test` shell command. Installs a
/// software BP at an internal sentinel, invokes it, checks the
/// hit counter, removes the BP, then does the same dance with a
/// hardware execute BP. Returns true on success.
bool BpSelfTest();

// ------------------ Phase 3: suspend + inspect + resume ------

/// Snapshot the saved trap frame of the task currently stopped on
/// `id`. Returns true + fills `*out` if a task is suspended there,
/// false otherwise. `out` must be non-null. The frame is a COPY —
/// mutating it has no effect; use BpStep to change control flow.
bool BpReadRegs(BreakpointId id, arch::TrapFrame* out);

/// Mutate the saved trap frame of the task currently stopped on
/// `id`. The kernel sanitises CS/SS/RFLAGS the same way
/// SYS_THREAD_SET_CONTEXT does — caller cannot promote the target
/// to ring 0, force IOPL > 0, suppress IF, or set the trap flag.
/// All GPRs (rax..r15), RIP, RSP, and the operator-safe RFLAGS
/// bits transfer verbatim. Returns BpError::None on success,
/// BpError::NotInstalled if no task is parked on this BP. The
/// edits land on the iretq stack image, taking effect when the
/// task is resumed via BpResume / BpStep.
BpError BpWriteRegs(BreakpointId id, const arch::TrapFrame* in);

/// Read `len` bytes of the stopped task's user memory starting at
/// `user_va` into `out`. Walks the target task's AddressSpace to
/// find the backing frame(s); returns the number of bytes
/// successfully copied (may be less than `len` if the page is
/// unmapped). Safe to call from any non-trap context.
u64 BpReadMem(BreakpointId id, u64 user_va, u8* out, u64 len);

/// Resume the task stopped on `id`. The task's saved rflags keep
/// their current TF bit — unchanged from whatever BpStep or the
/// trap handler last set. Returns BpError::None on success,
/// BpError::NotInstalled if no task is stopped on this BP.
BpError BpResume(BreakpointId id);

/// Resume the task with RFLAGS.TF = 1 so the CPU takes a
/// single-step #DB after the next instruction. That #DB re-enters
/// the BP subsystem and (if the BP was a SW BP with reinsert
/// pending) re-patches 0xCC automatically, then — because the
/// hit context is the same BP with suspend_on_hit set — parks
/// the task again. Net effect: "step one instruction forward
/// and stop."
BpError BpStep(BreakpointId id);

} // namespace duetos::debug
