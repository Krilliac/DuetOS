#pragma once

#include "util/types.h"

/*
 * DuetOS Win32 — custom diagnostics + safety extensions.
 *
 * The Win32 reimplementation lets us layer features over the
 * Microsoft ABI that real Windows can't add without breaking
 * compatibility. Features split into two tiers:
 *
 *   - **Auto-on** for every Win32 PE: pure-observability features
 *     that don't change anything an app can see. Apps with no
 *     diagnostics intent of their own still get them — no code
 *     change required. (FlightRecorder, HandleProvenance,
 *     ErrorProvenance, ContentionProfile, DeadlockDetect,
 *     InputReplay.)
 *
 *   - **Opt-in** by SYS_WIN32_CUSTOM op=SetPolicy: features whose
 *     presence is observable to apps that probe Windows-buggy
 *     behaviour. Quarantine-free, strict RWX, strict handle
 *     inheritance, async paint, pixel isolation.
 *
 * Operators flip the kernel-wide auto-on default at runtime via
 * op=SetSystemDefault — useful for promoting QuarantineFree to
 * default-on for a debug build of the OS without touching any
 * app's source. Already-running processes keep whatever default
 * they got at spawn; the change only affects newly-spawned PEs.
 *
 * Features (all gated by per-process policy bits):
 *
 *   - **Flight recorder**: ring buffer of the last
 *     kFlightRecorderDepth syscalls (num + arg snapshot + RIP +
 *     timestamp). Dumped on abnormal exit by the crash-dump
 *     path; live-readable via SYS_WIN32_CUSTOM op=Dump.
 *
 *   - **Tagged HANDLE provenance**: every Win32 handle the
 *     subsystem hands out is recorded in a per-process side
 *     table (handle, creator RIP, creator syscall, timestamp,
 *     generation). Use-after-CloseHandle becomes diagnosable —
 *     the generation bumps on close, so a stale handle dereference
 *     finds an inactive entry instead of a fresh slot.
 *
 *   - **GetLastError provenance**: the most-recent
 *     SetLastError records *who* set the error (RIP + syscall
 *     number + timestamp). A debugger can ask "where did
 *     ERROR_INVALID_PARAMETER come from?" in one call.
 *
 *   - **Quarantine free**: heap blocks freed by Win32HeapFree
 *     are held for kQuarantineMs before being available for
 *     re-allocation. Catches the classic free-then-reuse UAF
 *     pattern that real Windows tolerates silently.
 *
 *   - **Deadlock detection**: every WaitForSingleObject on a
 *     mutex registers a wait edge in a global graph. A cycle
 *     in the graph at wait time is a deadlock — logged with
 *     the full edge list before the wait blocks (caller's
 *     choice whether to break or proceed).
 *
 *   - **Contention profile**: per-mutex wait count + wait
 *     ticks accumulators. Free signal that a critical section
 *     is hot.
 *
 *   - **Force-async paint**: the WM keeps the last good frame
 *     and the compositor never blocks on a paint message. A
 *     hung WndProc no longer produces a "Not Responding" ghost.
 *
 *   - **Per-window pixel isolation**: cross-process BitBlt
 *     reads are denied by policy when both the source's owner
 *     and the destination's owner have this bit set. Closes
 *     the long-standing "BitBlt the desktop" exfil vector.
 *
 *   - **Input replay**: every WM_* message dispatched to a
 *     window with this bit set is captured into a global ring.
 *     Useful for record-and-replay debugging, GUI-fuzzing
 *     baselines, and reproducing input-driven heisenbugs.
 *
 *   - **Strict RWX**: a PE section with the
 *     IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE pair set is
 *     refused. Real Windows lets sloppy linkers ship RWX; we
 *     don't have to.
 *
 *   - **Strict handle inheritance**: child processes don't
 *     auto-inherit "inheritable" handles. Capabilities must be
 *     explicitly granted.
 *
 * Threading: per-process state lives on the Process struct
 * (lazy-allocated on first opt-in). All updates are made under
 * arch::Cli/Sti — every consumer is a syscall handler running
 * in the calling task's context.
 */

namespace duetos::core
{
struct Process;
}

namespace duetos::arch
{
struct TrapFrame;
}

namespace duetos::subsystems::win32::custom
{

// ---------- Policy bitmask (per-process) ----------
//
// Default for every process is 0 (all features off). Apps opt in
// via SYS_WIN32_CUSTOM op=SetPolicy. Stable bits — once a flag
// number is published it doesn't move.
inline constexpr u64 kPolicyFlightRecorder = 1ULL << 0;
inline constexpr u64 kPolicyHandleProvenance = 1ULL << 1;
inline constexpr u64 kPolicyErrorProvenance = 1ULL << 2;
inline constexpr u64 kPolicyQuarantineFree = 1ULL << 3;
inline constexpr u64 kPolicyDeadlockDetect = 1ULL << 4;
inline constexpr u64 kPolicyContentionProfile = 1ULL << 5;
inline constexpr u64 kPolicyAsyncPaint = 1ULL << 6;
inline constexpr u64 kPolicyPixelIsolation = 1ULL << 7;
inline constexpr u64 kPolicyInputReplay = 1ULL << 8;
inline constexpr u64 kPolicyStrictRwx = 1ULL << 9;
inline constexpr u64 kPolicyStrictHandleInherit = 1ULL << 10;

inline constexpr u64 kPolicyAllMask = (1ULL << 11) - 1ULL;

// ---------- Auto-on default ----------
//
// Tier-1 features change no observable behaviour — they only
// *record* signal — so every Win32 PE gets them at load time
// without the app's source having to opt in. Apps that genuinely
// don't want them can clear bits via SYS_WIN32_CUSTOM op=SetPolicy.
//
// Tier-2 (behaviour-changing) features stay opt-in: their
// presence in `kPolicyAutoOnDefault` would turn a Windows-buggy
// probe into a different Windows-buggy probe, which is exactly
// the tradeoff we're trying not to lose.
//
//   Auto-on (tier 1):
//     FlightRecorder, HandleProvenance, ErrorProvenance,
//     ContentionProfile, DeadlockDetect (cycle is logged but the
//     wait still proceeds — pure diagnostic), InputReplay (data
//     plane is pull-only).
//
//   Opt-in (tier 2):
//     QuarantineFree (delays heap reuse — observable to a UAF
//     test), AsyncPaint, PixelIsolation, StrictRwx (refuses some
//     loads outright), StrictHandleInherit.
inline constexpr u64 kPolicyAutoOnDefault = kPolicyFlightRecorder | kPolicyHandleProvenance | kPolicyErrorProvenance |
                                            kPolicyContentionProfile | kPolicyDeadlockDetect | kPolicyInputReplay;

// ---------- Sub-op codes for SYS_WIN32_CUSTOM ----------
//
// The single Win32-custom syscall multiplexes into these by rdi.
// Stable: numbered, never reused.
inline constexpr u64 kOpGetPolicy = 0;
inline constexpr u64 kOpSetPolicy = 1;
inline constexpr u64 kOpDumpFlight = 2;
inline constexpr u64 kOpDumpHandles = 3;
inline constexpr u64 kOpGetErrorProvenance = 4;
inline constexpr u64 kOpDetectDeadlock = 5;
inline constexpr u64 kOpDumpQuarantine = 6;
inline constexpr u64 kOpDumpContention = 7;
inline constexpr u64 kOpDumpInputReplay = 8;
inline constexpr u64 kOpGetSystemDefault = 9;
inline constexpr u64 kOpSetSystemDefault = 10;

// ---------- Per-process record types ----------
struct FlightRecord
{
    u64 timestamp_ns;
    u64 rip;
    u64 rdi;
    u64 rsi;
    u64 rdx;
    u32 syscall_num;
    u32 _pad;
};
inline constexpr u32 kFlightRecorderDepth = 64;

struct HandleProvenance
{
    u64 handle;
    u64 creator_rip;
    u64 timestamp_ns;
    u32 syscall_num;
    u32 generation; // bumped on close — stale handle reads land on inactive slot
    bool active;
    u8 _pad[7];
};
inline constexpr u32 kHandleProvenanceCap = 64;

struct ErrorProvenance
{
    u64 set_rip;
    u64 set_timestamp_ns;
    u32 last_value;
    u32 set_syscall_num;
};

struct QuarantineEntry
{
    u64 user_va;
    u64 size;
    u64 release_tick; // tick after which the entry may be re-armed
};
inline constexpr u32 kQuarantineDepth = 32;
// Hold freed heap blocks for ~250 ms at 100 Hz tick = 25 ticks.
inline constexpr u64 kQuarantineTicks = 25;

struct ContentionRecord
{
    u64 acquire_count;
    u64 wait_count;    // # times a wait actually blocked (count > 0)
    u64 total_wait_ms; // sum of wait durations in ms
};
// One record per Win32 mutex slot in the process (matches Process::kWin32MutexCap).
inline constexpr u32 kContentionSlotCap = 8;

// ---------- Global (kernel-wide) tables ----------
struct InputReplayEntry
{
    u64 timestamp_ns;
    u64 wparam;
    u64 lparam;
    u32 hwnd_biased;
    u32 message;
    u64 owner_pid;
};
inline constexpr u32 kInputReplayDepth = 256;

struct WaitEdge
{
    bool in_use;
    u8 _pad[3];
    u32 _pad2;
    u64 waiter_tid;
    u64 waiter_pid;
    u64 holder_tid; // 0 if unknown
    u64 holder_pid;
    u64 handle; // mutex handle the waiter is blocked on
};
inline constexpr u32 kWaitGraphCap = 64;

// ---------- Per-process state (heap-allocated) ----------
//
// Lives on Process::win32_custom_state (a void* that this module
// owns the layout of). Allocated lazily on first opt-in, freed
// in CleanupProcess. Zero-initialised on creation.
struct ProcessCustomState
{
    u64 policy;

    FlightRecord flight[kFlightRecorderDepth];
    u32 flight_head;
    u32 flight_count;

    HandleProvenance handles[kHandleProvenanceCap];
    u32 handles_count;

    ErrorProvenance error;

    QuarantineEntry quarantine[kQuarantineDepth];
    u32 quarantine_head;
    u32 quarantine_count;

    ContentionRecord contention[kContentionSlotCap];

    // Set when DetectCycle has reported the current cycle to the
    // log; cleared when the wait edge is removed. Avoids spam.
    bool cycle_reported;
    u8 _pad[7];
};

// ---------- Lifecycle ----------
//
// Lazy-init the per-process state if it doesn't exist yet. Returns
// the state pointer or nullptr on KMalloc failure (in which case
// the policy bit silently stays off — diagnostics are best-effort).
ProcessCustomState* EnsureState(core::Process* proc);

// Returns the process's state if it exists, nullptr otherwise. Use
// this from hook sites — never allocate from a hot path.
ProcessCustomState* GetState(core::Process* proc);

// Free the per-process state. Called by ProcessRelease.
void CleanupProcess(core::Process* proc);

// Apply the system-default policy mask to `proc`. Called once per
// Win32 PE at load time (from Win32HeapInit). Allocates the state
// block if needed; ORs system_default into the existing policy
// (idempotent). Best-effort — silent on KMalloc OOM.
void ApplySystemDefaultPolicy(core::Process* proc);

// Read / write the kernel-wide default policy mask. Defaults to
// kPolicyAutoOnDefault at boot; an operator (root shell, init
// script) can flip it via SYS_WIN32_CUSTOM op=SetSystemDefault to
// turn the diagnostic suite up (e.g. add quarantine for a debug
// session) or down (e.g. clear the lot for a production build).
u64 GetSystemDefaultPolicy();
void SetSystemDefaultPolicy(u64 mask);

// ---------- Hook entry points (called from existing handlers) ----------
//
// All of these no-op when the relevant policy bit isn't set. Safe
// to call on processes with no custom state at all.

void OnSyscallEntry(core::Process* proc, u64 num, const arch::TrapFrame* frame);
void OnHandleAlloc(core::Process* proc, u64 handle, u32 syscall_num, u64 caller_rip);
void OnHandleClose(core::Process* proc, u64 handle);
bool IsHandleActive(core::Process* proc, u64 handle);
void OnLastErrorSet(core::Process* proc, u32 value, u64 caller_rip, u32 syscall_num);
void OnHeapFree(core::Process* proc, u64 user_va, u64 size);

// Returns true if a quarantined block at `user_va` is still in
// quarantine (callers must skip such blocks during reuse). Drains
// expired entries as a side effect.
bool IsQuarantined(core::Process* proc, u64 user_va);

// Mutex contention + deadlock detect.
//
// `OnMutexWaitStart` registers a wait edge and runs cycle-detection.
// Returns true if a cycle was detected (caller may break, log, or
// proceed at its discretion — v0 always proceeds and just logs).
bool OnMutexWaitStart(core::Process* proc, u32 mutex_slot, u64 handle, u64 holder_tid, u64 holder_pid);

// `OnMutexWaitEnd` clears this thread's wait edge and, if the wait
// was blocking (start_tick != end_tick), bumps the contention record.
void OnMutexWaitEnd(core::Process* proc, u32 mutex_slot, u64 wait_ticks);

// Bump the acquire count for a mutex slot (called on every successful
// non-blocking acquire path too).
void OnMutexAcquire(core::Process* proc, u32 mutex_slot);

// ---------- Window-manager additions ----------

// True iff a cross-process BitBlt should be denied by policy. Both
// sides must opt in for this to fire (a single opted-in process
// can't deny reads to itself, only against other opted-in processes).
bool PixelIsolationDenies(core::Process* src_proc, core::Process* dst_proc);

// True iff `proc` is requesting force-async paint (the window
// manager keeps the last good frame and never stalls on a paint
// callback).
bool AsyncPaintActive(core::Process* proc);

// Push an input event into the global replay ring if the focused
// window's owner has kPolicyInputReplay set. owner_proc is the
// owning process; nullptr is allowed and skips the push.
void InputReplayPush(core::Process* owner_proc, u32 hwnd_biased, u32 message, u64 wparam, u64 lparam);

// ---------- PE loader policy ----------

// Returns true iff a PE section's CHARACTERISTICS bits demand
// kPolicyStrictRwx rejection. Caller (PE loader) maps non-rejected
// sections normally.
bool StrictRwxRejectsSection(core::Process* proc, u32 characteristics);

// ---------- Crash-dump hooks ----------
//
// Called by the panic / exit path when a process is dying
// abnormally. Emits the flight recorder + handle ledger to the
// serial log so a post-mortem reader sees full context.
void DumpOnAbnormalExit(core::Process* proc);

// ---------- Syscall handler ----------
//
// Single multiplexed entry. rdi = sub-op (kOp* above), rsi/rdx/r10
// = op-specific args. Return code in rax: 0/+ on success, -1 on
// invalid op or proc==nullptr.
void DoCustom(arch::TrapFrame* frame);

} // namespace duetos::subsystems::win32::custom
