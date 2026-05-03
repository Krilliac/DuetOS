#pragma once

#include "util/types.h"

/*
 * DuetOS — security event ring v0 (blue team foundation).
 *
 * A bounded ring buffer of structured security-relevant events.
 * Every wall trip / detector fire / mode change publishes here;
 * an operator (or a purple-team scorecard) snapshots it for
 * forensics, post-mortem, or coverage measurement.
 *
 * Why a ring instead of klog scraping? klog is line-formatted
 * for humans — each subsystem decides its own severity, prefix,
 * and detail level. Security analysis wants STRUCTURED data
 * with a stable schema (kind + actor pid + aux payload + uptime)
 * and lossless overwrite semantics ("we lost N old events" is a
 * first-class signal). klog stays for general logging; the
 * event ring is security-only.
 *
 * Capacity = 256 entries (~12 KiB). When full, oldest entry is
 * overwritten; `dropped_oldest` bumps. Sequence numbers are
 * monotonic across boot — never reused even after overwrite.
 *
 * Thread safety: protected by a single SpinLock. Safe from any
 * context (IRQ, NMI, task). Publishing is intentionally cheap —
 * the lock is held for the duration of one struct-copy and the
 * head/tail pointer update.
 *
 * See `.claude/knowledge/blue-team-event-ring-v0.md` for the
 * design rationale.
 */

namespace duetos::security
{

enum class EventKind : u16
{
    None = 0,

    // Wall-fired (defensive trip):
    CanaryTouch,
    PersistenceDrop,
    FsWriteRateBurst,     // 1 s / 16 MiB cap crossed
    FsWriteRateSustained, // 5 min / 256 MiB cap crossed
    FsWriteRateLong,      // 1 h / 2 GiB cap crossed
    SandboxDenialKill,    // 100 cap-denials threshold reaped
    TickBudgetKill,       // CPU-tick budget exhausted

    // Health detector fired (rootkit / corruption signal):
    IdtModified,
    GdtModified,
    KernelTextModified,
    SyscallMsrHijacked,
    BootSectorModified,
    Cr0WpCleared,
    Cr4SmepCleared,
    Cr4SmapCleared,
    EferNxeCleared,
    StackCanaryZero,
    FeatureControlUnlocked,

    // Image / loader:
    ImageRejected, // guard.cpp denied an image at load
    ImageWarned,   // guard.cpp emitted a Warn verdict

    // Policy / mode change (white team):
    PolicyChanged,
    GuardModeChanged,
    PersistenceModeChanged,
    BlockguardModeChanged,

    // Purple-team / IR:
    AttackSimRun,     // attack_sim suite invocation
    IrRunbookEmitted, // runbook line emitted for finding

    Count, // sentinel — keep last
};

const char* EventKindName(EventKind k);

inline constexpr u32 kEventTagLen = 24;

struct Event
{
    u64 seq;       // monotonic per-ring sequence number
    u64 uptime_ns; // when the event happened
    EventKind kind;
    u16 _pad;
    u32 actor_pid;          // calling process pid, or 0 if kernel-only
    u64 aux1;               // kind-specific payload (HealthIssue index, etc.)
    u64 aux2;               // kind-specific payload (window bytes, etc.)
    char tag[kEventTagLen]; // short tag (op name, path basename, ...)
};

struct EventRingStats
{
    u64 published_total; // every successful publish bumps this
    u64 dropped_oldest;  // overwrites that lost an unread event
    u64 head;            // next slot to write
    u64 tail;            // oldest valid slot (only diverges from head once buffer wraps)
    u64 capacity;        // ring size in entries
};

/// Boot-time init. Zeroes counters + storage. Safe to call before
/// other security subsystems publish; a publish before Init() is
/// also safe (storage is constinit).
void EventRingInit();

/// Publish a fully-formed event. The `seq` and `uptime_ns` fields
/// are filled in by the publish path — callers pass kind, pid,
/// aux1, aux2, tag.
void EventRingPublishKind(EventKind kind, u32 actor_pid, u64 aux1, u64 aux2, const char* tag);

/// Read a non-mutating snapshot of the ring's bookkeeping.
EventRingStats EventRingStatsRead();

/// Iterator: callback fires per-event from oldest to newest.
/// Visitor is called under the ring lock — keep it short, and
/// in particular DO NOT call EventRingPublishKind from inside
/// the visitor (would deadlock).
using EventVisitor = void (*)(const Event& e, void* cookie);
void EventRingForEach(EventVisitor visitor, void* cookie);

/// Filtered visit: only events whose kind == `kind`. Same lock
/// rules as EventRingForEach.
void EventRingForEachKind(EventKind kind, EventVisitor visitor, void* cookie);

/// Pretty-print the most recent `n` events (newest at the bottom).
/// Capped internally to the ring capacity. Emits to COM1 / klog.
void EventRingDumpRecent(u64 n);

/// Boot-time self-test. Publishes a few synthetic events, walks
/// them back, asserts seq monotonicity + correct ordering.
void EventRingSelfTest();

} // namespace duetos::security
