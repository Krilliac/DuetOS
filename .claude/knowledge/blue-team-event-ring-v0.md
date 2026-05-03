# Blue team — security event ring v0

**Type:** Decision + Pattern
**Status:** Active — foundation TU for the blue / purple / white work
**Last updated:** 2026-05-03

## What it is

A bounded ring buffer of structured security-relevant events.
Every detector / wall / mode-change publishes to the ring; an
operator (or a test) can snapshot it for forensics, post-
mortem, or the purple-team coverage scorecard.

Today the kernel has klog (general logging, line-formatted) and
the runtime checker's `HealthReport` (counters per
`HealthIssue`). Neither of those gives an analyst the **timeline
of security events**: "between 12:01 and 12:03, the system saw
an IDT modification, then a canary trip, then 4 sandbox-denial
threshold kills." The event ring fills that gap.

## API shape

```cpp
namespace duetos::security {

enum class EventKind : u16
{
    None = 0,
    // Wall-fired (defensive trip):
    CanaryTouch,            // canary path / suspicious extension
    PersistenceDrop,        // autostart-equivalent path mutation
    FsWriteRateBurst,       //  1 s / 16 MiB cap crossed
    FsWriteRateSustained,   //  5 min / 256 MiB cap crossed
    FsWriteRateLong,        //  1 h / 2 GiB cap crossed
    SandboxDenialKill,      //  100 cap-denials threshold reaped
    TickBudgetKill,         //  CPU-tick budget exhausted
    // Health detector fired (rootkit / corruption signal):
    IdtModified, GdtModified, KernelTextModified,
    SyscallMsrHijacked, BootSectorModified,
    Cr0WpCleared, Cr4SmepCleared, Cr4SmapCleared, EferNxeCleared,
    StackCanaryZero, FeatureControlUnlocked,
    // Image / loader:
    ImageRejected,          // guard.cpp denied an image at load
    ImageWarned,            // guard.cpp emitted a Warn verdict
    // Policy / mode change:
    PolicyChanged,
    GuardModeChanged,
    PersistenceModeChanged,
    BlockguardModeChanged,
    // Purple-team / IR:
    AttackSimRun,           // attack_sim suite invocation
    IrRunbookEmitted,       // runbook line emitted for finding
    Count,
};

struct Event
{
    u64 seq;            // monotonic per-ring sequence number
    u64 uptime_ns;      // when the event happened
    EventKind kind;
    u16 _pad;
    u32 actor_pid;      // calling process pid, or 0 if kernel-only
    u64 aux1;           // kind-specific payload (HealthIssue index, etc.)
    u64 aux2;           // kind-specific payload (window bytes, etc.)
    char tag[24];       // short tag (op name, path basename, ...)
};

void EventRingPublish(const Event& e);
void EventRingPublishKind(EventKind kind, u32 actor_pid,
                          u64 aux1, u64 aux2, const char* tag);

// Snapshot APIs — non-mutating walks of the ring.
struct EventRingStats { u64 published_total; u64 dropped_oldest; u64 head; u64 tail; u64 capacity; };
EventRingStats EventRingStatsRead();

// Iterator: callback fires per-event from oldest to newest.
using EventVisitor = void (*)(const Event& e, void* cookie);
void EventRingForEach(EventVisitor visitor, void* cookie);

// Filtered visit: only events matching `kind`.
void EventRingForEachKind(EventKind kind, EventVisitor visitor, void* cookie);

// Boot init.
void EventRingInit();

// Shell-facing pretty-printer. Emits the last `n` events
// (newest at the bottom) to the serial console.
void EventRingDumpRecent(u64 n);

const char* EventKindName(EventKind k);

} // namespace duetos::security
```

## Storage

- Bounded ring of `Event` structs, capacity 256 entries (~12 KiB).
  When full, oldest entry is overwritten + `dropped_oldest`
  bumps (so an analyst can tell the ring lost data).
- Single-producer ordering today (kernel-only callers); a
  spinlock guards the head/tail pointers so multi-producer
  safety lands cheaply when SMP comes in.
- Event seq numbers monotonic across the lifetime of boot
  (never reused, even on overwrite).

## Wiring (publishes from existing TUs)

- `kernel/security/canary.cpp` `CanaryTrip` →
  `EventKind::CanaryTouch` with `aux1 = trip kind` and
  `tag = op`.
- `kernel/security/canary.cpp` `PersistenceNote` →
  `EventKind::PersistenceDrop`.
- `kernel/proc/process.cpp` `RecordFsWrite` (on threshold cross)
  → `EventKind::FsWriteRate{Burst,Sustained,Long}`.
- `kernel/proc/process.cpp` `RecordSandboxDenial` (on threshold)
  → `EventKind::SandboxDenialKill`.
- `kernel/diag/runtime_checker.cpp` `Report` →
  `EventKind::<detector>` for the security-critical issues.
- `kernel/security/guard.cpp` denial path →
  `EventKind::ImageRejected`.

## What this does NOT replace

- **klog** stays for general kernel logging. Event-ring is
  security-only and structured (one row per event, fixed
  fields).
- **HealthReport** counters stay for "how many of each issue
  total since boot". Event ring captures **timeline** + **per-
  event context** (actor pid, aux payload).

## Shell command

`secevents [N]` dumps the last N events (default 32). Output
is one line per event:

```
[seq=0001 t=+002.341s pid=0042 CanaryTouch         tag=create   aux=0x40
 seq=0002 t=+002.343s pid=0042 SandboxDenialKill   tag=Cap=Net  aux=0x64
 seq=0003 t=+003.001s pid=0000 IdtModified         tag=AttackSim aux=0x12]
```

## Storage pattern: KMalloc-zero-init

The ring storage is a `constinit` static array — no KMalloc, no
init-order surprises. Ready from the first publish, even before
`EventRingInit` runs.
