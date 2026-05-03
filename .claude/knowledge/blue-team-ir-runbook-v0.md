# Blue team — IR runbook v0

**Type:** Decision + Pattern
**Status:** Active
**Last updated:** 2026-05-03

## What it is

A per-finding-class table of structured "what just happened
+ what to check next + what to do if it re-happens" guidance.
When a wall fires, the IR runbook emits a follow-up line to
serial + publishes an `IrRunbookEmitted` event so the operator
can correlate the raw kill-line with the recommended response.

Today the kernel emits things like:

```
[fsguard] pid=0042 name="ransomware-pe" tripped 1s/16MiB cap (window_bytes=0x1000040) — terminating (suspected ransomware)
```

The operator sees the line, the task dies, and that's it. The
runbook adds:

```
[ir] FsWriteRateBurst — recommended next steps:
[ir]   1. Check `secevents 50` for cluster of related events around uptime.
[ir]   2. Inspect image source via `imagelog pid=0042` (file path, hash, signer).
[ir]   3. If image is a recent install: `guard show` to see vetting verdict.
[ir]   4. If wall keeps firing for the same image, escalate `policy set forensic`.
[ir]   5. Persistence keys: `secevents kind=PersistenceDrop` for accompanying drops.
```

## API shape

```cpp
namespace duetos::security {

struct IrRunbookEntry
{
    EventKind  kind;
    const char* one_line_summary;   // "FsWriteRateBurst — caller wrote >16 MiB in 1 s"
    const char* what_happened;      // 1-2 sentences explaining the trip
    const char* steps[6];           // up to 6 numbered steps; nullptr terminates
    const char* escalate_to;        // "policy set forensic" or similar
};

const IrRunbookEntry* IrRunbookLookup(EventKind kind);

// Emit the runbook lines for `kind` to the serial console + publish
// an IrRunbookEmitted event with the EventKind in aux1 so the
// purple-team scorecard sees that the runbook actually ran.
void IrRunbookEmit(EventKind kind, u32 actor_pid);

// Boot-time self-test: walks every EventKind and asserts the
// table either has an entry OR explicitly opts out (only the
// no-runbook-needed kinds — None, Count, generic mode-changes —
// are exempt). Prevents new EventKinds from sliding in without
// follow-up guidance.
void IrRunbookSelfTest();

// Stats — every emit bumps `emits_total`; `last_kind` aids
// "what was the latest finding?" queries.
struct IrRunbookStats { u64 emits_total; EventKind last_kind; u64 last_uptime_ns; };
IrRunbookStats IrRunbookStatsRead();

} // namespace duetos::security
```

## Wiring

- `CanaryTrip` calls `IrRunbookEmit(EventKind::CanaryTouch, pid)`
  after `RuntimeCheckerNoteCanaryFileTouched`.
- `PersistenceNote` calls `IrRunbookEmit(EventKind::PersistenceDrop, pid)`.
- `RecordFsWrite` (on threshold cross) calls
  `IrRunbookEmit(EventKind::FsWriteRate{Burst,Sustained,Long}, pid)`.
- `RecordSandboxDenial` (on threshold) calls
  `IrRunbookEmit(EventKind::SandboxDenialKill, pid)`.
- `Report` (for security-critical detectors only) calls
  `IrRunbookEmit(EventKind::<detector>, 0)`.

To avoid double-publish, `IrRunbookEmit` itself is the one that
publishes the `IrRunbookEmitted` event — the wall-trip event was
already published by the wall code.

## Runbook table sketch (initial coverage)

| EventKind | Summary | Steps |
|---|---|---|
| CanaryTouch | "Process touched a registered canary or suspicious-extension path" | secevents 50; imagelog pid=N; guard show; consider policy forensic |
| PersistenceDrop | "Process mutated an autostart-equivalent path" | secevents kind=PersistenceDrop; if Advisory + repeated, switch to Deny via policy |
| FsWriteRateBurst | "Process wrote >16 MiB in 1 second" | secevents 50; imagelog pid; check image hash against guard allowlist |
| FsWriteRateSustained | "Process wrote >256 MiB in 5 minutes (low-and-slow)" | secevents kind=FsWriteRateSustained; correlate with Persistence drops; consider forensic policy |
| FsWriteRateLong | "Process wrote >2 GiB in 1 hour (persistent attacker)" | escalate to forensic immediately; pull `imagelog`; consider freezing all kCapFsWrite holders |
| SandboxDenialKill | "Process hit 100 cap-denials — reaped as malicious" | imagelog pid=N to identify the binary; check for related image-rejection events |
| IdtModified / GdtModified / KernelTextModified | "Kernel-mode rootkit indicator" | check `health show`; this should never fire in production — **investigate immediately** |
| SyscallMsrHijacked | "LSTAR / STAR / SYSENTER MSR drift since boot baseline" | rootkit hook indicator; pull `secevents kind=SyscallMsrHijacked` for repetition; reboot is the only recovery |
| Cr0WpCleared / Cr4SmepCleared / Cr4SmapCleared / EferNxeCleared | "Security CR/EFER bit silently cleared" | health Heal already restored it; check `secevents` for repetition (silent clear → Heal → silent clear loop = active rootkit) |
| StackCanaryZero | "__stack_chk_guard zeroed" | active attack on canary protection; reboot immediately; investigate boot history |
| BootSectorModified | "MBR/GPT modified since boot baseline" | bootkit; reinstall OS image |
| ImageRejected | "Loader denied an image at load" | guard log shows the verdict reason; check the path in `imagelog` |

## What this does NOT do

- It does NOT decide policy. The runbook recommends; the
  operator (or the white-team policy engine) decides.
- It does NOT auto-execute steps. Each step is text the
  operator types or feeds to a script.
- It does NOT block the kill. By the time the runbook emits,
  the offending task is already flagged for reap.

## Why this matters for purple team

The runbook is the source of truth for "given a finding, what
SHOULD a defender do?" The purple-team scorecard can measure:
- Did the runbook fire? (yes/no)
- How long after the original wall trip? (latency)
- Was the recommendation acted on? (out of scope for v0; needs
  operator-side instrumentation)
