# Runtime Recovery Strategy — Halt vs. Restart vs. Retry vs. Reject

_Last updated: 2026-04-20_

## Purpose

Decide, **per category of fault**, whether the kernel should:

1. **Halt** the CPU (unrecoverable integrity violation),
2. **Restart** a contained subsystem (driver / process / service),
3. **Retry** with backoff (transient hardware or peer error),
4. **Reject** and return an error (bad input crossing a trust boundary),
5. **Quarantine** (mark-bad + isolate for later analysis).

Without a written taxonomy, every new subsystem re-argues this from
first principles and the kernel slowly drifts into either "panics all
the time for non-panic-worthy things" or — far worse for an
anti-malware-aware OS — "silently heals corrupted state and masks
live bugs / active attacks."

This doc is the **source of truth** for the question "when X happens,
what does the kernel do?" Individual subsystems may defer to it with
a one-line reference; deviations must be justified per-subsystem and
logged in `design-decisions-log.md`.

## Governing principles

1. **Kernel-integrity violations halt.** If the frame allocator's
   freelist is corrupt, we do not know what else is corrupt. Silent
   reset = silent compromise. Halt, dump state, let the watchdog /
   operator intervene. This is consistent with Linux, BSD, and
   Windows `KeBugCheck`.

2. **Corruption is rarely bounded to one object.** If a heap header's
   `size` field is nonsensical, the memory it came from was likely
   written by code that doesn't respect heap invariants — and that
   code is still running. Resetting the header doesn't fix the
   writer.

3. **Security posture beats availability posture at the kernel
   boundary.** This kernel has anti-malware hard-stop as a stated
   goal (see `security-malware-hard-stop-plan.md`). Self-healing
   patterns are exactly what sophisticated rootkits exploit to evade
   detection — e.g. corrupting a capability table and counting on
   the kernel to "fix" it to a permissive default. No self-heal on
   security-relevant state.

4. **Recovery is appropriate at fault-isolation boundaries we
   already trust.** Process ≠ kernel. Driver ≠ kernel (future). A
   device ≠ the driver (device flakes, driver doesn't have to die).
   Recover across boundaries, not inside them.

5. **Every recovery emits an audit event.** Silent recovery is worse
   than loud panic — operations/security teams need to know
   something went wrong even if the system kept running. Tie into
   `klog` `Error`-level at minimum; future security subsystem will
   hook a structured event sink.

6. **Retry is bounded.** Infinite retry masks stuck hardware as
   infinite latency. Every retry has a finite attempt count and a
   terminal "give up and propagate" state.

## Fault taxonomy

### Class A — Kernel integrity (HALT)

**Scope:** anything a kernel invariant depends on.

- Frame allocator bitmap consistency.
- Kernel heap chunk header sanity (`size`, `next` pointer in-pool).
- Page-table walker hitting an unexpected large-page or null entry.
- Scheduler runqueue / sleepqueue / wait-queue link corruption.
- Mutex held by a task that is `Dead`, or held by a CPU that isn't
  currently executing.
- Spinlock released by a CPU that doesn't own it.
- Capability table entries with invalid types (future).
- IOAPIC / LAPIC MMIO writes that don't round-trip (hardware lying).

**Response:** `core::Panic(subsystem, message)`. Serial dump of
relevant state, halt the CPU. On SMP, broadcast an NMI to peer CPUs
and halt them too (future — see SMP work).

**Rationale:** We cannot prove corruption is bounded. Continuing
risks cascading failure and masks the root cause. A halt captures
the state when the invariant first broke, which is the only
debuggable moment.

### Class B — Driver fault (RESTART — future)

**Scope:** in-kernel device drivers that misbehave.

- Driver probes a device and the device never responds (timeout).
- Driver gets an unexpected error status from its device (bus
  parity, DMA abort, etc.).
- Driver's own internal invariant violated (but the kernel's
  isn't — e.g. a driver state machine entered an unreachable
  state).
- Driver hangs (watchdog fires on its IRQ handler).

**Response:**
1. Capture the driver's name, the fault reason, and any device
   register snapshot it wants to archive.
2. Call driver's `Teardown()` to mask IRQs, abandon in-flight DMAs,
   free driver-private memory.
3. Mark the driver suspect — N strikes per device before we stop
   auto-restarting.
4. Call `Probe()` again if retries remain; else leave the device
   offline and emit a `klog::Error` event.
5. Kernel continues normally.

**Critical invariant:** the driver must NOT be holding any kernel
lock when it faults. If it is, that's a Class-A violation — the
kernel lost an invariant — and it escalates to Panic. This is why
drivers must document what locks they hold in each code path (see
`CLAUDE.md` "Thread safety rules").

**Nothing actionable today** — we have PS/2, which has no fault path.
The `kernel/diag/recovery.h` module defines the API shape for when
the first real driver arrives.

### Class C — Process / task fault (KILL — future, post-ring-3)

**Scope:** user-mode processes that crash.

- Page fault on a user address with no valid mapping.
- Illegal instruction in ring 3.
- Syscall with out-of-range arguments that the handler rejects.
- Explicit `exit()` with a nonzero status.
- Process quota exceeded (memory / file handles / etc.).

**Response:**
1. Deliver a fatal signal equivalent or record crash reason.
2. Release every kernel-side resource owned by the task (file
   descriptors, memory mappings, IPC handles, wait queues it was
   parked on).
3. Mark the task `Dead` + enqueue on the reaper list.
4. Reaper frees the task struct + stack asynchronously.
5. If the task was a system service: init (PID 1, future) decides
   whether to respawn.
6. Kernel continues normally.

**Nothing actionable today until ring 3 lands.** But the reaper
piece IS actionable — we already leak `Dead` tasks (see
`sched-blocking-primitives-v0.md` Notes). Closing that leak is the
first real recovery path in the codebase.

### Class D — Transient hardware / peer error (RETRY)

**Scope:** I/O paths that talk to hardware or (future) network peers.

- AHCI / NVMe command completion with a retriable status.
- NIC packet drop on the transmit ring.
- Serial port busy / full.
- ACPI event register read-back mismatch (rare — usually indicates
  a glitch, not persistent).

**Response:**
1. Retry with exponential backoff — N attempts, caps on both attempt
   count and total wait time.
2. On final failure, escalate one level up: driver sees "device
   offline," fs sees "I/O error," net sees "link down."
3. `klog::Warn` on every retry, `klog::Error` on final give-up.

**Policy:** default 3 retries / 100 ms total timeout for latency-
sensitive paths; 10 retries / 1 s total for background work.
Specific subsystems override per known device characteristics.

**Actionable today:** small helper in `kernel/diag/recovery.h` —
`RetryWithBackoff(Fn, Policy)`. Usable when we have an I/O path
that needs it; costs one API surface now, zero call sites.

### Class E — Bad input across trust boundary (REJECT)

**Scope:** anything crossing into the kernel from a less-trusted
caller — user-mode syscalls (future), untrusted IPC peers, parsing
external data.

- Syscall argument out of range.
- Capability handle doesn't refer to the claimed object.
- Untrusted-source file header fails validation.
- PE loader rejects a malformed import table.

**Response:**
1. Reject at the boundary. Never touch the invalid value past
   validation.
2. Return a typed error to the caller (future `Result<T, E>` ABI).
3. `klog::Warn` (not Error — bad input is normal at this boundary).
4. Rate-limit identical errors to avoid log flooding by a hostile
   caller.
5. Security subsystem gets an event — see `security-malware-hard-
   stop-plan.md` §3.A, the Security Policy Engine exec gate is
   exactly this.

**Nothing actionable today until we have a trust boundary** — PS/2
driver is fully kernel-resident. First real use is the syscall
surface when ring 3 lands.

### Class F — Well-bounded object state (RESET + AUDIT)

**Scope:** specific object instances where we can **prove**
corruption is isolated to that one object.

- A connection struct in a future TCP stack, where the struct is
  reachable only from a per-connection hash table entry.
- A cache entry where the underlying data is re-fetchable.
- A per-file lease / lock that can be dropped and re-acquired.

**Response:**
1. Drop the object. Return the entry to its pool / free the memory.
2. Notify any watcher that depended on it ("connection reset,"
   "cache miss").
3. `klog::Error` with as much detail as we can without touching the
   suspect bytes.
4. Metric: count of "object-reset" events per subsystem — a spike
   is a red flag that the bug isn't bounded after all.

**Case-by-case review required.** The "well-bounded" claim is
usually wrong — an assumption that the bug is local when in fact the
cause wrote through a bad pointer from elsewhere. When in doubt,
escalate to Class A. Subsystems that opt into Class F recovery must
document the bounded-ness argument in their knowledge file.

## Decision flow

When a fault is detected, the code at the detection point answers
**four questions** in order:

```
1. Does this violate a kernel-wide invariant (heap / paging /
   scheduler / locks / capabilities)?
   YES → Class A (HALT). Stop here.
   NO  → continue.

2. Is this a fault within a subsystem that has a documented
   fault-isolation boundary (driver / process / cache) AND the
   fault hasn't yet crossed that boundary?
   YES → Class B (driver) / C (process) / F (object): RESTART.
   NO  → continue.

3. Is the failing operation idempotent or retriable, with a known
   transient cause?
   YES → Class D (RETRY with bounded backoff).
   NO  → continue.

4. Is this bad input crossing a trust boundary from a less-trusted
   caller?
   YES → Class E (REJECT + audit event).
   NO  → Class A (HALT) — we don't have a category for it, which
         means it's unexpected, which means kernel integrity may be
         compromised.
```

"Unexpected fault defaults to halt" is the secure default. New
categories get added deliberately, with their bounded-ness argument
written down first.

## Today's state

| Class | Status | Notes |
|-------|--------|-------|
| A HALT | **Active** | `core::Panic` + `KASSERT` landed. |
| B Driver RESTART | **API only** | `kernel/diag/recovery.h` shell; no driver uses it yet. |
| C Process KILL | **Partial — task reaper** | Dead-task reaper closes the known leak. Full process-kill semantics arrive with ring 3. |
| D RETRY | **API only** | `RetryWithBackoff` helper; no I/O path uses it yet. |
| E REJECT | **Deferred** | Requires a trust boundary. Arrives with syscalls. |
| F Object RESET | **Deferred** | Case-by-case; no subsystem opted in yet. |

## Anti-patterns to avoid

- **"Reset the freelist head to null if it looks bad."** The
  corruption wrote through the head pointer; resetting it loses
  every free chunk AND doesn't fix the writer. Halt.
- **"Retry the mutex lock if Unlock detects wrong owner."** The
  wrong-owner condition is a scheduler or memory invariant violation.
  Retrying hides the bug. Halt.
- **"Catch and swallow a fault in a driver so the kernel stays up."**
  If the driver held a lock when it faulted, the kernel's state is
  already inconsistent. Escalate. Driver restart only works when the
  driver's fault boundary is enforced by the driver model.
- **"Silently restart a process that keeps crashing."** Without a
  rate limit + root-cause investigation, the restart loop masks a
  repeated bug and, if that bug is security-relevant, masks an
  attack. Every restart is an audit event; a rising rate triggers
  operator visibility.
- **"Return a default value when parse fails."** The default is a
  trust decision — the caller should make it, with full context.
  Return an error; let the caller decide.

## Revisit when

- Drivers with real fault paths arrive (NVMe / xHCI / GPU) — pressure-
  test the Class B API surface. Expect to tune the retry counts.
- Ring 3 + first user processes — flesh out Class C.
- The first network / storage I/O path — flesh out Class D retry
  policies with real numbers.
- Security Policy Engine lands — hook Class E + Class F audit events
  into the SPE event stream.
- SMP bring-up — Class A halt on one CPU must broadcast-halt peers
  (NMI-IPI); don't leave other CPUs running on corrupt shared state.
- A subsystem proposes Class F recovery — review the bounded-ness
  argument before accepting.

## See also

- `security-malware-hard-stop-plan.md` — the security posture Class
  A / E / F defend.
- `design-decisions-log.md` entry 018 (this doc's inaugural entry).
- `sched-blocking-primitives-v0.md` — the "Dead tasks leak" note
  that motivated Class C's first concrete implementation (the
  reaper).
