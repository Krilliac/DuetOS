# Program Backlog, Execution Gates, and Session Continuation Plan

_Last updated: 2026-04-20_

## Goal

Convert the roadmap into an execution system that survives long-running sessions and context switches.

---

## Delivery Model

Each track uses:

- **Epics** (multi-week architecture chunks),
- **Slices** (mergeable, testable increments),
- **Gates** (must-pass quality/security thresholds).

No epic can close without gate pass.

---

## Global Gates (apply to every track)

### Gate G1 — Integration

- Feature is wired into runtime path.
- Failure path is explicitly tested.

### Gate G2 — Security

- New attack surface documented.
- Privilege boundaries reviewed.

### Gate G3 — Operability

- Logs/metrics/traces added for key state transitions.
- Panic/failure diagnostics are actionable.

### Gate G4 — Performance

- Baseline measurement exists.
- Regression budget defined and respected.

### Gate G5 — Documentation

- Architecture note updated.
- Runbook/test-plan updated.

---

## Immediate Continuation Backlog (next long session)

## Stream A — Finish Track 2 Architecture Lock

1. freeze BootInfo schema + compatibility policy,
2. finalize ACPI “required vs optional” table contract,
3. lock AP bring-up timeout/retry policy,
4. define PCI BAR allocator ownership + locking model.

**Gate to exit Stream A:** design docs reviewed and no unresolved critical assumptions.

---

## Stream B — Security Foundation Coupled Early

1. define kernel exec-hook API surface,
2. define trust-verdict enum used by loaders,
3. map where deny/quarantine actions occur in process lifecycle,
4. define minimum event fields for security audit logs.

**Gate to exit Stream B:** loader integration plan approved by both platform and security owners.

---

## Stream C — Milestone Test Matrix

1. build M1–M3 acceptance matrix,
2. define emulated and real-hardware test lanes,
3. define “release-blocking” vs “known issue” severity rules,
4. define bisect playbook for boot regressions.

**Gate to exit Stream C:** every milestone has executable pass/fail criteria.

---

## Epic Queue by Phase

### Phase A (Tracks 1–4)

- A1: deterministic build + artifact metadata,
- A2: platform foundation (Track 2 deep dive),
- A3: process/IPC ABI lock,
- A4: syscall governance and tracing baseline.

### Phase B (Tracks 5–7)

- B1: VFS + native FS write-safe MVP,
- B2: storage/USB/input production baseline,
- B3: service manager and crash-recovery path.

### Phase C (Tracks 8–10)

- C1: display/gpu abstraction and fallback renderer,
- C2: compositor + window protocol + shell primitives,
- C3: audio server + driver integration.

### Phase D (Tracks 11–12)

- D1: PE loader + ntdll/kernel32 core,
- D2: user32/gdi32 integration with native compositor,
- D3: DXGI + D3D11 translation reliability/perf pass.

### Phase E (Track 13 across all)

- E1: executable trust and policy engine,
- E2: runtime hard-stop + quarantine,
- E3: secure update and incident response.

---

## Ownership Model

Per epic assign:

- one primary owner,
- one backup owner,
- one security reviewer,
- one validation/test owner.

No unowned epic enters active state.

---

## Risk Register (must be reviewed weekly)

1. **Driver delays** block graphics and desktop schedule.
2. **ABI churn** causes repeated userland rework.
3. **Security deferral** creates expensive retrofit risk.
4. **Unbounded scope** in Win32 compatibility work.
5. **Insufficient real hardware testing** hides firmware/device bugs.

Each risk must have owner + mitigation + trigger threshold.

---

## “Definition of Ready” for New Work Items

Before implementation starts, a slice must include:

- explicit interface contract,
- dependent subsystem list,
- failure semantics,
- observability plan,
- test strategy,
- security impact statement.

If any item is missing, the slice is not ready.

---

## Session Continuity Protocol

For long sessions and interrupted handoffs:

1. start from this backlog file and current roadmap,
2. pick one stream (A/B/C) as session focus,
3. log decisions in `docs/knowledge/` immediately,
4. never end a session with undocumented architectural decisions,
5. update next-session checklist before stopping.

---

## Next-Session Checklist (authoritative)

1. Complete Track 2 contract docs from `track-2-platform-foundation-implementation-plan.md`.
2. Define Security Policy Engine interface draft (request/response + verdict semantics).
3. Draft milestone validation matrix for M1, M2, M3.
4. Assign owners for Phase A epics and set first gate review date.

