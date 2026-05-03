# Security team colors — DuetOS map

**Type:** Decision + Pattern
**Status:** Active — anchors the multi-color security work
**Last updated:** 2026-05-03

## What it is

The cybersecurity industry classifies security work by colors,
each owning a different concern. DuetOS adopts the standard
wheel and assigns each color a specific surface in the
codebase. This document is the meta-index — it points at the
per-color v0 plans and tracks coverage progress.

## The wheel

| Color | Role |
|---|---|
| **Red** | Offensive — simulate attacks, prove walls hold |
| **Blue** | Defensive — detect, respond to, recover from attacks at runtime |
| **Yellow** | Builders — secure-by-default APIs and development practices |
| **Purple** | Bridges red ↔ blue — measure detection coverage and latency |
| **Green** | Bridges yellow ↔ blue — feed detection requirements back to builders |
| **Orange** | Bridges yellow ↔ red — secure coding informed by attacker techniques |
| **White** | Governance — policy, escalation rules, audit, oversight |

## DuetOS coverage today

| Color | Status | Surface |
|---|---|---|
| Red    | ✅ strong   | `kernel/security/attack_sim.cpp` (16 in-kernel attacks), `kernel/proc/ring3_smoke.cpp` (12 ring-3 hostile probes), `kernel/security/pentest_gui.cpp` (operator console) |
| Blue   | 🟡 partial  | `kernel/diag/runtime_checker.cpp` (~28 detectors); kill paths via `KillReason::*`; Heal paths for descriptor tables / syscall MSRs / CR bits. **v1 brings:** event ring + IR runbook (this slice) |
| Yellow | 🟡 partial  | `Result<T,E>`, cap-gated syscalls, W^X enforced in MapUserPage, no `new`/`delete` in kernel, KMalloc-zero-init pattern. No formal "secure code" checklist yet |
| Purple | ❌ → 🟡     | **v0 in this slice:** `kernel/security/purple_team.cpp` wraps `AttackSimRun` with detection-latency + false-positive measurement |
| Green  | ❌          | Future — when formal IR runbooks are written, the gaps they expose feed back as "yellow team should add API X" — no harness yet |
| Orange | 🟡 minimal  | Comments in attack_sim describe the threat each detector defends against, but no formal "common pitfall" doc for new code reviewers |
| White  | 🟡 → ✅     | **v0 in this slice:** `kernel/security/policy.cpp` defines profiles (Lab / Production / Forensic) that compose all the per-subsystem modes coherently |

## Per-color knowledge files

- **Blue team — security event ring**: `.claude/knowledge/blue-team-event-ring-v0.md`
- **Blue team — IR runbook**: `.claude/knowledge/blue-team-ir-runbook-v0.md`
- **Purple team — coverage scorecard**: `.claude/knowledge/purple-team-coverage-scorecard-v0.md`
- **White team — policy engine**: `.claude/knowledge/white-team-policy-engine-v0.md`
- **Red team — coverage matrix** (existing): `.claude/knowledge/redteam-coverage-matrix-v0.md`

## Why each color matters in an OS context

- **Red without Blue** = "we know how attackers come in but we
  can't see them when they do." Pretty walls, no logging.
- **Blue without Red** = "we have detectors but no idea if
  they actually fire on real attacks." Brittle detection.
- **Red without Purple** = "every attack passes a self-test,
  but nobody verifies the production detection latency."
  Detectors might fire too late to matter.
- **No Yellow** = "secure code is whatever the last reviewer
  remembered to ask for." Regressions accumulate quietly.
- **No White** = "every subsystem has its own toggle, no one
  set of switches captures the operator's intent." The
  operator types `guard enforce` but forgets `persistence
  deny` — half-defended state.

## Slice plan (this session)

1. **Event ring** — foundation that everything else publishes to.
2. **IR runbook** — per-finding follow-up guidance.
3. **Policy engine** — coherent profile flips.
4. **Purple-team scorecard** — coverage report wrapping AttackSimRun.

Each lands as a separate kernel TU; all four ship together so
the boot init order is right (event ring before everything,
purple-team last). Plans for Green / Orange teams are deferred
until the formal IR runbooks are mature enough to generate
gap reports automatically.
