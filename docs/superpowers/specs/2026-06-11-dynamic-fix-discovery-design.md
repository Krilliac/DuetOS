# Dynamic Fix-Discovery Expansion — Design

**Date:** 2026-06-11
**Status:** Approved (design); implementation pending
**Author:** Claude (Opus 4.8) with Krill
**Related:** [`kernel/diag/fix_journal.h`](../../../kernel/diag/fix_journal.h),
[`tools/build/gen-fix-patches.py`](../../../tools/build/gen-fix-patches.py),
[`kernel/env/neural_policy.h`](../../../kernel/env/neural_policy.h),
Design-Decisions #016 (learner emits data, never self-modifying code).

## Problem

The fix-journal → `gen-fix-patches.py` → human-review pipeline works, but its
richest input is **hand-placed `// GAP:` / `// STUB:` markers**. A 2026-06-11
chained-load campaign produced 82 generated patches — *all* of the
marker-observability class — because the only "this is incomplete" signal the
generator can mine at volume is a marker a human already typed. The system has
dynamic runtime detectors (`trap_capture`, `oom`, `cap_denial`,
`unknown_syscall`, `unmapped_thunk`, `soft_fault_recov`, `loader_reject`) and
an autonomic learner that emits `AutonomicProposal` records, but none of these
*discover* fix-worthy code sites the way a marker names one.

**Goal:** add discovery layers that find fix-worthy sites from (C) static
structure, (A) live runtime behavior, and (B) the autonomic learner — without
a human first annotating the site — feeding the existing pipeline unchanged
downstream of the journal.

## Invariants (do not violate)

1. **DD#016:** the learner and the discovery layers emit DATA (journal
   records, structured proposals). Patches are produced by the *generator* and
   gated `#if 0` until a *human* flips them. No component writes `.text`.
2. **Single source of truth:** all discovered signal lands in the existing
   on-disk `FixJournal` ring (`KERNEL.FIX`). No parallel store.
3. **Bounded noise:** every discovery layer has explicit caps (below). The
   value of the marker discipline was a *bounded* gap inventory; dynamic
   discovery must not flood it. (Cf. the cap-audit self-test de-noising fix,
   same session — self-test denials were polluting the journal.)
4. **Subsystem isolation:** discovery instrumentation in the syscall path must
   not let a guest steer what gets recorded beyond "I hit an unimplemented
   path" — the record is keyed by *kernel* RIP, not guest data.

## Architecture — one pipeline, three new sources

```
C: static scan (build-time)  ─┐ candidate manifest (un-annotated gap-shaped sites)
                              ├─► correlate by source_pin / RIP
A: runtime inference (kernel) ┘ FixJournal(InferredGap), keyed by caller RIP, dedup+repeat
                                       │ hit-frequency + health correlation
B: learner ranking/proposals  ───────►  FixJournal(AutonomicProposal), data only
                                       ▼
        gen-fix-patches.py (+ new patch classes) ─► fix-patches/*.patch (#if 0)
                                       ▼
        human review (dfix-to-branch) ─► flip #if 0 ─► commit
```

Each source is independently shippable and independently testable.

---

## Phase A — Runtime gap inference (kernel)

**Unit:** one new `FixDetector::InferredGap` value + one recording choke-point.

**What it does.** When a syscall handler returns a *not-implemented-class*
sentinel to a guest, the dispatcher records an `InferredGap` journal entry
keyed by the handler's return RIP. The journal already dedups per
`(detector, source_pin)` with a repeat count and resolves RIP → `func+0xNN`
via addr2line, so an unimplemented path a guest hits N times collapses to one
record `repeat=N` with a resolvable source pin — exactly the shape a
hand-placed `FIX_NOTE_GAP` produces, but with zero annotation.

**Where.** The return path of the native syscall dispatcher
(`kernel/syscall/syscall.cpp`), at the single point where a handler's
`Result`/status is about to cross back to the guest. Recording uses the
existing `FixJournalRecordAtCaller(FixDetector::InferredGap, …)` so the pin
resolves to the *handler*, not the dispatcher primitive.

**Not-implemented-class sentinels (the only triggers):**
`kStatusNotImplemented`, `core::ErrorCode::NotImplemented`, and the Linux/Win32
`-ENOSYS` shape. A `PermissionDenied`, `NotFound`, `InvalidArgument`, or any
*correct* error is NOT a gap and must not record.

**Noise guards (all required):**
- **Guest-origin only** — record only when the syscall came from a guest
  (`proc != nullptr` / guest-entry flag); kernel-internal callers never record.
- **Sentinel-class allow-list** — only the not-implemented set above.
- **RIP dedup** — handled by the journal's existing per-pin dedup.
- **Per-boot rate cap** — a global cap on distinct InferredGap pins per boot
  (e.g. 128) so a pathological build can't exhaust the ring; over-cap
  increments a dropped counter (already in `FixJournalStats`).

**Output:** journal records of `FixDetector::InferredGap`. Downstream,
`gen-fix-patches.py` gets a new class that renders an InferredGap into the same
"wire this site into the journal / implement the path" note+patch shape as a
marker, but tagged "discovered (runtime), not annotated."

---

## Phase C — Static gap discovery (build-time tool)

**Unit:** `tools/build/gap-scan.py` (sibling of `gen-fix-markers.py`).

**What it does.** Scans kernel/driver/subsystem source for gap-shaped patterns
and emits `gap-candidates.json` (`{file, line, function, pattern_kind,
guest_reachable_guess}`). Patterns:
- `return kStatusNotImplemented` / `Err{ErrorCode::NotImplemented}` / `-ENOSYS`
- `default:` switch arms returning a not-impl sentinel
- `// TODO` / `// FIXME` (lower confidence)
- empty/stub function bodies returning a sentinel

**Cross-reference.** Joins against the existing marker manifest
(`gen-fix-markers.py` output) and reports only **un-annotated** candidates — a
site that already has a `// GAP:` is the human's job, done.

**Feeds the generator.** `gap-candidates.json` becomes an additional
`gen-fix-patches.py` input. Correlation by `source_pin`/file:line:
- candidate **with** a Phase-A runtime `InferredGap` hit → **"confirmed live"**
  (high priority — a real guest hit an unannotated gap),
- candidate **without** a hit → **"cold candidate"** (low priority — exists in
  source but never exercised this run).

**Why static + runtime together:** A alone finds only what was hit this boot; C
alone finds structure with no evidence of relevance. The join is the value —
"unannotated gap that a guest actually reached" is the high-signal set.

---

## Phase B — Learner-driven ranking + config proposals

**Unit:** an extension to the autonomic learner (`kernel/env/`), strictly
data-emitting.

**Ranking.** The learner already snapshots health/load each cycle. Correlate
`InferredGap` hit-bursts with health/load dips (a not-implemented path hit
immediately before a workload stalls is higher-salience than one hit during
idle). Emit a salience score per discovered gap.

**Config proposals (new proposal kind).** Beyond the existing action-gate
proposals, the learner emits bounded **config** proposals it has runtime
evidence for, e.g. "host-visible VK memory `KMalloc` returned null N× under
load → propose raising the relevant cap," as an `AutonomicProposal` record
carrying: `{target_symbol, current_value, proposed_value, evidence_summary}`.
`gen-fix-patches.py` renders these into `#if 0`-gated config-constant patches.

**Hard DD#016 boundary.** The learner produces a *structured proposal* (symbol
+ numbers + evidence). The *generator* produces the diff. A *human* flips the
`#if 0`. There is no path from the learner to a source-file write; a unit test
asserts this (no filesystem/codegen API reachable from the learner TU).

**Bounds.** Proposals require accumulated evidence (≥ a threshold of correlated
observations), are decay-gated like the action-gate learner, and target only a
small allow-list of tunable config symbols (not arbitrary constants).

---

## Testing

- **Phase A:** host/unit test feeding synthetic not-implemented returns →
  asserts one deduped `InferredGap` record with correct repeat and resolved
  pin; asserts a `PermissionDenied` return records nothing. Boot self-test: a
  known-unimplemented syscall produces exactly one record.
- **Phase C:** `gap-scan.py` unit test over a fixture source tree (known gaps →
  expected manifest); asserts annotated sites are excluded.
- **Phase B:** learner unit test that a synthetic exhaustion pattern yields one
  bounded, evidence-backed proposal; a structural test that no codegen/FS API
  is linkable from the learner TU (DD#016 enforcement).
- **End-to-end:** stress boot → `KERNEL.FIX` contains `InferredGap` records →
  `gen-fix-patches.py` emits the new patch classes → every emitted patch passes
  `git apply --check`.

## Sequencing

**A → C → B.** A is highest-value and self-contained (proves the discovery
loop with one enum + one choke-point). C is a cheap static layer that enriches
A's output. B is the ambitious learner extension and is gated on A+C producing
the signal it ranks. Each phase is its own slice with its own
build/format/boot-smoke verification and wiki/Design-Decisions updates.

## Out of scope

- Auto-applying any generated patch (DD#016 — human flips every gate).
- The learner proposing arbitrary code (only allow-listed config symbols).
- Replacing hand-placed markers (they remain valid; discovery is additive).
