# Dynamic Fix-Discovery Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement task-by-task. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Discover fix-worthy sites without hand-placed `// GAP:` markers — from live runtime behavior (A), static structure (C), and the autonomic learner (B) — feeding the existing FixJournal → gen-fix-patches pipeline.

**Architecture:** One new `FixDetector::InferredGap` recorded at the `SyscallDispatch` return choke-point when a guest gets `kStatusNotImplemented` (A); a `gap-scan.py` static scanner emitting un-annotated candidates joined with A's hits (C); a learner extension emitting bounded evidence-backed config proposals as `AutonomicProposal` data (B). DD#016: data in, `#if 0` patches out, human flips the gate.

**Tech Stack:** C++23 kernel, Python 3 generator tooling, hosted unit tests (tests/host), QEMU boot smoke.

**Spec:** `docs/superpowers/specs/2026-06-11-dynamic-fix-discovery-design.md`

---

## Phase A — Runtime gap inference (kernel)

### Task A1: Add `FixDetector::InferredGap`

**Files:**
- Modify: `kernel/diag/fix_journal.h` (enum `FixDetector`, after `AutonomicProposal = 11`)
- Modify: `tools/build/gen-fix-patches.py` (`DETECTORS` map + an `inferred_gap` branch)

- [ ] **Step 1:** Add enum value `InferredGap = 12,` with a doc comment: "A recognized syscall whose handler returned kStatusNotImplemented to a guest. Distinct from UnknownSyscall (unknown number) — this is a known number whose behavior is unimplemented. source_pin = `syscall:0xNN`, ctx_a = syscall number. Dedups per number → repeat=N."
- [ ] **Step 2:** In `gen-fix-patches.py` `DETECTORS` dict add `12: "inferred_gap"`; in the classify chain add an `elif r.detector_name == "inferred_gap":` branch producing a NOTE (not auto-patch) shaped like the gap-marker note but tagged "discovered at runtime (no source marker)".
- [ ] **Step 3:** Commit: `fix-journal: add InferredGap detector for runtime-discovered unimplemented syscalls`

### Task A2: Record InferredGap at the dispatch choke-point (host test first)

**Files:**
- Test: `tests/host/test_inferred_gap.cpp` (new)
- Modify: `tests/host/CMakeLists.txt` (register the test)
- Create: `kernel/syscall/inferred_gap.h` + `inferred_gap.cpp` (small, testable: the decision + record)
- Modify: `kernel/syscall/syscall.cpp` (call it once at the dispatch return)
- Modify: `tests/fuzz/host_shim/diag/fix_journal.h` if the shim lacks `FixJournalRecord` (mirror per the mm-idiom-audit lesson)

The recordable unit is pure and testable: given `(rax_value, syscall_number)`, decide whether to record and with what pin. Put it in a freestanding header so the host test links it without the kernel.

- [ ] **Step 1: Write the failing test** `tests/host/test_inferred_gap.cpp`:

```cpp
// Verifies InferredGapShouldRecord: kStatusNotImplemented -> record keyed by
// syscall number; any other rax (success, PermissionDenied, NotFound) -> no record.
#include "syscall/inferred_gap_decide.h"
#include <cassert>
#include <cstdio>
using duetos::syscall::InferredGapShouldRecord;
int main()
{
    constexpr unsigned long long kNotImpl = 0xC0000002ULL;
    // not-implemented sentinel -> record
    assert(InferredGapShouldRecord(kNotImpl) == true);
    // success (0) -> no record
    assert(InferredGapShouldRecord(0) == false);
    // a correct error (STATUS_ACCESS_DENIED 0xC0000022) -> no record
    assert(InferredGapShouldRecord(0xC0000022ULL) == false);
    // NotFound (0xC0000034) -> no record
    assert(InferredGapShouldRecord(0xC0000034ULL) == false);
    std::printf("[inferred-gap-host] PASS\n");
    return 0;
}
```

- [ ] **Step 2: Run to verify it fails** (header missing). Build via the Windows-native g++ host-test path (see memory `windows-native-host-tests`) or WSL. Expected: compile error "no such file inferred_gap_decide.h".

- [ ] **Step 3: Create the decision header** `kernel/syscall/inferred_gap_decide.h`:

```cpp
#pragma once
namespace duetos::syscall
{
// The native "recognized but unimplemented" sentinel (STATUS_NOT_IMPLEMENTED).
// Must equal kStatusNotImplemented in syscall.cpp.
inline constexpr unsigned long long kInferredGapSentinel = 0xC0000002ULL;

// True iff a guest received the not-implemented sentinel for a recognized
// syscall — the one case worth recording as a discovered gap. A success or a
// *correct* error (PermissionDenied, NotFound, InvalidArgument) is not a gap.
constexpr bool InferredGapShouldRecord(unsigned long long rax_value)
{
    return rax_value == kInferredGapSentinel;
}
} // namespace duetos::syscall
```

- [ ] **Step 4: Run test to verify it passes.** Expected: `[inferred-gap-host] PASS`.

- [ ] **Step 5: Wire the recorder into the kernel.** Create `kernel/syscall/inferred_gap.cpp` (+ `.h` declaring `void InferredGapMaybeRecord(u64 rax_value, u64 syscall_number);`). Implementation:

```cpp
#include "syscall/inferred_gap.h"
#include "syscall/inferred_gap_decide.h"
#include "diag/fix_journal.h"
namespace duetos::syscall
{
// Per-boot cap on DISTINCT inferred-gap syscall pins so a pathological build
// can't exhaust the ring; over-cap drops are counted by the journal stats.
inline constexpr u32 kInferredGapPinCap = 128;

void InferredGapMaybeRecord(u64 rax_value, u64 syscall_number)
{
    if (!InferredGapShouldRecord(rax_value))
        return;
    // pin = "syscall:0x<num>" — dedups per number; a storm becomes repeat=N.
    char pin[24] = "syscall:0x";
    u64 v = syscall_number;
    char* p = pin + 10;
    // hex, max 4 nibbles for a syscall number
    int started = 0;
    for (int shift = 12; shift >= 0; shift -= 4)
    {
        u32 nib = (v >> shift) & 0xF;
        if (nib != 0 || started || shift == 0)
        {
            *p++ = (nib < 10) ? char('0' + nib) : char('a' + nib - 10);
            started = 1;
        }
    }
    *p = '\0';
    (void)::duetos::diag::FixJournalRecord(::duetos::diag::FixDetector::InferredGap, pin,
                                           "recognized syscall returned NotImplemented — implement or remove the op",
                                           syscall_number, 0);
}
} // namespace duetos::syscall
```

- [ ] **Step 6: Call it once at the dispatch return.** In `kernel/syscall/syscall.cpp`, at the single point after the dispatch switch where `frame->rax` is final and before `SyscallDispatch` returns, add: `duetos::syscall::InferredGapMaybeRecord(frame->rax, num);` (guard: only on the normal dispatch tail, NOT the early cap-deny return). Confirm there is one tail; if dispatch returns from many points, record inside the `default`-arm sites that set `kStatusNotImplemented` instead (key by `num`).

- [ ] **Step 7: Build kernel + boot smoke.** Per wsl-build skill. Expected: clean build; a boot exercising a not-implemented syscall yields exactly one `InferredGap` record in KERNEL.FIX (verify with `gen-fix-report.py`).

- [ ] **Step 8: Commit:** `syscall: record InferredGap when a guest hits an unimplemented recognized syscall`

---

## Phase C — Static gap discovery (build-time tool)

### Task C1: `tools/build/gap-scan.py`

**Files:**
- Create: `tools/build/gap-scan.py`
- Create: `tools/build/test_gap_scan.py` (pytest, runs hosted — no kernel build)
- Modify: `tools/build/gen-fix-patches.py` (accept `--gap-candidates gap-candidates.json`, correlate)

- [ ] **Step 1: Write the failing test** `tools/build/test_gap_scan.py`:

```python
# Fixture tree with one annotated gap (excluded) and one un-annotated
# not-implemented return (included). Asserts the scanner reports only the
# un-annotated one.
import json, subprocess, sys, tempfile, os, textwrap
def test_scan_reports_only_unannotated(tmp_path):
    f = tmp_path / "k.cpp"
    f.write_text(textwrap.dedent('''
        void a() { /* GAP: known */ return; }            // annotated -> excluded
        long b() { return kStatusNotImplemented; }        // un-annotated -> included
    '''))
    out = tmp_path / "cand.json"
    subprocess.check_call([sys.executable, "tools/build/gap-scan.py",
                           "--root", str(tmp_path), "--out", str(out)])
    cands = json.loads(out.read_text())
    pins = {c["function"] for c in cands}
    assert "b" in pins
    assert "a" not in pins
```

- [ ] **Step 2: Run, verify it fails** (`gap-scan.py` missing). `pytest tools/build/test_gap_scan.py -v`.
- [ ] **Step 3: Implement `gap-scan.py`** — walk `*.cpp/*.c/*.h` under `--root` (default kernel/ drivers/ subsystems/), regex for `kStatusNotImplemented`, `Err{ErrorCode::NotImplemented}`, `-ENOSYS`, not-impl `default:` arms, `// TODO`/`// FIXME`; record `{file, line, function, pattern_kind, guest_reachable_guess}`. Exclude a line whose enclosing function/nearby lines already carry `// GAP:`/`// STUB:`/`FIX_NOTE_`. Emit JSON to `--out`.
- [ ] **Step 4: Run, verify pass.**
- [ ] **Step 5: Correlate in `gen-fix-patches.py`** — add `--gap-candidates`; for each candidate, mark `confirmed_live` if an `InferredGap` record shares the syscall/file pin, else `cold`. Confirmed-live candidates render a high-priority note; cold ones a low-priority note.
- [ ] **Step 6: Commit:** `tools/build: gap-scan.py static gap discovery + gen-fix-patches correlation`

---

## Phase B — Learner-driven ranking + config proposals

### Task B1: Bounded config-proposal emission (data only)

**Files:**
- Create: `kernel/env/config_proposal.h` + `config_proposal.cpp` (the allow-list + the emit-as-data function)
- Test: `tests/host/test_config_proposal.cpp`
- Modify: `kernel/env/autonomic.cpp` (call the emitter when evidence threshold crossed)
- Modify: `tools/build/gen-fix-patches.py` (render `AutonomicProposal` config records → `#if 0` constant patch)

- [ ] **Step 1: Write the failing test** `tests/host/test_config_proposal.cpp`:

```cpp
// A config proposal is emitted only after evidence >= threshold, only for an
// allow-listed symbol, and carries {current, proposed, evidence_count}.
#include "env/config_proposal_decide.h"
#include <cassert>
#include <cstdio>
using namespace duetos::env;
int main()
{
    // below threshold -> no proposal
    assert(ConfigProposalDecide(ConfigKnob::VkHostMemCap, /*observed_exhaustions=*/2).emit == false);
    // at/above threshold -> proposal with a bounded raise
    auto d = ConfigProposalDecide(ConfigKnob::VkHostMemCap, 8);
    assert(d.emit == true);
    assert(d.proposed_value > d.current_value);
    assert(d.proposed_value <= d.current_value * 2); // bounded: never more than 2x
    std::printf("[config-proposal-host] PASS\n");
    return 0;
}
```

- [ ] **Step 2: Run, verify it fails.**
- [ ] **Step 3: Implement `kernel/env/config_proposal_decide.h`** — `enum class ConfigKnob` (small allow-list), `struct ConfigProposalDecision { bool emit; u64 current_value; u64 proposed_value; u32 evidence_count; }`, `constexpr ConfigProposalDecision ConfigProposalDecide(ConfigKnob, u32 observed)` with `kEvidenceThreshold = 4` and a bounded raise (`min(current*2, current + step)`). Current values come from a `constexpr` table keyed by knob.
- [ ] **Step 4: Run, verify pass.**
- [ ] **Step 5: Emit as data** — `config_proposal.cpp` `EmitConfigProposal(ConfigKnob, observed)` calls `FixJournalRecord(AutonomicProposal, "config:<knob>", "<current>-><proposed> (evidence=N)", current, proposed)`. NO source write. Add a structural assertion (test) that no FS/codegen header is included by the TU.
- [ ] **Step 6: Wire into `autonomic.cpp`** — where the learner accumulates evidence (e.g. an exhaustion counter), call `EmitConfigProposal` once per knob per boot when threshold crosses. Gate behind the existing autonomic master-off + shield.
- [ ] **Step 7: Render in `gen-fix-patches.py`** — an `AutonomicProposal` record whose pin starts `config:` produces an `#if 0`-gated patch changing the named constant from current→proposed, with the evidence in the patch comment.
- [ ] **Step 8: Build + boot smoke + commit:** `env: learner emits bounded config proposals as data (DD#016); gen-fix-patches renders them`

---

## Cross-cutting closeout

- [ ] Update `wiki/` (fix-journal / autonomic pages) — new InferredGap detector, gap-scan tool, config-proposal kind.
- [ ] Append `wiki/reference/Design-Decisions.md` — dynamic discovery is additive to markers; DD#016 boundary reaffirmed for config proposals.
- [ ] Re-scan all signals (build, host ctest, clang-format, boot-log-analyze) per Definition-of-Done.

## Self-review notes

- Spec coverage: A (Task A1–A2), C (Task C1), B (Task B1), cross-cutting closeout — all spec sections mapped.
- Sentinel reality: native path uses `kStatusNotImplemented=0xC0000002`; `ErrorCode::NotImplemented` does NOT exist in result.h — plan targets the real sentinel. Linux `-ENOSYS` choke-point is a documented follow-on, not v1.
- Host-test linkage: decision logic is split into freestanding `*_decide.h` headers so hosted tests link without the kernel (matches `win32-surface-smokes-bare-metal-only` lesson).
