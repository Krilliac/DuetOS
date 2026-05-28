# Idiom Audit — Phase 1, Wave 1, PR #1 (kernel/util) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Sweep `kernel/util/` for the six Phase-1 idiom patterns (naked `new`/`delete`, sentinel returns, raw owning ptrs, `m_` prefix, `[[nodiscard]]` on `Result`-returning functions, API-contract `const`), fix every latent error-handling bug and every preexisting boot failure/crash the audit surfaces, and merge as **PR #1 of Wave 1**.

**Architecture:** Subsystem-by-subsystem leverage-ordered sweep per spec §5. `kernel/util/` runs first because its headers (`Result<T,E>`, `types.h`, `debug_assert.h`, `defer.h`, `string.h`, `nospec.h`, `compiler.h`) are consumed everywhere — its modernization unblocks every downstream subsystem. Each pattern is one or more commits within the PR; surfaced bugs are separate `fix(util): ...` commits; the spec §7.4 verification gate (build, format, ctest, 3× boot smoke, STUB/GAP discipline, subsystem-isolation audit) must be clean before merge. The `Result<T, E>` primitive itself (`kernel/util/result.h`, `result.cpp`) is **out of scope** per spec §4 — only its callers in other util TUs get migrated.

**Tech Stack:** C++23 (no exceptions, no RTTI, `-Werror`), Clang 18+ / GCC 13+, CMake 3.25+, NASM (untouched), kernel allocators (`UniquePtr<T>::Make`, `kheap::Alloc`, `slab::Alloc<T>`, `Page::Allocate`). No Rust changes in this PR; `kernel/util/img_meta_rust/` and `kernel/util/vt_parser_rust/` are skipped.

**Spec:** `docs/superpowers/specs/2026-05-27-idiom-audit-phase1-pattern-sweep-design.md` (read first, especially §6 playbook and §7 PR contract).

**Branch:** `claude/idiom-audit-phase1-util` (created off `origin/main` at Task 1 Step 1).

---

## File Structure

### Likely modified (audit confirms which; not all need touching)
- `kernel/util/result.h` — **NO content changes** (out of scope per spec §4); may only be re-read to confirm `[[nodiscard]]` is on the class.
- `kernel/util/result.cpp` — `[[nodiscard]]` on `ResultSelfTest()` if needed; sentinel-return audit; m_ prefix; const review.
- `kernel/util/result_check.h` — `[[nodiscard]]` and const review.
- `kernel/util/types.h` — m_ prefix on any class members (mostly POD; light touch).
- `kernel/util/debug_assert.h` — review only; macros, no class state.
- `kernel/util/defer.h` — `[[nodiscard]]` and const on the defer guard's accessors.
- `kernel/util/build_config.h` — review only.
- `kernel/util/cache.h` — `m_` prefix; const on accessors.
- `kernel/util/compiler.h` — review only.
- `kernel/util/nospec.h` — review only.
- `kernel/util/string.{h,cpp}` — sentinel returns (most likely candidates); naked new (unlikely); m_ prefix in any helper classes.
- `kernel/util/symbols.{h,cpp}` + `kernel/util/symbols_stub.cpp` — sentinel returns (lookup misses); raw owning ptrs for symbol tables (likely non-owning); m_ prefix on the symbol-table class.
- `kernel/util/random.{h,cpp}` — sentinel returns on entropy-low; m_ prefix.
- `kernel/util/saturating.{h,cpp}` — review only; arithmetic helpers.
- `kernel/util/datetime.{h,cpp}` — sentinel returns; m_ prefix on the date/time struct (likely POD — may stay).
- `kernel/util/unicode.{h,cpp}` — sentinel returns on invalid codepoint; m_ prefix.
- `kernel/util/vt_parser.{h,cpp}` — sentinel returns on parse errors; m_ prefix on parser state. **Note**: `vt_parser_rust/` is the Rust crate; the C++ vt_parser may be the legacy fallback or a wrapper — confirm at Task 2.
- `kernel/util/adler32.{h,cpp}`, `crc32.{h,cpp}`, `base64.{h,cpp}` — sentinel returns on bad input; minimal class state.
- `kernel/util/bmp.{h,cpp}`, `jpeg.{h,cpp}`, `png.{h,cpp}`, `tga.{h,cpp}` — image decoders; sentinel returns + raw owning ptrs for decode buffers + m_ prefix on decoder-state classes. `jpeg.cpp` is the largest (996 lines).
- `kernel/util/gzip.{h,cpp}`, `deflate.{h,cpp}`, `zip.{h,cpp}` — compression; sentinel returns + buffer ownership + m_ prefix.
- `kernel/util/soft_float.{h,cpp}` — software-float; minimal sentinel surface; check for m_ on the soft-float context.
- `kernel/util/soft_float_selftest.cpp` — test code; usually following its own style.

### Skipped (out of scope)
- `kernel/util/string_erms.S` — ASM (per spec §4).
- `kernel/util/img_meta_rust/`, `kernel/util/vt_parser_rust/` — Rust crates (per spec §4).

### Hosted tests touched (only if surfaced bugs need regression coverage)
- `tests/host/test_util_*.cpp` — one new test file per surfaced bug, naming convention `test_util_<symptom>.cpp`. Most steps below assume zero surfaced bugs; the per-bug sub-tasks are spelled out in their own steps.

### Self-test sentinel (per spec §10)
- `kernel/util/result.cpp` — `ResultSelfTest()` already exists; modify to emit the wave-1 sentinel line `[idiom-audit-selftest] PASS (wave-1)` at the end of its existing PASS path. **One-line addition** via `arch::SerialWrite`.
- `tools/test/boot-log-analyze.sh` — add a grep for the new sentinel line in the existing self-test umbrella section.

---

## Task 1: Pre-flight — branch, baseline gate, audit-tools

**Files:** No code changes yet.

- [ ] **Step 1: Create the branch off a fresh `origin/main`**

Run:
```bash
git status --short
git fetch origin main
git checkout -b claude/idiom-audit-phase1-util origin/main
git log --oneline -3
```
Expected: working tree clean (the `?? tools/test/passd-*.sh` untracked files from prior work are fine to ignore), branch created off `origin/main`, last 3 commits show recent main HEAD.

- [ ] **Step 2: Verify the runtime toolbox per CLAUDE.md is installed**

Run:
```bash
which qemu-system-x86_64 grub-mkrescue xorriso mtools clang-format gdb && \
  ls -la /usr/share/ovmf 2>/dev/null | head -3
```
Expected: all binaries resolve to a path; OVMF directory exists. If any fail, install the full toolbox per CLAUDE.md "Live-test runtime tooling — install on demand" before continuing.

- [ ] **Step 3: Configure the release build preset**

Run:
```bash
cmake --preset x86_64-release 2>&1 | tail -10
```
Expected: "Configuring done" + "Generating done" on the final two lines, zero error lines.

- [ ] **Step 4: Baseline build (must succeed before any sweep work)**

Run:
```bash
cmake --build build/x86_64-release --parallel $(nproc) 2>&1 | tail -30
```
Expected: build completes; final line is the kernel link or last `[100%]` target; **zero** `warning:` lines (`-Werror` is on, so any warning is a build failure).

- [ ] **Step 5: Baseline hosted ctest (must be green per spec §6.7 baseline rule)**

Run:
```bash
(cd build/x86_64-release && ctest --output-on-failure 2>&1 | tail -25)
```
Expected: "100% tests passed". If any test fails, that's a preexisting baseline failure. Per spec §6.7's baseline rule, fix it with a `fix(<area>): ...` commit on **this branch** BEFORE starting the pattern sweep. Commit message: `fix(<area>): <one-line symptom>` with Co-Authored-By trailer.

- [ ] **Step 6: Baseline boot smoke (3 runs per spec §7.4 item 4)**

Run:
```bash
for i in 1 2 3; do
  DUETOS_TIMEOUT=20 tools/qemu/run.sh build/x86_64-release/duetos.iso \
    > /tmp/util-baseline.$i.log 2>&1
  tools/test/boot-log-analyze.sh /tmp/util-baseline.$i.log \
    && echo "RUN $i: PASS" \
    || { echo "RUN $i: FAIL"; tail -40 /tmp/util-baseline.$i.log; }
done
```
Expected: 3× "PASS". If any run fails, that's a preexisting boot failure. Per spec §6.7, fix it on this branch first; per §8 R1 it's exempt from the surfaced-bug cap.

- [ ] **Step 7: Capture the baseline state for later comparison**

Run:
```bash
mkdir -p /tmp/util-audit
git rev-parse HEAD > /tmp/util-audit/baseline-sha.txt
cmake --build build/x86_64-release --target kernel_elf 2>&1 \
  | grep -E "warning|error" > /tmp/util-audit/baseline-build.txt || true
wc -l kernel/util/*.cpp kernel/util/*.h 2>/dev/null \
  | sort -rn > /tmp/util-audit/baseline-linecounts.txt
```
Expected: three files in `/tmp/util-audit/` capturing the baseline SHA, any build warnings (should be empty), and per-file line counts.

---

## Task 1.5: Preamble — clean preexisting baseline warnings

> **Added 2026-05-27 after Phase-3 baseline gate finding.** Task 1's baseline build surfaced **48 preexisting warnings** in non-`util` code. CLAUDE.md states "Zero warnings: `-Wall -Wextra -Wpedantic -Werror`" but the toolchain at HEAD `670c6090` has only `-Wall -Wextra -Wpedantic` (no `-Werror`), so the warnings don't gate the build. Per the user's call (and consistent with spec §6.7's no-deferring rule + CLAUDE.md's "fix anything you surface" rule), these are fixed as **preamble commits on the same `claude/idiom-audit-phase1-util` branch** — the util PR includes them.

**Files (from Phase-3 finding):**
- `kernel/apps/{clock,about,devicemgr,help,notify_center,firewall,netstatus}.cpp`
- `kernel/arch/x86_64/{cet,smp}.cpp`
- `kernel/cpu/{ipi_call,percpu}.cpp`
- `kernel/net/tls.cpp`
- `kernel/subsystems/graphics/graphics_vk_selftest.cpp`

**Warning categories:**
- 22× `-Wunused-const-variable` — remove unused or `[[maybe_unused]]`.
- 12× `-Wshadow` — rename the inner variable.
- 8× `-Wmissing-field-initializers` — add explicit `{}` initializers.
- 2× `-Wunused-variable` — delete or `[[maybe_unused]]`.
- 2× `-Wunused-function` — delete or `[[maybe_unused]]`.
- 2× `-Wunused-but-set-variable` — delete assignment or use the value.

- [ ] **Step 1: Capture the exact baseline warning list** so we can verify completeness:

```bash
wsl bash -c 'cd ~/source/DuetOS && grep -E "warning:" /tmp/util-baseline-build.log | sort -u > /tmp/util-audit/baseline-warnings.txt && wc -l /tmp/util-audit/baseline-warnings.txt && head -10 /tmp/util-audit/baseline-warnings.txt'
```
Expected: file count ~48 (some warnings may be duplicates from re-included headers; the sort -u dedupes).

- [ ] **Step 2: Apply fixes per category**

For each warning in the list, apply the appropriate mechanical fix:

- **`unused-const-variable`** — if the constant is genuinely never referenced, delete it; if it's a deliberate-for-future or self-documenting placeholder, add `[[maybe_unused]]` before the declaration.
- **`shadow`** — rename the inner variable. Pick a name that disambiguates from the shadowed outer (e.g., outer `auto x = ...; for (auto x : ...)` → rename inner to `xi` or domain-specific).
- **`missing-field-initializers`** — add explicit `{}` for each missing field, or use `{.field = ...}` designated initializers if the struct supports them.
- **`unused-variable` / `unused-function`** — delete (preferred per anti-bloat) or `[[maybe_unused]]` if a callable that's documented for external use.
- **`unused-but-set-variable`** — delete the dead assignment; if the value IS being computed deliberately for a side-effect, either restructure to avoid the unused result or assign to `[[maybe_unused]]`.

**Skip rules:**
- Do NOT touch warnings in `third_party/` or generated code.
- Do NOT touch `kernel/util/*` warnings in this Task — those (if any) get caught by Task 6 (m_ prefix) and Task 8 (const). Task 1.5 is non-util-only.
- Do NOT introduce new TODO/FIXME markers for "fix this properly later" — the fix lands here.

- [ ] **Step 3: Rebuild and verify warning count drops to 0**

```bash
wsl bash -c 'cd ~/source/DuetOS && cmake --build build/x86_64-release --parallel $(nproc) 2>&1 | tee /tmp/util-after-warnings-build.log | tail -30 && echo "---" && grep -cE "warning:|error:" /tmp/util-after-warnings-build.log'
```
Expected: final grep count is `0`. If non-zero, identify the residual warning(s) and re-apply Step 2.

- [ ] **Step 4: Run ctest and 1× boot smoke to confirm fixes don't regress runtime**

```bash
wsl bash -c 'cd ~/source/DuetOS/build/x86_64-release && ctest --output-on-failure 2>&1 | tail -10'
wsl bash -c 'cd ~/source/DuetOS && DUETOS_TIMEOUT=20 tools/qemu/run.sh build/x86_64-release/duetos.iso > /tmp/util-after-warnings-smoke.log 2>&1 && tools/test/boot-log-analyze.sh /tmp/util-after-warnings-smoke.log && echo PASS || echo FAIL'
```
Expected: ctest 100%, boot smoke PASS.

- [ ] **Step 5: Commit as a single preamble commit**

```bash
git add kernel/apps/ kernel/arch/x86_64/ kernel/cpu/ kernel/net/ kernel/subsystems/graphics/
git commit -m "$(cat <<'EOF'
fix(toolchain): clear 48 preexisting baseline warnings

Cleans warnings present at HEAD 670c6090 ahead of the kernel/util
Phase-1 idiom sweep. Categories:
- 22x -Wunused-const-variable
- 12x -Wshadow
-  8x -Wmissing-field-initializers
-  2x -Wunused-variable
-  2x -Wunused-function
-  2x -Wunused-but-set-variable

Files touched: kernel/apps/{clock,about,devicemgr,help,notify_center,
firewall,netstatus}.cpp, kernel/arch/x86_64/{cet,smp}.cpp, kernel/cpu/
{ipi_call,percpu}.cpp, kernel/net/tls.cpp, kernel/subsystems/graphics/
graphics_vk_selftest.cpp.

Per spec §6.7's no-deferring rule and CLAUDE.md's "fix anything you
surface" doctrine. Lands as preamble on the util branch before any
util pattern-sweep commits so the util PR ships a tree with the
"Zero warnings" doctrine actually upheld.

Note: -Werror is still not on. Whether to flip it on is a separate
decision out-of-scope here (would convert any future warning into a
build failure — a defensive measure but disruptive to add now).

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

- [ ] **Step 6: Re-capture baseline state with new SHA**

```bash
wsl bash -c 'cd ~/source/DuetOS && git rev-parse HEAD > /tmp/util-audit/baseline-sha.txt && cat /tmp/util-audit/baseline-sha.txt'
```
The SHA recorded for the rest of the plan is now this new HEAD (the post-warning-cleanup commit), not the original `670c6090`.

---

## Task 2: Audit phase — grep + classify per pattern

The audit produces six worklists (one per Phase-1 pattern) covering every site in `kernel/util/` C++ TUs. Worklists live in `/tmp/util-audit/` (not committed); the subsequent pattern-sweep Tasks read them.

**Files:** No code changes yet; only scratch worklists.

- [ ] **Step 1: Audit Pattern 1 — naked `new` / `delete`**

Run:
```bash
grep -nHE '\bnew\s+[A-Za-z_]' kernel/util/*.cpp kernel/util/*.h 2>/dev/null \
  | grep -v 'placement.*new\|new (.*)' \
  > /tmp/util-audit/p1-naked-new.txt
grep -nHE '\bdelete\s+[A-Za-z_]|\bdelete\[\]' kernel/util/*.cpp kernel/util/*.h 2>/dev/null \
  > /tmp/util-audit/p1-naked-delete.txt
wc -l /tmp/util-audit/p1-*.txt
```
Expected: two files; line counts give the site count per file. Each line is `file:line:source`. Per spec §6.1, skip placement new and arch-bringup allocations (none expected in `util/`).

- [ ] **Step 2: Audit Pattern 2 — sentinel returns**

Run:
```bash
grep -nHE '\breturn\s+-1\s*;|\breturn\s+false\s*;|\breturn\s+nullptr\s*;|\breturn\s+NULL\s*;' \
  kernel/util/*.cpp kernel/util/*.h 2>/dev/null \
  > /tmp/util-audit/p2-sentinels.txt
wc -l /tmp/util-audit/p2-sentinels.txt
```
Expected: one file. **This is the largest pattern by site count**; per spec §6.2 skip rules, many sites are legitimate (genuine `bool` predicates, `find()`-style nullable returns). Classification happens at Step 7.

- [ ] **Step 3: Audit Pattern 3 — raw owning pointer candidates**

Run:
```bash
grep -nHE '^\s*(class|struct).*\{|[A-Za-z_]+\s*\*\s*[a-z_][A-Za-z0-9_]*\s*[=;]' \
  kernel/util/*.h kernel/util/*.cpp 2>/dev/null \
  | grep -vE '//|const\s+char\s*\*|^\s*\*|extern' \
  > /tmp/util-audit/p3-raw-ptr-candidates.txt
wc -l /tmp/util-audit/p3-raw-ptr-candidates.txt
```
Expected: one file. The grep is noisy — most hits are non-owning observer pointers. Classification at Step 7 separates owning from non-owning.

- [ ] **Step 4: Audit Pattern 4 — `m_` prefix gaps**

Run:
```bash
grep -nHE '^\s*(class|struct)\s+[A-Z][A-Za-z0-9_]*' kernel/util/*.h kernel/util/*.cpp 2>/dev/null \
  > /tmp/util-audit/p4-class-decls.txt
grep -nHE '^\s+[a-z_][A-Za-z0-9_]*\s+[a-z_][A-Za-z0-9_]*\s*[=;{]' \
  kernel/util/*.h kernel/util/*.cpp 2>/dev/null \
  | grep -vE 'return |if |for |while |^\s*//' \
  > /tmp/util-audit/p4-member-candidates.txt
wc -l /tmp/util-audit/p4-*.txt
```
Expected: two files. POD record structs are skipped per spec §6.4; classification identifies which class declarations have private members or methods (m_ applies) vs pure record structs (m_ doesn't).

- [ ] **Step 5: Audit Pattern 5 — `[[nodiscard]]` gaps**

Run:
```bash
grep -nHE '\bResult\s*<' kernel/util/*.h kernel/util/*.cpp 2>/dev/null \
  | grep -v '\[\[nodiscard\]\]' \
  | grep -vE '^\s*//|\sclass\s+Result|\sstruct\s+Result|template\s*<' \
  > /tmp/util-audit/p5-result-returners.txt
wc -l /tmp/util-audit/p5-result-returners.txt
```
Expected: one file. Each line is a candidate `Result<...>`-returning function declaration. The `Result` class itself already has `[[nodiscard]]` (see `kernel/util/result.h:180`), so this catches function-declaration-level gaps where the diagnostic comes from the function annotation rather than the type.

- [ ] **Step 6: Audit Pattern 6 — `const` on cross-subsystem API methods**

Run:
```bash
grep -nHE '^\s*[A-Za-z_][A-Za-z0-9_:]*\s+[A-Za-z_][A-Za-z0-9_]*\s*\(' \
  kernel/util/*.h 2>/dev/null \
  | grep -vE 'const\s*[;{]|\sconst\s*$|^\s*//' \
  > /tmp/util-audit/p6-method-candidates.txt
wc -l /tmp/util-audit/p6-method-candidates.txt
```
Expected: one file. Most hits are mutating methods (free functions don't get const). Classification: which methods don't modify any non-`mutable` member and are visible to other subsystems? Those get `const`.

- [ ] **Step 7: Classify each site**

For each worklist, open the file and annotate each row with one of:
- `CONVERT` — apply the pattern's mechanical rule.
- `SKIP:<rule>` — matches a §6.N skip-rule; record which rule (e.g., `SKIP:placement-new`, `SKIP:legitimate-bool-predicate`, `SKIP:non-owning-observer`, `SKIP:POD-record-struct`, `SKIP:in-TU-helper-deferred-to-track-4`).
- `BUG-CANDIDATE` — the site looks like a latent bug (caller ignored sentinel, mismatched delete, etc.). Will be re-investigated at the pattern's sweep Task; if confirmed a bug, gets a `fix(util): ...` commit per spec §6.7.

The annotation lives in the worklist file itself, one line per row.

Expected: every row in every worklist annotated. Counts of `CONVERT` per pattern recorded for the PR description's "Pattern coverage table" (spec §7.2 item 2).

- [ ] **Step 8: Record the audit summary**

Run:
```bash
{
  echo "kernel/util Phase-1 audit summary"
  echo "Baseline SHA: $(cat /tmp/util-audit/baseline-sha.txt)"
  for p in p1-naked-new p1-naked-delete p2-sentinels p3-raw-ptr-candidates \
           p4-class-decls p4-member-candidates p5-result-returners \
           p6-method-candidates; do
    total=$(wc -l < /tmp/util-audit/$p.txt)
    convert=$(grep -c '^CONVERT' /tmp/util-audit/$p.txt 2>/dev/null || echo 0)
    skip=$(grep -c '^SKIP' /tmp/util-audit/$p.txt 2>/dev/null || echo 0)
    bug=$(grep -c '^BUG-CANDIDATE' /tmp/util-audit/$p.txt 2>/dev/null || echo 0)
    echo "$p: total=$total convert=$convert skip=$skip bug-candidates=$bug"
  done
} > /tmp/util-audit/SUMMARY.txt
cat /tmp/util-audit/SUMMARY.txt
```
Expected: the SUMMARY.txt shows per-pattern counts. These numbers populate the PR description's "Pattern coverage table" at Task 11.

- [ ] **Step 9: Sanity-check the bug-candidate count against the cap**

Run:
```bash
total_bugs=$(grep -h '^BUG-CANDIDATE' /tmp/util-audit/*.txt | wc -l)
echo "Bug candidates so far: $total_bugs (cap is ≤8 ordinary; preexisting boot failures exempt)"
```
Expected: if `total_bugs > 8`, the cap may be hit (per spec §8 R1). Decision: proceed with the sweep; if the actual confirmed-bug count exceeds 8 during the sweep, split the PR as described in spec §8 R1. **Boot-failure bugs are NOT counted toward the cap.** Do not abandon the sweep at this step — the count is a heads-up, not a stop signal.

---

## Task 3: Pattern 1 sweep — naked `new` / `delete` → allocators

**Files:** modify the files in `/tmp/util-audit/p1-naked-new.txt` and `p1-naked-delete.txt` that have `CONVERT` rows.

- [ ] **Step 1: Re-read the worklist**

Run:
```bash
grep '^CONVERT' /tmp/util-audit/p1-naked-new.txt /tmp/util-audit/p1-naked-delete.txt
```
Expected: each row prefixed `CONVERT`. If empty, skip to Step 6 — no pattern-1 work in `util/`.

- [ ] **Step 2: Apply migrations per spec §6.1 mechanical rule**

For each `CONVERT` row, edit the source file. Choose the allocator by use-case:

| Site shape | Allocator |
|------------|-----------|
| Single-instance, owner-scoped lifetime | `UniquePtr<T>::Make(...)` |
| High-churn small type with a dedicated slab class | `slab::Alloc<T>()` |
| Raw byte buffer | `kheap::Alloc(size)` |
| Page-aligned / DMA buffer | `Page::Allocate(count)` |

Example migration:
```cpp
// Before
auto* p = new ParserState();
// ... uses p ...
delete p;

// After
auto p = UniquePtr<ParserState>::Make();
// ... uses p.get() or p->... ; no manual delete
```

Add `#include "mm/unique_ptr.h"` (or whichever owns `UniquePtr`) at the top of any modified `.cpp` if not already present.

- [ ] **Step 3: Format + build after the pattern sweep**

Run:
```bash
find kernel/util \( -name '*.h' -o -name '*.cpp' \) | xargs clang-format -i
cmake --build build/x86_64-release --parallel $(nproc) 2>&1 | tail -20
```
Expected: zero warnings, zero errors. If build fails, the most likely cause is a missing `#include` or a non-owning-pointer mistakenly converted. Re-classify and re-apply.

- [ ] **Step 4: Hosted ctest after the pattern sweep**

Run:
```bash
(cd build/x86_64-release && ctest --output-on-failure 2>&1 | tail -10)
```
Expected: all tests still pass. If a util self-test fails, that's a surfaced bug — branch to the bug-fix sub-flow at Step 5.

- [ ] **Step 5: Handle surfaced bugs (skip if none)**

For each `BUG-CANDIDATE` in this pattern's worklist that the build/test surfaced as an actual bug, run the bug-fix sub-flow:

1. Write a regression test in `tests/host/test_util_<symptom>.cpp`:
   ```cpp
   #include <gtest/gtest.h>
   #include "<header>.h"
   TEST(UtilFooTest, ReturnsExpectedShapeOnX) {
       // exercise the bug
       EXPECT_EQ(<correct-behavior>);
   }
   ```
   Add the test to `tests/host/CMakeLists.txt`.
2. Build + run the new test, confirm it FAILS:
   ```bash
   cmake --build build/x86_64-release --target test_util_<symptom>
   (cd build/x86_64-release && ctest -R "UtilFooTest" --output-on-failure)
   ```
3. Fix the bug in the source.
4. Re-run the test, confirm it PASSES.
5. Per spec §7.3 commit shape, the bug-fix is its own commit titled `fix(util): <symptom>` AND the regression test is its own commit titled `test(util): regression test for <symptom>`.

- [ ] **Step 6: Commit the pattern sweep**

If Step 2 had any `CONVERT` rows applied:
```bash
git add kernel/util/
git commit -m "$(cat <<'EOF'
idiom-audit(kernel/util): naked new -> allocators

Migrates N naked new/delete sites in kernel/util/ to:
- UniquePtr<T>::Make for owner-scoped single instances
- kheap::Alloc for raw byte buffers
- slab::Alloc<T> for slab-cached small types

Per spec §6.1. Sites listed in PR description.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```
Replace `N` with the actual count from Step 1.

Expected: commit created; `git log --oneline -1` shows the new HEAD.

---

## Task 4: Pattern 2 sweep — sentinel returns → `Result<T, E>`

**Files:** modify the files in `/tmp/util-audit/p2-sentinels.txt` that have `CONVERT` rows. This is the largest pattern; expect this Task to take the most time of any in the PR.

- [ ] **Step 1: Re-read the worklist and pre-pick `ErrorCode`s**

Run:
```bash
grep '^CONVERT' /tmp/util-audit/p2-sentinels.txt | head -40
```
For each `CONVERT` row, mentally pick the `ErrorCode` variant from `kernel/util/result.h:93` that best fits the failure mode. The 18 existing variants cover most cases. Per spec §6.2, **adding new variants requires PR-description justification** — surface that need now, not at commit time. If a row has 5+ failure modes the kernel-wide enum doesn't cover, consider a per-subsystem error enum per spec §6.2 (rare in `util/`).

- [ ] **Step 2: Apply migrations per spec §6.2 mechanical rule**

For each `CONVERT` row, rewrite the function signature and call sites. Example:

```cpp
// Before — string.cpp
int ParseInt(const char* s, int base) {
    if (!s) return -1;
    // ... parse ...
    if (overflow) return -1;
    return value;
}

// After
Result<i32> ParseInt(const char* s, i32 base) {
    if (!s) return Err{ErrorCode::InvalidArgument};
    // ... parse ...
    if (overflow) return Err{ErrorCode::Overflow};
    return value;
}
```

Update every caller:
```cpp
// Before
int n = ParseInt(s, 10);
if (n < 0) { /* error */ }

// After (using RESULT_TRY_ASSIGN)
RESULT_TRY_ASSIGN(i32 n, ParseInt(s, 10));
// or branching:
auto r = ParseInt(s, 10);
if (!r) { /* error path uses r.error() */ }
i32 n = r.take();
```

**Skip rules (do not convert):**
- `bool IsLocked() const;` → stays `bool` (genuine predicate).
- `T* FindById(id);` returning `nullptr` for "not found" with no error semantics → stays `T*` (per spec §6.2).
- Measured hot paths where `Result` construction cost is observable → leave as-is with a comment.

- [ ] **Step 3: Update callers across the tree**

A signature change in `kernel/util/` ripples to callers elsewhere. Find them:
```bash
# Replace `ParseInt` with each migrated function name
grep -rnE '\bParseInt\s*\(' kernel/ userland/ 2>/dev/null \
  | grep -v 'kernel/util/'
```
Update each caller to handle the `Result` shape. **This is where most surfaced bugs appear** — callers ignoring the sentinel return become callers ignoring the `Result`, which the build catches via `[[nodiscard]]`.

- [ ] **Step 4: Format + build**

Run:
```bash
find kernel userland \( -name '*.h' -o -name '*.cpp' \) | xargs clang-format -i 2>/dev/null
cmake --build build/x86_64-release --parallel $(nproc) 2>&1 | tail -30
```
Expected: zero warnings (caller discards of `Result` would surface as `-Werror=unused-result`), zero errors. If `[[nodiscard]]` warnings fire on callers, **do not** silence with `(void)foo()` — that's spec §6.5's "not acceptable" pattern. Either propagate via `RESULT_TRY` / `RESULT_TRY_ASSIGN` / `RESULT_LOG_AND_DROP`, or handle the error explicitly.

- [ ] **Step 5: Hosted ctest**

Run:
```bash
(cd build/x86_64-release && ctest --output-on-failure 2>&1 | tail -15)
```
Expected: all tests pass. Sentinel-migration test failures usually mean a caller's expected `-1` is now an `Err{}` but the test still checks for `-1`. Update the test to check `r.has_value()` / `r.error()`.

- [ ] **Step 6: Handle surfaced bugs (per Task 3 Step 5's sub-flow)**

For each ignored-sentinel caller surfaced by the build/test, run the regression-test + fix + verify + commit sub-flow.

- [ ] **Step 7: Mid-PR boot smoke (1×, fast feedback)**

Run:
```bash
DUETOS_TIMEOUT=20 tools/qemu/run.sh build/x86_64-release/duetos.iso \
  > /tmp/util-p2-smoke.log 2>&1
tools/test/boot-log-analyze.sh /tmp/util-p2-smoke.log && echo PASS || echo FAIL
```
Expected: PASS. If FAIL, per spec §6.7 category 2 fix the boot failure in this PR; surfaced boot failures are exempt from the §8 R1 cap.

- [ ] **Step 8: Commit the pattern sweep**

```bash
git add kernel/ userland/
git commit -m "$(cat <<'EOF'
idiom-audit(kernel/util): sentinel returns -> Result<T,E>

Migrates N sentinel-return sites in kernel/util/ and their callers
across the tree. ErrorCode picks listed in PR description.

Per spec §6.2. Callers updated to use RESULT_TRY / RESULT_TRY_ASSIGN
or explicit .has_value() branch. No new ErrorCode variants added
unless justified in the PR description's "ErrorCode additions"
section.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```
Replace `N` with the actual count. If new `ErrorCode` variants were added, list them in the commit body with the call site that forced each.

---

## Task 5: Pattern 3 sweep — raw owning ptrs → `UniquePtr<T>`

**Files:** modify files in `/tmp/util-audit/p3-raw-ptr-candidates.txt` that have `CONVERT` rows.

- [ ] **Step 1: Re-read the worklist**

Run:
```bash
grep '^CONVERT' /tmp/util-audit/p3-raw-ptr-candidates.txt
```
Expected: each `CONVERT` row identifies an owning raw pointer (member or local). If empty, skip to Step 5.

- [ ] **Step 2: Apply migrations per spec §6.3 mechanical rule**

For each `CONVERT` row, replace the raw pointer with `UniquePtr<T>`. Example:

```cpp
// Before
class SymbolTable {
    Entry* m_entries = nullptr;   // owning, manual delete in dtor
public:
    SymbolTable() : m_entries(new Entry[N]) {}
    ~SymbolTable() { delete[] m_entries; }
};

// After
class SymbolTable {
    UniquePtr<Entry[]> m_entries;
public:
    SymbolTable() : m_entries(UniquePtr<Entry[]>::Make(N)) {}
    // ~SymbolTable() = default; — destructor drops manual delete
};
```

**Skip rules (do not convert):**
- Non-owning observer pointers (back-pointers, registry references).
- Pointers owned by another subsystem.
- Pointers to statics / never-deallocated objects.

**Pitfall:** if the same heap object is held by `T*` in multiple structures, decide which is the owner *before* converting. Document in the worklist annotation.

- [ ] **Step 3: Format + build + ctest**

Run:
```bash
find kernel/util \( -name '*.h' -o -name '*.cpp' \) | xargs clang-format -i
cmake --build build/x86_64-release --parallel $(nproc) 2>&1 | tail -15
(cd build/x86_64-release && ctest --output-on-failure 2>&1 | tail -10)
```
Expected: zero warnings, all tests pass.

- [ ] **Step 4: Handle surfaced bugs (spec §6.7 category 3)**

Memory-ownership bugs the migration exposes (mismatched delete/delete[], leaks, use-after-free). Per Task 3 Step 5's sub-flow. **Bugs that produce a boot failure are exempt from the §8 R1 cap.**

- [ ] **Step 5: Commit**

```bash
git add kernel/util/
git commit -m "$(cat <<'EOF'
idiom-audit(kernel/util): raw owning ptrs -> UniquePtr

Migrates N owning raw pointers in kernel/util/ to UniquePtr<T>.
Per spec §6.3. Non-owning observer pointers left as raw.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 6: Pattern 4 sweep — `m_` prefix on members

**Files:** modify files in `/tmp/util-audit/p4-member-candidates.txt` that have `CONVERT` rows.

- [ ] **Step 1: Re-read the worklist**

Run:
```bash
grep '^CONVERT' /tmp/util-audit/p4-member-candidates.txt
```
Expected: each `CONVERT` row identifies a class/struct with non-prefixed members where the class is not a POD record-struct.

- [ ] **Step 2: Apply renames per spec §6.4 — one commit per class**

Per spec §6.4 pitfall: **do not bundle multiple class renames into one mega-commit.** Each class's rename is its own commit; if a single rename breaks the build, isolated reverts are easy.

For each class:
1. Rename every member in the class declaration: `size_t length;` → `size_t m_length;`.
2. Update the constructor's member-initializer list: `: length(n)` → `: m_length(n)`.
3. Update every reference in the class's methods (in-header inlines and the matching `.cpp`).
4. Update external references (other TUs accessing `obj.length` — if the member was public).

Example:
```cpp
// Before
class StringBuffer {
    char* data;
    size_t length;
    size_t capacity;
public:
    StringBuffer(size_t cap) : data(new char[cap]), length(0), capacity(cap) {}
    size_t Size() const { return length; }
};

// After
class StringBuffer {
    char* m_data;
    size_t m_length;
    size_t m_capacity;
public:
    StringBuffer(size_t cap) : m_data(new char[cap]), m_length(0), m_capacity(cap) {}
    size_t Size() const { return m_length; }
};
```

**Skip rules:**
- POD record-structs (no private members, no methods): `struct Vec3 { f32 x, y, z; };` stays.
- Union members.
- Public global structs that exist as ABI shapes (offsets touched from assembly).

- [ ] **Step 3: Format + build + ctest after EACH class rename**

```bash
find kernel/util \( -name '*.h' -o -name '*.cpp' \) | xargs clang-format -i
cmake --build build/x86_64-release --parallel $(nproc) 2>&1 | tail -15
(cd build/x86_64-release && ctest --output-on-failure 2>&1 | tail -10)
```
Expected: zero warnings, all tests pass. If any reference outside the class wasn't updated, build fails with "no member named 'length'". Fix and re-build.

- [ ] **Step 4: Commit each class rename separately**

```bash
git add kernel/util/<file>.{h,cpp}
git commit -m "$(cat <<'EOF'
idiom-audit(kernel/util): m_ prefix on <ClassName> members

Per spec §6.4. <ClassName> is not a POD record struct (has methods
and/or private members), so m_ prefix applies.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

Repeat for each renamed class.

---

## Task 7: Pattern 5 sweep — `[[nodiscard]]` on `Result`-returners

**Files:** modify files in `/tmp/util-audit/p5-result-returners.txt` that have `CONVERT` rows.

- [ ] **Step 1: Re-read the worklist**

Run:
```bash
grep '^CONVERT' /tmp/util-audit/p5-result-returners.txt
```
Expected: each `CONVERT` row identifies a function declaration returning `Result<...>` without `[[nodiscard]]`.

- [ ] **Step 2: Add `[[nodiscard]]` at each declaration site**

Add `[[nodiscard]]` to the declaration (header or in-class definition), NOT the definition site. Example:

```cpp
// Before (in header)
Result<u32> ComputeChecksum(const u8* data, size_t len);

// After
[[nodiscard]] Result<u32> ComputeChecksum(const u8* data, size_t len);
```

**Skip rules:** lambdas, function pointer types (syntactically can't annotate).

- [ ] **Step 3: Build — `[[nodiscard]]` will surface caller-discard sites**

Run:
```bash
cmake --build build/x86_64-release --parallel $(nproc) 2>&1 | tee /tmp/util-p5-build.log | tail -30
```
Expected: build may emit `-Werror=unused-result` for callers that discard a now-annotated function's return. **Each such warning is a surfaced bug** per spec §6.5 "Pitfalls" — fix it (handle the error, propagate via `RESULT_TRY`, or use `RESULT_LOG_AND_DROP` with a comment). **`(void)foo()` without justification is not acceptable.**

- [ ] **Step 4: Handle each surfaced caller (per Task 3 Step 5's sub-flow)**

Each fix is its own `fix(util): <symptom>` commit. The regression test goes in `tests/host/test_util_<symptom>.cpp` and is its own `test(util): ...` commit.

- [ ] **Step 5: Format + build + ctest**

```bash
find kernel/util kernel \( -name '*.h' -o -name '*.cpp' \) | xargs clang-format -i 2>/dev/null
cmake --build build/x86_64-release --parallel $(nproc) 2>&1 | tail -15
(cd build/x86_64-release && ctest --output-on-failure 2>&1 | tail -10)
```
Expected: zero warnings, all tests pass.

- [ ] **Step 6: Commit**

```bash
git add kernel/util/ kernel/ userland/
git commit -m "$(cat <<'EOF'
idiom-audit(kernel/util): [[nodiscard]] on Result returners

Adds [[nodiscard]] to N function declarations returning Result<T,E>
in kernel/util/ headers. Surfaced callers fixed in fix(util): ...
commits.

Per spec §6.5.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 8: Pattern 6 sweep — `const` on cross-subsystem API methods

**Files:** modify files in `/tmp/util-audit/p6-method-candidates.txt` that have `CONVERT` rows.

- [ ] **Step 1: Re-read the worklist**

Run:
```bash
grep '^CONVERT' /tmp/util-audit/p6-method-candidates.txt
```
Expected: methods on classes whose public methods are consumed across subsystem headers, that don't modify non-`mutable` state.

- [ ] **Step 2: Add `const` per spec §6.6 mechanical rule**

Add `const` after the parameter list:
```cpp
// Before
size_t StringBuffer::Size() { return m_length; }

// After
size_t StringBuffer::Size() const { return m_length; }
```

**Skip rules:**
- In-TU helpers and private utility methods (deferred to track #4).
- Methods returning non-const pointers/references to members (need const-overload pair, design work, out-of-scope here).

**Pitfall:** "logical const" with a memoization cache requires `mutable` on the cache. If encountered, surface in the PR description and decide explicitly. Don't add `const` blindly.

- [ ] **Step 3: Format + build + ctest**

```bash
find kernel/util kernel \( -name '*.h' -o -name '*.cpp' \) | xargs clang-format -i 2>/dev/null
cmake --build build/x86_64-release --parallel $(nproc) 2>&1 | tail -15
(cd build/x86_64-release && ctest --output-on-failure 2>&1 | tail -10)
```
Expected: zero warnings, all tests pass.

- [ ] **Step 4: Commit**

```bash
git add kernel/util/
git commit -m "$(cat <<'EOF'
idiom-audit(kernel/util): const on non-mutating API methods

Adds const to N non-mutating method declarations on kernel/util/
classes consumed across subsystem headers. Per spec §6.6.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 9: Wave-1 self-test sentinel (per spec §10)

**Files:**
- Modify: `kernel/util/result.cpp` — add the sentinel emission to the end of `ResultSelfTest()`'s PASS path.
- Modify: `tools/test/boot-log-analyze.sh` — add a grep for the new sentinel in the existing self-test umbrella section.

- [ ] **Step 1: Find the existing `ResultSelfTest()` PASS line**

Run:
```bash
grep -nE 'ResultSelfTest|\[result-selftest\] PASS|arch::SerialWrite' kernel/util/result.cpp | head -10
```
Expected: lines showing where the self-test currently emits its existing PASS sentinel (if any). If no PASS sentinel exists, this step also adds the result-selftest line.

- [ ] **Step 2: Add the wave-1 sentinel emission**

Edit `kernel/util/result.cpp` so the final lines of `ResultSelfTest()` emit:
```cpp
arch::SerialWrite("[idiom-audit-selftest] PASS (wave-1)\n");
```
**Position:** end of `ResultSelfTest()`, AFTER any existing PASS line, gated by the same success path. Add `#include "arch/x86_64/serial.h"` (or whichever header owns `arch::SerialWrite`) if not already present.

- [ ] **Step 3: Build + ctest**

```bash
cmake --build build/x86_64-release --parallel $(nproc) 2>&1 | tail -10
(cd build/x86_64-release && ctest --output-on-failure 2>&1 | tail -10)
```
Expected: zero warnings, all tests pass.

- [ ] **Step 4: Mid-PR boot smoke to confirm the sentinel fires**

Run:
```bash
DUETOS_TIMEOUT=20 tools/qemu/run.sh build/x86_64-release/duetos.iso \
  > /tmp/util-sentinel-smoke.log 2>&1
grep -F '[idiom-audit-selftest] PASS (wave-1)' /tmp/util-sentinel-smoke.log
```
Expected: one line of output showing the sentinel was emitted. If empty, `ResultSelfTest()` was not on the boot path or the emission line wasn't reached — investigate.

- [ ] **Step 5: Update `boot-log-analyze.sh` to grep the sentinel**

Find the script's self-test umbrella section and add a row that checks for the wave-1 sentinel. Pattern after the existing Pass A/B/C/D sentinel rows. Example (adapt to the script's actual structure):
```bash
# In tools/test/boot-log-analyze.sh, in the self-test umbrella section
grep -F '[idiom-audit-selftest] PASS (wave-1)' "$LOG" >/dev/null \
  || { echo "MISSING: [idiom-audit-selftest] PASS (wave-1) sentinel"; exit 1; }
```

- [ ] **Step 6: Verify the analyzer treats a missing sentinel as failure**

Run:
```bash
# Strip the sentinel from a captured log and re-run the analyzer
grep -v 'idiom-audit-selftest' /tmp/util-sentinel-smoke.log > /tmp/util-missing-sentinel.log
tools/test/boot-log-analyze.sh /tmp/util-missing-sentinel.log
echo "exit=$?"
```
Expected: non-zero exit, with "MISSING: [idiom-audit-selftest] PASS (wave-1) sentinel" in output. If the analyzer exits 0, the new check isn't wired in correctly — re-edit.

- [ ] **Step 7: Commit**

```bash
git add kernel/util/result.cpp tools/test/boot-log-analyze.sh
git commit -m "$(cat <<'EOF'
idiom-audit(kernel/util): wave-1 self-test sentinel

Emit [idiom-audit-selftest] PASS (wave-1) from ResultSelfTest()'s
PASS path and grep it in tools/test/boot-log-analyze.sh. Per spec
§10. Wave-N gate: every wave's first PR adds one sentinel; boot-
log-analyze fails when an expected sentinel is missing.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 10: Final verification gate (spec §7.4 in full)

**Files:** no new code changes; gate runs on the existing PR HEAD.

- [ ] **Step 1: Format clean (spec §7.4 item 2)**

Run:
```bash
find kernel drivers subsystems userland \( -name '*.h' -o -name '*.hpp' -o -name '*.c' -o -name '*.cpp' \) \
  | xargs clang-format --dry-run --Werror 2>&1 | tail -20
echo "exit=$?"
```
Expected: empty output, exit 0. ASM (`.S`) files NOT formatted per CLAUDE.md.

- [ ] **Step 2: Build clean — zero warnings, zero errors (spec §7.4 item 1)**

Run:
```bash
rm -rf build/x86_64-release
cmake --preset x86_64-release 2>&1 | tail -5
cmake --build build/x86_64-release --parallel $(nproc) 2>&1 | tee /tmp/util-final-build.log | tail -40
grep -E 'warning:|error:' /tmp/util-final-build.log | head -20
```
Expected: tail shows the final link line; the grep for `warning:|error:` returns nothing. **A clean-from-scratch build is required**, not an incremental one — incremental can mask stale-object regressions.

- [ ] **Step 3: Hosted ctest clean (spec §7.4 item 3)**

Run:
```bash
(cd build/x86_64-release && ctest --output-on-failure 2>&1 | tail -25)
```
Expected: "100% tests passed". Every regression test added during the sweep is among them.

- [ ] **Step 4: Boot smoke 3× clean (spec §7.4 item 4)**

Run:
```bash
for i in 1 2 3; do
  DUETOS_TIMEOUT=20 tools/qemu/run.sh build/x86_64-release/duetos.iso \
    > /tmp/util-final-smoke.$i.log 2>&1
  tools/test/boot-log-analyze.sh /tmp/util-final-smoke.$i.log \
    && echo "RUN $i: PASS" \
    || { echo "RUN $i: FAIL"; tail -50 /tmp/util-final-smoke.$i.log; exit 1; }
done
```
Expected: 3× "PASS". Per spec §8 R5: re-running until green is NOT acceptable. If any one of 3 fails, investigate per CLAUDE.md's intermittent-bug pattern-matching (collision class, refcount asymmetry, scheduling-sensitive, hash-order, GC-timing, cache-warmup).

- [ ] **Step 5: STUB/GAP discipline (spec §7.4 item 5)**

Run:
```bash
git diff origin/main..HEAD | grep -E '^\+.*// (STUB|GAP):' | head -20
```
Expected: every added STUB/GAP marker corresponds to an "Out-of-scope items spotted" entry in the PR description (filled in at Task 11) AND a row in `wiki/reference/Roadmap.md` for future work. If markers exist without these, add them now.

- [ ] **Step 6: Subsystem-isolation audit (spec §7.4 item 6)**

Run:
```bash
git diff origin/main..HEAD -- 'kernel/subsystems/**' | head -50
```
Expected: empty (this is a util-only PR; touching subsystem code would mean a sentinel-return migration propagated into a subsystem TU, which is OK as long as no new kernel-state-mutation path was added outside cap gates). Per spec §7.4 item 6, audit confirms: no subsystem code mutates kernel-internal state outside cap-gated syscalls.

- [ ] **Step 7: Re-check the wave-1 sentinel fires in all 3 boot smoke runs**

Run:
```bash
for i in 1 2 3; do
  grep -F '[idiom-audit-selftest] PASS (wave-1)' /tmp/util-final-smoke.$i.log > /dev/null \
    && echo "RUN $i: sentinel PRESENT" \
    || echo "RUN $i: sentinel MISSING"
done
```
Expected: 3× "sentinel PRESENT". A missing sentinel means `ResultSelfTest()` wasn't on the boot path of that run — investigate.

- [ ] **Step 8: Capture gate output for the PR description**

Run:
```bash
{
  echo "## Verification gate output (PR description §6)"
  echo
  echo "### Build (clean from scratch)"
  tail -5 /tmp/util-final-build.log
  echo
  echo "### ctest"
  (cd build/x86_64-release && ctest --output-on-failure 2>&1 | tail -10)
  echo
  echo "### Boot smoke 3x"
  for i in 1 2 3; do
    tools/test/boot-log-analyze.sh /tmp/util-final-smoke.$i.log >/dev/null \
      && echo "Run $i: PASS" || echo "Run $i: FAIL"
  done
} > /tmp/util-audit/GATE-OUTPUT.txt
cat /tmp/util-audit/GATE-OUTPUT.txt
```
Expected: GATE-OUTPUT.txt populated; will be pasted into the PR description at Task 11.

---

## Task 11: PR open + description per spec §7.2

**Files:** no code changes; PR creation via `gh`.

- [ ] **Step 1: Re-sync against `origin/main` and rebase**

Per spec §8 R3 wave-drift mitigation:
```bash
git fetch origin main
git rebase origin/main
```
If conflicts, resolve them and re-run the verification gate from Task 10 Step 1.

- [ ] **Step 2: Push the branch**

Run:
```bash
git push -u origin claude/idiom-audit-phase1-util
```
Expected: branch pushed; URL printed.

- [ ] **Step 3: Compose the PR description per spec §7.2**

Sections in order:
1. **Wave & dependency** — "Wave 1, PR 1. No upstream dependencies (Wave 1 is the first wave)."
2. **Pattern coverage table** — read from `/tmp/util-audit/SUMMARY.txt`. One row per pattern: total / convert / skip / bugs.
3. **Surfaced bugs** — bulleted list from the `fix(util): ...` commits. Each entry: `<symptom> — fixed in <sha>`.
4. **ErrorCode additions** — listed at Task 4 Step 8; justification for each.
5. **Out-of-scope items spotted** — STUB/GAP markers added (from Task 10 Step 5) with Roadmap rows.
6. **Verification gate** — paste `/tmp/util-audit/GATE-OUTPUT.txt`.

- [ ] **Step 4: Open the PR via `gh`**

Run:
```bash
gh pr create --title "idiom-audit(kernel/util): phase-1 sweep" --body "$(cat <<'EOF'
[Filled in from Step 3 — paste the composed description here.]

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)" --base main --head claude/idiom-audit-phase1-util
```
Expected: PR URL printed. The PR description matches spec §7.2's six-section structure.

- [ ] **Step 5: Wait for CI; address any feedback**

Run:
```bash
gh pr checks --watch
```
Expected: all CI checks turn green. Per spec §7.7, if a check fails after merge, the PR is reverted within 24h, not patched forward.

- [ ] **Step 6: Final spot-check after CI green**

Run:
```bash
gh pr view --json mergeable,statusCheckRollup | head -20
```
Expected: `"mergeable": "MERGEABLE"`, all status checks SUCCESS.

- [ ] **Step 7: Mark Wave 1 PR #1 complete**

The PR is now mergeable. After merge:
- The wave-1 dependency for `log`/`sync`/`mm`/`core` PRs is partially satisfied (only `util` blocks them; the other Wave-1 PRs can also start once `util` lands).
- The next session writes the plan for the next Wave 1 PR — likely `log` since it's small and self-contained.

---

## Self-Review (writing-plans skill)

This plan was self-reviewed for spec coverage, placeholders, and type consistency. The util PR maps to spec §5 Wave 1 PR #1; every Phase-1 pattern (spec §6.1–§6.6) has a Task; the verification gate (spec §7.4) is Task 10; the PR description (spec §7.2) is Task 11; the wave-1 sentinel (spec §10) is Task 9. The surfaced-bug fix protocol (spec §6.7) is reused as the sub-flow in Task 3 Step 5 and referenced from every subsequent pattern Task. Spec §8 R1's cap rule and §8 R5's boot-smoke 3× rule are referenced at the relevant gates.

**No placeholders.** Every step has actual commands and expected output.

**Subsequent plans:** after this PR merges, separate writing-plans cycles will produce per-PR plans for the remaining Wave 1 PRs (`log`, `sync`, `mm-core`, `mm-paging`, `core`), informed by the real signal this util sweep surfaces.
