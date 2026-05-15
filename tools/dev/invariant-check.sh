#!/usr/bin/env bash
# tools/dev/invariant-check.sh — DuetOS's own static analyzer.
#
# This is the "your own" half of the codebase-analysis tooling: a set of
# project-specific structural invariants that no off-the-shelf analyzer
# (clang-tidy / cppcheck / clippy) knows about, because they encode
# CLAUDE.md architecture rules rather than language rules.
#
# Design rule for what lives here: a check earns a place ONLY if it is
# high-signal and near-zero false-positive on the current tree, so that
# a non-zero exit is always a real regression and never noise. Noisy
# heuristics (naked new/delete by grep, cross-subsystem include grep)
# were evaluated and deliberately left out — they flag documented,
# intentional shared primitives and would train people to ignore the
# tool. Language-level smells are clang-tidy/cppcheck's job; this file
# only owns the rules those tools structurally cannot see.
#
# Read-only. Exits non-zero iff a GATING invariant is violated.
# Informational sections never affect the exit code.

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/../.." && pwd)"
cd "${REPO_ROOT}"

FAIL=0

section() { printf '\n-- %s --\n' "$1"; }
fail()    { printf 'FAIL: %s\n' "$1"; FAIL=1; }
ok()      { printf 'ok: %s\n' "$1"; }

# ---------------------------------------------------------------------------
# GATE 1 — userland is freestanding (CLAUDE.md subsystem-isolation rule 3).
#
# "Userland DLLs (userland/libs/*) are freestanding. They do not include
# kernel headers." Generalised to all of userland/. The violation shape
# is unambiguous: a userland TU whose #include path literally resolves
# into the kernel/ tree (either "kernel/..." or "../.../kernel/..."),
# so the regex carries no false positives — userland's own headers never
# sit under a path component named `kernel`.
# ---------------------------------------------------------------------------
section "GATE 1: userland does not include kernel headers"
ul_hits="$(grep -rnE '#include[[:space:]]*[<"]([^">]*\.\./)*kernel/' \
    userland --include='*.c' --include='*.cpp' \
    --include='*.h' --include='*.hpp' 2>/dev/null || true)"
if [[ -n "${ul_hits}" ]]; then
    fail "userland TU(s) include kernel headers:"
    printf '%s\n' "${ul_hits}"
else
    ok "no userland -> kernel header includes"
fi

# ---------------------------------------------------------------------------
# GATE 2 — no std:: in kernel code (CLAUDE.md: "std:: is user-land only").
#
# Heuristic: per match, strip the //-line comment, ignore block-comment
# body lines (leading `*` / `/*`) and host-test-shim lines, then keep the
# match only if a std:: token survives in actual code. String literals
# are an accepted blind spot — the tree is clean today, so this is a
# regression guard, not a sweep, and the blind spot only ever produces
# false NEGATIVES (a missed std:: in a string), never a false alarm.
# ---------------------------------------------------------------------------
section "GATE 2: no std:: in kernel code"
std_hits="$(grep -rnE '\bstd::' kernel \
        --include='*.cpp' --include='*.h' --include='*.hpp' 2>/dev/null \
    | grep -vE 'DUETOS_HOST_TEST|/tests/' \
    | awk -F: '
        {
            code = $0;
            sub(/^[^:]+:[0-9]+:/, "", code);   # drop file:line: prefix
            sub(/\/\/.*$/, "", code);          # strip // line comment
            if (code ~ /^[[:space:]]*[*]/)   next;  # block-comment body
            if (code ~ /^[[:space:]]*\/\*/)  next;  # block-comment open
            if (code ~ /\bstd::/) print $0;
        }' || true)"
if [[ -n "${std_hits}" ]]; then
    fail "std:: used in kernel code (std is userland-only):"
    printf '%s\n' "${std_hits}" | head -20
else
    ok "no std:: in kernel code"
fi

# ---------------------------------------------------------------------------
# INFO — STUB/GAP inventory. CLAUDE.md treats this as the live gap audit
# list. Not a gate (markers are expected to exist); surfaced so a run of
# the analyzer doubles as the inventory refresh.
# ---------------------------------------------------------------------------
section "INFO: STUB/GAP marker inventory"
stub_n="$(git grep -nE '// STUB:'  -- kernel userland drivers subsystems 2>/dev/null | wc -l | tr -d ' ')"
gap_n="$( git grep -nE '// GAP:'   -- kernel userland drivers subsystems 2>/dev/null | wc -l | tr -d ' ')"
printf 'STUB markers: %s\nGAP markers:  %s\n' "${stub_n}" "${gap_n}"
printf '(refresh the list with: git grep -nE "// (STUB|GAP):")\n'

# ---------------------------------------------------------------------------
# INFO — anti-bloat threshold report. CLAUDE.md thresholds are guidelines,
# not hard limits, so this is advisory: it names the files a maintainer
# should glance at before adding to, not a build-breaker.
# ---------------------------------------------------------------------------
section "INFO: files over the anti-bloat thresholds (advisory)"
over_src="$( { find kernel drivers subsystems userland -type f \
        \( -name '*.cpp' -o -name '*.c' -o -name '*.rs' \) \
        -exec wc -l {} + 2>/dev/null \
    | awk '$1 > 500 && $2 != "total"' | wc -l | tr -d ' '; } || true)"
over_hdr="$( { find kernel drivers subsystems userland -type f \
        \( -name '*.h' -o -name '*.hpp' \) \
        -exec wc -l {} + 2>/dev/null \
    | awk '$1 > 300 && $2 != "total"' | wc -l | tr -d ' '; } || true)"
printf 'impl files > 500 lines: %s\nheader files > 300 lines: %s\n' \
    "${over_src}" "${over_hdr}"
printf '(list with: find ... | xargs wc -l | sort -rn | head)\n'

section "RESULT"
if [[ ${FAIL} -ne 0 ]]; then
    echo "invariant-check.sh: GATING invariant(s) violated"
    exit 1
fi
echo "invariant-check.sh: all gating invariants hold"
