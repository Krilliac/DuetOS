#!/usr/bin/env bash
# tools/dev/analyze.sh — DuetOS codebase analysis: one command, our own
# analyzer + the external ones, static + (opt-in) dynamic.
#
# Phases
#   own       DuetOS invariant checks (tools/dev/invariant-check.sh).   GATING
#   cppcheck  whole-tree cppcheck; gates on error severity only, with
#             tools/dev/cppcheck-suppressions.txt for verified FPs.     GATING
#   tidy      clang-tidy advisory sample over compile_commands.json.    advisory
#   clippy    cargo clippy --workspace -D warnings (mirrors CI).        GATING
#   dynamic   ubsan + kasan QEMU boot smoke (opt-in, --dynamic).        GATING
#
# Philosophy mirrors .github/workflows/build.yml: clippy and the
# sanitiser boots are hard gates (CI fails on them); clang-tidy on a
# freestanding kernel is advisory because a full pass is mostly
# false-positive noise — surface the signal, don't block on it.
# Missing optional tools (cppcheck, clang-tidy, qemu) downgrade their
# phase to a skip with an apt hint; they never fake a pass and never
# hard-fail the run on absence.

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/../.." && pwd)"
cd "${REPO_ROOT}"

PRESET="x86_64-debug"
RUN_OWN=1
RUN_CPPCHECK=1
RUN_TIDY=1
RUN_CLIPPY=1
RUN_DYNAMIC=0
TIDY_LIMIT=30
SUPPRESS="${REPO_ROOT}/tools/dev/cppcheck-suppressions.txt"

usage() {
    cat <<'USAGE'
usage: tools/dev/analyze.sh [options]

Default: own + cppcheck + clang-tidy(advisory) + clippy. Dynamic is opt-in.

  --no-own        skip DuetOS invariant checks
  --no-cppcheck   skip cppcheck
  --no-tidy       skip clang-tidy advisory pass
  --no-clippy     skip cargo clippy
  --dynamic       ALSO run ubsan + kasan QEMU boot smoke (needs qemu)
  --preset <name> debug preset for compile_commands.json (default x86_64-debug)
  --tidy-limit N  kernel .cpp files to sample for clang-tidy (default 30)
  -h, --help      show this help
USAGE
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --no-own)      RUN_OWN=0; shift ;;
        --no-cppcheck) RUN_CPPCHECK=0; shift ;;
        --no-tidy)     RUN_TIDY=0; shift ;;
        --no-clippy)   RUN_CLIPPY=0; shift ;;
        --dynamic)     RUN_DYNAMIC=1; shift ;;
        --preset)      [[ $# -ge 2 ]] || { echo "analyze.sh: --preset needs a value" >&2; exit 2; }
                       PRESET="$2"; shift 2 ;;
        --tidy-limit)  [[ $# -ge 2 ]] || { echo "analyze.sh: --tidy-limit needs a value" >&2; exit 2; }
                       TIDY_LIMIT="$2"; shift 2 ;;
        -h|--help)     usage; exit 0 ;;
        *) echo "analyze.sh: unknown argument: $1" >&2; usage >&2; exit 2 ;;
    esac
done

FAIL=0
BUILD_DIR="build/${PRESET}"
phase() { printf '\n========== %s ==========\n' "$1"; }
gate_fail() { printf 'GATE FAILED: %s\n' "$1"; FAIL=1; }

# A built tree is needed for both cppcheck (it follows the compilation
# database, which references generated TUs) and clang-tidy. Configure +
# build once, up front, if any tree-consuming phase is selected.
ensure_tree() {
    [[ -f "${BUILD_DIR}/compile_commands.json" && -f "${BUILD_DIR}/kernel/duetos-kernel.elf" ]] && return 0
    phase "build ${PRESET} (for compile_commands.json + generated TUs)"
    cmake --preset "${PRESET}" -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
    cmake --build "${BUILD_DIR}" --parallel "$(nproc)"
}

if [[ ${RUN_OWN} -eq 1 ]]; then
    phase "own — DuetOS invariant checks (gating)"
    if ! bash "${REPO_ROOT}/tools/dev/invariant-check.sh"; then
        gate_fail "DuetOS invariant(s) violated"
    fi
fi

if [[ ${RUN_CPPCHECK} -eq 1 ]]; then
    phase "cppcheck — whole tree, error severity gated (gating)"
    if ! command -v cppcheck >/dev/null 2>&1; then
        echo "cppcheck not installed — skipping (apt-get install -y cppcheck)"
    else
        ensure_tree
        # cppcheck's suppressions parser is brittle with non-rule lines
        # across versions; feed it only the rule lines, keep the prose
        # documentation in the source file for maintainers.
        rules="$(mktemp)"
        grep -E '^[a-zA-Z][a-zA-Z0-9_]*:' "${SUPPRESS}" > "${rules}" || true
        report="$(mktemp)"
        cppcheck --project="${BUILD_DIR}/compile_commands.json" \
            --enable=warning,portability --inline-suppr --quiet \
            --suppress=missingIncludeSystem --suppress=missingInclude \
            --suppress=unmatchedSuppression --suppress=checkersReport \
            --suppressions-list="${rules}" \
            -j"$(nproc)" --template='{severity}|{file}:{line}|{id}|{message}' \
            2>"${report}" || true
        echo "severity counts:"
        cut -d'|' -f1 "${report}" | sort | uniq -c | sed 's/^/  /'
        errs="$(grep -cE '^error\|' "${report}" || true)"
        if [[ "${errs}" -gt 0 ]]; then
            echo "error-severity findings (each is a real-bug candidate):"
            grep -E '^error\|' "${report}" | sed 's/^/  /'
            gate_fail "${errs} new cppcheck error-severity finding(s) — triage: fix the bug, or, only if proven a cppcheck blind spot, add a line-pinned entry to tools/dev/cppcheck-suppressions.txt with the reason"
        else
            echo "error gate clean (warning/style/portability are advisory)"
        fi
        rm -f "${rules}" "${report}"
    fi
fi

if [[ ${RUN_TIDY} -eq 1 ]]; then
    phase "clang-tidy — advisory sample (non-gating, mirrors CI)"
    if ! command -v clang-tidy >/dev/null 2>&1; then
        echo "clang-tidy not installed — skipping (apt-get install -y clang-tidy-18)"
    else
        ensure_tree
        # Advisory only: a full clang-tidy pass on a freestanding kernel
        # is dominated by false positives, so CI caps it too. Surface
        # the first N kernel TUs' findings; never affect the exit code.
        find kernel -name '*.cpp' | sort | head -n "${TIDY_LIMIT}" | while read -r f; do
            clang-tidy -p "${BUILD_DIR}" "${f}" --quiet 2>&1 || true
        done | grep -E 'warning:|error:' | head -200 | sed 's/^/  /' || true
        echo "(advisory — clang-tidy never gates this run; see .clang-tidy for policy)"
    fi
fi

if [[ ${RUN_CLIPPY} -eq 1 ]]; then
    phase "clippy — cargo clippy --workspace -D warnings (gating)"
    if ! command -v cargo >/dev/null 2>&1; then
        echo "cargo missing — skipping Rust workspace checks (doctor.sh flags this)"
    elif ! cargo clippy --workspace --release --locked -- -D warnings; then
        gate_fail "cargo clippy reported warnings/errors"
    fi
fi

if [[ ${RUN_DYNAMIC} -eq 1 ]]; then
    # Dynamic analysis: build with the sanitiser presets and boot each
    # in QEMU. ctest-boot-smoke.sh already encodes the CI signature
    # list and the rc contract (0 pass / 1 regression / 2 env-skip),
    # so reuse it rather than re-deriving the boot oracle here.
    for dp in x86_64-debug-ubsan x86_64-kasan; do
        phase "dynamic — ${dp} QEMU boot smoke (gating)"
        cmake --preset "${dp}" >/dev/null
        cmake --build "build/${dp}" --parallel "$(nproc)"
        set +e
        bash "${REPO_ROOT}/tools/test/ctest-boot-smoke.sh" "build/${dp}"
        rc=$?
        set -e
        case "${rc}" in
            0) echo "${dp}: clean boot, no sanitiser report" ;;
            2) echo "${dp}: SKIP — qemu not installed (tools/dev/doctor.sh --live; apt-get install -y qemu-system-x86)" ;;
            *) gate_fail "${dp} boot smoke failed (sanitiser hit / panic / missing signature)" ;;
        esac
    done
fi

phase "RESULT"
if [[ ${FAIL} -ne 0 ]]; then
    echo "analyze.sh: one or more GATING phases failed"
    exit 1
fi
echo "analyze.sh: all gating phases passed"
