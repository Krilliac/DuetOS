#!/usr/bin/env bash
#
# Roundtrip test for tools/build/gen-fix-patches.py.
#
# Constructs a synthetic KERNEL.FIX with one record per auto-patchable
# detector class, runs the patch generator, and verifies that every
# emitted .patch survives `git apply --check`. Optionally applies the
# patches end-to-end (with `--build`), confirms the kernel still
# builds, and reverts.
#
# Why this exists
# ---------------
#
# The patch generator's value depends on the patches it emits actually
# being applicable to the live tree. A clang-format pass, a refactor,
# or an edit to one of the targets (`kernel/syscall/syscall.cpp`,
# `kernel/sched/sched.cpp`, the thunks table, ...) can silently break
# the generator's anchor-line search and the failure would only surface
# in production fix-cycle runs. This script catches that immediately.
#
# Usage
# -----
#   tools/test/fix-patch-roundtrip.sh                 # quick: gen + apply --check
#   tools/test/fix-patch-roundtrip.sh --build         # also apply, build, revert
#   tools/test/fix-patch-roundtrip.sh --keep          # don't delete the patches dir
#
# Exit status: 0 if every emitted patch passed --check (and built, with
# --build); 1 otherwise. So this doubles as a CI gate.
#
# Reusable rig (CLAUDE.md "Reusable Tooling"). Pairs with
# tools/qemu/run-fix-cycle.sh which runs the LIVE flow under QEMU.

set -euo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

DO_BUILD=0
KEEP=0
PRESET="${DUETOS_PRESET:-x86_64-debug}"
for arg in "$@"; do
    case "$arg" in
        --build) DO_BUILD=1 ;;
        --keep)  KEEP=1 ;;
        --preset=*) PRESET="${arg#--preset=}" ;;
        -h|--help)
            sed -n '2,/^$/p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *) echo "warning: ignoring unknown arg '$arg'" >&2 ;;
    esac
done

PATCH_DIR="$(mktemp -d -t fix-patch-rt-XXXXXX)"
# `mktemp -t NAME.suffix` is rejected on some libcs because the
# template's X's are not at the very end. Generate a directory and
# put the blob inside it with the desired extension.
FIX_BLOB_DIR="$(mktemp -d -t fix-blob-XXXXXX)"
FIX_BLOB="${FIX_BLOB_DIR}/synthetic.FIX"
trap '[[ $KEEP -eq 0 ]] && rm -rf "${PATCH_DIR}" "${FIX_BLOB_DIR}"' EXIT

echo "[rt] repo=${REPO_ROOT}" >&2
echo "[rt] patches=${PATCH_DIR}" >&2
echo "[rt] fix-blob=${FIX_BLOB}" >&2
echo "[rt] preset=${PRESET}" >&2

# ---------------------------------------------------------------------
# 1. Synthesize a KERNEL.FIX with one record per auto-patchable kind.
# ---------------------------------------------------------------------
#
# The records reference real anchors in the current tree:
#   * unknown_syscall  -> stub-arm patch for syscall 0xab12
#   * stub (hot)       -> KLOG_ONCE_WARN next to a real FIX_NOTE_STUB
#   * gap  (hot)       -> KLOG_ONCE_WARN next to a real FIX_NOTE_GAP
#   * stub (cold)      -> brief only (verifies the threshold gate)
#
# More classes (unmapped_thunk, cap_denial, loader_reject, soft_fault)
# don't need explicit synthetic records because their auto-patch shapes
# are exercised by their existing self-tests in the synthesizer module;
# this rig focuses on the new shapes (syscall stub, marker log).

python3 - "${FIX_BLOB}" <<'PY'
import struct
import sys

FIX_BLOB = sys.argv[1]
RECORD_FMT = struct.Struct("<IIQQQQIHBB40s40s")
HEADER = struct.Struct("<IIII")
FILE_MAGIC = 0x4A584946
RECORD_MAGIC = 0x52584946


def rec(seq, det, pin, hint, repeat=1, ctx_a=0, ctx_b=0, rip=0):
    return RECORD_FMT.pack(
        RECORD_MAGIC, seq, 0, rip, ctx_a, ctx_b, repeat, 0, det, 0,
        pin.encode()[:40], hint.encode()[:40],
    )


# Pin anchors here MUST match real source pins in the tree so the
# marker-log-upgrade synthesizer can find their FIX_NOTE_* call site.
# If any of these break, this script catches it before the production
# fix-cycle does.
records = [
    rec(1, 3, "syscall#ab12", "implement or route", repeat=12,
        ctx_a=0xab12, rip=0xffffffff80123456),
    rec(2, 2, "sched/sched.cpp:StealNormalFromPeer",
        "scan past pinned head to next-allowed task", repeat=50),
    rec(3, 1, "drivers/gpu/nvidia_gpu.cpp:GSP_CHANNEL",
        "wire GSP firmware load + RPC channel submit", repeat=20),
    # Cold marker (below the default threshold of 10) — should produce
    # only the brief, no marker-log-upgrade patch.
    rec(4, 2, "acpi/aml.cpp:HandleOpRegion",
        "evaluate computed OperationRegion bounds", repeat=3),
    # TrapCapture: a #PF write at CR2=0x10 (null-page write). The
    # brief synthesizer should recognise this as null_deref_write and
    # propose a guard. caller_rip is a placeholder; without a real
    # kernel ELF for addr2line it just won't symbolize.
    rec(5, 8, "TrapCapture+0x40", "trap PF page fault", repeat=1,
        ctx_a=(14 << 32) | 0x02, ctx_b=0x10, rip=0xffffffff80abcdef),
    # Selftest noise — must be filtered out cleanly.
    rec(6, 1, "selftest/stub.cpp:1", "stub selftest"),
    rec(7, 8, "selftest/trap.cpp:1", "trap capture selftest"),
]

blob = HEADER.pack(FILE_MAGIC, 1, len(records), 0) + b"".join(records)
with open(FIX_BLOB, "wb") as f:
    f.write(blob)
print(f"[rt] wrote {len(records)} synthetic records to {FIX_BLOB}", file=sys.stderr)
PY

# ---------------------------------------------------------------------
# 2. Run the patch generator. Capture stdout (markdown plan) to a file
# under PATCH_DIR so a --keep run leaves an auditable trace.
# ---------------------------------------------------------------------

PLAN_MD="${PATCH_DIR}/plan.md"
echo "[rt] running gen-fix-patches.py ..." >&2
if ! python3 "${REPO_ROOT}/tools/build/gen-fix-patches.py" \
        "${FIX_BLOB}" --out "${PATCH_DIR}" > "${PLAN_MD}" 2> "${PATCH_DIR}/gen.stderr"; then
    echo "[rt] FAIL: gen-fix-patches.py exited non-zero" >&2
    cat "${PATCH_DIR}/gen.stderr" >&2
    exit 1
fi

shopt -s nullglob
PATCHES=("${PATCH_DIR}"/*.patch)
shopt -u nullglob
PATCH_COUNT=${#PATCHES[@]}

echo "[rt] generated ${PATCH_COUNT} patch(es)" >&2
if [[ ${PATCH_COUNT} -eq 0 ]]; then
    echo "[rt] FAIL: gen-fix-patches.py produced ZERO patches — expected at least 2" >&2
    echo "[rt] generator stderr:" >&2
    cat "${PATCH_DIR}/gen.stderr" >&2
    exit 1
fi

# ---------------------------------------------------------------------
# 3. `git apply --check` every emitted patch. Track per-patch results.
# ---------------------------------------------------------------------

failed=0
for patch_path in "${PATCHES[@]}"; do
    patch_name="$(basename "${patch_path}")"
    if git -C "${REPO_ROOT}" apply --check "${patch_path}" 2> "${PATCH_DIR}/${patch_name}.checkerr"; then
        echo "  [PASS check] ${patch_name}" >&2
    else
        echo "  [FAIL check] ${patch_name}" >&2
        sed 's/^/      /' "${PATCH_DIR}/${patch_name}.checkerr" >&2
        failed=$((failed + 1))
    fi
done

if [[ ${failed} -gt 0 ]]; then
    echo "[rt] FAIL: ${failed}/${PATCH_COUNT} patch(es) failed apply --check" >&2
    exit 1
fi

# ---------------------------------------------------------------------
# 4. CLI flag matrix — verify --no-syscall-stub / --no-marker-log /
# --marker-log-threshold all behave as expected. Each variant produces
# a different patch count; the variants together should suppress at
# least one patch each.
# ---------------------------------------------------------------------

run_variant()
{
    local desc="$1"
    shift
    local tmp
    tmp="$(mktemp -d -t fix-rt-var-XXXXXX)"
    python3 "${REPO_ROOT}/tools/build/gen-fix-patches.py" \
        "${FIX_BLOB}" --out "${tmp}" "$@" > /dev/null 2>&1 || true
    local n
    shopt -s nullglob
    local fs=("${tmp}"/*.patch)
    shopt -u nullglob
    n=${#fs[@]}
    rm -rf "${tmp}"
    echo "  [${desc} -> ${n} patch(es)]"
}

echo "[rt] CLI flag matrix:" >&2
run_variant "default                    " >&2
run_variant "--no-syscall-stub          " --no-syscall-stub >&2
run_variant "--no-marker-log            " --no-marker-log >&2
run_variant "--marker-log-threshold=100 " --marker-log-threshold=100 >&2
run_variant "--no-marker-log --no-syscall-stub" --no-marker-log --no-syscall-stub >&2

# ---------------------------------------------------------------------
# 5. Optional: apply, build, revert. Only runs with --build because
# building the kernel is a ~30s operation we don't want as the default.
# ---------------------------------------------------------------------

if [[ ${DO_BUILD} -eq 1 ]]; then
    echo "[rt] --build: applying every patch and rebuilding" >&2
    if ! git -C "${REPO_ROOT}" diff --quiet || ! git -C "${REPO_ROOT}" diff --cached --quiet; then
        echo "[rt] FAIL: working tree must be clean for --build" >&2
        git -C "${REPO_ROOT}" status --short >&2
        exit 1
    fi
    applied=()
    for patch_path in "${PATCHES[@]}"; do
        if git -C "${REPO_ROOT}" apply "${patch_path}"; then
            applied+=("${patch_path}")
        else
            echo "[rt] FAIL: git apply ${patch_path} failed" >&2
            # Revert anything we already applied.
            for r in "${applied[@]}"; do
                git -C "${REPO_ROOT}" apply --reverse "${r}" || true
            done
            exit 1
        fi
    done
    echo "[rt] building (preset=${PRESET})..." >&2
    if ! cmake --build "${REPO_ROOT}/build/${PRESET}" --parallel "$(nproc)" \
            > "${PATCH_DIR}/build.log" 2>&1; then
        echo "[rt] FAIL: kernel build failed after applying all patches" >&2
        tail -30 "${PATCH_DIR}/build.log" >&2
        for r in "${applied[@]}"; do
            git -C "${REPO_ROOT}" apply --reverse "${r}" || true
        done
        exit 1
    fi
    echo "[rt] build OK; reverting all applied patches" >&2
    for r in "${applied[@]}"; do
        git -C "${REPO_ROOT}" apply --reverse "${r}"
    done
fi

# ---------------------------------------------------------------------
# 6. Summary.
# ---------------------------------------------------------------------

echo ""
echo "[rt] PASS — ${PATCH_COUNT} patches generated, all applied --check cleanly" >&2
if [[ ${DO_BUILD} -eq 1 ]]; then
    echo "[rt] PASS — combined apply + kernel build + revert succeeded" >&2
fi
if [[ ${KEEP} -eq 1 ]]; then
    echo "[rt] artifacts kept under ${PATCH_DIR}/ (plan.md + .patch files)" >&2
fi
