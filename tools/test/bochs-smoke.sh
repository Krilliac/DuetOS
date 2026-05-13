#!/usr/bin/env bash
# tools/test/bochs-smoke.sh
#
# Profile-aware Bochs smoke runner. Counterpart to
# profile-boot-smoke.sh, with the same exit-code contract and the
# same signature lists. Bochs models stricter x86 semantics than
# QEMU/TCG (segment limits, undefined-flag propagation, IF/RF/NT,
# TLB shootdown ordering) — a profile that passes here but fails
# under QEMU/TCG, or vice versa, IS the bug.
#
# Exit codes:
#   0 — full pass.
#   1 — real regression.
#   2 — environment skip (Bochs / ROMs missing, kernel not built).
#
# Usage: bochs-smoke.sh <profile> <cmake-binary-dir>
#   profile = bringup | ring3 | pe-hello | pe-winapi | pe-winkill | linux

set -eo pipefail

if [[ $# -ne 2 ]]; then
    echo "usage: $0 <profile> <cmake-binary-dir>" >&2
    echo "   profile = bringup | ring3 | pe-hello | pe-winapi | pe-winkill | linux" >&2
    exit 2
fi

PROFILE="$1"
BIN_DIR="$2"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BOCHS_RUN="${REPO_ROOT}/tools/qemu/bochs-run.sh"

if [[ ! -x "${BOCHS_RUN}" ]]; then
    echo "SKIP: ${BOCHS_RUN} not found"
    exit 2
fi
if ! command -v bochs >/dev/null 2>&1; then
    echo "SKIP: bochs not installed"
    exit 2
fi

SERIAL_LOG="${BIN_DIR}/bochs-${PROFILE}.log"
rm -f "${SERIAL_LOG}"

# Bochs is single-threaded and runs the guest at ~1/8 the wall-
# clock speed of QEMU/TCG (which itself is ~50x slower than KVM).
# 900s is the comfortable default for a bringup-profile run; PE
# profiles may need to override higher.
#
# DUETOS_BUILD_DIR pins bochs-run.sh's BUILD_DIR to the BIN_DIR
# we were called with. Without this, bochs-run.sh derives
# BUILD_DIR from ${REPO_ROOT}/build/${PRESET}, which works when
# BIN_DIR's basename is a real preset name (x86_64-debug) but
# breaks when the diff-boot harness calls us against a per-row
# scratch dir whose basename is something like
# diff-bringup-D-bochs-core2-seabios.
DUETOS_PRESET="$(basename "${BIN_DIR}")" \
DUETOS_BUILD_DIR="${BIN_DIR}" \
DUETOS_TIMEOUT="${DUETOS_TIMEOUT:-900}" \
DUETOS_SMOKE_PROFILE="${PROFILE}" \
    "${BOCHS_RUN}" 2>&1 || true

# Bochs writes COM1 output to ${BIN_DIR}/bochs-${PROFILE}.log via
# the bochsrc we generated. If the file doesn't exist, the run
# never produced serial output — usually a Bochs startup failure.
if [[ ! -s "${SERIAL_LOG}" ]]; then
    echo "FAIL: serial log ${SERIAL_LOG} is empty (Bochs startup failed?)"
    echo "=== last 40 lines of bochs log ==="
    tail -40 "${BIN_DIR}/bochs-${PROFILE}.bxlog" 2>/dev/null || true
    exit 1
fi

# Same signature lists as profile-boot-smoke.sh. Keeping them
# duplicated rather than sourcing the other script — sharing them
# would couple two test drivers and make per-engine adjustments
# (e.g. a Bochs-specific known gap) clumsier than it needs to be.
common_expected=(
    "boot : metrics bringup-complete"
    "[smoke] profile=${PROFILE} complete"
    "[string-selftest] PASS"
    "[hexdump-selftest] PASS"
    "[fs/vfs] self-test OK"
)
forbidden=(
    "PANIC"
    "DUETOS CRASH"
    "triple fault"
    "[health] ESCALATE:"
)

case "${PROFILE}" in
    bringup)
        expected=("${common_expected[@]}")
        ;;
    ring3)
        expected=(
            "${common_expected[@]}"
            "DuetOS v0 (ramfs-seeded)"
            "Hello from ring 3!"
            'queued task name="ring3-smoke-A"'
            'queued task name="ring3-smoke-B"'
            'queued task name="ring3-smoke-sandbox"'
        )
        ;;
    pe-hello)
        expected=(
            "${common_expected[@]}"
            "[hello-pe] Hello from a PE executable!"
            'pe spawn name="ring3-hello-pe"'
        )
        ;;
    pe-winapi)
        expected=(
            "${common_expected[@]}"
            'pe spawn name="ring3-hello-winapi"'
            "[hello-winapi] printed via kernel32.WriteFile!"
            "[vcruntime140] memset+memcpy+memmove OK"
            "[heap] HeapAlloc + GetProcessHeap OK"
            "exit rc   val=0xbeef"
        )
        ;;
    pe-winkill)
        expected=(
            "${common_expected[@]}"
            'pe spawn name="ring3-winkill"'
            "Windows Kill "
        )
        ;;
    linux)
        expected=(
            "${common_expected[@]}"
            'linux'
        )
        ;;
    *)
        echo "error: unknown profile '${PROFILE}'" >&2
        exit 2
        ;;
esac

banner=$(grep -aF '[boot] DuetOS build flavor:' "${SERIAL_LOG}" | head -1 || true)
selftests_on=0
if [[ "${banner}" == *"+selftests"* ]]; then
    selftests_on=1
fi
echo "bochs-smoke: profile=${PROFILE} banner=${banner:-<missing>}"
echo "bochs-smoke: selftests_on=${selftests_on}"

selftest_sigs=(
    "[string-selftest] PASS"
    "[hexdump-selftest] PASS"
    "[fs/vfs] self-test OK"
)

fail=0
missing=()
for sig in "${expected[@]}"; do
    if [[ ${selftests_on} -eq 0 ]]; then
        is_selftest_sig=0
        for ss in "${selftest_sigs[@]}"; do
            if [[ "$sig" == "$ss" ]]; then is_selftest_sig=1; break; fi
        done
        if [[ ${is_selftest_sig} -eq 1 ]]; then
            continue
        fi
    fi
    if ! grep -aF "$sig" "${SERIAL_LOG}" >/dev/null; then
        missing+=("$sig")
        fail=1
    fi
done
for sig in "${forbidden[@]}"; do
    if grep -aF "$sig" "${SERIAL_LOG}" >/dev/null; then
        echo "FORBIDDEN (present): $sig"
        grep -aF "$sig" "${SERIAL_LOG}" | head -3
        fail=1
    fi
done

if [[ $fail -ne 0 ]]; then
    for m in "${missing[@]}"; do
        echo "MISSING: $m"
    done
    echo "=== last 200 lines of serial log (${SERIAL_LOG}) ==="
    tail -200 "${SERIAL_LOG}" || true
    echo "=== expected signature presence map ==="
    for sig in "${expected[@]}"; do
        if grep -aF "$sig" "${SERIAL_LOG}" >/dev/null; then
            printf '  PRESENT : %s\n' "$sig"
        else
            printf '  MISSING : %s\n' "$sig"
        fi
    done
    exit 1
fi

echo "OK: profile=${PROFILE} — all ${#expected[@]} signatures present (bochs)."
exit 0
