#!/usr/bin/env bash
#
# hc-invariant-check.sh — empirical proof that the chrome-tactility
# fallback path on HighContrast leaves the rendered chrome bit-for-
# bit identical (within boot-determinism noise) regardless of
# whether tactility is auto-resolved (theme says off) or runtime-
# overridden off. Both paths should hit the same `else` branch in
# every chrome shadow site (window / dialog / menu / calendar /
# netpanel / tray flyout / login panel), so the resulting PPM
# should diff only by the live-widget noise the boot-determinism
# measurement establishes.
#
# WHAT IT PROVES
#   The chrome-tactility plan §8.5 step 6 invariant ("HighContrast
#   pixel-diff vs pre-spec confirms ZERO chrome change") in a form
#   we can verify without a pre-spec baseline: HighContrast's theme-
#   matrix opt-out (`tactility_enabled = false`) means every paint
#   site in the chrome routes through the legacy DropShadow / Blend*
#   fallback path. If the auto-vs-override diff stays within
#   boot-determinism noise (clock display, uptime ticker, network-
#   state widget, cursor anti-aliasing pos), the invariant holds.
#
# METHOD
#   1. Establish a noise floor via two identical HC boots (live
#      widgets vary; chrome should be identical).
#   2. Capture HC under tactility=auto (theme says off, override=-1).
#   3. Capture HC under tactility=off (override forces off).
#   4. Compare. PASS if diff <= 2 × noise floor + 32 px slack.
#
#   The 2× headroom accommodates that the three boots in step 1-3
#   may each have slightly different clock/ticker state; the +32
#   slack swallows a single misaligned glyph.
#
# USAGE
#   tools/test/hc-invariant-check.sh
#
# EXIT 0 = diff within noise floor — invariant holds.
#      1 = diff exceeds the threshold — likely a real regression.
#      2 = required tooling missing.

set -euo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

PRESET="${DUETOS_PRESET:-x86_64-debug-fast}"
LOG_DIR="${DUETOS_LOG_DIR:-${REPO_ROOT}/build}"
OUT_DIR="${LOG_DIR}/hc-invariant"
TIMEOUT="${DUETOS_TIMEOUT:-30}"
SLACK_PX=32

command -v qemu-system-x86_64 >/dev/null || { echo "ERROR: qemu-system-x86_64 missing" >&2; exit 2; }
command -v compare >/dev/null || { echo "ERROR: imagemagick compare missing" >&2; exit 2; }

mkdir -p "${OUT_DIR}"
rm -f "${OUT_DIR}"/*.ppm "${OUT_DIR}"/*.log

capture() {
    local label="$1"
    local cmdline="$2"
    local ppm="${OUT_DIR}/${label}.ppm"
    local log="${OUT_DIR}/${label}.log"

    echo "[hc-invariant] boot ${label}: ${cmdline}"
    DUETOS_PRESET="${PRESET}" DUETOS_TIMEOUT="${TIMEOUT}" \
        DUETOS_EXTRA_CMDLINE="${cmdline}" \
        "${REPO_ROOT}/tools/qemu/run.sh" > "${log}" 2>&1 &
    local run_pid=$!

    local deadline=$((SECONDS + TIMEOUT))
    while [[ ${SECONDS} -lt ${deadline} ]]
    do
        if grep -q '\[tactility-selftest\] PASS' "${log}" 2>/dev/null
        then
            break
        fi
        sleep 1
    done
    sleep 2

    DUETOS_PRESET="${PRESET}" "${REPO_ROOT}/tools/qemu/qmp.sh" screenshot "${ppm}" >/dev/null 2>&1 || true
    DUETOS_PRESET="${PRESET}" "${REPO_ROOT}/tools/qemu/qmp.sh" quit >/dev/null 2>&1 || true
    sleep 1
    kill "${run_pid}" 2>/dev/null || true
    wait "${run_pid}" 2>/dev/null || true
    # Settle before the next boot so the QMP socket + cdrom file
    # are released (the next run.sh would otherwise `rm -f` the
    # socket out from under a still-exiting QEMU instance).
    sleep 2

    if [[ ! -s "${ppm}" ]]
    then
        echo "[hc-invariant] FAIL: ${label} produced no PPM" >&2
        exit 1
    fi
}

capture noise_a "theme=highcontrast"
capture noise_b "theme=highcontrast"
capture override "theme=highcontrast tactility=off"

# compare's exit code is non-zero whenever the images differ
# (it returns the diff count, capped at 1). Wrap in a function +
# `|| true` so pipefail doesn't trip the script, and parse the
# stderr (where compare prints the AE count) for the leading
# integer.
diff_px() {
    local raw
    raw="$( { compare -metric AE "$1" "$2" /dev/null 2>&1 || true; } | head -1)"
    # Strip everything after the first integer.
    raw="${raw%% *}"
    printf '%s' "${raw:-0}"
}

NOISE="$(diff_px "${OUT_DIR}/noise_a.ppm" "${OUT_DIR}/noise_b.ppm")"
TEST="$(diff_px "${OUT_DIR}/noise_a.ppm" "${OUT_DIR}/override.ppm")"

echo "[hc-invariant] noise floor (auto vs auto)         : ${NOISE} px"
echo "[hc-invariant] auto vs tactility=off override     : ${TEST} px"

if ! [[ "${NOISE}" =~ ^[0-9]+$ ]] || ! [[ "${TEST}" =~ ^[0-9]+$ ]]
then
    echo "[hc-invariant] FAIL: compare did not return integer counts" >&2
    exit 1
fi

THRESHOLD=$(( 2 * NOISE + SLACK_PX ))
echo "[hc-invariant] threshold (2 × noise + ${SLACK_PX} slack): ${THRESHOLD} px"

if [[ "${TEST}" -le "${THRESHOLD}" ]]
then
    echo "[hc-invariant] OK: auto-vs-override diff ${TEST} ≤ noise threshold ${THRESHOLD}"
    echo "[hc-invariant]     HighContrast opt-out invariant holds within boot-determinism noise."
    exit 0
fi

echo "[hc-invariant] FAIL: auto-vs-override diff ${TEST} exceeds threshold ${THRESHOLD}" >&2
echo "[hc-invariant]   — the tactility=off override changes HighContrast chrome" >&2
echo "[hc-invariant]     beyond what live-widget boot-time variation explains." >&2
exit 1
