#!/usr/bin/env bash
#
# hc-boot-determinism.sh — runs the same HighContrast boot twice and
# diffs the captured PPMs. Measures the INHERENT inter-boot pixel
# variation (clock display, uptime ticker, network state, cursor
# anti-aliasing position from PS/2 timing, etc.) so a later
# tactility=auto-vs-off comparison can correctly distinguish a
# real chrome-paint regression from baseline boot-time noise.
#
# WHAT IT MEASURES
#   Two identical boots × HighContrast theme. Both runs land on
#   the chrome-tactility fallback path (theme.tactility_enabled=
#   false → ThemeTactilityEffective=false → else branch in every
#   *Shadow site). If the diff between two same-config boots is
#   N pixels, then any tactility=on-vs-off comparison should
#   accept diffs ≤ N as "within boot-determinism noise."
#
# USAGE
#   tools/test/hc-boot-determinism.sh
#
# OUTPUT
#   build/hc-determinism/run-1.ppm  build/hc-determinism/run-1.log
#   build/hc-determinism/run-2.ppm  build/hc-determinism/run-2.log
#
# EXIT 0 always — this is a measurement, not a pass/fail check.
#        Prints the diff count on the last line for downstream
#        consumption.

set -euo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

PRESET="${DUETOS_PRESET:-x86_64-debug-fast}"
LOG_DIR="${DUETOS_LOG_DIR:-${REPO_ROOT}/build}"
OUT_DIR="${LOG_DIR}/hc-determinism"
TIMEOUT="${DUETOS_TIMEOUT:-30}"

mkdir -p "${OUT_DIR}"
rm -f "${OUT_DIR}"/*.ppm "${OUT_DIR}"/*.log

run_one() {
    local idx="$1"
    local ppm="${OUT_DIR}/run-${idx}.ppm"
    local log="${OUT_DIR}/run-${idx}.log"

    echo "[hc-determinism] boot ${idx}/2 (theme=highcontrast)"
    DUETOS_PRESET="${PRESET}" DUETOS_TIMEOUT="${TIMEOUT}" \
        DUETOS_EXTRA_CMDLINE="theme=highcontrast" \
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

    # Ensure the previous boot fully ends before the next one
    # starts — otherwise the second boot would collide on the QMP
    # socket path and run.sh's `rm -f "${QMP_SOCK}"` would yank it
    # out from under the still-running first instance.
    sleep 1
    kill "${run_pid}" 2>/dev/null || true
    wait "${run_pid}" 2>/dev/null || true
    # Extra settling before the NEXT boot so the QMP socket file
    # has been unlinked + the cdrom file is no longer held.
    sleep 2
}

run_one 1
run_one 2

DIFF="?"
if [[ -s "${OUT_DIR}/run-1.ppm" && -s "${OUT_DIR}/run-2.ppm" ]] && command -v compare >/dev/null
then
    # compare exits non-zero whenever images differ (returns the
    # AE count, capped at 1). Wrap in a no-fail subshell so the
    # script's set -e doesn't trip, then strip everything after
    # the leading integer.
    raw="$( { compare -metric AE "${OUT_DIR}/run-1.ppm" "${OUT_DIR}/run-2.ppm" /dev/null 2>&1 || true; } | head -1)"
    raw="${raw%% *}"
    DIFF="${raw:-?}"
fi

echo "[hc-determinism] inter-boot pixel diff: ${DIFF}"
