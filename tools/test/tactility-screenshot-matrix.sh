#!/usr/bin/env bash
#
# tactility-screenshot-matrix.sh - per-theme visual regression
# capture (Phase 5 Task 25 of the chrome-tactility plan).
#
# WHAT IT DOES
#   Boots the kernel once per theme (10 boots total), captures a
#   desktop screenshot of each via QEMU's `screendump` monitor
#   command, and (if ImageMagick is available) tiles them into a
#   5x2 contact sheet for side-by-side review. Catches visual
#   regressions the [shadow|blend|theme]-selftest sentinels can't
#   see - e.g. a missed paint path that leaves a window opaque
#   when tactility is supposed to dim it.
#
# USAGE
#   tools/test/tactility-screenshot-matrix.sh
#
# OUTPUT
#   $DUETOS_LOG_DIR/shots/<theme>.ppm        per-theme screenshot
#   $DUETOS_LOG_DIR/shots/<theme>.log        per-theme boot log
#   $DUETOS_LOG_DIR/tactility-matrix.png     5x2 contact sheet
#                                            (only if `montage` is on PATH)
#
# ENV
#   DUETOS_LOG_DIR  -- output root (default: build)
#   DUETOS_TIMEOUT  -- per-theme boot timeout (default: 15s)
#
# EXIT 0 = every theme booted + a screenshot landed for each.
#      1 = at least one theme failed to produce a screenshot.
#      2 = boot tooling missing (qemu / run.sh).
#
# NOTE: The `DUETOS_SCREENDUMP=<file>` env var is consumed by
# tools/qemu/run.sh's QMP screendump hook (or a similar capture
# point added in Phase 5). If the hook isn't wired yet, the boot
# log is still captured for triage.

set -euo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

readonly THEMES=(
    classic
    slate10
    amber
    duet
    duetlight
    duetblue
    duetviolet
    duetgreen
    duetclassic
    highcontrast
)

LOG_DIR="${DUETOS_LOG_DIR:-${REPO_ROOT}/build}"
SHOTS_DIR="${LOG_DIR}/shots"
PER_THEME_TIMEOUT="${DUETOS_TIMEOUT:-15}"

if [[ ! -x "${REPO_ROOT}/tools/qemu/run.sh" ]]
then
    echo "ERROR: ${REPO_ROOT}/tools/qemu/run.sh missing or not executable" >&2
    exit 2
fi

mkdir -p "${SHOTS_DIR}"

failed=0
for theme in "${THEMES[@]}"
do
    shot="${SHOTS_DIR}/${theme}.ppm"
    log="${SHOTS_DIR}/${theme}.log"

    echo "[shots] capturing ${theme}..."
    rm -f "${shot}"

    DUETOS_TIMEOUT="${PER_THEME_TIMEOUT}" DUETOS_SCREENDUMP="${shot}" \
        "${REPO_ROOT}/tools/qemu/run.sh" \
        -append "theme=${theme} tactility=auto" \
        > "${log}" 2>&1 || true

    if [[ ! -s "${shot}" ]]
    then
        echo "  WARN: ${theme} produced no screenshot (see ${log})" >&2
        ((failed++)) || true
    fi
done

if command -v montage >/dev/null 2>&1
then
    montage "${SHOTS_DIR}"/*.ppm \
        -tile 5x2 -geometry +4+4 -label '%t' \
        "${LOG_DIR}/tactility-matrix.png"
    echo "[shots] grid: ${LOG_DIR}/tactility-matrix.png"
else
    echo "[shots] WARN: imagemagick (montage) missing; raw PPMs in ${SHOTS_DIR}" >&2
fi

if [[ ${failed} -gt 0 ]]
then
    echo "[shots] FAIL: ${failed}/${#THEMES[@]} themes produced no screenshot" >&2
    exit 1
fi

echo "[shots] OK (${#THEMES[@]}/${#THEMES[@]} themes)"
