#!/usr/bin/env bash
#
# hc-force-on-capture.sh — capture a HighContrast desktop with
# `tactility=on` runtime override forcing the chrome-tactility
# code paths ON despite the theme's opt-out. Used to verify
# (post-codex-fix) that the override actually renders visible
# chrome on opt-out themes.
#
# USAGE
#   tools/test/hc-force-on-capture.sh [out.ppm]
#     out.ppm  -- output PPM path (default: build/hc-force-on.ppm)
#
# EXIT 0 = boot reached the tactility-selftest umbrella AND PPM
#          landed non-empty.

set -euo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

OUT="${1:-${REPO_ROOT}/build/hc-force-on.ppm}"
PRESET="${DUETOS_PRESET:-x86_64-debug-fast}"
TIMEOUT="${DUETOS_TIMEOUT:-30}"
BOOT_LOG="${OUT%.ppm}.log"

mkdir -p "$(dirname "${OUT}")"
rm -f "${OUT}" "${BOOT_LOG}"

DUETOS_PRESET="${PRESET}" DUETOS_TIMEOUT="${TIMEOUT}" \
    DUETOS_EXTRA_CMDLINE="theme=highcontrast tactility=on" \
    "${REPO_ROOT}/tools/qemu/run.sh" > "${BOOT_LOG}" 2>&1 &
RUN_PID=$!

cleanup() {
    if kill -0 "${RUN_PID}" 2>/dev/null
    then
        DUETOS_PRESET="${PRESET}" "${REPO_ROOT}/tools/qemu/qmp.sh" quit >/dev/null 2>&1 || true
        sleep 1
        kill "${RUN_PID}" 2>/dev/null || true
    fi
    wait "${RUN_PID}" 2>/dev/null || true
}
trap cleanup EXIT

deadline=$((SECONDS + TIMEOUT))
while [[ ${SECONDS} -lt ${deadline} ]]
do
    if grep -q '\[tactility-selftest\] PASS' "${BOOT_LOG}" 2>/dev/null
    then
        break
    fi
    sleep 1
done
sleep 2

DUETOS_PRESET="${PRESET}" "${REPO_ROOT}/tools/qemu/qmp.sh" screenshot "${OUT}" >/dev/null 2>&1 || true

if [[ -s "${OUT}" ]]
then
    echo "[force-on] OK: ${OUT} ($(stat -c %s "${OUT}") bytes)"
    echo "[force-on] boot log: ${BOOT_LOG}"
else
    echo "[force-on] FAIL: no PPM captured (see ${BOOT_LOG})" >&2
    exit 1
fi
