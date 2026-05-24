#!/usr/bin/env bash
#
# tactility-screenshot-matrix.sh - boot the kernel and capture a
# desktop PPM via QEMU's QMP `screendump` (Phase 5 Task 25 of the
# chrome-tactility plan).
#
# v1 SCOPE
#   Single boot, single screenshot of the default-theme desktop.
#   The "matrix" naming is aspirational - the per-theme variant
#   would need either (a) per-theme ISO rebuilds (the kernel
#   cmdline is baked into grub.cfg at ISO build time; QEMU's
#   `-append` is `-kernel`-only) or (b) sending Ctrl+Alt+Y via
#   QMP `send-key` between screenshots to cycle through the 10
#   themes. (a) is the cleaner long-term path; both are deferred
#   until visual regression actually fires once.
#
# USAGE
#   tools/test/tactility-screenshot-matrix.sh [theme-label]
#     theme-label  -- string used in the output filename only;
#                     does not change which theme actually boots
#                     (default: "default").
#
# ENV
#   DUETOS_PRESET   -- build preset (default: x86_64-debug-fast,
#                      since this is for visual / self-test
#                      verification rather than production)
#   DUETOS_LOG_DIR  -- output root (default: build)
#   DUETOS_TIMEOUT  -- boot timeout, seconds (default: 25)
#
# OUTPUT
#   $DUETOS_LOG_DIR/shots/<theme-label>.ppm   captured PPM
#   $DUETOS_LOG_DIR/shots/<theme-label>.log   boot log
#
# EXIT 0 = boot reached the tactility-selftest umbrella PASS line
#          and the screendump landed a non-empty PPM.
#      1 = boot did not reach the umbrella, OR screendump returned
#          nothing.
#      2 = required tooling missing.

set -euo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

LABEL="${1:-default}"
PRESET="${DUETOS_PRESET:-x86_64-debug-fast}"
LOG_DIR="${DUETOS_LOG_DIR:-${REPO_ROOT}/build}"
SHOTS_DIR="${LOG_DIR}/shots"
TIMEOUT="${DUETOS_TIMEOUT:-25}"

PPM="${SHOTS_DIR}/${LABEL}.ppm"
BOOT_LOG="${SHOTS_DIR}/${LABEL}.log"

if [[ ! -x "${REPO_ROOT}/tools/qemu/run.sh" ]] || [[ ! -x "${REPO_ROOT}/tools/qemu/qmp.sh" ]]
then
    echo "ERROR: tools/qemu/{run,qmp}.sh missing or not executable" >&2
    exit 2
fi
command -v qemu-system-x86_64 >/dev/null || { echo "ERROR: qemu-system-x86_64 missing" >&2; exit 2; }

mkdir -p "${SHOTS_DIR}"
rm -f "${PPM}" "${BOOT_LOG}"

echo "[shots] booting preset=${PRESET} timeout=${TIMEOUT}s label=${LABEL}"

# Launch run.sh as a background job; capture its serial output to
# the boot log. The QMP socket comes up shortly after QEMU starts;
# we poll the boot log for the tactility umbrella PASS before
# issuing screendump.
DUETOS_PRESET="${PRESET}" DUETOS_TIMEOUT="${TIMEOUT}" \
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

# Wait for the tactility-selftest umbrella PASS to land — that's
# the signal that bringup ran every self-test in order, which
# means the desktop chrome has been painted at least once and is
# ready for screendump.
DEADLINE=$((SECONDS + TIMEOUT))
while [[ ${SECONDS} -lt ${DEADLINE} ]]
do
    if grep -q '\[tactility-selftest\] PASS' "${BOOT_LOG}" 2>/dev/null
    then
        break
    fi
    sleep 1
done

if ! grep -q '\[tactility-selftest\] PASS' "${BOOT_LOG}" 2>/dev/null
then
    echo "[shots] FAIL: tactility-selftest umbrella PASS never landed in ${BOOT_LOG}" >&2
    exit 1
fi

# Small additional pause so the compositor's idle redraw finishes
# before we sample — without this the screendump can catch a
# mid-paint frame.
sleep 2

# Capture via qmp.sh (writes PPM straight to disk).
DUETOS_PRESET="${PRESET}" "${REPO_ROOT}/tools/qemu/qmp.sh" screenshot "${PPM}" || {
    echo "[shots] FAIL: qmp.sh screenshot returned non-zero" >&2
    exit 1
}

if [[ ! -s "${PPM}" ]]
then
    echo "[shots] FAIL: screendump produced no bytes (${PPM})" >&2
    exit 1
fi

echo "[shots] OK: ${PPM}"
echo "[shots]     boot log: ${BOOT_LOG}"
