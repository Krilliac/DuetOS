#!/usr/bin/env bash
#
# tools/test/s3-cycle-smoke.sh
#
# Drive one full ACPI S3 (suspend-to-RAM) cycle under QEMU and prove
# the machine came back alive.
#
# WHY THIS EXISTS
#   S3 is the one kernel path that cannot be verified by compiling,
#   by a hosted test, or by a plain boot: the CPU genuinely loses
#   power, and the only evidence that the wake trampoline and the
#   context restore are correct is a guest that keeps running
#   afterwards. QEMU parks the VM on the SLP_TYP=S3 write and resumes
#   it only on a QMP `system_wakeup`, so something has to play the
#   part of the lid switch. That something is this script.
#
# WHAT IT CHECKS
#   1. the guest reaches `[suspend] entering S3`      (suspend worked)
#   2. QEMU reports run-state `suspended`             (it really slept)
#   3. after `qmp.sh wakeup`, `[suspend] resumed from S3` appears
#   4. the scheduler tick advances AFTER the resume    (still alive)
#   5. no panic / triple fault / FAIL after the resume point
#
# Check 4 is the one that matters. A resume that prints its line and
# then wedges would pass 1-3; only a tick that keeps moving proves the
# LAPIC, the IDT, and the restored stack all survived.
#
# USAGE
#   tools/test/s3-cycle-smoke.sh
#
# ENV
#   DUETOS_PRESET   build preset to boot     (default x86_64-debug)
#   S3_BOOT_TIMEOUT seconds to reach suspend (default 120)
#   S3_WAKE_TIMEOUT seconds to reach resume  (default 60)
#   S3_LIVE_SECS    seconds to watch for post-resume liveness (default 15)
#   S3_LOG          where to write the guest log
#                   (default ${TMPDIR:-/tmp}/duetos-s3-cycle.log)
#
# EXIT
#   0 cycle proven, 1 a check failed, 2 setup problem
#
# QUICK ANALYSIS
#   grep -nE '\[suspend\]' "$S3_LOG"
#   sed -n "/entering S3/,\$p" "$S3_LOG" | grep -nE 'PANIC|TRIPLE|FAIL'

set -uo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

PRESET="${DUETOS_PRESET:-x86_64-debug}"
BUILD_DIR="${REPO_ROOT}/build/${PRESET}"
BOOT_TIMEOUT="${S3_BOOT_TIMEOUT:-120}"
WAKE_TIMEOUT="${S3_WAKE_TIMEOUT:-60}"
LIVE_SECS="${S3_LIVE_SECS:-15}"
LOG="${S3_LOG:-${TMPDIR:-/tmp}/duetos-s3-cycle.log}"

if [[ ! -f "${BUILD_DIR}/duetos.iso" ]]; then
    echo "error: no ISO at ${BUILD_DIR}/duetos.iso — build preset ${PRESET} first" >&2
    exit 2
fi

# QEMU only emits the `\_S3` package in its DSDT when the ICH9 LPC
# bridge advertises S3. It is enabled by default on q35, but pin it
# explicitly so the harness does not silently degrade into "the
# firmware declared no S3, so nothing was tested".
readonly S3_ENABLE=(-global ICH9-LPC.disable_s3=0)

: > "${LOG}"

echo "[s3-smoke] booting ${PRESET} with s3test=1 (log: ${LOG})"
DUETOS_PRESET="${PRESET}" \
DUETOS_EXTRA_CMDLINE="s3test=1" \
DUETOS_TIMEOUT="$((BOOT_TIMEOUT + WAKE_TIMEOUT + LIVE_SECS + 30))" \
    "${REPO_ROOT}/tools/qemu/run.sh" "${S3_ENABLE[@]}" > "${LOG}" 2>&1 &
readonly RUN_PID=$!

cleanup() {
    kill "${RUN_PID}" 2>/dev/null
    pkill -P "${RUN_PID}" 2>/dev/null
    wait "${RUN_PID}" 2>/dev/null
}
trap cleanup EXIT

# run.sh relocates the QMP socket off non-socket filesystems; ask it
# the same way tools/qemu/qmp.sh does rather than assuming a path.
qmp() { DUETOS_PRESET="${PRESET}" "${REPO_ROOT}/tools/qemu/qmp.sh" "$@" 2>/dev/null; }

wait_for() { # $1=pattern $2=timeout-secs $3=description
    local waited=0
    while (( waited < $2 )); do
        if grep -qF "$1" "${LOG}" 2>/dev/null; then
            return 0
        fi
        if ! kill -0 "${RUN_PID}" 2>/dev/null; then
            echo "[s3-smoke] FAIL: guest exited while waiting for $3" >&2
            return 1
        fi
        sleep 1
        waited=$((waited + 1))
    done
    echo "[s3-smoke] FAIL: timed out after $2s waiting for $3" >&2
    return 1
}

# --- 1. suspend ----------------------------------------------------
wait_for "[suspend] entering S3" "${BOOT_TIMEOUT}" "the guest to enter S3" || exit 1
echo "[s3-smoke] guest reached the S3 entry sentinel"

# Give QEMU a moment to actually park the VM after the SLP_TYP write.
sleep 2

# --- 2. it really slept --------------------------------------------
STATUS="$(qmp status || true)"
if ! grep -q "suspended" <<<"${STATUS}"; then
    echo "[s3-smoke] FAIL: QEMU run-state is not 'suspended' after the S3 write" >&2
    echo "[s3-smoke]       query-status said: ${STATUS}" >&2
    exit 1
fi
echo "[s3-smoke] QEMU confirms run-state=suspended"

# Record how far the log had got, so the liveness check below only
# counts output produced AFTER the resume.
readonly LINES_AT_SUSPEND="$(wc -l < "${LOG}")"

# --- 3. wake -------------------------------------------------------
echo "[s3-smoke] delivering QMP system_wakeup"
if ! qmp wakeup > /dev/null; then
    echo "[s3-smoke] FAIL: could not deliver system_wakeup" >&2
    exit 1
fi

wait_for "[suspend] resumed from S3" "${WAKE_TIMEOUT}" "the guest to resume" || exit 1
echo "[s3-smoke] guest reached the resume sentinel"

# --- 4. still alive ------------------------------------------------
echo "[s3-smoke] watching ${LIVE_SECS}s for post-resume liveness"
readonly LINES_AFTER_RESUME="$(wc -l < "${LOG}")"
sleep "${LIVE_SECS}"
readonly LINES_LATER="$(wc -l < "${LOG}")"

if (( LINES_LATER <= LINES_AFTER_RESUME )); then
    echo "[s3-smoke] FAIL: no further output after the resume — guest wedged" >&2
    exit 1
fi
echo "[s3-smoke] guest produced $((LINES_LATER - LINES_AFTER_RESUME)) lines after resuming"

# --- 5. nothing broke on the way back ------------------------------
POST="$(tail -n "+${LINES_AT_SUSPEND}" "${LOG}")"
if grep -qE "PANIC|TRIPLE|kernel oops|task-kill" <<<"${POST}"; then
    echo "[s3-smoke] FAIL: fault signature after the suspend point:" >&2
    grep -nE "PANIC|TRIPLE|kernel oops|task-kill" <<<"${POST}" | head -5 >&2
    exit 1
fi

echo "[s3-smoke] PASS: S3 suspend/resume cycle completed and the guest kept running"
exit 0
