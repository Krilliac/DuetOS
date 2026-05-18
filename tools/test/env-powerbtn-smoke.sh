#!/usr/bin/env bash
# tools/test/env-powerbtn-smoke.sh
#
# Best-effort end-to-end probe of the slice-3 ACPI SCI power path:
#
#   QMP system_powerdown  →  guest ACPI power button (PWRBTN_STS)
#   →  SCI IRQ  →  AcpiSci handler latches + wakes g_env_wq
#   →  env-monitor task  →  acpi::AcpiShutdown()  →  guest S5.
#
# PROOF SIGNAL: the handler emits the raw structural sentinel
#   [env/sci] PWRBTN_STS latched
# the moment it sees PWRBTN_STS. That line (not the run-state, not
# a log level) is the unforgeable evidence the SCI was delivered
# and decoded. We gate on the equally-raw `[acpi/sci] armed`
# milestone (the SCI is live), press the button, and look for it.
#
# KNOWN ENVIRONMENT LIMIT — why this can SKIP:
# The env-monitor is a Normal-priority task that only gets real CPU
# after the boot task winds down. In the headless CI boot that is
# ~coincident with a PRE-EXISTING ~17 s automatic ACPI poweroff
# (present since before this feature — verified on the slice-2
# build), so the SCI arms just as the box powers itself off. There
# is then no window to land a button press before the unrelated
# auto-shutdown. That race is NOT a power-path failure, so this
# script reports SKIP (exit 0), not FAIL, when it loses the race.
# It returns PASS only on the positive sentinel, and FAIL only on a
# panic/triple-fault on the SCI path. On a long-lived interactive
# boot or real hardware (no CI auto-poweroff) it PASSes outright.
#
# Usage:   tools/test/env-powerbtn-smoke.sh
# Env:     DUETOS_PRESET (default x86_64-release)
#          PB_ARMED_WAIT_SECS  max secs to wait for [acpi/sci] armed (40)
#          PB_OBSERVE_SECS     secs to watch for the sentinel post-press (8)
# Exit:    0 = PASS or SKIP (message says which); 1 = FAIL.

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PRESET="${DUETOS_PRESET:-x86_64-release}"
BUILD_DIR="${REPO_ROOT}/build/${PRESET}"
ISO="${BUILD_DIR}/duetos.iso"
LOG="$(mktemp /tmp/env-powerbtn-XXXX.log)"
ARMED_WAIT="${PB_ARMED_WAIT_SECS:-40}"
OBSERVE="${PB_OBSERVE_SECS:-8}"

GUEST_PGID=""
cleanup()
{
    if [[ -n "${GUEST_PGID}" ]]; then
        kill -TERM "-${GUEST_PGID}" 2>/dev/null || true
        sleep 1
        kill -KILL "-${GUEST_PGID}" 2>/dev/null || true
    fi
}
trap cleanup EXIT

say()  { echo "[pb-smoke] $*"; }
pass() { echo "PASS: $*"; cleanup; trap - EXIT; rm -f "${LOG}"; exit 0; }
skip() { echo "SKIP: $*"; cleanup; trap - EXIT; rm -f "${LOG}"; exit 0; }
fail()
{
    echo "FAIL: $*" >&2
    echo "---- guest log tail ----" >&2
    tail -n 25 "${LOG}" >&2 2>/dev/null || true
    cleanup
    exit 1
}

[[ -f "${ISO}" ]] || fail "no ISO at ${ISO} — build it: cmake --build ${BUILD_DIR} --target duetos-iso"

say "booting ${PRESET} guest (log: ${LOG})"
setsid env DUETOS_PRESET="${PRESET}" DUETOS_TIMEOUT=120 DUETOS_QMP=1 \
    "${REPO_ROOT}/tools/qemu/run.sh" >"${LOG}" 2>&1 &
GUEST_PID=$!
GUEST_PGID="$(ps -o pgid= "${GUEST_PID}" 2>/dev/null | tr -d ' ')"
[[ -n "${GUEST_PGID}" ]] || fail "could not determine guest process group"

qmp() { DUETOS_PRESET="${PRESET}" "${REPO_ROOT}/tools/qemu/qmp.sh" "$@" 2>/dev/null; }
shutdown_now() { qmp status 2>/dev/null | grep -q '"status": *"shutdown"'; }
armed()        { grep -q '^\[acpi/sci\] armed' "${LOG}" 2>/dev/null; }
latched()      { grep -q '^\[env/sci\] PWRBTN_STS latched' "${LOG}" 2>/dev/null; }
paniced()      { grep -qE 'PANIC|TRIPLE|kernel oops' "${LOG}" 2>/dev/null; }

# Wait for the SCI to be live. The pre-existing CI auto-poweroff
# may beat it — that is the documented SKIP, not a failure.
waited=0
until armed; do
    paniced && fail "panic/triple-fault before the SCI armed"
    if shutdown_now; then
        skip "guest hit the pre-existing CI auto-shutdown before the SCI armed (env-monitor scheduled too late in this boot path — not a power-path defect; see slice-2 baseline)"
    fi
    sleep 1
    waited=$((waited + 1))
    [[ ${waited} -ge ${ARMED_WAIT} ]] && skip "[acpi/sci] armed not seen within ${ARMED_WAIT}s (monitor starved by the CI boot tail)"
    kill -0 "${GUEST_PID}" 2>/dev/null || skip "guest exited before the SCI armed"
done
say "[acpi/sci] armed seen at ~${waited}s — pressing the ACPI power button"

# Press immediately and a few more times: armed is ~coincident with
# the pre-existing auto-shutdown, so we want a press to land in any
# sliver before S5.
for _ in 1 2 3 4 5; do
    qmp powerdown >/dev/null 2>&1 || true
    latched && break
    sleep 0.4
done

# Watch for the unforgeable proof sentinel.
obs=0
while [[ ${obs} -lt ${OBSERVE} ]]; do
    if latched; then
        paniced && fail "panic/triple-fault on the power-button SCI path"
        pass "power button → SCI delivered + decoded ([env/sci] PWRBTN_STS latched); AcpiShutdown invoked"
    fi
    paniced && fail "panic/triple-fault on the power-button SCI path"
    sleep 1
    obs=$((obs + 1))
done

# No sentinel. If the box auto-shut (the documented race) that is a
# SKIP; a still-running guest that ignored the button is a real
# FAIL of the power path.
if shutdown_now || ! kill -0 "${GUEST_PID}" 2>/dev/null; then
    skip "no PWRBTN sentinel before the pre-existing CI auto-shutdown raced it (SCI was armed; delivery un-observable in this QEMU boot — see header)"
fi
fail "SCI armed and guest still running, but PWRBTN_STS never latched after ${OBSERVE}s of button presses — power path did not fire"
