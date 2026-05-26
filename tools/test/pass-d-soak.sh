#!/usr/bin/env bash
#
# pass-d-soak.sh — Pass D app-widget regression guard (Task 36).
#
# WHAT IT DOES
#   Boots the kernel with autologin=1 (the default cmdline in
#   tools/qemu/run.sh's primary grub entry, also forced via
#   DUETOS_EXTRA_CMDLINE when a theme override is requested), holds
#   for SOAK_SECONDS seconds, then asserts on the captured serial
#   log that every Pass D umbrella sentinel is green and that no
#   failure / lockup / oom signals fired under the sustained widget-
#   chrome traffic produced by the 28 migrated apps' boot self-tests.
#
#   The canonical boot-log-analyze.sh runs first (it exits non-zero
#   on any non-deliberate regression sentinel it recognises); Pass D
#   specific assertions follow on top:
#
#     - `[app-widgets-selftest] PASS` present (CRTP base + widget
#       state-machine self-test green).
#     - `[pass-d-selftest] PASS (widgets=ok, apps=28/28)` present
#       (umbrella aggregator fired with full app coverage).
#     - All 28 per-app `[<app>-selftest] PASS` sentinels present.
#     - Pass A/B/C umbrellas still green (must not regress).
#     - Boot reached steady state (`Entering idle loop` under the
#       autologin path, or `login: gate up` if autologin=0 was
#       forced via DUETOS_EXTRA_CMDLINE).
#     - No `PANIC` / `TRIPLE` lines.
#     - No `oom-slab-fault` line.
#     - No non-deliberate `soft-lockup` warnings (the deliberate
#       soft-lockup self-test uses the `selftest-42` / `selftest-99`
#       task names; those are subtracted out, matching pass-b /
#       pass-c soak).
#
# USAGE
#   tools/test/pass-d-soak.sh                  # default 60 s soak
#   tools/test/pass-d-soak.sh /tmp             # log dir = /tmp
#
# ENV
#   LOG               — output log path (default: ${LOG_DIR}/pass-d-soak.log)
#   SOAK_SECONDS      — total QEMU timeout in seconds (default: 60;
#                       ~10 s boot + 50 s sustained widget-chrome soak).
#   DUETOS_THEME      — theme override appended to the kernel cmdline
#                       via DUETOS_EXTRA_CMDLINE (default: unset).
#   DUETOS_LOG_DIR    — log output dir (overrides LOG default if set,
#                       also overrides the positional $1).
#   DUETOS_EXTRA_CMDLINE
#                     — forwarded verbatim to run.sh's extra-cmdline
#                       grub entry. If both this and DUETOS_THEME are
#                       set, the user-provided value wins (theme is
#                       only appended when this is empty).
#
# POSITIONAL
#   $1                — log dir (overridden by DUETOS_LOG_DIR if set).
#
# EXIT CODES
#   0 — PASS: every assertion held.
#   1 — FAIL: one or more assertions failed.
#   2 — tooling missing (run.sh not found / not executable).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
readonly REPO_ROOT

SOAK_SECONDS="${SOAK_SECONDS:-60}"

# Log location: DUETOS_LOG_DIR > $1 > build/.
if [[ -n "${DUETOS_LOG_DIR:-}" ]]; then
    LOG_DIR="${DUETOS_LOG_DIR}"
elif [[ $# -ge 1 && -n "$1" ]]; then
    LOG_DIR="$1"
else
    LOG_DIR="${REPO_ROOT}/build"
fi
mkdir -p "${LOG_DIR}"
LOG="${LOG:-${LOG_DIR}/pass-d-soak.log}"

# Tooling guard.
if [[ ! -x "${REPO_ROOT}/tools/qemu/run.sh" ]]; then
    echo "ERROR: ${REPO_ROOT}/tools/qemu/run.sh missing or not executable" >&2
    exit 2
fi

# Theme override → extra cmdline (same shape as pass-c-soak).
EXTRA_CMDLINE="${DUETOS_EXTRA_CMDLINE:-}"
if [[ -z "${EXTRA_CMDLINE}" && -n "${DUETOS_THEME:-}" ]]; then
    EXTRA_CMDLINE="theme=${DUETOS_THEME}"
fi

echo "[pass-d-soak] soak=${SOAK_SECONDS}s extra_cmdline='${EXTRA_CMDLINE}' log=${LOG}"

# Boot the kernel and capture the serial transcript.
# run.sh exits non-zero on timeout (expected); suppress with || true.
DUETOS_TIMEOUT="${SOAK_SECONDS}" \
DUETOS_EXTRA_CMDLINE="${EXTRA_CMDLINE}" \
    "${REPO_ROOT}/tools/qemu/run.sh" \
    > "${LOG}" 2>&1 || true

echo "[pass-d-soak] boot complete — analyzing ${LOG}"

# ── Canonical triage ──────────────────────────────────────────────────────────
# boot-log-analyze.sh is the authoritative regression gate (CLAUDE.md).
# It exits 1 if any non-deliberate failure sentinel appears AND already
# checks the Pass D umbrella section we re-assert below — running both
# is intentional: the analyzer catches drift the umbrella doesn't and
# vice-versa.
ANALYZE="${REPO_ROOT}/tools/test/boot-log-analyze.sh"
if [[ -x "${ANALYZE}" ]]; then
    echo
    echo "=== boot-log-analyze ==="
    if ! bash "${ANALYZE}" "${LOG}"; then
        echo "[pass-d-soak] FAIL: boot-log-analyze flagged a regression" >&2
        exit 1
    fi
fi

# ── Pass D specific assertions ────────────────────────────────────────────────
echo
echo "[pass-d-soak] sentinel checks:"

FAILS=0

check_present() {
    local label="$1" pat="$2"
    if grep -qE "${pat}" "${LOG}"; then
        echo "  OK    ${label}"
    else
        echo "  FAIL  ${label} (missing: ${pat})"
        FAILS=$((FAILS + 1))
    fi
}

check_absent() {
    local label="$1" pat="$2"
    local n
    n=$(grep -cE "${pat}" "${LOG}" || true)
    n="${n:-0}"
    if [[ "${n}" -eq 0 ]]; then
        echo "  OK    ${label} (0 occurrences)"
    else
        echo "  FAIL  ${label} (${n} occurrences of: ${pat})"
        FAILS=$((FAILS + 1))
    fi
}

# Per-app sentinels — the 28 apps Pass D migrated. Names match the
# literals each app emits via SerialWrite("[<app>-selftest] PASS\n").
APP_SENTINELS=(
    calculator
    notes
    files
    taskman
    settings
    browser
    calendar
    imageview
    clock
    hexview
    charmap
    devicemgr
    firewall
    help
    netstatus
    sysmon
    about
    notify
    notify_center
    screenshot
    settings-datetime
    settings-display
    settings-keyboard
    settings-mouse
    settings-sound
    terminal
    gfxdemo
    dbg-render
)

echo "[pass-d-soak] per-app sentinels (28):"
for app in "${APP_SENTINELS[@]}"; do
    # Square brackets escaped so grep -E treats them literally.
    # gfxdemo is an exception: it predates the
    # `[<app>-selftest] PASS` convention and emits
    # `[gfxdemo] self-test OK (...)` instead. Both shapes
    # satisfy the same contract — the boot umbrella reads its
    # GfxDemoSelfTestPassed() flag the same way as every other
    # app's PASS flag. Accept either form so we don't false-fail
    # on a known-good legacy sentinel.
    if [[ "${app}" == "gfxdemo" ]]; then
        check_present "  ${app} self-test OK (legacy)" '\[gfxdemo\] self-test OK'
    else
        check_present "  ${app}-selftest PASS" "\\[${app}-selftest\\] PASS"
    fi
done

echo
echo "[pass-d-soak] umbrella sentinels:"
check_present "app-widgets-selftest PASS" '\[app-widgets-selftest\] PASS'
check_present "pass-d-selftest PASS (28/28)" '\[pass-d-selftest\] PASS \(widgets=ok, apps=28/28\)'

echo
echo "[pass-d-soak] prior-pass umbrellas (must not regress):"
check_present "pass-c-selftest PASS" '\[pass-c-selftest\] PASS'
check_present "pass-b-selftest PASS" '\[pass-b-selftest\] PASS'
# Pass A umbrella is the tactility-selftest line (see Compositor.md
# §"Chrome Tactility (Pass A)" and tactility-screenshot-matrix.sh).
check_present "tactility-selftest PASS (Pass A)" '\[tactility-selftest\] PASS'

echo
echo "[pass-d-soak] runtime health:"
check_present "boot reached steady state"   '(Entering idle loop|login: gate up)'
check_absent  "PANIC / TRIPLE"              'PANIC|TRIPLE'
check_absent  "oom-slab-fault"              'oom-slab-fault'

# soft-lockup: same calculation as pass-b / pass-c soak — anchor on
# the diag/ WARN to avoid matching registration / narration lines,
# subtract the deliberate selftest-42 / selftest-99 fires.
lockup_all=$(grep -cE 'diag/soft-lockup.*soft-lockup' "${LOG}" || true)
lockup_deliberate=$(grep -cE 'selftest-(42|99)' "${LOG}" || true)
lockup_all="${lockup_all:-0}"
lockup_deliberate="${lockup_deliberate:-0}"
lockups=$(( lockup_all - lockup_deliberate ))
if [[ "${lockups}" -le 0 ]]; then
    echo "  OK    soft-lockup (deliberate ${lockup_deliberate} subtracted; net 0)"
else
    echo "  FAIL  soft-lockup (${lockups} non-deliberate after subtracting ${lockup_deliberate})"
    FAILS=$((FAILS + 1))
fi

echo
if [[ "${FAILS}" -eq 0 ]]; then
    echo "[pass-d-soak] PASS"
    exit 0
fi
echo "[pass-d-soak] FAIL — ${FAILS} assertion(s) failed; inspect ${LOG}" >&2
exit 1
