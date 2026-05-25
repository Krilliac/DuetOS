#!/usr/bin/env bash
#
# pass-c-soak.sh — Pass C text-heavy soak (Task 19).
#
# WHAT IT DOES
#   Boots the kernel with autologin=1 (the default cmdline in
#   tools/qemu/run.sh's primary grub entry, also forced via
#   DUETOS_EXTRA_CMDLINE when a theme override is requested), holds
#   for SOAK_SECONDS seconds, then asserts on the captured serial
#   log that every Pass C umbrella sentinel is green and that no
#   failure / lockup / oom signals fired under sustained chrome-text
#   traffic (taskbar clock + date tick, splash phase ticker, login
#   GUI repaints, desktop tile labels, dialog titles).
#
#   The canonical boot-log-analyze.sh runs first (it exits non-zero
#   on any non-deliberate regression sentinel it recognises); Pass C
#   specific assertions follow on top:
#
#     - `[chrome-text-selftest] PASS` present (chrome-text role
#       table + dispatch math passed the headless self-test).
#     - `[pass-c-selftest] PASS` present (Pass C umbrella aggregator
#       fired in boot_bringup after the chrome-text sub-test).
#     - `[pass-b-selftest] PASS` present (Pass C must not regress
#       Pass B's splash + wallpaper + login-gui umbrella).
#     - Boot reached steady state (`Entering idle loop` under the
#       autologin path, or `login: gate up` if autologin=0 was
#       forced via DUETOS_EXTRA_CMDLINE).
#     - No `PANIC` / `TRIPLE` lines.
#     - No `oom-slab-fault` line.
#     - No non-deliberate `soft-lockup` warnings (the deliberate
#       soft-lockup self-test uses the `selftest-42` / `selftest-99`
#       task names; those are subtracted out, matching pass-b-soak).
#
# USAGE
#   tools/test/pass-c-soak.sh
#
# ENV
#   LOG               — output log path (default: build/pass-c-soak.log)
#   SOAK_SECONDS      — total QEMU timeout in seconds (default: 35;
#                       ~10 s boot + 25 s text-heavy soak window).
#   DUETOS_THEME      — theme override appended to the kernel cmdline
#                       via DUETOS_EXTRA_CMDLINE (default: unset, i.e.
#                       the canonical run.sh entry boots with the
#                       project default theme + autologin=1).
#   DUETOS_LOG_DIR    — log output dir (overrides LOG default if set).
#   DUETOS_EXTRA_CMDLINE
#                     — forwarded verbatim to run.sh's extra-cmdline
#                       grub entry. If both this and DUETOS_THEME are
#                       set, the user-provided value wins (theme is
#                       only appended when this is empty).
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

SOAK_SECONDS="${SOAK_SECONDS:-35}"

# Log location: honour DUETOS_LOG_DIR if set, otherwise default to build/.
if [[ -n "${DUETOS_LOG_DIR:-}" ]]; then
    LOG_DIR="${DUETOS_LOG_DIR}"
else
    LOG_DIR="${REPO_ROOT}/build"
fi
mkdir -p "${LOG_DIR}"
LOG="${LOG:-${LOG_DIR}/pass-c-soak.log}"

# Tooling guard.
if [[ ! -x "${REPO_ROOT}/tools/qemu/run.sh" ]]; then
    echo "ERROR: ${REPO_ROOT}/tools/qemu/run.sh missing or not executable" >&2
    exit 2
fi

# Theme override → extra cmdline. The canonical "extra cmdline" grub
# entry in run.sh already bakes in `boot=desktop autologin=1`, so we
# only need to append `theme=<id>` when the caller asks for one. If
# DUETOS_EXTRA_CMDLINE is already set we honour it verbatim and skip
# the theme synthesis (the caller knows what they want).
EXTRA_CMDLINE="${DUETOS_EXTRA_CMDLINE:-}"
if [[ -z "${EXTRA_CMDLINE}" && -n "${DUETOS_THEME:-}" ]]; then
    EXTRA_CMDLINE="theme=${DUETOS_THEME}"
fi

echo "[pass-c-soak] soak=${SOAK_SECONDS}s extra_cmdline='${EXTRA_CMDLINE}' log=${LOG}"

# Boot the kernel and capture the serial transcript.
# run.sh exits non-zero on timeout (expected); suppress with || true.
DUETOS_TIMEOUT="${SOAK_SECONDS}" \
DUETOS_EXTRA_CMDLINE="${EXTRA_CMDLINE}" \
    "${REPO_ROOT}/tools/qemu/run.sh" \
    > "${LOG}" 2>&1 || true

echo "[pass-c-soak] boot complete — analyzing ${LOG}"

# ── Canonical triage ──────────────────────────────────────────────────────────
# boot-log-analyze.sh is the authoritative regression gate (CLAUDE.md).
# It exits 1 if any non-deliberate failure sentinel appears AND already
# checks the Pass C umbrella section we re-assert below — running both
# is intentional: the analyzer catches drift the umbrella doesn't and
# vice-versa.
ANALYZE="${REPO_ROOT}/tools/test/boot-log-analyze.sh"
if [[ -x "${ANALYZE}" ]]; then
    echo
    echo "=== boot-log-analyze ==="
    if ! bash "${ANALYZE}" "${LOG}"; then
        echo "[pass-c-soak] FAIL: boot-log-analyze flagged a regression" >&2
        exit 1
    fi
fi

# ── Pass C specific assertions ────────────────────────────────────────────────
echo
echo "[pass-c-soak] sentinel checks:"

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

check_present "chrome-text-selftest PASS"   '\[chrome-text-selftest\] PASS'
check_present "pass-c-selftest PASS"        '\[pass-c-selftest\] PASS'
check_present "pass-b-selftest PASS"        '\[pass-b-selftest\] PASS'
check_present "boot reached steady state"   '(Entering idle loop|login: gate up)'
check_absent  "PANIC / TRIPLE"              'PANIC|TRIPLE'
check_absent  "oom-slab-fault"              'oom-slab-fault'

# soft-lockup: only the diag/soft-lockup WARN line is the canonical
# regression signal (registration log lines + the self-test's own
# narration lines also contain the literal string but aren't the
# diagnostic itself). Subtract the deliberate self-test fires
# (selftest-42 / selftest-99 task names) — same logic shape as
# pass-b-soak.sh, but anchored on the diag/ WARN to avoid false
# positives from "[fault-domain] register name=soft-lockup" and
# "[soft-lockup] self-test:" narration.
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
    echo "[pass-c-soak] PASS"
    exit 0
fi
echo "[pass-c-soak] FAIL — ${FAILS} assertion(s) failed; inspect ${LOG}" >&2
exit 1
