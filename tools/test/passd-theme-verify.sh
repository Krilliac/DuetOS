#!/usr/bin/env bash
#
# passd-theme-verify.sh — boot each theme, report lines + bringup +
# terminal-selftest PASS. One-shot harness used to validate the
# Pass D duet-theme hang fix (2026-05-25) and re-runnable as a
# regression check for the chrome-tactility / TTF surface.
#
# USAGE
#   tools/test/passd-theme-verify.sh             # all 10 themes
#   tools/test/passd-theme-verify.sh duet duetlight   # subset
#
# ENV
#   DUETOS_TIMEOUT — per-theme timeout (default 45 s).
#   LOG_DIR        — log output dir (default /tmp).
set -euo pipefail

THEMES=("$@")
if [[ ${#THEMES[@]} -eq 0 ]]; then
    THEMES=(duet duetlight duetdeep duetsoft duetmono classic slate10 amber highcontrast duetclassic)
fi

LOG_DIR="${LOG_DIR:-/tmp}"
TIMEOUT="${DUETOS_TIMEOUT:-45}"

mkdir -p "${LOG_DIR}"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${REPO_ROOT}"

PASS=0
FAIL=0
for theme in "${THEMES[@]}"; do
    LOG="${LOG_DIR}/passd-verify-${theme}.log"
    DUETOS_EXTRA_CMDLINE="theme=${theme} autologin=1" \
    DUETOS_TIMEOUT="${TIMEOUT}" \
        tools/qemu/run.sh > "${LOG}" 2>&1 || true

    lines=$(wc -l < "${LOG}")
    bringup=$(grep -cE 'bringup-complete|All subsystems online|Entering idle loop' "${LOG}" || true)
    term_pass=$(grep -cE '\[terminal-selftest\] PASS' "${LOG}" || true)
    pass_d=$(grep -cE '\[pass-d-selftest\] PASS' "${LOG}" || true)

    if [[ "${bringup}" -ge 1 && "${term_pass}" -ge 1 ]]; then
        status="PASS"
        PASS=$((PASS + 1))
    else
        status="FAIL"
        FAIL=$((FAIL + 1))
    fi
    printf '%-14s %s  lines=%-6s bringup=%s term-pass=%s pass-d=%s  %s\n' \
        "${theme}" "${status}" "${lines}" "${bringup}" "${term_pass}" "${pass_d}" "${LOG}"
done

echo
echo "summary: ${PASS} pass, ${FAIL} fail"
exit "${FAIL}"
