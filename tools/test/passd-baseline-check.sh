#!/usr/bin/env bash
#
# passd-baseline-check.sh — verify whether amber/highcontrast/duetclassic
# behaved differently on the parent commit (pre-PaintAll-fix).
#
# Used 2026-05-25 to determine whether the bitmap-theme slowness exposed
# by the 60s timeout is a pre-existing condition (likely just slow boot)
# or an unintended side effect of the PaintAll-removal fix.
set -euo pipefail
cd /root/source/DuetOS

PARENT_SHA="${PARENT_SHA:-4caab695}"
TIMEOUT="${DUETOS_TIMEOUT:-60}"

echo "[baseline-check] checking out ${PARENT_SHA}"
git stash push -m "passd-baseline-check-stash" 2>/dev/null || true
git checkout "${PARENT_SHA}" 2>&1 | tail -2

echo "[baseline-check] rebuilding"
cmake --build build/x86_64-debug --parallel "$(nproc)" 2>&1 | tail -3

for theme in amber highcontrast duetclassic; do
    LOG="/tmp/baseline-${theme}.log"
    DUETOS_EXTRA_CMDLINE="theme=${theme} autologin=1" \
    DUETOS_TIMEOUT="${TIMEOUT}" \
        tools/qemu/run.sh > "${LOG}" 2>&1 || true
    lines=$(wc -l < "${LOG}")
    bringup=$(grep -cE 'bringup-complete|Entering idle loop' "${LOG}" || true)
    last_ts=$(grep -oE 't=[0-9]+\.[0-9]+ms' "${LOG}" | tail -1)
    echo "baseline ${theme}: lines=${lines} bringup=${bringup} last_ts=${last_ts}"
done

echo "[baseline-check] restoring fix"
git checkout claude/pass-d-app-widgets 2>&1 | tail -2
git stash pop 2>/dev/null || true
cmake --build build/x86_64-debug --parallel "$(nproc)" 2>&1 | tail -3
