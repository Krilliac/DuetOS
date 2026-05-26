#!/usr/bin/env bash
# Re-run a single theme with a long timeout to determine whether the
# previous fail was a real hang or just slow boot.
set -euo pipefail
cd /root/source/DuetOS

theme="${1:-amber}"
TIMEOUT="${DUETOS_TIMEOUT:-120}"
LOG="${LOG:-/tmp/longwait-${theme}.log}"

DUETOS_EXTRA_CMDLINE="theme=${theme} autologin=1" \
DUETOS_TIMEOUT="${TIMEOUT}" \
    tools/qemu/run.sh > "${LOG}" 2>&1 || true

lines=$(wc -l < "${LOG}")
bringup=$(grep -cE 'bringup-complete|Entering idle loop' "${LOG}" || true)
term_pass=$(grep -cE '\[terminal-selftest\] PASS' "${LOG}" || true)
last_ts=$(grep -oE 't=[0-9]+\.[0-9]+ms' "${LOG}" | tail -1)
echo "${theme}: lines=${lines} bringup=${bringup} term-pass=${term_pass} last_ts=${last_ts}"
echo "tail:"
tail -3 "${LOG}"
