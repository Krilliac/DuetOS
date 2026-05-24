#!/usr/bin/env bash
#
# tactility-soak.sh - chrome-tactility runtime soak (Phase 5 Task 24
# of the chrome-tactility plan).
#
# WHAT IT MEASURES
#   Boots the kernel with `render_stats=on` so DesktopCompose emits
#   per-phase dirty-pixel counts to COM1, runs idle for $SECONDS_RUN
#   seconds, then summarises:
#     - total dirty-pixel count (chrome-tactility spec §8.1 target:
#       <= 1.5x the pre-spec baseline)
#     - probe fires for blend-range-oob / shadow-atlas-invalid /
#       tactility-theme-mismatch (any fire = FAIL)
#     - PASS-line count for the four tactility-related self-tests
#       (blend / shadow / theme.tactility-matrix / umbrella)
#
# USAGE
#   tools/test/tactility-soak.sh [theme] [seconds]
#     theme    -- one of: classic slate10 amber duet duetlight
#                 duetblue duetviolet duetgreen duetclassic
#                 highcontrast (default: duet)
#     seconds  -- soak duration in seconds (default: 60)
#
# ENV
#   DUETOS_LOG_DIR  -- log output dir (default: build)
#   DUETOS_TIMEOUT  -- override boot timeout (passed to run.sh)
#
# EXIT 0 = no probe fires, all 4 PASS sentinels present.
#      1 = one or more probes fired or sentinels missing.
#      2 = boot tooling missing (qemu / run.sh).

set -euo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

THEME="${1:-duet}"
SECONDS_RUN="${2:-60}"
LOG_DIR="${DUETOS_LOG_DIR:-${REPO_ROOT}/build}"
mkdir -p "$LOG_DIR"
LOG="$LOG_DIR/tactility-soak-${THEME}.log"
TSV="$LOG_DIR/tactility-soak-${THEME}.tsv"

if [[ ! -x "${REPO_ROOT}/tools/qemu/run.sh" ]]
then
    echo "ERROR: ${REPO_ROOT}/tools/qemu/run.sh missing or not executable" >&2
    exit 2
fi

echo "[soak] theme=${THEME} seconds=${SECONDS_RUN} log=${LOG}"

DUETOS_TIMEOUT="${DUETOS_TIMEOUT:-${SECONDS_RUN}}" \
    "${REPO_ROOT}/tools/qemu/run.sh" \
    -append "theme=${THEME} render_stats=on tactility=auto" \
    > "$LOG" 2>&1 || true

# Extract render_stats lines into a per-phase TSV (one column per
# phase=foo total=N entry) so a downstream chart or threshold tool
# can grep instead of re-parsing the boot log.
awk '
    /\[render_stats\]/ {
        sub(/.*\[render_stats\] /, "");
        print
    }
' "$LOG" > "$TSV"

# Summary
total_dirty=$(grep -aoE 'total=[0-9]+' "$LOG" | tail -1 | cut -d= -f2 || echo "unknown")
probe_fires=$(grep -acE 'blend-range-oob|shadow-atlas-invalid|tactility-theme-mismatch' "$LOG" || true)
pass_lines=$(grep -acE '\[(blend|shadow|theme|tactility)-selftest\].*PASS' "$LOG" || true)

echo "[soak] summary:"
echo "  total dirty px : ${total_dirty}"
echo "  probe fires    : ${probe_fires}"
echo "  PASS lines     : ${pass_lines}"

# Fail loud on any probe fire (a probe firing in soak means a
# chrome-tactility regression that the boot self-tests didn't catch).
if [[ "${probe_fires}" -gt 0 ]]
then
    echo "[soak] FAIL: tactility probe fired - inspect ${LOG}" >&2
    exit 1
fi

# Require all four PASS lines (blend / shadow / theme-tactility-matrix /
# umbrella tactility-selftest) - if any is missing the soak ran on a
# kernel that lost a self-test wiring step.
if [[ "${pass_lines}" -lt 4 ]]
then
    echo "[soak] FAIL: expected >=4 tactility PASS sentinels, found ${pass_lines}" >&2
    exit 1
fi

echo "[soak] OK"
