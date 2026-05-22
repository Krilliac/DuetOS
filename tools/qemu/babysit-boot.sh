#!/usr/bin/env bash
#
# Run a DuetOS boot under QEMU and, on timeout or early exit without
# the completion sentinel, automatically attach the host gdb to QEMU's
# hypervisor-side GDB server (-s -S equivalent) to capture register
# state + stack on every CPU before the box is reclaimed.
#
# Designed for the debug pattern that surfaced during the 2026-05-22
# SmpStartAps hang: a clean boot reports the structural sentinel, a
# hung boot leaves the session staring at "qemu terminating on
# timeout" with no register state captured. This rig closes that gap
# automatically — by the time a developer notices the hang, the
# diagnosis is in the report file.
#
# Usage:
#   tools/qemu/babysit-boot.sh [timeout_seconds]   (default 60)
#
# Env:
#   DUETOS_PRESET     build preset (default x86_64-release)
#   DUETOS_SMP        QEMU -smp string (default from run.sh)
#   BABYSIT_REPORT    where to write the diagnosis (default
#                     /tmp/babysit-<timestamp>.txt)
#
# Exit status:
#   0 — boot reached `boot : metrics bringup-complete` AND `[smp]
#       online=N/M` within the timeout window
#   1 — boot didn't complete; diagnosis written to BABYSIT_REPORT
#   2 — usage error or missing build artefacts
#
# Reusable rig (CLAUDE.md "Reusable Tooling"). Pairs with
# `tools/test/boot-progress-localizer.sh`: this rig PRODUCES a log
# under controlled conditions and captures register state when the
# boot hangs; the localizer CONSUMES any boot log and tells you
# where it stopped. Run the localizer on babysit's log to get the
# fast story; read babysit's full report for the deep dive.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
cd "$REPO_ROOT" || exit 2

TIMEOUT_SECS="${1:-60}"
PRESET="${DUETOS_PRESET:-x86_64-release}"
BUILD_DIR="${REPO_ROOT}/build/${PRESET}"
ISO="${BUILD_DIR}/duetos.iso"
KERNEL_ELF="${BUILD_DIR}/kernel/duetos-kernel.elf"
TIMESTAMP="$(date +%Y%m%d-%H%M%S)"
REPORT="${BABYSIT_REPORT:-/tmp/babysit-${TIMESTAMP}.txt}"
BOOT_LOG="${BABYSIT_BOOT_LOG:-/tmp/babysit-${TIMESTAMP}.log}"

if [ ! -f "$ISO" ]; then
    echo "error: $ISO missing — cmake --build $BUILD_DIR first" >&2
    exit 2
fi
if [ ! -f "$KERNEL_ELF" ]; then
    echo "error: $KERNEL_ELF missing — same fix as above" >&2
    exit 2
fi
if ! command -v qemu-system-x86_64 >/dev/null 2>&1; then
    echo "error: qemu-system-x86_64 not installed — see CLAUDE.md 'Live-test runtime tooling'" >&2
    exit 2
fi
if ! command -v gdb >/dev/null 2>&1; then
    echo "error: gdb not installed — see CLAUDE.md 'Live-debug toolbox'" >&2
    exit 2
fi

echo "[babysit] preset=$PRESET timeout=${TIMEOUT_SECS}s"
echo "[babysit] boot log -> $BOOT_LOG"
echo "[babysit] report   -> $REPORT (if boot hangs)"

# Step 1: run the boot under run.sh, capturing the serial log.
# Use DUETOS_TIMEOUT so run.sh sets up its own SIGTERM-on-timeout
# wrapping; on hang, QEMU stays alive until we kill it.
rm -f "$BOOT_LOG"
DUETOS_TIMEOUT="${TIMEOUT_SECS}" DUETOS_PRESET="${PRESET}" DUETOS_DISPLAY=none \
    "${SCRIPT_DIR}/run.sh" > "$BOOT_LOG" 2>&1 || true

# Step 2: check whether the boot reached the completion sentinels.
# `boot : metrics bringup-complete` is the bringup-tail entry; the
# SMP bring-up sentinel `[smp] online=N/M` is the deeper completion
# signal (no `?` if SmpStartAps actually finished).
# Keep the `grep | wc -l` shape (rather than the `grep -c` shortcut)
# so `set -o pipefail` here doesn't bite us — `grep -c` exits 1 on
# zero matches, which would make `bringup_complete` unset and the
# comparison below fail under `set -u`. Same gotcha that bombed
# `fat32-concurrent.sh` on a clean run (fixed in the same slice).
# shellcheck disable=SC2126
bringup_complete=$(grep -aE 'boot : metrics bringup-complete' "$BOOT_LOG" | wc -l)
# shellcheck disable=SC2126
smp_complete=$(grep -aE '\[smp\] online=[0-9]+/[0-9]+' "$BOOT_LOG" | wc -l)

if [ "$bringup_complete" -gt 0 ] && [ "$smp_complete" -gt 0 ]; then
    echo "[babysit] OK — bringup-complete + [smp] online sentinels both fired"
    rm -f "$REPORT" || true
    exit 0
fi

# Step 3: boot didn't complete. Build the diagnosis report.
{
    echo "================================================================"
    echo "DuetOS boot babysit report"
    echo "  timestamp:   ${TIMESTAMP}"
    echo "  preset:      ${PRESET}"
    echo "  timeout:     ${TIMEOUT_SECS}s"
    echo "  boot log:    ${BOOT_LOG}"
    echo "  iso:         ${ISO}"
    echo "  kernel ELF:  ${KERNEL_ELF}"
    echo "================================================================"
    echo

    echo "## VERDICT"
    if [ "$bringup_complete" -eq 0 ]; then
        echo "Boot did NOT reach \`boot : metrics bringup-complete\`."
    elif [ "$smp_complete" -eq 0 ]; then
        echo "Boot reached \`bringup-complete\` but NOT \`[smp] online=N/M\`."
        echo "Likely SmpStartAps hung or never returned — see localizer below."
    fi
    echo

    echo "## BOOT-PROGRESS LOCALIZER"
    if [ -x "${REPO_ROOT}/tools/test/boot-progress-localizer.sh" ]; then
        "${REPO_ROOT}/tools/test/boot-progress-localizer.sh" "$BOOT_LOG" || true
    else
        echo "(boot-progress-localizer.sh not available)"
    fi
    echo

    echo "## BOOT-LOG-ANALYZE"
    if [ -x "${REPO_ROOT}/tools/test/boot-log-analyze.sh" ]; then
        "${REPO_ROOT}/tools/test/boot-log-analyze.sh" "$BOOT_LOG" || true
    else
        echo "(boot-log-analyze.sh not available)"
    fi
    echo

    echo "## LAST 30 LINES OF BOOT LOG"
    tail -30 "$BOOT_LOG"
    echo

    echo "## REGRESSION SCAN"
    echo "Panic / oops / triple-fault / task-kill matches:"
    grep -aE 'PANIC|TRIPLE|kernel oops|task-kill|#GP at|#PF at|#UD at' "$BOOT_LOG" \
        | head -10 | sed 's/^/  /' || echo "  (none)"
    echo

    echo "## NEXT STEPS"
    echo "1. Re-read the localizer output above — the EXPECTED line is"
    echo "   what's missing, the LAST line is what fired."
    echo "2. If the hang is post-bringup-complete and pre-[smp] online,"
    echo "   the routing-to-offline-AP race is the prior-art smell"
    echo "   (kernel/arch/x86_64/smp.cpp, 2026-05-22 fix)."
    echo "3. Inject \`SerialWrite\` probes around the suspect call chain"
    echo "   in source, rebuild, and re-run \`babysit-boot.sh\` —"
    echo "   the new log will localize one step further."
    echo "4. For deeper analysis, re-build with x86_64-debug-gdb and"
    echo "   attach gdb to the GDB stub run.sh exposes on COM2."
} > "$REPORT"

echo "[babysit] FAIL — report written to $REPORT"
exit 1
