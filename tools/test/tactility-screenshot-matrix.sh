#!/usr/bin/env bash
#
# tactility-screenshot-matrix.sh - boot the kernel and capture a
# desktop PPM via QEMU's QMP `screendump` (Phase 5 Task 25 of the
# chrome-tactility plan).
#
# SCOPE
#   No args: single boot, single PPM for the default theme.
#   1+ theme args: per-theme PPMs, one boot per theme via
#     run.sh's DUETOS_EXTRA_CMDLINE sidecar appending `theme=<name>`.
#   --all: iterates the 10 registered themes (classic, slate10,
#     amber, duet, duetlight, duetblue, duetviolet, duetgreen,
#     duetclassic, highcontrast).
#
# USAGE
#   tools/test/tactility-screenshot-matrix.sh
#     -> single PPM at build/shots/default.ppm
#   tools/test/tactility-screenshot-matrix.sh classic duet highcontrast
#     -> 3 PPMs, one per theme
#   tools/test/tactility-screenshot-matrix.sh --all
#     -> 10 PPMs, one per theme; ~3 min total at 25 s/theme
#
# ENV
#   DUETOS_PRESET   -- build preset (default: x86_64-debug-fast,
#                      since this is for visual / self-test
#                      verification rather than production)
#   DUETOS_LOG_DIR  -- output root (default: build)
#   DUETOS_TIMEOUT  -- per-theme boot timeout, seconds (default: 25)
#
# OUTPUT
#   $DUETOS_LOG_DIR/shots/<theme>.ppm   captured PPM
#   $DUETOS_LOG_DIR/shots/<theme>.log   boot log
#
# EXIT 0 = every requested theme produced a non-empty PPM AND its
#          boot reached the tactility-selftest umbrella PASS line.
#      1 = at least one theme failed to capture.
#      2 = required tooling missing.

set -euo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

readonly ALL_THEMES=(
    classic
    slate10
    amber
    duet
    duetlight
    duetblue
    duetviolet
    duetgreen
    duetclassic
    highcontrast
)

PRESET="${DUETOS_PRESET:-x86_64-debug-fast}"
LOG_DIR="${DUETOS_LOG_DIR:-${REPO_ROOT}/build}"
SHOTS_DIR="${LOG_DIR}/shots"
TIMEOUT="${DUETOS_TIMEOUT:-25}"

if [[ ! -x "${REPO_ROOT}/tools/qemu/run.sh" ]] || [[ ! -x "${REPO_ROOT}/tools/qemu/qmp.sh" ]]
then
    echo "ERROR: tools/qemu/{run,qmp}.sh missing or not executable" >&2
    exit 2
fi
command -v qemu-system-x86_64 >/dev/null || { echo "ERROR: qemu-system-x86_64 missing" >&2; exit 2; }

# Resolve which themes to capture.
declare -a THEMES
if [[ $# -eq 0 ]]
then
    THEMES=(default)
elif [[ "$1" == "--all" ]]
then
    THEMES=("${ALL_THEMES[@]}")
else
    THEMES=("$@")
fi

mkdir -p "${SHOTS_DIR}"

# Capture one theme. Returns 0 on success, 1 on failure.
capture_theme() {
    local theme="$1"
    local ppm="${SHOTS_DIR}/${theme}.ppm"
    local boot_log="${SHOTS_DIR}/${theme}.log"
    local extra_cmdline=""
    if [[ "${theme}" != "default" ]]
    then
        extra_cmdline="theme=${theme}"
    fi

    echo "[shots] booting preset=${PRESET} timeout=${TIMEOUT}s theme=${theme}"
    rm -f "${ppm}" "${boot_log}"

    DUETOS_PRESET="${PRESET}" DUETOS_TIMEOUT="${TIMEOUT}" \
        DUETOS_EXTRA_CMDLINE="${extra_cmdline}" \
        "${REPO_ROOT}/tools/qemu/run.sh" > "${boot_log}" 2>&1 &
    local run_pid=$!

    local cleanup_done=0
    cleanup_run() {
        if [[ ${cleanup_done} -eq 1 ]]; then return; fi
        cleanup_done=1
        if kill -0 "${run_pid}" 2>/dev/null
        then
            DUETOS_PRESET="${PRESET}" "${REPO_ROOT}/tools/qemu/qmp.sh" quit >/dev/null 2>&1 || true
            sleep 1
            kill "${run_pid}" 2>/dev/null || true
        fi
        wait "${run_pid}" 2>/dev/null || true
    }

    # Poll for the umbrella PASS as the "compositor ready" signal.
    local deadline=$((SECONDS + TIMEOUT))
    while [[ ${SECONDS} -lt ${deadline} ]]
    do
        if grep -q '\[tactility-selftest\] PASS' "${boot_log}" 2>/dev/null
        then
            break
        fi
        sleep 1
    done

    if ! grep -q '\[tactility-selftest\] PASS' "${boot_log}" 2>/dev/null
    then
        echo "[shots]   FAIL: tactility-selftest umbrella PASS never landed" >&2
        cleanup_run
        return 1
    fi

    # Small additional pause so the compositor's idle redraw
    # finishes before sampling.
    sleep 2

    DUETOS_PRESET="${PRESET}" "${REPO_ROOT}/tools/qemu/qmp.sh" screenshot "${ppm}" >/dev/null 2>&1 || {
        echo "[shots]   FAIL: qmp.sh screenshot non-zero" >&2
        cleanup_run
        return 1
    }

    cleanup_run

    if [[ ! -s "${ppm}" ]]
    then
        echo "[shots]   FAIL: PPM empty" >&2
        return 1
    fi

    local sz
    sz="$(stat -c %s "${ppm}" 2>/dev/null || echo unknown)"
    echo "[shots]   OK: ${ppm} (${sz} bytes)"
    return 0
}

failed=0
for theme in "${THEMES[@]}"
do
    capture_theme "${theme}" || ((failed++)) || true
done

# Optional contact-sheet via ImageMagick if more than one PPM
# landed and `montage` is on PATH.
if [[ ${#THEMES[@]} -gt 1 ]] && command -v montage >/dev/null 2>&1
then
    SHEET="${LOG_DIR}/tactility-matrix.png"
    available_ppms=()
    for theme in "${THEMES[@]}"
    do
        ppm="${SHOTS_DIR}/${theme}.ppm"
        [[ -s "${ppm}" ]] && available_ppms+=("${ppm}")
    done
    if [[ ${#available_ppms[@]} -gt 0 ]]
    then
        tile_x=5
        if [[ ${#available_ppms[@]} -lt 5 ]]
        then
            tile_x=${#available_ppms[@]}
        fi
        montage "${available_ppms[@]}" -tile "${tile_x}x" -geometry +4+4 -label '%t' "${SHEET}" 2>/dev/null && \
            echo "[shots] grid: ${SHEET}"
    fi
fi

if [[ ${failed} -gt 0 ]]
then
    echo "[shots] FAIL: ${failed}/${#THEMES[@]} themes failed" >&2
    exit 1
fi

echo "[shots] OK (${#THEMES[@]}/${#THEMES[@]} themes captured)"
