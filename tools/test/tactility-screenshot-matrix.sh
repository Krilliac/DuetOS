#!/usr/bin/env bash
#
# tactility-screenshot-matrix.sh - boot the kernel and capture a
# desktop PPM via QEMU's QMP `screendump` (Phase 5 Task 25 of the
# chrome-tactility plan; extended Pass B Task 22 for surface modes).
#
# SCOPE
#   No args: single boot, single PPM for the default theme (wallpaper
#     surface, autologin=1).
#   1+ theme args: per-theme PPMs, one boot per theme via
#     run.sh's DUETOS_EXTRA_CMDLINE sidecar appending `theme=<name>`.
#   --all: iterates the 10 registered themes (classic, slate10,
#     amber, duet, duetlight, duetblue, duetviolet, duetgreen,
#     duetclassic, highcontrast).
#
#   Surface flags control which UI moment is captured.  Exactly one
#   may be supplied; default is --wallpaper.
#     --splash    mid-boot frame before login (autologin=1, capture at 1.5 s)
#     --login     login GUI first paint (autologin=0, capture at 8 s)
#     --lock      post-idle lock screen (autologin=1 idlelock=2, capture at 10 s)
#     --wallpaper desktop after login (autologin=1, capture at 12 s)
#
#   Meta-modes (iterate multiple surfaces in one invocation):
#     --typography  Pass C reference set: iterates {login, lock, wallpaper}.
#                   Output PNG/PPM names are prefixed with "typography-"
#                   so reviewers can grep the Pass C chrome-text shots.
#                   The three surfaces cover the four Pass C type roles:
#                     login     -> Display (clock) + Title (panel header)
#                     lock      -> Title + Body (lock overlay text)
#                     wallpaper -> Body (menu rows) + Caption (taskbar date)
#
# USAGE
#   tools/test/tactility-screenshot-matrix.sh
#     -> single wallpaper PPM at build/shots/wallpaper-default.ppm
#   tools/test/tactility-screenshot-matrix.sh --login classic duet
#     -> 2 login PPMs: build/shots/login-classic.ppm, login-duet.ppm
#   tools/test/tactility-screenshot-matrix.sh --all
#     -> 10 wallpaper PPMs (default surface), one per theme
#   tools/test/tactility-screenshot-matrix.sh --lock --all
#     -> 10 lock PPMs, one per theme
#   tools/test/tactility-screenshot-matrix.sh --theme classic
#     -> single wallpaper PPM for theme 'classic'
#
# ENV
#   DUETOS_PRESET        -- build preset (default: x86_64-debug-fast)
#   DUETOS_LOG_DIR       -- output root (default: build)
#   DUETOS_TIMEOUT       -- per-theme boot timeout, seconds (default: 30)
#   DUETOS_CAPTURE_AT_MS -- override capture delay in ms (overrides surface default)
#
# OUTPUT
#   $DUETOS_LOG_DIR/shots/<surface>-<theme>.ppm   captured PPM
#   $DUETOS_LOG_DIR/shots/<surface>-<theme>.log   boot log
#
# EXIT 0 = every requested theme produced a non-empty PPM.
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
TIMEOUT="${DUETOS_TIMEOUT:-30}"

# ---------------------------------------------------------------------------
# Surface configuration — set by flag parsing below.
#
# SURFACE        one of: splash login lock wallpaper
# CAPTURE_AT_MS  delay after boot start before QMP screendump fires (ms)
# AUTOLOGIN      0 = show login screen, 1 = skip to desktop
# SURFACE_EXTRA  extra kernel cmdline tokens for the surface
# ---------------------------------------------------------------------------
SURFACE="wallpaper"
CAPTURE_AT_MS="${DUETOS_CAPTURE_AT_MS:-12000}"
AUTOLOGIN=1
SURFACE_EXTRA=""

# Typography meta-mode: when set to 1, the script iterates a fixed
# set of surfaces (declared in TYPOGRAPHY_SURFACES below) per theme
# and prefixes output filenames with "typography-".
TYPOGRAPHY_MODE=0
readonly TYPOGRAPHY_SURFACES=(login lock wallpaper)

# Theme filter — set via --theme <name> OR positional args.
declare -a THEME_ARGS

usage() {
    cat >&2 <<'EOF'
Usage: tactility-screenshot-matrix.sh [SURFACE] [THEME_SELECTOR] [theme ...]

Surface flags (mutually exclusive; default: --wallpaper):
  --splash      Capture mid-boot before login    (autologin=1, T+1.5 s)
  --login       Capture login GUI first paint    (autologin=0, T+8 s)
  --lock        Capture post-idle lock screen    (autologin=1 idlelock=2, T+10 s)
  --wallpaper   Capture desktop after login      (autologin=1, T+12 s)

Meta-modes (iterate multiple surfaces per theme):
  --typography  Pass C reference set: iterates {login, lock, wallpaper}
                with output PPMs named "typography-<surface>-<theme>.ppm"

Theme selectors (at most one):
  --all         All 10 registered themes
  --theme NAME  Single named theme
  (positional)  One or more theme names

Examples:
  tactility-screenshot-matrix.sh
  tactility-screenshot-matrix.sh --login --all
  tactility-screenshot-matrix.sh --lock classic duet
  tactility-screenshot-matrix.sh --wallpaper --theme highcontrast
  tactility-screenshot-matrix.sh --typography --theme duet
EOF
    exit 0
}

# Parse arguments — surface flags consumed first, then theme selectors.
DO_ALL=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --help|-h)
            usage
            ;;
        --splash)
            SURFACE=splash
            CAPTURE_AT_MS="${DUETOS_CAPTURE_AT_MS:-1500}"
            AUTOLOGIN=1
            SURFACE_EXTRA=""
            ;;
        --login)
            SURFACE=login
            CAPTURE_AT_MS="${DUETOS_CAPTURE_AT_MS:-8000}"
            AUTOLOGIN=0
            SURFACE_EXTRA=""
            ;;
        --lock)
            SURFACE=lock
            CAPTURE_AT_MS="${DUETOS_CAPTURE_AT_MS:-10000}"
            AUTOLOGIN=1
            SURFACE_EXTRA="idlelock=2"
            ;;
        --wallpaper)
            SURFACE=wallpaper
            CAPTURE_AT_MS="${DUETOS_CAPTURE_AT_MS:-12000}"
            AUTOLOGIN=1
            SURFACE_EXTRA=""
            ;;
        --typography)
            TYPOGRAPHY_MODE=1
            ;;
        --all)
            DO_ALL=1
            ;;
        --theme)
            if [[ $# -lt 2 ]]; then
                echo "ERROR: --theme requires an argument" >&2; exit 2
            fi
            THEME_ARGS+=("$2")
            shift
            ;;
        -*)
            echo "ERROR: unknown flag '$1'" >&2; exit 2
            ;;
        *)
            THEME_ARGS+=("$1")
            ;;
    esac
    shift
done

# Resolve the final theme list.
declare -a THEMES
if [[ ${DO_ALL} -eq 1 ]]; then
    THEMES=("${ALL_THEMES[@]}")
elif [[ ${#THEME_ARGS[@]} -gt 0 ]]; then
    THEMES=("${THEME_ARGS[@]}")
else
    THEMES=(default)
fi

if [[ ! -x "${REPO_ROOT}/tools/qemu/run.sh" ]] || [[ ! -x "${REPO_ROOT}/tools/qemu/qmp.sh" ]]
then
    echo "ERROR: tools/qemu/{run,qmp}.sh missing or not executable" >&2
    exit 2
fi
command -v qemu-system-x86_64 >/dev/null || { echo "ERROR: qemu-system-x86_64 missing" >&2; exit 2; }

mkdir -p "${SHOTS_DIR}"

# ---------------------------------------------------------------------------
# capture_theme THEME
#
# Boots the kernel with the surface-appropriate cmdline overrides, waits
# CAPTURE_AT_MS milliseconds (converted to seconds, rounded up), then
# fires QMP screendump.
#
# The tactility-selftest PASS poll from Pass A is retained for the
# wallpaper surface (where the compositor must be fully up).  For other
# surfaces the selftest may never emit (splash fires before it, login/lock
# stall it), so the poll is skipped and we rely solely on the timed delay.
#
# Output filename — without typography mode:
#   ${SHOTS_DIR}/${SURFACE}-${THEME}.ppm
# With --typography (TYPOGRAPHY_MODE=1) the basename is prefixed so the
# Pass C reference set is grep-able:
#   ${SHOTS_DIR}/typography-${SURFACE}-${THEME}.ppm
# ---------------------------------------------------------------------------
capture_theme() {
    local theme="$1"
    local name_prefix=""
    if [[ ${TYPOGRAPHY_MODE} -eq 1 ]]; then
        name_prefix="typography-"
    fi
    local ppm="${SHOTS_DIR}/${name_prefix}${SURFACE}-${theme}.ppm"
    local boot_log="${SHOTS_DIR}/${name_prefix}${SURFACE}-${theme}.log"

    # Build extra kernel cmdline: theme + autologin + surface extras.
    local extra_cmdline=""
    if [[ "${theme}" != "default" ]]; then
        extra_cmdline="theme=${theme}"
    fi
    extra_cmdline="${extra_cmdline:+${extra_cmdline} }autologin=${AUTOLOGIN}"
    if [[ -n "${SURFACE_EXTRA}" ]]; then
        extra_cmdline="${extra_cmdline} ${SURFACE_EXTRA}"
    fi

    # Convert ms to seconds, rounding up (minimum 1).
    local capture_delay_s=$(( (CAPTURE_AT_MS + 999) / 1000 ))
    [[ ${capture_delay_s} -lt 1 ]] && capture_delay_s=1

    echo "[shots] surface=${SURFACE} theme=${theme} preset=${PRESET} timeout=${TIMEOUT}s capture_at=${CAPTURE_AT_MS}ms"
    rm -f "${ppm}" "${boot_log}"

    DUETOS_PRESET="${PRESET}" DUETOS_TIMEOUT="${TIMEOUT}" \
        DUETOS_EXTRA_CMDLINE="${extra_cmdline}" \
        "${REPO_ROOT}/tools/qemu/run.sh" > "${boot_log}" 2>&1 &
    local run_pid=$!

    local cleanup_done=0
    cleanup_run() {
        if [[ ${cleanup_done} -eq 1 ]]; then return; fi
        cleanup_done=1
        if kill -0 "${run_pid}" 2>/dev/null; then
            DUETOS_PRESET="${PRESET}" "${REPO_ROOT}/tools/qemu/qmp.sh" quit >/dev/null 2>&1 || true
            sleep 1
            kill "${run_pid}" 2>/dev/null || true
        fi
        wait "${run_pid}" 2>/dev/null || true
    }

    if [[ "${SURFACE}" == "wallpaper" ]]; then
        # For the desktop surface, wait for the compositor ready signal
        # exactly as Pass A did — then take the additional timed delay.
        local deadline=$((SECONDS + TIMEOUT))
        while [[ ${SECONDS} -lt ${deadline} ]]; do
            if grep -q '\[tactility-selftest\] PASS' "${boot_log}" 2>/dev/null; then
                break
            fi
            sleep 1
        done

        if ! grep -q '\[tactility-selftest\] PASS' "${boot_log}" 2>/dev/null; then
            echo "[shots]   FAIL: tactility-selftest umbrella PASS never landed" >&2
            cleanup_run
            return 1
        fi

        # Small additional idle-redraw pause before sampling.
        sleep 2
    else
        # For splash/login/lock: just wait the surface-specific delay.
        # The selftest signal may never arrive for these surfaces.
        sleep "${capture_delay_s}"
    fi

    DUETOS_PRESET="${PRESET}" "${REPO_ROOT}/tools/qemu/qmp.sh" screenshot "${ppm}" >/dev/null 2>&1 || {
        echo "[shots]   FAIL: qmp.sh screenshot non-zero" >&2
        cleanup_run
        return 1
    }

    cleanup_run

    if [[ ! -s "${ppm}" ]]; then
        echo "[shots]   FAIL: PPM empty" >&2
        return 1
    fi

    local sz
    sz="$(stat -c %s "${ppm}" 2>/dev/null || echo unknown)"
    echo "[shots]   OK: ${ppm} (${sz} bytes)"
    return 0
}

# ---------------------------------------------------------------------------
# apply_surface_profile SURFACE_NAME
#
# Mutates the global surface config (SURFACE / CAPTURE_AT_MS / AUTOLOGIN /
# SURFACE_EXTRA) to the canonical defaults for the named surface.  Used by
# the --typography meta-mode to switch surfaces between captures of the
# same theme without re-parsing argv.  Honours DUETOS_CAPTURE_AT_MS only
# when the user pinned it explicitly (else uses each surface's default).
# ---------------------------------------------------------------------------
apply_surface_profile() {
    case "$1" in
        splash)
            SURFACE=splash
            CAPTURE_AT_MS="${DUETOS_CAPTURE_AT_MS:-1500}"
            AUTOLOGIN=1
            SURFACE_EXTRA=""
            ;;
        login)
            SURFACE=login
            CAPTURE_AT_MS="${DUETOS_CAPTURE_AT_MS:-8000}"
            AUTOLOGIN=0
            SURFACE_EXTRA=""
            ;;
        lock)
            SURFACE=lock
            CAPTURE_AT_MS="${DUETOS_CAPTURE_AT_MS:-10000}"
            AUTOLOGIN=1
            SURFACE_EXTRA="idlelock=2"
            ;;
        wallpaper)
            SURFACE=wallpaper
            CAPTURE_AT_MS="${DUETOS_CAPTURE_AT_MS:-12000}"
            AUTOLOGIN=1
            SURFACE_EXTRA=""
            ;;
        *)
            echo "ERROR: apply_surface_profile: unknown surface '$1'" >&2
            return 1
            ;;
    esac
}

# Build the list of surfaces to walk per theme.
declare -a SURFACES_TO_CAPTURE
if [[ ${TYPOGRAPHY_MODE} -eq 1 ]]; then
    SURFACES_TO_CAPTURE=("${TYPOGRAPHY_SURFACES[@]}")
    echo "[shots] mode=typography surfaces=${SURFACES_TO_CAPTURE[*]} themes=${#THEMES[@]} (total captures=$(( ${#SURFACES_TO_CAPTURE[@]} * ${#THEMES[@]} )))"
else
    SURFACES_TO_CAPTURE=("${SURFACE}")
fi

failed=0
total=0
for surface in "${SURFACES_TO_CAPTURE[@]}"
do
    apply_surface_profile "${surface}"
    for theme in "${THEMES[@]}"
    do
        total=$((total + 1))
        capture_theme "${theme}" || ((failed++)) || true
    done
done

# Optional contact-sheet via ImageMagick.  Build one sheet per surface
# captured (typography mode produces 3 sheets when --all is combined).
# Skipped when there's only one PPM total.
if [[ ${total} -gt 1 ]] && command -v montage >/dev/null 2>&1
then
    for surface in "${SURFACES_TO_CAPTURE[@]}"
    do
        sheet_prefix=""
        if [[ ${TYPOGRAPHY_MODE} -eq 1 ]]; then
            sheet_prefix="typography-"
        fi
        SHEET="${LOG_DIR}/tactility-matrix-${sheet_prefix}${surface}.png"
        available_ppms=()
        for theme in "${THEMES[@]}"
        do
            ppm="${SHOTS_DIR}/${sheet_prefix}${surface}-${theme}.ppm"
            [[ -s "${ppm}" ]] && available_ppms+=("${ppm}")
        done
        if [[ ${#available_ppms[@]} -gt 1 ]]
        then
            tile_x=5
            if [[ ${#available_ppms[@]} -lt 5 ]]
            then
                tile_x=${#available_ppms[@]}
            fi
            montage "${available_ppms[@]}" -tile "${tile_x}x" -geometry +4+4 -label '%t' "${SHEET}" 2>/dev/null && \
                echo "[shots] grid: ${SHEET}"
        fi
    done
fi

if [[ ${failed} -gt 0 ]]
then
    echo "[shots] FAIL: ${failed}/${total} captures failed (surfaces=${SURFACES_TO_CAPTURE[*]})" >&2
    exit 1
fi

echo "[shots] OK (${total}/${total} captures, surfaces=${SURFACES_TO_CAPTURE[*]})"
