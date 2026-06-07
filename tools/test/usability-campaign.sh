#!/usr/bin/env bash
#
# usability-campaign.sh - run a phase of the DuetOS usability campaign at
# host-max parallelism. Wraps desktop-qmp-session.sh (which namespaces
# every per-run artifact by INSTANCE) so N guests run concurrently without
# collision. Verdict per guest = boot-log-analyze on its serial log.
#
# USAGE:
#   usability-campaign.sh capacity
#   usability-campaign.sh explore   APP[:ICONX:ICONY] [APP...]
#   usability-campaign.sh chaos     gui|pe|syscall|resource [SECS]
#   usability-campaign.sh maxchaos  [SECS]     # all vectors at once, MAX_VMS guests
#   usability-campaign.sh extreme   [SECS]     # maxchaos + SMP8 + mem pressure
#
# ENV: DUETOS_PRESET (x86_64-debug)  PER_GUEST_MIB (1024)
set -euo pipefail
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly DRV="${SCRIPT_DIR}/drivers"
readonly SESSION="${SCRIPT_DIR}/desktop-qmp-session.sh"
PER_GUEST_MIB="${PER_GUEST_MIB:-1024}"

capacity() {
  local nproc free max
  nproc=$(nproc); free=$(free -m | awk '/^Mem:/{print $7}')
  max=$(( nproc-2 < free/PER_GUEST_MIB ? nproc-2 : free/PER_GUEST_MIB ))
  (( max < 1 )) && max=1
  echo "$max"
}

PRESET="${DUETOS_PRESET:-x86_64-debug}"
# desktop-qmp-session.sh writes the serial log to build/<preset>/sess-<INSTANCE>.serial.log
SERIAL_FOR() { echo "$(cd "${SCRIPT_DIR}/../.." && pwd)/build/${PRESET}/sess-${1}.serial.log"; }

run_one() {  # INSTANCE DRIVER  [extra env already exported]
  local inst="$1" drv="$2"
  bash "${SESSION}" "${inst}" "${drv}" >"/tmp/uc-${inst}.out" 2>&1 || true
  bash "${SCRIPT_DIR}/boot-log-analyze.sh" "$(SERIAL_FOR "${inst}")" \
    >"/tmp/uc-${inst}.verdict" 2>&1; echo "$inst rc=$? -> /tmp/uc-${inst}.verdict"
}

cmd="${1:?usage: see header}"; shift || true
case "$cmd" in
  capacity) capacity ;;
  explore)
    for spec in "$@"; do
      IFS=: read -r app ix iy <<<"$spec"
      EXPLORE_APP="$app" EXPLORE_ICON_X="${ix:-48}" EXPLORE_ICON_Y="${iy:-64}" \
        EXPLORE_SHOT_DIR="$(pwd)/docs/usability/screenshots/${app}" \
        run_one "exp-${app}" "${DRV}/explore-app-driver.py" &
      while (( $(jobs -r | wc -l) >= $(capacity) )); do wait -n; done
    done; wait ;;
  chaos)
    vector="${1:?gui|pe|syscall|resource}"; secs="${2:-75}"
    case "$vector" in
      gui)      drv="${DRV}/chaos-gui-driver.py" ;;
      pe)       drv="${DRV}/chaos-pe-driver.py" ;;
      syscall)  drv="${DRV}/chaos-syscall-driver.py" ;;
      resource) drv="${DRV}/chaos-syscall-driver.py"  # resource payloads live here
                export CHAOS_SECS="$secs" ;;
      *) echo "unknown vector $vector" >&2; exit 2 ;;
    esac
    CHAOS_SECS="$secs" run_one "chaos-${vector}" "$drv" ;;
  maxchaos)
    secs="${1:-90}"
    for v in gui pe syscall resource; do
      drv="${DRV}/chaos-${v}-driver.py"; [[ -f "$drv" ]] || drv="${DRV}/chaos-syscall-driver.py"
      CHAOS_SECS="$secs" run_one "max-${v}" "$drv" &
    done; wait ;;
  extreme)
    secs="${1:-120}"
    # Requires the DUETOS_SMP pass-through added to desktop-qmp-session.sh
    # in Task T-5 Step 4a (the stock script launches single-CPU).
    export DUETOS_SMP="${DUETOS_SMP:-8}"
    "${0}" maxchaos "$secs" ;;
  *) echo "unknown command $cmd" >&2; exit 2 ;;
esac
