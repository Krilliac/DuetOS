#!/usr/bin/env bash
#
# run-exe.sh — stage an arbitrary Windows .exe onto DuetOS's FAT32 disk
#              image and run it headlessly under QEMU, then report whether
#              the kernel's PE loader picked it up, loaded it, resolved its
#              imports, and ran it to exit.
#
# WHAT:
#   1. Encodes the host .exe path into a DOS 8.3 short filename (SFN).
#   2. Exports DUETOS_STAGE_FILES="$SFN=$hostexe" so tools/qemu/make-gpt-image.py
#      injects the file into the FAT32 ROOT directory when run.sh regenerates
#      nvme0.img on each boot.
#   3. Exports DUETOS_EXTRA_CMDLINE="peexec=$SFN" so the kernel's boot path
#      reads <SFN> off FAT32 vol 0 after mount and SpawnPeFile()s it.
#   4. Boots via tools/qemu/run.sh, capturing COM1 serial to a log.
#   5. Greps the serial log and prints a concise load/run report.
#
# WHY:
#   Until now the only PE on the image was a fixed seed. This harness lets a
#   developer drop ANY freestanding host .exe onto the image and watch the
#   kernel's [peexec]/[pe-load]/[dll-load] path execute it, with one command.
#
# USAGE:
#   tools/test/run-exe.sh <host-exe-path> [SFN]
#     <host-exe-path>  path to the .exe on the dev host (read by make-gpt-image)
#     [SFN]            optional explicit DOS 8.3 name (e.g. HELLO.EXE).
#                      Defaults to basename upper-cased + truncated to 8.3.
#
# ENV:
#   DUETOS_TIMEOUT   seconds to let QEMU run before TERM (default 45).
#   DUETOS_PRESET    build preset (passed through to run.sh; default its own).
#   Any other run.sh env var is honoured (DUETOS_SMP, DUETOS_ACCEL, ...).
#   Note: this script sets DUETOS_EXTRA_CMDLINE, so do not also set it.
#
# OUTPUT:
#   Serial log at /tmp/run-exe-<SFN>.log (path printed at the end).
#
# QUICK ANALYSIS (after a run):
#   grep -nE '^\[peexec\]|\[pe-load\]|\[dll-load\]' /tmp/run-exe-<SFN>.log
#   grep -nE 'unresolved|missing|thunk' /tmp/run-exe-<SFN>.log

set -euo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
readonly RUN_SH="${REPO_ROOT}/tools/qemu/run.sh"

if [[ $# -lt 1 || $# -gt 2 ]]; then
    echo "usage: $0 <host-exe-path> [SFN]" >&2
    exit 2
fi

HOST_EXE="$1"
if [[ ! -f "${HOST_EXE}" ]]; then
    echo "error: host exe not found: ${HOST_EXE}" >&2
    exit 2
fi
# make-gpt-image.py opens the path verbatim; give it an absolute one so the
# cwd at QEMU-launch time can't matter.
HOST_EXE="$(cd "$(dirname "${HOST_EXE}")" && pwd)/$(basename "${HOST_EXE}")"

# Derive the SFN. Explicit arg wins; otherwise upper-case the basename and
# truncate base->8, ext->3 (e.g. /x/help.exe -> HELP.EXE; longname.dll ->
# LONGNAME.DLL stays as-is at 8, weirdverylong.exe -> WEIRDVER.EXE).
derive_sfn() {
    local base ext name
    name="$(basename "$1")"
    name="$(printf '%s' "${name}" | tr '[:lower:]' '[:upper:]')"
    if [[ "${name}" == *.* ]]; then
        ext="${name##*.}"
        base="${name%.*}"
    else
        base="${name}"
        ext=""
    fi
    base="${base:0:8}"
    ext="${ext:0:3}"
    if [[ -n "${ext}" ]]; then
        printf '%s.%s' "${base}" "${ext}"
    else
        printf '%s' "${base}"
    fi
}

if [[ $# -eq 2 ]]; then
    SFN="$(printf '%s' "$2" | tr '[:lower:]' '[:upper:]')"
else
    SFN="$(derive_sfn "${HOST_EXE}")"
fi

LOG="/tmp/run-exe-${SFN}.log"

echo "[run-exe] host exe : ${HOST_EXE}"
echo "[run-exe] SFN      : ${SFN}"
echo "[run-exe] cmdline  : peexec=${SFN}"
echo "[run-exe] log      : ${LOG}"
echo "[run-exe] booting (timeout ${DUETOS_TIMEOUT:-45}s)..."

# run.sh regenerates nvme0.img via make-gpt-image.py each boot, so exporting
# DUETOS_STAGE_FILES is all the staging that's needed.
export DUETOS_STAGE_FILES="${SFN}=${HOST_EXE}"
export DUETOS_EXTRA_CMDLINE="peexec=${SFN}"
export DUETOS_TIMEOUT="${DUETOS_TIMEOUT:-45}"

# Capture both COM1 (stdout) and run.sh's own diagnostics (stderr). `timeout`
# inside run.sh returns non-zero on TERM; don't let that abort the report.
set +e
bash "${RUN_SH}" >"${LOG}" 2>&1
RC=$?
set -e

echo
echo "==================== run-exe report (${SFN}) ===================="
echo "[qemu exit] rc=${RC}"
echo

# --- Kernel peexec handler result ----------------------------------------
echo "--- [peexec] handler ---"
if grep -nE '^\[peexec\]' "${LOG}"; then :; else
    echo "  (no [peexec] lines — kernel handler may not be built, or cmdline"
    echo "   not honoured. Staging still round-tripped if make-gpt-image ran.)"
fi
echo

# --- PE load + DLL import resolution -------------------------------------
echo "--- [pe-load] / [dll-load] ---"
grep -nE '^\[pe-load\]|^\[dll-load\]' "${LOG}" || echo "  (none)"
echo

# --- Import / thunk problems ---------------------------------------------
echo "--- imports / unresolved / missing / thunk ---"
grep -niE 'unresolved|missing|thunk|import' "${LOG}" || echo "  (none)"
echo

# --- Faults ---------------------------------------------------------------
echo "--- faults (PANIC / TRIPLE / #GP / #PF / task-kill) ---"
grep -nE 'PANIC|TRIPLE|#GP|#PF|task-kill|kernel oops' "${LOG}" || echo "  (none)"
echo

# --- Verdict --------------------------------------------------------------
echo "--- verdict ---"
loaded="no"; ran="no"; exitcode="?"
if grep -qiE 'spawn|pid|loaded' <(grep -E '^\[peexec\]|^\[pe-load\]' "${LOG}"); then
    loaded="likely"
fi
if grep -qiE 'exit|exited|returned' "${LOG}"; then
    ran="likely"
    exitcode="$(grep -niE 'exit|exited|returned' "${LOG}" | head -1)"
fi
echo "  PE loaded?  ${loaded}"
echo "  PE ran/exited?  ${ran}"
[[ "${exitcode}" != "?" ]] && echo "  exit signal: ${exitcode}"
echo
echo "  full serial log: ${LOG}"
echo "================================================================="
