#!/usr/bin/env bash
#
# pe-corpus-run.sh — run a whole corpus of host Windows .exes on DuetOS and
#                    grade each one, producing a compatibility report.
#
# WHAT:
#   Wraps tools/test/run-exe.sh in a loop and classifies each run's serial log
#   into one outcome, so "does this batch of apps work" is one command and one
#   table rather than N boots read by hand.
#
#   Grades, in ladder order — each rung strictly further than the last:
#     NOTFOUND    the kernel never found the staged file on FAT32
#     LOADFAIL    [pe-load] never reached OK (bad image / rejected)
#     NOSPAWN     image loaded but no ring-3 task was created
#     FASTFAIL    ring-3 __fastfail — the CRT aborted and named a reason
#     FAULT       ring-3 fault (AV / #UD / #GP) with no clean exit
#     EXIT-<rc>   process ran and called ExitProcess with that code
#     CLEAN       process ran and exited 0
#
# WHY:
#   Rung-by-rung progress on the Win32 subsystem is only visible against a
#   fixed corpus. Re-running this after a slice shows exactly which binaries
#   moved up a rung — and which regressed, which a single hand-run boot of the
#   one app you were working on will never tell you.
#
# USAGE:
#   tools/test/pe-corpus-run.sh <exe-or-dir> [<exe-or-dir> ...]
#
# ENV:
#   DUETOS_TIMEOUT   per-boot seconds (default 150 — a TCG boot is slow)
#   DUETOS_PRESET    build preset (default x86_64-debug; the smoke
#                    signatures this greps for are Info-level, so a
#                    release build will grade everything NOTFOUND)
#   CORPUS_OUT       report path (default ./pe-corpus-report.tsv)
#   CORPUS_LOGDIR    where per-exe serial logs are kept (default /tmp)
#
# OUTPUT:
#   A TSV report (grade, detail, exe) plus the same table on stdout.
#   Per-run serial logs stay at $CORPUS_LOGDIR/run-exe-<SFN>.log for triage.
#
# QUICK ANALYSIS (after a run):
#   sort pe-corpus-report.tsv | awk -F'\t' '{print $1}' | uniq -c
#   grep FASTFAIL pe-corpus-report.tsv

set -uo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
readonly RUN_EXE="${SCRIPT_DIR}/run-exe.sh"

if [[ $# -lt 1 ]]; then
    echo "usage: $0 <exe-or-dir> [<exe-or-dir> ...]" >&2
    exit 2
fi

OUT="${CORPUS_OUT:-${PWD}/pe-corpus-report.tsv}"
LOGDIR="${CORPUS_LOGDIR:-/tmp}"
export DUETOS_TIMEOUT="${DUETOS_TIMEOUT:-150}"
export DUETOS_PRESET="${DUETOS_PRESET:-x86_64-debug}"

# Collect the corpus. Directories contribute their .exe files, one level deep —
# recursing into a game's whole tree would queue hundreds of boots by accident.
exes=()
for arg in "$@"; do
    if [[ -d "${arg}" ]]; then
        while IFS= read -r f; do exes+=("${f}"); done \
            < <(find "${arg}" -maxdepth 1 -type f -iname '*.exe' | sort)
    elif [[ -f "${arg}" ]]; then
        exes+=("${arg}")
    else
        echo "warn: skipping (not found): ${arg}" >&2
    fi
done

if [[ ${#exes[@]} -eq 0 ]]; then
    echo "error: corpus is empty" >&2
    exit 2
fi

printf 'grade\tdetail\texe\n' > "${OUT}"
echo "== running ${#exes[@]} binaries (timeout ${DUETOS_TIMEOUT}s each) =="

# Derive the same DOS 8.3 short name run-exe.sh would pick, so we can find the
# log it wrote. Keep this in step with run-exe.sh's own SFN derivation.
sfn_for() {
    local base="${1##*/}"
    local stem="${base%.*}"
    stem="$(printf '%s' "${stem}" | tr 'a-z' 'A-Z' | tr -cd 'A-Z0-9_' | cut -c1-8)"
    [[ -z "${stem}" ]] && stem="PE"
    printf '%s.EXE' "${stem}"
}

for exe in "${exes[@]}"; do
    sfn="$(sfn_for "${exe}")"
    log="${LOGDIR}/run-exe-${sfn}.log"
    rm -f "${log}"
    printf '  %-40s ' "${exe##*/}"

    bash "${RUN_EXE}" "${exe}" "${sfn}" >/dev/null 2>&1

    grade="NOTFOUND"
    detail="-"
    if [[ -f "${log}" ]]; then
        if grep -q '\[pe-load\] OK' "${log}"; then
            grade="NOSPAWN"
        elif grep -q '\[peexec\] read bytes=' "${log}"; then
            grade="LOADFAIL"
        fi

        if grep -q '\[ring3\] pe spawn' "${log}"; then
            grade="FAULT"
            # An exit rc is only meaningful once the task actually ran.
            rc="$(grep -oE 'sys : exit rc[^(]*val=0x[0-9a-fA-F]+' "${log}" | tail -1 |
                grep -oE '0x[0-9a-fA-F]+' | tail -1)"
            if grep -q '__fastfail' "${log}"; then
                grade="FASTFAIL"
                detail="$(grep -oE 'fail-fast reason[^"]*"[^"]*"' "${log}" | tail -1 |
                    grep -oE '"[^"]*"' | tr -d '"')"
                [[ -z "${detail}" ]] && detail="$(grep -oE 'fail-fast code[^(]*val=0x[0-9a-fA-F]+' "${log}" |
                    tail -1 | grep -oE '0x[0-9a-fA-F]+' | tail -1)"
            elif [[ -n "${rc}" ]]; then
                if [[ "${rc}" == "0x0" ]]; then
                    grade="CLEAN"
                else
                    grade="EXIT-${rc}"
                fi
            fi
        fi

        # Always record the first unresolved import — it is the single most
        # actionable detail for anything that did not reach CLEAN, and it is
        # lost if we only keep the grade.
        if [[ "${detail}" == "-" ]]; then
            miss="$(grep -oE 'unknown import -> catch-all NO-OP[^"]*"[^"]*"' "${log}" | head -1 |
                grep -oE '"[^"]*"' | tr -d '"')"
            [[ -n "${miss}" ]] && detail="miss:${miss}"
        fi
    fi

    printf '%s\t%s\t%s\n' "${grade}" "${detail}" "${exe}" >> "${OUT}"
    printf '%s (%s)\n' "${grade}" "${detail}"
done

echo
echo "== summary =="
tail -n +2 "${OUT}" | cut -f1 | sort | uniq -c | sort -rn
echo
echo "report: ${OUT}"
