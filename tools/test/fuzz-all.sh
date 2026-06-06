#!/usr/bin/env bash
#
# fuzz-all.sh — build every libFuzzer harness in tests/fuzz and run
# them all at once against DuetOS, then aggregate the results.
#
# WHY: the fuzz harnesses were grown one subsystem at a time (PE,
# ELF, GPT, FAT32, exFAT, NTFS, ext4, net, wireless). The point of
# building them up was to eventually throw EVERYTHING at the OS in
# one shot — a single command that exercises every untrusted-input
# parser in parallel and tells you, with one exit code, whether any
# of them fell over. That is this script. It doubles as a CI gate:
# non-zero exit iff any harness produced a crash / timeout / OOM /
# leak artifact, so it can sit in a workflow unmodified.
#
# Seeded corpora: harnesses with a seeds/gen_<name>_seeds.py get
# their corpus pre-seeded (so the fuzzer starts past the format
# gate); the rest start from whatever corpus/ already holds.
#
# USAGE: tools/test/fuzz-all.sh
# ENV:   FUZZ_SECONDS  per-harness wall budget       (default 60)
#        FUZZ_JOBS     max harnesses in parallel     (default nproc)
#        FUZZ_DIR      tests/fuzz location           (default repo tests/fuzz)
#
# Quick triage one-liners (artifacts are per-harness under
# build/art/<name>/ so a crash names its own harness):
#   ls tests/fuzz/build/art/*/crash-* tests/fuzz/corpus/*/crash-* 2>/dev/null
#   tests/fuzz/build/fuzz_<name> tests/fuzz/build/art/<name>/crash-*  # replay

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
FUZZ_DIR="${FUZZ_DIR:-${REPO_ROOT}/tests/fuzz}"
FUZZ_SECONDS="${FUZZ_SECONDS:-60}"
FUZZ_JOBS="${FUZZ_JOBS:-$(nproc 2>/dev/null || echo 4)}"

cd "${FUZZ_DIR}" || { echo "fuzz-all: no ${FUZZ_DIR}" >&2; exit 2; }

echo "== fuzz-all: building every harness =="
if ! make all >/tmp/fuzz-all-build.log 2>&1; then
    echo "fuzz-all: build FAILED — see /tmp/fuzz-all-build.log" >&2
    tail -20 /tmp/fuzz-all-build.log >&2
    exit 2
fi

mapfile -t HARNESSES < <(find build -maxdepth 1 -type f -name 'fuzz_*' -perm -u+x -printf '%f\n' | sort)
if [ "${#HARNESSES[@]}" -eq 0 ]; then
    echo "fuzz-all: no harness binaries in build/" >&2
    exit 2
fi

echo "== fuzz-all: ${#HARNESSES[@]} harnesses, ${FUZZ_SECONDS}s each, ${FUZZ_JOBS} in parallel =="

# Per-harness corpus + libFuzzer flags. Disk/exec-image parsers
# carry large valid seeds so they need a bigger max_len; the
# wireless/eapol parsers are small.
maxlen_for() {
    case "$1" in
        fuzz_ext4)  echo 1048576 ;;
        fuzz_pe)    echo 131072  ;;
        fuzz_gpt|fuzz_fat32|fuzz_exfat|fuzz_ntfs) echo 262144 ;;
        fuzz_aml)   echo 262144  ;;
        fuzz_net)   echo 2048    ;;
        fuzz_acpi)  echo 65536   ;;
        *)          echo 4096    ;;
    esac
}

run_one() {
    local h="$1" name="${1#fuzz_}"
    local corpus="corpus/${name}" gen="seeds/gen_${name}_seeds.py"
    mkdir -p "${corpus}" "build/art/${name}"
    [ -f "${gen}" ] && python3 "${gen}" "${corpus}" >/dev/null 2>&1
    # -timeout=20 turns a hung input into a recorded artifact
    # instead of a wedged job. -artifact_prefix scopes the
    # crash/timeout/oom/leak file to this harness's own dir —
    # without it every harness shares build/ as CWD, so ONE
    # crash (or a stale leftover) makes the results scan flag
    # all 24 FAIL and you can't tell which harness fell over.
    ( cd build && "./${h}" \
        -max_total_time="${FUZZ_SECONDS}" \
        -max_len="$(maxlen_for "${h}")" \
        -timeout=20 \
        -artifact_prefix="art/${name}/" \
        "../${corpus}" >"/tmp/fuzz-all-${name}.log" 2>&1 )
}

# Throttle to FUZZ_JOBS concurrent harnesses.
pids=()
for h in "${HARNESSES[@]}"; do
    run_one "${h}" &
    pids+=($!)
    while [ "$(jobs -rp | wc -l)" -ge "${FUZZ_JOBS}" ]; do wait -n; done
done
wait

echo
echo "== fuzz-all: results =="
fail=0
printf '%-14s %-8s %s\n' "HARNESS" "VERDICT" "DETAIL"
for h in "${HARNESSES[@]}"; do
    name="${h#fuzz_}"
    art=$(find "build/art/${name}" "corpus/${name}" -maxdepth 1 -type f \
        \( -name 'crash-*' -o -name 'timeout-*' -o -name 'oom-*' -o -name 'leak-*' \) \
        2>/dev/null | head -1)
    if [ -n "${art}" ]; then
        printf '%-14s %-8s %s\n' "${name}" "FAIL" "artifact: ${art}"
        fail=1
    else
        stats=$(grep -hoE 'cov: [0-9]+ ft: [0-9]+' "/tmp/fuzz-all-${name}.log" 2>/dev/null | tail -1)
        printf '%-14s %-8s %s\n' "${name}" "ok" "${stats:-ran}"
    fi
done

echo
if [ "${fail}" -ne 0 ]; then
    echo "fuzz-all: FAIL — at least one harness produced a crash artifact." >&2
    echo "Replay: tests/fuzz/build/fuzz_<name> tests/fuzz/build/art/<name>/<artifact>" >&2
    exit 1
fi
echo "fuzz-all: PASS — every harness survived ${FUZZ_SECONDS}s clean."
exit 0
