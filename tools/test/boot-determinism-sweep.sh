#!/usr/bin/env bash
#
# Boot DuetOS N times with the canonical config and diff the
# per-boot signal to surface INTERMITTENT defects — the kind a
# single boot hides (ASLR / scheduling-order / hash-order /
# work-steal-timing races). CLAUDE.md: "one run is not enough for
# intermittent symptoms."
#
# A deterministic kernel must produce byte-stable counts here:
# self-test OK/FAIL/SKIP, AP-online count, panic count, and the
# DISTINCT lockdep (held,id) pairs. Raw lockdep inversion COUNT is
# legitimately timing-variable (global held-stack, documented) so
# it is reported but not failed on; a NEW distinct pair across
# runs is a real finding.
#
# Usage:
#   tools/test/boot-determinism-sweep.sh [runs] [per_boot_timeout_s]
# Defaults: runs=8 timeout=80
#
# Reusable rig (CLAUDE.md "Reusable Tooling"): re-run after any
# scheduler / SMP / per-CPU-data change to catch a regression that
# only shows up on 1 boot in N.

set -u
RUNS="${1:-8}"
# AP bring-up lands ~t=20000ms guest; wall time to there varies
# run-to-run under TCG, so a tight cap truncates the slow boots
# before the [smp] sentinel and skews the "aps varies" check.
TMO="${2:-120}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
cd "$REPO_ROOT"
SUM="/tmp/sweep-summary.tsv"
printf 'run\tverdict\tdone\taps\tselftest_ok\tselftest_fail\tselftest_skip\tpanic\tElines\tlockdep_n\tlockdep_pairs\n' > "$SUM"

for i in $(seq 1 "$RUNS"); do
    log="/tmp/sweep-${i}.log"
    DUETOS_TIMEOUT="$TMO" DUETOS_DISPLAY=none tools/qemu/run.sh > "$log" 2>&1 || true

    rep=$(tools/test/boot-log-analyze.sh "$log" 2>/dev/null)
    verdict=$(printf '%s' "$rep" | grep -aoE 'verdict: (OK|ATTENTION)' | awk '{print $2}')
    done=$(printf '%s' "$rep" | grep -aqE 'reached: boot : metrics bringup-complete' && echo yes || echo NO)
    # Authoritative, interleave-proof SMP count (single-write
    # sentinel from arch/x86_64/smp.cpp), not the racy per-AP line.
    aps=$(grep -aoE '\[smp\] online=[0-9]+/[0-9]+' "$log" 2>/dev/null | tail -1 | sed 's/\[smp\] online=//')
    ok=$(printf '%s' "$rep"   | sed -n 's/.*OK=\([0-9]*\).*/\1/p' | head -1)
    fail=$(printf '%s' "$rep" | sed -n 's/.*non-deliberate FAIL=\([0-9]*\).*/\1/p' | head -1)
    skip=$(printf '%s' "$rep" | sed -n 's/.*SKIP=\([0-9]*\).*/\1/p' | head -1)
    panic=$(grep -aE 'PANIC|TRIPLE|kernel oops|task-kill' "$log" 2>/dev/null \
            | grep -acvE 'selftest|self-test|deliberately|injected|sanity line' 2>/dev/null)
    elines=$(printf '%s' "$rep" | sed -n 's/.*non-deliberate \[E\] lines: \([0-9]*\).*/\1/p' | head -1)
    ldn=$(grep -acE 'inversion detected' "$log" 2>/dev/null)
    ldp=$(grep -aA1 'inversion detected' "$log" 2>/dev/null \
          | grep -aoE 'newly-acquired="[^"]*"|class="[^"]*"' | paste - - | sort -u \
          | tr '\n' ';' | sed 's/[[:space:]]\+/ /g')
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$i" "${verdict:-?}" "$done" "${aps:-?}" "${ok:-?}" "${fail:-?}" \
        "${skip:-?}" "${panic:-?}" "${elines:-?}" "${ldn:-?}" "${ldp:-none}" >> "$SUM"
    echo "[sweep] run $i/$RUNS: verdict=${verdict:-?} done=${done} aps=${aps:-?} ok=${ok:-?} fail=${fail:-?} panic=${panic:-?} lockdep_n=${ldn:-?}"
done

echo
echo "=== per-run table ($SUM) ==="
# `column` lives in bsdmainutils/util-linux and is not guaranteed on
# a minimal dev host; fall back to a tab-expanding pretty-printer so
# the sweep still prints its table instead of dying mid-report.
if command -v column >/dev/null 2>&1; then
    column -t -s$'\t' "$SUM"
else
    sed 's/\t/  |  /g' "$SUM"
fi
echo
echo "=== determinism verdict ==="
flag=0
for col in verdict done aps selftest_ok selftest_fail selftest_skip panic Elines lockdep_pairs; do
    cn=$(head -1 "$SUM" | tr '\t' '\n' | grep -nxF "$col" | cut -d: -f1)
    vals=$(tail -n +2 "$SUM" | cut -f"$cn" | sort -u)
    nv=$(printf '%s\n' "$vals" | grep -c .)
    if [ "$nv" -gt 1 ]; then
        echo "  !! NON-DETERMINISTIC: $col varies across runs ->"
        printf '%s\n' "$vals" | sed 's/^/       /'
        flag=1
    fi
done
ldn_spread=$(tail -n +2 "$SUM" | cut -f10 | sort -n | sed -n '1p;$p' | tr '\n' '-' | sed 's/-$//')
echo "  (lockdep raw count spread: ${ldn_spread} — count variance is expected/known; pair-set variance is not)"
[ "$flag" -eq 0 ] && echo "  OK — every determinism-critical signal is byte-stable across $RUNS boots"
exit "$flag"
