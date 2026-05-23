#!/usr/bin/env bash
#
# trampoline-scribble-sweep.sh — measure the proactive trampoline-RA
# slot validator's fire rate across N boots. Used to bisect whether
# a candidate fix in the kstack / TLB-shootdown / scheduler chain
# moves the fire rate (CLAUDE.md "intermittent bugs ARE bugs — they're
# just sensitive to randomness").
#
# The validator lives at kernel/sched/sched.cpp:2386 and fires on
# switch-IN when the trampoline RA slot (stack_top - 8 of a kernel-
# only task) holds something that isn't `&SchedTaskTrampoline` /
# +0x17 / +0x1c. The pre-fix baseline (per Roadmap, "Boot-tail #UD")
# is ~65% on SMP=8 release boots. A fix that drops this to ~0% is
# the root cause; a fix that doesn't move it is in the wrong layer.
#
# Usage:
#   tools/test/trampoline-scribble-sweep.sh [runs] [timeout_s]
# Defaults: runs=30 timeout=45
#
# Env (passed through to run.sh):
#   DUETOS_PRESET   default: x86_64-release
#   DUETOS_SMP      default: 8,sockets=1,cores=8,threads=1
#   DUETOS_DISPLAY  forced to none

set -u
RUNS="${1:-30}"
TMO="${2:-45}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
cd "$REPO_ROOT" || exit 2

: "${DUETOS_PRESET:=x86_64-release}"
: "${DUETOS_SMP:=8,sockets=1,cores=8,threads=1}"
export DUETOS_PRESET DUETOS_SMP
export DUETOS_DISPLAY=none

SCRIBBLE_PAT='TRAMPOLINE RA SLOT scribbled|trampoline RA slot scribbled'
SUM="/tmp/trampoline-scribble-sweep.tsv"
LOGDIR="/tmp/scribble-sweep-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$LOGDIR"

printf 'run\tverdict\tscribbled\tobserved\tdone\tpanic\n' > "$SUM"

scribbled_count=0
done_count=0
panic_count=0

for i in $(seq 1 "$RUNS"); do
    log="$LOGDIR/run-${i}.log"
    DUETOS_TIMEOUT="$TMO" tools/qemu/run.sh > "$log" 2>&1 || true

    if grep -aqE "$SCRIBBLE_PAT" "$log"; then
        scribbled="yes"
        observed=$(grep -aoE 'observed=0x[0-9a-fA-F]+' "$log" | head -1 | cut -d= -f2)
        scribbled_count=$((scribbled_count + 1))
    else
        scribbled="no"
        observed="-"
    fi

    if grep -aqE 'boot : metrics bringup-complete' "$log"; then
        done="yes"
        done_count=$((done_count + 1))
    else
        done="NO"
    fi

    panic="no"
    # Match every panic shape the kernel can emit: classic PANIC banner,
    # CPU-exception trap shape, [panic] / [panic-summary] tags from
    # PanicWithValue, the recursive-panic short-circuit. Without
    # [panic]/[panic-summary] in the alternation, a soft-panic boot
    # (post-bringup PanicWithValue) gets logged as verdict=OK because
    # bringup-complete was already reached before the panic landed.
    if grep -aqE 'PANIC|\*\* CPU EXCEPTION \*\*|kernel oops|\[panic-summary\]|\[panic\] CPU halted|recursive-panic' "$log"; then
        panic="yes"
        panic_count=$((panic_count + 1))
        verdict="PANIC"
    elif [ "$done" = "yes" ]; then
        verdict="OK"
    else
        verdict="TIMEOUT"
    fi

    printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$i" "$verdict" "$scribbled" "${observed:-?}" "$done" "$panic" >> "$SUM"
    echo "[scribble-sweep] run $i/$RUNS verdict=$verdict scribbled=$scribbled observed=${observed:-?}"
done

echo
echo "=== summary ($SUM) ==="
if command -v column >/dev/null 2>&1; then
    column -t -s$'\t' "$SUM"
else
    sed 's/\t/  |  /g' "$SUM"
fi
echo
echo "=== aggregate ==="
echo "  runs            : $RUNS"
echo "  trampoline-scrb : $scribbled_count / $RUNS  ($(awk -v s="$scribbled_count" -v r="$RUNS" 'BEGIN { printf "%.1f", 100*s/r }')%)"
echo "  panic (any)     : $panic_count / $RUNS"
echo "  bringup-done    : $done_count / $RUNS"
echo "  logs            : $LOGDIR"
echo
echo "Baseline (pre-fix, Roadmap 'Boot-tail #UD'): ~65% scribble rate on SMP=8 release."
echo "A successful fix moves the trampoline-scrb rate to ~0/N."
