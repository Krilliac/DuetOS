#!/usr/bin/env bash
#
# Run the in-kernel CPU load driver at a fixed (workers, seconds)
# under -smp 1 and -smp 4, and print a side-by-side of guest
# throughput + host-core utilisation so the SMP scaling /
# responsiveness delta is a single number, not a vibe.
#
# What it measures, per SMP setting:
#   - guest throughput : the loadtest "iterations" total (each =
#                         kCpuInnerLoop=4096 inner ops) in the same
#                         kernel-time window — the scaling signal.
#   - ctx switches     : scheduler pressure over the window.
#   - idle ticks       : cores starved vs saturated.
#   - host CPU peak/avg : qemu process %CPU (100% = one host core).
#                         ~1 core under -smp 1, up to ~4 under
#                         -smp 4 iff the work really parallelises.
#
# Usage:
#   tools/qemu/smp-loadtest-compare.sh [secs] [workers]
# Env:
#   DUETOS_PRESET  build preset (default x86_64-debug — must have
#                  its duetos.iso built; relative scaling is
#                  preset-independent so debug is fine)
#
# Reusable rig (CLAUDE.md "Reusable Tooling"): re-run after any
# scheduler / runqueue / lock-granularity change to catch a
# scaling regression.

SECS="${1:-8}"
WORKERS="${2:-8}"
PRESET="${DUETOS_PRESET:-x86_64-debug}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
cd "$REPO_ROOT"

run_one() {
    local smp="$1"
    local log="/tmp/smp-load-${smp}.log"
    local csv="/tmp/smp-load-${smp}.csv"
    : > "$log"; : > "$csv"

    # TCG boot bring-up dominates wall time, and emulating -smp 4
    # multiplies it (4 vCPUs of guest instructions on the host's
    # TCG threads), so the cap must clear the worst case (4-vCPU
    # boot + the kernel-time load window expanded by the TCG
    # slowdown factor), not just SECS.
    DUETOS_PRESET="$PRESET" DUETOS_SMP="$smp" DUETOS_TIMEOUT=$((SECS * 40 + 200)) \
        tools/qemu/run-stress.sh cpu "$SECS" "$WORKERS" > "$log" 2>&1 &
    local outer=$!

    local qpid="" clk; clk=$(getconf CLK_TCK)
    for _ in $(seq 1 200); do
        qpid=$(pgrep -nf qemu-system-x86_64 || true)
        [ -n "$qpid" ] && break
        sleep 0.1
    done
    [ -z "$qpid" ] && { echo "smp=$smp: qemu never started"; return 1; }

    local pt=0 pw=0
    while kill -0 "$qpid" 2>/dev/null; do
        local now ticks
        now=$(date +%s.%N)
        # utime+stime: fields 14+15 of /proc/pid/stat, but comm
        # (field 2) can contain spaces/parens — split on the last
        # ')' so field offsets are stable.
        ticks=$(awk '{ s=$0; sub(/^.*\) /,"",s); n=split(s,f," "); print f[12]+f[13] }' \
                "/proc/$qpid/stat" 2>/dev/null)
        [ -z "$ticks" ] && break
        if [ "$pt" -ne 0 ]; then
            local dt dk cpu
            dt=$(awk -v a="$now" -v b="$pw" 'BEGIN{printf "%.4f",a-b}')
            dk=$(( ticks - pt ))
            cpu=$(awk -v dt="$dt" -v dk="$dk" -v c="$clk" 'BEGIN{if(dt<=0){print 0}else{printf "%.1f",(dk/c)/dt*100}}')
            echo "$cpu" >> "$csv"
        fi
        pt=$ticks; pw=$now
        sleep 0.5
    done
    wait "$outer" 2>/dev/null

    # Guest-side throughput summary (from the loadtest console block).
    local iters ctxsw idle elapsed spawned
    iters=$(grep -aA1 'iterations:' "$log" | grep -aoE '[0-9]+' | head -1)
    spawned=$(grep -aA1 'workers spawned:' "$log" | grep -aoE '[0-9]+' | head -1)
    elapsed=$(grep -aA1 'elapsed ticks:' "$log" | grep -aoE '[0-9]+' | head -1)
    ctxsw=$(grep -aA1 'ctx switches:' "$log" | grep -aoE '[0-9]+' | head -1)
    idle=$(grep -aA1 'idle ticks:' "$log" | grep -aoE '[0-9]+' | head -1)
    local peak avg
    peak=$(sort -rn "$csv" 2>/dev/null | head -1)
    avg=$(awk '{s+=$1;n++} END{if(n)printf "%.1f",s/n; else print "n/a"}' "$csv")
    local done="no"
    grep -aq '^\[stress\] done' "$log" && done="yes"

    echo "smp=${smp}: done=${done} workers=${spawned:-?} elapsed_ticks=${elapsed:-?} iterations=${iters:-?} ctx_switches=${ctxsw:-?} idle_ticks=${idle:-?} host_cpu_peak=${peak:-?}% host_cpu_avg=${avg:-?}%"
    echo "${iters:-0}" > "/tmp/smp-iters-${smp}"
}

echo "[smp-compare] preset=${PRESET} mode=cpu secs=${SECS} workers=${WORKERS}"
run_one 1
run_one 4
i1=$(cat /tmp/smp-iters-1 2>/dev/null || echo 0)
i4=$(cat /tmp/smp-iters-4 2>/dev/null || echo 0)
if [ "$i1" -gt 0 ] && [ "$i4" -gt 0 ]; then
    awk -v a="$i4" -v b="$i1" 'BEGIN{printf "[smp-compare] throughput scaling (4cpu / 1cpu) = %.2fx\n", a/b}'
fi
