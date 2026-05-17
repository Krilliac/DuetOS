#!/usr/bin/env bash
#
# Boot DuetOS (autologin desktop) headless and sample the QEMU
# host-CPU over time, correlating every sample with the guest
# serial-log timestamp. Use it to locate / quantify a CPU spike
# during bringup or steady-state, and to get before/after numbers
# when fixing one.
#
# Why correlate against the guest [t=...ms] stamp instead of wall
# clock: GRUB's menu timeout + OVMF run before the kernel emits
# any timestamp, so wall time alone can't tell "firmware idle wait"
# from "kernel bringup". Each row pins host-CPU% to the guest's own
# notion of time, so a spike maps straight onto the boot-log line
# that caused it.
#
# Usage:
#   tools/qemu/cpu-probe.sh [timeout_secs]      # default 80
# Env:
#   DUETOS_PRESET   build preset (default x86_64-debug)
# Output:
#   $LOG  — full serial log (also has the [t=...ms] stamps)
#   $CSV  — wall_s,cpu_pct,guest_t  (one row per ~200 ms sample)
#
# Quick analysis:
#   # peak samples
#   tail -n +2 "$CSV" | sort -t, -k2 -rn | head
#   # CPU vs guest time across the run
#   tail -n +2 "$CSV" | awk -F, 'NR%12==1{print $1"s "$2"% "$3}'
#
# A spike that collapses to ~0% the instant some guest activity
# stops is that activity's cost; grep the serial log around that
# guest-t window to name it (group fs/driver/sched line volume).

set -u
TIMEOUT_SECS="${1:-80}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
LOG="${DUETOS_CPU_LOG:-/tmp/duetos-cpu.log}"
CSV="${DUETOS_CPU_CSV:-/tmp/cpu_samples.csv}"
: > "$LOG"
echo "wall_s,cpu_pct,guest_t" > "$CSV"

cd "$REPO_ROOT"
DUETOS_TIMEOUT="$TIMEOUT_SECS" DUETOS_DISPLAY=none tools/qemu/run.sh > "$LOG" 2>&1 &
RUN_PID=$!

# Linux truncates /proc/<pid>/comm to 15 chars, so pgrep by name
# misses "qemu-system-x86_64" — match the full command line.
QPID=""
for _ in $(seq 1 60); do
    QPID=$(pgrep -nf qemu-system-x86_64 || true)
    [ -n "$QPID" ] && break
    sleep 0.1
done
[ -z "$QPID" ] && { echo "qemu never started — see $LOG"; exit 1; }

CLK=$(getconf CLK_TCK)
prev_ticks=0
prev_wall=0
start_wall=$(date +%s.%N)

while kill -0 "$QPID" 2>/dev/null; do
    now=$(date +%s.%N)
    st=$(cat /proc/$QPID/stat 2>/dev/null) || break
    rest=${st#*) }                 # skip pid + (comm); fields 14/15 follow
    set -- $rest
    ticks=$(( $12 + $13 ))         # utime + stime (clock ticks)
    wall_rel=$(awk -v a="$now" -v b="$start_wall" 'BEGIN{printf "%.3f", a-b}')
    if [ "$prev_ticks" -ne 0 ]; then
        dt=$(awk -v a="$now" -v b="$prev_wall" 'BEGIN{printf "%.4f", a-b}')
        dk=$(( ticks - prev_ticks ))
        cpu=$(awk -v dt="$dt" -v dk="$dk" -v c="$CLK" 'BEGIN{ if(dt<=0){print 0}else{printf "%.1f",(dk/c)/dt*100} }')
        ts=$(grep -aoE '\[t=[0-9.]+ms\]' "$LOG" | tail -1)
        echo "${wall_rel},${cpu},${ts}" >> "$CSV"
    fi
    prev_ticks=$ticks
    prev_wall=$now
    sleep 0.2
done
wait "$RUN_PID" 2>/dev/null
echo "done; samples=$(($(wc -l < "$CSV") - 1))  log=$LOG  csv=$CSV"
