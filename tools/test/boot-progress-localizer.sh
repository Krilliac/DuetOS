#!/usr/bin/env bash
#
# Localize a kernel boot hang by reading the LAST useful sentinel
# the boot emitted, against a reference list of expected sentinels
# in order. Tells you "boot reached X, next expected is Y" in one
# command — turning the "tail the log, recognise the pattern, look
# up what comes next" loop into a single invocation.
#
# Designed for the debug pattern this session re-derived manually
# while chasing the SmpStartAps offline-AP routing hang (2026-05-22):
# boot logs were tailed, last lines eyeballed, the next expected
# sentinel was looked up in main.cpp / smp.cpp / sched.cpp —
# repeated for every iteration of probe-inject / rebuild / boot.
# This rig consolidates that loop into one report.
#
# Usage:
#   tools/test/boot-progress-localizer.sh [logfile]
# With no arg it picks the newest of:
#   /tmp/duetos-*.log build/*/stress-*.log build/*/*.log
#
# Exit status: 0 if the boot reached the final completion sentinel,
# 1 if it didn't (a hang or early fault). The exit code lets the
# rig double as a CI gate ("did this build's boot reach the end?").
#
# Reusable rig (CLAUDE.md "Reusable Tooling"). Pairs with the other
# boot-time analysers: `boot-log-analyze.sh` reports CLAUDE.md's
# full regression scan; this rig answers the narrower
# "where did it stop?" question.

set -u

LOG="${1:-}"
if [ -z "$LOG" ]; then
    # shellcheck disable=SC2012  # same auto-pick pattern as boot-log-analyze.sh
    LOG=$(ls -t /tmp/duetos-*.log build/*/stress-*.log build/*/*.log 2>/dev/null | head -1)
fi
if [ -z "$LOG" ] || [ ! -f "$LOG" ]; then
    echo "usage: $0 [logfile]   (no DuetOS serial log found to auto-pick)" >&2
    exit 2
fi

# The canonical boot sequence — each entry is "pattern|description".
# The patterns are ordered: a boot that reaches entry N is expected
# to reach entry N+1 next. Adding a new boot stage means inserting
# a row in the right place. Patterns are sed-style basic regex.
# The grep is unanchored so a partial line still matches.
sentinels=(
    'qemu accel=|QEMU launcher banner'
    '\[hv\] hypervisor present|hypervisor detection complete'
    'phase=earlycon complete|early console handed off'
    'phase=physmem complete|physical memory map parsed'
    'phase=paging complete|paging tables installed'
    'phase=heap complete|kernel heap online'
    'phase=apic complete|LAPIC initialised'
    'phase=time complete|timer subsystem online'
    'phase=percpubsp complete|BSP PerCpu installed'
    'phase=drivers complete|driver bring-up done'
    'phase=vfs complete|VFS mounted'
    'boot : metrics bringup-complete|bringup tail entry'
    'Bringing up APs|SmpStartAps entry'
    '\[arch/smp\] starting AP|first per-AP iteration'
    '\[smp\] online=|SMP bring-up complete sentinel'
    'phase=smp complete|post-SMP phase complete'
    '\[boot\] phase=userland|userland phase entered'
)

echo "------------------------------------------------------------"
echo "Boot-progress localizer: $LOG"
echo "  size=$(wc -c < "$LOG") bytes"
echo "------------------------------------------------------------"

# Find the last sentinel reached AND the first one not reached.
last_reached_idx=-1
last_reached_desc=""
last_reached_line=""
for i in "${!sentinels[@]}"; do
    pattern="${sentinels[$i]%%|*}"
    desc="${sentinels[$i]##*|}"
    # `tail -1` so a sentinel emitted multiple times reports its
    # latest emission (e.g. `Bringing up APs` only fires once but
    # `[arch/smp] starting AP` fires per-AP).
    match=$(grep -aE "$pattern" "$LOG" 2>/dev/null | tail -1)
    if [ -n "$match" ]; then
        last_reached_idx=$i
        last_reached_desc=$desc
        last_reached_line=$match
    fi
done

# Report reached / expected.
if [ "$last_reached_idx" -lt 0 ]; then
    echo "REACHED:  (no known sentinel — boot probably didn't start)"
    rc=1
else
    pattern="${sentinels[$last_reached_idx]%%|*}"
    echo "REACHED:  step $((last_reached_idx + 1))/${#sentinels[@]}  $last_reached_desc"
    echo "          pattern: $pattern"
    # Truncate the matched line to 120 cols so the report stays scannable.
    echo "          last:    $(printf '%s' "$last_reached_line" | head -c 120)"
fi

final_idx=$(( ${#sentinels[@]} - 1 ))
if [ "$last_reached_idx" -ge "$final_idx" ]; then
    echo "VERDICT:  reached the final sentinel — boot completed"
    rc=0
else
    next_idx=$(( last_reached_idx + 1 ))
    next_pattern="${sentinels[$next_idx]%%|*}"
    next_desc="${sentinels[$next_idx]##*|}"
    echo "EXPECTED: step $((next_idx + 1))/${#sentinels[@]}  $next_desc"
    echo "          pattern: $next_pattern"
    echo "VERDICT:  HANG — boot stopped before reaching '$next_desc'"
    rc=1
fi

# Tail of the log is often more useful than the last sentinel
# because the LAST output (panic banner, init-wedge, raw register
# dump) tells you what was happening when progress stopped. Cap
# the dump to 15 lines so the report stays one screen.
echo "------------------------------------------------------------"
echo "LAST LINES OF LOG (most-recent 15):"
tail -15 "$LOG" | sed 's/^/  /'

echo "------------------------------------------------------------"
exit "$rc"
