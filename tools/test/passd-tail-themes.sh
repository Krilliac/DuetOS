#!/usr/bin/env bash
# One-shot helper: tail the last few lines of each per-theme verify log.
# Used by the 2026-05-25 audit to compare amber/highcontrast/duetclassic
# (timed-out) against duet/duetlight (PASS).
for theme in duet duetlight duetdeep duetsoft duetmono classic slate10 amber highcontrast duetclassic; do
    log="/tmp/passd-verify-${theme}.log"
    if [[ ! -f "${log}" ]]; then
        echo "=== ${theme}: NO LOG ==="
        continue
    fi
    last_ts=$(grep -oE 't=[0-9]+\.[0-9]+ms' "${log}" | tail -1)
    lines=$(wc -l < "${log}")
    bringup=$(grep -cE 'bringup-complete|Entering idle loop' "${log}")
    echo "=== ${theme}: lines=${lines} bringup=${bringup} last_ts=${last_ts} ==="
    tail -2 "${log}"
    echo
done
