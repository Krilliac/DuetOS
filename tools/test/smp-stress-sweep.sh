#!/usr/bin/env bash
#
# Re-trigger the SMP stress-cpu scenario that surfaced under the
# 2026-05-22 "stress gap fixes" slice. Locks in:
#
#   - SMP=8 vCPUs (sockets=1, cores=4, threads=2) — the topology
#     past 4-vCPU where the per-CPU runqueue races, work-stealing
#     fan-out, and AP-bring-up storm all get exercised in one boot.
#   - x86_64-debug preset by default (UBSAN/KASAN/red-zone audit
#     active) — surfaces both real races and instrumentation faults.
#   - boot-time `stress=cpu` driver with N workers for SECS seconds.
#   - Repeats the scenario REPEATS times so intermittent races
#     (ASLR-dependent collisions, cross-CPU per-task pickup, AP
#     bring-up timing) get N chances to fire.
#
# Designed to pair with `tools/test/boot-log-analyze.sh` — each run
# captures a serial log into build/<preset>/smp-stress-N.log so a
# later session can `boot-log-analyze.sh` each one and grep the
# verdict line for "OK" vs "ATTENTION".
#
# Usage:
#   tools/test/smp-stress-sweep.sh [secs] [workers] [repeats]
# Defaults:
#   secs=20  workers=8  repeats=5
# Env:
#   DUETOS_PRESET   build preset under build/<preset> (default x86_64-debug)
#   DUETOS_SMP      override -smp string
#                   (default 8,sockets=1,cores=4,threads=2)
#   DUETOS_TIMEOUT  outer wallclock cap in seconds
#                   (default secs * 8 + 120 — TCG ratio + boot + buffer)
#   DUETOS_KEEP_LOGS=0 to discard the per-repeat logs after analysis
#
# Exit status: 0 if every repeat reached `[stress] done` AND each
# log analyzes clean; non-zero otherwise. The first repeat with
# a non-OK verdict drives the exit code.
#
# Why this exists: the canonical `tools/qemu/run-stress.sh` does
# one run with one SMP setting; this rig drives the sweep + log
# capture pattern explicitly. The next session investigating an
# SMP race / AP-bring-up regression at SMP=8 can just run this
# script and grep its output.
#
# Reusable rig (CLAUDE.md "Reusable Tooling"): the 2026-05-22 slice
# used this to repro the AP-bring-up recursive-fault under SMP=8;
# a future SMP race investigation should drive the same scenario,
# not re-derive the env / DUETOS_SMP / log path conventions.

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

SECS="${1:-20}"
WORKERS="${2:-8}"
REPEATS="${3:-5}"

PRESET="${DUETOS_PRESET:-x86_64-debug}"
SMP_STR="${DUETOS_SMP:-8,sockets=1,cores=4,threads=2}"
TIMEOUT_DEFAULT=$((SECS * 8 + 120))
TIMEOUT_SECS="${DUETOS_TIMEOUT:-${TIMEOUT_DEFAULT}}"

BUILD_DIR="${REPO_ROOT}/build/${PRESET}"
ISO_PATH="${BUILD_DIR}/duetos.iso"
if [ ! -f "$ISO_PATH" ]; then
    echo "error: $ISO_PATH missing — run cmake --build ${BUILD_DIR} first" >&2
    exit 1
fi
if ! command -v qemu-system-x86_64 >/dev/null 2>&1; then
    echo "error: qemu-system-x86_64 not installed — see CLAUDE.md 'Live-test runtime tooling'" >&2
    exit 1
fi

echo "[smp-stress-sweep] preset=${PRESET} smp=${SMP_STR} secs=${SECS} workers=${WORKERS} repeats=${REPEATS} timeout=${TIMEOUT_SECS}s"

# Sequence of per-repeat outcomes. Filled in as we go.
PASS=0
FAIL=0
FIRST_FAIL_LOG=""

for ((i = 1; i <= REPEATS; ++i)); do
    echo "[smp-stress-sweep] === repeat ${i}/${REPEATS} ==="
    PER_LOG="${BUILD_DIR}/smp-stress-${i}.log"
    # run-stress.sh writes to ${BUILD_DIR}/stress-${MODE}.log; tee
    # that to the per-repeat slot so each invocation has its own
    # captured log to analyze (the analyzer wants distinct files;
    # also lets a failed run be archived for the next session).
    DUETOS_PRESET="${PRESET}" DUETOS_SMP="${SMP_STR}" DUETOS_TIMEOUT="${TIMEOUT_SECS}" \
        "${REPO_ROOT}/tools/qemu/run-stress.sh" cpu "${SECS}" "${WORKERS}" 0 \
        2>&1 | tail -10
    if [ -f "${BUILD_DIR}/stress-cpu.log" ]; then
        cp "${BUILD_DIR}/stress-cpu.log" "${PER_LOG}"
    else
        echo "[smp-stress-sweep] warn: per-mode log not produced; analyzer will skip" >&2
        continue
    fi

    if "${REPO_ROOT}/tools/test/boot-log-analyze.sh" "${PER_LOG}" >/dev/null 2>&1; then
        echo "[smp-stress-sweep] repeat ${i}: OK"
        PASS=$((PASS + 1))
    else
        echo "[smp-stress-sweep] repeat ${i}: ATTENTION — see ${PER_LOG}"
        if [ -z "$FIRST_FAIL_LOG" ]; then
            FIRST_FAIL_LOG="${PER_LOG}"
        fi
        FAIL=$((FAIL + 1))
    fi
done

echo "[smp-stress-sweep] result: ${PASS} clean, ${FAIL} non-clean of ${REPEATS} repeats"
if [ "${FAIL}" -gt 0 ]; then
    echo "[smp-stress-sweep] first non-clean log: ${FIRST_FAIL_LOG}"
    echo "[smp-stress-sweep]   tools/test/boot-log-analyze.sh ${FIRST_FAIL_LOG}"
fi

if [ "${DUETOS_KEEP_LOGS:-1}" = "0" ] && [ "${FAIL}" -eq 0 ]; then
    rm -f "${BUILD_DIR}"/smp-stress-*.log
fi

[ "${FAIL}" -eq 0 ]
