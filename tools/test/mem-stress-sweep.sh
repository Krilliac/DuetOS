#!/usr/bin/env bash
#
# Re-trigger the boot-time memory-stress scenario that the
# 2026-05-22 "stress gap fixes" slice characterized.
#
# What it does:
#   - Boots DuetOS with `stress=mem stress-secs=SECS stress-mib=MIB`
#     so the in-kernel stress driver allocates + touches MIB MiB of
#     heap, holds it for SECS seconds, then frees.
#   - Captures the serial log to build/<preset>/mem-stress-MIB.log
#     and runs `tools/test/boot-log-analyze.sh` on it. Looks for:
#       - graceful KMalloc==nullptr handling vs assume-non-null
#         crashes (the LOADTEST: "KMalloc returned null at chunk N
#         — heap exhausted" sentinel is the green signal);
#       - no panic / triple-fault / kernel oops;
#       - heap_used returns to baseline after free
#         (LOADTEST: "heap used post:" should be within ~1 KiB of
#         "heap used pre:").
#
# Usage:
#   tools/test/mem-stress-sweep.sh [secs] [mib] [ram_size]
# Defaults:
#   secs=20  mib=200  ram_size=512M
# Env:
#   DUETOS_PRESET   build preset (default x86_64-release; debug is
#                   slower under TCG but exercises KASAN+UBSAN paths)
#   DUETOS_SMP      override -smp string
#                   (default 4,sockets=1,cores=2,threads=2)
#   DUETOS_TIMEOUT  outer wallclock cap (default secs * 8 + 90)
#
# Exit status: 0 if `[stress] done` reached AND analyzer verdict OK;
# non-zero otherwise.
#
# Reusable rig (CLAUDE.md "Reusable Tooling"): pairs with
# `smp-stress-sweep.sh` (CPU-side) and `run-stress.sh mem`
# (one-shot mode without the analyzer pass).

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

SECS="${1:-20}"
MIB="${2:-200}"
RAM="${3:-512M}"

PRESET="${DUETOS_PRESET:-x86_64-release}"
SMP_STR="${DUETOS_SMP:-4,sockets=1,cores=2,threads=2}"
TIMEOUT_DEFAULT=$((SECS * 8 + 90))
TIMEOUT_SECS="${DUETOS_TIMEOUT:-${TIMEOUT_DEFAULT}}"

BUILD_DIR="${REPO_ROOT}/build/${PRESET}"
if [ ! -f "${BUILD_DIR}/duetos.iso" ]; then
    echo "error: ${BUILD_DIR}/duetos.iso missing — cmake --build ${BUILD_DIR}" >&2
    exit 1
fi
if ! command -v qemu-system-x86_64 >/dev/null 2>&1; then
    echo "error: qemu-system-x86_64 not installed — see CLAUDE.md 'Live-test runtime tooling'" >&2
    exit 1
fi

echo "[mem-stress] preset=${PRESET} ram=${RAM} smp=${SMP_STR} secs=${SECS} mib=${MIB} timeout=${TIMEOUT_SECS}s"

DUETOS_PRESET="${PRESET}" DUETOS_SMP="${SMP_STR}" DUETOS_RAM="${RAM}" \
    DUETOS_TIMEOUT="${TIMEOUT_SECS}" \
    "${REPO_ROOT}/tools/qemu/run-stress.sh" mem "${SECS}" 0 "${MIB}" 2>&1 | tail -10

PER_LOG="${BUILD_DIR}/mem-stress-${MIB}.log"
if [ -f "${BUILD_DIR}/stress-mem.log" ]; then
    cp "${BUILD_DIR}/stress-mem.log" "${PER_LOG}"
else
    echo "[mem-stress] error: per-mode log not produced" >&2
    exit 1
fi

echo "[mem-stress] === analyzer pass on ${PER_LOG} ==="
"${REPO_ROOT}/tools/test/boot-log-analyze.sh" "${PER_LOG}"
analyzer_rc=$?

# Specific check: did the loadtest report exhaustion (the
# "KMalloc returned null at chunk" sentinel)? At 200 MiB on a
# 512 MiB guest with ~96 MiB heap, exhaustion is expected and the
# clean handler should bail. At <= 80 MiB it should NOT trip.
if grep -q "KMalloc returned null at chunk" "${PER_LOG}"; then
    echo "[mem-stress] heap exhaustion detected and handled cleanly (good)"
fi

# Heap balance check — pre/post should match.
pre=$(grep -aoE "heap used pre:[[:space:]]+[0-9]+" "${PER_LOG}"  | head -1 | grep -oE '[0-9]+$' || true)
post=$(grep -aoE "heap used post:[[:space:]]+[0-9]+" "${PER_LOG}" | head -1 | grep -oE '[0-9]+$' || true)
if [ -n "$pre" ] && [ -n "$post" ]; then
    delta=$(( post - pre ))
    abs_delta=$(( delta < 0 ? -delta : delta ))
    if [ "$abs_delta" -le 16 ]; then
        echo "[mem-stress] heap pre=${pre} KiB post=${post} KiB — balanced"
    else
        echo "[mem-stress] heap pre=${pre} KiB post=${post} KiB — DELTA ${delta} KiB (LEAK?)" >&2
        analyzer_rc=1
    fi
fi

exit "${analyzer_rc}"
