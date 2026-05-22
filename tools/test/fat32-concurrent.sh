#!/usr/bin/env bash
#
# Characterize FAT32 contention under concurrent ring-3 workloads.
#
# DuetOS' FAT32 driver serializes every public operation through one
# global `g_fat32_mutex` (kernel/fs/fat32.cpp:68). Two saturation
# corners are visible without rewriting the locking:
#   1. Priority inversion (no priority inheritance today)
#   2. Livelock under wake-storm — many tasks wake + park instead of
#      doing FS work.
#
# This rig drives the worst-case workload that already exists in the
# kernel boot path:
#   - The Linux synfs ELF (kernel/subsystems/linux/ring3_smoke.cpp's
#     `SpawnSynfsElf`) — issues the mkdir/rename/chmod/truncate/...
#     FS-mutation surface against FAT32.
#   - The Win32 PE smoke (ring3-hello-pe et al.) — also hits FAT32
#     for path lookup + file read.
# Both run from the boot tail under profile=None, so a plain
# `boot=tty` boot exercises the contention. We just need to capture
# the log and measure the rate.
#
# Captures the serial log, then prints:
#   - total `fs/fat32 : lookup` lines      (driver entry-point hits)
#   - distinct path strings observed
#   - any `mutex` parking / waking sentinels
#   - any `inversion detected` lockdep warnings tagging fat32
#   - any non-deliberate `[E]` lines from fs/fat32
#
# Usage:
#   tools/test/fat32-concurrent.sh [secs]   (default 60)
# Env:
#   DUETOS_PRESET   build preset (default x86_64-release; debug
#                   produces more contention because UBSAN/KASAN
#                   slow each FAT32 call)
#   DUETOS_SMP      override -smp string
#                   (default 4,sockets=1,cores=2,threads=2)
#   DUETOS_TIMEOUT  outer wallclock cap (default secs * 6 + 90)
#
# Exit status: 0 if no non-deliberate [E] fs/fat32 lines AND no
# new inversion (beyond the deliberate selftest-A/B pair); non-zero
# otherwise.
#
# Reusable rig (CLAUDE.md "Reusable Tooling"): re-run after any
# fs/fat32 locking change to compare contention numbers.

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

SECS="${1:-60}"
PRESET="${DUETOS_PRESET:-x86_64-release}"
SMP_STR="${DUETOS_SMP:-4,sockets=1,cores=2,threads=2}"
TIMEOUT_DEFAULT=$((SECS * 6 + 90))
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

# Drive the existing stress-spin path — the spin driver mostly
# stays out of the way of the boot-tail PE/synfs smokes which
# generate the FAT32 contention we want to observe. `spin` is the
# lightest-weight stress mode (single CPU spin, no extra workers)
# so it doesn't drown the synfs/PE smoke transcripts in
# loadtest-cpu output.
LOG="${BUILD_DIR}/fat32-concurrent-${SECS}.log"
rm -f "${LOG}"

echo "[fat32-concurrent] preset=${PRESET} smp=${SMP_STR} secs=${SECS} timeout=${TIMEOUT_SECS}s"

DUETOS_PRESET="${PRESET}" DUETOS_SMP="${SMP_STR}" \
    DUETOS_TIMEOUT="${TIMEOUT_SECS}" \
    "${REPO_ROOT}/tools/qemu/run-stress.sh" spin "${SECS}" 0 0 2>&1 | tee /dev/null > /dev/null || true

if [ -f "${BUILD_DIR}/stress-spin.log" ]; then
    cp "${BUILD_DIR}/stress-spin.log" "${LOG}"
else
    echo "[fat32-concurrent] error: per-mode log not produced" >&2
    exit 1
fi

echo
echo "=== FAT32 CONTENTION REPORT (${LOG}) ==="
# grep -c always prints a count (0 if none) on stdout; it exits 1
# on zero matches. Do NOT chain `|| echo 0` — bash would then run
# both grep's "0" output AND echo's "0", giving the arithmetic
# below a two-line string that bombs with "syntax error in
# expression". Same gotcha boot-log-analyze.sh's gc() documents.
lookup_count=$(grep -ac "fs/fat32 : lookup" "${LOG}" 2>/dev/null; true)
distinct_paths=$(grep -aoE 'fs/fat32 : lookup[^"]+"[^"]+"' "${LOG}" \
                 | grep -oE '"[^"]+"' | sort -u | wc -l)
mutex_wait=$(grep -ac "mutex.*wait\|MutexLock.*block\|waiter" "${LOG}" 2>/dev/null; true)
inv_count=$(grep -ac "inversion detected" "${LOG}" 2>/dev/null; true)
# Selftest-A/B is the deliberate lockdep self-test; deduct it.
expected_selftest_inv=1
real_inv=$((inv_count - expected_selftest_inv))
[ "$real_inv" -lt 0 ] && real_inv=0
err_fat32=$(grep -acE '\[E\] .*fs/fat32' "${LOG}" 2>/dev/null; true)

echo "  fs/fat32 lookup line-rate:      ${lookup_count} over ${SECS}s = $(( lookup_count / (SECS > 0 ? SECS : 1) ))/sec"
echo "  distinct path strings:          ${distinct_paths}"
echo "  mutex-block / waiter sentinels: ${mutex_wait}"
echo "  lockdep inversions (real):      ${real_inv} (after subtracting 1 deliberate self-test)"
echo "  fs/fat32 [E] lines:             ${err_fat32}"
echo

if [ "${err_fat32}" -gt 0 ] || [ "${real_inv}" -gt 0 ]; then
    echo "[fat32-concurrent] non-clean: investigate above counters"
    grep -aE '\[E\] .*fs/fat32|inversion detected' "${LOG}" | head -5
    exit 1
fi

echo "[fat32-concurrent] no non-deliberate fs/fat32 errors or inversions in ${SECS}s window"
exit 0
