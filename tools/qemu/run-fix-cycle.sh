#!/usr/bin/env bash
#
# One-shot fix-journal cycle:
#   1. boot a smoke profile (default pe-winapi)
#   2. extract KERNEL.FIX from the on-disk NVMe image
#   3. run gen-fix-report.py against it
#   4. run gen-fix-patches.py against it (dry-run, --out=fix-patches/)
#   5. print both reports + the boot summary line from serial
#
# Usage:
#   tools/qemu/run-fix-cycle.sh                       # default profile
#   DUETOS_SMOKE_PROFILE=ring3 tools/qemu/run-fix-cycle.sh
#   tools/qemu/run-fix-cycle.sh --baseline=fix-baseline.txt
#
# Pass-through env vars:
#   DUETOS_PRESET            (default x86_64-debug)
#   DUETOS_SMOKE_PROFILE     (default pe-winapi)
#   DUETOS_TIMEOUT           (default 300)
#   DUETOS_FIX_OUT           (default fix-patches/)
#
# Exits non-zero if the smoke run itself failed (boot didn't reach
# the sentinel) — but a clean smoke with NEW journal records is still
# considered success: the patches are advisory, not gating.

set -euo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

PRESET="${DUETOS_PRESET:-x86_64-debug}"
PROFILE="${DUETOS_SMOKE_PROFILE:-pe-winapi}"
TIMEOUT="${DUETOS_TIMEOUT:-300}"
FIX_OUT="${DUETOS_FIX_OUT:-${REPO_ROOT}/fix-patches}"
BUILD_DIR="${REPO_ROOT}/build/${PRESET}"
NVME_IMG="${BUILD_DIR}/nvme0.img"
LOG_FILE="${BUILD_DIR}/fix-cycle-${PROFILE}.log"
EXTRACTED_FIX="${BUILD_DIR}/KERNEL.FIX"

BASELINE_ARG=""
for arg in "$@"; do
    case "$arg" in
        --baseline=*) BASELINE_ARG="$arg" ;;
        *) echo "warning: ignoring unknown arg '$arg'" >&2 ;;
    esac
done

echo "[fix-cycle] preset=${PRESET} profile=${PROFILE} timeout=${TIMEOUT}s" >&2
echo "[fix-cycle] log=${LOG_FILE}" >&2

# 1. Boot the smoke profile. Capture serial to the log file. The
#    inner script handles QEMU lifecycle + timeout + isa-debug-exit.
DUETOS_PRESET="${PRESET}" \
DUETOS_SMOKE_PROFILE="${PROFILE}" \
DUETOS_TIMEOUT="${TIMEOUT}" \
"${SCRIPT_DIR}/run.sh" >"${LOG_FILE}" 2>&1 || {
    rc=$?
    # exit 33 is the sentinel-reached path under run.sh's KVM exit
    # code mapping; treat it as success. Anything else is a real
    # smoke failure and we abort the cycle.
    if [[ "$rc" != "33" ]]; then
        echo "[fix-cycle] smoke FAILED (exit=$rc); see ${LOG_FILE}" >&2
        tail -20 "${LOG_FILE}" >&2
        exit "$rc"
    fi
}

# Print the smoke completion line + boot-summary block from the log.
echo "" >&2
echo "[fix-cycle] === smoke summary ===" >&2
grep -E "smoke.*profile=.*complete|fix_journal_summary|fix_journal=ok|fix_journal_persist=ok" "${LOG_FILE}" >&2 || true
echo "" >&2

# 2. Extract KERNEL.FIX from the NVMe image. The on-disk format is
#    a 16-byte FIXJ header + N*128-byte records. We locate the
#    header by magic and copy the full blob to a host-side file.
if [[ ! -f "${NVME_IMG}" ]]; then
    echo "[fix-cycle] no NVMe image at ${NVME_IMG}; cannot extract" >&2
    exit 1
fi

python3 - "$NVME_IMG" "$EXTRACTED_FIX" <<'PY'
import struct
import sys

img_path, out_path = sys.argv[1], sys.argv[2]
with open(img_path, "rb") as fh:
    data = fh.read()
off = data.find(b"FIXJ")
if off < 0:
    print(f"[fix-cycle] no FIXJ magic in {img_path} — empty journal?", file=sys.stderr)
    sys.exit(0)
header = data[off : off + 16]
magic, ver, count, _rsvd = struct.unpack("<IIII", header)
if magic != 0x4A584946:
    print(f"[fix-cycle] bad magic 0x{magic:08x} at {off}", file=sys.stderr)
    sys.exit(1)
size = 16 + count * 128
with open(out_path, "wb") as fh:
    fh.write(data[off : off + size])
print(f"[fix-cycle] extracted {size} bytes ({count} records) -> {out_path}", file=sys.stderr)
PY

# Empty journal is a success state — nothing to triage.
if [[ ! -s "${EXTRACTED_FIX}" ]]; then
    echo "[fix-cycle] no records to triage. Done." >&2
    exit 0
fi

# 3. Generate the markdown report.
echo "" >&2
echo "[fix-cycle] === fix journal report ===" >&2
if [[ -n "${BASELINE_ARG}" ]]; then
    python3 "${REPO_ROOT}/tools/build/gen-fix-report.py" "${EXTRACTED_FIX}" "${BASELINE_ARG}"
else
    python3 "${REPO_ROOT}/tools/build/gen-fix-report.py" "${EXTRACTED_FIX}"
fi

# 4. Generate candidate source patches.
echo "" >&2
echo "[fix-cycle] === patch generation ===" >&2
python3 "${REPO_ROOT}/tools/build/gen-fix-patches.py" "${EXTRACTED_FIX}" --out="${FIX_OUT}"

echo "" >&2
echo "[fix-cycle] done. Patches under ${FIX_OUT}/" >&2
