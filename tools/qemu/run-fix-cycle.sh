#!/usr/bin/env bash
#
# One-shot fix-journal cycle:
#   1. boot a smoke profile (default pe-winapi)
#   2. extract KERNEL.FIX from the on-disk NVMe image
#   3. generate a source STUB/GAP marker manifest
#   4. run gen-fix-report.py against it + marker manifest
#   5. run gen-fix-patches.py against it (dry-run, --out=fix-patches/)
#   6. print both reports + the boot summary line from serial
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
MARKERS_JSON="${BUILD_DIR}/fix-markers.json"

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

FILE_MAGIC_BYTES = b"FIXJ"
FILE_MAGIC = 0x4A584946
FILE_VERSION = 1
HEADER_SIZE = 16
RECORD_STRIDE = 128
MAX_RECORDS = 1024
HEADER = struct.Struct("<IIII")

img_path, out_path = sys.argv[1], sys.argv[2]
with open(img_path, "rb") as fh:
    data = fh.read()

candidates = []
scan = 0
while True:
    off = data.find(FILE_MAGIC_BYTES, scan)
    if off < 0:
        break
    scan = off + 1
    if off + HEADER_SIZE > len(data):
        continue
    magic, ver, count, rsvd = HEADER.unpack(data[off : off + HEADER_SIZE])
    if magic != FILE_MAGIC or ver != FILE_VERSION or rsvd != 0:
        continue
    if count > MAX_RECORDS:
        continue
    size = HEADER_SIZE + count * RECORD_STRIDE
    if off + size > len(data):
        continue
    candidates.append((count, off, size))

if not candidates:
    print(
        f"[fix-cycle] no valid FIXJ journal in {img_path}; "
        "writing an empty FIXJ so marker-only generation can continue",
        file=sys.stderr,
    )
    with open(out_path, "wb") as fh:
        fh.write(HEADER.pack(FILE_MAGIC, FILE_VERSION, 0, 0))
    sys.exit(0)

# Multiple valid blobs can exist in the reserved region or FAT archive
# chain. Prefer the richest snapshot; break ties by later offset, which
# is usually the latest overwrite in a raw block image scan.
count, off, size = max(candidates, key=lambda c: (c[0], c[1]))
with open(out_path, "wb") as fh:
    fh.write(data[off : off + size])
print(
    f"[fix-cycle] found {len(candidates)} valid FIXJ candidate(s); "
    f"selected offset {off} ({count} records, {size} bytes) -> {out_path}",
    file=sys.stderr,
)
PY

# A zero-record journal is still useful when paired with the marker
# manifest below: self-fix generation can create observability patches
# for source STUB/GAP comments even when this smoke profile hit no
# runtime gaps.

# 3. Generate the source marker manifest. The report uses it to
#    show cold/unobservable markers; patch generation uses it to
#    create safe FIX_NOTE_* observability patches for in-function
#    source markers.
python3 "${REPO_ROOT}/tools/build/gen-fix-markers.py" \
    --root "${REPO_ROOT}" \
    --output "${MARKERS_JSON}" >&2

# 4. Generate the markdown report.
echo "" >&2
echo "[fix-cycle] === fix journal report ===" >&2
if [[ -n "${BASELINE_ARG}" ]]; then
    python3 "${REPO_ROOT}/tools/build/gen-fix-report.py" \
        "${EXTRACTED_FIX}" "${BASELINE_ARG}" \
        --markers "${MARKERS_JSON}"
else
    python3 "${REPO_ROOT}/tools/build/gen-fix-report.py" \
        "${EXTRACTED_FIX}" \
        --markers "${MARKERS_JSON}"
fi

# 5. Generate candidate source patches.
echo "" >&2
echo "[fix-cycle] === patch generation ===" >&2
python3 "${REPO_ROOT}/tools/build/gen-fix-patches.py" \
    "${EXTRACTED_FIX}" \
    --markers "${MARKERS_JSON}" \
    --out="${FIX_OUT}"

echo "" >&2
echo "[fix-cycle] done. Patches under ${FIX_OUT}/" >&2
