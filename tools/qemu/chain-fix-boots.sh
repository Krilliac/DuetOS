#!/usr/bin/env bash
#
# Chain N smoke-profile boots without resetting the NVMe image so
# the FAT32 KERNEL.FIX file rotates (KERNEL.FIX -> KERNEL.F0 -> F1
# -> F2 -> F3) and the fix-journal accumulates GAPs across profiles.
# A single boot only surfaces what that profile exercises; chaining
# 4-5 profiles surfaces a richer cross-section and lets the offline
# patch generator emit more `marker-log-*.patch` files (which gate
# on a per-pin `repeat_count >= --marker-log-threshold` cumulative
# count).
#
# Usage:
#   tools/qemu/chain-fix-boots.sh <profile> [<profile> ...]
#
# Example:
#   tools/qemu/chain-fix-boots.sh pe-hello pe-winapi pe-winkill ring3 linux
#
# After the chain runs, gather every FIXJ blob the kernel left in
# the NVMe image:
#
#   python3 - <<'PY'
#   import struct
#   HDR = struct.Struct("<IIII")
#   data = open("build/x86_64-debug/nvme0.img","rb").read()
#   for i, m in enumerate(
#       (off, HDR.unpack(data[off:off+16]))
#       for off in range(0, len(data)-16)
#       if data[off:off+4] == b"FIXJ"
#   ):
#       off, (magic, ver, count, rsvd) = m
#       if magic != 0x4A584946 or ver != 1 or rsvd != 0 or count > 1024: continue
#       sz = 16 + count*128
#       open(f"build/x86_64-debug/KERNEL.F{i}", "wb").write(data[off:off+sz])
#   PY
#
# Then aggregate with:
#   python3 tools/build/gen-fix-report.py build/x86_64-debug/KERNEL.F* \
#     | tee fix-aggregated.md
#   python3 tools/build/gen-fix-patches.py build/x86_64-debug/KERNEL.F0 \
#     --markers build/x86_64-debug/fix-markers.json \
#     --kernel-elf build/x86_64-debug/kernel/duetos-kernel.elf \
#     --enable-all-patches --marker-log-threshold 3 \
#     --out fix-patches/
#
# Env overrides:
#   DUETOS_PRESET    — build preset (default x86_64-debug)
#   DUETOS_TIMEOUT   — per-boot wallclock cap in seconds (default 180)
#
# Caveat: this trades the per-boot determinism guarantee of run.sh
# (which regenerates nvme0.img every invocation) for cross-boot
# accumulation. Use it for fix-journal triage, not for regression
# determinism work.

set -euo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

if [[ $# -lt 1 ]]; then
    echo "usage: $0 <profile> [<profile> ...]" >&2
    echo "       profiles: bringup ring3 pe-hello pe-winapi pe-winkill linux browser" >&2
    exit 2
fi

PRESET="${DUETOS_PRESET:-x86_64-debug}"
TIMEOUT="${DUETOS_TIMEOUT:-180}"
BUILD_DIR="${REPO_ROOT}/build/${PRESET}"
NVME="${BUILD_DIR}/nvme0.img"
SATA="${BUILD_DIR}/sata0.img"
MAKE_GPT="${SCRIPT_DIR}/make-gpt-image.py"
LOG_DIR="${BUILD_DIR}/chain-fix-logs"

mkdir -p "${LOG_DIR}"

# Save the real GPT image builder and swap in a no-op while we
# chain — the no-op makes run.sh preserve the previous boot's NVMe
# state, which is what lets the FAT32 KERNEL.FIX rotation work.
# Trap restores the real builder on any exit path.
SAVED_GPT=$(mktemp -t make-gpt-image.real.XXXXXX.py)
cp "${MAKE_GPT}" "${SAVED_GPT}"
restore_gpt() {
    cp "${SAVED_GPT}" "${MAKE_GPT}"
    rm -f "${SAVED_GPT}"
}
trap restore_gpt EXIT

# Prime: build a fresh GPT once via the real builder, then swap in
# the noop so subsequent run.sh invocations keep this image.
python3 "${SAVED_GPT}" "${NVME}"
python3 "${SAVED_GPT}" "${SATA}"

cat > "${MAKE_GPT}" <<'NOOP'
#!/usr/bin/env python3
# tools/qemu/chain-fix-boots.sh installs this stub so run.sh leaves
# the existing nvme0.img / sata0.img in place between chained boots.
# The real builder is restored on chain-fix-boots.sh exit (trap).
import sys
print(f"[chain-fix-boots] preserving {sys.argv[1]}")
NOOP
chmod +x "${MAKE_GPT}"

for prof in "$@"; do
    log="${LOG_DIR}/${prof}.log"
    echo "[chain-fix-boots] === boot profile=${prof} log=${log} ==="
    if DUETOS_PRESET="${PRESET}" \
       DUETOS_SMOKE_PROFILE="${prof}" \
       DUETOS_TIMEOUT="${TIMEOUT}" \
       "${SCRIPT_DIR}/run.sh" > "${log}" 2>&1; then
        rc=0
    else
        rc=$?
    fi
    # exit 33 is the QEMU isa-debug-exit sentinel path for smoke
    # profiles; treat as success.
    if [[ "${rc}" != "0" && "${rc}" != "33" ]]; then
        echo "[chain-fix-boots] profile=${prof} FAILED (exit=${rc}); see ${log}" >&2
        tail -10 "${log}" >&2
        exit "${rc}"
    fi
    echo "[chain-fix-boots] profile=${prof} ok (rc=${rc})"
done

echo "[chain-fix-boots] done. NVMe at ${NVME}; logs at ${LOG_DIR}/"
echo "[chain-fix-boots] extract FIX blobs with the Python snippet in this script's header,"
echo "[chain-fix-boots] then run tools/build/gen-fix-{report,patches}.py against them."
