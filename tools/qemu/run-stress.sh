#!/usr/bin/env bash
#
# Boot DuetOS straight into a stress-driver run.
#
# Usage:
#   tools/qemu/run-stress.sh <mode> [secs] [workers] [mib]
#     mode    : cpu | mem | mix | spin
#     secs    : run window in seconds (default 10)
#     workers : CPU worker count for cpu/mix (default 8)
#     mib     : MiB to allocate for mem/mix (default 32)
#
# Builds a sidecar ISO that pins a synthetic grub entry passing
# `boot=tty stress=<mode> stress-secs=... stress-workers=... stress-mib=...`
# on the kernel cmdline, then runs it through tools/qemu/run.sh.
#
# Captures the serial transcript to ${BUILD_DIR}/stress-<mode>.log
# so the boot-time `[stress] start` / `[stress] done` sentinels are
# observable from outside the VM.
#
# Env overrides forwarded to run.sh:
#   DUETOS_PRESET   — build preset under build/<preset> (default x86_64-release)
#   DUETOS_TIMEOUT  — outer wallclock cap in seconds (default secs + 30)
#   DUETOS_RAM      — QEMU -m (default 512M)
#   DUETOS_SMP      — QEMU -smp (default unset = single CPU)
#
# Exits 0 if `[stress] done` appears in the serial log within the
# timeout window; non-zero otherwise.

set -euo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

if [[ $# -lt 1 ]]; then
    echo "usage: $0 <cpu|mem|mix|spin> [secs] [workers] [mib]" >&2
    exit 2
fi

MODE="$1"
SECS="${2:-10}"
WORKERS="${3:-8}"
MIB="${4:-32}"

case "${MODE}" in
    cpu|mem|mix|spin) ;;
    *) echo "error: bad mode '${MODE}' (expected cpu|mem|mix|spin)" >&2; exit 2 ;;
esac

PRESET="${DUETOS_PRESET:-x86_64-release}"
BUILD_DIR="${REPO_ROOT}/build/${PRESET}"
ISO_OUT="${BUILD_DIR}/duetos-stress-${MODE}.iso"
ISO_STAGE="${BUILD_DIR}/duetos-stress-${MODE}-stage"
SERIAL_LOG="${BUILD_DIR}/stress-${MODE}.log"

if [[ ! -f "${BUILD_DIR}/duetos.iso" ]]; then
    echo "error: canonical ISO not built at ${BUILD_DIR}/duetos.iso" >&2
    echo "       cmake --build ${BUILD_DIR}" >&2
    exit 1
fi
if ! command -v grub-mkrescue >/dev/null 2>&1; then
    echo "error: grub-mkrescue missing — install qemu-system-x86 grub-* xorriso mtools ovmf" >&2
    exit 1
fi

# Stage a sidecar ISO whose grub.cfg has exactly one menu entry — the
# stress entry. timeout=0 means GRUB fires immediately; no nav keys.
rm -rf "${ISO_STAGE}" "${ISO_OUT}" "${SERIAL_LOG}"
mkdir -p "${ISO_STAGE}/boot/grub"
cp "${BUILD_DIR}/kernel/iso-stage/boot/duetos-kernel.elf" \
   "${ISO_STAGE}/boot/duetos-kernel.elf"
cat > "${ISO_STAGE}/boot/grub/grub.cfg" <<EOF
set timeout=0
set default=0
menuentry "DuetOS — Stress ${MODE}" {
    multiboot2 /boot/duetos-kernel.elf boot=tty stress=${MODE} stress-secs=${SECS} stress-workers=${WORKERS} stress-mib=${MIB}
    boot
}
EOF
grub-mkrescue --compress=xz -o "${ISO_OUT}" "${ISO_STAGE}" >/dev/null 2>&1

# Outer timeout: stress window + heap settle + boot bring-up. Bring-up
# is the dominant cost (a few seconds on TCG); 30s is generous.
TIMEOUT_DEFAULT=$((SECS + 30))
export DUETOS_TIMEOUT="${DUETOS_TIMEOUT:-${TIMEOUT_DEFAULT}}"
export DUETOS_SMOKE_ISO="${ISO_OUT}"
export DUETOS_PRESET="${PRESET}"

echo "[run-stress] mode=${MODE} secs=${SECS} workers=${WORKERS} mib=${MIB}"
echo "[run-stress] iso=${ISO_OUT}"
echo "[run-stress] timeout=${DUETOS_TIMEOUT}s"
echo "[run-stress] serial log -> ${SERIAL_LOG}"

# Tee serial so we both see it live and have a file to grep.
# Disable pipefail just for the tee pipeline — `timeout` returning
# 124 on the outer wallclock cap is expected (kernel never halts;
# stress driver is one task among many).
set +o pipefail
"${SCRIPT_DIR}/run.sh" 2>&1 | tee "${SERIAL_LOG}" || true
set -o pipefail

if grep -q "^\[stress\] done" "${SERIAL_LOG}"; then
    echo "[run-stress] OK — stress driver completed cleanly"
    exit 0
fi
echo "[run-stress] FAIL — '[stress] done' sentinel not seen in ${SERIAL_LOG}" >&2
exit 1
