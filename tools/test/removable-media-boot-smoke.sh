#!/usr/bin/env bash
# Build a regular-file DuetOS removable image and boot it under OVMF.
# No host block device is opened or discovered by this test.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
readonly REPO_ROOT
readonly PRESET="${DUETOS_PRESET:-x86_64-debug}"
readonly BUILD_DIR="${REPO_ROOT}/build/${PRESET}"
readonly KERNEL_ELF="${DUETOS_KERNEL_ELF:-${BUILD_DIR}/kernel/duetos-kernel.elf}"
readonly TIMEOUT_SECS="${DUETOS_TIMEOUT:-180}"
readonly BUILDER="${REPO_ROOT}/tools/image/build-removable-media.sh"

for tool in qemu-system-x86_64 timeout; do
    if ! command -v "${tool}" >/dev/null 2>&1; then
        echo "[removable-smoke] required host tool not found: ${tool}" >&2
        exit 2
    fi
done
if [[ ! -f "${KERNEL_ELF}" ]]; then
    echo "[removable-smoke] kernel ELF not found: ${KERNEL_ELF}" >&2
    echo "  build: cmake --build build/${PRESET}" >&2
    exit 2
fi

OVMF_CODE=""
for candidate in \
    /usr/share/ovmf/OVMF.fd \
    /usr/share/OVMF/OVMF_CODE_4M.fd \
    /usr/share/OVMF/OVMF_CODE.fd \
    /usr/share/qemu/OVMF.fd; do
    if [[ -f "${candidate}" ]]; then
        OVMF_CODE="${candidate}"
        break
    fi
done
if [[ -z "${OVMF_CODE}" ]]; then
    echo "[removable-smoke] OVMF firmware not found" >&2
    exit 2
fi

TMP_DIR="$(mktemp -d -t duetos-removable-smoke.XXXXXX)"
readonly TMP_DIR
readonly IMAGE="${TMP_DIR}/duetos-removable.img"
readonly SERIAL_LOG="${TMP_DIR}/serial.log"
trap 'rm -rf "${TMP_DIR}"' EXIT

"${BUILDER}" --kernel "${KERNEL_ELF}" --output "${IMAGE}" --size-mib 128 --boot-mode smoke

echo "[removable-smoke] booting regular-file image under OVMF"
set +e
timeout --foreground --preserve-status --signal=TERM "${TIMEOUT_SECS}" \
    qemu-system-x86_64 \
    -machine q35 \
    -cpu max \
    -m 512M \
    -smp 4 \
    -bios "${OVMF_CODE}" \
    -drive "format=raw,file=${IMAGE},if=virtio" \
    -display none \
    -serial "file:${SERIAL_LOG}" \
    -no-reboot \
    -device "isa-debug-exit,iobase=0xf4,iosize=0x01"
QEMU_EXIT=$?
set -e

if ! grep -q 'metrics bringup-complete' "${SERIAL_LOG}"; then
    echo "[removable-smoke] FAIL: bringup-complete missing (qemu exit=${QEMU_EXIT})" >&2
    tail -80 "${SERIAL_LOG}" >&2 || true
    exit 1
fi
if grep -Eq 'PANIC|triple fault|KASSERT failed' "${SERIAL_LOG}"; then
    echo "[removable-smoke] FAIL: fatal marker present (qemu exit=${QEMU_EXIT})" >&2
    tail -80 "${SERIAL_LOG}" >&2 || true
    exit 1
fi

"${REPO_ROOT}/tools/test/boot-log-analyze.sh" "${SERIAL_LOG}"
echo "[removable-smoke] PASS (qemu exit=${QEMU_EXIT})"
