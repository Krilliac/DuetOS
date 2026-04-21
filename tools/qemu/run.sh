#!/usr/bin/env bash
#
# Launch the freshly-built CustomOS kernel in QEMU.
#
# Default boot path:  ISO + GRUB + Multiboot2.
# Reasoning:          QEMU's `-kernel` flag speaks Multiboot 1, but our
#                     kernel header is Multiboot 2. Booting the ISO lets
#                     GRUB do the Multiboot2 handoff properly.
#
# Flags chosen for early-boot diagnosis:
#   -serial stdio          : pipe COM1 to this terminal
#   -no-reboot             : halt on triple fault instead of resetting
#   -no-shutdown           : leave QEMU alive so `info registers` works
#   -d int,cpu_reset       : trace interrupts + reset causes
#   -D qemu.log            : dump that trace to qemu.log
#   -display none          : headless (override by exporting CUSTOMOS_DISPLAY=gtk)
#
# Extra argv is forwarded to QEMU, so `tools/qemu/run.sh -s -S` will start
# it waiting for gdb on :1234.
#
# Requires (on Ubuntu):
#   sudo apt-get install -y qemu-system-x86 grub-common grub-pc-bin xorriso mtools

set -euo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

PRESET="${CUSTOMOS_PRESET:-x86_64-debug}"
BUILD_DIR="${REPO_ROOT}/build/${PRESET}"
ISO_IMAGE="${BUILD_DIR}/customos.iso"
KERNEL_ELF="${BUILD_DIR}/kernel/customos-kernel.elf"
DISPLAY_MODE="${CUSTOMOS_DISPLAY:-none}"
TIMEOUT_SECS="${CUSTOMOS_TIMEOUT:-}"

if ! command -v qemu-system-x86_64 >/dev/null 2>&1; then
    echo "error: qemu-system-x86_64 is not installed." >&2
    echo "       sudo apt-get install -y qemu-system-x86" >&2
    exit 1
fi

if [[ -f "${ISO_IMAGE}" ]]; then
    BOOT_SOURCE=(-cdrom "${ISO_IMAGE}" -boot d)
elif [[ -f "${KERNEL_ELF}" ]]; then
    echo "warning: ${ISO_IMAGE} not found, falling back to -kernel (Multiboot 1)." >&2
    echo "         This will NOT boot today — the kernel uses Multiboot 2." >&2
    echo "         Install grub-pc-bin + xorriso and rebuild so the ISO target runs." >&2
    BOOT_SOURCE=(-kernel "${KERNEL_ELF}")
else
    echo "error: neither ${ISO_IMAGE} nor ${KERNEL_ELF} exists." >&2
    echo "       build first:" >&2
    echo "         cmake --preset ${PRESET}" >&2
    echo "         cmake --build build/${PRESET}" >&2
    exit 1
fi

# Scratch NVMe image. 16 MiB GPT-formatted raw file with one data
# partition at LBA 2048..(end-34). The first 8 bytes of that
# partition carry a "CUSTOMOS" marker so both the NVMe self-test
# (via the GPT parse in kernel/fs/gpt) and any future filesystem
# slice has a grep-able success signal. Kept in the build
# directory so it rebuilds per-preset and never pollutes the
# source tree.
NVME_IMAGE="${BUILD_DIR}/nvme0.img"
if [[ ! -f "${NVME_IMAGE}" ]]; then
    python3 "${SCRIPT_DIR}/make-gpt-image.py" "${NVME_IMAGE}"
fi

# Scratch SATA image. Same layout as the NVMe image — a small GPT
# disk with a "CUSTOMOS" marker in the data partition — so the
# AHCI self-test can assert the 0x55AA PMBR signature just like
# NVMe. Kept as a separate file so writes on one backend never
# bleed into the other's self-test.
SATA_IMAGE="${BUILD_DIR}/sata0.img"
if [[ ! -f "${SATA_IMAGE}" ]]; then
    python3 "${SCRIPT_DIR}/make-gpt-image.py" "${SATA_IMAGE}"
fi

QEMU_ARGS=(
    -machine  q35
    -cpu      max
    -m        512M
    -display  "${DISPLAY_MODE}"
    -serial   stdio
    -no-reboot
    -no-shutdown
    -d        int,cpu_reset
    -D        qemu.log
    -drive    "file=${NVME_IMAGE},if=none,id=nvme0,format=raw"
    -device   "nvme,serial=cafebabe,drive=nvme0"
    # Separate AHCI controller with one SATA disk. The q35 machine
    # has a built-in AHCI at 0:1f.2 carrying the CD-ROM; adding a
    # dedicated "ahci,id=ahci1" plus an ide-hd on bus ahci1.0
    # gives us a clean test path with only a hard-disk device
    # (no ATAPI), which matches the v1 driver scope.
    -device   "ahci,id=ahci1"
    -drive    "file=${SATA_IMAGE},if=none,id=sata0,format=raw"
    -device   "ide-hd,bus=ahci1.0,drive=sata0"
    "${BOOT_SOURCE[@]}"
)

if [[ -n "${TIMEOUT_SECS}" ]]; then
    exec timeout --foreground --preserve-status --signal=TERM "${TIMEOUT_SECS}" \
         qemu-system-x86_64 "${QEMU_ARGS[@]}" "$@"
else
    exec qemu-system-x86_64 "${QEMU_ARGS[@]}" "$@"
fi
