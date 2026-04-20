#!/usr/bin/env bash
#
# Launch the freshly-built CustomOS kernel in QEMU.
#
# This script is deliberately minimal. It:
#   1. Locates the kernel ELF in build/<preset>/kernel/.
#   2. Picks sensible QEMU flags for early-boot diagnosis:
#        -serial stdio       : pipe COM1 to this terminal
#        -no-reboot          : halt on triple fault instead of resetting
#        -no-shutdown        : leave QEMU alive so `info registers` works
#        -d int,cpu_reset    : trace interrupts + reset causes
#        -D qemu.log         : dump that trace to qemu.log in the CWD
#   3. Forwards any extra argv to QEMU, so callers can add `-s -S` for gdb,
#      `-display none -nographic`, `-smp 4`, etc.
#
# Requires: qemu-system-x86_64 on PATH. On Ubuntu:
#     sudo apt-get install -y qemu-system-x86 ovmf xorriso grub-pc-bin grub-common
#
# Multiboot2 note: QEMU's `-kernel` uses the Multiboot 1 protocol. Our
# kernel header is Multiboot 2 — so for now this script expects a
# Multiboot2-aware path (either a GRUB ISO built with grub-mkrescue, or a
# QEMU fork that understands Multiboot2). The ISO-build helper will land
# in a follow-up commit. Until then, this script is a placeholder that
# documents the final invocation.

set -euo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

PRESET="${CUSTOMOS_PRESET:-x86_64-debug}"
BUILD_DIR="${REPO_ROOT}/build/${PRESET}"
KERNEL_ELF="${BUILD_DIR}/kernel/customos-kernel.elf"

if [[ ! -f "${KERNEL_ELF}" ]]; then
    echo "error: kernel ELF not found at ${KERNEL_ELF}" >&2
    echo "       build it first:" >&2
    echo "         cmake --preset ${PRESET}" >&2
    echo "         cmake --build build/${PRESET}" >&2
    exit 1
fi

if ! command -v qemu-system-x86_64 >/dev/null 2>&1; then
    echo "error: qemu-system-x86_64 is not installed." >&2
    echo "       install with: sudo apt-get install -y qemu-system-x86" >&2
    exit 1
fi

# -kernel uses Multiboot 1. Once grub-mkrescue-based ISO assembly lands,
# switch this to `-cdrom build/${PRESET}/customos.iso`.
exec qemu-system-x86_64 \
    -machine q35 \
    -cpu max \
    -m 512M \
    -kernel "${KERNEL_ELF}" \
    -serial stdio \
    -no-reboot \
    -no-shutdown \
    -d int,cpu_reset \
    -D qemu.log \
    "$@"
