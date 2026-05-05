#!/usr/bin/env bash
#
# Boot DuetOS's UEFI loader (BOOTX64.EFI) under qemu+OVMF and verify
# the Phase A banner reaches the firmware console.
#
# This is a tools/test/ peer of ctest-boot-smoke.sh — that one boots
# the kernel via GRUB+Multiboot2; this one boots the native UEFI
# loader. Phase A's deliverable is "the firmware accepts our PE32+
# binary and runs efi_main"; the in-band signal for that is the
# banner string showing up on COM1.
#
# Requires (one-time, per CLAUDE.md's live-test runtime tooling):
#   sudo apt-get install -y qemu-system-x86 ovmf
#
# Usage:
#   tools/test/uefi-smoke.sh                  # default x86_64-release
#   DUETOS_PRESET=x86_64-debug tools/test/uefi-smoke.sh
#   DUETOS_TIMEOUT=10 tools/test/uefi-smoke.sh   # cap QEMU wall clock
#
# Exit code:
#   0  banner observed
#   1  banner missing (Phase A regression — the binary built but the
#      firmware didn't run efi_main, or the banner string drifted)
#   2  prerequisite missing (qemu / OVMF / BOOTX64.EFI)

set -euo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

PRESET="${DUETOS_PRESET:-x86_64-release}"
BUILD_DIR="${REPO_ROOT}/build/${PRESET}"
EFI_IMAGE="${BUILD_DIR}/boot/uefi/BOOTX64.EFI"
KERNEL_ELF="${BUILD_DIR}/kernel/duetos-kernel.elf"
TIMEOUT_SECS="${DUETOS_TIMEOUT:-15}"

# OVMF firmware path. The naming has shifted across Ubuntu/Debian
# revisions; check the canonical locations in order. The combined
# `OVMF.fd` (CODE + VARS in one image) is what `-bios` wants.
OVMF_CODE=""
for cand in \
    /usr/share/ovmf/OVMF.fd \
    /usr/share/OVMF/OVMF_CODE_4M.fd \
    /usr/share/OVMF/OVMF_CODE.fd \
    /usr/share/qemu/OVMF.fd ; do
    if [ -f "${cand}" ]; then
        OVMF_CODE="${cand}"
        break
    fi
done

# Markers to grep for in the captured serial log. Keep both in
# sync with boot/uefi/main.cpp.
#   BANNER  — Phase A toolchain-proof banner.
#   KERNEL  — Phase B.1 marker emitted after a successful
#             open + read + validate of duetos-kernel.elf on the
#             boot ESP. Absence indicates the loader couldn't
#             find / open / read / validate the kernel image.
readonly BANNER_NEEDLE="DuetOS UEFI loader v0"
readonly KERNEL_NEEDLE="kernel ELF: valid x86_64 image"

# --------------------------------------------------------------
# Prerequisite checks. Fail with code 2 + a useful "what to do"
# message if anything is missing — easier to act on than a raw
# qemu / cp error.
# --------------------------------------------------------------

if ! command -v qemu-system-x86_64 > /dev/null; then
    echo "[uefi-smoke] qemu-system-x86_64 not installed" >&2
    echo "  install: sudo apt-get install -y qemu-system-x86" >&2
    exit 2
fi
if [ -z "${OVMF_CODE}" ]; then
    echo "[uefi-smoke] OVMF firmware not found in any canonical location" >&2
    echo "  install: sudo apt-get install -y ovmf" >&2
    exit 2
fi
if [ ! -f "${EFI_IMAGE}" ]; then
    echo "[uefi-smoke] BOOTX64.EFI not built at ${EFI_IMAGE}" >&2
    echo "  build:   cmake --build build/${PRESET} --target duetos-uefi" >&2
    exit 2
fi
# Phase B.1 also requires the kernel ELF to be staged on the
# virtual ESP so the loader's ProbeKernelElf can find + validate
# it. Skip cleanly if the kernel hasn't been built — the
# CMakeLists' add_subdirectory(kernel) target builds this.
if [ ! -f "${KERNEL_ELF}" ]; then
    echo "[uefi-smoke] kernel ELF not built at ${KERNEL_ELF}" >&2
    echo "  build:   cmake --build build/${PRESET}" >&2
    exit 2
fi

# --------------------------------------------------------------
# Stage a virtual FAT32 ESP. QEMU's `-drive file=fat:rw:DIR`
# wraps a host directory in an ephemeral FAT32 volume; we only
# need the EFI/BOOT/BOOTX64.EFI path so the firmware finds the
# loader on its default boot path.
# --------------------------------------------------------------

readonly ESP_DIR="$(mktemp -d -t duetos-esp.XXXXXX)"
readonly LOG_FILE="$(mktemp -t duetos-uefi-log.XXXXXX)"
trap 'rm -rf "${ESP_DIR}" "${LOG_FILE}"' EXIT

mkdir -p "${ESP_DIR}/EFI/BOOT"
cp "${EFI_IMAGE}" "${ESP_DIR}/EFI/BOOT/BOOTX64.EFI"
# Phase B.1: stage the kernel ELF at the volume root so the
# loader's ProbeKernelElf can open it via SimpleFileSystem.
# Path matches the CHAR16 literal in main.cpp's kKernelPath.
cp "${KERNEL_ELF}" "${ESP_DIR}/duetos-kernel.elf"

# --------------------------------------------------------------
# Run QEMU. `-serial file:LOG_FILE` captures COM1 — the loader
# mirrors its banner there (in addition to ConOut) so this script
# can grep for the marker. `-no-reboot` makes the loader's hlt
# loop terminate the run instead of resetting; combined with
# `timeout` below, the run is bounded.
# --------------------------------------------------------------

# `timeout` kills QEMU after TIMEOUT_SECS — the loader's halt
# loop never exits on its own, so we rely on the wall-clock cap
# to terminate. Exit 124 from `timeout` is normal; we judge on
# log content, not on QEMU's exit code.
echo "[uefi-smoke] booting ${EFI_IMAGE} under OVMF (timeout ${TIMEOUT_SECS}s)"
set +e
timeout "${TIMEOUT_SECS}" qemu-system-x86_64 \
    -bios "${OVMF_CODE}" \
    -drive "format=raw,file=fat:rw:${ESP_DIR}" \
    -display none \
    -serial "file:${LOG_FILE}" \
    -no-reboot
QEMU_EXIT=$?
set -e

# --------------------------------------------------------------
# Verify the banner reached COM1. The loader mirrors its banner
# from ConOut to COM1 (port 0x3F8) explicitly so this grep is
# stable across firmware revisions and graphical-vs-serial
# console routing.
#
# Phase A acceptance: the marker is in the serial log AND QEMU
# terminated via timeout (loader's hlt loop reached, no fault).
# QEMU exit 124 (timeout) or 0 are both fine; anything else is
# a fault during firmware load and a Phase A regression.
# --------------------------------------------------------------

if ! grep -q "${BANNER_NEEDLE}" "${LOG_FILE}"; then
    echo "[uefi-smoke] FAIL (Phase A banner NOT found; qemu exit=${QEMU_EXIT})"
    echo "--- last 40 lines of serial log ---"
    tail -40 "${LOG_FILE}" || true
    exit 1
fi
if ! grep -q "${KERNEL_NEEDLE}" "${LOG_FILE}"; then
    echo "[uefi-smoke] FAIL (Phase B.1 kernel-validation marker NOT found; qemu exit=${QEMU_EXIT})"
    echo "--- last 40 lines of serial log ---"
    tail -40 "${LOG_FILE}" || true
    exit 1
fi
echo "[uefi-smoke] PASS (Phase A banner + Phase B.1 kernel ELF validated; qemu exit=${QEMU_EXIT})"
exit 0
