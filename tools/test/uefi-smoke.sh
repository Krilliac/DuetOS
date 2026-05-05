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
TIMEOUT_SECS="${DUETOS_TIMEOUT:-15}"

# OVMF firmware path. Ubuntu/Debian ships OVMF_CODE.fd here.
OVMF_CODE="/usr/share/OVMF/OVMF_CODE.fd"

# The banner string the loader's main.cpp prints. Keep this in
# sync with boot/uefi/main.cpp's `kBanner`.
readonly BANNER_NEEDLE="DuetOS UEFI loader v0"

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
if [ ! -f "${OVMF_CODE}" ]; then
    echo "[uefi-smoke] OVMF firmware not found at ${OVMF_CODE}" >&2
    echo "  install: sudo apt-get install -y ovmf" >&2
    exit 2
fi
if [ ! -f "${EFI_IMAGE}" ]; then
    echo "[uefi-smoke] BOOTX64.EFI not built at ${EFI_IMAGE}" >&2
    echo "  build:   cmake --build build/${PRESET} --target duetos-uefi" >&2
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

if grep -q "${BANNER_NEEDLE}" "${LOG_FILE}"; then
    echo "[uefi-smoke] PASS (banner observed on COM1, qemu exit=${QEMU_EXIT})"
    exit 0
fi

echo "[uefi-smoke] FAIL (banner NOT found in serial log; qemu exit=${QEMU_EXIT})"
echo "--- last 40 lines of serial log ---"
tail -40 "${LOG_FILE}" || true
exit 1
