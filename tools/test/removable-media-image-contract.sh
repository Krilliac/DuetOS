#!/usr/bin/env bash
# Safety contract for tools/image/build-removable-media.sh.
# The builder is allowed to create regular files only.  Device-shaped paths
# must be rejected before construction tools run, even when --force is set.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
readonly REPO_ROOT
readonly BUILDER="${REPO_ROOT}/tools/image/build-removable-media.sh"
TMP_DIR="$(mktemp -d -t duetos-removable-contract.XXXXXX)"
readonly TMP_DIR
trap 'rm -rf "${TMP_DIR}"' EXIT

readonly KERNEL="${TMP_DIR}/kernel.elf"
printf '\x7fELF' >"${KERNEL}"

expect_refusal()
{
    local label="$1"
    local needle="$2"
    shift 2

    local stderr_file="${TMP_DIR}/${label}.stderr"
    if "${BUILDER}" --kernel "${KERNEL}" "$@" 2>"${stderr_file}"; then
        echo "FAIL: ${label} was accepted" >&2
        exit 1
    fi
    if ! grep -Fq "${needle}" "${stderr_file}"; then
        echo "FAIL: ${label} did not report '${needle}'" >&2
        cat "${stderr_file}" >&2
        exit 1
    fi
}

expect_refusal "posix-device" "refusing device-like output" --output /dev/sda
expect_refusal "posix-device-force" "refusing device-like output" --output /dev/sda --force
expect_refusal "windows-device" "refusing device-like output" --output '\\.\PhysicalDrive0'

readonly EXISTING="${TMP_DIR}/existing.img"
touch "${EXISTING}"
expect_refusal "existing-output" "output already exists" --output "${EXISTING}"

if [[ -n "${DUETOS_KERNEL_ELF:-}" ]]; then
    readonly IMAGE="${TMP_DIR}/Duet OS removable.img"
    readonly EXTRACTED_KERNEL="${TMP_DIR}/extracted-kernel.elf"
    readonly EXTRACTED_EFI="${TMP_DIR}/BOOTX64.EFI"

    "${BUILDER}" --kernel "${DUETOS_KERNEL_ELF}" --output "${IMAGE}" --size-mib 128

    parted -sm "${IMAGE}" unit B print >"${TMP_DIR}/parted.txt"
    if ! grep -Eq ':fat32:.*boot, esp;' "${TMP_DIR}/parted.txt"; then
        echo "FAIL: image does not contain a FAT32 ESP" >&2
        cat "${TMP_DIR}/parted.txt" >&2
        exit 1
    fi

    mcopy -i "${IMAGE}@@1048576" ::/EFI/BOOT/BOOTX64.EFI "${EXTRACTED_EFI}"
    mcopy -i "${IMAGE}@@1048576" ::/boot/duetos-kernel.elf "${EXTRACTED_KERNEL}"
    [[ -s "${EXTRACTED_EFI}" ]] || { echo "FAIL: BOOTX64.EFI is empty" >&2; exit 1; }
    cmp --silent "${DUETOS_KERNEL_ELF}" "${EXTRACTED_KERNEL}" || {
        echo "FAIL: staged kernel differs from the input ELF" >&2
        exit 1
    }
fi

echo "PASS: removable-media image safety contract"
