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
#   sudo apt-get install -y qemu-system-x86 grub-common grub-pc-bin grub-efi-amd64-bin xorriso mtools ovmf
#
# OVMF is required because UEFI is the default boot firmware
# (see UEFI_MODE below). Set CUSTOMOS_LEGACY=1 to boot via
# SeaBIOS instead and skip the OVMF requirement.

set -euo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

PRESET="${CUSTOMOS_PRESET:-x86_64-debug}"
BUILD_DIR="${REPO_ROOT}/build/${PRESET}"
ISO_IMAGE="${BUILD_DIR}/customos.iso"
KERNEL_ELF="${BUILD_DIR}/kernel/customos-kernel.elf"
DISPLAY_MODE="${CUSTOMOS_DISPLAY:-none}"
TIMEOUT_SECS="${CUSTOMOS_TIMEOUT:-}"
# Boot firmware: UEFI (OVMF) by default, SeaBIOS when
# CUSTOMOS_LEGACY=1. UEFI is the primary target for commodity
# PC hardware post-2010; SeaBIOS stays available for
# legacy-BIOS regression tests and for hosts where OVMF isn't
# installed. The hybrid ISO carries both boot records
# (grub-mkrescue embeds El Torito entries for both), so the
# same image works with either firmware.
#
# Historical: this flag was introduced as opt-in (CUSTOMOS_UEFI=1).
# Flipped to default 2026-04 once every self-test ran clean
# under OVMF — "boots on commodity PC hardware" is a project
# pillar, and SeaBIOS is not what modern machines ship.
LEGACY_MODE="${CUSTOMOS_LEGACY:-0}"
if [[ -n "${CUSTOMOS_UEFI:-}" ]]; then
    # Back-compat: honor an explicit CUSTOMOS_UEFI setting. UEFI=0
    # means "force legacy"; UEFI=1 is redundant (it's already the
    # default) but harmless.
    if [[ "${CUSTOMOS_UEFI}" == "0" ]]; then
        LEGACY_MODE=1
    fi
fi
UEFI_MODE=1
if [[ "${LEGACY_MODE}" == "1" ]]; then
    UEFI_MODE=0
fi

if ! command -v qemu-system-x86_64 >/dev/null 2>&1; then
    echo "error: qemu-system-x86_64 is not installed." >&2
    echo "       sudo apt-get install -y qemu-system-x86" >&2
    exit 1
fi

UEFI_ARGS=()
if [[ "${UEFI_MODE}" == "1" ]]; then
    OVMF_CODE="${CUSTOMOS_OVMF_CODE:-/usr/share/OVMF/OVMF_CODE_4M.fd}"
    OVMF_VARS_TEMPLATE="${CUSTOMOS_OVMF_VARS:-/usr/share/OVMF/OVMF_VARS_4M.fd}"
    if [[ ! -f "${OVMF_CODE}" || ! -f "${OVMF_VARS_TEMPLATE}" ]]; then
        echo "error: UEFI is the default boot firmware but OVMF isn't installed." >&2
        echo "       Option A (recommended): sudo apt-get install -y ovmf" >&2
        echo "       Option B (skip UEFI, use SeaBIOS): CUSTOMOS_LEGACY=1 $0 ..." >&2
        echo "       expected: ${OVMF_CODE} and ${OVMF_VARS_TEMPLATE}" >&2
        exit 1
    fi
    # Per-run writable copy of OVMF NVRAM (BootOrder / boot entries).
    # Discarded on each invocation so a previous run can't sabotage
    # the next one with a Boot#### that points at a stale path.
    OVMF_VARS_COPY="${BUILD_DIR}/ovmf-vars.fd"
    cp "${OVMF_VARS_TEMPLATE}" "${OVMF_VARS_COPY}"
    UEFI_ARGS=(
        -drive "if=pflash,format=raw,readonly=on,file=${OVMF_CODE}"
        -drive "if=pflash,format=raw,file=${OVMF_VARS_COPY}"
    )
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

# Scratch NVMe + SATA images. GPT-formatted raw files with one
# FAT32 data partition seeded by make-gpt-image.py. The FS self-
# tests mutate these images (fatwrite / fatappend / fatnew); an
# image from a previous run would fail the "fresh fixture"
# assertions (e.g. HELLO.TXT expected at 17 bytes, not 5017).
# Regenerate on every invocation — build is seconds, trades off
# nothing meaningful for determinism.
NVME_IMAGE="${BUILD_DIR}/nvme0.img"
SATA_IMAGE="${BUILD_DIR}/sata0.img"
python3 "${SCRIPT_DIR}/make-gpt-image.py" "${NVME_IMAGE}"
python3 "${SCRIPT_DIR}/make-gpt-image.py" "${SATA_IMAGE}"

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
    # xHCI host controller. q35 doesn't ship with one by default,
    # so explicitly attach so the USB stack has something to bring
    # up. We also park one usb-kbd on the bus so the port-scan
    # path has a real connected device to enumerate (Enable Slot,
    # eventually Address Device + descriptor fetch).
    -device   "qemu-xhci,id=xhci"
    -device   "usb-kbd,bus=xhci.0"
    # Intel e1000e (82574L) NIC on a user-mode netdev. QEMU's
    # SLIRP stack gives us one-way connectivity to the outside +
    # a loopback path that returns broadcast frames for self-test.
    # Specify mac= so the driver's EEPROM-read path sees a stable
    # value across reboots. `-device e1000e` advertises the MSI-X
    # capability so the driver's IRQ-wake path gets exercised;
    # `-device e1000` would fall back to polling.
    -netdev   "user,id=net0"
    -device   "e1000e,netdev=net0,mac=52:54:00:12:34:56"
    "${UEFI_ARGS[@]}"
    "${BOOT_SOURCE[@]}"
)

if [[ -n "${TIMEOUT_SECS}" ]]; then
    exec timeout --foreground --preserve-status --signal=TERM "${TIMEOUT_SECS}" \
         qemu-system-x86_64 "${QEMU_ARGS[@]}" "$@"
else
    exec qemu-system-x86_64 "${QEMU_ARGS[@]}" "$@"
fi
