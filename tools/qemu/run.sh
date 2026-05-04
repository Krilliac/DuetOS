#!/usr/bin/env bash
#
# Launch the freshly-built DuetOS kernel in QEMU.
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
#   -display none          : headless (override by exporting DUETOS_DISPLAY=gtk)
#
# Extra argv is forwarded to QEMU, so `tools/qemu/run.sh -s -S` will start
# it waiting for gdb on :1234.
#
# Requires (on Ubuntu):
#   sudo apt-get install -y qemu-system-x86 grub-common grub-pc-bin grub-efi-amd64-bin xorriso mtools ovmf
#
# OVMF is required because UEFI is the default boot firmware
# (see UEFI_MODE below). Set DUETOS_LEGACY=1 to boot via
# SeaBIOS instead and skip the OVMF requirement.

set -euo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

PRESET="${DUETOS_PRESET:-x86_64-debug}"
BUILD_DIR="${REPO_ROOT}/build/${PRESET}"
ISO_IMAGE="${BUILD_DIR}/duetos.iso"
KERNEL_ELF="${BUILD_DIR}/kernel/duetos-kernel.elf"
DISPLAY_MODE="${DUETOS_DISPLAY:-none}"
TIMEOUT_SECS="${DUETOS_TIMEOUT:-}"
# Boot firmware: UEFI (OVMF) by default, SeaBIOS when
# DUETOS_LEGACY=1. UEFI is the primary target for commodity
# PC hardware post-2010; SeaBIOS stays available for
# legacy-BIOS regression tests and for hosts where OVMF isn't
# installed. The hybrid ISO carries both boot records
# (grub-mkrescue embeds El Torito entries for both), so the
# same image works with either firmware.
#
# Historical: this flag was introduced as opt-in (DUETOS_UEFI=1).
# Flipped to default 2026-04 once every self-test ran clean
# under OVMF — "boots on commodity PC hardware" is a project
# pillar, and SeaBIOS is not what modern machines ship.
LEGACY_MODE="${DUETOS_LEGACY:-0}"
if [[ -n "${DUETOS_UEFI:-}" ]]; then
    # Back-compat: honor an explicit DUETOS_UEFI setting. UEFI=0
    # means "force legacy"; UEFI=1 is redundant (it's already the
    # default) but harmless.
    if [[ "${DUETOS_UEFI}" == "0" ]]; then
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
    OVMF_CODE="${DUETOS_OVMF_CODE:-/usr/share/OVMF/OVMF_CODE_4M.fd}"
    OVMF_VARS_TEMPLATE="${DUETOS_OVMF_VARS:-/usr/share/OVMF/OVMF_VARS_4M.fd}"
    if [[ ! -f "${OVMF_CODE}" || ! -f "${OVMF_VARS_TEMPLATE}" ]]; then
        echo "error: UEFI is the default boot firmware but OVMF isn't installed." >&2
        echo "       Option A (recommended): sudo apt-get install -y ovmf" >&2
        echo "       Option B (skip UEFI, use SeaBIOS): DUETOS_LEGACY=1 $0 ..." >&2
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

# qemu-smoke profile selector. When DUETOS_SMOKE_PROFILE is set, we
# rebuild a per-profile ISO with `smoke=<profile>` baked into the
# grub cmdline so the kernel routes into kernel/test/smoke_profile.cpp's
# scenario-only path on boot. Each profile runs ONE focused scenario
# (bringup-only / ring3 / pe-hello / pe-winapi / pe-winkill / linux),
# emits a `[smoke] profile=<name> complete` sentinel, and exits QEMU
# via the isa-debug-exit device added below. CI runs the profiles in
# parallel as a job matrix. Keeping the ISO sidecar means the
# always-on boot=desktop / boot=tty entries stay unchanged for the
# default `tools/qemu/run.sh` invocation (no profile -> full boot).
SMOKE_PROFILE="${DUETOS_SMOKE_PROFILE:-}"
if [[ -n "${SMOKE_PROFILE}" ]]; then
    if ! command -v grub-mkrescue >/dev/null 2>&1; then
        echo "error: DUETOS_SMOKE_PROFILE=${SMOKE_PROFILE} requires grub-mkrescue" >&2
        echo "       install via: sudo apt-get install -y grub-common grub-pc-bin xorriso mtools" >&2
        exit 1
    fi
    SMOKE_ISO_STAGE="${BUILD_DIR}/smoke-iso-stage-${SMOKE_PROFILE}"
    SMOKE_ISO="${BUILD_DIR}/duetos-smoke-${SMOKE_PROFILE}.iso"
    rm -rf "${SMOKE_ISO_STAGE}"
    mkdir -p "${SMOKE_ISO_STAGE}/boot/grub"
    cp "${KERNEL_ELF}" "${SMOKE_ISO_STAGE}/boot/duetos-kernel.elf"
    # Single-entry grub.cfg, timeout=0, default=0 — auto-boots straight
    # into the smoke kernel cmdline. boot=desktop is preserved so the
    # post-bringup composite path still runs (compositor init, etc.);
    # the kernel routes into the smoke profile after bringup-complete.
    cat > "${SMOKE_ISO_STAGE}/boot/grub/grub.cfg" <<EOF
set timeout=0
set default=0
menuentry "DuetOS — smoke ${SMOKE_PROFILE}" {
    multiboot2 /boot/duetos-kernel.elf boot=desktop smoke=${SMOKE_PROFILE} autologin=1
    boot
}
EOF
    grub-mkrescue --compress=xz -o "${SMOKE_ISO}" "${SMOKE_ISO_STAGE}" >/dev/null 2>&1
    if [[ ! -f "${SMOKE_ISO}" ]]; then
        echo "error: failed to build smoke ISO ${SMOKE_ISO}" >&2
        exit 1
    fi
    BOOT_SOURCE=(-cdrom "${SMOKE_ISO}" -boot d)
    echo "[run.sh] smoke profile=${SMOKE_PROFILE} iso=${SMOKE_ISO}" >&2
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

# Use KVM when /dev/kvm is reachable (CI runners on bare metal,
# Linux dev hosts with the right capability bits), fall through to
# TCG otherwise. The `kvm:tcg` syntax tells QEMU "try kvm first,
# downgrade silently to tcg if it fails" so the same script works
# everywhere without an env-var dance. KVM speeds the qemu-smoke
# job ~50x — the boot/test path that takes ~60s under TCG completes
# in ~1.5s under KVM, well inside the CI wall-clock budget.
ACCEL="tcg"
if [[ -r /dev/kvm && -w /dev/kvm ]]; then
    ACCEL="kvm:tcg"
fi
# Log the acceleration choice so a slow CI run is easy to diagnose
# from the workflow log alone — without this, "did the smoke job
# actually use KVM?" required re-checking permissions on /dev/kvm
# after the fact.
echo "[run.sh] qemu accel=${ACCEL}" >&2

# Per-run binary minidump file. The kernel's crash-dump path
# emits a Windows-format .dmp via `outb 0xE9, %al` (port 0xE9
# is QEMU's `-debugcon` channel); QEMU appends each byte to
# this file as it arrives. On a successful boot with no panic
# the file stays empty / zero bytes — no harm. On a panic it
# materialises a real .dmp that Visual Studio / WinDbg /
# VSCode-cppvsdbg open directly. Truncate per-run so a stale
# dump from a prior boot doesn't masquerade as the current one.
MINIDUMP_FILE="${BUILD_DIR}/duetos.dmp"
: > "${MINIDUMP_FILE}"
echo "[run.sh] minidump sink=${MINIDUMP_FILE}" >&2

QEMU_ARGS=(
    -machine  "q35,accel=${ACCEL}"
    -cpu      max
    -m        512M
    -display  "${DISPLAY_MODE}"
    -serial   stdio
    # COM2 → host TCP server on ${DUETOS_GDB_PORT} (default 1234).
    # `wait=off` so QEMU doesn't block waiting for a GDB connection
    # at boot — the kernel's GDB stub stays silent until the
    # debugger actually attaches. This is a separate channel from
    # QEMU's own `-gdb` flag (which exposes QEMU's hypervisor-side
    # debugger) — ours speaks to the in-kernel stub at the guest
    # OS's level: attach to it and you debug the running DuetOS
    # kernel, not QEMU's emulator state.
    -serial   "tcp::${DUETOS_GDB_PORT:-1234},server=on,wait=off"
    -no-reboot
    -no-shutdown
    -d        int,cpu_reset
    -D        qemu.log
    -debugcon "file:${MINIDUMP_FILE}"
    # isa-debug-exit: a tiny device that lets the guest exit QEMU
    # cleanly. Writing an OUT byte B to port 0xf4 terminates QEMU
    # with exit status (B<<1)|1. arch::TestExit (kernel/arch/x86_64/
    # cpu.h) writes 0x10 → exit 0x21 = "smoke sentinel reached".
    # Always present (no-op for full boots that never call
    # TestExit); harmless on bare metal where port 0xf4 is unused.
    -device   "isa-debug-exit,iobase=0xf4,iosize=0x01"
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
    -device   "usb-mouse,bus=xhci.0"
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
