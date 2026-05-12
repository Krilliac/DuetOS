#!/usr/bin/env bash
#
# Capture a screenshot of DuetOS booted with a specific GRUB
# menu entry. Written for the theme demo so we can produce one
# PNG per theme without shuffling the canonical grub.cfg.
#
# Usage:
#   tools/qemu/screenshot-theme.sh <menu-entry-index> <output.png>
#
# <menu-entry-index> is the absolute entry index into
# boot/grub/grub.cfg counting from 0. E.g. 5 → "Desktop Classic
# (autologin)". The harness builds a one-shot sidecar ISO that
# pins `set default=<menu-entry-index>` so GRUB auto-boots the
# target without keystroke navigation — sendkey-based nav under
# `-display none` is brittle (`error: no suitable video mode
# found` when keys arrive mid-gfxterm transition).
#
# Mirrors tools/qemu/screenshot.sh's QEMU args + serial-marker
# polling + PPM->PNG conversion; only the boot path differs.

set -euo pipefail
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

if [[ $# -lt 2 ]]; then
    echo "usage: $0 <menu-entry-index> <output.png>" >&2
    exit 2
fi

ENTRY_INDEX="$1"
OUT_PNG="$2"
PRESET="${DUETOS_PRESET:-x86_64-debug}"
BUILD_DIR="${REPO_ROOT}/build/${PRESET}"
ISO_IMAGE="${BUILD_DIR}/duetos.iso"
SERIAL_LOG="${BUILD_DIR}/screen.serial.log"
PPM_OUT="${BUILD_DIR}/screen.ppm"
MON_SOCK="${BUILD_DIR}/qemu-mon.sock"
SETTLE="${DUETOS_SETTLE:-6}"

if [[ ! -f "${ISO_IMAGE}" ]]; then
    echo "error: ISO not built: ${ISO_IMAGE}" >&2
    exit 1
fi
if ! command -v grub-mkrescue >/dev/null 2>&1; then
    echo "error: grub-mkrescue not found — install via:" >&2
    echo "       sudo apt-get install -y grub-common grub-pc-bin grub-efi-amd64-bin xorriso mtools" >&2
    exit 1
fi

NVME_IMAGE="${BUILD_DIR}/nvme0.img"
SATA_IMAGE="${BUILD_DIR}/sata0.img"
python3 "${SCRIPT_DIR}/make-gpt-image.py" "${NVME_IMAGE}"
python3 "${SCRIPT_DIR}/make-gpt-image.py" "${SATA_IMAGE}"

# Build a sidecar ISO that pins the requested entry as the GRUB
# default, copies the kernel ELF from the canonical staging dir,
# and runs `timeout=0` so the boot auto-fires. Source the menu
# entries from the live boot/grub/grub.cfg so we don't drift
# from the canonical menu — just replace the timeout + default
# header.
SCREEN_ISO_STAGE="${BUILD_DIR}/screenshot-iso-stage-${ENTRY_INDEX}"
SCREEN_ISO="${BUILD_DIR}/duetos-screen-${ENTRY_INDEX}.iso"
rm -rf "${SCREEN_ISO_STAGE}"
mkdir -p "${SCREEN_ISO_STAGE}/boot/grub"
cp "${BUILD_DIR}/kernel/iso-stage/boot/duetos-kernel.elf" "${SCREEN_ISO_STAGE}/boot/duetos-kernel.elf"
{
    echo "set timeout=0"
    echo "set default=${ENTRY_INDEX}"
    # Drop the original `set timeout=`/`set default=` lines from
    # the canonical grub.cfg; keep every menuentry block as-is so
    # entry indices align with the documented mapping
    # (README.md → docs/screenshots/).
    grep -v -E '^[[:space:]]*set (timeout|default)=' "${REPO_ROOT}/boot/grub/grub.cfg"
} > "${SCREEN_ISO_STAGE}/boot/grub/grub.cfg"
grub-mkrescue --compress=xz -o "${SCREEN_ISO}" "${SCREEN_ISO_STAGE}" >/dev/null 2>&1
if [[ ! -f "${SCREEN_ISO}" ]]; then
    echo "error: failed to build screenshot ISO ${SCREEN_ISO}" >&2
    exit 1
fi

rm -f "${SERIAL_LOG}" "${PPM_OUT}" "${MON_SOCK}" "${OUT_PNG}"

# UEFI / OVMF — match run.sh's default firmware. See
# screenshot.sh for the rationale (kernel ELF spawn path is
# sensitive to firmware memory-map differences; UEFI is the
# project's primary target).
OVMF_CODE="${DUETOS_OVMF_CODE:-/usr/share/OVMF/OVMF_CODE_4M.fd}"
OVMF_VARS_TEMPLATE="${DUETOS_OVMF_VARS:-/usr/share/OVMF/OVMF_VARS_4M.fd}"
OVMF_VARS_COPY="${BUILD_DIR}/screen-theme-ovmf-vars.fd"
cp "${OVMF_VARS_TEMPLATE}" "${OVMF_VARS_COPY}"

# Match screenshot.sh's option matrix: USB can be disabled via
# DUETOS_NO_USB=1 to dodge an intermittent xHCI reset-loop wedge
# under TCG, and we always pass `-net none` so QEMU 8.2's default
# e1000e + user-mode netdev can't race the ArpInsert chain walk
# during net stack bring-up. A networking-specific screenshot can
# override via DUETOS_NET_DEVICE.
USB_ARGS=()
if [[ "${DUETOS_NO_USB:-0}" != "1" ]]; then
    USB_ARGS=(
        -device "qemu-xhci,id=xhci"
        -device "usb-kbd,bus=xhci.0"
    )
fi
NET_ARGS=(-net none)
if [[ -n "${DUETOS_NET_DEVICE:-}" ]]; then
    # shellcheck disable=SC2206
    NET_ARGS=(${DUETOS_NET_DEVICE})
fi

qemu-system-x86_64 \
    -drive "if=pflash,format=raw,readonly=on,file=${OVMF_CODE}" \
    -drive "if=pflash,format=raw,file=${OVMF_VARS_COPY}" \
    -machine q35 -cpu max -m 512M \
    -vga virtio \
    -display none \
    -serial "file:${SERIAL_LOG}" \
    -monitor "unix:${MON_SOCK},server,nowait" \
    -no-reboot -no-shutdown \
    -drive "file=${NVME_IMAGE},if=none,id=nvme0,format=raw" \
    -device "nvme,serial=cafebabe,drive=nvme0" \
    -device "ahci,id=ahci1" \
    -drive "file=${SATA_IMAGE},if=none,id=sata0,format=raw" \
    -device "ide-hd,bus=ahci1.0,drive=sata0" \
    "${USB_ARGS[@]}" \
    "${NET_ARGS[@]}" \
    -cdrom "${SCREEN_ISO}" -boot d &
QEMU_PID=$!

trap 'kill "${QEMU_PID}" 2>/dev/null || true; rm -f "${MON_SOCK}"' EXIT

# Poll for the bringup-complete marker (compositor online and
# painting). screenshot.sh uses the same marker — kheartbeat is a
# scheduler-thread tick that fires AFTER the full ring-3 spawn
# settles, which under TCG can push past the harness budget.
readonly BOOT_MARKER="${DUETOS_BOOT_MARKER:-bringup-complete}"
for _ in $(seq 1 "${DUETOS_BOOT_WAIT_SECS:-600}"); do
    if [[ -f "${SERIAL_LOG}" ]] && grep -q "${BOOT_MARKER}" "${SERIAL_LOG}"; then
        break
    fi
    sleep 1
done
if ! grep -q "${BOOT_MARKER}" "${SERIAL_LOG}" 2>/dev/null; then
    echo "error: '${BOOT_MARKER}' marker never appeared in ${SERIAL_LOG}" >&2
    tail -60 "${SERIAL_LOG}" >&2 || true
    exit 1
fi

sleep "${SETTLE}"

python3 - <<PY "${MON_SOCK}" "${PPM_OUT}"
import socket, sys, time
sock_path, ppm = sys.argv[1:3]
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
for _ in range(30):
    try:
        s.connect(sock_path); break
    except (FileNotFoundError, ConnectionRefusedError):
        time.sleep(0.2)
else:
    print("failed to connect to qemu monitor", file=sys.stderr)
    sys.exit(2)
s.settimeout(5.0)
def send(cmd):
    s.sendall((cmd + "\n").encode()); time.sleep(0.3)
send(f"screendump {ppm}")
time.sleep(1.5)
send("quit")
s.close()
PY

wait "${QEMU_PID}" 2>/dev/null || true

if [[ ! -f "${PPM_OUT}" ]]; then
    echo "error: screendump did not produce ${PPM_OUT}" >&2
    exit 1
fi

convert "${PPM_OUT}" "${OUT_PNG}"
echo "screenshot: ${OUT_PNG}  (grub-entry=${ENTRY_INDEX})"
