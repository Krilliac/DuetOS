#!/usr/bin/env bash
#
# Capture a screenshot of DuetOS booted with a specific GRUB
# menu entry. Written for the theme demo so we can produce one
# PNG per theme without shuffling grub.cfg's default= line.
#
# Usage:
#   tools/qemu/screenshot-theme.sh <menu-down-count> <output.png>
#
# <menu-down-count> is how many "sendkey down" presses to issue
# before "ret" during GRUB's 3-second timeout window. 0 boots the
# default entry (index 0). See boot/grub/grub.cfg for the
# entry order.
#
# Mirrors tools/qemu/screenshot.sh one-for-one — same QEMU args,
# same serial-marker poll, same PPM->PNG conversion path — with
# the arrow-key sequence exposed as an argument.

set -euo pipefail
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

if [[ $# -lt 2 ]]; then
    echo "usage: $0 <menu-down-count> <output.png>" >&2
    exit 2
fi

DOWN_COUNT="$1"
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

NVME_IMAGE="${BUILD_DIR}/nvme0.img"
SATA_IMAGE="${BUILD_DIR}/sata0.img"
python3 "${SCRIPT_DIR}/make-gpt-image.py" "${NVME_IMAGE}"
python3 "${SCRIPT_DIR}/make-gpt-image.py" "${SATA_IMAGE}"

rm -f "${SERIAL_LOG}" "${PPM_OUT}" "${MON_SOCK}" "${OUT_PNG}"

# UEFI / OVMF — match run.sh's default firmware. See
# screenshot.sh for the rationale (kernel ELF spawn path is
# sensitive to firmware memory-map differences; UEFI is the
# project's primary target).
OVMF_CODE="${DUETOS_OVMF_CODE:-/usr/share/OVMF/OVMF_CODE_4M.fd}"
OVMF_VARS_TEMPLATE="${DUETOS_OVMF_VARS:-/usr/share/OVMF/OVMF_VARS_4M.fd}"
OVMF_VARS_COPY="${BUILD_DIR}/screen-theme-ovmf-vars.fd"
cp "${OVMF_VARS_TEMPLATE}" "${OVMF_VARS_COPY}"

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
    -device "qemu-xhci,id=xhci" \
    -device "usb-kbd,bus=xhci.0" \
    -cdrom "${ISO_IMAGE}" -boot d &
QEMU_PID=$!

trap 'kill "${QEMU_PID}" 2>/dev/null || true; rm -f "${MON_SOCK}"' EXIT

# Drive GRUB: poll the serial log for the "highlighted entry will
# be executed automatically" marker that GRUB emits while the menu
# is up, then send N down-arrows and ret. Polling the marker
# (instead of a fixed sleep) handles slow firmware paths (OVMF
# takes 3-5s to reach GRUB) without baking in a worst-case wait.
(
    # First: wait until the QEMU monitor socket exists.
    for _ in $(seq 1 60); do
        [[ -S "${MON_SOCK}" ]] && break
        sleep 0.5
    done
    # Second: wait for GRUB to be on screen (it writes the
    # menu countdown to the serial log).
    for _ in $(seq 1 60); do
        if grep -q "automatically in" "${SERIAL_LOG}" 2>/dev/null; then
            break
        fi
        sleep 0.3
    done
    python3 - <<PY "${MON_SOCK}" "${DOWN_COUNT}"
import socket, sys, time
p = sys.argv[1]
n = int(sys.argv[2])
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect(p)
# Drain the monitor banner so subsequent commands aren't racing
# against init bytes the parser hasn't consumed yet.
s.settimeout(0.5)
try:
    while s.recv(4096):
        pass
except socket.timeout:
    pass
def send(cmd):
    s.sendall((cmd + "\n").encode()); time.sleep(0.4)
for _ in range(n):
    send("sendkey down")
send("sendkey ret")
s.close()
PY
) &

# Poll for the kheartbeat marker.
for _ in $(seq 1 60); do
    if [[ -f "${SERIAL_LOG}" ]] && grep -q "kheartbeat" "${SERIAL_LOG}"; then
        break
    fi
    sleep 1
done
if ! grep -q "kheartbeat" "${SERIAL_LOG}" 2>/dev/null; then
    echo "error: kheartbeat marker never appeared in ${SERIAL_LOG}" >&2
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
echo "screenshot: ${OUT_PNG}  (grub-down=${DOWN_COUNT})"
