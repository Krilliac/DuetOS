#!/usr/bin/env bash
#
# Boot CustomOS in GUI mode and capture a single framebuffer PNG.
#
# Runs QEMU headless with the standard kernel ISO, waits for the
# boot-log marker that says "desktop compositor is painting", then
# drives the QEMU monitor via a Unix socket to:
#   1. screendump into a PPM file,
#   2. quit QEMU.
# Finally converts the PPM to PNG with ImageMagick.
#
# Usage:
#   tools/qemu/screenshot.sh            -> build/x86_64-debug/screen.png
#   tools/qemu/screenshot.sh out.png    -> writes to out.png
#
# Env:
#   CUSTOMOS_PRESET   (default x86_64-debug)
#   CUSTOMOS_SETTLE   seconds to wait AFTER the boot marker appears
#                     so long-running self-tests have time to paint
#                     the full compose (default 5)

set -euo pipefail
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

PRESET="${CUSTOMOS_PRESET:-x86_64-debug}"
BUILD_DIR="${REPO_ROOT}/build/${PRESET}"
ISO_IMAGE="${BUILD_DIR}/customos.iso"
OUT_PNG="${1:-${BUILD_DIR}/screen.png}"
SERIAL_LOG="${BUILD_DIR}/screen.serial.log"
PPM_OUT="${BUILD_DIR}/screen.ppm"
MON_SOCK="${BUILD_DIR}/qemu-mon.sock"
SETTLE="${CUSTOMOS_SETTLE:-5}"

if [[ ! -f "${ISO_IMAGE}" ]]; then
    echo "error: ISO not built: ${ISO_IMAGE}" >&2
    echo "       cmake --build build/${PRESET}" >&2
    exit 1
fi

# Fresh scratch disks every invocation for determinism (same pattern
# the main run.sh uses).
NVME_IMAGE="${BUILD_DIR}/nvme0.img"
SATA_IMAGE="${BUILD_DIR}/sata0.img"
python3 "${SCRIPT_DIR}/make-gpt-image.py" "${NVME_IMAGE}"
python3 "${SCRIPT_DIR}/make-gpt-image.py" "${SATA_IMAGE}"

rm -f "${SERIAL_LOG}" "${PPM_OUT}" "${MON_SOCK}" "${OUT_PNG}"

# Launch QEMU in the background with:
#   - serial -> file (so we can grep for the "boot ok" marker),
#   - monitor -> unix socket (so we can send screendump + quit),
#   - display -> none (headless).
qemu-system-x86_64 \
    -machine q35 -cpu max -m 512M \
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

# Ensure QEMU is cleaned up on any exit.
trap 'kill "${QEMU_PID}" 2>/dev/null || true; rm -f "${MON_SOCK}"' EXIT

# If CUSTOMOS_DEMO=1, drive GRUB via the monitor DURING its 3-
# second timeout window: arrow-down past "Desktop" + "TTY" entries
# to land on "Desktop (demo widgets)", then enter. Must happen
# before GRUB auto-selects the default.
if [[ "${CUSTOMOS_DEMO:-0}" == "1" ]]; then
    (
        sleep 1  # let QEMU come up + monitor socket appear
        python3 - <<'PY' "${MON_SOCK}"
import socket, sys, time
p = sys.argv[1]
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
for _ in range(30):
    try:
        s.connect(p); break
    except (FileNotFoundError, ConnectionRefusedError):
        time.sleep(0.2)
def send(cmd):
    s.sendall((cmd + "\n").encode()); time.sleep(0.2)
send("sendkey down")
send("sendkey down")
send("sendkey ret")
s.close()
PY
    ) &
fi

# Poll the serial log for a marker that means "desktop is composed
# and the scheduler is running". kheartbeat fires periodically; once
# we see one line, the compositor has painted at least once.
for _ in $(seq 1 60); do
    if [[ -f "${SERIAL_LOG}" ]] && grep -q "kheartbeat" "${SERIAL_LOG}"; then
        break
    fi
    sleep 1
done
if ! grep -q "kheartbeat" "${SERIAL_LOG}" 2>/dev/null; then
    echo "error: kheartbeat marker never appeared in ${SERIAL_LOG}" >&2
    tail -40 "${SERIAL_LOG}" >&2 || true
    exit 1
fi

# Give the compositor a second pass so tray + clock have a chance
# to paint the second time (first pass is pre-heartbeat).
sleep "${SETTLE}"

# Drive the monitor via the Unix socket. QEMU prints a banner and a
# prompt; we just stream commands and close.
python3 - <<PY "${MON_SOCK}" "${PPM_OUT}"
import socket, sys, time
sock_path, ppm = sys.argv[1:3]
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
for _ in range(30):
    try:
        s.connect(sock_path)
        break
    except (FileNotFoundError, ConnectionRefusedError):
        time.sleep(0.2)
else:
    print("failed to connect to qemu monitor", file=sys.stderr)
    sys.exit(2)
s.settimeout(5.0)
def send(cmd):
    s.sendall((cmd + "\n").encode())
    time.sleep(0.3)
send(f"screendump {ppm}")
time.sleep(1.0)
send("quit")
s.close()
PY

# Wait for QEMU to exit so the screendump is fully flushed.
wait "${QEMU_PID}" 2>/dev/null || true

if [[ ! -f "${PPM_OUT}" ]]; then
    echo "error: screendump did not produce ${PPM_OUT}" >&2
    exit 1
fi

# Convert PPM -> PNG. Prefer ImageMagick; fall back to a tiny pure-
# python converter so this script works without extra deps.
if command -v magick >/dev/null 2>&1; then
    magick "${PPM_OUT}" "${OUT_PNG}"
elif command -v convert >/dev/null 2>&1; then
    convert "${PPM_OUT}" "${OUT_PNG}"
else
    python3 - <<PY "${PPM_OUT}" "${OUT_PNG}"
import sys, zlib, struct
ppm_path, png_path = sys.argv[1:3]
with open(ppm_path, "rb") as f:
    data = f.read()
# Parse P6 header: magic, width, height, maxval, pixel data.
def take(d, i):
    while i < len(d) and d[i:i+1] in (b" ", b"\t", b"\r", b"\n"):
        i += 1
    if i < len(d) and d[i:i+1] == b"#":
        while i < len(d) and d[i:i+1] != b"\n":
            i += 1
        return take(d, i + 1)
    return i
i = 0
assert data[0:2] == b"P6"
i += 2
tokens = []
for _ in range(3):
    i = take(data, i)
    j = i
    while j < len(data) and data[j:j+1] not in (b" ", b"\t", b"\r", b"\n"):
        j += 1
    tokens.append(int(data[i:j]))
    i = j
i += 1  # single whitespace after maxval
W, H, _ = tokens
raw = data[i:]
# Build PNG.
def chunk(tag, payload):
    return (struct.pack(">I", len(payload)) + tag + payload +
            struct.pack(">I", zlib.crc32(tag + payload) & 0xFFFFFFFF))
sig = b"\x89PNG\r\n\x1a\n"
ihdr = struct.pack(">IIBBBBB", W, H, 8, 2, 0, 0, 0)
rows = []
for y in range(H):
    row = raw[y*W*3:(y+1)*W*3]
    rows.append(b"\x00" + row)
idat = zlib.compress(b"".join(rows), 9)
with open(png_path, "wb") as f:
    f.write(sig)
    f.write(chunk(b"IHDR", ihdr))
    f.write(chunk(b"IDAT", idat))
    f.write(chunk(b"IEND", b""))
PY
fi

echo "screenshot: ${OUT_PNG}"
