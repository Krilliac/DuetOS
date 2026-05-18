#!/usr/bin/env bash
#
# tray-click-ubsan-repro.sh — reproduce the UBSan flood the user hit by
# clicking the system tray (battery/audio/chevron, bottom-right).
#
# Boots the autologin desktop (virtio-gpu), waits for bringup-complete +
# settle, then drives the QEMU PS/2 mouse via the HMP monitor: slam the
# cursor to the bottom-right, then click across the tray cell band a few
# times. Captures COM1 to a log and prints every distinct `[ubsan] ...
# at <file>:<hexline>:<hexcol>` so the UB site can be fixed.
#
# USAGE: tools/test/tray-click-ubsan-repro.sh
# ENV:   DUETOS_PRESET (x86_64-release) DUETOS_BOOT_TIMEOUT (220)
#        DUETOS_SETTLE (14)

set -euo pipefail
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
PRESET="${DUETOS_PRESET:-x86_64-release}"
BUILD_DIR="${REPO_ROOT}/build/${PRESET}"
KERNEL_ELF="${BUILD_DIR}/kernel/duetos-kernel.elf"
BOOT_TIMEOUT="${DUETOS_BOOT_TIMEOUT:-220}"
SETTLE="${DUETOS_SETTLE:-14}"
OVMF_CODE="${DUETOS_OVMF_CODE:-/usr/share/OVMF/OVMF_CODE_4M.fd}"
OVMF_VARS_TEMPLATE="${DUETOS_OVMF_VARS:-/usr/share/OVMF/OVMF_VARS_4M.fd}"

STAGE="${BUILD_DIR}/ubsan-iso-stage"
SMOKE_ISO="${BUILD_DIR}/duetos-ubsan.iso"
SERIAL_LOG="${BUILD_DIR}/ubsan.serial.log"
MON_SOCK="${BUILD_DIR}/ubsan-mon.sock"
OVMF_VARS_COPY="${BUILD_DIR}/ubsan-ovmf-vars.fd"
NVME_IMAGE="${BUILD_DIR}/ubsan-nvme0.img"
SATA_IMAGE="${BUILD_DIR}/ubsan-sata0.img"

[[ -f "${KERNEL_ELF}" ]] || { echo "error: kernel not built" >&2; exit 1; }
rm -rf "${STAGE}"; mkdir -p "${STAGE}/boot/grub"
cp "${KERNEL_ELF}" "${STAGE}/boot/duetos-kernel.elf"
cat > "${STAGE}/boot/grub/grub.cfg" <<'EOF'
set timeout=0
set default=0
menuentry "DuetOS — ubsan repro desktop" {
    multiboot2 /boot/duetos-kernel.elf boot=desktop smoke=none autologin=1
    boot
}
EOF
grub-mkrescue --compress=xz -o "${SMOKE_ISO}" "${STAGE}" >/dev/null 2>&1
cp "${OVMF_VARS_TEMPLATE}" "${OVMF_VARS_COPY}"
python3 "${SCRIPT_DIR}/../qemu/make-gpt-image.py" "${NVME_IMAGE}"
python3 "${SCRIPT_DIR}/../qemu/make-gpt-image.py" "${SATA_IMAGE}"
rm -f "${MON_SOCK}" "${SERIAL_LOG}"

qemu-system-x86_64 \
    -drive "if=pflash,format=raw,readonly=on,file=${OVMF_CODE}" \
    -drive "if=pflash,format=raw,file=${OVMF_VARS_COPY}" \
    -machine q35 -cpu max -m 512M \
    -vga virtio -display none \
    -serial "file:${SERIAL_LOG}" \
    -monitor "unix:${MON_SOCK},server,nowait" \
    -no-reboot -no-shutdown \
    -drive "file=${NVME_IMAGE},if=none,id=nvme0,format=raw" \
    -device "nvme,serial=cafebabe,drive=nvme0" \
    -device "ahci,id=ahci1" \
    -drive "file=${SATA_IMAGE},if=none,id=sata0,format=raw" \
    -device "ide-hd,bus=ahci1.0,drive=sata0" \
    -net none \
    -cdrom "${SMOKE_ISO}" -boot d &
QEMU_PID=$!
trap 'kill "${QEMU_PID}" 2>/dev/null || true; rm -f "${MON_SOCK}"' EXIT

python3 - "$MON_SOCK" "$SERIAL_LOG" "$BOOT_TIMEOUT" "$SETTLE" <<'PY'
import socket, sys, time

mon_p, slog, boot_to, settle = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4])

def logtext():
    try: return open(slog, "rb").read().decode("utf-8", "replace")
    except FileNotFoundError: return ""

end = time.time() + boot_to
while time.time() < end and "bringup-complete" not in logtext():
    time.sleep(0.5)
if "bringup-complete" not in logtext():
    print("FAIL: bringup-complete never appeared"); sys.exit(3)
time.sleep(settle)

s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
for _ in range(120):
    try: s.connect(mon_p); break
    except (FileNotFoundError, ConnectionRefusedError): time.sleep(0.25)
time.sleep(0.5); s.recv(65536)

def hmp(cmd, settle=0.12):
    s.sendall((cmd + "\n").encode()); time.sleep(settle)

def pin_topleft():
    # QEMU drops/clamps a single huge relative move; walk it in
    # int8-safe steps so every packet is delivered.
    for _ in range(50):
        hmp("mouse_move -120 -120", settle=0.03)

def move_to(px, py):
    # From (0,0), step right/down in <=120-px PS/2-safe increments.
    pin_topleft()
    x = 0
    while x < px:
        d = min(120, px - x); hmp("mouse_move %d 0" % d, settle=0.03); x += d
    y = 0
    while y < py:
        d = min(120, py - y); hmp("mouse_move 0 %d" % d, settle=0.03); y += d

def click():
    hmp("mouse_button 1"); hmp("mouse_button 0", settle=0.6)

ubsan_before = logtext().count("[ubsan]")

# Tray cells + chevron sit just left of the clock block on the
# bottom taskbar (screen 1024x768, taskbar ~ y 726..768). Click a
# spread of x across the tray icon band at the taskbar mid-line.
for tx in (905, 930, 880, 955, 860, 980, 820):
    move_to(tx, 746)
    click()
    hmp("", settle=0.5)

# Let any per-compose UBSan flood accumulate.
time.sleep(7)

txt = logtext()
ub = [ln for ln in txt.splitlines() if "[ubsan]" in ln]
print("ubsan lines before clicks: %d   after: %d   (delta %d)"
      % (ubsan_before, len(ub), len(ub) - ubsan_before))
seen = {}
for ln in ub:
    key = ln.split("[ubsan]", 1)[1].strip()
    seen[key] = seen.get(key, 0) + 1
if seen:
    print("distinct UBSan sites (kind at file:hexline:hexcol  xN):")
    for k, n in sorted(seen.items(), key=lambda kv: -kv[1]):
        print("  %s   x%d" % (k, n))
else:
    print("NO [ubsan] observed. tail of tray-click markers:")
    for ln in txt.splitlines():
        if "[ui] tray" in ln or "tray flyout" in ln:
            print("  " + ln)
print("--- last 25 serial lines ---")
print("\n".join(txt.splitlines()[-25:]))
sys.exit(0 if seen else 7)
PY
RC=$?
echo "[ubsan-repro] serial log: ${SERIAL_LOG}"
exit $RC
