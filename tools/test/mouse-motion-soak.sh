#!/usr/bin/env bash
#
# mouse-motion-soak.sh — drive sustained PS/2 mouse motion on the
# autologin desktop and measure soft-lockup pressure.
#
# WHY: a per-packet blocking serial trace in the mouse-reader task
# monopolised that task across enough consecutive scheduler ticks to
# trip kernel/diag/soft_lockup.cpp under continuous motion (user
# repro). This soak reproduces "user waggles the mouse for a while"
# headlessly so the fix can be VERIFIED (not assumed): it asserts the
# per-packet trace is gone and counts runtime soft-lockup warnings
# (excluding the deliberate boot self-test) during the soak window.
#
# Run against x86_64-debug-ubsan — that's the build operators boot
# (debug logging on) and where the regression actually showed.
#
# USAGE: tools/test/mouse-motion-soak.sh
# ENV:   DUETOS_PRESET (x86_64-debug-ubsan) DUETOS_SOAK_SECS (45)
#        DUETOS_BOOT_TIMEOUT (600) DUETOS_SETTLE (25)

set -euo pipefail
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
PRESET="${DUETOS_PRESET:-x86_64-debug-ubsan}"
BUILD_DIR="${REPO_ROOT}/build/${PRESET}"
KERNEL_ELF="${BUILD_DIR}/kernel/duetos-kernel.elf"
SOAK="${DUETOS_SOAK_SECS:-45}"
BOOT_TIMEOUT="${DUETOS_BOOT_TIMEOUT:-600}"
SETTLE="${DUETOS_SETTLE:-25}"
OVMF_CODE="${DUETOS_OVMF_CODE:-/usr/share/OVMF/OVMF_CODE_4M.fd}"
OVMF_VARS_TEMPLATE="${DUETOS_OVMF_VARS:-/usr/share/OVMF/OVMF_VARS_4M.fd}"

STAGE="${BUILD_DIR}/soak-iso-stage"
SMOKE_ISO="${BUILD_DIR}/duetos-soak.iso"
SERIAL_LOG="${BUILD_DIR}/soak.serial.log"
MON_SOCK="${BUILD_DIR}/soak-mon.sock"
OVMF_VARS_COPY="${BUILD_DIR}/soak-ovmf-vars.fd"
NVME_IMAGE="${BUILD_DIR}/soak-nvme0.img"
SATA_IMAGE="${BUILD_DIR}/soak-sata0.img"

[[ -f "${KERNEL_ELF}" ]] || { echo "error: kernel not built: ${KERNEL_ELF}" >&2; exit 1; }
rm -rf "${STAGE}"; mkdir -p "${STAGE}/boot/grub"
cp "${KERNEL_ELF}" "${STAGE}/boot/duetos-kernel.elf"
cat > "${STAGE}/boot/grub/grub.cfg" <<'EOF'
set timeout=0
set default=0
menuentry "DuetOS — mouse soak desktop" {
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

python3 - "$MON_SOCK" "$SERIAL_LOG" "$BOOT_TIMEOUT" "$SETTLE" "$SOAK" <<'PY'
import socket, sys, time

mon_p, slog, boot_to, settle, soak = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4]), int(sys.argv[5])

def logtext():
    try: return open(slog, "rb").read().decode("utf-8", "replace")
    except FileNotFoundError: return ""

end = time.time() + boot_to
while time.time() < end and "bringup-complete" not in logtext():
    time.sleep(0.5)
if "bringup-complete" not in logtext():
    print("FAIL: bringup-complete never appeared"); sys.exit(3)
time.sleep(settle)

# Mark where the soak begins so boot-time soft-lockup self-test
# (deliberate val=0x2a/0x63) is excluded from the count.
mark = len(logtext())

s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
for _ in range(120):
    try: s.connect(mon_p); break
    except (FileNotFoundError, ConnectionRefusedError): time.sleep(0.25)
time.sleep(0.5); s.recv(65536)

# Continuous motion: a long box/zig-zag walk, no clicks, for `soak`
# seconds. Small int8-safe deltas at a brisk cadence approximate a
# user waggling the mouse around the desktop.
deadline = time.time() + soak
pat = [(30, 0), (0, 25), (-28, 0), (0, -23), (22, 18), (-20, -16)]
i = 0
while time.time() < deadline:
    dx, dy = pat[i % len(pat)]
    s.sendall(("mouse_move %d %d\n" % (dx, dy)).encode())
    time.sleep(0.02)  # ~50 moves/s — brisk sustained motion
    i += 1

time.sleep(3)
txt = logtext()
soaked = txt[mark:]
pkt = soaked.count("input/ps2mouse : packet") + soaked.count("[mouse] dx=")
sl = [ln for ln in soaked.splitlines() if "diag/soft-lockup : soft-lockup" in ln]
sat = soaked.count('by="cpu-saturation"')
print("soak window: %ds, ~%d mouse_move injected" % (soak, i))
print("per-packet mouse trace lines during soak: %d  (expect 0)" % pkt)
print("runtime soft-lockup warnings during soak: %d  (was ~30 with the trace)" % len(sl))
print("cpu-saturation autonomic firings during soak: %d" % sat)
for ln in sl[:6]:
    print("  " + ln.strip())
ok = (pkt == 0) and (len(sl) == 0)
print("RESULT: %s" % ("PASS — trace gone AND no soft-lockup under sustained motion"
                       if ok else "ATTENTION — see counts above"))
sys.exit(0 if ok else 7)
PY
RC=$?
echo "[mouse-soak] serial log: ${SERIAL_LOG}"
exit $RC
