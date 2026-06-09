#!/usr/bin/env bash
#
# browser-explore-session.sh — like desktop-qmp-session.sh (the proven GUI
# harness whose screendumps actually capture the DuetOS framebuffer) BUT with
# QEMU SLIRP user networking (e1000) enabled, so the kernel browser can reach
# real websites. Boots headless, waits for the desktop, then runs a driver.
#
# USAGE: browser-explore-session.sh DRIVER_PY
#   DRIVER_PY invoked as: python3 DRIVER_PY <MON_SOCK> <SERIAL_LOG>
# ENV: DUETOS_PRESET(x86_64-debug) DUETOS_SETTLE(18) DUETOS_BOOT_TIMEOUT(600)
#      SITES, SHOT_DIR passed through to the driver via env.
set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DRIVER_PY="${1:?usage: browser-explore-session.sh DRIVER_PY}"
PRESET="${DUETOS_PRESET:-x86_64-debug}"
SETTLE="${DUETOS_SETTLE:-18}"
BOOT_TIMEOUT="${DUETOS_BOOT_TIMEOUT:-600}"
SMP="${DUETOS_SMP:-1}"
BUILD="${REPO}/build/${PRESET}"
KERNEL_ELF="${BUILD}/kernel/duetos-kernel.elf"
OVMF_CODE="${DUETOS_OVMF_CODE:-/usr/share/OVMF/OVMF_CODE_4M.fd}"
OVMF_VARS_TEMPLATE="${DUETOS_OVMF_VARS:-/usr/share/OVMF/OVMF_VARS_4M.fd}"
PFX="${BUILD}/explore"
STAGE="${PFX}-stage"; ISO="${PFX}.iso"; SERIAL_LOG="${PFX}.serial.log"
MON_SOCK="${PFX}-mon.sock"; VARS="${PFX}-ovmf-vars.fd"; NVME="${PFX}-nvme.img"

[[ -f "${KERNEL_ELF}" ]] || { echo "kernel not built"; exit 1; }
rm -rf "${STAGE}"; mkdir -p "${STAGE}/boot/grub"
cp "${KERNEL_ELF}" "${STAGE}/boot/duetos-kernel.elf"
cat > "${STAGE}/boot/grub/grub.cfg" <<'EOF'
if loadfont unicode ; then
    insmod gfxterm; insmod all_video
    set gfxmode=1024x768x32; set gfxpayload=keep; terminal_output gfxterm
fi
set timeout=0
set default=0
menuentry "DuetOS explore" {
    multiboot2 /boot/duetos-kernel.elf boot=desktop smoke=none autologin=1
    boot
}
EOF
grub-mkrescue --compress=xz -o "${ISO}" "${STAGE}" >/dev/null 2>&1
cp "${OVMF_VARS_TEMPLATE}" "${VARS}"
python3 "${REPO}/tools/qemu/make-gpt-image.py" "${NVME}"
rm -f "${MON_SOCK}" "${SERIAL_LOG}"

# Same as desktop-qmp-session, EXCEPT: SLIRP user networking via e1000 (the
# driver DuetOS gets a real 10.0.2.15 DHCP lease + NAT internet on), instead
# of -net none. accel kvm:tcg for speed.
qemu-system-x86_64 \
    -drive "if=pflash,format=raw,readonly=on,file=${OVMF_CODE}" \
    -drive "if=pflash,format=raw,file=${VARS}" \
    -machine "q35,accel=kvm:tcg" -cpu max -m 512M -smp "${SMP}" \
    -vga virtio -display none \
    -serial "file:${SERIAL_LOG}" -monitor "unix:${MON_SOCK},server,nowait" \
    -no-reboot -no-shutdown \
    -netdev user,id=net0 -device e1000,netdev=net0 \
    -drive "file=${NVME},if=none,id=nvme0,format=raw" -device "nvme,serial=cafebabe,drive=nvme0" \
    -cdrom "${ISO}" -boot d &
QEMU_PID=$!
trap 'kill "${QEMU_PID}" 2>/dev/null || true; rm -f "${MON_SOCK}"' EXIT

export SERIAL_LOG MON_SOCK
python3 - "${MON_SOCK}" "${SERIAL_LOG}" "${BOOT_TIMEOUT}" "${SETTLE}" "${DRIVER_PY}" <<'PY'
import runpy, sys, time
mon, slog, boot_to, settle, driver = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4]), sys.argv[5]
def logtext():
    try: return open(slog,"rb").read().decode("utf-8","replace")
    except FileNotFoundError: return ""
end = time.time()+boot_to
while time.time()<end and "bringup-complete" not in logtext(): time.sleep(0.5)
if "bringup-complete" not in logtext():
    print("FAIL: bringup-complete never appeared", flush=True); sys.exit(3)
time.sleep(settle)
sys.argv = [driver, mon, slog]
runpy.run_path(driver, run_name="__main__")
PY
echo "[explore-session] serial: ${SERIAL_LOG}"
