#!/usr/bin/env bash
#
# desktop-qmp-session.sh — boot the autologin DuetOS desktop headless,
# wait until it is interactive, then hand a Python driver a live HMP
# monitor socket + the serial log so it can inject input (sendkey /
# mouse_move / mouse_button), screendump, and assert on serial output.
#
# WHY: lets several controlling agents each drive an independent guest
# in parallel for input / GUI / compositor testing without a display.
# Every temp artifact is namespaced by INSTANCE so concurrent sessions
# never collide on sockets / ISO stages / disk images.
#
# USAGE: desktop-qmp-session.sh INSTANCE DRIVER_PY
#   INSTANCE   — unique alnum id; namespaces all per-run files.
#   DRIVER_PY  — path to a python3 script. Invoked as
#                  python3 DRIVER_PY <MON_SOCK> <SERIAL_LOG>
#                once the guest has printed "bringup-complete" and
#                settled for DUETOS_SETTLE seconds. Its exit code is
#                this script's exit code.
#
# DRIVER CONTRACT (helpers it can rely on): connect a unix-stream
# socket to MON_SOCK, recv the greeting, then send HMP command lines:
#   "sendkey a\n"            single key (QEMU key name; combos: ctrl-c)
#   "mouse_move DX DY\n"     relative pointer motion
#   "mouse_button N\n"       1=left 2=right 4=middle (bitmask), 0=release
#   "screendump /tmp/x.ppm\n"
# Read SERIAL_LOG (host file) at any point for guest output.
#
# ENV: DUETOS_PRESET (x86_64-debug) DUETOS_SETTLE (20)
#      DUETOS_BOOT_TIMEOUT (600)
set -euo pipefail
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

INSTANCE="${1:?usage: desktop-qmp-session.sh INSTANCE DRIVER_PY}"
DRIVER_PY="${2:?usage: desktop-qmp-session.sh INSTANCE DRIVER_PY}"
[[ -f "${DRIVER_PY}" ]] || { echo "error: driver not found: ${DRIVER_PY}" >&2; exit 2; }

PRESET="${DUETOS_PRESET:-x86_64-debug}"
SETTLE="${DUETOS_SETTLE:-20}"
BOOT_TIMEOUT="${DUETOS_BOOT_TIMEOUT:-600}"
SMP="${DUETOS_SMP:-1}"
BUILD_DIR="${REPO_ROOT}/build/${PRESET}"
KERNEL_ELF="${BUILD_DIR}/kernel/duetos-kernel.elf"
OVMF_CODE="${DUETOS_OVMF_CODE:-/usr/share/OVMF/OVMF_CODE_4M.fd}"
OVMF_VARS_TEMPLATE="${DUETOS_OVMF_VARS:-/usr/share/OVMF/OVMF_VARS_4M.fd}"

PFX="${BUILD_DIR}/sess-${INSTANCE}"
STAGE="${PFX}-stage"
ISO="${PFX}.iso"
SERIAL_LOG="${PFX}.serial.log"
MON_SOCK="${PFX}-mon.sock"
VARS="${PFX}-ovmf-vars.fd"
NVME="${PFX}-nvme.img"
SATA="${PFX}-sata.img"

[[ -f "${KERNEL_ELF}" ]] || { echo "error: kernel not built: ${KERNEL_ELF}" >&2; exit 1; }
rm -rf "${STAGE}"; mkdir -p "${STAGE}/boot/grub"
cp "${KERNEL_ELF}" "${STAGE}/boot/duetos-kernel.elf"
cat > "${STAGE}/boot/grub/grub.cfg" <<'EOF'
# Mirror the canonical boot/grub/grub.cfg + run.sh video setup so GRUB
# sets a gfx mode and the multiboot2 framebuffer-request tag reaches
# the kernel. Without it the kernel logs "no framebuffer tag" and falls
# back to the EFI-GOP rebind path (which works, but the framebuffer
# self-test SKIPs and the boot looks displayless to a triage reader).
if loadfont unicode ; then
    insmod gfxterm
    if [ "${feature_all_video_module}" = "y" ] ; then
        insmod all_video
    else
        insmod vbe
        insmod vga
        insmod efi_gop
        insmod efi_uga
    fi
    set gfxmode=1024x768x32
    set gfxpayload=keep
    terminal_output gfxterm
fi
set timeout=0
set default=0
menuentry "DuetOS qmp-session desktop" {
    multiboot2 /boot/duetos-kernel.elf boot=desktop smoke=none autologin=1
    boot
}
EOF
grub-mkrescue --compress=xz -o "${ISO}" "${STAGE}" >/dev/null 2>&1
cp "${OVMF_VARS_TEMPLATE}" "${VARS}"
python3 "${REPO_ROOT}/tools/qemu/make-gpt-image.py" "${NVME}"
python3 "${REPO_ROOT}/tools/qemu/make-gpt-image.py" "${SATA}"
rm -f "${MON_SOCK}" "${SERIAL_LOG}"

qemu-system-x86_64 \
    -drive "if=pflash,format=raw,readonly=on,file=${OVMF_CODE}" \
    -drive "if=pflash,format=raw,file=${VARS}" \
    -machine q35 -cpu max -m 512M -smp "${SMP}" -vga virtio -display none \
    -serial "file:${SERIAL_LOG}" -monitor "unix:${MON_SOCK},server,nowait" \
    -no-reboot -no-shutdown \
    -drive "file=${NVME},if=none,id=nvme0,format=raw" -device "nvme,serial=cafebabe,drive=nvme0" \
    -device "ahci,id=ahci1" -drive "file=${SATA},if=none,id=sata0,format=raw" \
    -device "ide-hd,bus=ahci1.0,drive=sata0" \
    -net none -cdrom "${ISO}" -boot d &
QEMU_PID=$!
trap 'kill "${QEMU_PID}" 2>/dev/null || true; rm -f "${MON_SOCK}"' EXIT

# Wait for interactive desktop, settle, then run the driver.
python3 - "${MON_SOCK}" "${SERIAL_LOG}" "${BOOT_TIMEOUT}" "${SETTLE}" "${DRIVER_PY}" <<'PY'
import runpy, sys, time
mon, slog, boot_to, settle, driver = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4]), sys.argv[5]
def logtext():
    try: return open(slog, "rb").read().decode("utf-8", "replace")
    except FileNotFoundError: return ""
end = time.time() + boot_to
while time.time() < end and "bringup-complete" not in logtext():
    time.sleep(0.5)
if "bringup-complete" not in logtext():
    print("FAIL: bringup-complete never appeared", flush=True); sys.exit(3)
time.sleep(settle)
# Hand the driver its argv (MON_SOCK, SERIAL_LOG) and run it in-process.
sys.argv = [driver, mon, slog]
runpy.run_path(driver, run_name="__main__")
PY
RC=$?
echo "[qmp-session:${INSTANCE}] serial: ${SERIAL_LOG} (rc=${RC})"
exit ${RC}
