#!/usr/bin/env bash
#
# winver-screendump.sh — boot the autologin DuetOS desktop headless with a
# staged Windows .exe set to auto-spawn via `peexec=`, give a Python driver a
# live HMP monitor socket, and let it screendump the framebuffer so a GUI PE
# (e.g. winver.exe's ShellAboutW "About" window) can be visually verified.
#
# This is desktop-qmp-session.sh + the run-exe.sh staging path fused: the GRUB
# cmdline carries `peexec=<SFN>` so the kernel spawns the staged .exe onto the
# running desktop, and the FAT32 nvme image is seeded with the host .exe.
#
# USAGE:
#   winver-screendump.sh INSTANCE HOST_EXE SFN DRIVER_PY
#     INSTANCE   unique alnum id (namespaces all per-run temp files)
#     HOST_EXE   path to the .exe on the dev host
#     SFN        DOS 8.3 name the kernel reads off FAT32 (e.g. WINVER.EXE)
#     DRIVER_PY  python3 driver, invoked: DRIVER_PY <MON_SOCK> <SERIAL_LOG>
#
# ENV: DUETOS_PRESET (x86_64-debug) DUETOS_SETTLE (18) DUETOS_BOOT_TIMEOUT (600)
set -euo pipefail
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

INSTANCE="${1:?usage: winver-screendump.sh INSTANCE HOST_EXE SFN DRIVER_PY}"
HOST_EXE="${2:?missing HOST_EXE}"
SFN="${3:?missing SFN}"
DRIVER_PY="${4:?missing DRIVER_PY}"
[[ -f "${HOST_EXE}" ]] || { echo "error: host exe not found: ${HOST_EXE}" >&2; exit 2; }
[[ -f "${DRIVER_PY}" ]] || { echo "error: driver not found: ${DRIVER_PY}" >&2; exit 2; }

PRESET="${DUETOS_PRESET:-x86_64-debug}"
SETTLE="${DUETOS_SETTLE:-18}"
BOOT_TIMEOUT="${DUETOS_BOOT_TIMEOUT:-600}"
BUILD_DIR="${REPO_ROOT}/build/${PRESET}"
KERNEL_ELF="${BUILD_DIR}/kernel/duetos-kernel.elf"
OVMF_CODE="${DUETOS_OVMF_CODE:-/usr/share/OVMF/OVMF_CODE_4M.fd}"
OVMF_VARS_TEMPLATE="${DUETOS_OVMF_VARS:-/usr/share/OVMF/OVMF_VARS_4M.fd}"

PFX="${BUILD_DIR}/wvsess-${INSTANCE}"
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
cat > "${STAGE}/boot/grub/grub.cfg" <<EOF
if loadfont unicode ; then
    insmod gfxterm
    if [ "\${feature_all_video_module}" = "y" ] ; then
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
menuentry "DuetOS winver-screendump desktop" {
    multiboot2 /boot/duetos-kernel.elf boot=desktop smoke=none autologin=1 peexec=${SFN}
    boot
}
EOF
grub-mkrescue --compress=xz -o "${ISO}" "${STAGE}" >/dev/null 2>&1
cp "${OVMF_VARS_TEMPLATE}" "${VARS}"
# Seed the staged .exe into the FAT32 root of BOTH disk images. The
# kernel's peexec-deferred task latches onto "FAT vol 0" — which one
# that is depends on async storage enumeration order (nvme vs ahci),
# so put the file on both to guarantee the lookup hits regardless.
DUETOS_STAGE_FILES="${SFN}=${HOST_EXE}" python3 "${REPO_ROOT}/tools/qemu/make-gpt-image.py" "${NVME}"
DUETOS_STAGE_FILES="${SFN}=${HOST_EXE}" python3 "${REPO_ROOT}/tools/qemu/make-gpt-image.py" "${SATA}"
rm -f "${MON_SOCK}" "${SERIAL_LOG}"

qemu-system-x86_64 \
    -drive "if=pflash,format=raw,readonly=on,file=${OVMF_CODE}" \
    -drive "if=pflash,format=raw,file=${VARS}" \
    -machine q35 -cpu max -m 512M -vga virtio -display none \
    -serial "file:${SERIAL_LOG}" -monitor "unix:${MON_SOCK},server,nowait" \
    -no-reboot -no-shutdown \
    -drive "file=${NVME},if=none,id=nvme0,format=raw" -device "nvme,serial=cafebabe,drive=nvme0" \
    -device "ahci,id=ahci1" -drive "file=${SATA},if=none,id=sata0,format=raw" \
    -device "ide-hd,bus=ahci1.0,drive=sata0" \
    -net none -cdrom "${ISO}" -boot d &
QEMU_PID=$!
trap 'kill "${QEMU_PID}" 2>/dev/null || true; rm -f "${MON_SOCK}"' EXIT

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
sys.argv = [driver, mon, slog]
runpy.run_path(driver, run_name="__main__")
PY
RC=$?
echo "[winver-screendump:${INSTANCE}] serial: ${SERIAL_LOG} (rc=${RC})"
exit ${RC}
