#!/usr/bin/env bash
#
# Capture a PNG of the DuetOS Browser rendering its built-in welcome
# page — fully headless, no input injection.
#
# How it works:
#   1. Stage a single-entry GRUB ISO that auto-boots (timeout=0)
#      `boot=desktop theme=classic autologin=1 demo-browser=1`. The
#      demo-browser=1 cmdline makes the kernel render the welcome page
#      and show the Browser window at boot (kernel/core/boot_bringup.cpp
#      -> apps::browser::BrowserOpenDemo), so no Start-menu click is
#      needed. autologin skips the login gate.
#   2. Boot it under QEMU with `-device bochs-display`. This matters:
#      the kernel's Bochs-VBE driver targets the bochs-display MMIO
#      interface, and only that device reflects the guest's scanout to
#      a QMP `screendump` under `-display none`. Legacy `-vga std`
#      reads back blank; `-vga virtio` aborts QEMU 8.2.2 under TCG
#      (qemu_mutex_lock_iothread assertion). Likewise we never inject
#      keys — `send-key` hits the same TCG assertion on this build.
#   3. Wait for the desktop, then QMP `screendump` -> PNG.
#
# Usage:
#   tools/qemu/browser-screenshot.sh [out.png]
#     (default: build/<preset>/browser.png)
#
# Env:
#   DUETOS_PRESET     (default x86_64-debug-fast)
#   DUETOS_SETTLE     seconds after the desktop is up before capture (default 10)
#   DUETOS_BOOT_TIMEOUT max seconds to wait for the desktop (default 220)

set -euo pipefail
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

PRESET="${DUETOS_PRESET:-x86_64-debug-fast}"
BUILD_DIR="${REPO_ROOT}/build/${PRESET}"
KERNEL_ELF="${BUILD_DIR}/kernel/duetos-kernel.elf"
OUT_PNG="${1:-${BUILD_DIR}/browser.png}"
SETTLE="${DUETOS_SETTLE:-10}"
BOOT_TIMEOUT="${DUETOS_BOOT_TIMEOUT:-220}"

STAGE="${BUILD_DIR}/browser-shot-iso"
ISO="${BUILD_DIR}/duetos-demo-browser.iso"
SERIAL_LOG="${BUILD_DIR}/browser-shot.serial.log"
QMP_SOCK="${BUILD_DIR}/browser-shot-qmp.sock"
PPM="${BUILD_DIR}/browser-shot.ppm"

for tool in qemu-system-x86_64 grub-mkrescue convert python3; do
    command -v "$tool" >/dev/null 2>&1 || { echo "error: missing $tool" >&2; exit 1; }
done
[[ -f "${KERNEL_ELF}" ]] || { echo "error: kernel not built: ${KERNEL_ELF}" >&2; exit 1; }

# --- 1. Stage the single-entry demo-browser ISO --------------------
rm -rf "${STAGE}"; mkdir -p "${STAGE}/boot/grub"
cp "${KERNEL_ELF}" "${STAGE}/boot/duetos-kernel.elf"
cat > "${STAGE}/boot/grub/grub.cfg" <<'EOF'
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
menuentry "DuetOS — demo browser" {
    multiboot2 /boot/duetos-kernel.elf boot=desktop theme=classic autologin=1 demo-browser=1
    boot
}
EOF
grub-mkrescue --compress=xz -o "${ISO}" "${STAGE}" >/dev/null 2>&1
[[ -f "${ISO}" ]] || { echo "error: grub-mkrescue failed" >&2; exit 1; }

# --- 2. Boot under QEMU with bochs-display, no key injection -------
OVMF_CODE="${DUETOS_OVMF_CODE:-/usr/share/OVMF/OVMF_CODE_4M.fd}"
OVMF_VARS_TEMPLATE="${DUETOS_OVMF_VARS:-/usr/share/OVMF/OVMF_VARS_4M.fd}"
OVMF_VARS_COPY="${BUILD_DIR}/browser-shot-ovmf-vars.fd"
cp "${OVMF_VARS_TEMPLATE}" "${OVMF_VARS_COPY}"
NVME_IMAGE="${BUILD_DIR}/nvme0.img"
python3 "${SCRIPT_DIR}/make-gpt-image.py" "${NVME_IMAGE}" >/dev/null 2>&1
rm -f "${SERIAL_LOG}" "${QMP_SOCK}" "${PPM}" "${OUT_PNG}"

qemu-system-x86_64 \
    -drive "if=pflash,format=raw,readonly=on,file=${OVMF_CODE}" \
    -drive "if=pflash,format=raw,file=${OVMF_VARS_COPY}" \
    -machine q35,accel=tcg -cpu max -m 512M \
    -display none -vga none -device bochs-display \
    -serial "file:${SERIAL_LOG}" \
    -qmp "unix:${QMP_SOCK},server=on,wait=off" \
    -no-reboot -no-shutdown \
    -drive "file=${NVME_IMAGE},if=none,id=nvme0,format=raw" \
    -device "nvme,serial=cafebabe,drive=nvme0" \
    -net none -cdrom "${ISO}" -boot d &
QEMU_PID=$!
trap 'kill "${QEMU_PID}" 2>/dev/null || true; rm -f "${QMP_SOCK}"' EXIT

echo "[browser-shot] booting demo-browser ISO (<= ${BOOT_TIMEOUT}s)..."
deadline=$(( $(date +%s) + BOOT_TIMEOUT ))
until grep -qa "skipping login gate" "${SERIAL_LOG}" 2>/dev/null \
      && [[ "$(wc -l < "${SERIAL_LOG}" 2>/dev/null || echo 0)" -gt 1900 ]]; do
    kill -0 "${QEMU_PID}" 2>/dev/null || { echo "[browser-shot] QEMU exited early"; tail -3 "${SERIAL_LOG}" 2>/dev/null; exit 1; }
    grep -qa "assertion\|Bail out" "${SERIAL_LOG}" 2>/dev/null && { echo "[browser-shot] QEMU assertion"; exit 1; }
    (( $(date +%s) > deadline )) && { echo "[browser-shot] timed out waiting for desktop"; exit 1; }
    sleep 2
done
echo "[browser-shot] desktop up; settling ${SETTLE}s..."
sleep "${SETTLE}"

# --- 3. QMP screendump -> PNG -------------------------------------
python3 - "${QMP_SOCK}" "${PPM}" <<'PY'
import json, socket, sys
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.settimeout(10); s.connect(sys.argv[1])
f = s.makefile("rwb", buffering=0)
def snd(o): f.write((json.dumps(o) + "\r\n").encode())
def rt():
    while True:
        l = f.readline()
        if not l: sys.exit("QMP closed")
        m = json.loads(l)
        if "return" in m or "error" in m: return m
f.readline(); snd({"execute": "qmp_capabilities"}); rt()
snd({"execute": "screendump", "arguments": {"filename": sys.argv[2]}})
print("[browser-shot] screendump:", json.dumps(rt()))
PY
sleep 2
[[ -f "${PPM}" ]] || { echo "error: no PPM produced" >&2; exit 1; }
convert "${PPM}" "${OUT_PNG}" && rm -f "${PPM}"
echo "[browser-shot] wrote ${OUT_PNG} ($(identify -format '%wx%h %k colors' "${OUT_PNG}" 2>/dev/null))"
