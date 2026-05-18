#!/usr/bin/env bash
#
# gfx-frames-clean-smoke.sh — runtime proof of the content-diff frame
# elision (kernel/drivers/video/framebuffer.cpp).
#
# WHAT IT PROVES
#   On an idle autologin desktop the ui-ticker recomposes the whole
#   surface ~1/s, but the recompose lands pixel-identical output, so
#   FramebufferEndCompose's content diff finds an empty delta and
#   skips the blit/present. That elided frame is counted as
#   `frames_clean`. So on a healthy idle desktop:
#       frames_composed keeps climbing   (compositor still alive — NOT frozen)
#       frames_clean    keeps climbing   (the elision is actually firing)
#   Both must hold: composed-climbing alone could be a flicker (#286
#   ungated) and clean-climbing without composed-climbing could be a
#   freeze (#288). The pair together is the freeze-proof signature.
#
# HOW
#   Boots a single-entry smoke ISO (boot=desktop smoke=none autologin=1
#   -> idle desktop, no PE smokes under an emulator) under QEMU with
#   `-vga virtio` (the virtio-gpu backend whose host round-trip the
#   elision removes), COM1 on a bidirectional unix socket. After the
#   bringup-complete marker it drives the kernel serial shell: `gfx`,
#   idle DUETOS_IDLE_SECS, `gfx` again, and diffs the two snapshots.
#
# USAGE
#   tools/test/gfx-frames-clean-smoke.sh
#
# ENV
#   DUETOS_PRESET     build preset (default x86_64-release)
#   DUETOS_IDLE_SECS  idle window between the two gfx reads (default 8)
#   DUETOS_BOOT_TIMEOUT  max secs to wait for bringup-complete (default 180)
#   DUETOS_OVMF_CODE / DUETOS_OVMF_VARS  OVMF firmware overrides
#
# EXIT 0 = both counters climbed (elision proven). Non-zero otherwise;
# the serial log path is printed for triage with boot-log-analyze.sh.

set -euo pipefail
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

PRESET="${DUETOS_PRESET:-x86_64-release}"
BUILD_DIR="${REPO_ROOT}/build/${PRESET}"
KERNEL_ELF="${BUILD_DIR}/kernel/duetos-kernel.elf"
IDLE_SECS="${DUETOS_IDLE_SECS:-8}"
BOOT_TIMEOUT="${DUETOS_BOOT_TIMEOUT:-180}"
OVMF_CODE="${DUETOS_OVMF_CODE:-/usr/share/OVMF/OVMF_CODE_4M.fd}"
OVMF_VARS_TEMPLATE="${DUETOS_OVMF_VARS:-/usr/share/OVMF/OVMF_VARS_4M.fd}"

STAGE="${BUILD_DIR}/gfx-clean-iso-stage"
SMOKE_ISO="${BUILD_DIR}/duetos-gfx-clean.iso"
SERIAL_SOCK="${BUILD_DIR}/gfx-clean-serial.sock"
MON_SOCK="${BUILD_DIR}/gfx-clean-mon.sock"
SERIAL_LOG="${BUILD_DIR}/gfx-clean.serial.log"
OVMF_VARS_COPY="${BUILD_DIR}/gfx-clean-ovmf-vars.fd"
NVME_IMAGE="${BUILD_DIR}/gfx-clean-nvme0.img"
SATA_IMAGE="${BUILD_DIR}/gfx-clean-sata0.img"

[[ -f "${KERNEL_ELF}" ]] || { echo "error: kernel not built: ${KERNEL_ELF}" >&2; exit 1; }
command -v grub-mkrescue >/dev/null || { echo "error: grub-mkrescue missing" >&2; exit 1; }

# Single-entry smoke ISO — same cmdline shape run.sh's smoke path uses.
rm -rf "${STAGE}"; mkdir -p "${STAGE}/boot/grub"
cp "${KERNEL_ELF}" "${STAGE}/boot/duetos-kernel.elf"
cat > "${STAGE}/boot/grub/grub.cfg" <<'EOF'
set timeout=0
set default=0
menuentry "DuetOS — gfx-clean idle desktop" {
    multiboot2 /boot/duetos-kernel.elf boot=desktop smoke=none autologin=1
    boot
}
EOF
grub-mkrescue --compress=xz -o "${SMOKE_ISO}" "${STAGE}" >/dev/null 2>&1
[[ -f "${SMOKE_ISO}" ]] || { echo "error: smoke ISO build failed" >&2; exit 1; }

cp "${OVMF_VARS_TEMPLATE}" "${OVMF_VARS_COPY}"
python3 "${SCRIPT_DIR}/../qemu/make-gpt-image.py" "${NVME_IMAGE}"
python3 "${SCRIPT_DIR}/../qemu/make-gpt-image.py" "${SATA_IMAGE}"
rm -f "${SERIAL_SOCK}" "${MON_SOCK}" "${SERIAL_LOG}"

qemu-system-x86_64 \
    -drive "if=pflash,format=raw,readonly=on,file=${OVMF_CODE}" \
    -drive "if=pflash,format=raw,file=${OVMF_VARS_COPY}" \
    -machine q35 -cpu max -m 512M \
    -vga virtio \
    -display none \
    -chardev "socket,id=com1,path=${SERIAL_SOCK},server=on,wait=off" \
    -serial chardev:com1 \
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
trap 'kill "${QEMU_PID}" 2>/dev/null || true; rm -f "${SERIAL_SOCK}" "${MON_SOCK}"' EXIT

python3 - "$SERIAL_SOCK" "$SERIAL_LOG" "$BOOT_TIMEOUT" "$IDLE_SECS" <<'PY'
import socket, sys, time, re, threading

sock_path, log_path, boot_to, idle = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4])

s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
for _ in range(240):
    try:
        s.connect(sock_path); break
    except (FileNotFoundError, ConnectionRefusedError):
        time.sleep(0.25)
else:
    print("FAIL: never connected to COM1 socket"); sys.exit(2)

buf = bytearray()
lock = threading.Lock()
stop = False
logf = open(log_path, "wb")

def reader():
    while not stop:
        try:
            d = s.recv(4096)
        except OSError:
            break
        if not d:
            break
        with lock:
            buf.extend(d)
        logf.write(d); logf.flush()

t = threading.Thread(target=reader, daemon=True); t.start()

def text():
    with lock:
        return bytes(buf).decode("utf-8", "replace")

def wait_for(substr, timeout):
    end = time.time() + timeout
    while time.time() < end:
        if substr in text():
            return True
        time.sleep(0.5)
    return False

# 1. Bringup must complete (compositor online).
if not wait_for("bringup-complete", boot_to):
    print("FAIL: 'bringup-complete' never appeared within %ds" % boot_to)
    sys.exit(3)
# Let autologin land + the desktop run a few ui-ticker passes.
time.sleep(8)

CLEAN = re.compile(r"\(clean=(\d+)\s+partial=(\d+)\s+full=(\d+)\)")
COMP  = re.compile(r"frames composed:\s+(\d+)")

def gfx_snapshot(tag):
    with lock:
        mark = len(buf)
    s.sendall(b"\n")
    time.sleep(0.4)
    s.sendall(b"gfx\n")
    end = time.time() + 25
    while time.time() < end:
        with lock:
            chunk = bytes(buf[mark:]).decode("utf-8", "replace")
        c = CLEAN.search(chunk)
        fc = COMP.search(chunk)
        if c and fc:
            return int(fc.group(1)), int(c.group(1)), int(c.group(2)), int(c.group(3))
        time.sleep(0.5)
    print("FAIL: gfx output not parsed for snapshot '%s'" % tag)
    print("---- last 1500 chars on COM1 ----")
    print(text()[-1500:])
    sys.exit(4)

comp1, clean1, part1, full1 = gfx_snapshot("t0")
print("t0: composed=%d clean=%d partial=%d full=%d" % (comp1, clean1, part1, full1))
time.sleep(idle)
comp2, clean2, part2, full2 = gfx_snapshot("t1")
print("t1: composed=%d clean=%d partial=%d full=%d" % (comp2, clean2, part2, full2))

stop = True
dcomp, dclean = comp2 - comp1, clean2 - clean1
print("delta over %ds idle: composed +%d  clean +%d  partial +%d  full +%d"
      % (idle, dcomp, dclean, part2 - part1, full2 - full1))

ok = True
if dcomp <= 0:
    print("FAIL: frames_composed did NOT climb — compositor is frozen (the #288 failure mode)")
    ok = False
if dclean <= 0:
    print("FAIL: frames_clean did NOT climb — idle recomposes are NOT being elided "
          "(content-diff not firing -> would flicker, the #286 ungated mode)")
    ok = False
if ok:
    print("PASS: idle desktop composes (+%d) AND elides them as clean (+%d) — "
          "content-diff frame elision is working, freeze-proof signature confirmed"
          % (dcomp, dclean))
sys.exit(0 if ok else 5)
PY
RC=$?
echo "[gfx-clean] serial log: ${SERIAL_LOG}"
exit $RC
