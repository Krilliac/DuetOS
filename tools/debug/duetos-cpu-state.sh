#!/usr/bin/env bash
#
# duetos-cpu-state.sh — boot the kernel headless, wait N seconds,
# then query QEMU's monitor for the live CPU state (registers, IRQ
# counters, halt status). The probe is the most direct way to
# diagnose "kernel went silent" symptoms without an interactive
# debugger session: a non-progressing init shows up as RIP pointing
# into a polling loop; a hung-but-healthy kernel shows up as
# `HLT=1` in the idle task (the common scenario, and a useful
# confirmation that the box did finish booting).
#
# This script was the tool that confirmed the apparent "xHCI hang"
# in the screenshot harness was actually a successful boot —
# `info registers` showed RIP in IdleMain with HLT=1, which means
# the kernel reached the idle loop and was just waiting on input.
# The screenshot tool was killing QEMU before its poll budget
# rolled over to "found bringup-complete", and the screen.serial.log
# was being truncated to the pre-kill window.
#
# Usage:
#   tools/debug/duetos-cpu-state.sh [wait_secs] [iso_path]
#
# Defaults:
#   wait_secs = 200
#   iso_path  = build/x86_64-debug/duetos.iso
#
# Env:
#   DUETOS_OVMF_CODE  — OVMF firmware path (default OVMF_CODE_4M.fd)
#   DUETOS_OVMF_VARS  — OVMF vars template (default OVMF_VARS_4M.fd)

set -e

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

WAIT_SECS="${1:-200}"
ISO_IMAGE="${2:-${REPO_ROOT}/build/x86_64-debug/duetos.iso}"
OVMF_CODE="${DUETOS_OVMF_CODE:-/usr/share/OVMF/OVMF_CODE_4M.fd}"
OVMF_VARS_SRC="${DUETOS_OVMF_VARS:-/usr/share/OVMF/OVMF_VARS_4M.fd}"

SERIAL_LOG="/tmp/duetos-cpu-state.serial.log"
MON_SOCK="/tmp/duetos-cpu-state-mon.sock"
OVMF_VARS_COPY="/tmp/duetos-cpu-state-ovmf-vars.fd"

if [[ ! -f "${ISO_IMAGE}" ]]; then
    echo "error: ISO not built: ${ISO_IMAGE}" >&2
    exit 1
fi
cp "${OVMF_VARS_SRC}" "${OVMF_VARS_COPY}"
rm -f "${SERIAL_LOG}" "${MON_SOCK}"

qemu-system-x86_64 \
    -drive "if=pflash,format=raw,readonly=on,file=${OVMF_CODE}" \
    -drive "if=pflash,format=raw,file=${OVMF_VARS_COPY}" \
    -machine q35 -cpu max -m 512M \
    -vga virtio \
    -display none \
    -serial "file:${SERIAL_LOG}" \
    -monitor "unix:${MON_SOCK},server,nowait" \
    -no-reboot -no-shutdown \
    -cdrom "${ISO_IMAGE}" -boot d &
QPID=$!
echo "qemu pid=${QPID} serial=${SERIAL_LOG} mon=${MON_SOCK}"

# Wait for the boot to settle / wedge.
sleep "${WAIT_SECS}"

# Probe the monitor. `info registers` gives RIP / HLT state / flags;
# `info irq` gives the IRQ counters by line — useful for confirming
# whether the timer and other IRQs are still firing at the QEMU
# delivery level. `info status` reports VM running / paused.
python3 - <<PY
import socket, sys, time
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect("${MON_SOCK}")
s.settimeout(8.0)
def send_and_read(cmd):
    s.sendall((cmd + "\n").encode())
    time.sleep(1.0)
    out = b""
    s.setblocking(False)
    try:
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            out += chunk
    except (BlockingIOError, OSError):
        pass
    s.setblocking(True)
    return out.decode("latin-1", errors="replace")
for cmd in ("info registers", "info status", "info irq"):
    print(f"=== {cmd} ===")
    print(send_and_read(cmd))
    print()
s.sendall(b"quit\n")
PY

wait "${QPID}" 2>/dev/null || true
echo
echo "serial-log tail:"
tail -25 "${SERIAL_LOG}"
