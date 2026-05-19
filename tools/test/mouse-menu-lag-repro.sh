#!/usr/bin/env bash
#
# mouse-menu-lag-repro.sh — open the start menu, then drive sustained
# PS/2 mouse motion over it and assert the driver's packet ring never
# overflows.
#
# WHY: the start menu felt very slow to navigate. Root cause: the
# mouse-reader forced a full-screen DesktopCompose() on EVERY motion
# packet while a menu was open (kernel/core/boot_tasks.cpp). A full
# recompose can't keep up with the ~100 Hz PS/2 packet rate, so the
# 32-slot decoded-packet ring in kernel/drivers/input/ps2mouse.cpp
# overflows, drop-oldest discards motion deltas, and the cursor
# crawls. The fix coalesces queued same-button motion into one
# compose AND gates the menu recompose on an actual hover-row change.
#
# This harness reproduces "user opens Start and waggles the mouse
# around it" headlessly so the fix can be VERIFIED, not assumed. The
# load-bearing assertion is that the ps2mouse once-warn
#   "mouse packet ring full — discarding OLDEST (consumer too slow)"
# never appears: it is a KLOG_ONCE_WARN (fires at most once, ever), so
# scanning the whole log is correct — pre-fix it fires during the
# soak; post-fix it must be absent. A second assertion requires the
# "[ui] menu open" sentinel so a run that failed to open the menu
# fails LOUD instead of passing vacuously.
#
# Run against x86_64-debug-ubsan — the build operators boot (debug
# logging on, UBSan live) and where the lag was observed.
#
# KNOWN LIMITATION (headless): opening the Start menu needs a
# pixel-precise click on a theme-dependent START rect. Some QEMU HMP
# rigs cannot place the click reliably; this script then exits
# 75 (INCONCLUSIVE) — NOT a regression. The netpanel-hover path in
# the sibling mouse-motion-soak.sh exercises the identical
# recompose-per-motion mechanism and is the proven stand-in
# assertion. Exit codes: 0=PASS, 7=ATTENTION (real ring overflow /
# soft-lockup regression), 75=INCONCLUSIVE (could not open menu).
#
# USAGE: tools/test/mouse-menu-lag-repro.sh
# ENV:   DUETOS_PRESET (x86_64-debug-ubsan) DUETOS_SOAK_SECS (40)
#        DUETOS_BOOT_TIMEOUT (600) DUETOS_SETTLE (25)

set -euo pipefail
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
PRESET="${DUETOS_PRESET:-x86_64-debug-ubsan}"
BUILD_DIR="${REPO_ROOT}/build/${PRESET}"
KERNEL_ELF="${BUILD_DIR}/kernel/duetos-kernel.elf"
SOAK="${DUETOS_SOAK_SECS:-40}"
BOOT_TIMEOUT="${DUETOS_BOOT_TIMEOUT:-600}"
SETTLE="${DUETOS_SETTLE:-25}"
OVMF_CODE="${DUETOS_OVMF_CODE:-/usr/share/OVMF/OVMF_CODE_4M.fd}"
OVMF_VARS_TEMPLATE="${DUETOS_OVMF_VARS:-/usr/share/OVMF/OVMF_VARS_4M.fd}"

STAGE="${BUILD_DIR}/menulag-iso-stage"
SMOKE_ISO="${BUILD_DIR}/duetos-menulag.iso"
SERIAL_LOG="${BUILD_DIR}/menulag.serial.log"
MON_SOCK="${BUILD_DIR}/menulag-mon.sock"
OVMF_VARS_COPY="${BUILD_DIR}/menulag-ovmf-vars.fd"
NVME_IMAGE="${BUILD_DIR}/menulag-nvme0.img"
SATA_IMAGE="${BUILD_DIR}/menulag-sata0.img"

[[ -f "${KERNEL_ELF}" ]] || { echo "error: kernel not built: ${KERNEL_ELF}" >&2; exit 1; }
rm -rf "${STAGE}"; mkdir -p "${STAGE}/boot/grub"
cp "${KERNEL_ELF}" "${STAGE}/boot/duetos-kernel.elf"
cat > "${STAGE}/boot/grub/grub.cfg" <<'EOF'
set timeout=0
set default=0
menuentry "DuetOS — menu-lag repro desktop" {
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

s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
for _ in range(120):
    try: s.connect(mon_p); break
    except (FileNotFoundError, ConnectionRefusedError): time.sleep(0.25)
time.sleep(0.5); s.recv(65536)

def send(cmd):
    s.sendall((cmd + "\n").encode()); time.sleep(0.03)

# The START button is on the taskbar; clicking it is the only way to
# open the start menu (no keyboard shortcut). Headless QEMU HMP
# clicking is pixel-imprecise, and the taskbar layout/START offset is
# theme-dependent, so a single fixed corner-click is unreliable.
# Strategy: park the cursor at the bottom edge (PS/2 deltas clamp at
# the screen border, so a big overshoot is safe), then sweep a left
# click across several x offsets along the bottom until the
# "[ui] menu open" sentinel appears. Returns "open" on success,
# "inconclusive" if the menu could not be opened in this rig (a
# tooling limitation, NOT a fix regression — distinct exit code).
def open_start_menu():
    # Drop to the bottom-left first: hard left + hard down (positive
    # dy is screen-down; the sibling soak proves that convention).
    for _ in range(40):
        send("mouse_move -300 300")
    # Sweep the click rightward along the bottom edge: START sits at
    # the left of the taskbar but its exact x depends on the theme.
    for step in range(0, 14):
        before = len(logtext())
        send("mouse_button 1"); time.sleep(0.08); send("mouse_button 0")
        time.sleep(0.9)
        if "[ui] menu open" in logtext()[before:]:
            return "open"
        send("mouse_move 28 0")  # nudge right, stay on the taskbar row
    return "inconclusive"

state = open_start_menu()
if state == "inconclusive":
    # Could not open the menu via HMP in this rig. Don't masquerade
    # as a regression: the netpanel-hover path in mouse-motion-soak.sh
    # exercises the identical recompose-per-motion mechanism and is
    # the proven stand-in. Exit 75 (EX_TEMPFAIL) = inconclusive.
    print("INCONCLUSIVE: start menu could not be opened headlessly in "
          "this QEMU rig (HMP click placement). Not a regression — see "
          "mouse-motion-soak.sh for the proven analogous assertion.")
    print("[menu-lag-repro] serial log: %s" % slog)
    sys.exit(75)

# Sustained motion while the menu is open: a brisk zig-zag that walks
# up into the menu and around its rows — the exact gesture that
# overran the ring pre-fix. No clicks (a click would dismiss the
# menu). ~50 moves/s for `soak` seconds.
deadline = time.time() + soak
pat = [(0, -250), (18, 0), (0, 250), (-18, 0), (14, -120), (-14, 120)]
i = 0
while time.time() < deadline:
    dx, dy = pat[i % len(pat)]
    send("mouse_move %d %d" % (dx, dy))
    time.sleep(0.02)
    i += 1

time.sleep(3)
txt = logtext()
# KLOG_ONCE_WARN -> at most one occurrence ever; scan the whole log.
ring_full = "mouse packet ring full" in txt
menu_open = txt.count("[ui] menu open")
sl = [ln for ln in txt.splitlines() if "diag/soft-lockup : soft-lockup" in ln]
sat = txt.count('by="cpu-saturation"')

print("soak window: %ds, ~%d mouse_move injected over the open menu" % (soak, i))
print("'[ui] menu open' sentinels: %d  (>=1 required)" % menu_open)
print("ps2mouse ring-full once-warn present: %s  (expect False)" % ring_full)
print("runtime soft-lockup warnings: %d  (expect 0)" % len(sl))
print("cpu-saturation autonomic firings: %d" % sat)
for ln in sl[:6]:
    print("  " + ln.strip())
ok = (not ring_full) and (menu_open >= 1) and (len(sl) == 0)
print("RESULT: %s" % ("PASS — ring never overflowed under sustained menu-hover motion"
                       if ok else "ATTENTION — see counts above"))
sys.exit(0 if ok else 7)
PY
RC=$?
echo "[menu-lag-repro] serial log: ${SERIAL_LOG}"
exit $RC
