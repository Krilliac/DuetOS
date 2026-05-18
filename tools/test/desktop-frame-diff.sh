#!/usr/bin/env bash
#
# desktop-frame-diff.sh — capture two idle-desktop frames N ms apart
# and render (a) the frame and (b) a change-highlight overlay as PNGs.
#
# WHY: the content-diff frame elision (framebuffer.cpp) only elides a
# recompose that lands pixel-identical. If an "idle" desktop never goes
# clean (frames_clean flat, flicker persists) something repaints every
# compose. This rig shows EXACTLY which pixels change between two idle
# frames so the offending UI element is identifiable by location/shape.
#
# Boots the same idle autologin ISO as gfx-frames-clean-smoke.sh, uses
# the QEMU monitor `screendump` (PPM), and a stdlib-only Python PPM->PNG
# + diff (no ImageMagick / PIL dependency).
#
# USAGE: tools/test/desktop-frame-diff.sh [out_dir]
# ENV:   DUETOS_PRESET (x86_64-release) DUETOS_GAP_MS (1500)
#        DUETOS_BOOT_TIMEOUT (200) DUETOS_SETTLE (12)

set -euo pipefail
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
PRESET="${DUETOS_PRESET:-x86_64-release}"
BUILD_DIR="${REPO_ROOT}/build/${PRESET}"
KERNEL_ELF="${BUILD_DIR}/kernel/duetos-kernel.elf"
OUT_DIR="${1:-${BUILD_DIR}}"
GAP_MS="${DUETOS_GAP_MS:-1500}"
BOOT_TIMEOUT="${DUETOS_BOOT_TIMEOUT:-200}"
SETTLE="${DUETOS_SETTLE:-12}"
OVMF_CODE="${DUETOS_OVMF_CODE:-/usr/share/OVMF/OVMF_CODE_4M.fd}"
OVMF_VARS_TEMPLATE="${DUETOS_OVMF_VARS:-/usr/share/OVMF/OVMF_VARS_4M.fd}"

STAGE="${BUILD_DIR}/fdiff-iso-stage"
SMOKE_ISO="${BUILD_DIR}/duetos-fdiff.iso"
SERIAL_LOG="${BUILD_DIR}/fdiff.serial.log"
MON_SOCK="${BUILD_DIR}/fdiff-mon.sock"
OVMF_VARS_COPY="${BUILD_DIR}/fdiff-ovmf-vars.fd"
NVME_IMAGE="${BUILD_DIR}/fdiff-nvme0.img"
SATA_IMAGE="${BUILD_DIR}/fdiff-sata0.img"
PPM_A="${BUILD_DIR}/fdiff-a.ppm"
PPM_B="${BUILD_DIR}/fdiff-b.ppm"

[[ -f "${KERNEL_ELF}" ]] || { echo "error: kernel not built: ${KERNEL_ELF}" >&2; exit 1; }

rm -rf "${STAGE}"; mkdir -p "${STAGE}/boot/grub"
cp "${KERNEL_ELF}" "${STAGE}/boot/duetos-kernel.elf"
cat > "${STAGE}/boot/grub/grub.cfg" <<'EOF'
set timeout=0
set default=0
menuentry "DuetOS — fdiff idle desktop" {
    multiboot2 /boot/duetos-kernel.elf boot=desktop smoke=none autologin=1
    boot
}
EOF
grub-mkrescue --compress=xz -o "${SMOKE_ISO}" "${STAGE}" >/dev/null 2>&1
[[ -f "${SMOKE_ISO}" ]] || { echo "error: smoke ISO build failed" >&2; exit 1; }
cp "${OVMF_VARS_TEMPLATE}" "${OVMF_VARS_COPY}"
python3 "${SCRIPT_DIR}/../qemu/make-gpt-image.py" "${NVME_IMAGE}"
python3 "${SCRIPT_DIR}/../qemu/make-gpt-image.py" "${SATA_IMAGE}"
rm -f "${MON_SOCK}" "${SERIAL_LOG}" "${PPM_A}" "${PPM_B}"

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

python3 - "$MON_SOCK" "$SERIAL_LOG" "$BOOT_TIMEOUT" "$SETTLE" "$GAP_MS" \
            "$PPM_A" "$PPM_B" "$OUT_DIR" <<'PY'
import socket, sys, time, os, struct, zlib

mon_p, slog, boot_to, settle, gap_ms, ppm_a, ppm_b, out_dir = sys.argv[1:9]
boot_to, settle, gap_ms = int(boot_to), int(settle), int(gap_ms)

def wait_marker(path, sub, timeout):
    end = time.time() + timeout
    while time.time() < end:
        try:
            if sub in open(path, "rb").read().decode("utf-8", "replace"):
                return True
        except FileNotFoundError:
            pass
        time.sleep(0.5)
    return False

if not wait_marker(slog, "bringup-complete", boot_to):
    print("FAIL: bringup-complete never appeared"); sys.exit(3)
time.sleep(settle)

def mon():
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    for _ in range(120):
        try: s.connect(mon_p); break
        except (FileNotFoundError, ConnectionRefusedError): time.sleep(0.25)
    time.sleep(0.5); s.recv(65536)
    return s

def screendump(s, path):
    if os.path.exists(path): os.remove(path)
    s.sendall(("screendump %s\n" % path).encode())
    end = time.time() + 20
    while time.time() < end:
        if os.path.exists(path) and os.path.getsize(path) > 1000:
            time.sleep(0.3); return True
        time.sleep(0.2)
    return False

s = mon()
if not screendump(s, ppm_a): print("FAIL: screendump A"); sys.exit(4)
time.sleep(gap_ms / 1000.0)
if not screendump(s, ppm_b): print("FAIL: screendump B"); sys.exit(4)

def read_ppm(path):
    d = open(path, "rb").read()
    assert d[:2] == b"P6", "not P6 PPM"
    i, fields = 2, []
    while len(fields) < 3:
        while d[i] in b" \t\r\n": i += 1
        if d[i:i+1] == b"#":
            while d[i] not in b"\r\n": i += 1
            continue
        j = i
        while d[j] not in b" \t\r\n": j += 1
        fields.append(int(d[i:j])); i = j
    i += 1
    w, h, mx = fields
    return w, h, d[i:i + w*h*3]

wa, ha, A = read_ppm(ppm_a)
wb, hb, B = read_ppm(ppm_b)
print("frame A %dx%d  frame B %dx%d" % (wa, ha, wb, hb))
if (wa, ha) != (wb, hb):
    print("FAIL: frame size mismatch"); sys.exit(5)
w, h = wa, ha

minx, miny, maxx, maxy, changed = w, h, -1, -1, 0
GX, GY = 64, 36
grid = [[0]*GX for _ in range(GY)]
for y in range(h):
    ro = y*w*3
    for x in range(w):
        o = ro + x*3
        if A[o:o+3] != B[o:o+3]:
            changed += 1
            if x < minx: minx = x
            if x > maxx: maxx = x
            if y < miny: miny = y
            if y > maxy: maxy = y
            grid[y*GY//h][x*GX//w] += 1

total = w*h
print("changed pixels: %d / %d (%.1f%%)" % (changed, total, 100.0*changed/total))
if changed:
    print("change bbox: %dx%d @ (%d,%d)  [x %d..%d  y %d..%d]"
          % (maxx-minx+1, maxy-miny+1, minx, miny, minx, maxx, miny, maxy))
print("change heat-map (each cell = %dx%d px; '.'=none #=dense):" % (w//GX, h//GY))
for row in grid:
    mxc = max(row) or 1
    print("".join(" .:-=+*#%@"[min(9, c*9//mxc)] if c else "." for c in row))

def write_png(path, w, h, rgb, mark=None):
    # mark: optional bytes-parallel "changed" mask -> tint red.
    def chunk(tag, data):
        return (struct.pack(">I", len(data)) + tag + data
                + struct.pack(">I", zlib.crc32(tag + data) & 0xffffffff))
    raw = bytearray()
    for y in range(h):
        raw.append(0)
        ro = y*w*3
        if mark is None:
            raw += rgb[ro:ro+w*3]
        else:
            for x in range(w):
                o = ro + x*3
                if mark[y*w + x]:
                    raw += bytes((255, 0, 0))
                else:
                    g = (rgb[o]*30 + rgb[o+1]*59 + rgb[o+2]*11)//100 // 2
                    raw += bytes((g, g, g))
    comp = zlib.compress(bytes(raw), 9)
    with open(path, "wb") as f:
        f.write(b"\x89PNG\r\n\x1a\n")
        f.write(chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0)))
        f.write(chunk(b"IDAT", comp))
        f.write(chunk(b"IEND", b""))

mask = bytearray(w*h)
for y in range(h):
    ro = y*w*3
    for x in range(w):
        o = ro+x*3
        if A[o:o+3] != B[o:o+3]:
            mask[y*w+x] = 1

a_png = os.path.join(out_dir, "fdiff-frameA.png")
d_png = os.path.join(out_dir, "fdiff-changes.png")
write_png(a_png, w, h, A)
write_png(d_png, w, h, A, mask)
print("WROTE %s" % a_png)
print("WROTE %s" % d_png)
PY
RC=$?
echo "[fdiff] serial log: ${SERIAL_LOG}"
exit $RC
