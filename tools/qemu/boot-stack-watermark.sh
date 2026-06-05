#!/usr/bin/env bash
#
# Measure the BSP boot-stack high-water mark.
#
# Why this exists:
#   The "SMP=4 boot-tail wild-jump cascade" (Roadmap / Design-Decisions
#   2026-06-05) was root-caused as a boot-stack OVERFLOW: the deep
#   post-x509 network self-tests (HttpSelfTest / TlsSocketSelfTest) run the
#   full TLS->x509->ASN.1->RSA/EC chain on the BSP boot task's stack and
#   demanded ~268 KiB, overflowing the then-128 KiB stack ~140 KiB into low
#   RAM (silently, because the higher-half 2 MiB map is RW). The fix grew
#   the boot stack to 512 KiB "with headroom". This tool MEASURES that
#   headroom so the claim is checkable, not asserted — and stays as a
#   permanent regression gauge: if a future change pushes peak usage toward
#   512 KiB, the number here climbs visibly before it overflows again.
#
# How it works:
#   The boot stack lives in .bss.boot (zero-initialised at load) between the
#   `stack_bottom` and `stack_top` symbols. The stack grows DOWN from
#   stack_top. After the deep self-tests run, the lowest address ever
#   written is the high-water mark; everything below it is still pristine
#   zero. We boot debug, wait for the LAST deep-stack self-test to print its
#   PASS sentinel (TlsSocketSelfTest, which runs after HttpSelfTest), dump
#   the boot-stack physical range via the QEMU monitor `pmemsave`, then scan
#   from stack_bottom upward for the first non-zero byte. peak = stack_top -
#   first_nonzero.
#
# Caveats:
#   - "First non-zero from the bottom" can slightly UNDER-count peak usage
#     if the deepest frames left leading zero bytes; the crypto frames are
#     dense non-zero, so the boundary is crisp in practice. Treat the number
#     as a tight lower bound on peak usage / upper bound on headroom.
#   - Debug (KASAN+UBSAN) is REQUIRED: the deep self-tests are
#     kBootSelfTests-gated and only run under debug. Release never exercises
#     this stack pressure.
#
# Usage:
#   tools/qemu/boot-stack-watermark.sh
#
# Env:
#   DUETOS_PRESET   build preset (default x86_64-debug — MUST be a
#                   self-test build or the deep tests never run)
#   DUETOS_WM_MARKER  serial marker to wait for (default the
#                     tls-socket-selftest PASS line)
#   DUETOS_WM_TIMEOUT outer wallclock cap in seconds (default 360 — the
#                     debug boot to TlsSocketSelfTest is slow under TCG)
#   DUETOS_SMP      QEMU -smp (default 4,sockets=1,cores=2,threads=2)

set -euo pipefail
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

PRESET="${DUETOS_PRESET:-x86_64-debug}"
BUILD_DIR="${REPO_ROOT}/build/${PRESET}"
ISO_IMAGE="${BUILD_DIR}/duetos.iso"
KERNEL_ELF="${BUILD_DIR}/kernel/duetos-kernel.elf"
MARKER="${DUETOS_WM_MARKER:-[tls-socket-selftest] PASS}"
TIMEOUT="${DUETOS_WM_TIMEOUT:-360}"
SMP="${DUETOS_SMP:-4,sockets=1,cores=2,threads=2}"

SERIAL_LOG="${BUILD_DIR}/wm.serial.log"
DUMP_BIN="${BUILD_DIR}/wm.bootstack.bin"
MON_SOCK="${BUILD_DIR}/wm-mon.sock"

if [[ ! -f "${ISO_IMAGE}" ]]; then
    echo "error: ISO not built: ${ISO_IMAGE} (cmake --build build/${PRESET})" >&2
    exit 1
fi

# Resolve the boot-stack symbol addresses from the ELF. These are the
# kernel's LOW link addresses (the higher-half 0xffffffff80... view is the
# same physical page + KERNEL_VIRTUAL_BASE), so the nm value IS the physical
# address pmemsave wants.
read -r SB_HEX ST_HEX < <(
    nm "${KERNEL_ELF}" | awk '
        /[[:space:]]stack_bottom$/ { sb=$1 }
        /[[:space:]]stack_top$/    { st=$1 }
        END { print sb, st }'
)
if [[ -z "${SB_HEX}" || -z "${ST_HEX}" ]]; then
    echo "error: could not resolve stack_bottom/stack_top from ${KERNEL_ELF}" >&2
    exit 1
fi
SB=$((16#${SB_HEX}))
ST=$((16#${ST_HEX}))
SIZE=$((ST - SB))
printf "[wm] boot stack: phys 0x%x..0x%x  size=%d bytes (%d KiB)\n" "${SB}" "${ST}" "${SIZE}" "$((SIZE / 1024))"

OVMF_CODE="${DUETOS_OVMF_CODE:-/usr/share/OVMF/OVMF_CODE_4M.fd}"
OVMF_VARS_TEMPLATE="${DUETOS_OVMF_VARS:-/usr/share/OVMF/OVMF_VARS_4M.fd}"
OVMF_VARS_COPY="${BUILD_DIR}/wm-ovmf-vars.fd"
cp "${OVMF_VARS_TEMPLATE}" "${OVMF_VARS_COPY}"

NVME_IMAGE="${BUILD_DIR}/wm-nvme0.img"
SATA_IMAGE="${BUILD_DIR}/wm-sata0.img"
python3 "${SCRIPT_DIR}/make-gpt-image.py" "${NVME_IMAGE}"
python3 "${SCRIPT_DIR}/make-gpt-image.py" "${SATA_IMAGE}"

rm -f "${SERIAL_LOG}" "${DUMP_BIN}" "${MON_SOCK}"

# -net none: same ArpInsert race avoidance the screenshot harness documents.
qemu-system-x86_64 \
    -drive "if=pflash,format=raw,readonly=on,file=${OVMF_CODE}" \
    -drive "if=pflash,format=raw,file=${OVMF_VARS_COPY}" \
    -machine q35 -cpu max -m 512M \
    -smp "${SMP}" \
    -display none \
    -serial "file:${SERIAL_LOG}" \
    -monitor "unix:${MON_SOCK},server,nowait" \
    -no-reboot -no-shutdown \
    -drive "file=${NVME_IMAGE},if=none,id=nvme0,format=raw" \
    -device "nvme,serial=cafebabe,drive=nvme0" \
    -device "ahci,id=ahci1" \
    -drive "file=${SATA_IMAGE},if=none,id=sata0,format=raw" \
    -device "ide-hd,bus=ahci1.0,drive=sata0" \
    -net none \
    -cdrom "${ISO_IMAGE}" -boot d &
QEMU_PID=$!
trap 'kill "${QEMU_PID}" 2>/dev/null || true; rm -f "${MON_SOCK}"' EXIT

echo "[wm] waiting for marker: '${MARKER}' (timeout ${TIMEOUT}s)"
deadline=$((SECONDS + TIMEOUT))
seen=0
while (( SECONDS < deadline )); do
    if [[ -f "${SERIAL_LOG}" ]] && grep -qF "${MARKER}" "${SERIAL_LOG}"; then
        seen=1
        break
    fi
    if ! kill -0 "${QEMU_PID}" 2>/dev/null; then
        echo "[wm] QEMU exited before marker appeared" >&2
        break
    fi
    sleep 1
done

if (( seen == 0 )); then
    echo "[wm] ERROR: marker '${MARKER}' never appeared — boot too slow or faulted" >&2
    echo "[wm] serial tail:" >&2
    tail -8 "${SERIAL_LOG}" 2>/dev/null >&2 || true
    exit 2
fi
echo "[wm] marker seen at t=${SECONDS}s wall — dumping boot stack via monitor"

# Let any in-flight frame from the same self-test settle, then pmemsave.
sleep 1
python3 - "${MON_SOCK}" "${SB}" "${SIZE}" "${DUMP_BIN}" <<'PY'
import socket, sys, time, os
sock_path, base, size, out = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), sys.argv[4]
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
for _ in range(60):
    try:
        s.connect(sock_path); break
    except (FileNotFoundError, ConnectionRefusedError):
        time.sleep(0.2)
else:
    print("[wm] failed to connect to monitor", file=sys.stderr); sys.exit(2)
s.settimeout(2.0)
def drain():
    try:
        while s.recv(4096):
            pass
    except socket.timeout:
        pass
drain()  # consume the HMP banner + prompt before issuing the command
# Quote the path so any unusual char can't split the arg; HMP pmemsave
# writes `size` bytes of guest physical memory at `base` to the file.
s.sendall(('pmemsave 0x%x 0x%x "%s"\n' % (base, size, out)).encode())
# Poll for the dump to reach full size instead of guessing a sleep.
deadline = time.time() + 15
while time.time() < deadline:
    if os.path.exists(out) and os.path.getsize(out) >= size:
        break
    time.sleep(0.3)
drain()
s.sendall(b"quit\n")
time.sleep(0.5)
s.close()
PY

wait "${QEMU_PID}" 2>/dev/null || true

if [[ ! -f "${DUMP_BIN}" ]]; then
    echo "[wm] ERROR: pmemsave produced no dump at ${DUMP_BIN}" >&2
    exit 3
fi

# Scan: stack grows DOWN from the top. First non-zero from the bottom is the
# high-water low boundary; peak usage = size - that_offset.
python3 - "${DUMP_BIN}" "${SB}" "${ST}" <<'PY'
import sys
dump, sb, st = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
data = open(dump, "rb").read()
size = st - sb
if len(data) < size:
    print("[wm] WARN: short dump (%d < %d)" % (len(data), size))
    size = len(data)
first_nz = None
for off in range(size):
    if data[off] != 0:
        first_nz = off
        break
if first_nz is None:
    print("[wm] boot stack is ALL ZERO — marker fired but stack never used? (suspicious)")
    sys.exit(4)
peak = size - first_nz
hw_phys = sb + first_nz
print("------------------------------------------------------------")
print("[wm] boot-stack high-water result")
print("  stack region   : phys 0x%x .. 0x%x  (%d KiB)" % (sb, st, size // 1024))
print("  high-water low  : phys 0x%x  (offset %d from stack_bottom)" % (hw_phys, first_nz))
print("  peak usage      : %d bytes (%.1f KiB)" % (peak, peak / 1024.0))
print("  headroom left   : %d bytes (%.1f KiB)  = %.1f%% of stack free"
      % (first_nz, first_nz / 1024.0, 100.0 * first_nz / size))
print("  pre-fix demand  : ~268 KiB measured on the 128 KiB stack (overflowed ~140 KiB)")
verdict = "PASS" if peak < size * 0.75 else ("TIGHT" if peak < size else "OVERFLOW")
print("  verdict         : %s" % verdict)
print("------------------------------------------------------------")
PY
