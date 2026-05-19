#!/usr/bin/env bash
#
# Boot DuetOS straight into the self-driving GUI fuzz harness.
#
# Stages a sidecar ISO whose single GRUB entry auto-boots the
# Classic desktop with `autologin=1 gui-fuzz=<secs>` so the
# in-kernel runner (kernel/security/gui_fuzz.cpp) pumps a seeded
# torrent of keyboard + mouse events through the live window
# manager / widget / menu / hotkey dispatch, then TestExits.
#
# Usage:
#   tools/qemu/gui-fuzz.sh [secs] [seed]
#     secs : fuzz run window in seconds (default 25)
#     seed : xorshift seed, hex or dec (default kernel constant);
#            re-pass the seed printed by a crashing run to repro.
#
# Env:
#   DUETOS_PRESET   build preset (default x86_64-release)
#   DUETOS_TIMEOUT  outer wallclock cap (default secs + 60)
#   DUETOS_THEME    desktop theme (default classic)
#
# Serial transcript -> ${BUILD_DIR}/gui-fuzz.log
# Exit 0 iff `[gui-fuzz] complete` appears AND the boot-log
# regression scan finds no panic / oops / triple-fault; non-zero
# otherwise. Doubles as a CI gate.

set -euo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

SECS="${1:-25}"
SEED="${2:-}"
THEME="${DUETOS_THEME:-classic}"

PRESET="${DUETOS_PRESET:-x86_64-release}"
BUILD_DIR="${REPO_ROOT}/build/${PRESET}"
ISO_OUT="${BUILD_DIR}/duetos-gui-fuzz.iso"
ISO_STAGE="${BUILD_DIR}/duetos-gui-fuzz-stage"
SERIAL_LOG="${BUILD_DIR}/gui-fuzz.log"

if [[ ! -f "${BUILD_DIR}/duetos.iso" ]]; then
    echo "error: canonical ISO not built at ${BUILD_DIR}/duetos.iso" >&2
    echo "       cmake --build ${BUILD_DIR}" >&2
    exit 1
fi
if ! command -v grub-mkrescue >/dev/null 2>&1; then
    echo "error: grub-mkrescue missing — install qemu-system-x86 grub-* xorriso mtools ovmf" >&2
    exit 1
fi

SEED_ARG=""
if [[ -n "${SEED}" ]]; then
    SEED_ARG=" gui-fuzz-seed=${SEED}"
fi

rm -rf "${ISO_STAGE}" "${ISO_OUT}" "${SERIAL_LOG}"
mkdir -p "${ISO_STAGE}/boot/grub"
cp "${BUILD_DIR}/kernel/iso-stage/boot/duetos-kernel.elf" \
   "${ISO_STAGE}/boot/duetos-kernel.elf"
cat > "${ISO_STAGE}/boot/grub/grub.cfg" <<EOF
set timeout=0
set default=0
menuentry "DuetOS — GUI fuzz" {
    multiboot2 /boot/duetos-kernel.elf boot=desktop theme=${THEME} autologin=1 gui-fuzz=${SECS}${SEED_ARG}
    boot
}
EOF
grub-mkrescue --compress=xz -o "${ISO_OUT}" "${ISO_STAGE}" >/dev/null 2>&1

TIMEOUT_DEFAULT=$((SECS + 60))
export DUETOS_TIMEOUT="${DUETOS_TIMEOUT:-${TIMEOUT_DEFAULT}}"
export DUETOS_SMOKE_ISO="${ISO_OUT}"
export DUETOS_PRESET="${PRESET}"

echo "[gui-fuzz] secs=${SECS} seed=${SEED:-<default>} theme=${THEME}"
echo "[gui-fuzz] iso=${ISO_OUT}"
echo "[gui-fuzz] timeout=${DUETOS_TIMEOUT}s  serial -> ${SERIAL_LOG}"

set +o pipefail
"${SCRIPT_DIR}/run.sh" 2>&1 | tee "${SERIAL_LOG}" || true
set -o pipefail

rc=0
# Not line-anchored: concurrent COM1 writers can prefix the
# sentinel on its physical line. It is emitted exactly once, so
# an unanchored match is unambiguous.
if ! grep -q "\[gui-fuzz\] complete" "${SERIAL_LOG}"; then
    echo "[gui-fuzz] FAIL — '[gui-fuzz] complete' sentinel not seen" >&2
    rc=1
fi
# Unambiguous kernel-fault sentinels only. NOT a bare "#GP" — the
# boot path legitimately logs "arch/thermal : ... would #GP,
# skipping" on a non-Intel vendor, which is informational, not a
# fault. Real faults surface as PANIC / TRIPLE / oops / a lockdep
# or mutex-ownership violation.
CRASH_RE='PANIC|TRIPLE FAULT|TRIPLE-FAULT|kernel oops|task-kill|MUTEX-NONOWNER|SELF-DEADLOCK|release out-of-order|popped task was not Ready|no runnable task available'
if grep -anE "${CRASH_RE}" "${SERIAL_LOG}" >/dev/null; then
    echo "[gui-fuzz] FAIL — crash signature in serial log:" >&2
    grep -anE "${CRASH_RE}" "${SERIAL_LOG}" | head -20 >&2
    rc=1
fi
if [[ ${rc} -eq 0 ]]; then
    echo "[gui-fuzz] OK — runner completed, no crash signature"
fi
exit ${rc}
