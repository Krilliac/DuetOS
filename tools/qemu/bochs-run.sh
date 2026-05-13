#!/usr/bin/env bash
# tools/qemu/bochs-run.sh
#
# Boot the freshly-built DuetOS kernel under Bochs. Bochs is a much
# stricter x86 emulator than QEMU/TCG — it models segment limits,
# undefined-flag behaviour, IF/RF/NT propagation, and TLB shootdown
# in ways that real silicon will and TCG won't. We use it as the
# second emulator in the differential-boot harness so an "it boots
# under QEMU" claim is checked against a distinct bug profile.
#
# Headless only — Bochs's GUI front-ends aren't worth bringing into
# CI. Serial COM1 is captured to ${BUILD_DIR}/bochs-${profile}.log
# (the same shape profile-boot-smoke.sh's verifier reads).
#
# Inputs (env):
#   DUETOS_PRESET           — preset name (default x86_64-debug).
#   DUETOS_SMOKE_PROFILE    — required. Mirrors run.sh's smoke
#                             profile selector; an empty profile is
#                             rejected (no point booting Bochs for
#                             an interactive boot).
#   DUETOS_TIMEOUT          — seconds before SIGTERM (default 300).
#   DUETOS_BOCHS_CPU        — Bochs CPU model name (default
#                             core2_penryn_t9600). Run
#                             `bochs --help cpu` for the full list.
#                             core2 is intentionally older than
#                             you'd pick on real hardware: stricter
#                             feature set surfaces "we assumed X
#                             without checking CPUID" bugs that a
#                             newer model would hide.
#   DUETOS_BOCHS_IPS        — instructions-per-second pacing
#                             (default 50000000). Higher = faster
#                             wall-clock but Bochs is single-
#                             threaded; 50M is the sweet spot.
#   DUETOS_BOCHS_BIOS       — ROM image path. Default
#                             /usr/share/seabios/bios.bin —
#                             /usr/share/bochs/BIOS-bochs-latest
#                             triple-faults during the legacy-
#                             BIOS power-on sequence under newer
#                             CPU models on Bochs 2.7. SeaBIOS is
#                             the same image QEMU uses, so this
#                             also matches the qemu-tcg-seabios
#                             row's BIOS for direct comparison.
#
# Requires: bochs, grub-mkrescue, xorriso, mtools.

set -euo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

PRESET="${DUETOS_PRESET:-x86_64-debug}"
BUILD_DIR="${REPO_ROOT}/build/${PRESET}"
KERNEL_ELF="${BUILD_DIR}/kernel/duetos-kernel.elf"
SMOKE_PROFILE="${DUETOS_SMOKE_PROFILE:-}"
TIMEOUT_SECS="${DUETOS_TIMEOUT:-300}"
BOCHS_CPU="${DUETOS_BOCHS_CPU:-core2_penryn_t9600}"
BOCHS_IPS="${DUETOS_BOCHS_IPS:-50000000}"

if [[ -z "${SMOKE_PROFILE}" ]]; then
    echo "error: DUETOS_SMOKE_PROFILE must be set for bochs-run.sh." >&2
    echo "       Bochs has no interactive boot path in this harness." >&2
    exit 2
fi

for tool in bochs grub-mkrescue xorriso mtools; do
    if ! command -v "${tool}" >/dev/null 2>&1; then
        if [[ "${tool}" == "mtools" ]]; then
            # mtools is a package, not a single binary; probe one of
            # its binaries instead.
            if command -v mcopy >/dev/null 2>&1; then
                continue
            fi
        fi
        echo "error: ${tool} not installed." >&2
        exit 1
    fi
done

if [[ ! -f "${KERNEL_ELF}" ]]; then
    echo "error: ${KERNEL_ELF} not found — build the kernel first." >&2
    exit 1
fi

# Bochs ROM images. Path layout matches Debian/Ubuntu's `bochs`
# package; override via DUETOS_BOCHS_BIOS / DUETOS_BOCHS_VGABIOS
# if running on a distro that puts them elsewhere.
BOCHS_BIOS="${DUETOS_BOCHS_BIOS:-/usr/share/seabios/bios.bin}"
BOCHS_VGABIOS="${DUETOS_BOCHS_VGABIOS:-/usr/share/bochs/VGABIOS-lgpl-latest}"
if [[ ! -f "${BOCHS_BIOS}" || ! -f "${BOCHS_VGABIOS}" ]]; then
    echo "error: Bochs ROMs missing." >&2
    echo "       expected: ${BOCHS_BIOS} and ${BOCHS_VGABIOS}" >&2
    echo "       install via: sudo apt-get install -y seabios bochs bochsbios vgabios" >&2
    exit 1
fi

# Smoke ISO builder. Mirrors the inline block in run.sh; kept
# separate because Bochs's boot path is independent of QEMU's.
# Single-entry grub.cfg with `smoke=<profile>` baked in so the
# kernel routes into the scenario-only path on boot.
SMOKE_STAGE="${BUILD_DIR}/bochs-iso-stage-${SMOKE_PROFILE}"
SMOKE_ISO="${BUILD_DIR}/duetos-bochs-${SMOKE_PROFILE}.iso"
rm -rf "${SMOKE_STAGE}"
mkdir -p "${SMOKE_STAGE}/boot/grub"
cp "${KERNEL_ELF}" "${SMOKE_STAGE}/boot/duetos-kernel.elf"
cat > "${SMOKE_STAGE}/boot/grub/grub.cfg" <<EOF
set timeout=0
set default=0
menuentry "DuetOS — bochs smoke ${SMOKE_PROFILE}" {
    multiboot2 /boot/duetos-kernel.elf boot=desktop smoke=${SMOKE_PROFILE} autologin=1
    boot
}
EOF
grub-mkrescue --compress=xz -o "${SMOKE_ISO}" "${SMOKE_STAGE}" >/dev/null 2>&1
if [[ ! -f "${SMOKE_ISO}" ]]; then
    echo "error: failed to build smoke iso ${SMOKE_ISO}" >&2
    exit 1
fi

SERIAL_LOG="${BUILD_DIR}/bochs-${SMOKE_PROFILE}.log"
BOCHS_LOG="${BUILD_DIR}/bochs-${SMOKE_PROFILE}.bxlog"
BOCHSRC="${BUILD_DIR}/bochs-${SMOKE_PROFILE}.bxrc"
: > "${SERIAL_LOG}"
: > "${BOCHS_LOG}"

# Bochs config:
#   * ips=${BOCHS_IPS}        : single-CPU pacing target.
#   * display_library=term    : ncurses-based headless front-end.
#                               Ubuntu's bochs package doesn't ship
#                               a `nogui` mode; `term` is the closest
#                               equivalent (no X11 / SDL dependency).
#   * com1 mode=file          : serial COM1 → SERIAL_LOG, mirroring
#                               QEMU's -serial stdio capture.
#   * boot: cdrom             : auto-boot the smoke ISO via GRUB's
#                               legacy BIOS El Torito entry.
#   * cpu: reset_on_triple_fault=0 : let triple faults halt the box
#                               so an external `timeout` wrapper
#                               can cut the run rather than seeing
#                               the kernel loop through reboot.
#   * panic: action=fatal     : a Bochs panic (typically "unsupported
#                               instruction" or "page fault outside
#                               long mode") should kill the run and
#                               surface as a regression, not be
#                               silently ignored.
#   * memory: guest=512       : matches QEMU's -m 512M.
cat > "${BOCHSRC}" <<EOF
plugin_ctrl: unmapped=1, biosdev=1, speaker=1, extfpuirq=1, parallel=1, serial=1, gameport=0
romimage: file=${BOCHS_BIOS}
vgaromimage: file=${BOCHS_VGABIOS}
cpu: model=${BOCHS_CPU}, count=1, ips=${BOCHS_IPS}, reset_on_triple_fault=0
memory: guest=512, host=512
boot: cdrom
ata0-master: type=cdrom, path=${SMOKE_ISO}, status=inserted
com1: enabled=1, mode=file, dev=${SERIAL_LOG}
port_e9_hack: enabled=1
display_library: term
log: ${BOCHS_LOG}
panic: action=fatal
error: action=report
info:  action=ignore
debug: action=ignore
clock: sync=none, time0=local
EOF

# Ubuntu's `bochs` package is compiled with the internal debugger
# enabled, which means the simulator drops to a `<bochs:1>` prompt
# at t=0 and waits on stdin before running a single guest
# instruction. We don't ship a non-debug build (rebuilding Bochs
# without debugger support is ~5 minutes of CI time per job, not
# worth it), so feed the debugger a `c` (continue) via `-rc`. Any
# subsequent breakpoint / panic in the simulator will re-enter the
# debugger and stall again — that's fine here because the external
# `timeout` wraps the whole invocation and our serial-log assert
# already happened by then.
DEBUGGER_RC="${BUILD_DIR}/bochs-${SMOKE_PROFILE}.debugrc"
cat > "${DEBUGGER_RC}" <<EOF
c
EOF

echo "[bochs-run] profile=${SMOKE_PROFILE} cpu=${BOCHS_CPU} ips=${BOCHS_IPS}" >&2
echo "[bochs-run] iso=${SMOKE_ISO}" >&2
echo "[bochs-run] serial=${SERIAL_LOG}" >&2

# `-q` skips the interactive configuration menu (Bochs prompts by
# default on first run for "press enter to start"). `-f` selects
# the rc we just wrote. `-rc` feeds the debugger `c` to continue
# past its t=0 prompt. External `timeout` cuts the run regardless
# of whether the kernel halts at its sentinel — Bochs doesn't honour
# QEMU's isa-debug-exit, so reaching the [smoke] complete sentinel
# leaves the CPU spinning on HLT until we kill it.
exec timeout --foreground --preserve-status --signal=TERM "${TIMEOUT_SECS}" \
     bochs -q -f "${BOCHSRC}" -rc "${DEBUGGER_RC}" </dev/null >>"${BOCHS_LOG}" 2>&1
