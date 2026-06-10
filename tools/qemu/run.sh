#!/usr/bin/env bash
#
# Launch the freshly-built DuetOS kernel in QEMU.
#
# Default boot path:  ISO + GRUB + Multiboot2.
# Reasoning:          QEMU's `-kernel` flag speaks Multiboot 1, but our
#                     kernel header is Multiboot 2. Booting the ISO lets
#                     GRUB do the Multiboot2 handoff properly.
#
# Flags chosen for early-boot diagnosis:
#   -serial stdio          : pipe COM1 to this terminal
#   -no-reboot             : halt on triple fault instead of resetting
#   -no-shutdown           : leave QEMU alive so `info registers` works
#   -d int,cpu_reset       : trace interrupts + reset causes
#   -D qemu.log            : dump that trace to qemu.log
#   -display none          : headless (override by exporting DUETOS_DISPLAY=gtk)
#
# Extra argv is forwarded to QEMU, so `tools/qemu/run.sh -s -S` will start
# it waiting for gdb on :1234.
#
# Requires (on Ubuntu):
#   sudo apt-get install -y qemu-system-x86 grub-common grub-pc-bin grub-efi-amd64-bin xorriso mtools ovmf
#
# OVMF is required because UEFI is the default boot firmware
# (see UEFI_MODE below). Set DUETOS_LEGACY=1 to boot via
# SeaBIOS instead and skip the OVMF requirement.

set -euo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

PRESET="${DUETOS_PRESET:-x86_64-debug}"
BUILD_DIR="${REPO_ROOT}/build/${PRESET}"
# DUETOS_SMOKE_ISO swaps the canonical ISO out for a per-call
# sidecar (built by ctest-boot-smoke.sh with `pe-smokes=1` baked
# into the cmdline). Keeps the canonical grub.cfg untouched while
# letting one specific harness opt into the emulator-gated
# smokes. Mirrors the DUETOS_SMOKE_PROFILE pattern below.
ISO_IMAGE="${DUETOS_SMOKE_ISO:-${BUILD_DIR}/duetos.iso}"
KERNEL_ELF="${BUILD_DIR}/kernel/duetos-kernel.elf"
DISPLAY_MODE="${DUETOS_DISPLAY:-none}"
TIMEOUT_SECS="${DUETOS_TIMEOUT:-}"

# Back-compat with the documented invocation:
#   tools/qemu/run.sh build/x86_64-debug/duetos.iso
# Treat a leading .iso path as the boot image instead of forwarding it
# to QEMU as an extra writable disk, which collides with the same file
# when ISO_IMAGE already points there. Remaining argv stays available
# for raw QEMU flags such as -s -S.
if [[ $# -gt 0 && "${1}" == *.iso ]]; then
    ISO_IMAGE="$1"
    shift
fi
# Boot firmware: UEFI (OVMF) by default, SeaBIOS when
# DUETOS_LEGACY=1. UEFI is the primary target for commodity
# PC hardware post-2010; SeaBIOS stays available for
# legacy-BIOS regression tests and for hosts where OVMF isn't
# installed. The hybrid ISO carries both boot records
# (grub-mkrescue embeds El Torito entries for both), so the
# same image works with either firmware.
#
# Historical: this flag was introduced as opt-in (DUETOS_UEFI=1).
# Flipped to default 2026-04 once every self-test ran clean
# under OVMF — "boots on commodity PC hardware" is a project
# pillar, and SeaBIOS is not what modern machines ship.
LEGACY_MODE="${DUETOS_LEGACY:-0}"
if [[ -n "${DUETOS_UEFI:-}" ]]; then
    # Back-compat: honor an explicit DUETOS_UEFI setting. UEFI=0
    # means "force legacy"; UEFI=1 is redundant (it's already the
    # default) but harmless.
    if [[ "${DUETOS_UEFI}" == "0" ]]; then
        LEGACY_MODE=1
    fi
fi
UEFI_MODE=1
if [[ "${LEGACY_MODE}" == "1" ]]; then
    UEFI_MODE=0
fi

if ! command -v qemu-system-x86_64 >/dev/null 2>&1; then
    echo "error: qemu-system-x86_64 is not installed." >&2
    echo "       sudo apt-get install -y qemu-system-x86" >&2
    exit 1
fi

UEFI_ARGS=()
if [[ "${UEFI_MODE}" == "1" ]]; then
    OVMF_CODE="${DUETOS_OVMF_CODE:-/usr/share/OVMF/OVMF_CODE_4M.fd}"
    OVMF_VARS_TEMPLATE="${DUETOS_OVMF_VARS:-/usr/share/OVMF/OVMF_VARS_4M.fd}"
    if [[ ! -f "${OVMF_CODE}" || ! -f "${OVMF_VARS_TEMPLATE}" ]]; then
        echo "error: UEFI is the default boot firmware but OVMF isn't installed." >&2
        echo "       Option A (recommended): sudo apt-get install -y ovmf" >&2
        echo "       Option B (skip UEFI, use SeaBIOS): DUETOS_LEGACY=1 $0 ..." >&2
        echo "       expected: ${OVMF_CODE} and ${OVMF_VARS_TEMPLATE}" >&2
        exit 1
    fi
    # Per-run writable copy of OVMF NVRAM (BootOrder / boot entries).
    # Discarded on each invocation so a previous run can't sabotage
    # the next one with a Boot#### that points at a stale path.
    OVMF_VARS_COPY="${BUILD_DIR}/ovmf-vars.fd"
    cp "${OVMF_VARS_TEMPLATE}" "${OVMF_VARS_COPY}"
    UEFI_ARGS=(
        -drive "if=pflash,format=raw,readonly=on,file=${OVMF_CODE}"
        -drive "if=pflash,format=raw,file=${OVMF_VARS_COPY}"
    )
fi

if [[ -f "${ISO_IMAGE}" ]]; then
    BOOT_SOURCE=(-drive "file=${ISO_IMAGE},index=2,media=cdrom,readonly=on,format=raw" -boot d)
elif [[ -f "${KERNEL_ELF}" ]]; then
    echo "warning: ${ISO_IMAGE} not found, falling back to -kernel (Multiboot 1)." >&2
    echo "         This will NOT boot today — the kernel uses Multiboot 2." >&2
    echo "         Install grub-pc-bin + xorriso and rebuild so the ISO target runs." >&2
    BOOT_SOURCE=(-kernel "${KERNEL_ELF}")
else
    echo "error: neither ${ISO_IMAGE} nor ${KERNEL_ELF} exists." >&2
    echo "       build first:" >&2
    echo "         cmake --preset ${PRESET}" >&2
    echo "         cmake --build build/${PRESET}" >&2
    exit 1
fi

# qemu-smoke profile selector. When DUETOS_SMOKE_PROFILE is set, we
# rebuild a per-profile ISO with `smoke=<profile>` baked into the
# grub cmdline so the kernel routes into kernel/test/smoke_profile.cpp's
# scenario-only path on boot. Each profile runs ONE focused scenario
# (bringup-only / ring3 / pe-hello / pe-winapi / pe-winkill / linux),
# emits a `[smoke] profile=<name> complete` sentinel, and exits QEMU
# via the isa-debug-exit device added below. CI runs the profiles in
# parallel as a job matrix. Keeping the ISO sidecar means the
# always-on boot=desktop / boot=tty entries stay unchanged for the
# default `tools/qemu/run.sh` invocation (no profile -> full boot).
# `DUETOS_EXTRA_CMDLINE` sidecar — when set, builds an ISO sidecar
# that appends the given string to the multiboot2 cmdline. Lets a
# caller select a non-default theme / cap-audit level / etc. without
# touching the canonical grub.cfg. When DUETOS_SMOKE_PROFILE is ALSO
# set, the extra string is appended to the profile's cmdline instead
# (so e.g. `bringup` + `selftests=full` can run together for a manual
# on-target crypto self-test check). Default empty (no sidecar).
EXTRA_CMDLINE="${DUETOS_EXTRA_CMDLINE:-}"

SMOKE_PROFILE="${DUETOS_SMOKE_PROFILE:-}"
if [[ -z "${SMOKE_PROFILE}" && -n "${EXTRA_CMDLINE}" ]]; then
    if ! command -v grub-mkrescue >/dev/null 2>&1; then
        echo "error: DUETOS_EXTRA_CMDLINE requires grub-mkrescue" >&2
        exit 1
    fi
    EXTRA_TAG="$(printf '%s' "${EXTRA_CMDLINE}" | tr -c 'a-zA-Z0-9' '_' | cut -c1-32)"
    EXTRA_ISO_STAGE="${BUILD_DIR}/extra-iso-stage-${EXTRA_TAG}"
    EXTRA_ISO="${BUILD_DIR}/duetos-extra-${EXTRA_TAG}.iso"
    rm -rf "${EXTRA_ISO_STAGE}"
    mkdir -p "${EXTRA_ISO_STAGE}/boot/grub"
    cp "${KERNEL_ELF}" "${EXTRA_ISO_STAGE}/boot/duetos-kernel.elf"
    # Mirror the video-mode setup from the canonical boot/grub/grub.cfg
    # so the multiboot2 framebuffer-request tag is honoured — without
    # this GRUB skips the gfx mode set, no framebuffer tag reaches the
    # kernel, and the compositor self-tests SKIP because
    # FramebufferAvailable() is false.
    cat > "${EXTRA_ISO_STAGE}/boot/grub/grub.cfg" <<EOF
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
menuentry "DuetOS — extra cmdline" {
    multiboot2 /boot/duetos-kernel.elf boot=desktop autologin=1 ${EXTRA_CMDLINE}
    boot
}
EOF
    grub-mkrescue --compress=xz -o "${EXTRA_ISO}" "${EXTRA_ISO_STAGE}" >/dev/null 2>&1
    [[ -f "${EXTRA_ISO}" ]] || { echo "error: failed to build extra-cmdline ISO ${EXTRA_ISO}" >&2; exit 1; }
    ISO_IMAGE="${EXTRA_ISO}"
    BOOT_SOURCE=(-cdrom "${ISO_IMAGE}" -boot d)
    echo "[run.sh] extra cmdline ISO: ${ISO_IMAGE}"
    echo "[run.sh] extra cmdline    : ${EXTRA_CMDLINE}"
fi

if [[ -n "${SMOKE_PROFILE}" ]]; then
    if ! command -v grub-mkrescue >/dev/null 2>&1; then
        echo "error: DUETOS_SMOKE_PROFILE=${SMOKE_PROFILE} requires grub-mkrescue" >&2
        echo "       install via: sudo apt-get install -y grub-common grub-pc-bin xorriso mtools" >&2
        exit 1
    fi
    SMOKE_ISO_STAGE="${BUILD_DIR}/smoke-iso-stage-${SMOKE_PROFILE}"
    SMOKE_ISO="${BUILD_DIR}/duetos-smoke-${SMOKE_PROFILE}.iso"
    rm -rf "${SMOKE_ISO_STAGE}"
    mkdir -p "${SMOKE_ISO_STAGE}/boot/grub"
    cp "${KERNEL_ELF}" "${SMOKE_ISO_STAGE}/boot/duetos-kernel.elf"
    # Single-entry grub.cfg, timeout=0, default=0 — auto-boots straight
    # into the smoke kernel cmdline. boot=desktop is preserved so the
    # post-bringup composite path still runs (compositor init, etc.);
    # the kernel routes into the smoke profile after bringup-complete.
    # Optional watchdog-proof injection: DUETOS_BOOT_STALL=<phase>
    # bakes `boot-stall=<phase>` so kernel/diag/boot_observe.cpp wedges
    # that phase and the hang watchdog can be demonstrated to fire +
    # TestExit. Off by default; debug/CI proof only.
    BOOT_STALL_ARG=""
    if [[ -n "${DUETOS_BOOT_STALL:-}" ]]; then
        BOOT_STALL_ARG=" boot-stall=${DUETOS_BOOT_STALL}"
    fi
    # Append DUETOS_EXTRA_CMDLINE to the profile cmdline when both are
    # set — e.g. `selftests=full` so the bringup profile also runs the
    # opt-in heavy crypto self-tests for a manual on-target check.
    EXTRA_ARG=""
    if [[ -n "${EXTRA_CMDLINE}" ]]; then
        EXTRA_ARG=" ${EXTRA_CMDLINE}"
        echo "[run.sh] smoke profile extra cmdline: ${EXTRA_CMDLINE}" >&2
    fi
    cat > "${SMOKE_ISO_STAGE}/boot/grub/grub.cfg" <<EOF
set timeout=0
set default=0
menuentry "DuetOS — smoke ${SMOKE_PROFILE}" {
    multiboot2 /boot/duetos-kernel.elf boot=desktop smoke=${SMOKE_PROFILE} autologin=1${BOOT_STALL_ARG}${EXTRA_ARG}
    boot
}
EOF
    grub-mkrescue --compress=xz -o "${SMOKE_ISO}" "${SMOKE_ISO_STAGE}" >/dev/null 2>&1
    if [[ ! -f "${SMOKE_ISO}" ]]; then
        echo "error: failed to build smoke ISO ${SMOKE_ISO}" >&2
        exit 1
    fi
    BOOT_SOURCE=(-drive "file=${SMOKE_ISO},index=2,media=cdrom,readonly=on,format=raw" -boot d)
    echo "[run.sh] smoke profile=${SMOKE_PROFILE} iso=${SMOKE_ISO}" >&2
fi

# Scratch NVMe + SATA images. GPT-formatted raw files with one
# FAT32 data partition seeded by make-gpt-image.py. The FS self-
# tests mutate these images (fatwrite / fatappend / fatnew); an
# image from a previous run would fail the "fresh fixture"
# assertions (e.g. HELLO.TXT expected at 17 bytes, not 5017).
# Regenerate on every invocation — build is seconds, trades off
# nothing meaningful for determinism.
NVME_IMAGE="${BUILD_DIR}/nvme0.img"
SATA_IMAGE="${BUILD_DIR}/sata0.img"
python3 "${SCRIPT_DIR}/make-gpt-image.py" "${NVME_IMAGE}"
python3 "${SCRIPT_DIR}/make-gpt-image.py" "${SATA_IMAGE}"

# Raw scratch disk for virtio-blk (IRQ-driven completion +
# multi-in-flight self-test). Deliberately NOT GPT-formatted: the
# self-test only writes patterned sectors to a disk carrying no
# partition signature, so a zero-filled raw file is the fixture.
# Created once (no per-run regeneration needed — the self-test
# re-seeds its own patterns every boot and never depends on prior
# contents).
VBLK_IMAGE="${BUILD_DIR}/vblk0.img"
if [[ ! -f "${VBLK_IMAGE}" ]]; then
    truncate -s 16M "${VBLK_IMAGE}"
fi

# Use KVM when /dev/kvm is reachable (CI runners on bare metal,
# Linux dev hosts with the right capability bits), fall through to
# TCG otherwise. The `kvm:tcg` syntax tells QEMU "try kvm first,
# downgrade silently to tcg if it fails" so the same script works
# everywhere without an env-var dance. KVM speeds the qemu-smoke
# job ~50x — the boot/test path that takes ~60s under TCG completes
# in ~1.5s under KVM, well inside the CI wall-clock budget.
#
# DUETOS_ACCEL overrides the auto-pick. Differential-boot harnesses
# (tools/test/diff-boot-smoke.sh) pin to `tcg` so two passes on the
# same host both run the modeled instruction stream — KVM would
# defeat the comparison by handing both passes the same host
# silicon and erasing the cross-emulator signal.
ACCEL="tcg"
if [[ -r /dev/kvm && -w /dev/kvm ]]; then
    ACCEL="kvm:tcg"
fi
ACCEL="${DUETOS_ACCEL:-${ACCEL}}"
# Log the acceleration choice so a slow CI run is easy to diagnose
# from the workflow log alone — without this, "did the smoke job
# actually use KVM?" required re-checking permissions on /dev/kvm
# after the fact.
echo "[run.sh] qemu accel=${ACCEL}" >&2

# Per-run binary minidump file. The kernel's crash-dump path
# emits a Windows-format .dmp via `outb 0xE9, %al` (port 0xE9
# is QEMU's `-debugcon` channel); QEMU appends each byte to
# this file as it arrives. On a successful boot with no panic
# the file stays empty / zero bytes — no harm. On a panic it
# materialises a real .dmp that Visual Studio / WinDbg /
# VSCode-cppvsdbg open directly. Truncate per-run so a stale
# dump from a prior boot doesn't masquerade as the current one.
MINIDUMP_FILE="${BUILD_DIR}/duetos.dmp"
: > "${MINIDUMP_FILE}"
echo "[run.sh] minidump sink=${MINIDUMP_FILE}" >&2

# COM2 transport selector. Set DUETOS_GDB_TRANSPORT to:
#   tcp  (default) — TCP server on DUETOS_GDB_PORT (1234).
#   pty  — host pty whose name QEMU prints to stderr; GDB
#          attaches via `target remote /dev/pts/N`. This is the
#          software null-modem path — same UART code path the
#          kernel would drive on real hardware over USB-UART.
#   stdio — when the human log isn't on COM1 anyway. Rare;
#           supported for completeness.
# Probe whether DUETOS_GDB_PORT is bindable. If the caller pinned
# it explicitly, honour the pin and fail loudly if it's busy. If
# they took the default and 1234 is in use (typical: a leftover
# qemu from a previous run, or a concurrent ctest), pick a free
# ephemeral port instead. Without this, the ctest boot-smoke
# fails to even spawn qemu when the port is held — yielding a
# blizzard of MISSING signatures despite the kernel being fine.
duetos_gdb_port_is_pinned=0
if [[ -n "${DUETOS_GDB_PORT:-}" ]]; then
    duetos_gdb_port_is_pinned=1
fi
DUETOS_GDB_PORT="${DUETOS_GDB_PORT:-1234}"
if [[ "${DUETOS_GDB_TRANSPORT:-tcp}" == "tcp" ]] && command -v python3 > /dev/null 2>&1; then
    # Try to bind the requested port. If python3 can't grab it, the
    # port is in use (or otherwise unbindable). Pinned port: exit
    # with a clear message. Default port: silently fall back to a
    # python-picked ephemeral port. python3 is the lowest-common-
    # denominator probe — `ss` / `netstat` are missing on minimal
    # images.
    # `|| true` keeps a python non-zero exit (port unbindable) from
    # tripping `set -e`. The probe distinguishes the free / busy
    # cases by stdout content (`free`) not by exit code.
    duetos_gdb_probe_rc=$(python3 - "${DUETOS_GDB_PORT}" 2>/dev/null <<'PY' || true
import socket, sys
port = int(sys.argv[1])
s = socket.socket()
try:
    s.bind(("", port))
    print("free")
finally:
    s.close()
PY
)
    if [[ "${duetos_gdb_probe_rc}" != "free" ]]; then
        if [[ ${duetos_gdb_port_is_pinned} -eq 1 ]]; then
            echo "[run.sh] error: DUETOS_GDB_PORT=${DUETOS_GDB_PORT} is not bindable" >&2
            exit 2
        fi
        DUETOS_GDB_PORT="$(python3 -c 'import socket; s=socket.socket(); s.bind(("",0)); print(s.getsockname()[1]); s.close()')"
        echo "[run.sh] default GDB port busy — falling back to ${DUETOS_GDB_PORT}" >&2
    fi
fi

case "${DUETOS_GDB_TRANSPORT:-tcp}" in
    tcp)   DUETOS_GDB_TRANSPORT_QEMU="tcp::${DUETOS_GDB_PORT},server=on,wait=off" ;;
    pty)   DUETOS_GDB_TRANSPORT_QEMU="pty" ;;
    stdio) DUETOS_GDB_TRANSPORT_QEMU="stdio" ;;
    *)
        echo "[run.sh] error: unsupported DUETOS_GDB_TRANSPORT=${DUETOS_GDB_TRANSPORT}" >&2
        exit 2
        ;;
esac
echo "[run.sh] gdb transport=${DUETOS_GDB_TRANSPORT:-tcp} -> ${DUETOS_GDB_TRANSPORT_QEMU}" >&2

# DUETOS_CPU overrides `-cpu max` for differential matrices — pinning
# qemu64 / Haswell / Skylake-Client / etc. exercises different CPUID
# leaves, MSR sets, and feature gates than `max` does, and the
# diff-boot harness uses that to surface CPUID-dependent bugs that
# `max` would silently paper over.
CPU_MODEL="${DUETOS_CPU:-max}"

# Optional knobs for stress testing the live kernel:
#   DUETOS_RAM   — sets `-m` (default 512M). Useful for forcing the
#                  memory stress driver to hit the heap ceiling early.
#   DUETOS_SMP   — sets `-smp` (default
#                  `4,sockets=1,cores=2,threads=2`). Same 4 vCPUs
#                  as before (no extra host load) but now 2
#                  physical cores x 2 SMT threads, so every boot
#                  exercises the per-CPU runqueues + work-stealing
#                  + reschedule-IPI paths AND the SMT-aware
#                  placement path (`smt-placement-selftest`
#                  PASSes). The value is passed to `-smp` as one
#                  token, so overrides work verbatim:
#                    DUETOS_SMP=4  -> flat 4-socket non-SMT boot
#                                     (smt-placement-selftest SKIPs;
#                                     verifies the byte-for-byte
#                                     EffectiveLoad identity path)
#                    DUETOS_SMP=1  -> single-CPU regression boot
#                  All boot self-tests pass under SMP and the
#                  structural sentinels stay intact, so the SMT
#                  topology is safe as the default.
RAM_SIZE="${DUETOS_RAM:-512M}"

SMP_ARGS=(-smp "${DUETOS_SMP:-4,sockets=1,cores=2,threads=2}")

# QMP control socket. A host-side unix socket, fully orthogonal to
# COM1 (-serial stdio), COM2 (the GDB transport), and the
# isa-debug-exit device — so it never disturbs the serial log or a
# live GDB session. Lets tools/qemu/qmp.sh poll guest status, grab a
# framebuffer screendump, or quit the VM cleanly without SIGKILL.
# Disable with DUETOS_QMP=0.
QMP_ARGS=()
QMP_SOCK="${BUILD_DIR}/qmp.sock"
if [[ "${DUETOS_QMP:-1}" != "0" ]]; then
    rm -f "${QMP_SOCK}"
    QMP_ARGS=(-qmp "unix:${QMP_SOCK},server=on,wait=off")
fi

# COM1 backend. Default `stdio` (the human log on this terminal). When
# DUETOS_SERIAL_FILE is set, COM1 goes to QEMU's *file* chardev instead,
# which write()s each chunk straight to the fd with NO stdio buffering —
# so the trailing output survives even a host-side QEMU `abort()` (e.g.
# the TCG BQL assertion) that would otherwise drop the block-buffered
# stdio→pipe tail. Essential for capturing a panic/forensic dump that
# fires just before such an abort. (Quote-stripped so the `file:` prefix
# reaches QEMU intact.)
if [[ -n "${DUETOS_SERIAL_FILE:-}" ]]; then
    COM1_ARGS=(-serial "file:${DUETOS_SERIAL_FILE}")
    echo "[run.sh] COM1 → unbuffered file: ${DUETOS_SERIAL_FILE}"
else
    COM1_ARGS=(-serial stdio)
fi

# Optional Intel VT-d IOMMU emulation. The kernel's VT-d driver no-ops
# without a DMAR table, so by default QEMU exposes none and the IOMMU
# stays inert. DUETOS_IOMMU_DEVICE=1 adds `-device intel-iommu` (DMA
# remapping only, intremap=off) plus the split irqchip QEMU requires for
# it; the kernel then programs VT-d identity translation at boot. Used to
# verify DMA-remapping enforcement under QEMU.
MACHINE_OPTS="q35,accel=${ACCEL}"
IOMMU_DEVICE_ARGS=()
if [[ "${DUETOS_IOMMU_DEVICE:-0}" != "0" ]]; then
    MACHINE_OPTS="${MACHINE_OPTS},kernel-irqchip=split"
    IOMMU_DEVICE_ARGS=(-device "intel-iommu,intremap=off")
    echo "[run.sh] Intel VT-d IOMMU device enabled (intremap=off)" >&2
fi

QEMU_ARGS=(
    -machine  "${MACHINE_OPTS}"
    "${IOMMU_DEVICE_ARGS[@]}"
    -cpu      "${CPU_MODEL}"
    "${SMP_ARGS[@]}"
    -m        "${RAM_SIZE}"
    "${QMP_ARGS[@]}"
    -display  "${DISPLAY_MODE}"
    "${COM1_ARGS[@]}"
    # COM2 → GDB transport. Default is a TCP server on
    # ${DUETOS_GDB_PORT} (1234) — the canonical attach path under
    # QEMU. Set DUETOS_GDB_TRANSPORT=pty to instead create a
    # host-side pty (path printed in QEMU's stderr line `char
    # device redirected to /dev/pts/N`); GDB then attaches via
    # `target remote /dev/pts/N`. The pty mode is the software
    # equivalent of a null-modem cable + USB-UART on real hardware
    # — the kernel-side stub drives the same 16550 register set,
    # so this exercises the exact same code path that an iron
    # attach would. `wait=off` so QEMU doesn't block waiting for a
    # GDB connection at boot — the kernel's GDB stub stays silent
    # until the debugger actually attaches. Separate from QEMU's
    # `-gdb` flag (which is QEMU's hypervisor-side debugger).
    -serial   "${DUETOS_GDB_TRANSPORT_QEMU}"
    -no-reboot
    -no-shutdown
    -d        int,cpu_reset
    -D        qemu.log
    -debugcon "file:${MINIDUMP_FILE}"
    # isa-debug-exit: a tiny device that lets the guest exit QEMU
    # cleanly. Writing an OUT byte B to port 0xf4 terminates QEMU
    # with exit status (B<<1)|1. arch::TestExit (kernel/arch/x86_64/
    # cpu.h) writes 0x10 → exit 0x21 = "smoke sentinel reached".
    # Always present (no-op for full boots that never call
    # TestExit); harmless on bare metal where port 0xf4 is unused.
    -device   "isa-debug-exit,iobase=0xf4,iosize=0x01"
    -drive    "file=${NVME_IMAGE},if=none,id=nvme0,format=raw"
    -device   "nvme,serial=cafebabe,drive=nvme0"
    # Separate AHCI controller with one SATA disk. The q35 machine
    # has a built-in AHCI at 0:1f.2 carrying the CD-ROM; adding a
    # dedicated "ahci,id=ahci1" plus an ide-hd on bus ahci1.0
    # gives us a clean test path with only a hard-disk device
    # (no ATAPI), which matches the v1 driver scope.
    -device   "ahci,id=ahci1"
    -drive    "file=${SATA_IMAGE},if=none,id=sata0,format=raw"
    -device   "ide-hd,bus=ahci1.0,drive=sata0"
    # xHCI host controller. q35 doesn't ship with one by default,
    # so explicitly attach so the USB stack has something to bring
    # up. We also park one usb-kbd on the bus so the port-scan
    # path has a real connected device to enumerate (Enable Slot,
    # eventually Address Device + descriptor fetch).
    -device   "qemu-xhci,id=xhci"
    -device   "usb-kbd,bus=xhci.0"
    -device   "usb-mouse,bus=xhci.0"
    # Intel e1000e (82574L) NIC on a user-mode netdev. QEMU's
    # SLIRP stack gives us one-way connectivity to the outside +
    # a loopback path that returns broadcast frames for self-test.
    # Specify mac= so the driver's EEPROM-read path sees a stable
    # value across reboots. `-device e1000e` advertises the MSI-X
    # capability so the driver's IRQ-wake path gets exercised;
    # `-device e1000` would fall back to polling.
    -netdev   "user,id=net0"
    -device   "e1000e,netdev=net0,mac=52:54:00:12:34:56"
    # virtio transport coverage. Without at least one virtio-pci
    # device QEMU never instantiates the virtio bus, so the whole
    # virtio driver tree (transport + rng/blk/net/balloon/console/
    # input probes) probes nothing and rots untested. virtio-rng
    # needs no backing file and exercises the single-queue
    # negotiate -> queue-setup -> DRIVER_OK -> entropy-pull path;
    # virtio-balloon (also file-less) exercises the dual-queue
    # DRIVER_OK path. Neither collides with the nvme/ahci/e1000e
    # devices above.
    # disable-legacy=on forces the modern (virtio-1.0,
    # non-transitional) PCI presentation; our transport is
    # modern-only (requires VIRTIO_F_VERSION_1) and skips
    # transitional device IDs (0x1000-0x103f).
    -device   "virtio-rng-pci,disable-legacy=on"
    -device   "virtio-balloon-pci,disable-legacy=on"
    # virtio-blk on the raw scratch image above. Exercises the
    # driver's MSI-X IRQ-completion + multi-in-flight request path
    # (the boot self-test spawns concurrent readers/writers against
    # vblk0). disable-legacy=on is mandatory — VirtioInit skips
    # transitional device IDs (0x1000-0x103f).
    -drive    "file=${VBLK_IMAGE},if=none,id=vblk0,format=raw"
    -device   "virtio-blk-pci,drive=vblk0,disable-legacy=on"
    # Intel HDA controller + output codec so the audio backend's
    # BDL/stream/DMA byte path is exercised every smoke. audiodev
    # `none` = no host audio sink (silent, headless-safe) while the
    # device model + stream DMA + LPIB counter still run.
    -audiodev "none,id=duetsnd"
    -device   "intel-hda"
    -device   "hda-output,audiodev=duetsnd"
    "${UEFI_ARGS[@]}"
    "${BOOT_SOURCE[@]}"
)

if [[ -n "${TIMEOUT_SECS}" ]]; then
    exec timeout --foreground --preserve-status --signal=TERM "${TIMEOUT_SECS}" \
         qemu-system-x86_64 "${QEMU_ARGS[@]}" "$@"
else
    exec qemu-system-x86_64 "${QEMU_ARGS[@]}" "$@"
fi
