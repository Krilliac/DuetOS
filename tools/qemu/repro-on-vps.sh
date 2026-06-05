#!/usr/bin/env bash
#
# tools/qemu/repro-on-vps.sh — provision a fresh Linux box and hunt the
# boot-tail wild trap-frame on REAL hardware-virt (KVM, -cpu host).
#
# WHY:  The wild trap-frame bug is hardware-virt-specific (observed under
#       VirtualBox; the canary trace sits post-MWAIT in IdleMain). It does
#       NOT reproduce under QEMU/TCG — TCG emulates MWAIT, interrupt delivery,
#       the APIC timer, and the TSC in software, smoothing over exactly the
#       microarchitectural quirks that produce the wild frame. To reproduce it
#       you need guest instructions running on real VT-x: a bare-metal box, or
#       a VPS that exposes the vmx/svm flag (nested virt). This script turns
#       such a box into a one-command repro rig, with the trap-entry ring
#       (now carrying the full iretq frame: vec|err|rip|cs|rflags|cpu_rsp|ss)
#       as the capture.
#
# USAGE:
#   tools/qemu/repro-on-vps.sh setup        # install toolchain + qemu/kvm + debug tools
#   tools/qemu/repro-on-vps.sh build        # cmake configure + build x86_64-debug
#   tools/qemu/repro-on-vps.sh hunt [N]     # N KVM boots (default 30); stop on first capture
#   tools/qemu/repro-on-vps.sh all  [N]     # setup + build + hunt
#   tools/qemu/repro-on-vps.sh check        # just verify the box can do hardware-virt
#
# ENV (override defaults):
#   DUETOS_REPRO_SMP        single-CPU matches the bug shape           (default 1)
#   DUETOS_REPRO_TIMEOUT    per-boot wall-clock seconds                (default 90)
#   DUETOS_REPRO_PRESET     cmake preset to build/boot                 (default x86_64-debug)
#   DUETOS_REPRO_LOGDIR     where per-boot logs land                  (default /tmp/duetos-repro)
#
# QUICK ANALYSIS:
#   grep -l 'WILD trap-frame\|RUNAWAY' /tmp/duetos-repro/*.log   # which boots tripped
#   tools/test/boot-log-analyze.sh /tmp/duetos-repro/boot-NN.log # triage a capture
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${REPO_ROOT}"

PRESET="${DUETOS_REPRO_PRESET:-x86_64-debug}"
SMP="${DUETOS_REPRO_SMP:-1}"
TIMEOUT="${DUETOS_REPRO_TIMEOUT:-90}"
LOGDIR="${DUETOS_REPRO_LOGDIR:-/tmp/duetos-repro}"
ISO="build/${PRESET}/duetos.iso"

log() { printf '[repro] %s\n' "$*" >&2; }

# Hard gate: a box with no /dev/kvm or no vmx/svm in CPUID cannot reproduce a
# hardware-virt bug — it would silently fall back to TCG and "pass" forever.
# Fail LOUDLY so a mis-provisioned VPS (provider didn't expose nested virt) is
# caught at minute one, not after a green hunt that proves nothing.
check_hwvirt() {
    local flags
    flags="$(grep -oE 'vmx|svm' /proc/cpuinfo | sort -u | tr '\n' ' ')"
    if [[ ! -e /dev/kvm ]]; then
        log "FATAL: /dev/kvm is missing. This box cannot run KVM."
        log "       Your provider did not expose hardware virtualization."
        log "       A TCG fallback would NOT reproduce the bug — refusing to pretend."
        return 1
    fi
    if [[ -z "${flags}" ]]; then
        log "FATAL: no vmx/svm CPU flag visible to the guest — nested virt is off."
        log "       Pick a provider that exposes it (SSD Nodes upper tier, ExtraVM,"
        log "       OVH US dedicated, or real bare metal)."
        return 1
    fi
    log "hardware-virt OK: /dev/kvm present, CPU flags = ${flags}"
    return 0
}

setup() {
    log "installing build toolchain + QEMU/KVM + debug toolbox (apt)…"
    sudo apt-get update -qq
    # Build chain (clang/lld/cmake; the .S files are GAS-assembled, no nasm).
    sudo apt-get install -y clang lld llvm cmake ninja-build build-essential git
    # Live-boot runtime: QEMU + UEFI + ISO build chain.
    sudo apt-get install -y qemu-system-x86 qemu-kvm grub-common grub-pc-bin \
        grub-efi-amd64-bin xorriso mtools ovmf
    # Live-debug toolbox (the GDB stub is useless without a host gdb).
    sudo apt-get install -y gdb binutils strace lsof jq ripgrep
    # So a non-root user can open /dev/kvm without sudo on every boot.
    if ! id -nG "$USER" | tr ' ' '\n' | grep -qx kvm; then
        sudo usermod -aG kvm "$USER" || true
        log "added $USER to the 'kvm' group — log out/in (or 'newgrp kvm') to apply."
    fi
    check_hwvirt || log "WARNING: setup finished but hardware-virt is unavailable (see above)."
}

build() {
    log "configuring + building preset=${PRESET} (this is the instrumented kernel)…"
    cmake --preset "${PRESET}"
    cmake --build "build/${PRESET}" --parallel "$(nproc)"
    [[ -f "${ISO}" ]] || { log "FATAL: ${ISO} not produced — is the iso target enabled?"; return 1; }
    log "built ${ISO}"
}

hunt() {
    local runs="${1:-30}" i log_i
    check_hwvirt
    [[ -f "${ISO}" ]] || { log "no ${ISO} — run 'build' first."; return 1; }
    mkdir -p "${LOGDIR}"
    log "hunting: ${runs} single-CPU (-cpu host) KVM boots, MWAIT passthrough on."
    log "   per-boot timeout=${TIMEOUT}s  logs=${LOGDIR}"
    for ((i = 1; i <= runs; i++)); do
        log_i="${LOGDIR}/boot-$(printf '%02d' "$i").log"
        # -cpu host => guest sees the real CPU's MONITOR/MWAIT; cpu-pm=on makes
        # the guest's mwait actually idle the physical core (bare-metal/VBox-like
        # wake semantics) instead of KVM's default mwait-exit-as-nop. That is the
        # execution fidelity TCG can't give and the most likely trigger lever.
        DUETOS_ACCEL=kvm DUETOS_CPU=host DUETOS_SMP="${SMP}" DUETOS_TIMEOUT="${TIMEOUT}" \
            tools/qemu/run.sh "${ISO}" -overcommit cpu-pm=on >"${log_i}" 2>&1 || true
        if grep -qE 'WILD trap-frame|RUNAWAY trap recursion|wild trap-frame pointer' "${log_i}"; then
            log "*** CAPTURED on boot #${i} — ${log_i} ***"
            log "--- trap-entry ring (16 slots) ---"
            grep -A 20 -E 'trap-entry ring' "${log_i}" || true
            grep -nE 'WILD trap-frame|RUNAWAY|wild trap-frame pointer' "${log_i}" || true
            log "Send me ${log_i} (or the lines above) and I'll localize the root."
            return 0
        fi
        log "boot #${i}: clean (no wild frame)."
    done
    log "no reproduction in ${runs} boots. The bug is intermittent — re-run 'hunt' with a"
    log "higher N, or it may need the exact host CPU/hypervisor VirtualBox used."
    return 0
}

case "${1:-all}" in
    setup) setup ;;
    build) build ;;
    hunt)  hunt "${2:-30}" ;;
    check) check_hwvirt ;;
    all)   setup; build; hunt "${2:-30}" ;;
    *) log "usage: $0 {setup|build|hunt [N]|all [N]|check}"; exit 2 ;;
esac
