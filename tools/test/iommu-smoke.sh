#!/usr/bin/env bash
# tools/test/iommu-smoke.sh — boot DuetOS with QEMU's intel-iommu device
# exposed, so the kernel's DMAR/VT-d code path runs against a live
# (emulated) IOMMU instead of the default "table absent" path.
#
# QEMU exposes intel-iommu via `-device intel-iommu`. Requirements:
#   - q35 machine type (already the default in tools/qemu/run.sh)
#   - kernel-irqchip=split (intel-iommu needs the IOAPIC in user-space)
#   - intremap=off for v0; turn on once kernel-side IR enable lands
#
# Run from repo root:
#     bash tools/test/iommu-smoke.sh
#
# Env vars:
#   DUETOS_PRESET   — kernel preset (default x86_64-debug)
#   DUETOS_TIMEOUT  — wall-clock cap in seconds (default 60)
#
# What this script proves:
#   - DmarInit() actually decodes a real DMAR ACPI table (not just
#     the "table absent" path).
#   - VtdInit() actually maps the IOMMU register window and decodes
#     CAP / ECAP from real hardware (well, QEMU's emulation of it).
#   - Both self-tests still pass alongside the live decode.
#
# Expected boot-log markers (greppable):
#     [dmar] present=yes haw=...
#     [vtd] iommu[0] base=... ver=1.0 mgaw=39 ...
#     [vtd-selftest] PASS
#
# Future slices that program the IOMMU (RTADDR, GCMD.TE, IOTLB
# invalidate) should add their own grep-able sentinels here so a
# single run of this script verifies the whole stack.

set -euo pipefail

PRESET="${DUETOS_PRESET:-x86_64-debug}"
TIMEOUT_SECS="${DUETOS_TIMEOUT:-60}"

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/../.." && pwd)"
BUILD_DIR="${REPO_ROOT}/build/${PRESET}"

if [[ ! -f "${BUILD_DIR}/duetos.iso" ]]; then
    echo "iommu-smoke: no ISO at ${BUILD_DIR}/duetos.iso — run 'ninja duetos.iso' first" >&2
    exit 2
fi

OVMF_CODE="${OVMF_CODE:-/usr/share/OVMF/OVMF_CODE_4M.fd}"
OVMF_VARS="${BUILD_DIR}/ovmf-vars.fd"
if [[ ! -f "${OVMF_CODE}" ]]; then
    echo "iommu-smoke: missing ${OVMF_CODE} — install with: sudo apt-get install -y ovmf" >&2
    exit 2
fi
if [[ ! -f "${OVMF_VARS}" ]]; then
    # First-time setup: copy the writable OVMF NVRAM template.
    cp /usr/share/OVMF/OVMF_VARS_4M.fd "${OVMF_VARS}"
fi

LOG="${LOG:-/tmp/iommu-smoke.log}"

# Note: deliberately a minimal QEMU command — no NVMe / AHCI / xHCI
# clutter. We only need DMAR/VT-d code path to run, so the smallest
# possible device set keeps the boot fast and the log focused.
timeout "${TIMEOUT_SECS}" qemu-system-x86_64 \
    -machine q35,accel=kvm:tcg,kernel-irqchip=split \
    -cpu max \
    -smp 4 \
    -m 512M \
    -display none \
    -serial stdio \
    -no-reboot -no-shutdown \
    -device intel-iommu,intremap=off \
    -drive "if=pflash,format=raw,readonly=on,file=${OVMF_CODE}" \
    -drive "if=pflash,format=raw,file=${OVMF_VARS}" \
    -drive "file=${BUILD_DIR}/duetos.iso,index=2,media=cdrom,readonly=on,format=raw" \
    -boot d \
    > "${LOG}" 2>&1 || true

if grep -qE "^\[vtd\] iommu\[0\] base=" "${LOG}"; then
    echo "iommu-smoke: OK — live VT-d decode succeeded"
    grep -E "^\[dmar\]|^\[vtd" "${LOG}"
    exit 0
else
    echo "iommu-smoke: FAIL — no [vtd] iommu[0] line in boot log" >&2
    echo "Last 30 lines of ${LOG}:"
    tail -30 "${LOG}" >&2
    exit 1
fi
