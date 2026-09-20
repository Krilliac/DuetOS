# Removable-Media Boot Image Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Produce a deterministic UEFI removable-media image as a regular file, boot it through GRUB in QEMU/OVMF, and never inspect or write a physical disk.

**Architecture:** A host-side shell builder creates a bounded GPT image with one FAT32 ESP, generates a removable-path GRUB `BOOTX64.EFI` with an embedded configuration, and copies the DuetOS kernel into the ESP. A contract test verifies safety refusals and image layout; a QEMU smoke test proves the artifact reaches the kernel's existing `bringup-complete` sentinel through the supported GRUB + Multiboot2 path. The experimental direct UEFI loader remains separate and is not promoted by this work.

**Tech Stack:** Bash, GNU GRUB tooling, parted, mtools, QEMU/OVMF, existing DuetOS kernel/ISO build.

**Spec:** `wiki/reference/Daily-Driver-Readiness.md`

## Global Constraints

- The user explicitly cancelled repartitioning; no command may enumerate for mutation, resize, format, mount, or write a physical disk.
- The builder accepts only a regular-file output path and rejects `/dev/*`, `\\.\PhysicalDrive*`, `PhysicalDrive*`, and an existing block device.
- No elevation is required or requested; all image construction operates on an ordinary file.
- The boot contract remains GRUB + Multiboot2. `boot/uefi/BOOTX64.EFI` is Phase B.1 only and must not be described as a kernel boot path.
- Default artifact size is 128 MiB, with a 1 MiB-aligned GPT ESP and deterministic labels/configuration.
- Every code change is test-first, DCO-signed, and committed on `codex/install-persistence`.

## Review Focus

- A device-like output argument must fail before any file is opened or command is run.
- An existing output must fail closed unless `--force` is supplied; `--force` still must not permit a device path.
- Missing `grub-mkstandalone`, `parted`, `mformat`, `mcopy`, kernel ELF, or OVMF must produce an actionable prerequisite failure.
- Paths containing spaces must remain one argument through every tool invocation.
- QEMU reaching shutdown without `bringup-complete` must fail the smoke test rather than count as a successful boot.

---

### Task 1: Pin the builder safety contract

**Files:**
- Create: `tools/test/removable-media-image-contract.sh`
- Create: `tools/image/build-removable-media.sh`

**Interfaces:**
- Consumes: `--kernel <duetos-kernel.elf> --output <regular-file.img> [--size-mib 128] [--force]`.
- Produces: exit `0` plus a GPT/FAT32 image, exit `2` for usage/prerequisite failures, exit `1` for construction/validation failures.

- [ ] **Step 1: Write the failing safety test**

```bash
#!/usr/bin/env bash
set -euo pipefail
repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
builder="${repo}/tools/image/build-removable-media.sh"
tmp="$(mktemp -d -t duetos-removable-contract.XXXXXX)"
trap 'rm -rf "${tmp}"' EXIT
printf '\x7fELF' >"${tmp}/kernel.elf"

if "${builder}" --kernel "${tmp}/kernel.elf" --output /dev/sda 2>"${tmp}/err"; then
    echo "FAIL: device-like output accepted" >&2
    exit 1
fi
grep -q "refusing device-like output" "${tmp}/err"

touch "${tmp}/existing.img"
if "${builder}" --kernel "${tmp}/kernel.elf" --output "${tmp}/existing.img" 2>"${tmp}/err"; then
    echo "FAIL: existing output accepted without --force" >&2
    exit 1
fi
grep -q "output already exists" "${tmp}/err"
```

- [ ] **Step 2: Run the contract test and verify RED**

Run: `bash tools/test/removable-media-image-contract.sh`

Expected: failure because `tools/image/build-removable-media.sh` does not exist.

- [ ] **Step 3: Implement argument parsing and fail-closed output validation**

The builder must parse the four documented options, canonicalize only the parent directory, and perform this gate before `truncate`, `parted`, or mtools:

```bash
case "${OUTPUT}" in
    /dev/*|\\\\.\\PhysicalDrive*|*PhysicalDrive*)
        echo "error: refusing device-like output: ${OUTPUT}" >&2
        exit 2
        ;;
esac
if [[ -b "${OUTPUT}" ]]; then
    echo "error: refusing block-device output: ${OUTPUT}" >&2
    exit 2
fi
if [[ -e "${OUTPUT}" && "${FORCE}" != 1 ]]; then
    echo "error: output already exists (use --force for a regular file): ${OUTPUT}" >&2
    exit 2
fi
```

- [ ] **Step 4: Run the contract test and verify GREEN**

Run: `bash tools/test/removable-media-image-contract.sh`

Expected: `PASS: removable-media image safety contract`.

- [ ] **Step 5: Commit**

```bash
git add tools/test/removable-media-image-contract.sh tools/image/build-removable-media.sh
git commit -s -m "feat(tooling): add safe removable image contract"
```

### Task 2: Build and validate the regular-file image

**Files:**
- Modify: `tools/image/build-removable-media.sh`
- Modify: `tools/test/removable-media-image-contract.sh`

**Interfaces:**
- Consumes: the validated options from Task 1 and host tools `grub-mkstandalone`, `parted`, `mformat`, `mmd`, `mcopy`.
- Produces: one GPT image whose first partition is a FAT32 ESP containing `/EFI/BOOT/BOOTX64.EFI` and `/boot/duetos-kernel.elf`.

- [ ] **Step 1: Extend the test with a real temporary-image assertion**

```bash
"${builder}" --kernel "${real_kernel}" --output "${tmp}/Duet OS test.img" --size-mib 128
parted -s "${tmp}/Duet OS test.img" print | grep -Eq 'fat32.*boot, esp|fat32.*esp'
mdir -i "${tmp}/Duet OS test.img@@1048576" ::/EFI/BOOT | grep -q BOOTX64
mdir -i "${tmp}/Duet OS test.img@@1048576" ::/boot | grep -q DUETOS-KERNEL
```

- [ ] **Step 2: Verify RED**

Run: `DUETOS_KERNEL_ELF=build/x86_64-debug/kernel/duetos-kernel.elf bash tools/test/removable-media-image-contract.sh`

Expected: layout/file assertion failure because construction is not implemented.

- [ ] **Step 3: Implement deterministic image construction**

Use a temporary directory for the embedded GRUB configuration and EFI binary. The exact construction sequence is:

```bash
truncate -s "$((SIZE_MIB * 1024 * 1024))" "${OUTPUT}"
parted -s "${OUTPUT}" mklabel gpt
parted -s "${OUTPUT}" mkpart ESP fat32 1MiB "$((SIZE_MIB - 1))MiB"
parted -s "${OUTPUT}" set 1 esp on
mformat -F -i "${OUTPUT}@@1048576" -v DUETOS ::
mmd -i "${OUTPUT}@@1048576" ::/EFI ::/EFI/BOOT ::/boot
grub-mkstandalone -O x86_64-efi -o "${tmp}/BOOTX64.EFI" "boot/grub/grub.cfg=${tmp}/grub.cfg"
mcopy -i "${OUTPUT}@@1048576" "${tmp}/BOOTX64.EFI" ::/EFI/BOOT/BOOTX64.EFI
mcopy -i "${OUTPUT}@@1048576" "${KERNEL}" ::/boot/duetos-kernel.elf
```

The embedded `grub.cfg` must contain one menu entry with:

```text
set timeout=0
set default=0
menuentry "DuetOS removable-media smoke" {
    multiboot2 /boot/duetos-kernel.elf boot=desktop autologin=1 smoke=bringup
    boot
}
```

- [ ] **Step 4: Verify GREEN and deterministic metadata**

Run the Task 2 test twice to different output files, compare `parted -sm ... print` plus recursively listed FAT paths, and require identical results. Byte-for-byte image identity is not required because GRUB EFI metadata may carry toolchain-dependent bytes.

- [ ] **Step 5: Commit**

```bash
git add tools/image/build-removable-media.sh tools/test/removable-media-image-contract.sh
git commit -s -m "feat(tooling): build UEFI removable media image"
```

### Task 3: Prove the artifact boots under OVMF

**Files:**
- Create: `tools/test/removable-media-boot-smoke.sh`
- Modify: `tests/host/CMakeLists.txt`

**Interfaces:**
- Consumes: the image builder and an existing x86_64 debug kernel build.
- Produces: a bounded QEMU log with `metrics bringup-complete`, or a non-zero result with the last serial lines.

- [ ] **Step 1: Write the failing smoke test**

The test must create its image in `mktemp -d`, locate OVMF using the same candidate order as `tools/test/uefi-smoke.sh`, boot with `timeout --foreground 180 qemu-system-x86_64 -bios ... -drive format=raw,file=... -display none -serial file:... -no-reboot`, and require:

```bash
grep -q 'metrics bringup-complete' "${serial_log}"
! grep -Eq 'PANIC|triple fault|KASSERT failed' "${serial_log}"
```

- [ ] **Step 2: Verify RED**

Run: `DUETOS_PRESET=x86_64-debug bash tools/test/removable-media-boot-smoke.sh`

Expected: failure because the smoke script does not yet exist.

- [ ] **Step 3: Implement the bounded OVMF launch and diagnostics**

Reuse `tools/test/boot-log-analyze.sh` after QEMU terminates. Treat timeout exit `124` as acceptable only when the completion marker exists; all other missing-marker exits fail.

- [ ] **Step 4: Verify GREEN**

Run: `DUETOS_PRESET=x86_64-debug bash tools/test/removable-media-boot-smoke.sh`

Expected: image layout PASS, QEMU boot analyzer verdict OK, and zero non-deliberate failures.

- [ ] **Step 5: Commit**

```bash
git add tools/test/removable-media-boot-smoke.sh tests/host/CMakeLists.txt
git commit -s -m "test(boot): verify removable image under OVMF"
```

### Task 4: Document the safe bare-metal boundary

**Files:**
- Create: `wiki/tooling/Removable-Media-Boot.md`
- Modify: `wiki/_Sidebar.md`
- Modify: `wiki/reference/Daily-Driver-Readiness.md`

**Interfaces:**
- Consumes: the verified builder and smoke commands.
- Produces: operator guidance that stops at regular-file artifact creation and QEMU verification.

- [ ] **Step 1: Document prerequisites, build, inspection, and QEMU commands**

State prominently that the tool never writes a device and that transferring the image to USB is intentionally out of scope until a future request names and verifies an exact removable target.

- [ ] **Step 2: Record the readiness delta honestly**

Mark “removable UEFI artifact boots in OVMF” as verified while leaving real-hardware, installer, direct-UEFI handoff, and persistent DuetFS-root gates open.

- [ ] **Step 3: Verify documentation**

Run:

```bash
tools/check-wiki-nav.sh
tools/check-wiki-quality.sh
git diff --check
```

- [ ] **Step 4: Commit**

```bash
git add wiki/tooling/Removable-Media-Boot.md wiki/_Sidebar.md wiki/reference/Daily-Driver-Readiness.md
git commit -s -m "docs(boot): define removable-media safety boundary"
```

### Task 5: Full branch gate and publication

**Files:**
- Verify all files changed by Tasks 1-4.

**Interfaces:**
- Consumes: the frozen branch candidate.
- Produces: a pushed `codex/install-persistence` branch and pull request only after every local gate passes.

- [ ] **Step 1: Run the full verification set**

```bash
cmake --build build/x86_64-debug --parallel 8
ctest --test-dir build/host-tests --output-on-failure -j 8
bash tools/test/removable-media-image-contract.sh
DUETOS_PRESET=x86_64-debug bash tools/test/removable-media-boot-smoke.sh
tools/check-wiki-nav.sh
tools/check-wiki-quality.sh
git diff --check
```

- [ ] **Step 2: Review the branch diff and safety mutation**

Temporarily replace the device-path rejection with `true`, confirm the contract test fails to protect `/dev/sda`, then restore the guard and rerun green.

- [ ] **Step 3: Push and open the PR**

```bash
git push --set-upstream origin codex/install-persistence
gh pr create --base main --head codex/install-persistence --title "Add safe UEFI removable-media boot image" --body "Builds a regular-file-only GPT/FAT32 removable image, rejects physical-device targets, and proves the supported GRUB + Multiboot2 path under QEMU/OVMF. Physical media writing remains out of scope."
```
