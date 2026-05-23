#!/usr/bin/env bash
# tools/build/build-linux-vdso.sh
#
# Assembles kernel/subsystems/linux/vdso/vdso.S, links it with
# the per-blob linker script, strips down to the raw .vdso.text
# bytes, and embeds the result as a constexpr u8 array for the
# kernel to map into every Linux ELF process.
#
# Output: a C++ header containing kBinLinuxVdsoBytes (the raw
# page contents) plus kOffLinuxVdso* constants for each export.
# Today the only export is __kernel_rt_sigreturn at offset 0; the
# slot reservation in vdso.S leaves room for __vdso_clock_gettime
# etc. without reflowing.
#
# Usage:
#     build-linux-vdso.sh <repo_root> <out_header>

set -euo pipefail

if [[ $# -ne 2 ]]; then
    echo "usage: $0 <repo_root> <out_header>" >&2
    exit 2
fi

REPO_ROOT="$1"
OUT_HEADER="$2"
SRC="${REPO_ROOT}/kernel/subsystems/linux/vdso/vdso.S"
LDS="${REPO_ROOT}/kernel/subsystems/linux/vdso/vdso.lds"
EMBED="${REPO_ROOT}/tools/build/embed-blob.py"

WORK_DIR="$(dirname "${OUT_HEADER}")/linux-vdso"
mkdir -p "${WORK_DIR}"
OBJ="${WORK_DIR}/vdso.o"
ELF="${WORK_DIR}/vdso.elf"
BIN="${WORK_DIR}/vdso.bin"

CLANG="${CLANG:-clang}"
LD="${LD:-ld.lld}"
OBJCOPY="${OBJCOPY:-llvm-objcopy}"

# Assemble for the Linux x86_64 ABI (System V) — this code runs
# in Linux-ELF user processes, NOT in the Windows PE userland.
"${CLANG}" --target=x86_64-linux-gnu -ffreestanding -nostdinc \
    -c "${SRC}" -o "${OBJ}"

# Link with our minimal script: places .vdso.text at offset 0,
# drops the .note / .comment noise. -e suppresses the missing-
# _start warning — no startup needed on a code blob.
"${LD}" -nostdlib -e __kernel_rt_sigreturn -T "${LDS}" -o "${ELF}" "${OBJ}"

# Strip to raw bytes — what the kernel will paint into the user
# process's vDSO page verbatim.
"${OBJCOPY}" -O binary --only-section=.vdso.text "${ELF}" "${BIN}"

# Sanity: the blob must be non-empty and fit in one 4 KiB page.
SIZE="$(stat -c%s "${BIN}")"
if [[ "${SIZE}" -eq 0 ]]; then
    echo "build-linux-vdso.sh: produced 0-byte blob — linker dropped .vdso.text" >&2
    exit 1
fi
if [[ "${SIZE}" -gt 4096 ]]; then
    echo "build-linux-vdso.sh: blob ${SIZE} bytes exceeds one page (4096)" >&2
    exit 1
fi

python3 "${EMBED}" \
    "${BIN}" \
    "${OUT_HEADER}" \
    kBinLinuxVdsoBytes \
    --namespace "duetos::subsystems::linux::vdso::generated"

echo "build-linux-vdso.sh: wrote ${OUT_HEADER} (blob ${SIZE} bytes)"
