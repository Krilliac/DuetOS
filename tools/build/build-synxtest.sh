#!/usr/bin/env bash
# tools/build/build-synxtest.sh
#
# Compiles userland/apps/synxtest/synxtest.c into a freestanding
# x86_64 Linux-ABI ELF (no libc, no crt — synxtest defines its own
# _start and inline syscall asm). Embeds the resulting bytes into a
# C++ header via embed-blob.py.
#
# The kernel ramfs hands the embedded bytes to
# core::SpawnElfLinux (see kernel/subsystems/linux/ring3_smoke.cpp
# SpawnSynxTestElf), the kernel ELF loader maps PT_LOAD segments,
# and the task issues `syscall` instructions that are routed via
# MSR_LSTAR through LinuxSyscallDispatch.
#
# Usage:
#     build-synxtest.sh <repo_root> <out_header>
#
# Arguments are absolute paths. Invoked from CMake via
# add_custom_command — see kernel/CMakeLists.txt.

set -euo pipefail

if [[ $# -ne 2 ]]; then
    echo "usage: $0 <repo_root> <out_header>" >&2
    exit 2
fi

REPO_ROOT="$1"
OUT_HEADER="$2"
SRC_C="${REPO_ROOT}/userland/apps/synxtest/synxtest.c"
EMBED="${REPO_ROOT}/tools/build/embed-blob.py"

WORK_DIR="$(dirname "${OUT_HEADER}")/synxtest"
mkdir -p "${WORK_DIR}"

CLANG="${CLANG:-clang}"
LLD="${LLD:-ld.lld}"

# Same flags as build-usershell-elf.sh: freestanding, no libc,
# no PIC (kernel ELF loader v0 doesn't apply relocations), no
# red zone, no canary, no unwind tables. -Os because the synxtest
# header is checked into git history; we want the diff small when
# the source changes.
CFLAGS=(
    --target=x86_64-unknown-none-elf
    -ffreestanding
    -nostdlib
    -fno-pic
    -fno-pie
    -mno-red-zone
    -fno-stack-protector
    -fno-builtin
    -fno-asynchronous-unwind-tables
    -fno-omit-frame-pointer
    -Os
    -Wall -Wextra
)

"${CLANG}" "${CFLAGS[@]}" -c "${SRC_C}" -o "${WORK_DIR}/synxtest.o"

# Static, no dynamic loader, no default libs. Entry is `_start`
# (defined by synxtest.c). Image base 0x400000 matches the
# previous hand-built header.
"${LLD}" \
    -static \
    --no-dynamic-linker \
    -e _start \
    --build-id=none \
    -Ttext=0x400000 \
    -o "${WORK_DIR}/synxtest.elf" \
    "${WORK_DIR}/synxtest.o"

if [[ ! -s "${WORK_DIR}/synxtest.elf" ]]; then
    echo "build-synxtest.sh: lld produced no output" >&2
    exit 1
fi

python3 "${EMBED}" \
    "${WORK_DIR}/synxtest.elf" \
    "${OUT_HEADER}" \
    kBinSynxtestElfBytes \
    --namespace "duetos::fs::generated"

echo "build-synxtest.sh: wrote ${OUT_HEADER} (ELF $(stat -c%s "${WORK_DIR}/synxtest.elf") bytes)"
