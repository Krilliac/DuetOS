#!/usr/bin/env bash
# tools/build/build-synet.sh
#
# Sister of build-synxtest.sh — compiles
# userland/apps/synet/synet.c into a freestanding x86_64
# Linux-ABI ELF (no libc, no crt — synet.c defines its own
# _start and inline syscall asm). Embeds the resulting bytes
# into a C++ header via embed-blob.py.
#
# The kernel ramfs hands the embedded bytes to
# core::SpawnElfLinux (see kernel/subsystems/linux/ring3_smoke.cpp
# SpawnSynetElf). Synet runs with kCapNet so the socket-family
# syscalls it issues (socket/bind/listen/accept/connect/sendto/
# recvfrom/...) actually reach the kernel handlers instead of
# bouncing off the dispatch-level kCapNet cap gate.
#
# Usage:
#     build-synet.sh <repo_root> <out_header>
#
# Invoked from CMake via add_custom_command — see
# kernel/CMakeLists.txt.

set -euo pipefail

if [[ $# -ne 2 ]]; then
    echo "usage: $0 <repo_root> <out_header>" >&2
    exit 2
fi

REPO_ROOT="$1"
OUT_HEADER="$2"
SRC_C="${REPO_ROOT}/userland/apps/synet/synet.c"
EMBED="${REPO_ROOT}/tools/build/embed-blob.py"

WORK_DIR="$(dirname "${OUT_HEADER}")/synet"
mkdir -p "${WORK_DIR}"

CLANG="${CLANG:-clang}"
LLD="${LLD:-ld.lld}"

# Same flag set as build-synxtest.sh:
# - freestanding, no libc, no PIC, no red zone, no canary.
# - -mno-sse / -mno-mmx / -mgeneral-regs-only required because
#   the kernel doesn't enable CR4.OSFXSR per user thread; clang
#   otherwise emits movaps for stack zero-init and the first
#   such insn #GP's. See linux-app-coverage-pattern-v0.md.
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
    -mno-sse
    -mno-sse2
    -mno-mmx
    -mgeneral-regs-only
    -Os
    -Wall -Wextra
)

"${CLANG}" "${CFLAGS[@]}" -c "${SRC_C}" -o "${WORK_DIR}/synet.o"

"${LLD}" \
    -static \
    --no-dynamic-linker \
    -e _start \
    --build-id=none \
    -Ttext=0x400000 \
    -o "${WORK_DIR}/synet.elf" \
    "${WORK_DIR}/synet.o"

if [[ ! -s "${WORK_DIR}/synet.elf" ]]; then
    echo "build-synet.sh: lld produced no output" >&2
    exit 1
fi

python3 "${EMBED}" \
    "${WORK_DIR}/synet.elf" \
    "${OUT_HEADER}" \
    kBinSynetElfBytes \
    --namespace "duetos::fs::generated"

echo "build-synet.sh: wrote ${OUT_HEADER} (ELF $(stat -c%s "${WORK_DIR}/synet.elf") bytes)"
