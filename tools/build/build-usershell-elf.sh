#!/usr/bin/env bash
# tools/build/build-usershell-elf.sh
#
# Compiles userland/libc/src/{crt0.S,syscall.c} + userland/shell/shell.c
# into a freestanding x86_64 ELF executable using host clang + lld,
# then embeds the resulting bytes into a C++ header via embed-blob.py.
#
# This is the host-side half of the userland-shell pipeline. The
# kernel ramfs hands the embedded bytes to core::SpawnElfFile; the
# kernel ELF loader maps PT_LOAD segments and jumps to e_entry.
#
# Usage:
#     build_usershell_elf.sh <repo_root> <out_header>
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
LIBC_INC="${REPO_ROOT}/userland/libc/include"
LIBC_SRC="${REPO_ROOT}/userland/libc/src"
SHELL_SRC="${REPO_ROOT}/userland/shell/shell.c"
EMBED="${REPO_ROOT}/tools/build/embed-blob.py"

WORK_DIR="$(dirname "${OUT_HEADER}")/usershell"
mkdir -p "${WORK_DIR}"

CLANG="${CLANG:-clang}"
LLD="${LLD:-ld.lld}"

# Common compile flags for every userland TU. Freestanding (no
# glibc, no CRT linkage), no PIC (kernel ELF loader v0 does not
# apply relocations), no red zone (matches kernel constraint),
# no stack canary (no canary check infrastructure in userland yet),
# no unwind tables (no SEH-shaped exception handling).
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
    -O2
    -Wall -Wextra
    -I"${LIBC_INC}"
)

"${CLANG}" "${CFLAGS[@]}" -c "${LIBC_SRC}/crt0.S"     -o "${WORK_DIR}/crt0.o"
"${CLANG}" "${CFLAGS[@]}" -c "${LIBC_SRC}/syscall.c"  -o "${WORK_DIR}/syscall.o"
"${CLANG}" "${CFLAGS[@]}" -c "${SHELL_SRC}"           -o "${WORK_DIR}/shell.o"

# Link. Static, no dynamic loader, no default libs. Entry is
# `_start` from crt0.S. `--build-id=none` keeps the ELF compact
# and reproducible. Image base 0x400000 matches the previous
# hand-coded stub so kernel-side debug code still recognises the
# entry-point neighbourhood.
#
# `-z noseparate-code` keeps code + read-only data in the same
# PT_LOAD segment instead of lld's default 3-segment layout (PHDR
# at 0x200000, code at 0x400000, rodata at 0x401XXX). The
# kernel's v0 ELF loader maps every PT_LOAD into user VA, so a
# layout that places PHDR at 0x200000 (well below the .text
# base) collides with a region the kernel-shipped userland
# wasn't designed to populate, taking the loader's
# AddressSpaceMapUserPage path through a code path that
# subsequently double-faults. Forcing a single PT_LOAD at
# 0x400000 keeps the layout congruent with the previous
# hand-coded usershell.elf and the existing windowed_hello /
# hello PE stubs.
#
# `--script` with the inline single-segment script would be
# more surgical; the linker flag does the job in one line.
"${LLD}" \
    -static \
    --no-dynamic-linker \
    -e _start \
    --build-id=none \
    -T "${REPO_ROOT}/userland/libc/usershell.lds" \
    -o "${WORK_DIR}/usershell.elf" \
    "${WORK_DIR}/crt0.o" \
    "${WORK_DIR}/syscall.o" \
    "${WORK_DIR}/shell.o"

if [[ ! -s "${WORK_DIR}/usershell.elf" ]]; then
    echo "build_usershell_elf.sh: lld produced no output" >&2
    exit 1
fi

# Emit the generated header the kernel consumes.
python3 "${EMBED}" \
    "${WORK_DIR}/usershell.elf" \
    "${OUT_HEADER}" \
    kBinUsershellElfBytesCompiled \
    --namespace "duetos::fs::generated"

echo "build_usershell_elf.sh: wrote ${OUT_HEADER} (ELF $(stat -c%s "${WORK_DIR}/usershell.elf") bytes)"
