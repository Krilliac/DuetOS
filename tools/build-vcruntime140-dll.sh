#!/usr/bin/env bash
# tools/build-vcruntime140-dll.sh
#
# Compiles userland/libs/vcruntime140/vcruntime140.c into a
# freestanding x86_64 Windows PE DLL and embeds the bytes as
# a C++ constexpr u8 array for inclusion in the kernel.
#
# Stage-2 slice 13: retires the memset / memcpy / memmove flat
# stubs in kernel/subsystems/win32/stubs.cpp. Every MSVC-built
# PE calls these routinely (struct copy / zero-init / CRT
# startup), so the via-DLL path fires heavily.
#
# Usage:
#     build-vcruntime140-dll.sh <repo_root> <out_header>
#
# Invoked from kernel/CMakeLists.txt via add_custom_command.

set -euo pipefail

if [[ $# -ne 2 ]]; then
    echo "usage: $0 <repo_root> <out_header>" >&2
    exit 2
fi

REPO_ROOT="$1"
OUT_HEADER="$2"
SRC_DIR="${REPO_ROOT}/userland/libs/vcruntime140"
SRC_C="${SRC_DIR}/vcruntime140.c"
EMBED="${REPO_ROOT}/tools/embed-blob.py"

WORK_DIR="$(dirname "${OUT_HEADER}")/vcruntime140"
mkdir -p "${WORK_DIR}"
OBJ="${WORK_DIR}/vcruntime140.obj"
DLL="${WORK_DIR}/vcruntime140.dll"

CLANG="${CLANG:-clang}"
LLD_LINK="${LLD_LINK:-lld-link}"

"${CLANG}" \
    --target=x86_64-pc-windows-msvc \
    -c \
    -ffreestanding \
    -nostdlib \
    -fno-stack-protector \
    -fno-builtin \
    -fno-builtin-memset \
    -fno-builtin-memcpy \
    -fno-builtin-memmove \
    -mno-red-zone \
    -fno-asynchronous-unwind-tables \
    -O2 \
    -Wall -Wextra \
    "${SRC_C}" \
    -o "${OBJ}"

rm -f "${DLL}"

# /base:0x10030000 — 1 MiB above kernel32.dll's 0x10020000.
# Preserves the "1 MiB per DLL" spacing used by customdll(1/2)
# and kernel32.
set +e
"${LLD_LINK}" \
    /dll \
    /noentry \
    /nodefaultlib \
    /base:0x10030000 \
    /export:memset \
    /export:memcpy \
    /export:memmove \
    /out:"${DLL}" \
    "${OBJ}" 2>&1 | grep -v "align specified without /driver"
LINK_RC=${PIPESTATUS[0]}
set -e
if [[ ${LINK_RC} -ne 0 ]]; then
    echo "build-vcruntime140-dll.sh: lld-link failed (rc=${LINK_RC})" >&2
    exit ${LINK_RC}
fi

if [[ ! -s "${DLL}" ]]; then
    echo "build-vcruntime140-dll.sh: lld-link produced no output" >&2
    exit 1
fi

python3 "${EMBED}" \
    "${DLL}" \
    "${OUT_HEADER}" \
    kBinVcruntime140DllBytes \
    --namespace "customos::fs::generated"

echo "build-vcruntime140-dll.sh: wrote ${OUT_HEADER} (DLL $(stat -c%s "${DLL}") bytes)"
