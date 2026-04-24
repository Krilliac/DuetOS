#!/usr/bin/env bash
# tools/build-customdll2.sh
#
# Compiles userland/libs/customdll2/customdll2.c into a
# freestanding x86_64 Windows PE DLL and embeds the bytes as
# a C++ constexpr u8 array for inclusion in the kernel.
# Stage-2 slice 9 uses this alongside customdll.dll to exercise
# the multi-DLL preload path in SpawnPeFile.
#
# Usage:
#     build-customdll2.sh <repo_root> <out_header>
#
# Invoked from kernel/CMakeLists.txt via add_custom_command.

set -euo pipefail

if [[ $# -ne 2 ]]; then
    echo "usage: $0 <repo_root> <out_header>" >&2
    exit 2
fi

REPO_ROOT="$1"
OUT_HEADER="$2"
SRC_DIR="${REPO_ROOT}/userland/libs/customdll2"
SRC_C="${SRC_DIR}/customdll2.c"
EMBED="${REPO_ROOT}/tools/embed-blob.py"

WORK_DIR="$(dirname "${OUT_HEADER}")/customdll2"
mkdir -p "${WORK_DIR}"
OBJ="${WORK_DIR}/customdll2.obj"
DLL="${WORK_DIR}/customdll2.dll"

CLANG="${CLANG:-clang}"
LLD_LINK="${LLD_LINK:-lld-link}"

"${CLANG}" \
    --target=x86_64-pc-windows-msvc \
    -c \
    -ffreestanding \
    -nostdlib \
    -fno-stack-protector \
    -fno-builtin \
    -mno-red-zone \
    -fno-asynchronous-unwind-tables \
    -O2 \
    -Wall -Wextra \
    "${SRC_C}" \
    -o "${OBJ}"

rm -f "${DLL}"

# /base:0x10010000 — 1 MiB above customdll.dll's 0x10000000.
# Plenty of headroom for customdll's 3 pages; no collision.
set +e
"${LLD_LINK}" \
    /dll \
    /noentry \
    /nodefaultlib \
    /base:0x10010000 \
    /export:CustomDouble \
    /out:"${DLL}" \
    "${OBJ}" 2>&1 | grep -v "align specified without /driver"
LINK_RC=${PIPESTATUS[0]}
set -e
if [[ ${LINK_RC} -ne 0 ]]; then
    echo "build-customdll2.sh: lld-link failed (rc=${LINK_RC})" >&2
    exit ${LINK_RC}
fi

if [[ ! -s "${DLL}" ]]; then
    echo "build-customdll2.sh: lld-link produced no output" >&2
    exit 1
fi

python3 "${EMBED}" \
    "${DLL}" \
    "${OUT_HEADER}" \
    kBinCustomDll2Bytes \
    --namespace "customos::fs::generated"

echo "build-customdll2.sh: wrote ${OUT_HEADER} (DLL $(stat -c%s "${DLL}") bytes)"
