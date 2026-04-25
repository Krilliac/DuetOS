#!/usr/bin/env bash
# tools/build-kernelbase-dll.sh
#
# Compiles userland/libs/kernelbase into a forwarder-only
# x86_64 Windows PE DLL. Every export in kernelbase.def is a
# cross-DLL forwarder to kernel32.dll; the kernel loader's
# forwarder chaser resolves them at IAT-patch time.

set -euo pipefail

if [[ $# -ne 2 ]]; then
    echo "usage: $0 <repo_root> <out_header>" >&2
    exit 2
fi

REPO_ROOT="$1"
OUT_HEADER="$2"
SRC_DIR="${REPO_ROOT}/userland/libs/kernelbase"
SRC_C="${SRC_DIR}/kernelbase.c"
DEF="${SRC_DIR}/kernelbase.def"
EMBED="${REPO_ROOT}/tools/embed-blob.py"

WORK_DIR="$(dirname "${OUT_HEADER}")/kernelbase"
mkdir -p "${WORK_DIR}"
OBJ="${WORK_DIR}/kernelbase.obj"
DLL="${WORK_DIR}/kernelbase.dll"

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

set +e
"${LLD_LINK}" \
    /dll \
    /noentry \
    /nodefaultlib \
    /base:0x10090000 \
    /def:"${DEF}" \
    /out:"${DLL}" \
    "${OBJ}" 2>&1 | grep -v "align specified without /driver"
LINK_RC=${PIPESTATUS[0]}
set -e
if [[ ${LINK_RC} -ne 0 ]]; then
    echo "build-kernelbase-dll.sh: lld-link failed (rc=${LINK_RC})" >&2
    exit ${LINK_RC}
fi

python3 "${EMBED}" \
    "${DLL}" \
    "${OUT_HEADER}" \
    kBinKernelbaseDllBytes \
    --namespace "duetos::fs::generated"

echo "build-kernelbase-dll.sh: wrote ${OUT_HEADER} (DLL $(stat -c%s "${DLL}") bytes)"
