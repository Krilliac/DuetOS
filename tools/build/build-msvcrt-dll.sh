#!/usr/bin/env bash
# tools/build/build-msvcrt-dll.sh
#
# Compiles userland/libs/msvcrt/msvcrt.c into a freestanding
# x86_64 Windows PE DLL. Retires the prior string-intrinsic
# stubs from kernel/subsystems/win32/stubs.cpp.
#
# Usage:
#     build-msvcrt-dll.sh <repo_root> <out_header>

set -euo pipefail

if [[ $# -ne 2 ]]; then
    echo "usage: $0 <repo_root> <out_header>" >&2
    exit 2
fi

REPO_ROOT="$1"
OUT_HEADER="$2"
SRC_DIR="${REPO_ROOT}/userland/libs/msvcrt"
SRC_C="${SRC_DIR}/msvcrt.c"
EMBED="${REPO_ROOT}/tools/build/embed-blob.py"

WORK_DIR="$(dirname "${OUT_HEADER}")/msvcrt"
mkdir -p "${WORK_DIR}"
OBJ="${WORK_DIR}/msvcrt.obj"
DLL="${WORK_DIR}/msvcrt.dll"

CLANG="${CLANG:-clang}"
LLD_LINK="${LLD_LINK:-lld-link}"

"${CLANG}" \
    --target=x86_64-pc-windows-msvc \
    -c \
    -ffreestanding \
    -nostdlib \
    -fno-stack-protector \
    -fno-builtin \
    -fno-builtin-strlen \
    -fno-builtin-strcmp \
    -fno-builtin-strcpy \
    -fno-builtin-strchr \
    -fno-builtin-wcslen \
    -fno-builtin-wcscmp \
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
    /base:0x10040000 \
    /export:strlen \
    /export:strcmp \
    /export:strcpy \
    /export:strchr \
    /export:wcslen \
    /export:wcscmp \
    /export:wcscpy \
    /export:wcschr \
    /out:"${DLL}" \
    "${OBJ}" 2>&1 | grep -v "align specified without /driver"
LINK_RC=${PIPESTATUS[0]}
set -e
if [[ ${LINK_RC} -ne 0 ]]; then
    echo "build-msvcrt-dll.sh: lld-link failed (rc=${LINK_RC})" >&2
    exit ${LINK_RC}
fi

if [[ ! -s "${DLL}" ]]; then
    echo "build-msvcrt-dll.sh: lld-link produced no output" >&2
    exit 1
fi

python3 "${EMBED}" \
    "${DLL}" \
    "${OUT_HEADER}" \
    kBinMsvcrtDllBytes \
    --namespace "duetos::fs::generated"

echo "build-msvcrt-dll.sh: wrote ${OUT_HEADER} (DLL $(stat -c%s "${DLL}") bytes)"
