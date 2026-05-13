#!/usr/bin/env bash
# tools/build/build-stub-32-dll.sh — generic i386 (PE32) DLL builder.
#
# Compiles userland/libs/<dll_name>_32/<dll_name>_32.c into a
# freestanding PE32 Windows DLL using clang --target=i686-pc-windows-msvc
# + lld-link /machine:x86. The output basename is "<dll_name>.dll"
# (NOT "<dll_name>_32.dll") so the PE Export Directory's Name field
# matches the i386 importer's descriptor.
#
# Usage:
#     build-stub-32-dll.sh <repo_root> <out_header> <dll_name> <base_va> <symbol_name>
#
# Example:
#     build-stub-32-dll.sh /home/.../DuetOS .../generated_user32_32_dll.h \
#                          user32 0x10060000 kBinUser32_32DllBytes

set -euo pipefail

if [[ $# -ne 5 ]]; then
    echo "usage: $0 <repo_root> <out_header> <dll_name> <base_va> <symbol_name>" >&2
    exit 2
fi

REPO_ROOT="$1"
OUT_HEADER="$2"
DLL_NAME="$3"
BASE_VA="$4"
SYMBOL_NAME="$5"

SRC_DIR="${REPO_ROOT}/userland/libs/${DLL_NAME}_32"
SRC_C="${SRC_DIR}/${DLL_NAME}_32.c"
DEF_FILE="${SRC_DIR}/${DLL_NAME}_32.def"
EMBED="${REPO_ROOT}/tools/build/embed-blob.py"

WORK_DIR="$(dirname "${OUT_HEADER}")/${DLL_NAME}_32"
mkdir -p "${WORK_DIR}"
OBJ="${WORK_DIR}/${DLL_NAME}_32.obj"
DLL="${WORK_DIR}/${DLL_NAME}.dll"

CLANG="${CLANG:-clang}"
LLD_LINK="${LLD_LINK:-lld-link}"

"${CLANG}" \
    --target=i686-pc-windows-msvc \
    -c \
    -ffreestanding -nostdlib -fno-stack-protector -fno-builtin \
    -mno-red-zone -fno-asynchronous-unwind-tables \
    -O2 -Wall -Wextra \
    "${SRC_C}" -o "${OBJ}"

rm -f "${DLL}"
set +e
"${LLD_LINK}" \
    /dll /noentry /nodefaultlib /machine:x86 \
    "/base:${BASE_VA}" \
    "/def:${DEF_FILE}" \
    /out:"${DLL}" "${OBJ}" 2>&1 | grep -v "align specified without /driver"
LINK_RC=${PIPESTATUS[0]}
set -e
if [[ ${LINK_RC} -ne 0 ]]; then
    echo "build-stub-32-dll.sh: lld-link failed for ${DLL_NAME} (rc=${LINK_RC})" >&2
    exit ${LINK_RC}
fi

if [[ ! -s "${DLL}" ]]; then
    echo "build-stub-32-dll.sh: lld-link produced no output" >&2
    exit 1
fi

python3 "${EMBED}" \
    "${DLL}" \
    "${OUT_HEADER}" \
    "${SYMBOL_NAME}" \
    --namespace "duetos::fs::generated"

echo "build-stub-32-dll.sh: wrote ${OUT_HEADER} (${DLL_NAME} $(stat -c%s "${DLL}") bytes)"
