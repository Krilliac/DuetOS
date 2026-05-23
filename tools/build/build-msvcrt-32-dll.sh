#!/usr/bin/env bash
# tools/build/build-msvcrt-32-dll.sh
#
# Compiles userland/libs/msvcrt_32/msvcrt_32.c into a freestanding
# i386 (PE32) Windows DLL — the 32-bit companion to our PE32+
# msvcrt.dll. Provides the string / memory / CRT-startup intrinsics
# every MSVC-built PE32 calls during boot.
#
# Output basename is "msvcrt.dll" so the PE Export Directory's Name
# field matches the i386 importer's descriptor.
#
# Usage:
#     build-msvcrt-32-dll.sh <repo_root> <out_header>

set -euo pipefail

if [[ $# -ne 2 ]]; then
    echo "usage: $0 <repo_root> <out_header>" >&2
    exit 2
fi

REPO_ROOT="$1"
OUT_HEADER="$2"
SRC_DIR="${REPO_ROOT}/userland/libs/msvcrt_32"
SRC_C="${SRC_DIR}/msvcrt_32.c"
SRC_S="${SRC_DIR}/chkstk.S"
EMBED="${REPO_ROOT}/tools/build/embed-blob.py"

WORK_DIR="$(dirname "${OUT_HEADER}")/msvcrt_32"
mkdir -p "${WORK_DIR}"
OBJ_C="${WORK_DIR}/msvcrt_32.obj"
OBJ_S="${WORK_DIR}/chkstk.obj"
DLL="${WORK_DIR}/msvcrt.dll"

CLANG="${CLANG:-clang}"
LLD_LINK="${LLD_LINK:-lld-link}"

"${CLANG}" \
    --target=i686-pc-windows-msvc \
    -c \
    -ffreestanding -nostdlib -fno-stack-protector -fno-builtin \
    -mno-red-zone -fno-asynchronous-unwind-tables \
    -O2 -Wall -Wextra \
    "${SRC_C}" -o "${OBJ_C}"

# Assemble the i386 chkstk family (real page-probing helper)
# alongside the C source. clang's integrated assembler handles
# the .S extension; the C-only flags above are accepted-and-
# ignored for assembly input but we omit them here anyway for
# clarity.
"${CLANG}" \
    --target=i686-pc-windows-msvc \
    -c -ffreestanding -nostdlib \
    "${SRC_S}" -o "${OBJ_S}"

rm -f "${DLL}"
set +e
"${LLD_LINK}" \
    /dll /noentry /nodefaultlib /machine:x86 \
    /base:0x10040000 \
    /def:"${SRC_DIR}/msvcrt_32.def" \
    /out:"${DLL}" "${OBJ_C}" "${OBJ_S}" 2>&1 | grep -v "align specified without /driver"
LINK_RC=${PIPESTATUS[0]}
set -e
if [[ ${LINK_RC} -ne 0 ]]; then
    echo "build-msvcrt-32-dll.sh: lld-link failed (rc=${LINK_RC})" >&2
    exit ${LINK_RC}
fi

if [[ ! -s "${DLL}" ]]; then
    echo "build-msvcrt-32-dll.sh: lld-link produced no output" >&2
    exit 1
fi

python3 "${EMBED}" \
    "${DLL}" \
    "${OUT_HEADER}" \
    kBinMsvcrt_32DllBytes \
    --namespace "duetos::fs::generated"

echo "build-msvcrt-32-dll.sh: wrote ${OUT_HEADER} (DLL $(stat -c%s "${DLL}") bytes)"
