#!/usr/bin/env bash
# tools/build/build-kernel32-32-dll.sh
#
# Compiles userland/libs/kernel32_32/kernel32_32.c into a
# freestanding i386 (PE32) Windows DLL — the 32-bit companion to
# our PE32+ kernel32.dll. PE32 processes spawned by the kernel
# preload this DLL into their (low-4GB) address space; their IAT
# entries to KERNEL32.dll resolve into here.
#
# Result has Machine=0x014C and OptHdrMagic=0x10B (PE32), which the
# kernel's loader (Layer 1 of 32-bit PE support) recognises.
#
# Usage:
#     build-kernel32-32-dll.sh <repo_root> <out_header>
#
# Invoked from kernel/CMakeLists.txt via add_custom_command.

set -euo pipefail

if [[ $# -ne 2 ]]; then
    echo "usage: $0 <repo_root> <out_header>" >&2
    exit 2
fi

REPO_ROOT="$1"
OUT_HEADER="$2"
SRC_DIR="${REPO_ROOT}/userland/libs/kernel32_32"
SRC_C="${SRC_DIR}/kernel32_32.c"
EMBED="${REPO_ROOT}/tools/build/embed-blob.py"

WORK_DIR="$(dirname "${OUT_HEADER}")/kernel32_32"
mkdir -p "${WORK_DIR}"
OBJ="${WORK_DIR}/kernel32_32.obj"
# Output filename is "kernel32.dll" (not kernel32_32.dll) because
# lld-link stamps the basename of /out: into the PE Export Directory's
# Name field. That's the string the PE32 importer's case-insensitive
# DllNameEqCI compares against "KERNEL32.dll" in the import-descriptor.
DLL="${WORK_DIR}/kernel32.dll"

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
# A .def file with `LIBRARY kernel32.dll` sets the PE export-table
# Name field — the string the PE32 importer's IAT walker compares
# against the import-descriptor DLL name ("KERNEL32.dll" in
# pe32_smoke's case). Without this the field would default to the
# file basename "kernel32_32.dll" and the case-insensitive
# DllNameEqCI match would never fire.
"${LLD_LINK}" \
    /dll /noentry /nodefaultlib /machine:x86 \
    /base:0x10020000 \
    /def:"${SRC_DIR}/kernel32_32.def" \
    /out:"${DLL}" "${OBJ}" 2>&1 | grep -v "align specified without /driver"
LINK_RC=${PIPESTATUS[0]}
set -e
if [[ ${LINK_RC} -ne 0 ]]; then
    echo "build-kernel32-32-dll.sh: lld-link failed (rc=${LINK_RC})" >&2
    exit ${LINK_RC}
fi

if [[ ! -s "${DLL}" ]]; then
    echo "build-kernel32-32-dll.sh: lld-link produced no output" >&2
    exit 1
fi

python3 "${EMBED}" \
    "${DLL}" \
    "${OUT_HEADER}" \
    kBinKernel32_32DllBytes \
    --namespace "duetos::fs::generated"

echo "build-kernel32-32-dll.sh: wrote ${OUT_HEADER} (DLL $(stat -c%s "${DLL}") bytes)"
