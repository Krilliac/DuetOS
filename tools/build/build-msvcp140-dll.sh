#!/usr/bin/env bash
# tools/build/build-msvcp140-dll.sh
#
# Compiles userland/libs/msvcp140/msvcp140.c + the matching
# .def file into a freestanding x86_64 Windows PE DLL.
# Retires the 17 MSVCP140 flat stubs (C++ std:: throw helpers
# + ostream helpers).
#
# Exports all use mangled C++ names that bash can't pass on
# the command line; they come from msvcp140.def via /def:
# instead of /export:.

set -euo pipefail

if [[ $# -ne 2 ]]; then
    echo "usage: $0 <repo_root> <out_header>" >&2
    exit 2
fi

REPO_ROOT="$1"
OUT_HEADER="$2"
SRC_DIR="${REPO_ROOT}/userland/libs/msvcp140"
SRC_C="${SRC_DIR}/msvcp140.c"
DEF="${SRC_DIR}/msvcp140.def"
EMBED="${REPO_ROOT}/tools/build/embed-blob.py"

WORK_DIR="$(dirname "${OUT_HEADER}")/msvcp140"
mkdir -p "${WORK_DIR}"
OBJ="${WORK_DIR}/msvcp140.obj"
DLL="${WORK_DIR}/msvcp140.dll"

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
    /base:0x10080000 \
    /def:"${DEF}" \
    /out:"${DLL}" \
    "${OBJ}" 2>&1 | grep -v "align specified without /driver"
LINK_RC=${PIPESTATUS[0]}
set -e
if [[ ${LINK_RC} -ne 0 ]]; then
    echo "build-msvcp140-dll.sh: lld-link failed (rc=${LINK_RC})" >&2
    exit ${LINK_RC}
fi

python3 "${EMBED}" \
    "${DLL}" \
    "${OUT_HEADER}" \
    kBinMsvcp140DllBytes \
    --namespace "duetos::fs::generated"

echo "build-msvcp140-dll.sh: wrote ${OUT_HEADER} (DLL $(stat -c%s "${DLL}") bytes)"
