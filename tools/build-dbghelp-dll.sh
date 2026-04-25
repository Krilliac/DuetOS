#!/usr/bin/env bash
# tools/build-dbghelp-dll.sh
#
# Compiles userland/libs/dbghelp/dbghelp.c into a freestanding
# x86_64 Windows PE DLL. Retires the 11 dbghelp flat-stub rows.
#
# All entry points are no-ops (Init/Cleanup return TRUE; every
# Sym* / StackWalk / MiniDumpWriteDump returns 0 = "no info").

set -euo pipefail

if [[ $# -ne 2 ]]; then
    echo "usage: $0 <repo_root> <out_header>" >&2
    exit 2
fi

REPO_ROOT="$1"
OUT_HEADER="$2"
SRC_DIR="${REPO_ROOT}/userland/libs/dbghelp"
SRC_C="${SRC_DIR}/dbghelp.c"
EMBED="${REPO_ROOT}/tools/embed-blob.py"

WORK_DIR="$(dirname "${OUT_HEADER}")/dbghelp"
mkdir -p "${WORK_DIR}"
OBJ="${WORK_DIR}/dbghelp.obj"
DLL="${WORK_DIR}/dbghelp.dll"

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
    /base:0x10070000 \
    /export:SymInitialize \
    /export:SymInitializeW \
    /export:SymCleanup \
    /export:SymFromAddr \
    /export:SymFromAddrW \
    /export:SymGetLineFromAddr64 \
    /export:SymLoadModule64 \
    /export:StackWalk64 \
    /export:SymFunctionTableAccess64 \
    /export:SymGetModuleBase64 \
    /export:MiniDumpWriteDump \
    /out:"${DLL}" \
    "${OBJ}" 2>&1 | grep -v "align specified without /driver"
LINK_RC=${PIPESTATUS[0]}
set -e
if [[ ${LINK_RC} -ne 0 ]]; then
    echo "build-dbghelp-dll.sh: lld-link failed (rc=${LINK_RC})" >&2
    exit ${LINK_RC}
fi

python3 "${EMBED}" \
    "${DLL}" \
    "${OUT_HEADER}" \
    kBinDbghelpDllBytes \
    --namespace "duetos::fs::generated"

echo "build-dbghelp-dll.sh: wrote ${OUT_HEADER} (DLL $(stat -c%s "${DLL}") bytes)"
