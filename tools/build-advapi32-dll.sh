#!/usr/bin/env bash
# tools/build-advapi32-dll.sh — stage-2 slice 27.

set -euo pipefail

if [[ $# -ne 2 ]]; then
    echo "usage: $0 <repo_root> <out_header>" >&2
    exit 2
fi

REPO_ROOT="$1"
OUT_HEADER="$2"
SRC_DIR="${REPO_ROOT}/userland/libs/advapi32"
SRC_C="${SRC_DIR}/advapi32.c"
EMBED="${REPO_ROOT}/tools/embed-blob.py"

WORK_DIR="$(dirname "${OUT_HEADER}")/advapi32"
mkdir -p "${WORK_DIR}"
OBJ="${WORK_DIR}/advapi32.obj"
DLL="${WORK_DIR}/advapi32.dll"

CLANG="${CLANG:-clang}"
LLD_LINK="${LLD_LINK:-lld-link}"

"${CLANG}" \
    --target=x86_64-pc-windows-msvc \
    -c \
    -ffreestanding -nostdlib -fno-stack-protector -fno-builtin \
    -mno-red-zone -fno-asynchronous-unwind-tables \
    -O2 -Wall -Wextra \
    "${SRC_C}" -o "${OBJ}"

rm -f "${DLL}"
set +e
"${LLD_LINK}" \
    /dll /noentry /nodefaultlib /base:0x100A0000 \
    /export:RegOpenKeyExA /export:RegOpenKeyExW /export:RegOpenKeyA /export:RegOpenKeyW \
    /export:RegCloseKey /export:RegCreateKeyW /export:RegCreateKeyExW \
    /export:RegDeleteKeyW /export:RegDeleteValueW \
    /export:RegEnumKeyW /export:RegEnumKeyExW /export:RegEnumValueW \
    /export:RegQueryValueA /export:RegQueryValueW /export:RegQueryValueExA /export:RegQueryValueExW \
    /export:RegSetValueW /export:RegSetValueExW \
    /export:OpenProcessToken /export:AdjustTokenPrivileges \
    /export:LookupPrivilegeValueA /export:LookupPrivilegeValueW \
    /export:GetUserNameA /export:GetUserNameW \
    /export:SystemFunction036 \
    /out:"${DLL}" "${OBJ}" 2>&1 | grep -v "align specified without /driver"
LINK_RC=${PIPESTATUS[0]}
set -e
if [[ ${LINK_RC} -ne 0 ]]; then
    echo "build-advapi32-dll.sh: lld-link failed (rc=${LINK_RC})" >&2
    exit ${LINK_RC}
fi

python3 "${EMBED}" "${DLL}" "${OUT_HEADER}" kBinAdvapi32DllBytes --namespace "duetos::fs::generated"
echo "build-advapi32-dll.sh: wrote ${OUT_HEADER} (DLL $(stat -c%s "${DLL}") bytes)"
