#!/usr/bin/env bash
# tools/build-stub-dll.sh — generic freestanding Windows PE DLL
# builder. Reads a config file that lists base VA + export names,
# compiles the matching .c source, lld-link's the output.
#
# Usage:
#   build-stub-dll.sh <repo_root> <out_header> <dll_name> <base_va> <export_list>
#
# <dll_name>      short name (e.g. "shlwapi") matching the
#                 directory under userland/libs/ and the .c file
#                 basename.
# <base_va>       DLL load base (hex with 0x prefix).
# <export_list>   comma-separated list of function names to
#                 /export:.

set -euo pipefail

if [[ $# -ne 5 ]]; then
    echo "usage: $0 <repo_root> <out_header> <dll_name> <base_va> <export_list>" >&2
    exit 2
fi

REPO_ROOT="$1"
OUT_HEADER="$2"
DLL_NAME="$3"
BASE_VA="$4"
EXPORTS="$5"

SRC_DIR="${REPO_ROOT}/userland/libs/${DLL_NAME}"
SRC_C="${SRC_DIR}/${DLL_NAME}.c"
EMBED="${REPO_ROOT}/tools/embed-blob.py"
SYMBOL_NAME="kBin${DLL_NAME^}DllBytes" # e.g. kBinShlwapiDllBytes

# Bash ${foo^} capitalises the first letter. If the DLL name has
# a digit or all-lowercase quirk we want PascalCase approximation.
# Re-derive by hand for the handful of single-word DLL names we
# ship; keep it simple:
case "${DLL_NAME}" in
    shlwapi)   SYMBOL_NAME=kBinShlwapiDllBytes ;;
    shell32)   SYMBOL_NAME=kBinShell32DllBytes ;;
    ole32)     SYMBOL_NAME=kBinOle32DllBytes ;;
    oleaut32)  SYMBOL_NAME=kBinOleaut32DllBytes ;;
    winmm)     SYMBOL_NAME=kBinWinmmDllBytes ;;
    bcrypt)    SYMBOL_NAME=kBinBcryptDllBytes ;;
    psapi)     SYMBOL_NAME=kBinPsapiDllBytes ;;
    *)         ;; # leave whatever ${DLL_NAME^} produced
esac

WORK_DIR="$(dirname "${OUT_HEADER}")/${DLL_NAME}"
mkdir -p "${WORK_DIR}"
OBJ="${WORK_DIR}/${DLL_NAME}.obj"
DLL="${WORK_DIR}/${DLL_NAME}.dll"

CLANG="${CLANG:-clang}"
LLD_LINK="${LLD_LINK:-lld-link}"

"${CLANG}" \
    --target=x86_64-pc-windows-msvc \
    -c \
    -ffreestanding -nostdlib -fno-stack-protector -fno-builtin \
    -mno-red-zone -fno-asynchronous-unwind-tables \
    -O2 -Wall -Wextra \
    "${SRC_C}" -o "${OBJ}"

# Build /export: args from comma-separated list.
EXPORT_ARGS=()
IFS=',' read -ra NAMES <<< "${EXPORTS}"
for n in "${NAMES[@]}"; do
    EXPORT_ARGS+=("/export:${n}")
done

rm -f "${DLL}"
set +e
"${LLD_LINK}" \
    /dll /noentry /nodefaultlib "/base:${BASE_VA}" \
    "${EXPORT_ARGS[@]}" \
    /out:"${DLL}" "${OBJ}" 2>&1 | grep -v "align specified without /driver"
LINK_RC=${PIPESTATUS[0]}
set -e
if [[ ${LINK_RC} -ne 0 ]]; then
    echo "build-stub-dll.sh: lld-link failed for ${DLL_NAME} (rc=${LINK_RC})" >&2
    exit ${LINK_RC}
fi

python3 "${EMBED}" "${DLL}" "${OUT_HEADER}" "${SYMBOL_NAME}" --namespace "customos::fs::generated"
echo "build-stub-dll.sh: wrote ${OUT_HEADER} (${DLL_NAME} $(stat -c%s "${DLL}") bytes)"
