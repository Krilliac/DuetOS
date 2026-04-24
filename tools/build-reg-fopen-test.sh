#!/usr/bin/env bash
# tools/build-reg-fopen-test.sh
#
# Build the stage-2 slice 34 end-to-end test PE. Imports from
# advapi32 (real registry) + ucrtbase (real fopen) + kernel32
# (ExitProcess). Verifies HKLM\Software\Microsoft\Windows NT\
# CurrentVersion\ProductName == "DuetOS" and /bin/hello.exe
# first two bytes == "MZ".

set -euo pipefail

if [[ $# -ne 2 ]]; then
    echo "usage: $0 <repo_root> <out_header>" >&2
    exit 2
fi

REPO_ROOT="$1"
OUT_HEADER="$2"
SRC_DIR="${REPO_ROOT}/userland/apps/reg_fopen_test"
SRC_C="${SRC_DIR}/hello.c"
EMBED="${REPO_ROOT}/tools/embed-blob.py"

WORK_DIR="$(dirname "${OUT_HEADER}")/reg_fopen_test"
mkdir -p "${WORK_DIR}"
OBJ="${WORK_DIR}/hello.obj"
EXE="${WORK_DIR}/reg_fopen_test.exe"

CLANG="${CLANG:-clang}"
LLD_LINK="${LLD_LINK:-lld-link}"
DLLTOOL="${DLLTOOL:-llvm-dlltool}"

# One .lib per .def file.
GEN_LIBS=()
for def in "${SRC_DIR}"/*.def; do
    base=$(basename "${def}" .def)
    lib="${WORK_DIR}/${base}.lib"
    "${DLLTOOL}" -d "${def}" -l "${lib}" -m i386:x86-64
    GEN_LIBS+=("${lib}")
done

"${CLANG}" \
    --target=x86_64-pc-windows-msvc \
    -c \
    -ffreestanding -nostdlib -fno-stack-protector -fno-builtin \
    -mno-red-zone -mno-sse -mno-sse2 -mno-mmx -mgeneral-regs-only \
    -fno-asynchronous-unwind-tables \
    -O2 -Wall -Wextra \
    "${SRC_C}" -o "${OBJ}"

rm -f "${EXE}"
set +e
"${LLD_LINK}" \
    /subsystem:console /entry:_start /nodefaultlib \
    /base:0x140000000 \
    /out:"${EXE}" \
    "${OBJ}" "${GEN_LIBS[@]}" 2>&1 | grep -v "align specified without /driver"
LINK_RC=${PIPESTATUS[0]}
set -e
if [[ ${LINK_RC} -ne 0 ]]; then
    echo "build-reg-fopen-test.sh: lld-link failed (rc=${LINK_RC})" >&2
    exit ${LINK_RC}
fi

python3 "${EMBED}" "${EXE}" "${OUT_HEADER}" kBinRegFopenTestBytes --namespace "duetos::fs::generated"
echo "build-reg-fopen-test.sh: wrote ${OUT_HEADER} (PE $(stat -c%s "${EXE}") bytes)"
