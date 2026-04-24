#!/usr/bin/env bash
# tools/build-windowed-hello.sh
#
# Compiles userland/apps/windowed_hello/hello.c into a real
# x86_64 Windows PE/COFF .exe that imports CreateWindowExA,
# ShowWindow, MessageBoxA from user32.dll and Sleep,
# ExitProcess from kernel32.dll. Same pipeline as the
# hello_winapi fixture, with a different set of .def files.
#
# Usage: build-windowed-hello.sh <repo_root> <out_header>
#
# Invoked from kernel/CMakeLists.txt via add_custom_command.

set -euo pipefail

if [[ $# -ne 2 ]]; then
    echo "usage: $0 <repo_root> <out_header>" >&2
    exit 2
fi

REPO_ROOT="$1"
OUT_HEADER="$2"
SRC_DIR="${REPO_ROOT}/userland/apps/windowed_hello"
SRC_C="${SRC_DIR}/hello.c"
EMBED="${REPO_ROOT}/tools/embed-blob.py"

WORK_DIR="$(dirname "${OUT_HEADER}")/windowed_hello"
mkdir -p "${WORK_DIR}"
OBJ="${WORK_DIR}/hello.obj"
EXE="${WORK_DIR}/windowed_hello.exe"

CLANG="${CLANG:-clang}"
LLD_LINK="${LLD_LINK:-lld-link}"
DLLTOOL="${DLLTOOL:-llvm-dlltool}"

# Generate one import library per .def file. Both user32.def
# (CreateWindowExA, ShowWindow, MessageBoxA) and kernel32.def
# (Sleep, ExitProcess) live in the fixture's directory.
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
    -ffreestanding \
    -nostdlib \
    -fno-stack-protector \
    -fno-builtin \
    -mno-red-zone \
    -mno-sse \
    -mno-sse2 \
    -mno-mmx \
    -mgeneral-regs-only \
    -fno-asynchronous-unwind-tables \
    -O2 \
    -Wall -Wextra \
    "${SRC_C}" \
    -o "${OBJ}"

rm -f "${EXE}"

set +e
"${LLD_LINK}" \
    /subsystem:windows \
    /entry:mainCRTStartup \
    /nodefaultlib \
    /base:0x140000000 \
    /out:"${EXE}" \
    "${OBJ}" \
    "${GEN_LIBS[@]}" 2>&1 | grep -v "align specified without /driver"
LINK_RC=${PIPESTATUS[0]}
set -e
if [[ ${LINK_RC} -ne 0 ]]; then
    echo "build-windowed-hello.sh: lld-link failed (rc=${LINK_RC})" >&2
    exit ${LINK_RC}
fi

if [[ ! -s "${EXE}" ]]; then
    echo "build-windowed-hello.sh: lld-link produced no output" >&2
    exit 1
fi

python3 "${EMBED}" \
    "${EXE}" \
    "${OUT_HEADER}" \
    kBinWindowedHelloBytes \
    --namespace "duetos::fs::generated"

echo "build-windowed-hello.sh: wrote ${OUT_HEADER} (PE $(stat -c%s "${EXE}") bytes)"
