#!/usr/bin/env bash
# tools/build-customdll-test.sh
#
# Compiles userland/apps/customdll_test/hello.c into a real
# x86_64 Windows PE/COFF .exe that imports three functions from
# customdll.dll (CustomAdd, CustomMul, CustomVersion) plus
# ExitProcess from kernel32.dll. Bytes are embedded as a
# C++ constexpr u8 array for inclusion in the kernel.
#
# Unlike hello_winapi which imports only from kernel32, this PE
# is the first fixture that exercises the stage-2 slice-6
# via-DLL path: at load time, ResolveImports consults the
# pre-loaded customdll.dll image and patches each
# customdll.dll!* IAT slot directly with the DLL's export VA.
#
# Usage: build-customdll-test.sh <repo_root> <out_header>
#
# Invoked from kernel/CMakeLists.txt via add_custom_command.

set -euo pipefail

if [[ $# -ne 2 ]]; then
    echo "usage: $0 <repo_root> <out_header>" >&2
    exit 2
fi

REPO_ROOT="$1"
OUT_HEADER="$2"
SRC_DIR="${REPO_ROOT}/userland/apps/customdll_test"
SRC_C="${SRC_DIR}/hello.c"
EMBED="${REPO_ROOT}/tools/embed-blob.py"

WORK_DIR="$(dirname "${OUT_HEADER}")/customdll_test"
mkdir -p "${WORK_DIR}"
OBJ="${WORK_DIR}/hello.obj"
EXE="${WORK_DIR}/customdll_test.exe"

CLANG="${CLANG:-clang}"
LLD_LINK="${LLD_LINK:-lld-link}"
DLLTOOL="${DLLTOOL:-llvm-dlltool}"

# One .lib per .def. llvm-dlltool stamps the LIBRARY name from
# the .def into the generated .lib's import descriptors, so
# lld-link emits the correct DLL references at link time.
GEN_LIBS=()
for def in "${SRC_DIR}"/*.def; do
    base=$(basename "${def}" .def)
    lib="${WORK_DIR}/${base}.lib"
    "${DLLTOOL}" -d "${def}" -l "${lib}" -m i386:x86-64
    GEN_LIBS+=("${lib}")
done

# Compile. Freestanding (no CRT), no SSE (the program does no
# floating-point / SIMD and we don't want to pull in cookie /
# chkstk support paths the CRT would normally provide).
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

# Link. Default /dynamicbase (so a .reloc directory is present
# — the PE loader walks it with aslr_delta=0 today, but the
# path stays live). Default /filealign=512 — we want the PE to
# look like a real-world Windows executable.
set +e
"${LLD_LINK}" \
    /subsystem:console \
    /entry:_start \
    /nodefaultlib \
    /base:0x140000000 \
    /out:"${EXE}" \
    "${OBJ}" \
    "${GEN_LIBS[@]}" 2>&1 | grep -v "align specified without /driver"
LINK_RC=${PIPESTATUS[0]}
set -e
if [[ ${LINK_RC} -ne 0 ]]; then
    echo "build-customdll-test.sh: lld-link failed (rc=${LINK_RC})" >&2
    exit ${LINK_RC}
fi

if [[ ! -s "${EXE}" ]]; then
    echo "build-customdll-test.sh: lld-link produced no output" >&2
    exit 1
fi

python3 "${EMBED}" \
    "${EXE}" \
    "${OUT_HEADER}" \
    kBinCustomDllTestBytes \
    --namespace "customos::fs::generated"

echo "build-customdll-test.sh: wrote ${OUT_HEADER} (PE $(stat -c%s "${EXE}") bytes)"
