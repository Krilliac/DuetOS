#!/usr/bin/env bash
# tools/build-hello-winapi.sh
#
# Compiles userland/apps/hello_winapi/hello.c into a real
# x86_64 Windows PE/COFF .exe that imports ExitProcess from
# kernel32.dll. Unlike tools/build-hello-pe.sh, this one:
#
#   * Generates kernel32.lib via llvm-dlltool from
#     userland/apps/hello_winapi/kernel32.def.
#   * Links against that .lib so the resulting PE carries a
#     real Import Directory.
#   * Leaves FileAlignment at 512 (lld-link's default) — we
#     want the produced PE to look like a real-world Windows
#     executable, not an oddly-aligned test fixture.
#
# The CustomOS kernel PE loader then parses the Import
# Directory, resolves ExitProcess through the Win32 stubs
# table (see kernel/subsystems/win32/stubs.{h,cpp}), patches
# the IAT slot with the stub VA, and transfers control to
# the PE's _start. _start issues a CALL through the IAT,
# ends up in the stub, and the stub does int 0x80 SYS_EXIT.
#
# Usage: build-hello-winapi.sh <repo_root> <out_header>
#
# Invoked from kernel/CMakeLists.txt via add_custom_command.

set -euo pipefail

if [[ $# -ne 2 ]]; then
    echo "usage: $0 <repo_root> <out_header>" >&2
    exit 2
fi

REPO_ROOT="$1"
OUT_HEADER="$2"
SRC_DIR="${REPO_ROOT}/userland/apps/hello_winapi"
SRC_C="${SRC_DIR}/hello.c"
DEF_KERNEL32="${SRC_DIR}/kernel32.def"
DEF_VCRUNTIME140="${SRC_DIR}/vcruntime140.def"
EMBED="${REPO_ROOT}/tools/embed-blob.py"

WORK_DIR="$(dirname "${OUT_HEADER}")/hello_winapi"
mkdir -p "${WORK_DIR}"
OBJ="${WORK_DIR}/hello.obj"
LIB_KERNEL32="${WORK_DIR}/kernel32.lib"
LIB_VCRUNTIME140="${WORK_DIR}/vcruntime140.lib"
EXE="${WORK_DIR}/hello_winapi.exe"

CLANG="${CLANG:-clang}"
LLD_LINK="${LLD_LINK:-lld-link}"
DLLTOOL="${DLLTOOL:-llvm-dlltool}"

# Generate per-DLL import libraries from their .def files.
# Each .lib contains only __imp_* symbols for functions from
# the specific DLL the .def names. lld-link uses the import
# descriptors to decide which kernel32/vcruntime140 functions
# end up in the final PE's Import Directory.
"${DLLTOOL}" -d "${DEF_KERNEL32}" -l "${LIB_KERNEL32}" -m i386:x86-64
"${DLLTOOL}" -d "${DEF_VCRUNTIME140}" -l "${LIB_VCRUNTIME140}" -m i386:x86-64

# Compile.
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

# Link. No /align:4096 — we want the real-world default
# FileAlignment=512 that the PE loader now accepts.
"${LLD_LINK}" \
    /subsystem:console \
    /entry:_start \
    /nodefaultlib \
    /base:0x140000000 \
    /dynamicbase:no \
    /out:"${EXE}" \
    "${OBJ}" \
    "${LIB_KERNEL32}" \
    "${LIB_VCRUNTIME140}" 2>&1 | grep -v "align specified without /driver" || true

if [[ ! -s "${EXE}" ]]; then
    echo "build-hello-winapi.sh: lld-link produced no output" >&2
    exit 1
fi

python3 "${EMBED}" \
    "${EXE}" \
    "${OUT_HEADER}" \
    kBinHelloWinapiBytes \
    --namespace "customos::fs::generated"

echo "build-hello-winapi.sh: wrote ${OUT_HEADER} (PE $(stat -c%s "${EXE}") bytes)"
