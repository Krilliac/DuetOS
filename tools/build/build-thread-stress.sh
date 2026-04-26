#!/usr/bin/env bash
# tools/build/build-hello-winapi.sh
#
# Compiles userland/apps/thread_stress/hello.c into a real
# x86_64 Windows PE/COFF .exe that imports ExitProcess from
# kernel32.dll. Unlike tools/build/build-hello-pe.sh, this one:
#
#   * Generates kernel32.lib via llvm-dlltool from
#     userland/apps/thread_stress/kernel32.def.
#   * Links against that .lib so the resulting PE carries a
#     real Import Directory.
#   * Leaves FileAlignment at 512 (lld-link's default) — we
#     want the produced PE to look like a real-world Windows
#     executable, not an oddly-aligned test fixture.
#
# The DuetOS kernel PE loader then parses the Import
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
SRC_DIR="${REPO_ROOT}/userland/apps/thread_stress"
SRC_C="${SRC_DIR}/hello.c"
EMBED="${REPO_ROOT}/tools/build/embed-blob.py"

WORK_DIR="$(dirname "${OUT_HEADER}")/thread_stress"
mkdir -p "${WORK_DIR}"
OBJ="${WORK_DIR}/hello.obj"
EXE="${WORK_DIR}/thread_stress.exe"

CLANG="${CLANG:-clang}"
LLD_LINK="${LLD_LINK:-lld-link}"
DLLTOOL="${DLLTOOL:-llvm-dlltool}"

resolve_dlltool() {
    if command -v "${DLLTOOL}" >/dev/null 2>&1; then
        echo "${DLLTOOL}"
        return 0
    fi

    local candidate
    for candidate in llvm-dlltool llvm-dlltool-18 llvm-dlltool-17 llvm-dlltool-16 x86_64-w64-mingw32-dlltool; do
        if command -v "${candidate}" >/dev/null 2>&1; then
            echo "${candidate}"
            return 0
        fi
    done

    echo "build-thread-stress.sh: no dlltool found." >&2
    echo "  Tried DLLTOOL=${DLLTOOL} plus llvm-dlltool{-18,-17,-16} and x86_64-w64-mingw32-dlltool." >&2
    echo "  Install llvm binutils (provides llvm-dlltool) or mingw-w64 binutils." >&2
    exit 1
}

DLLTOOL_BIN="$(resolve_dlltool)"

# Generate one import library per .def file in the source
# directory. Each .def names a specific DLL in its LIBRARY
# line (kernel32.dll, vcruntime140.dll, api-ms-win-crt-*, …)
# and llvm-dlltool bakes that name into the resulting .lib's
# import descriptors. The PE lld-link produces references
# each DLL by exactly the name from the corresponding .def.
#
# Collect all generated .libs into GEN_LIBS so we can pass
# them to lld-link below.
GEN_LIBS=()
for def in "${SRC_DIR}"/*.def; do
    base=$(basename "${def}" .def)
    lib="${WORK_DIR}/${base}.lib"
    "${DLLTOOL_BIN}" -d "${def}" -l "${lib}" -m i386:x86-64
    GEN_LIBS+=("${lib}")
done

# Compile.
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

# Link. No /align:4096 — we want the real-world default
# FileAlignment=512 that the PE loader now accepts. Also
# default /dynamicbase, which emits a real .reloc directory —
# the loader's base-reloc walker walks it (delta is 0 in
# v0 so no addresses actually change, but the walk catches a
# malformed .reloc table up front and keeps the test fixture
# shape aligned with real-world MSVC-linked PEs).
#
# Delete the prior EXE first so a silent link failure (e.g.
# undefined import) doesn't leave the PREVIOUS exe in place
# and trick the embed step into baking stale bytes into the
# kernel. Caught a real bug during bring-up where a
# missing .def export silently re-shipped the old PE.
rm -f "${EXE}"

# Capture link output, filter the harmless /align noise, but
# preserve the linker's exit status via PIPESTATUS so a real
# error (undefined symbol, bad object) terminates the script.
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
    echo "build-hello-winapi.sh: lld-link failed (rc=${LINK_RC})" >&2
    exit ${LINK_RC}
fi

if [[ ! -s "${EXE}" ]]; then
    echo "build-hello-winapi.sh: lld-link produced no output" >&2
    exit 1
fi

python3 "${EMBED}" \
    "${EXE}" \
    "${OUT_HEADER}" \
    kBinThreadStressBytes \
    --namespace "duetos::fs::generated"

echo "build-hello-winapi.sh: wrote ${OUT_HEADER} (PE $(stat -c%s "${EXE}") bytes)"
