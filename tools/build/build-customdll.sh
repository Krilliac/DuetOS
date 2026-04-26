#!/usr/bin/env bash
# tools/build/build-customdll.sh
#
# Compiles userland/libs/customdll/customdll.c into a
# freestanding x86_64 Windows PE DLL and embeds the bytes as
# a C++ constexpr u8 array for inclusion in the kernel.
#
# The kernel's stage-2 DLL loader self-test (called from
# kernel_main) hands this blob to DllLoad + PeParseExports and
# asserts that:
#
#     CustomAdd    -> resolves by name and by ordinal
#     CustomMul    -> resolves by name and by ordinal
#     CustomVersion-> resolves by name
#
# The DLL has no imports, no TLS, no DllMain. /noentry tells
# lld-link to skip the default _DllMainCRTStartup reference —
# we don't have a CRT.
#
# Usage:
#     build-customdll.sh <repo_root> <out_header>
#
# Invoked from kernel/CMakeLists.txt via add_custom_command.

set -euo pipefail

if [[ $# -ne 2 ]]; then
    echo "usage: $0 <repo_root> <out_header>" >&2
    exit 2
fi

REPO_ROOT="$1"
OUT_HEADER="$2"
SRC_DIR="${REPO_ROOT}/userland/libs/customdll"
SRC_C="${SRC_DIR}/customdll.c"
EMBED="${REPO_ROOT}/tools/build/embed-blob.py"

WORK_DIR="$(dirname "${OUT_HEADER}")/customdll"
mkdir -p "${WORK_DIR}"
OBJ="${WORK_DIR}/customdll.obj"
DLL="${WORK_DIR}/customdll.dll"

CLANG="${CLANG:-clang}"
LLD_LINK="${LLD_LINK:-lld-link}"

# Compile. Freestanding, no CRT, no SSE (the DLL does not
# contain floating-point or SIMD — matching hello_winapi). We
# do NOT pass -mno-sse/-mno-sse2 here because the resulting
# DLL is only parsed by the kernel, never executed, so ABI
# preservation is irrelevant.
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

# Link as a DLL.
#
#   /dll         — DLL subsystem; emits IMAGE_FILE_DLL
#                  (0x2000) in FileHeader.Characteristics,
#                  which is exactly the gate DllLoad checks.
#   /noentry     — no DllMain needed; skip the default entry.
#   /nodefaultlib— no msvcrt / libcmt.
#   /export:NAME — declare each function as an export.
#                  Equivalent to __declspec(dllexport) in the
#                  source; we pass both so the .obj carries
#                  the export directive AND lld-link knows to
#                  include the function even with /gc-sections.
#   /base:0x10000000 — DLL preferred base; the kernel self-test
#                  supplies aslr_delta=0 so the image lands
#                  there exactly.
#
# Capture linker output via PIPESTATUS so a real error
# (undefined symbol) terminates the script.
set +e
"${LLD_LINK}" \
    /dll \
    /noentry \
    /nodefaultlib \
    /base:0x10000000 \
    /export:CustomAdd \
    /export:CustomMul \
    /export:CustomVersion \
    /export:CustomAddFwd=customdll.CustomAdd \
    /out:"${DLL}" \
    "${OBJ}" 2>&1 | grep -v "align specified without /driver"
LINK_RC=${PIPESTATUS[0]}
set -e
if [[ ${LINK_RC} -ne 0 ]]; then
    echo "build-customdll.sh: lld-link failed (rc=${LINK_RC})" >&2
    exit ${LINK_RC}
fi

if [[ ! -s "${DLL}" ]]; then
    echo "build-customdll.sh: lld-link produced no output" >&2
    exit 1
fi

python3 "${EMBED}" \
    "${DLL}" \
    "${OUT_HEADER}" \
    kBinCustomDllBytes \
    --namespace "duetos::fs::generated"

echo "build-customdll.sh: wrote ${OUT_HEADER} (DLL $(stat -c%s "${DLL}") bytes)"
