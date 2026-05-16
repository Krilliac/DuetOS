#!/usr/bin/env bash
#
# build-seh-try-pe.sh — compile + embed seh_try_pe.exe, the real
# MSVC __try/__except/__finally SEH test. Built with
# clang --target=x86_64-pc-windows-msvc -fasync-exceptions (the
# flag that makes clang emit .pdata/.xdata + the
# __C_specific_handler personality over hardware faults), then
# linked with lld-link against our OWN kernel32.lib / ntdll.lib
# import libraries (produced as a side effect of the kernel32 /
# ntdll DLL builds). No MSVC SDK, no CRT.
#
# Usage: build-seh-try-pe.sh <repo_root> <out_header>
set -euo pipefail

if [[ $# -ne 2 ]]; then
    echo "usage: $0 <repo_root> <out_header>" >&2
    exit 2
fi

REPO_ROOT="$1"
OUT_HEADER="$2"
SRC="${REPO_ROOT}/userland/apps/seh_try_pe/seh_try_pe.c"
EMBED="${REPO_ROOT}/tools/build/embed-blob.py"
CLANG="${CLANG:-clang}"
LLD_LINK="${LLD_LINK:-lld-link}"

# The kernel32 / ntdll import libs sit next to this header in the
# kernel binary dir (build-{kernel32,ntdll}-dll.sh write their work
# trees there). The CMake dependency edge guarantees they exist.
KDIR="$(dirname "${OUT_HEADER}")"
KERNEL32_LIB="${KDIR}/kernel32/kernel32.lib"
NTDLL_LIB="${KDIR}/ntdll/ntdll.lib"
WORK_DIR="${KDIR}/seh_try_pe"
mkdir -p "${WORK_DIR}"
OBJ="${WORK_DIR}/seh_try_pe.obj"
EXE="${WORK_DIR}/seh_try_pe.exe"

for lib in "${KERNEL32_LIB}" "${NTDLL_LIB}"; do
    if [[ ! -s "${lib}" ]]; then
        echo "build-seh-try-pe.sh: missing import lib ${lib}" >&2
        exit 1
    fi
done

"${CLANG}" \
    --target=x86_64-pc-windows-msvc \
    -c \
    -ffreestanding \
    -nostdlib \
    -fno-stack-protector \
    -fno-builtin \
    -mno-red-zone \
    -fasync-exceptions \
    -O2 \
    -Wall -Wextra \
    "${SRC}" \
    -o "${OBJ}"

rm -f "${EXE}"
"${LLD_LINK}" \
    /nologo \
    /subsystem:console \
    /entry:mainCRTStartup \
    /nodefaultlib \
    "${OBJ}" \
    "${KERNEL32_LIB}" \
    "${NTDLL_LIB}" \
    /out:"${EXE}"

if [[ ! -s "${EXE}" ]]; then
    echo "build-seh-try-pe.sh: lld-link produced no output" >&2
    exit 1
fi

python3 "${EMBED}" \
    "${EXE}" \
    "${OUT_HEADER}" \
    kBinSehTryPeBytes \
    --namespace "duetos::fs::generated"

echo "build-seh-try-pe.sh: wrote ${OUT_HEADER} (EXE $(stat -c%s "${EXE}") bytes)"
