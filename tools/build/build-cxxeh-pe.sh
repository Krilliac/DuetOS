#!/usr/bin/env bash
#
# build-cxxeh-pe.sh — compile + embed cxxeh_pe.exe, the real MSVC
# C++ exception-handling test. Built with
# clang --target=x86_64-pc-windows-msvc (C++ exceptions on, which
# makes clang emit .pdata/.xdata + the __CxxFrameHandler3
# personality and call _CxxThrowException for `throw`), then
# linked with lld-link against our OWN kernel32.lib / ntdll.lib /
# vcruntime140.lib import libraries. No MSVC SDK, no CRT.
#
# Usage: build-cxxeh-pe.sh <repo_root> <out_header>
set -euo pipefail

if [[ $# -ne 2 ]]; then
    echo "usage: $0 <repo_root> <out_header>" >&2
    exit 2
fi

REPO_ROOT="$1"
OUT_HEADER="$2"
SRC="${REPO_ROOT}/userland/apps/cxxeh_pe/cxxeh_pe.cpp"
EMBED="${REPO_ROOT}/tools/build/embed-blob.py"
CLANG="${CLANG:-clang}"
LLD_LINK="${LLD_LINK:-lld-link}"

KDIR="$(dirname "${OUT_HEADER}")"
KERNEL32_LIB="${KDIR}/kernel32/kernel32.lib"
NTDLL_LIB="${KDIR}/ntdll/ntdll.lib"
VCRUNTIME_LIB="${KDIR}/vcruntime140/vcruntime140.lib"
WORK_DIR="${KDIR}/cxxeh_pe"
mkdir -p "${WORK_DIR}"
OBJ="${WORK_DIR}/cxxeh_pe.obj"
EXE="${WORK_DIR}/cxxeh_pe.exe"

for lib in "${KERNEL32_LIB}" "${NTDLL_LIB}" "${VCRUNTIME_LIB}"; do
    if [[ ! -s "${lib}" ]]; then
        echo "build-cxxeh-pe.sh: missing import lib ${lib}" >&2
        exit 1
    fi
done

# C++ exceptions stay ON (default for .cpp on the windows-msvc
# target) so clang emits the FuncInfo / .xdata + __CxxFrameHandler3
# references and lowers `throw` to _CxxThrowException. -O0 is
# deterministic + fast and emits the full unwind tables. RTTI off
# (catch matches via the EH TypeDescriptor, not typeid). The
# timeout+retry mirrors build-seh-try-pe.sh's guard against clang's
# occasional SEH-codegen stall.
CLANG_ARGS=(--target=x86_64-pc-windows-msvc -c -ffreestanding -nostdlib -fno-stack-protector -fno-builtin
            -fno-rtti -mno-red-zone -O0 -Wall -Wextra "${SRC}" -o "${OBJ}")

_ok=0
for _attempt in 1 2 3 4; do
    rm -f "${OBJ}"
    if timeout 120 "${CLANG}" "${CLANG_ARGS[@]}" 2>/dev/null && [[ -s "${OBJ}" ]]; then
        _ok=1
        break
    fi
    echo "build-cxxeh-pe.sh: clang attempt ${_attempt} stalled/failed — retrying" >&2
done
if [[ "${_ok}" -ne 1 ]]; then
    "${CLANG}" "${CLANG_ARGS[@]}"
fi

rm -f "${EXE}"
"${LLD_LINK}" \
    /nologo \
    /subsystem:console \
    /entry:mainCRTStartup \
    /nodefaultlib \
    "${OBJ}" \
    "${KERNEL32_LIB}" \
    "${NTDLL_LIB}" \
    "${VCRUNTIME_LIB}" \
    /out:"${EXE}"

if [[ ! -s "${EXE}" ]]; then
    echo "build-cxxeh-pe.sh: lld-link produced no output" >&2
    exit 1
fi

python3 "${EMBED}" \
    "${EXE}" \
    "${OUT_HEADER}" \
    kBinCxxEhPeBytes \
    --namespace "duetos::fs::generated"

echo "build-cxxeh-pe.sh: wrote ${OUT_HEADER} (EXE $(stat -c%s "${EXE}") bytes)"
