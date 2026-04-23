#!/usr/bin/env bash
# tools/build-syscall-stress.sh
#
# Compiles userland/apps/syscall_stress/hello.c into a real
# x86_64 Windows PE/COFF .exe that exercises the Win32 APIs
# added in batch 51 — OutputDebugStringA, ExitThread,
# GetProcessTimes, GetSystemTimes, GlobalMemoryStatusEx,
# WaitForMultipleObjects.
#
# Mirrors tools/build-thread-stress.sh — same compile/link
# flags, same embed pipeline, just a different source dir.
#
# Usage: build-syscall-stress.sh <repo_root> <out_header>
#
# Invoked from kernel/CMakeLists.txt via add_custom_command.

set -euo pipefail

if [[ $# -ne 2 ]]; then
    echo "usage: $0 <repo_root> <out_header>" >&2
    exit 2
fi

REPO_ROOT="$1"
OUT_HEADER="$2"
SRC_DIR="${REPO_ROOT}/userland/apps/syscall_stress"
SRC_C="${SRC_DIR}/hello.c"
EMBED="${REPO_ROOT}/tools/embed-blob.py"

WORK_DIR="$(dirname "${OUT_HEADER}")/syscall_stress"
mkdir -p "${WORK_DIR}"
OBJ="${WORK_DIR}/hello.obj"
EXE="${WORK_DIR}/syscall_stress.exe"

CLANG="${CLANG:-clang}"
LLD_LINK="${LLD_LINK:-lld-link}"
DLLTOOL="${DLLTOOL:-llvm-dlltool}"

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
    echo "build-syscall-stress.sh: lld-link failed (rc=${LINK_RC})" >&2
    exit ${LINK_RC}
fi

if [[ ! -s "${EXE}" ]]; then
    echo "build-syscall-stress.sh: lld-link produced no output" >&2
    exit 1
fi

python3 "${EMBED}" \
    "${EXE}" \
    "${OUT_HEADER}" \
    kBinSyscallStressBytes \
    --namespace "customos::fs::generated"

echo "build-syscall-stress.sh: wrote ${OUT_HEADER} (PE $(stat -c%s "${EXE}") bytes)"
