#!/usr/bin/env bash
#
# build-delayload-pe.sh — compile + embed delayload_pe.exe, the
# fixture that proves the PE loader binds
# IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT (directory 13) at load time.
#
# mingw-w64's ld cannot emit an MSVC-shaped delay-load directory
# (dlltool's --output-delaylib produces the descriptor but ld does
# not populate data directory 13), so this fixture cannot go through
# userland/apps/build-smokes.sh with the other smoke PEs. lld-link's
# /delayload does emit the directory, which is why this one is built
# the same way as cxxeh_pe / seh_try_pe: clang
# --target=x86_64-pc-windows-msvc plus lld-link against our OWN
# kernel32.lib / user32.lib import libraries. No MSVC SDK, no CRT.
#
# The image supplies its own `__delayLoadHelper2` (delayimp.lib is
# not available and, more to the point, the fixture wants that
# helper as a tripwire — see userland/apps/delayload_pe/).
#
# Usage: build-delayload-pe.sh <repo_root> <out_header>
set -euo pipefail

if [[ $# -ne 2 ]]; then
    echo "usage: $0 <repo_root> <out_header>" >&2
    exit 2
fi

REPO_ROOT="$1"
OUT_HEADER="$2"
SRC="${REPO_ROOT}/userland/apps/delayload_pe/delayload_pe.c"
EMBED="${REPO_ROOT}/tools/build/embed-blob.py"
CLANG="${CLANG:-clang}"
LLD_LINK="${LLD_LINK:-lld-link}"

KDIR="$(dirname "${OUT_HEADER}")"
KERNEL32_LIB="${KDIR}/kernel32/kernel32.lib"
USER32_LIB="${KDIR}/user32/user32.lib"
WORK_DIR="${KDIR}/delayload_pe"
mkdir -p "${WORK_DIR}"
OBJ="${WORK_DIR}/delayload_pe.obj"
EXE="${WORK_DIR}/delayload_pe.exe"

for lib in "${KERNEL32_LIB}" "${USER32_LIB}"; do
    if [[ ! -s "${lib}" ]]; then
        echo "build-delayload-pe.sh: missing import lib ${lib}" >&2
        exit 1
    fi
done

"${CLANG}" \
    --target=x86_64-pc-windows-msvc -c \
    -ffreestanding -nostdlib -fno-stack-protector -fno-builtin \
    -mno-red-zone -fno-asynchronous-unwind-tables -O0 -Wall -Wextra \
    "${SRC}" -o "${OBJ}"

rm -f "${EXE}"
"${LLD_LINK}" \
    /nologo \
    /subsystem:console \
    /entry:mainCRTStartup \
    /nodefaultlib \
    /delayload:user32.dll \
    "${OBJ}" \
    "${KERNEL32_LIB}" \
    "${USER32_LIB}" \
    /out:"${EXE}"

if [[ ! -s "${EXE}" ]]; then
    echo "build-delayload-pe.sh: lld-link produced no output" >&2
    exit 1
fi

# Fail loudly if the linker did NOT emit data directory 13 — without
# it the fixture would silently degrade into an ordinary-import test
# and "PASS" while proving nothing about delay-load.
python3 - "${EXE}" <<'PY'
import struct, sys
d = open(sys.argv[1], 'rb').read()
opt = struct.unpack_from('<I', d, 0x3C)[0] + 24
magic = struct.unpack_from('<H', d, opt)[0]
dd = opt + (112 if magic == 0x20B else 96)
rva, size = struct.unpack_from('<II', d, dd + 13 * 8)
if rva == 0 or size == 0:
    sys.exit("build-delayload-pe.sh: no IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT in the linked image")
print("build-delayload-pe.sh: delay-import dir rva=0x%x size=%d" % (rva, size))
PY

python3 "${EMBED}" \
    "${EXE}" \
    "${OUT_HEADER}" \
    kBinDelayloadPeBytes \
    --namespace "duetos::fs::generated"

echo "build-delayload-pe.sh: wrote ${OUT_HEADER} (EXE $(stat -c%s "${EXE}") bytes)"
