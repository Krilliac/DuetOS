#!/usr/bin/env bash
#
# build-sxs-fixture.sh — build the side-by-side DLL fixture pair.
#
# WHAT:
#   Compiles userland/libs/sxslib/sxslib.c into sxslib.dll and
#   userland/apps/sxs_test/sxs_test.c into sxstest.exe, with the .exe
#   statically importing two functions from the .dll.
#
# WHY:
#   Unlike every other PE fixture in this tree, this pair is NOT embedded
#   into the kernel image. Both files are staged onto the FAT32 volume by
#   tools/qemu/run.sh, side by side in the root directory. The .exe can
#   therefore only run if the loader found, gated and bound a DLL that
#   ships beside it on disk — which is exactly the capability under test.
#   Embedding either half would make the test prove nothing.
#
# USAGE:
#   tools/build/build-sxs-fixture.sh --out-dir <dir>
#
#   Produces <dir>/SXSLIB.DLL and <dir>/SXSTEST.EXE. The names are the
#   DOS 8.3 short names the FAT32 image builder writes, so the import
#   name recorded in the .exe ("sxslib.dll") matches the on-disk entry
#   case-insensitively with no short-name mangling involved.
#
# ENV:
#   CC   mingw cross compiler (default x86_64-w64-mingw32-gcc)
#
# EXITS 0 with no output produced when the toolchain is absent — the
# CMake caller treats a missing fixture as "battery row skipped", the
# same contract embed-blob.py --empty provides for embedded fixtures.

set -euo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

CC="${CC:-x86_64-w64-mingw32-gcc}"
OUT_DIR=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --out-dir) OUT_DIR="$2"; shift 2 ;;
        *) echo "error: unknown argument $1" >&2; exit 2 ;;
    esac
done

if [[ -z "${OUT_DIR}" ]]; then
    echo "usage: $0 --out-dir <dir>" >&2
    exit 2
fi

if ! command -v "${CC}" >/dev/null 2>&1; then
    echo "[sxs-fixture] ${CC} not found — skipping fixture build" >&2
    exit 0
fi

mkdir -p "${OUT_DIR}"

readonly DLL_SRC="${REPO_ROOT}/userland/libs/sxslib/sxslib.c"
readonly EXE_SRC="${REPO_ROOT}/userland/apps/sxs_test/sxs_test.c"
readonly DLL_OUT="${OUT_DIR}/SXSLIB.DLL"
readonly EXE_OUT="${OUT_DIR}/SXSTEST.EXE"
readonly IMPLIB="${OUT_DIR}/libsxslib.a"

# Freestanding on both halves: DuetOS's PE loader wants a 4096-byte
# SectionAlignment and no CRT startup it cannot satisfy.
COMMON=(-nostdlib -ffreestanding -fno-stack-protector -mno-stack-arg-probe)

# The DLL. --out-implib gives the .exe something to link against; the
# LIBRARY name baked into that import lib is the output basename, which
# is why the output is named sxslib.dll before being copied to the 8.3
# name. -Wl,--enable-auto-image-base is deliberately NOT used: a fixed
# preferred base keeps the loader's ASLR roll the only thing moving it.
"${CC}" "${COMMON[@]}" -shared \
    -Wl,--entry,DllMainCRTStartup \
    -Wl,--out-implib,"${IMPLIB}" \
    -Wl,--image-base,0x10400000 \
    -o "${OUT_DIR}/sxslib.dll" "${DLL_SRC}"
# Two-step rename for case-insensitive filesystems (NTFS via WSL).
mv -f "${OUT_DIR}/sxslib.dll" "${OUT_DIR}/sxslib.dll.tmp"
mv -f "${OUT_DIR}/sxslib.dll.tmp" "${DLL_OUT}"

# The .exe. Imports resolve against the import lib at link time and
# against the on-disk DLL at load time.
"${CC}" "${COMMON[@]}" \
    -e mainCRTStartup \
    -Wl,--subsystem,console \
    -Wl,--entry,mainCRTStartup \
    -o "${EXE_OUT}" "${EXE_SRC}" "${IMPLIB}" -lkernel32

echo "[sxs-fixture] built $(basename "${DLL_OUT}") + $(basename "${EXE_OUT}") in ${OUT_DIR}"
