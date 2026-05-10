#!/usr/bin/env bash
# tools/build/build-native-app.sh
#
# Generic builder for portable native DuetOS ELF apps.
# Replaces the per-app one-off scripts (build-usershell-elf.sh,
# etc.) for any new app whose layout matches the convention:
#
#   userland/native-apps/<name>/<name>.c
#
# Compiles `<name>.c` + the userland libc (crt0, syscall, string,
# stdio, setjmp) into a freestanding x86_64 ELF, then embeds the
# bytes into a C++ header via embed-blob.py for the kernel ramfs.
#
# Usage:
#     build-native-app.sh <repo_root> <out_header> <app_name> [extra-source...]
#
# Generated header exposes (via embed-blob.py default namespace
# `duetos::fs::generated`):
#     constexpr u8  kBin<App>NativeBytes[];
#     constexpr u64 kBin<App>NativeBytes_len;
# where <App> is `<app_name>` Pascal-cased.

set -euo pipefail

if [[ $# -lt 3 ]]; then
    echo "usage: $0 <repo_root> <out_header> <app_name> [extra-source...]" >&2
    exit 2
fi

REPO_ROOT="$1"
OUT_HEADER="$2"
APP_NAME="$3"
shift 3

LIBC_INC="${REPO_ROOT}/userland/libc/include"
LIBC_SRC="${REPO_ROOT}/userland/libc/src"
APP_SRC="${REPO_ROOT}/userland/native-apps/${APP_NAME}/${APP_NAME}.c"
EMBED="${REPO_ROOT}/tools/build/embed-blob.py"
LDS="${LIBC_SRC}/../usershell.lds"

if [[ ! -f "${APP_SRC}" ]]; then
    echo "build-native-app: source not found: ${APP_SRC}" >&2
    exit 2
fi
if [[ ! -f "${LDS}" ]]; then
    echo "build-native-app: linker script missing: ${LDS}" >&2
    exit 2
fi

WORK_DIR="$(dirname "${OUT_HEADER}")/native-${APP_NAME}"
mkdir -p "${WORK_DIR}"

CLANG="${CLANG:-clang}"
LLD="${LLD:-ld.lld}"

# Pascal-case the app name for the embedded symbol. So e.g.
# "hello_native" → "HelloNative" → "kBinHelloNativeBytes".
SYMBOL_BASE="$(printf '%s\n' "${APP_NAME}" | awk -F'[_-]' '{
    out=""
    for (i = 1; i <= NF; ++i) {
        s = $i
        out = out toupper(substr(s,1,1)) substr(s,2)
    }
    print out
}')"
SYMBOL_NAME="kBin${SYMBOL_BASE}Bytes"

CFLAGS=(
    --target=x86_64-unknown-none-elf
    -ffreestanding
    -nostdlib
    -fno-pic
    -fno-pie
    -mno-red-zone
    -fno-stack-protector
    -fno-builtin
    -fno-exceptions
    -fno-asynchronous-unwind-tables
    -mgeneral-regs-only
    -O2
    -Wall -Wextra -Wpedantic
    -I"${LIBC_INC}"
)

ASFLAGS=(
    --target=x86_64-unknown-none-elf
    -nostdlib
)

# Compile each TU.
declare -a OBJS
compile_one() {
    local src="$1"
    local obj="${WORK_DIR}/$(basename "${src}").o"
    case "${src}" in
        *.S) "${CLANG}" "${ASFLAGS[@]}" -c "${src}" -o "${obj}" ;;
        *.c) "${CLANG}" "${CFLAGS[@]}"  -c "${src}" -o "${obj}" ;;
        *)
            echo "build-native-app: unknown source extension: ${src}" >&2
            exit 2
            ;;
    esac
    OBJS+=("${obj}")
}

# Userland libc TUs.
compile_one "${LIBC_SRC}/crt0.S"
compile_one "${LIBC_SRC}/syscall.c"
compile_one "${LIBC_SRC}/string.S"
compile_one "${LIBC_SRC}/setjmp.S"
if [[ -f "${LIBC_SRC}/stdio.c" ]]; then
    compile_one "${LIBC_SRC}/stdio.c"
fi
# The app's own primary source.
compile_one "${APP_SRC}"
# Any extra-source files passed by CMake.
for extra in "$@"; do
    compile_one "${extra}"
done

ELF="${WORK_DIR}/${APP_NAME}.elf"
"${LLD}" \
    --no-undefined \
    -T "${LDS}" \
    -o "${ELF}" \
    "${OBJS[@]}"

# Embed the resulting bytes.
python3 "${EMBED}" "${ELF}" "${OUT_HEADER}" "${SYMBOL_NAME}" \
    --namespace "duetos::fs::generated"
