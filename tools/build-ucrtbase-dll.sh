#!/usr/bin/env bash
# tools/build-ucrtbase-dll.sh
#
# Compiles userland/libs/ucrtbase/ucrtbase.c into a
# freestanding x86_64 Windows PE DLL. Retires the prior
# UCRT runtime stubs — heap, exit, CRT startup shims,
# string intrinsics.
#
# Usage:
#     build-ucrtbase-dll.sh <repo_root> <out_header>

set -euo pipefail

if [[ $# -ne 2 ]]; then
    echo "usage: $0 <repo_root> <out_header>" >&2
    exit 2
fi

REPO_ROOT="$1"
OUT_HEADER="$2"
SRC_DIR="${REPO_ROOT}/userland/libs/ucrtbase"
SRC_C="${SRC_DIR}/ucrtbase.c"
EMBED="${REPO_ROOT}/tools/embed-blob.py"

WORK_DIR="$(dirname "${OUT_HEADER}")/ucrtbase"
mkdir -p "${WORK_DIR}"
OBJ="${WORK_DIR}/ucrtbase.obj"
DLL="${WORK_DIR}/ucrtbase.dll"

CLANG="${CLANG:-clang}"
LLD_LINK="${LLD_LINK:-lld-link}"

"${CLANG}" \
    --target=x86_64-pc-windows-msvc \
    -c \
    -ffreestanding \
    -nostdlib \
    -fno-stack-protector \
    -fno-builtin \
    -fno-builtin-malloc \
    -fno-builtin-free \
    -fno-builtin-calloc \
    -fno-builtin-realloc \
    -fno-builtin-exit \
    -fno-builtin-strlen \
    -fno-builtin-strcmp \
    -fno-builtin-strcpy \
    -fno-builtin-strchr \
    -mno-red-zone \
    -fno-asynchronous-unwind-tables \
    -O2 \
    -Wall -Wextra \
    "${SRC_C}" \
    -o "${OBJ}"

rm -f "${DLL}"

# /base:0x10050000 — 1 MiB above msvcrt.dll.
set +e
"${LLD_LINK}" \
    /dll \
    /noentry \
    /nodefaultlib \
    /base:0x10050000 \
    /export:malloc \
    /export:free \
    /export:calloc \
    /export:realloc \
    /export:_aligned_malloc \
    /export:_aligned_free \
    /export:exit \
    /export:_exit \
    /export:_initterm \
    /export:_initterm_e \
    /export:_cexit \
    /export:_c_exit \
    /export:_set_app_type \
    /export:__setusermatherr \
    /export:_configthreadlocale \
    /export:strlen \
    /export:strcmp \
    /export:strcpy \
    /export:strchr \
    /export:atoi \
    /export:atol \
    /export:strtol \
    /export:strtoul \
    /export:terminate \
    /export:_invalid_parameter_noinfo_noreturn \
    /export:vsnprintf /export:snprintf /export:sprintf /export:_vsnprintf \
    /export:printf /export:puts /export:putchar \
    /export:vprintf /export:vfprintf /export:fprintf \
    /export:__acrt_iob_func \
    /export:fopen /export:_wfopen /export:fclose \
    /export:fread /export:fwrite /export:fflush \
    /export:fputs /export:fputc /export:fgets /export:fgetc \
    /export:fseek /export:ftell /export:feof /export:ferror \
    /export:strncmp /export:strncpy /export:strcat /export:strncat \
    /export:_stricmp /export:_strnicmp \
    /export:abs /export:labs /export:llabs \
    /export:isalpha /export:isdigit /export:isspace /export:isprint /export:isalnum \
    /export:toupper /export:tolower \
    /export:qsort /export:bsearch \
    /export:sscanf /export:vsscanf \
    /export:rand /export:srand \
    /export:getenv /export:_putenv /export:_putenv_s \
    /export:_errno \
    /out:"${DLL}" \
    "${OBJ}" 2>&1 | grep -v "align specified without /driver"
LINK_RC=${PIPESTATUS[0]}
set -e
if [[ ${LINK_RC} -ne 0 ]]; then
    echo "build-ucrtbase-dll.sh: lld-link failed (rc=${LINK_RC})" >&2
    exit ${LINK_RC}
fi

if [[ ! -s "${DLL}" ]]; then
    echo "build-ucrtbase-dll.sh: lld-link produced no output" >&2
    exit 1
fi

python3 "${EMBED}" \
    "${DLL}" \
    "${OUT_HEADER}" \
    kBinUcrtbaseDllBytes \
    --namespace "duetos::fs::generated"

echo "build-ucrtbase-dll.sh: wrote ${OUT_HEADER} (DLL $(stat -c%s "${DLL}") bytes)"
