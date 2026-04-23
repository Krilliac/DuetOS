#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

python3 tools/linux-compat/gen-linux-syscall-table.py \
    --csv tools/linux-compat/linux-syscalls-x86_64.csv \
    --mapped-from-dispatcher kernel/subsystems/linux/syscall.cpp \
    --out kernel/subsystems/linux/linux_syscall_table_generated.h

python3 tools/win32-compat/gen-nt-shim.py \
    --csv tools/win32-compat/nt-syscalls-x64.csv \
    --version "Windows 11 and Server (11 25H2)" \
    --out kernel/subsystems/win32/nt_syscall_table_generated.h

python3 tools/gen-syscall-matrix.py \
    --syscall-h kernel/core/syscall.h \
    --linux-table kernel/subsystems/linux/linux_syscall_table_generated.h \
    --nt-table kernel/subsystems/win32/nt_syscall_table_generated.h \
    --translate-cpp kernel/subsystems/translation/translate.cpp \
    --out-json docs/syscall-abi-matrix.json \
    --out-csv docs/syscall-abi-matrix.csv \
    --out-md docs/syscall-abi-matrix.md
