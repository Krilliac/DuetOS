#!/usr/bin/env bash
# Helper for the wsl.exe call chain used by Claude during the
# result-checks-and-guards session. Wraps the cmake build with
# llvm-18 on PATH so build-linux-vdso.sh can find llvm-objcopy
# without us editing the toolchain file.
#
# Usage:
#   wsl-kernel-build.sh [target]   # default target: duetos-kernel.elf
set -euo pipefail
export PATH="/usr/lib/llvm-18/bin:${PATH}"
cd ~/source/DuetOS
TARGET="${1:-duetos-kernel.elf}"
exec cmake --build build/x86_64-release --target "${TARGET}" -j8
