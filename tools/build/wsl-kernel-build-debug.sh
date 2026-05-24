#!/usr/bin/env bash
# Debug-preset kernel build for the result-checks-and-guards session.
# Used to verify DEBUG_ASSERT additions compile cleanly under the
# debug preset (assertions ON).
set -euo pipefail
export PATH="/usr/lib/llvm-18/bin:${PATH}"
cd ~/source/DuetOS
TARGET="${1:-duetos-kernel.elf}"
exec cmake --build build/x86_64-debug --target "${TARGET}" -j8
