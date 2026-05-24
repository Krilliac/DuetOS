#!/usr/bin/env bash
# Build both release and debug ISOs for the result-checks-and-guards
# session. Output paths echoed at the end so the Windows side can pick
# them up and copy to Desktop\DuetOS Logs.
set -euo pipefail
export PATH="/usr/lib/llvm-18/bin:${PATH}"
cd ~/source/DuetOS

echo "=== building x86_64-release/duetos.iso ==="
cmake --build build/x86_64-release --target duetos.iso -j8 2>&1 | tail -3

echo "=== building x86_64-debug/duetos.iso ==="
cmake --build build/x86_64-debug --target duetos.iso -j8 2>&1 | tail -3

echo "=== artefacts ==="
ls -la build/x86_64-release/duetos.iso build/x86_64-debug/duetos.iso
