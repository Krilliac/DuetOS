#!/usr/bin/env bash
# Run the in-kernel GUI fuzz harness for SECS (default 30) under WSL.
# Captures the run log to /mnt/c/.../gui-fuzz.log and copies the
# auto-staged ISO to OneDrive Desktop\\DuetOS Logs for parallel
# inspection.
set -euo pipefail
SECS="${1:-30}"
export PATH="/usr/lib/llvm-18/bin:${PATH}"
cd ~/source/DuetOS
# Build canonical ISO first (release for speed)
cmake --build build/x86_64-release --target duetos.iso -j8 2>&1 | tail -3
DUETOS_PRESET=x86_64-release DUETOS_TIMEOUT=$((SECS + 90)) \
  tools/qemu/gui-fuzz.sh "${SECS}" 2>&1 | tail -40
cp -f build/x86_64-release/gui-fuzz.log "/mnt/c/Users/natew/AppData/Local/Temp/gui-fuzz.log" || true
echo "log copied to /mnt/c/Users/natew/AppData/Local/Temp/gui-fuzz.log"
