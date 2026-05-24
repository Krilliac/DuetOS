#!/usr/bin/env bash
# Run bringup smoke until we get a PASS, then capture that log to
# /mnt/c/.../bringup-pass.log. Counterpart to wsl-bringup-repro.sh.
set -euo pipefail
cd ~/source/DuetOS
export PATH="/usr/lib/llvm-18/bin:${PATH}"
MAX_ATTEMPTS="${1:-20}"
for i in $(seq 1 "${MAX_ATTEMPTS}"); do
  echo "=== attempt ${i}/${MAX_ATTEMPTS} ===" >&2
  if DUETOS_TIMEOUT=120 tools/test/profile-boot-smoke.sh bringup build/x86_64-debug >/tmp/profile-stdout 2>&1; then
    cp -f build/x86_64-debug/smoke-bringup.log /mnt/c/Users/natew/AppData/Local/Temp/bringup-pass.log
    echo "PASS — log copied to /mnt/c/Users/natew/AppData/Local/Temp/bringup-pass.log"
    exit 0
  else
    echo "  FAIL"
  fi
done
exit 1
