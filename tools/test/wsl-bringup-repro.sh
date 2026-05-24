#!/usr/bin/env bash
# Loop bringup smoke until we get a failure (hang/regression),
# preserve the failing log to /tmp/bringup-fail.log, and print
# the tail. Helper for PR #336's intermittent hang investigation.
set -euo pipefail
cd ~/source/DuetOS
export PATH="/usr/lib/llvm-18/bin:${PATH}"
MAX_ATTEMPTS="${1:-20}"
for i in $(seq 1 "${MAX_ATTEMPTS}"); do
  echo "=== attempt ${i}/${MAX_ATTEMPTS} ===" >&2
  if DUETOS_TIMEOUT=120 tools/test/profile-boot-smoke.sh bringup build/x86_64-debug >/tmp/profile-stdout 2>&1; then
    echo "  PASS"
  else
    rc=$?
    echo "  FAIL rc=${rc}"
    cp -f build/x86_64-debug/smoke-bringup.log /tmp/bringup-fail.log
    cp -f build/x86_64-debug/smoke-bringup.log /mnt/c/Users/natew/AppData/Local/Temp/bringup-fail.log
    echo "--- profile-stdout tail ---"
    tail -20 /tmp/profile-stdout
    echo "--- smoke log tail (60 lines) ---"
    tail -60 /tmp/bringup-fail.log
    echo "(full log copied to /mnt/c/Users/natew/AppData/Local/Temp/bringup-fail.log)"
    exit 0
  fi
done
echo "No failure in ${MAX_ATTEMPTS} attempts" >&2
exit 1
