#!/usr/bin/env bash
# Run a smoke profile under WSL with the canonical toolchain on PATH.
# Helper for live-iteration of the bringup hang during PR #336.
set -euo pipefail
PROFILE="${1:-bringup}"
TIMEOUT="${DUETOS_TIMEOUT:-120}"
cd ~/source/DuetOS
export PATH="/usr/lib/llvm-18/bin:${PATH}"
DUETOS_TIMEOUT=${TIMEOUT} exec tools/test/profile-boot-smoke.sh "${PROFILE}" build/x86_64-debug
