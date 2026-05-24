#!/usr/bin/env bash
set -euo pipefail
export PATH="/usr/lib/llvm-18/bin:${PATH}"
cd ~/source/DuetOS
DUETOS_PRESET=x86_64-release tools/qemu/screenshot.sh /mnt/c/Users/natew/AppData/Local/Temp/desktop.png 2>&1 | tail -10
echo "screenshot written to /mnt/c/Users/natew/AppData/Local/Temp/desktop.png"
