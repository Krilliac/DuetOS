#!/usr/bin/env bash
set -euo pipefail
cd ~/source/DuetOS
FILES=(
  "kernel/core/session_restore.cpp"
  "kernel/drivers/input/ps2kbd.cpp"
  "kernel/core/boot_bringup.cpp"
)
for f in "${FILES[@]}"; do
  cp "/mnt/c/Users/natew/source/repos/DuetOS/${f}" "${f}"
  clang-format -i "${f}"
  cp "${f}" "/mnt/c/Users/natew/source/repos/DuetOS/${f}"
done
echo "formatted ${#FILES[@]} files"
