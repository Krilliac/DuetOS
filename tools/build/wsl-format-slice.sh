#!/usr/bin/env bash
# clang-format the slice-1 file set, then copy results back to the
# Windows working tree. Helper for the result-checks-and-guards session.
set -euo pipefail
cd ~/source/DuetOS
FILES=(
  "kernel/util/result.h"
  "kernel/util/result_check.h"
  "kernel/diag/fix_journal.h"
  "kernel/core/init.h"
  "kernel/core/init.cpp"
  "kernel/core/boot_bringup.cpp"
  "kernel/core/main.cpp"
  "kernel/net/wireless/wdev.h"
  "kernel/net/wireless/wdev.cpp"
  "kernel/net/wireless/mlme.cpp"
)
for f in "${FILES[@]}"; do
  clang-format -i "${f}"
  cp "${f}" "/mnt/c/Users/natew/source/repos/DuetOS/${f}"
done
echo "formatted ${#FILES[@]} files"
