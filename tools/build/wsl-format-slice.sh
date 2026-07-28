#!/usr/bin/env bash
# clang-format the slice-1 file set in the WSL-native tree, then copy the
# results back to the Windows working tree.
#
# Both trees are resolved by wsl-tree-paths.sh rather than hardcoded: this
# script copies files back OVER the Windows checkout, and the old literal
# named source/repos/DuetOS, which is no longer the active checkout.
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/wsl-tree-paths.sh"

cd "$WSL_TREE"
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
# Check the whole set before mutating anything, so a renamed file fails the
# run up front instead of half-way through a back-copy.
for f in "${FILES[@]}"; do
  [[ -f "$f" ]]              || { echo "ERROR: missing in $WSL_TREE: $f" >&2; exit 2; }
  [[ -f "$WIN_TREE/$f" ]]    || { echo "ERROR: missing in $WIN_TREE: $f" >&2; exit 2; }
done
for f in "${FILES[@]}"; do
  clang-format -i "${f}"
  cp "${f}" "$WIN_TREE/${f}"
done
echo "formatted ${#FILES[@]} files -> $WIN_TREE"
