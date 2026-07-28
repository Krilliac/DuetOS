#!/usr/bin/env bash
# Push the slice-2 file set from the Windows tree into the WSL-native tree,
# clang-format it there, then copy the formatted result back.
#
# Both trees are resolved by wsl-tree-paths.sh rather than hardcoded. This
# script copies in BOTH directions, so a stale literal could either overwrite
# current work with an old copy or land formatting in a checkout nobody reads.
# The old literals named source/repos/DuetOS and /root/source/DuetOS, neither
# of which is the active tree any more.
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/wsl-tree-paths.sh"

FILES=(
  "kernel/syscall/syscall.cpp"
  "kernel/subsystems/linux/extra_syscalls.cpp"
  "kernel/subsystems/linux/syscall_clone.cpp"
  "kernel/subsystems/linux/syscall_cred.cpp"
  "kernel/subsystems/linux/syscall_mm.cpp"
  "kernel/subsystems/linux/syscall_stub.cpp"
)
# Validate the whole set before copying anything: a half-applied sync leaves
# the two trees silently diverged, which is worse than not running at all.
for f in "${FILES[@]}"; do
  [[ -f "$WIN_TREE/$f" ]] || { echo "ERROR: missing in $WIN_TREE: $f" >&2; exit 2; }
  [[ -d "$(dirname "$WSL_TREE/$f")" ]] \
      || { echo "ERROR: no destination dir in $WSL_TREE for: $f" >&2; exit 2; }
done

for f in "${FILES[@]}"; do
  cp "$WIN_TREE/${f}" "$WSL_TREE/${f}"
done
cd "$WSL_TREE"
for f in "${FILES[@]}"; do
  clang-format -i "${f}"
  cp "${f}" "$WIN_TREE/${f}"
done
echo "synced + formatted ${#FILES[@]} files between $WIN_TREE and $WSL_TREE"
