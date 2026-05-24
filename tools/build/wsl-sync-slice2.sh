#!/usr/bin/env bash
# Sync slice-2 file set from /mnt/c to ~/source/DuetOS and rebuild +
# format. Helper for the result-checks-and-guards session.
set -euo pipefail
FILES=(
  "kernel/syscall/syscall.cpp"
  "kernel/subsystems/linux/extra_syscalls.cpp"
  "kernel/subsystems/linux/syscall_clone.cpp"
  "kernel/subsystems/linux/syscall_cred.cpp"
  "kernel/subsystems/linux/syscall_mm.cpp"
  "kernel/subsystems/linux/syscall_stub.cpp"
)
for f in "${FILES[@]}"; do
  cp "/mnt/c/Users/natew/source/repos/DuetOS/${f}" "/root/source/DuetOS/${f}"
done
cd ~/source/DuetOS
for f in "${FILES[@]}"; do
  clang-format -i "${f}"
  cp "${f}" "/mnt/c/Users/natew/source/repos/DuetOS/${f}"
done
echo "synced + formatted ${#FILES[@]} files"
