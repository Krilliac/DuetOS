#!/usr/bin/env bash
# Sync the Windows DuetOS checkout (read from /mnt/c) into a clean
# WSL-native scratch directory under /root/scratch/. The /mnt/c
# 9p mount can't host a CMake build (EINVAL + CRLF, per
# .claude/memory/duetos-wsl-build-workflow.md); this script gives
# you a Linux-native copy you can configure + build against.
#
# Idempotent — re-run to pick up freshly-edited files. Uses
# --delete so files removed on the Windows side disappear from
# the scratch copy too.
#
# Usage:
#   wsl.exe -- bash /mnt/c/Users/natew/source/repos/DuetOS/tools/build/sync-to-wsl-scratch.sh [dest]
#
# If [dest] is omitted, syncs to /root/scratch/duetos-tactility.

set -euo pipefail

SRC=/mnt/c/Users/natew/source/repos/DuetOS
DEST=${1:-/root/scratch/duetos-tactility}

if [[ -z "$DEST" || "$DEST" == "/" ]]
then
    echo "ERROR: refusing to sync to '$DEST' — pick a real destination" >&2
    exit 2
fi

mkdir -p "$DEST"
rsync -a --delete \
    --exclude=/build --exclude=/.git --exclude=node_modules \
    --exclude='*.log' --exclude='cmake-build-*' \
    --exclude='.vs' --exclude='.vscode' \
    "$SRC/" "$DEST/"
echo "synced -> $DEST"
