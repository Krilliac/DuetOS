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
# SRC is derived from this script's own location, NOT hardcoded: the
# checkout has moved before (source/repos/DuetOS -> OneDrive/Documentos/DuetOS)
# and the stale literal silently synced — and therefore built and tested — the
# wrong tree. Self-locating means the script always syncs the checkout it is
# part of. Override with DUETOS_SRC=... only if you really mean to.
#
# Usage:
#   wsl.exe -- bash <repo>/tools/build/sync-to-wsl-scratch.sh [dest]
#
# If [dest] is omitted, syncs to /root/scratch/duetos-tactility.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="${DUETOS_SRC:-$(cd "$SCRIPT_DIR/../.." && pwd)}"
DEST=${1:-/root/scratch/duetos-tactility}

if [[ -z "$DEST" || "$DEST" == "/" ]]
then
    echo "ERROR: refusing to sync to '$DEST' — pick a real destination" >&2
    exit 2
fi

# Sanity-check that SRC really is a DuetOS checkout before an rsync --delete
# points at it. Without this a mis-set DUETOS_SRC would happily mirror an
# unrelated directory over the destination.
if [[ ! -f "$SRC/CMakePresets.json" || ! -d "$SRC/kernel" ]]
then
    echo "ERROR: '$SRC' does not look like a DuetOS checkout" >&2
    echo "       (expected CMakePresets.json and kernel/ inside it)" >&2
    exit 2
fi

if [[ "$(readlink -f "$SRC")" == "$(readlink -f "$DEST")" ]]
then
    echo "ERROR: refusing to sync '$SRC' onto itself" >&2
    exit 2
fi

echo "source -> $SRC"
mkdir -p "$DEST"
rsync -a --delete \
    --exclude=/build --exclude=/.git --exclude=node_modules \
    --exclude='*.log' --exclude='cmake-build-*' \
    --exclude='.vs' --exclude='.vscode' \
    --exclude=/.claude/worktrees \
    "$SRC/" "$DEST/"
echo "synced -> $DEST"
