#!/usr/bin/env bash
# wsl-tree-paths.sh — resolve the two trees the WSL helper scripts shuttle
# files between, and refuse to guess.
#
# Sourced, never executed:
#     source "$(dirname "${BASH_SOURCE[0]}")/wsl-tree-paths.sh"
#
# The WSL helpers keep a Linux-native build tree (fast, CMake-capable) beside
# the Windows working tree (what the editor and git see), and copy files back
# and forth. Each helper used to hardcode both paths. That is a live hazard:
# the Windows checkout moved from source/repos/DuetOS to
# OneDrive/Documentos/DuetOS, so the literals now name a stale copy — and these
# scripts copy files BACK over the Windows tree, so a stale literal means
# formatting or edits land in a checkout nobody is reading, or a stale file
# overwrites a current one.
#
# Resolution, in order:
#   WIN_TREE  <- $DUETOS_WIN_TREE, else this script's own repo root if it is
#                under /mnt/, else fail.
#   WSL_TREE  <- $DUETOS_WSL_TREE, else /root/scratch/duetos-main if it exists,
#                else fail.
#
# Failing closed is the point: an unset path must stop the script, never fall
# back to a literal that used to be right.

_wtp_die() { echo "ERROR: $*" >&2; exit 2; }

_wtp_is_checkout() { [[ -f "$1/CMakePresets.json" && -d "$1/kernel" ]]; }

_WTP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
_WTP_SELF_ROOT="$(cd "$_WTP_DIR/../.." && pwd)"

if [[ -n "${DUETOS_WIN_TREE:-}" ]]; then
    WIN_TREE="$DUETOS_WIN_TREE"
elif [[ "$_WTP_SELF_ROOT" == /mnt/* ]]; then
    WIN_TREE="$_WTP_SELF_ROOT"
else
    _wtp_die "cannot resolve the Windows tree. Set DUETOS_WIN_TREE=/mnt/c/path/to/DuetOS
       (this script is at '$_WTP_SELF_ROOT', which is not under /mnt/)."
fi

if [[ -n "${DUETOS_WSL_TREE:-}" ]]; then
    WSL_TREE="$DUETOS_WSL_TREE"
elif [[ -d /root/scratch/duetos-main ]]; then
    WSL_TREE=/root/scratch/duetos-main
else
    _wtp_die "cannot resolve the WSL-native tree. Run tools/build/sync-to-wsl-scratch.sh
       first, or set DUETOS_WSL_TREE=/root/scratch/<name>."
fi

_wtp_is_checkout "$WIN_TREE" || _wtp_die "WIN_TREE '$WIN_TREE' is not a DuetOS checkout."
_wtp_is_checkout "$WSL_TREE" || _wtp_die "WSL_TREE '$WSL_TREE' is not a DuetOS checkout."

[[ "$(readlink -f "$WIN_TREE")" != "$(readlink -f "$WSL_TREE")" ]] \
    || _wtp_die "WIN_TREE and WSL_TREE resolve to the same directory."

export WIN_TREE WSL_TREE
