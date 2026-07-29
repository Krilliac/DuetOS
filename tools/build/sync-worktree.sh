#!/usr/bin/env bash
#
# sync-worktree.sh — mirror a Windows-hosted DuetOS checkout into a WSL
#                    worktree so it can actually be compiled.
#
# WHAT:
#   rsync (or cp -r fallback) the tracked source tree from a checkout on
#   /mnt/c into a native-ext4 worktree, stripping CR line endings from the
#   text files that the Windows side may have written with CRLF.
#
# WHY:
#   The kernel CANNOT be built over /mnt/c: the 9p mount returns EINVAL for
#   some of the build's file operations, and CRLF confuses the assembler and
#   the shell fixture builders. Every session that edits on Windows and
#   compiles in WSL re-derives this script; committing it pays that cost once.
#
# USAGE:
#   tools/build/sync-worktree.sh <windows-checkout> <wsl-worktree>
#
#   e.g. tools/build/sync-worktree.sh \
#          /mnt/c/Users/me/src/DuetOS/.claude/worktrees/agent-xyz  ~/duet-lane
#
# NOTES:
#   - Copies WORKING-TREE state, not git state. The destination keeps its own
#     .git; nothing is committed or pushed here.
#   - Direction is one-way by design: Windows -> WSL. Never sync back, or a
#     WSL build artefact can overwrite an edit you have not committed.
#
# QUICK CHECK (after a sync):
#   diff -rq --exclude=.git <src> <dst> | head

set -euo pipefail

if [[ $# -ne 2 ]]; then
    echo "usage: $0 <windows-checkout> <wsl-worktree>" >&2
    exit 2
fi

SRC="${1%/}"
DST="${2%/}"

if [[ ! -d "${SRC}" ]]; then
    echo "error: source checkout not found: ${SRC}" >&2
    exit 2
fi
if [[ ! -d "${DST}" ]]; then
    echo "error: destination worktree not found: ${DST}" >&2
    exit 2
fi
case "${DST}" in
    /mnt/*)
        echo "error: destination is on /mnt — the build cannot run there" >&2
        exit 2
        ;;
esac

# Anchor every exclude to the transfer root with a leading '/'. An
# unanchored 'build' also matches tools/build, which silently stops the
# build helpers from ever reaching the WSL side — a failure that looks
# like "my edit did nothing" rather than like a sync bug.
EXCLUDES=(--exclude '/.git' --exclude '/build' --exclude '/.claude/worktrees')

if command -v rsync >/dev/null 2>&1; then
    rsync -a --delete "${EXCLUDES[@]}" "${SRC}/" "${DST}/"
else
    # cp fallback: no --delete semantics, so stale files can linger. Good
    # enough for an incremental compile loop; use rsync when you can.
    (cd "${SRC}" && tar --exclude=./.git --exclude=./build --exclude=./.claude/worktrees -cf - .) \
        | (cd "${DST}" && tar -xf -)
fi

# Strip CR from the text the toolchain parses. Binary fixtures and the .git
# directory are excluded above, so this is safe to run over the whole tree.
find "${DST}" -type f \
    \( -name '*.c' -o -name '*.h' -o -name '*.cpp' -o -name '*.hpp' -o -name '*.rs' \
       -o -name '*.S' -o -name '*.asm' -o -name '*.sh' -o -name '*.py' -o -name '*.def' \
       -o -name 'CMakeLists.txt' -o -name '*.cmake' -o -name '*.json' \) \
    -exec sed -i 's/\r$//' {} +

# Shell fixtures must stay executable across the copy.
find "${DST}/tools" "${DST}/userland" -type f -name '*.sh' -exec chmod +x {} + 2>/dev/null || true

echo "[sync-worktree] ${SRC} -> ${DST} done"
