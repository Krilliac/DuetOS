#!/usr/bin/env bash
# release.sh — Mark a subsystem complete, push the session branch, optionally merge.
#
# Part of the DuetOS parallel-session protocol (see CLAUDE_PARALLEL.md).
#
# Usage:   tools/parallel/release.sh <subsystem> [--merge]
# Example: tools/parallel/release.sh win32-com
#          tools/parallel/release.sh win32-com --merge
#
# --merge is the explicit opt-in that DuetOS requires before touching main.
# Only use it when CI is green on the branch and the work has no in-flight
# dependency on another session.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$PROJECT_ROOT"

WORK_FILE="PARALLEL_WORK.md"
SESSION_ID="${CLAUDE_SESSION_ID:-$(hostname)-$$}"
TIMESTAMP="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

SUBSYSTEM="${1:-}"
MERGE_FLAG="${2:-}"

if [[ -z "$SUBSYSTEM" ]]; then
    echo "Usage: $0 <subsystem> [--merge]"
    exit 1
fi

if [[ ! -f "$WORK_FILE" ]]; then
    echo "❌ $WORK_FILE not found. Nothing to release."
    exit 1
fi

# Derive the session branch the same way claim.sh did.
CURRENT_BRANCH="$(git rev-parse --abbrev-ref HEAD)"
if [[ "$CURRENT_BRANCH" == claude/* ]]; then
    BRANCH="$CURRENT_BRANCH"
else
    BRANCH="claude/${SUBSYSTEM}"
fi

# Flip the subsystem's marker 🟢 → ✅ and stamp completion on its Status line.
awk -v subsystem="$SUBSYSTEM" -v timestamp="$TIMESTAMP" '
    /^### 🟢 / && $3 == subsystem { sub(/🟢/, "✅"); found = 1 }
    found && /- \*\*Status\*\*: IN PROGRESS/ {
        sub(/IN PROGRESS/, "COMPLETED @ " timestamp); found = 0
    }
    { print }
' "$WORK_FILE" > "${WORK_FILE}.tmp" && mv "${WORK_FILE}.tmp" "$WORK_FILE"

git add -A
git commit -m "feat(${SUBSYSTEM}): complete subsystem [session ${SESSION_ID}]" \
    || echo "→ Nothing new to commit."

echo "→ Pushing ${BRANCH}..."
git push -u origin "${BRANCH}" --force-with-lease

echo ""
echo "✅ Released: ${SUBSYSTEM} (branch ${BRANCH} pushed)"

if [[ "$MERGE_FLAG" == "--merge" ]]; then
    echo "→ Merging ${BRANCH} into main (explicit --merge)..."
    git checkout main
    git pull origin main
    git merge "${BRANCH}" --no-ff \
        -m "merge(${SUBSYSTEM}): integrate session branch [${TIMESTAMP}]"
    git push origin main
    git checkout "${BRANCH}"
    echo "✅ Merged into main."
fi

echo ""
echo "Next: another session can now safely claim files in this subsystem."
