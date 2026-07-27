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

# Match the stable ASCII structure, not a display marker whose encoding
# varies between Windows PowerShell, Git Bash, and CI locales.
if ! awk -v subsystem="$SUBSYSTEM" -v timestamp="$TIMESTAMP" '
    $1 == "###" && $3 == subsystem {
        print "### [DONE] " subsystem
        matched = 1
        in_target = 1
        next
    }
    in_target && /- \*\*Status\*\*: IN PROGRESS/ {
        sub(/IN PROGRESS/, "COMPLETED @ " timestamp)
        updated = 1
        in_target = 0
    }
    { print }
    END {
        if (!matched || !updated)
            exit 3
    }
' "$WORK_FILE" > "${WORK_FILE}.tmp"; then
    rm -f -- "${WORK_FILE}.tmp"
    echo "Error: active subsystem '${SUBSYSTEM}' was not found; nothing released." >&2
    exit 1
fi
mv "${WORK_FILE}.tmp" "$WORK_FILE"

# Releasing a coordinator claim must never absorb implementation files
# another fleet lane is still writing. Stage and commit only the
# coordinator record; leave every unrelated staged/unstaged path alone.
git add -- "$WORK_FILE"
if ! git diff --cached --quiet -- "$WORK_FILE"; then
    git commit -s -m "feat(${SUBSYSTEM}): complete subsystem [session ${SESSION_ID}]" -- "$WORK_FILE"
else
    echo "→ Nothing new to commit."
fi

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
