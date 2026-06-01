#!/usr/bin/env bash
# claim.sh — Register this Claude Code session as owning a subsystem.
#
# Part of the DuetOS parallel-session protocol (see CLAUDE_PARALLEL.md).
# Multiple concurrent sessions coordinate file ownership through a single
# tracked coordinator file, PARALLEL_WORK.md, at the repo root.
#
# Usage:   tools/parallel/claim.sh <subsystem> <files_or_dirs> [description]
# Example: tools/parallel/claim.sh win32-com "subsystems/win32/ole32/*" "COM/IDispatch"
#
# Env:
#   CLAUDE_SESSION_ID  — overrides the session identifier (default: host-PID).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$PROJECT_ROOT"

WORK_FILE="PARALLEL_WORK.md"
SESSION_ID="${CLAUDE_SESSION_ID:-$(hostname)-$$}"
TIMESTAMP="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

SUBSYSTEM="${1:-}"
FILES="${2:-}"
DESCRIPTION="${3:-No description provided}"

if [[ -z "$SUBSYSTEM" || -z "$FILES" ]]; then
    echo "Usage: $0 <subsystem> <files_or_dirs> [description]"
    echo "Example: $0 win32-com 'subsystems/win32/ole32/*' 'COM/IDispatch'"
    exit 1
fi

# Branch model: DuetOS sessions live on claude/* branches (the web harness
# checks one out per session). If we are already on such a branch, claim
# against it; otherwise derive claude/<subsystem>.
CURRENT_BRANCH="$(git rev-parse --abbrev-ref HEAD)"
if [[ "$CURRENT_BRANCH" == claude/* ]]; then
    BRANCH="$CURRENT_BRANCH"
else
    BRANCH="claude/${SUBSYSTEM}"
fi

# Pull latest before claiming so the coordinator reflects merged work.
echo "→ Syncing with origin/main..."
git fetch origin main
git rebase origin/main 2>/dev/null || echo "  (rebase skipped — resolve manually if behind)"

# Warn if the target files look already-claimed. Match the files string as a
# fixed literal ('*' etc. must not be treated as regex).
if [[ -f "$WORK_FILE" ]] && grep -qF -- "Files: \`${FILES}\`" "$WORK_FILE"; then
    echo "⚠️  WARNING: '$FILES' may already be claimed by another session:"
    grep -B2 -A2 -F -- "Files: \`${FILES}\`" "$WORK_FILE" || true
    read -rp "Continue anyway? [y/N] " confirm
    [[ "$confirm" =~ ^[Yy]$ ]] || exit 1
fi

# Bootstrap the coordinator file on first use.
if [[ ! -f "$WORK_FILE" ]]; then
    cat > "$WORK_FILE" <<'EOF'
# Parallel Work Coordinator

Auto-managed by tools/parallel/claim.sh and release.sh — do not edit by hand.

## Active Sessions
EOF
fi

# Append the claim entry.
cat >> "$WORK_FILE" <<EOF

### 🟢 ${SUBSYSTEM}
- **Session**: \`${SESSION_ID}\`
- **Branch**: \`${BRANCH}\`
- **Files**: \`${FILES}\`
- **Description**: ${DESCRIPTION}
- **Claimed**: ${TIMESTAMP}
- **Status**: IN PROGRESS
EOF

# Ensure we are on the session branch.
if [[ "$BRANCH" != "$CURRENT_BRANCH" ]]; then
    if git show-ref --quiet "refs/heads/${BRANCH}"; then
        echo "→ Checking out existing branch '${BRANCH}'..."
        git checkout "${BRANCH}"
    else
        echo "→ Creating branch '${BRANCH}'..."
        git checkout -b "${BRANCH}"
    fi
fi

git add "$WORK_FILE"
git commit -m "chore: claim subsystem '${SUBSYSTEM}' [session ${SESSION_ID}]" || true

echo ""
echo "✅ Claimed: ${SUBSYSTEM}"
echo "   Branch:  ${BRANCH}"
echo "   Files:   ${FILES}"
echo "   Session: ${SESSION_ID}"
echo ""
echo "When done: tools/parallel/release.sh ${SUBSYSTEM}"
