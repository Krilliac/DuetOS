#!/usr/bin/env bash
# status.sh — Show the current parallel-session state.
#
# Part of the DuetOS parallel-session protocol (see CLAUDE_PARALLEL.md).
#
# Usage: tools/parallel/status.sh

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$PROJECT_ROOT" || exit 1

WORK_FILE="PARALLEL_WORK.md"

if [[ ! -f "$WORK_FILE" ]]; then
    echo "No active parallel work. PARALLEL_WORK.md not found."
    exit 0
fi

echo ""
echo "═══════════════════════════════════════"
echo "  Parallel Session Status"
echo "═══════════════════════════════════════"
echo ""

# grep -c prints "0" AND exits 1 on no match, so a bare '|| echo 0' would
# emit the count twice. '|| true' keeps grep's own "0" and clears the status.
ACTIVE="$(grep -c "🟢" "$WORK_FILE" 2>/dev/null || true)"
DONE="$(grep -c "✅" "$WORK_FILE" 2>/dev/null || true)"

echo "  Active: ${ACTIVE}  |  Completed: ${DONE}"
echo ""

# Print each session block (everything from one '### ' header to the next).
awk '
    /^### / {
        if (block) print block "\n"
        block = $0
        next
    }
    block { block = block "\n" $0 }
    END { if (block) print block }
' "$WORK_FILE"

echo ""
echo "═══════════════════════════════════════"
echo ""
echo "Conflict check:"

# Collect the Files value of each ACTIVE (🟢) claim and look for duplicates —
# two live sessions owning the same path is the real conflict. Completed
# claims have released their files, so they're excluded.
FILES_LIST="$(awk '
    /^### / { active = ($0 ~ /🟢/) }
    active && /\*\*Files\*\*:/ {
        v = $0; sub(/^[^`]*`/, "", v); sub(/`.*/, "", v); print v
    }
' "$WORK_FILE")"
DUPES="$(printf '%s\n' "$FILES_LIST" | sort | uniq -d | grep -v '^$' || true)"
if [[ -n "$DUPES" ]]; then
    echo "  ⚠️  POTENTIAL CONFLICT on:"
    printf '     %s\n' "$DUPES"
else
    echo "  ✅ No file conflicts detected."
fi
echo ""
