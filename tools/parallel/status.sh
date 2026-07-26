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

# Status text is the machine-readable contract. Heading emoji are presentation
# only; matching them is unreliable in some Git-for-Windows text-tool builds.
# grep -c prints "0" and exits 1 on no match, so `|| true` preserves one count.
ACTIVE="$(grep -c '^- \*\*Status\*\*: IN PROGRESS$' "$WORK_FILE" 2>/dev/null || true)"
DONE="$(grep -c '^- \*\*Status\*\*: COMPLETED @ ' "$WORK_FILE" 2>/dev/null || true)"

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

# Collect the Files value of each active claim and look for duplicates. Two
# live sessions owning the same path is the real conflict; completed claims
# have released their files and are excluded.
FILES_LIST="$(awk '
    function flush() {
        if (active && files != "") print files
        active = 0; files = ""
    }
    /^### / { flush(); next }
    /\*\*Files\*\*:/ {
        files = $0
        sub(/^[^`]*`/, "", files)
        sub(/`.*/, "", files)
    }
    /^- \*\*Status\*\*: IN PROGRESS$/ { active = 1 }
    END { flush() }
' "$WORK_FILE")"
DUPES="$(printf '%s\n' "$FILES_LIST" | sort | uniq -d | grep -v '^$' || true)"
if [[ -n "$DUPES" ]]; then
    echo "  ⚠️  POTENTIAL CONFLICT on:"
    printf '     %s\n' "$DUPES"
else
    echo "  ✅ No file conflicts detected."
fi
echo ""
