#!/bin/bash

# DuetOS Wiki Quality Checks
# - Detect stale hardcoded metrics in top-level pages
# - Ensure wiki authoring template and contributing guidance exist
# - Flag pages without YAML-style audience/scope frontmatter blocks
#
# Adapted from Krilliac/SparkEngine tools/check-wiki-quality.sh.
#
# Usage:
#   ./check-wiki-quality.sh            # strict (exit 1 on issues)
#   ./check-wiki-quality.sh --warn-only

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
WIKI_DIR="$PROJECT_ROOT/wiki"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info()    { echo -e "${BLUE}[WIKI-QUALITY]${NC} $1"; }
log_success() { echo -e "${GREEN}[WIKI-QUALITY]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WIKI-QUALITY]${NC} $1"; }

WARN_ONLY=false
if [ "${1:-check}" = "--warn-only" ]; then
    WARN_ONLY=true
fi

ISSUES=0

check_no_pattern() {
    local file="$1"
    local pattern="$2"
    local description="$3"

    if grep -nE "$pattern" "$file" >/dev/null 2>&1; then
        log_warning "$description found in $(basename "$file")"
        grep -nE "$pattern" "$file" || true
        ISSUES=$((ISSUES + 1))
    fi
}

log_info "Running wiki quality checks..."

if [ ! -d "$WIKI_DIR" ]; then
    log_warning "Wiki directory $WIKI_DIR does not exist"
    exit 1
fi

if [ ! -f "$WIKI_DIR/_Template.md" ]; then
    log_warning "Missing wiki/_Template.md"
    ISSUES=$((ISSUES + 1))
fi

CONTRIBUTING_FILE="$WIKI_DIR/advanced/Contributing.md"
if [ ! -f "$CONTRIBUTING_FILE" ]; then
    log_warning "Missing $CONTRIBUTING_FILE"
    ISSUES=$((ISSUES + 1))
elif ! grep -qE "Wiki Authoring Standard" "$CONTRIBUTING_FILE"; then
    log_warning "Contributing.md does not include 'Wiki Authoring Standard' section"
    ISSUES=$((ISSUES + 1))
fi

# Stale hardcoded numbers in headlining pages — these change every commit and
# must come from the auto-sync block, not be baked into prose.
STALE_PATTERNS='29 userland DLLs|~760 exports|~57 numbered calls|33 slices'
HOME_FILE="$WIKI_DIR/Home.md"
if [ -f "$HOME_FILE" ]; then
    if grep -qE "$STALE_PATTERNS" "$HOME_FILE"; then
        log_warning "Hardcoded count phrasing in $(basename "$HOME_FILE") — prefer the AUTO:stats block"
        grep -nE "$STALE_PATTERNS" "$HOME_FILE" || true
        ISSUES=$((ISSUES + 1))
    fi
fi

# Pages should declare audience or scope at the top — flag pages that look like
# stubs (single-paragraph, no headings beyond the title).
log_info "Checking for stub-like pages..."
while IFS= read -r mdfile; do
    [ -f "$mdfile" ] || continue
    local_name=$(basename "$mdfile")
    [ "$local_name" = "_Sidebar.md" ] && continue
    [ "$local_name" = "_Template.md" ] && continue

    # Count headings beyond the title
    heading_count=$(grep -cE '^##[^#]' "$mdfile" 2>/dev/null)
    heading_count=${heading_count:-0}
    if [ "$heading_count" -lt 2 ] 2>/dev/null; then
        log_warning "  $local_name has fewer than 2 second-level headings (looks like a stub)"
        ISSUES=$((ISSUES + 1))
    fi
done < <(find "$WIKI_DIR" -name '*.md' ! -name '_*.md')

if [ "$ISSUES" -eq 0 ]; then
    log_success "Wiki quality checks passed"
    exit 0
fi

if [ "$WARN_ONLY" = true ]; then
    log_warning "$ISSUES issue(s) detected (warn-only mode)"
    exit 0
fi

log_warning "$ISSUES issue(s) detected"
exit 1
