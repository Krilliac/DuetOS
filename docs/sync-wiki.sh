#!/bin/bash

# DuetOS Wiki Synchronization Script
# Scans the codebase and updates wiki pages with accurate, current information.
# Designed to run in any environment (no external doc generators needed).
#
# Adapted from Krilliac/SparkEngine docs/sync-wiki.sh.
#
# What it does:
#   1. Scans kernel/, drivers, subsystems, userland for syscalls, drivers, DLLs
#   2. Updates auto-generated sections in existing wiki pages (between markers)
#   3. Updates Home.md feature list and statistics
#   4. Flags wiki pages that reference files/classes that no longer exist
#
# Usage:
#   ./sync-wiki.sh              # Full sync (default)
#   ./sync-wiki.sh check        # Dry-run: report what's out of date
#   ./sync-wiki.sh status       # Show sync status

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
WIKI_DIR="$PROJECT_ROOT/wiki"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info()    { echo -e "${BLUE}[WIKI-SYNC]${NC} $1"; }
log_success() { echo -e "${GREEN}[WIKI-SYNC]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WIKI-SYNC]${NC} $1"; }
log_error()   { echo -e "${RED}[WIKI-SYNC]${NC} $1"; }

CHANGES_MADE=0
WARNINGS=0
CHECK_MODE=false

# ============================================================================
# Helper: Update a block between markers in a file
# Markers: <!-- AUTO:section_name --> ... <!-- /AUTO:section_name -->
# ============================================================================
update_auto_section() {
    local file="$1"
    local section="$2"
    local content="$3"

    local start_marker="<!-- AUTO:${section} -->"
    local end_marker="<!-- /AUTO:${section} -->"

    if ! grep -qF "$start_marker" "$file" 2>/dev/null; then
        return 1
    fi

    local tmpfile
    tmpfile=$(mktemp)

    awk -v start="$start_marker" -v end="$end_marker" -v body="$content" '
        $0 ~ start { print; print body; skip=1; next }
        $0 ~ end   { skip=0 }
        !skip       { print }
    ' "$file" > "$tmpfile"

    if ! diff -q "$file" "$tmpfile" > /dev/null 2>&1; then
        cp "$tmpfile" "$file"
        CHANGES_MADE=$((CHANGES_MADE + 1))
        log_info "  Updated [$section] in $(basename "$file")"
    fi

    rm -f "$tmpfile"
    return 0
}

# ============================================================================
# Collect codebase inventory
# ============================================================================
collect_inventory() {
    local tmpfile
    tmpfile=$(mktemp)

    # --- Syscall numbers (from syscall_names.def, X(SYS_NAME, NUMBER) form) ---
    SYSCALL_LIST=""
    if [ -f "$PROJECT_ROOT/kernel/syscall/syscall_names.def" ]; then
        SYSCALL_LIST=$(grep -E '^\s*X\s*\(' "$PROJECT_ROOT/kernel/syscall/syscall_names.def" 2>/dev/null \
            | sed -E 's/^\s*X\s*\(\s*(SYS_[A-Z0-9_]+)\s*,\s*([0-9]+).*/\2|\1/' \
            | sort -t'|' -k1n -u)
    fi
    SYSCALL_COUNT=$(echo "$SYSCALL_LIST" | grep -c '|' || true)

    # --- Capability bits (kCap* enumerators in kernel/proc/process.h) ---
    CAP_LIST=""
    if [ -f "$PROJECT_ROOT/kernel/proc/process.h" ]; then
        CAP_LIST=$(grep -oE '\bkCap[A-Z][A-Za-z0-9_]*' "$PROJECT_ROOT/kernel/proc/process.h" 2>/dev/null \
            | sort -u)
    fi
    CAP_COUNT=$(echo "$CAP_LIST" | grep -c 'kCap' || true)

    # --- Drivers (kernel/drivers/<class>/) ---
    DRIVER_LIST=""
    if [ -d "$PROJECT_ROOT/kernel/drivers" ]; then
        find "$PROJECT_ROOT/kernel/drivers" -mindepth 1 -maxdepth 1 -type d 2>/dev/null \
            | sort > "$tmpfile"
        while IFS= read -r cdir; do
            [ -z "$cdir" ] && continue
            local class
            class=$(basename "$cdir")
            local count
            count=$(find "$cdir" -name '*.cpp' 2>/dev/null | wc -l)
            DRIVER_LIST="${DRIVER_LIST}${class}|${count}|"$'\n'
        done < "$tmpfile"
    fi
    DRIVER_COUNT=$(echo "$DRIVER_LIST" | grep -c '|' || true)

    # --- Userland DLLs (userland/libs/<dll>) ---
    DLL_LIST=""
    DLL_EXPORT_TOTAL=0
    if [ -d "$PROJECT_ROOT/userland/libs" ]; then
        find "$PROJECT_ROOT/userland/libs" -mindepth 1 -maxdepth 1 -type d 2>/dev/null \
            | sort > "$tmpfile"
        while IFS= read -r dlldir; do
            [ -z "$dlldir" ] && continue
            local dll
            dll=$(basename "$dlldir")
            local exports=0
            if [ -d "$dlldir" ]; then
                exports=$(grep -rhE '^\s*DUETOS_EXPORT\b|^\s*WIN32_EXPORT\b' "$dlldir" 2>/dev/null | wc -l)
            fi
            DLL_LIST="${DLL_LIST}${dll}|${exports}\n"
            DLL_EXPORT_TOTAL=$((DLL_EXPORT_TOTAL + exports))
        done < "$tmpfile"
    fi
    DLL_COUNT=$(echo -e "$DLL_LIST" | grep -c '|' || true)

    # --- Tests (tests/) ---
    TEST_FILE_COUNT=0
    if [ -d "$PROJECT_ROOT/tests" ]; then
        TEST_FILE_COUNT=$(find "$PROJECT_ROOT/tests" -name '*.cpp' -o -name '*.c' 2>/dev/null | wc -l)
    fi

    # --- Header / source counts ---
    HEADER_COUNT=0
    SOURCE_COUNT=0
    for d in "$PROJECT_ROOT/kernel" "$PROJECT_ROOT/userland" "$PROJECT_ROOT/boot"; do
        [ -d "$d" ] || continue
        HEADER_COUNT=$((HEADER_COUNT + $(find "$d" \( -name '*.h' -o -name '*.hpp' \) 2>/dev/null | wc -l)))
        SOURCE_COUNT=$((SOURCE_COUNT + $(find "$d" \( -name '*.c' -o -name '*.cpp' -o -name '*.rs' -o -name '*.S' \) 2>/dev/null | wc -l)))
    done

    # --- STUB / GAP markers ---
    STUB_COUNT=0
    GAP_COUNT=0
    if command -v git >/dev/null 2>&1 && [ -d "$PROJECT_ROOT/.git" ]; then
        STUB_COUNT=$(cd "$PROJECT_ROOT" && git grep -nE '// STUB:' 2>/dev/null | wc -l)
        GAP_COUNT=$(cd "$PROJECT_ROOT" && git grep -nE '// GAP:' 2>/dev/null | wc -l)
    fi

    # --- Wiki pages ---
    WIKI_PAGE_COUNT=0
    if [ -d "$WIKI_DIR" ]; then
        WIKI_PAGE_COUNT=$(find "$WIKI_DIR" -name '*.md' ! -name '_*.md' | wc -l)
    fi

    rm -f "$tmpfile"
}

# ============================================================================
# Sync: Syscall ABI page — handler inventory
# ============================================================================
sync_syscall_page() {
    local page="$WIKI_DIR/specifications/Syscall-ABI.md"
    [ -f "$page" ] || return 0

    if ! grep -qF "<!-- AUTO:syscall_list -->" "$page"; then
        {
            echo ""
            echo "## Syscall Handler Inventory"
            echo ""
            echo "<!-- AUTO:syscall_list -->"
            echo "<!-- /AUTO:syscall_list -->"
        } >> "$page"
        CHANGES_MADE=$((CHANGES_MADE + 1))
        log_info "  Added auto-sync markers to Syscall-ABI.md"
    fi

    local body
    body=$(printf '| # | Symbol |\n|---|--------|\n'
        echo "$SYSCALL_LIST" | grep -v '^$' | while IFS='|' read -r num sym; do
            printf '| %s | `%s` |\n' "$num" "$sym"
        done)

    update_auto_section "$page" "syscall_list" "$body"
}

# ============================================================================
# Sync: Capabilities page — capability bit inventory
# ============================================================================
sync_caps_page() {
    local page="$WIKI_DIR/security/Capabilities.md"
    [ -f "$page" ] || return 0

    if ! grep -qF "<!-- AUTO:cap_list -->" "$page"; then
        {
            echo ""
            echo "## Capability Bit Inventory"
            echo ""
            echo "<!-- AUTO:cap_list -->"
            echo "<!-- /AUTO:cap_list -->"
        } >> "$page"
        CHANGES_MADE=$((CHANGES_MADE + 1))
        log_info "  Added auto-sync markers to Capabilities.md"
    fi

    local body
    body=$(printf '| # | Capability |\n|---|------------|\n'
        echo "$CAP_LIST" | grep -v '^$' | nl -ba -w1 -s' ' | while read -r idx name; do
            printf '| %s | `%s` |\n' "$idx" "$name"
        done)

    update_auto_section "$page" "cap_list" "$body"
}

# ============================================================================
# Sync: Driver Overview page
# ============================================================================
sync_drivers_page() {
    local page="$WIKI_DIR/drivers/Driver-Overview.md"
    [ -f "$page" ] || return 0

    if ! grep -qF "<!-- AUTO:driver_list -->" "$page"; then
        {
            echo ""
            echo "## Driver Inventory"
            echo ""
            echo "<!-- AUTO:driver_list -->"
            echo "<!-- /AUTO:driver_list -->"
        } >> "$page"
        CHANGES_MADE=$((CHANGES_MADE + 1))
        log_info "  Added auto-sync markers to Driver-Overview.md"
    fi

    local body
    body=$(printf '| Class | Source files | Path |\n|-------|--------------|------|\n'
        echo "$DRIVER_LIST" | grep -v '^$' | sort -u | while IFS='|' read -r class count _trail; do
            printf '| `%s` | %s | `kernel/drivers/%s/` |\n' "$class" "$count" "$class"
        done)

    update_auto_section "$page" "driver_list" "$body"
}

# ============================================================================
# Sync: Win32 DLLs page
# ============================================================================
sync_win32_dlls_page() {
    local page="$WIKI_DIR/subsystems/Win32-DLLs.md"
    [ -f "$page" ] || return 0

    if ! grep -qF "<!-- AUTO:dll_list -->" "$page"; then
        {
            echo ""
            echo "## Userland DLL Inventory"
            echo ""
            echo "<!-- AUTO:dll_list -->"
            echo "<!-- /AUTO:dll_list -->"
        } >> "$page"
        CHANGES_MADE=$((CHANGES_MADE + 1))
        log_info "  Added auto-sync markers to Win32-DLLs.md"
    fi

    local body
    body=$(printf '*%s DLLs preloaded into every Win32 PE process.*\n\n' "$DLL_COUNT"
        printf '| DLL | Exports (approx) | Path |\n|-----|------------------|------|\n'
        echo -e "$DLL_LIST" | grep -v '^$' | sort | while IFS='|' read -r dll exports; do
            printf '| `%s` | %s | `userland/libs/%s/` |\n' "$dll" "$exports" "$dll"
        done)

    update_auto_section "$page" "dll_list" "$body"
}

# ============================================================================
# Sync: Home.md project statistics
# ============================================================================
sync_home_page() {
    local page="$WIKI_DIR/Home.md"
    [ -f "$page" ] || return 0

    if ! grep -qF "<!-- AUTO:stats -->" "$page"; then
        {
            echo ""
            echo "## Project Statistics"
            echo ""
            echo "<!-- AUTO:stats -->"
            echo "<!-- /AUTO:stats -->"
        } >> "$page"
        CHANGES_MADE=$((CHANGES_MADE + 1))
        log_info "  Added auto-sync markers to Home.md"
    fi

    local last_synced
    if [ "$CHECK_MODE" = true ]; then
        last_synced=$(grep -E '^\| \*Last synced\* \| \*.*\* \|$' "$page" \
            | sed -E 's/^\| \*Last synced\* \| \*(.*)\* \|$/\1/' | head -1)
        [ -n "$last_synced" ] || last_synced="N/A"
    else
        last_synced="$(date '+%Y-%m-%d %H:%M')"
    fi

    local stats_content
    stats_content="| Metric | Count |
|--------|-------|
| Header files | ${HEADER_COUNT} |
| Source files | ${SOURCE_COUNT} |
| Syscalls (numbered) | ${SYSCALL_COUNT} |
| Capability bits | ${CAP_COUNT} |
| Kernel drivers | ${DRIVER_COUNT} |
| Userland DLLs | ${DLL_COUNT} |
| DLL exports (approx) | ${DLL_EXPORT_TOTAL} |
| Test files | ${TEST_FILE_COUNT} |
| STUB markers | ${STUB_COUNT} |
| GAP markers | ${GAP_COUNT} |
| Wiki pages | ${WIKI_PAGE_COUNT} |
| *Last synced* | *${last_synced}* |"

    update_auto_section "$page" "stats" "$stats_content"
}

# ============================================================================
# Check: find wiki references to files that no longer exist
# ============================================================================
check_stale_references() {
    log_info "Checking for stale references in wiki..."

    find "$WIKI_DIR" -name '*.md' | while IFS= read -r wfile; do
        # Linux-source-tree references (drivers/net/..., drivers/usb/..., etc.)
        # in Linux-Networking-Port-Opportunities.md are deliberately external.
        # Win32-Thunks-Compat-Note.md exists specifically to document a rename
        # so it intentionally references the old (missing) stubs.* paths.
        local base
        base=$(basename "$wfile")
        case "$base" in
            Linux-Networking-Port-Opportunities.md|Win32-Thunks-Compat-Note.md)
                continue
                ;;
        esac
        grep -oE '`(kernel|userland|boot|subsystems|tools|tests)/[^`[:space:]]+\.(h|hpp|c|cpp|rs|S|md|sh|py)`' "$wfile" 2>/dev/null \
            | tr -d '`' | sort -u | while read -r ref_path; do
                if [ ! -e "$PROJECT_ROOT/$ref_path" ]; then
                    log_warning "  $(basename "$wfile"): references missing path \`$ref_path\`"
                    WARNINGS=$((WARNINGS + 1))
                fi
            done
    done
}

# ============================================================================
# Sidebar consistency
# ============================================================================
sync_sidebar() {
    local sidebar="$WIKI_DIR/_Sidebar.md"
    [ -f "$sidebar" ] || return 0

    find "$WIKI_DIR" -name '*.md' ! -name '_*.md' | while IFS= read -r wfile; do
        local page_name
        page_name=$(basename "$wfile" .md)
        if ! grep -qF "$page_name" "$sidebar" 2>/dev/null; then
            log_warning "  Wiki page '$page_name' is not listed in _Sidebar.md"
            WARNINGS=$((WARNINGS + 1))
        fi
    done
}

# ============================================================================
# Main
# ============================================================================
main() {
    local command="${1:-sync}"

    case "$command" in
        sync|full)
            log_info "Synchronizing wiki with codebase..."
            echo ""

            collect_inventory

            sync_syscall_page
            sync_caps_page
            sync_drivers_page
            sync_win32_dlls_page
            sync_home_page
            sync_sidebar
            check_stale_references

            echo ""
            if [ "$CHANGES_MADE" -gt 0 ]; then
                log_success "Wiki sync complete: $CHANGES_MADE page(s) updated"
            else
                log_success "Wiki is already up to date"
            fi
            if [ "$WARNINGS" -gt 0 ]; then log_warning "$WARNINGS warning(s) — review above"; fi
            ;;

        check)
            log_info "Dry-run: checking wiki freshness..."
            echo ""
            CHECK_MODE=true

            collect_inventory
            check_stale_references
            sync_sidebar

            local tmpdir
            tmpdir=$(mktemp -d)
            (cd "$WIKI_DIR" && find . -name '*.md' -print0 | \
                while IFS= read -r -d '' rel; do
                    mkdir -p "$tmpdir/$(dirname "$rel")"
                    cp "$rel" "$tmpdir/$rel"
                done)

            sync_syscall_page
            sync_caps_page
            sync_drivers_page
            sync_win32_dlls_page
            sync_home_page

            local stale=0
            while IFS= read -r -d '' mdfile; do
                local rel="${mdfile#$WIKI_DIR/}"
                if [ -f "$tmpdir/$rel" ] && ! diff -q "$mdfile" "$tmpdir/$rel" > /dev/null 2>&1; then
                    log_warning "  $rel is out of date"
                    stale=$((stale + 1))
                fi
            done < <(find "$WIKI_DIR" -name '*.md' -print0)

            (cd "$tmpdir" && find . -name '*.md' -print0 | \
                while IFS= read -r -d '' rel; do
                    cp "$rel" "$WIKI_DIR/$rel"
                done)
            rm -rf "$tmpdir"

            echo ""
            if [ "$stale" -gt 0 ]; then
                log_warning "$stale page(s) need updating. Run: docs/sync-wiki.sh sync"
                exit 1
            else
                log_success "Wiki is up to date"
            fi
            if [ "$WARNINGS" -gt 0 ]; then log_warning "$WARNINGS warning(s) — review above"; fi
            ;;

        status)
            collect_inventory
            echo "======================================================"
            log_info "DuetOS Wiki Sync Status"
            echo "======================================================"
            echo ""
            log_info "Codebase inventory:"
            echo "  Headers:       $HEADER_COUNT"
            echo "  Sources:       $SOURCE_COUNT"
            echo "  Syscalls:      $SYSCALL_COUNT"
            echo "  Caps:          $CAP_COUNT"
            echo "  Drivers:       $DRIVER_COUNT"
            echo "  DLLs:          $DLL_COUNT"
            echo "  DLL exports:   $DLL_EXPORT_TOTAL"
            echo "  Test files:    $TEST_FILE_COUNT"
            echo "  STUB markers:  $STUB_COUNT"
            echo "  GAP markers:   $GAP_COUNT"
            echo ""
            log_info "Wiki:"
            echo "  Pages:         $WIKI_PAGE_COUNT"
            echo "  Directory:     $WIKI_DIR"
            echo "======================================================"
            ;;

        help|-h|--help)
            echo "DuetOS Wiki Synchronization Script"
            echo ""
            echo "Usage: $0 [sync|check|status|help]"
            echo ""
            echo "  sync    Update wiki pages with current codebase data (default)"
            echo "  check   Dry-run: report what's out of date (exits 1 if stale)"
            echo "  status  Show codebase and wiki statistics"
            echo "  help    Show this message"
            echo ""
            echo "Auto-synced wiki pages:"
            echo "  specifications/Syscall-ABI.md  — syscall handler inventory"
            echo "  security/Capabilities.md       — capability bit inventory"
            echo "  drivers/Driver-Overview.md     — kernel driver inventory"
            echo "  subsystems/Win32-DLLs.md       — userland DLL inventory"
            echo "  Home.md                        — project statistics"
            echo "  _Sidebar.md                    — checks for unlisted pages"
            ;;

        *)
            log_error "Unknown command: $command"
            main help
            exit 1
            ;;
    esac
}

main "$@"
