#!/usr/bin/env bash
# status.sh — parse and report coordinator integrity and scope intersections.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$PROJECT_ROOT"

if command -v python3 >/dev/null 2>&1; then
    PYTHON_BIN="python3"
elif command -v python >/dev/null 2>&1; then
    PYTHON_BIN="python"
else
    echo "Error: Python 3 is required for parallel status validation." >&2
    exit 1
fi

GUARD="$SCRIPT_DIR/claims_guard.py"
WORK_FILE="PARALLEL_WORK.md"
GIT_COMMON_DIR="$(git rev-parse --path-format=absolute --git-common-dir)"
HOLDER_PID="$$"
case "${OSTYPE:-}" in
    msys*|cygwin*)
        NATIVE_PID="$(ps -p "$$" | awk 'NR == 2 { print $4 }')"
        [[ "$NATIVE_PID" =~ ^[0-9]+$ ]] && HOLDER_PID="$NATIVE_PID"
        ;;
esac
LOCK_TIMEOUT="${DUETOS_PARALLEL_LOCK_TIMEOUT:-15}"
LOCK_STALE_AFTER="${DUETOS_PARALLEL_LOCK_STALE_AFTER:-600}"
LOCK_TOKEN=""

cleanup() {
    local rc=$?
    trap - EXIT INT TERM
    if [[ -n "$LOCK_TOKEN" ]]; then
        if ! "$PYTHON_BIN" "$GUARD" lock-release \
            --common-dir "$GIT_COMMON_DIR" --token "$LOCK_TOKEN"; then
            echo "Error: failed to release the parallel coordinator lock." >&2
            [[ $rc -ne 0 ]] || rc=1
        fi
    fi
    exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

LOCK_TOKEN="$("$PYTHON_BIN" "$GUARD" lock-acquire \
    --common-dir "$GIT_COMMON_DIR" \
    --operation status \
    --timeout "$LOCK_TIMEOUT" \
    --stale-after "$LOCK_STALE_AFTER" \
    --holder-pid "$HOLDER_PID" \
    --holder-host "$(hostname)")"

set +e
"$PYTHON_BIN" "$GUARD" status --file "$WORK_FILE"
STATUS_RC=$?
set -e

"$PYTHON_BIN" "$GUARD" lock-release \
    --common-dir "$GIT_COMMON_DIR" --token "$LOCK_TOKEN"
LOCK_TOKEN=""
exit "$STATUS_RC"
