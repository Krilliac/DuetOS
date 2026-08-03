#!/usr/bin/env bash
# claim.sh — atomically register and publish one parallel-work claim.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$PROJECT_ROOT"

WORK_FILE="PARALLEL_WORK.md"
GUARD="$SCRIPT_DIR/claims_guard.py"
SESSION_ID="${CLAUDE_SESSION_ID:-$(hostname)-$$}"
TIMESTAMP="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
LOCK_TIMEOUT="${DUETOS_PARALLEL_LOCK_TIMEOUT:-15}"
LOCK_STALE_AFTER="${DUETOS_PARALLEL_LOCK_STALE_AFTER:-600}"

if command -v python3 >/dev/null 2>&1; then
    PYTHON_BIN="python3"
elif command -v python >/dev/null 2>&1; then
    PYTHON_BIN="python"
else
    echo "Error: Python 3 is required for parallel claim validation." >&2
    exit 1
fi

usage() {
    echo "Usage: $0 <subsystem> <files_or_dirs> [description]" >&2
}

die() {
    echo "Error: $*" >&2
    exit 1
}

if [[ $# -lt 2 || $# -gt 3 ]]; then
    usage
    exit 1
fi

SUBSYSTEM="$1"
FILES="$2"
DESCRIPTION="${3:-No description provided}"
[[ -n "$SUBSYSTEM" ]] || die "subsystem cannot be empty"

git rev-parse --is-inside-work-tree >/dev/null 2>&1 || die "not inside a Git worktree"
CURRENT_BRANCH="$(git symbolic-ref --quiet --short HEAD)" || die "detached HEAD cannot publish a claim"
[[ "$CURRENT_BRANCH" == claude/* ]] || \
    die "claim from a claude/* branch; create/switch the branch before carrying dirty work"
BRANCH="$CURRENT_BRANCH"
GIT_COMMON_DIR="$(git rev-parse --path-format=absolute --git-common-dir)" || \
    die "cannot resolve the Git common directory"
HOLDER_PID="$$"
case "${OSTYPE:-}" in
    msys*|cygwin*)
        NATIVE_PID="$(ps -p "$$" | awk 'NR == 2 { print $4 }')"
        [[ "$NATIVE_PID" =~ ^[0-9]+$ ]] && HOLDER_PID="$NATIVE_PID"
        ;;
esac

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
    --operation "claim:${SUBSYSTEM}" \
    --timeout "$LOCK_TIMEOUT" \
    --stale-after "$LOCK_STALE_AFTER" \
    --holder-pid "$HOLDER_PID" \
    --holder-host "$(hostname)")" || die "could not acquire coordinator lock"

COORDINATOR_STATE="$(git status --porcelain=v1 --untracked-files=all -- "$WORK_FILE")"
[[ -z "$COORDINATOR_STATE" ]] || \
    die "$WORK_FILE must be clean before claiming (unrelated dirty files are allowed)"

CANONICAL_FILES="$("$PYTHON_BIN" "$GUARD" check-claim \
    --file "$WORK_FILE" --subsystem "$SUBSYSTEM" --scopes "$FILES")" || \
    die "claim validation failed"

REMOTE_REF="refs/heads/${BRANCH}"
REMOTE_TRACKING_REF="refs/remotes/origin/${BRANCH}"
REMOTE_LINE="$(git ls-remote --heads origin "$REMOTE_REF")" || \
    die "could not query origin/${BRANCH}"
if [[ -n "$REMOTE_LINE" ]]; then
    [[ "$(printf '%s\n' "$REMOTE_LINE" | wc -l | tr -d ' ')" == "1" ]] || \
        die "origin returned an ambiguous branch ref for ${BRANCH}"
    ADVERTISED_OID="${REMOTE_LINE%%[[:space:]]*}"
    git fetch --no-tags origin "+${REMOTE_REF}:${REMOTE_TRACKING_REF}" || \
        die "failed to fetch origin/${BRANCH}"
    FETCHED_OID="$(git rev-parse --verify "$REMOTE_TRACKING_REF")" || \
        die "fetched origin/${BRANCH} has no verifiable object"
    [[ "$FETCHED_OID" == "$ADVERTISED_OID" ]] || \
        die "origin/${BRANCH} changed during fetch; retry from a fresh state"
    git merge-base --is-ancestor "$FETCHED_OID" HEAD || \
        die "origin/${BRANCH} is not an ancestor of HEAD; reconcile manually before claiming"
fi

"$PYTHON_BIN" "$GUARD" append-claim \
    --file "$WORK_FILE" \
    --subsystem "$SUBSYSTEM" \
    --scopes "$CANONICAL_FILES" \
    --session "$SESSION_ID" \
    --branch "$BRANCH" \
    --description "$DESCRIPTION" \
    --timestamp "$TIMESTAMP"

git add -- "$WORK_FILE"
set +e
git diff --cached --quiet -- "$WORK_FILE"
STAGED_RC=$?
set -e
[[ $STAGED_RC -eq 1 ]] || {
    [[ $STAGED_RC -eq 0 ]] && die "coordinator mutation produced no staged claim"
    die "could not inspect the staged coordinator claim"
}
git commit -s -m "chore: claim subsystem '${SUBSYSTEM}' [session ${SESSION_ID}]" -- "$WORK_FILE" || \
    die "signed coordinator commit failed"
CLAIM_COMMIT="$(git rev-parse HEAD)" || die "cannot resolve claim commit"

mapfile -t CLAIM_PATHS < <(git diff-tree --no-commit-id --name-only -r "$CLAIM_COMMIT")
[[ ${#CLAIM_PATHS[@]} -eq 1 && "${CLAIM_PATHS[0]}" == "$WORK_FILE" ]] || \
    die "claim commit contains paths other than ${WORK_FILE}"
git log -1 --format=%B "$CLAIM_COMMIT" | grep -q '^Signed-off-by: ' || \
    die "claim commit is missing a Signed-off-by trailer"

git push -u origin "HEAD:${REMOTE_REF}" || die "normal claim push failed"
VERIFIED_LINE="$(git ls-remote --exit-code --heads origin "$REMOTE_REF")" || \
    die "could not verify the published claim"
VERIFIED_OID="${VERIFIED_LINE%%[[:space:]]*}"
[[ "$VERIFIED_OID" == "$CLAIM_COMMIT" ]] || \
    die "remote branch head does not equal the signed claim commit"

"$PYTHON_BIN" "$GUARD" lock-release \
    --common-dir "$GIT_COMMON_DIR" --token "$LOCK_TOKEN" || \
    die "could not release coordinator lock after publication"
LOCK_TOKEN=""

echo
echo "Claimed and published: ${SUBSYSTEM}"
echo "  Branch:  ${BRANCH}"
echo "  Files:   ${CANONICAL_FILES}"
echo "  Session: ${SESSION_ID}"
echo "  Commit:  ${CLAIM_COMMIT}"
echo
echo "When done: tools/parallel/release.sh ${SUBSYSTEM}"
