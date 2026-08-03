#!/usr/bin/env bash
# release.sh — atomically complete, publish, and optionally fast-forward a claim.

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
    echo "Error: Python 3 is required for parallel release validation." >&2
    exit 1
fi

usage() {
    echo "Usage: $0 <subsystem> [--merge]" >&2
}

die() {
    echo "Error: $*" >&2
    exit 1
}

if [[ $# -lt 1 || $# -gt 2 ]]; then
    usage
    exit 1
fi
SUBSYSTEM="$1"
MERGE_FLAG="${2:-}"
[[ -n "$SUBSYSTEM" ]] || die "subsystem cannot be empty"
[[ -z "$MERGE_FLAG" || "$MERGE_FLAG" == "--merge" ]] || {
    usage
    exit 1
}
[[ -f "$WORK_FILE" ]] || die "$WORK_FILE not found; nothing to release"

git rev-parse --is-inside-work-tree >/dev/null 2>&1 || die "not inside a Git worktree"
BRANCH="$(git symbolic-ref --quiet --short HEAD)" || die "detached HEAD cannot release a claim"
[[ "$BRANCH" == claude/* ]] || die "release from the claude/* branch that owns the claim"
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
    --operation "release:${SUBSYSTEM}" \
    --timeout "$LOCK_TIMEOUT" \
    --stale-after "$LOCK_STALE_AFTER" \
    --holder-pid "$HOLDER_PID" \
    --holder-host "$(hostname)")" || die "could not acquire coordinator lock"

COORDINATOR_STATE="$(git status --porcelain=v1 --untracked-files=all -- "$WORK_FILE")"
[[ -z "$COORDINATOR_STATE" ]] || \
    die "$WORK_FILE must be clean before release (unrelated dirty files are allowed without --merge)"
if [[ "$MERGE_FLAG" == "--merge" ]]; then
    [[ -z "$(git status --porcelain=v1 --untracked-files=all)" ]] || \
        die "--merge requires a completely clean worktree and index"
fi

REMOTE_REF="refs/heads/${BRANCH}"
REMOTE_TRACKING_REF="refs/remotes/origin/${BRANCH}"
REMOTE_LINE="$(git ls-remote --heads origin "$REMOTE_REF")" || \
    die "could not query origin/${BRANCH}"
[[ -n "$REMOTE_LINE" ]] || die "origin/${BRANCH} does not exist; publish the claim before releasing it"
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
    die "origin/${BRANCH} is not an ancestor of HEAD; reconcile manually before release"

"$PYTHON_BIN" "$GUARD" complete-claim \
    --file "$WORK_FILE" --subsystem "$SUBSYSTEM" --timestamp "$TIMESTAMP" \
    --branch "$BRANCH"

git add -- "$WORK_FILE"
set +e
git diff --cached --quiet -- "$WORK_FILE"
STAGED_RC=$?
set -e
[[ $STAGED_RC -eq 1 ]] || {
    [[ $STAGED_RC -eq 0 ]] && die "coordinator mutation produced no staged release"
    die "could not inspect the staged coordinator release"
}
git commit -s -m "feat(${SUBSYSTEM}): complete subsystem [session ${SESSION_ID}]" -- "$WORK_FILE" || \
    die "signed coordinator release commit failed"
RELEASE_COMMIT="$(git rev-parse HEAD)" || die "cannot resolve release commit"

mapfile -t RELEASE_PATHS < <(git diff-tree --no-commit-id --name-only -r "$RELEASE_COMMIT")
[[ ${#RELEASE_PATHS[@]} -eq 1 && "${RELEASE_PATHS[0]}" == "$WORK_FILE" ]] || \
    die "release commit contains paths other than ${WORK_FILE}"
git log -1 --format=%B "$RELEASE_COMMIT" | grep -q '^Signed-off-by: ' || \
    die "release commit is missing a Signed-off-by trailer"

git push -u origin "HEAD:${REMOTE_REF}" || die "normal release push failed"
VERIFIED_LINE="$(git ls-remote --exit-code --heads origin "$REMOTE_REF")" || \
    die "could not verify the published release"
VERIFIED_OID="${VERIFIED_LINE%%[[:space:]]*}"
[[ "$VERIFIED_OID" == "$RELEASE_COMMIT" ]] || \
    die "remote branch head does not equal the signed release commit"

if [[ "$MERGE_FLAG" == "--merge" ]]; then
    [[ -z "$(git status --porcelain=v1 --untracked-files=all)" ]] || \
        die "worktree became dirty before --merge"
    MAIN_REMOTE_REF="refs/heads/main"
    MAIN_TRACKING_REF="refs/remotes/origin/main"
    MAIN_LINE="$(git ls-remote --exit-code --heads origin "$MAIN_REMOTE_REF")" || \
        die "could not query origin/main"
    MAIN_ADVERTISED_OID="${MAIN_LINE%%[[:space:]]*}"
    git fetch --no-tags origin "${MAIN_REMOTE_REF}:${MAIN_TRACKING_REF}" || \
        die "origin/main was rewritten or could not be fetched"
    MAIN_FETCHED_OID="$(git rev-parse --verify "$MAIN_TRACKING_REF")" || \
        die "cannot resolve fetched origin/main"
    LOCAL_MAIN_OID="$(git rev-parse --verify refs/heads/main)" || \
        die "local main does not exist"
    [[ "$MAIN_FETCHED_OID" == "$MAIN_ADVERTISED_OID" ]] || \
        die "origin/main changed during fetch"
    [[ "$LOCAL_MAIN_OID" == "$MAIN_FETCHED_OID" ]] || \
        die "local main is stale, ahead, or diverged from origin/main"
    git merge-base --is-ancestor "$MAIN_FETCHED_OID" "$RELEASE_COMMIT" || \
        die "session branch cannot fast-forward main"

    git switch main || die "could not switch to main"
    git merge --ff-only "$BRANCH" || die "non-fast-forward main merge refused"
    [[ "$(git rev-parse HEAD)" == "$RELEASE_COMMIT" ]] || \
        die "fast-forward main did not land on the verified release commit"
    git push origin "HEAD:${MAIN_REMOTE_REF}" || die "normal main push failed"
    MAIN_VERIFIED_LINE="$(git ls-remote --exit-code --heads origin "$MAIN_REMOTE_REF")" || \
        die "could not verify pushed main"
    [[ "${MAIN_VERIFIED_LINE%%[[:space:]]*}" == "$RELEASE_COMMIT" ]] || \
        die "remote main does not equal the verified release commit"
    git switch "$BRANCH" || die "merged, but could not switch back to ${BRANCH}"
fi

"$PYTHON_BIN" "$GUARD" lock-release \
    --common-dir "$GIT_COMMON_DIR" --token "$LOCK_TOKEN" || \
    die "could not release coordinator lock after publication"
LOCK_TOKEN=""

echo
echo "Released and published: ${SUBSYSTEM}"
echo "  Branch: ${BRANCH}"
echo "  Commit: ${RELEASE_COMMIT}"
if [[ "$MERGE_FLAG" == "--merge" ]]; then
    echo "  Main:   fast-forwarded and verified"
fi
echo
echo "Another session may now claim this scope."
