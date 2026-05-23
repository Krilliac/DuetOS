#!/usr/bin/env bash
#
# Interactive review + apply for fix-journal generated patches.
#
# The expected workflow:
#   1. Run the OS under QEMU (or on real hardware) — the fix-journal
#      records every breakage class it can intercept into KERNEL.FIX.
#   2. Run tools/qemu/run-fix-cycle.sh to extract KERNEL.FIX and run
#      gen-fix-patches.py against it. With --enable-all-patches the
#      generator emits every real-applicable patch class (thunks,
#      syscall stubs, marker logs, KASSERT demotes, trap guards,
#      OOM nullchecks, fault-react probes, …). Each one is wrapped
#      in `#if 0 ... #endif` so applying is behaviourally a no-op
#      until the reviewer affirmatively flips the gate.
#   3. Run THIS script. For each .patch under fix-patches/, the
#      script shows the diff, asks y/N/edit/skip/quit, and applies
#      the accepted ones to a fresh branch. The reviewer can `e`dit
#      a patch in $EDITOR before applying, which is the modify
#      step the journal->patch automation hands off cleanly.
#   4. Reviewer flips selected `#if 0` -> `#if 1` to activate
#      semantic changes, then commits + pushes the branch.
#
# This is the "review and modify" half of the journal-driven
# auto-patch workflow. It deliberately stops short of `git push`
# and PR creation — those are human-driven, every time, per
# Decision #016.
#
# Usage:
#   tools/qemu/dfix-apply-interactive.sh                       # default
#   tools/qemu/dfix-apply-interactive.sh --fix-out=fix-patches # explicit
#   tools/qemu/dfix-apply-interactive.sh --branch=my-name      # branch
#   tools/qemu/dfix-apply-interactive.sh --dry-run             # show, don't apply
#   tools/qemu/dfix-apply-interactive.sh --auto-yes            # accept all (CI)
#
# Env vars:
#   EDITOR             — used for `e`dit-before-apply (default: vi)
#   DUETOS_FIX_OUT     — patches directory (default: fix-patches/)
#   DUETOS_FIX_BRANCH  — target branch name (default: claude/fix-from-journal-<ts>)
#
# Reusable rig (CLAUDE.md "Reusable Tooling"). Pairs with
# tools/qemu/run-fix-cycle.sh (which PRODUCES the patches) and
# tools/qemu/dfix-to-branch.sh (which is the non-interactive
# bulk-apply variant for CI).

set -euo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

FIX_OUT="${DUETOS_FIX_OUT:-${REPO_ROOT}/fix-patches}"
DRY_RUN=0
AUTO_YES=0
BRANCH_NAME="${DUETOS_FIX_BRANCH:-}"
EDITOR="${EDITOR:-vi}"

for arg in "$@"; do
    case "$arg" in
        --fix-out=*) FIX_OUT="${arg#--fix-out=}" ;;
        --branch=*)  BRANCH_NAME="${arg#--branch=}" ;;
        --dry-run)   DRY_RUN=1 ;;
        --auto-yes)  AUTO_YES=1 ;;
        -h|--help)
            sed -n '2,/^$/p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *) echo "warning: ignoring unknown arg '$arg'" >&2 ;;
    esac
done

if [[ -z "${BRANCH_NAME}" ]]; then
    BRANCH_NAME="claude/fix-from-journal-$(date +%Y%m%d-%H%M%S)"
fi

if [[ ! -d "${FIX_OUT}" ]]; then
    echo "error: ${FIX_OUT} does not exist" >&2
    echo "       run tools/qemu/run-fix-cycle.sh first to populate it" >&2
    exit 1
fi

shopt -s nullglob
PATCHES=("${FIX_OUT}"/*.patch)
shopt -u nullglob
if [[ ${#PATCHES[@]} -eq 0 ]]; then
    echo "info: no .patch files under ${FIX_OUT}/ — nothing to review" >&2
    exit 0
fi

echo "[dfix-apply] found ${#PATCHES[@]} patch(es) under ${FIX_OUT}/" >&2
echo "[dfix-apply] target branch: ${BRANCH_NAME}" >&2
if [[ ${DRY_RUN} -eq 1 ]]; then
    echo "[dfix-apply] DRY RUN — no changes will be applied" >&2
fi
echo "" >&2

# Working-tree must be clean before we start branching.
if [[ ${DRY_RUN} -eq 0 ]]; then
    if ! git -C "${REPO_ROOT}" diff --quiet || \
       ! git -C "${REPO_ROOT}" diff --cached --quiet; then
        echo "error: working tree is dirty; commit/stash first" >&2
        git -C "${REPO_ROOT}" status --short >&2
        exit 1
    fi
    if ! git -C "${REPO_ROOT}" rev-parse --verify "${BRANCH_NAME}" >/dev/null 2>&1; then
        git -C "${REPO_ROOT}" checkout -b "${BRANCH_NAME}" >&2
    else
        echo "[dfix-apply] branch ${BRANCH_NAME} already exists; checking it out" >&2
        git -C "${REPO_ROOT}" checkout "${BRANCH_NAME}" >&2
    fi
fi

# Prompt loop. For each patch, show the diff (paged if it's long),
# accept y/N/e/s/q.
applied=0
edited=0
skipped=0
quit=0

show_diff()
{
    local pp="$1"
    local n
    n=$(wc -l < "${pp}")
    if [[ ${n} -gt 60 ]]; then
        less -F -X "${pp}"
    else
        cat "${pp}"
    fi
}

for patch_path in "${PATCHES[@]}"; do
    [[ ${quit} -eq 1 ]] && break
    patch_name="$(basename "${patch_path}")"
    echo "================================================================" >&2
    echo "[dfix-apply] patch: ${patch_name}" >&2
    echo "================================================================" >&2
    # Brief title extracted from the patch file's first hunk header
    # (the part after `### `, which is what render_markdown writes).
    title_line=$(grep -m 1 '^### ' "${patch_path}" 2>/dev/null || true)
    if [[ -n "${title_line}" ]]; then
        echo "title: ${title_line#### }" >&2
    fi
    echo "" >&2
    show_diff "${patch_path}"
    echo "" >&2

    if [[ ${AUTO_YES} -eq 1 ]]; then
        choice="y"
    else
        echo -n "[dfix-apply] apply this patch? [y/N/e=edit/s=skip/q=quit]: " >&2
        # Read from /dev/tty so a piped invocation can still prompt
        # the operator. If /dev/tty isn't available (CI), fall back
        # to N to be safe.
        if [[ -t 0 ]] || [[ -e /dev/tty ]]; then
            read -r choice < /dev/tty || choice="N"
        else
            choice="N"
        fi
    fi
    choice="${choice,,}"

    case "${choice}" in
        y|yes)
            ;;
        e|edit)
            "${EDITOR}" "${patch_path}"
            edited=$((edited + 1))
            ;;
        s|skip|n|no|"")
            skipped=$((skipped + 1))
            continue
            ;;
        q|quit)
            quit=1
            continue
            ;;
        *)
            echo "[dfix-apply] unknown choice '${choice}', treating as skip" >&2
            skipped=$((skipped + 1))
            continue
            ;;
    esac

    if [[ ${DRY_RUN} -eq 1 ]]; then
        echo "[dfix-apply] DRY RUN — would apply ${patch_name}" >&2
        applied=$((applied + 1))
        continue
    fi
    if ! git -C "${REPO_ROOT}" apply --check "${patch_path}" 2>/dev/null; then
        echo "[dfix-apply] skip (does not apply cleanly after edits): ${patch_name}" >&2
        skipped=$((skipped + 1))
        continue
    fi
    git -C "${REPO_ROOT}" apply "${patch_path}"
    git -C "${REPO_ROOT}" add -A
    git -C "${REPO_ROOT}" commit -m "fix-journal: apply ${patch_name}

Reviewed-by: operator (interactive).
Generated by tools/build/gen-fix-patches.py against KERNEL.FIX.

Semantic changes in this patch are gated behind \`#if 0\` per
Decision #016 — applying this commit DOES NOT change kernel
behaviour. Flip the \`#if 0\` to \`#if 1\` in a follow-up commit
to activate the proposed shape after verifying it's correct
for the surrounding context."
    applied=$((applied + 1))
done

echo "" >&2
echo "================================================================" >&2
echo "[dfix-apply] summary:" >&2
echo "  applied : ${applied}" >&2
echo "  edited  : ${edited} (counted separately; included in applied if accepted)" >&2
echo "  skipped : ${skipped}" >&2
echo "  total   : ${#PATCHES[@]}" >&2
if [[ ${quit} -eq 1 ]]; then
    echo "  exited early on 'quit'" >&2
fi
if [[ ${DRY_RUN} -eq 0 && ${applied} -gt 0 ]]; then
    echo "" >&2
    echo "Next steps (operator-driven, not automated):" >&2
    echo "  1. Inspect the commits on ${BRANCH_NAME} via 'git log'." >&2
    echo "  2. For each gated patch, decide whether to flip the \`#if 0\` to" >&2
    echo "     \`#if 1\` to activate the semantic change. Land a separate" >&2
    echo "     commit per activation so a revert is a single git revert." >&2
    echo "  3. git push -u origin ${BRANCH_NAME}" >&2
fi
