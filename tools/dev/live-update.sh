#!/usr/bin/env bash
# tools/dev/live-update.sh — pull repo updates and tell the developer
# what can be hot-reloaded vs what forces a full rebuild + QEMU restart.
#
# Why this is host-side: DuetOS is from-scratch; the running kernel has
# no in-kernel git client and no network channel to fetch a working
# tree. Everything under userland/ is .incbin-baked into the kernel
# image at build time. So the meaningful boundary is "did the change
# affect anything that ends up in the kernel image, or anything the
# kernel itself runs?" If yes, the running QEMU instance must be
# rebuilt and rebooted. If no, the change is host-side only (docs,
# host scripts, host-side tests) and the running QEMU is still valid.
#
# Read-only against the host. The only mutation is `git fetch` and
# (when --apply is given) a fast-forward of the current branch.

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/../.." && pwd)"

REMOTE="origin"
REF="main"
APPLY=0
SELF_TEST=0
VERBOSE=0

# Exit codes used by callers (CI, watch loops):
#   0  — up to date OR docs/host-only update; no rebuild needed
#   10 — kernel rebuild + QEMU restart required
#   2  — bad arguments
#   3  — git fetch failed
#   4  — working tree dirty, refusing to fast-forward
#   5  — fast-forward not possible (diverged); manual rebase needed
EXIT_NO_REBUILD=0
EXIT_REBUILD_REQUIRED=10
EXIT_BAD_ARGS=2
EXIT_FETCH_FAILED=3
EXIT_DIRTY_TREE=4
EXIT_DIVERGED=5

usage() {
    cat <<'USAGE'
usage: tools/dev/live-update.sh [options]

Pulls repo updates and classifies the changed files into
"hot-reloadable on the running QEMU instance" or "RESTART REQUIRED".

Default behaviour is dry-run: fetches the remote, classifies the
pending delta, prints the verdict, and exits without modifying the
working tree. Pass --apply to fast-forward the local branch.

Options:
  --remote <name>   Git remote to fetch from (default: origin)
  --ref <name>      Branch/ref on the remote to compare against (default: main)
  --apply           Fast-forward the local branch onto the fetched ref
  --self-test       Run the classifier against a built-in fixture and exit
  -v, --verbose     Print one line per changed path with its class
  -h, --help        Show this help

Exit codes:
   0   up to date OR only docs / host-side tools changed (no rebuild)
  10   kernel / boot / userland / build-system changed: rebuild + reboot QEMU
   2   bad arguments
   3   git fetch failed
   4   working tree is dirty; refusing to --apply
   5   local and remote have diverged; --apply needs a manual rebase
USAGE
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --remote)
            [[ $# -ge 2 ]] || { echo "live-update.sh: --remote needs a value" >&2; exit "${EXIT_BAD_ARGS}"; }
            REMOTE="$2"; shift 2 ;;
        --ref)
            [[ $# -ge 2 ]] || { echo "live-update.sh: --ref needs a value" >&2; exit "${EXIT_BAD_ARGS}"; }
            REF="$2"; shift 2 ;;
        --apply) APPLY=1; shift ;;
        --self-test) SELF_TEST=1; shift ;;
        -v|--verbose) VERBOSE=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "live-update.sh: unknown argument: $1" >&2; usage >&2; exit "${EXIT_BAD_ARGS}" ;;
    esac
done

# classify_path <path>
#
# Echoes one of: DOCS, HOST-TOOLS, HOST-TESTS, KERNEL-IMAGE.
#
# Anything in DOCS or HOST-TOOLS or HOST-TESTS is hot-reloadable —
# the running kernel image is unaffected, the developer just re-runs
# whatever surfaced the change (read the wiki, re-run the script,
# re-run ctest on the host).
#
# Anything classified KERNEL-IMAGE means: the next boot of the
# kernel will differ from the one currently running in QEMU. That is
# the "RESTART REQUIRED" set:
#
#   - kernel/ boot/ drivers/ subsystems/   — kernel and in-kernel
#     drivers compile straight into the kernel ELF
#   - userland/                            — every userland binary
#     and DLL is .incbin'd into the kernel image (search
#     `duetos_embed_blob` in kernel/CMakeLists.txt for the list)
#   - top-level CMakeLists.txt / CMakePresets.json / cmake/
#     toolchains / Cargo.* / rust-toolchain.toml — touch the build
#     system in a way the running image cannot reflect
#
# Classification falls through to KERNEL-IMAGE on anything not
# explicitly known to be host-side. The default is conservative: if
# we have not proven a path is host-only, we tell the developer to
# rebuild. The cost of an unnecessary rebuild is a few minutes; the
# cost of a missed rebuild is a confusing "my code change didn't do
# anything" debugging session.
classify_path() {
    local path="$1"

    case "${path}" in
        # --- pure docs -------------------------------------------------
        wiki/*|docs/*) echo "DOCS"; return ;;
        *.md|LICENSE|AGENTS.md|CLAUDE.md|README*) echo "DOCS"; return ;;

        # --- host-side tooling ----------------------------------------
        # Excludes tools/build/embed-blob.py and friends that produce
        # generated headers consumed by the kernel build — those count
        # as KERNEL-IMAGE because the next build will pick up the new
        # generator output.
        tools/build/embed-blob.py) echo "KERNEL-IMAGE"; return ;;
        tools/build/gen-firmware-ramfs.py) echo "KERNEL-IMAGE"; return ;;
        tools/build/gen-kernel-blob.sh) echo "KERNEL-IMAGE"; return ;;
        tools/build/gen-symbols.sh) echo "KERNEL-IMAGE"; return ;;
        tools/build/regenerate-syscall-artifacts.sh) echo "KERNEL-IMAGE"; return ;;
        tools/build/build-*.sh) echo "KERNEL-IMAGE"; return ;;
        tools/firmware/*) echo "KERNEL-IMAGE"; return ;;
        tools/dev/*|tools/qemu/*|tools/debug/*|tools/test/*) echo "HOST-TOOLS"; return ;;
        tools/check-wiki-*.sh) echo "HOST-TOOLS"; return ;;
        tools/pkg/*|tools/release/*|tools/security/*) echo "HOST-TOOLS"; return ;;
        tools/cleanroom/*|tools/linux-compat/*|tools/win32-compat/*) echo "HOST-TOOLS"; return ;;

        # --- hosted unit tests + fuzz harnesses -----------------------
        tests/host/*|tests/fuzz/*) echo "HOST-TESTS"; return ;;

        # --- kernel image inputs --------------------------------------
        kernel/*|boot/*|drivers/*|subsystems/*) echo "KERNEL-IMAGE"; return ;;
        userland/*) echo "KERNEL-IMAGE"; return ;;
        CMakeLists.txt|CMakePresets.json) echo "KERNEL-IMAGE"; return ;;
        cmake/*) echo "KERNEL-IMAGE"; return ;;
        Cargo.toml|Cargo.lock|rust-toolchain.toml|rustfmt.toml) echo "KERNEL-IMAGE"; return ;;

        # --- unknown: be conservative, force rebuild ------------------
        *) echo "KERNEL-IMAGE"; return ;;
    esac
}

print_legend() {
    cat <<'LEGEND'
[live-update] classes:
  DOCS         pure documentation — no rebuild, no restart
  HOST-TOOLS   dev/build/test/qemu helpers — no kernel-image change
  HOST-TESTS   hosted unit + fuzz tests — re-run on host, no restart
  KERNEL-IMAGE in kernel ELF / baked into ramfs / build system — REBUILD + RESTART REQUIRED
LEGEND
}

# Self-test: drives classify_path against a fixed table of inputs.
# Every row that lands in tree must classify to its declared bucket.
# Run via --self-test before trusting the verdict; the CI smoke job
# can call this without a working git remote.
run_self_test() {
    local -a cases=(
        # docs
        "wiki/Home.md|DOCS"
        "wiki/kernel/Subsystem-Isolation.md|DOCS"
        "docs/sync-wiki.sh|DOCS"
        "README.md|DOCS"
        "CLAUDE.md|DOCS"
        "AGENTS.md|DOCS"
        "LICENSE|DOCS"
        # host tools
        "tools/dev/live-update.sh|HOST-TOOLS"
        "tools/dev/doctor.sh|HOST-TOOLS"
        "tools/qemu/run.sh|HOST-TOOLS"
        "tools/check-wiki-nav.sh|HOST-TOOLS"
        "tools/pkg/src/main.rs|HOST-TOOLS"
        # host tests
        "tests/host/test_thunk_hash.cpp|HOST-TESTS"
        "tests/fuzz/host_shim/fuzz_target.cpp|HOST-TESTS"
        # kernel-image surfaces
        "kernel/sched/sched.cpp|KERNEL-IMAGE"
        "boot/uefi/main.c|KERNEL-IMAGE"
        "drivers/storage/nvme/nvme.cpp|KERNEL-IMAGE"
        "userland/libs/kernel32/kernel32.cpp|KERNEL-IMAGE"
        "userland/apps/hello/main.c|KERNEL-IMAGE"
        "CMakeLists.txt|KERNEL-IMAGE"
        "CMakePresets.json|KERNEL-IMAGE"
        "cmake/toolchains/x86_64-kernel.cmake|KERNEL-IMAGE"
        "Cargo.toml|KERNEL-IMAGE"
        "rust-toolchain.toml|KERNEL-IMAGE"
        # tools/ generators that produce kernel-image inputs are
        # NOT host-only — a regenerated header lands in the next
        # kernel build.
        "tools/build/embed-blob.py|KERNEL-IMAGE"
        "tools/build/gen-firmware-ramfs.py|KERNEL-IMAGE"
        "tools/build/build-kernel32-dll.sh|KERNEL-IMAGE"
        "tools/firmware/some-fw-builder.sh|KERNEL-IMAGE"
        # unknown / new top-level path: be conservative
        "some-new-top-level-file.txt|KERNEL-IMAGE"
    )

    local fail=0
    local row path want got
    for row in "${cases[@]}"; do
        path="${row%|*}"
        want="${row#*|}"
        got="$(classify_path "${path}")"
        if [[ "${got}" != "${want}" ]]; then
            printf '[live-update][self-test] FAIL  %s -> %s (want %s)\n' "${path}" "${got}" "${want}" >&2
            fail=1
        else
            printf '[live-update][self-test] ok    %s -> %s\n' "${path}" "${got}"
        fi
    done
    if (( fail )); then
        echo "[live-update][self-test] FAIL — classifier table drifted" >&2
        return 1
    fi
    echo "[live-update][self-test] PASS"
    return 0
}

if (( SELF_TEST )); then
    run_self_test
    exit $?
fi

cd "${REPO_ROOT}"

# Sanity: we must be inside a git work tree.
if ! git rev-parse --git-dir >/dev/null 2>&1; then
    echo "[live-update] not inside a git work tree at ${REPO_ROOT}" >&2
    exit "${EXIT_BAD_ARGS}"
fi

# Fetch with the same retry/backoff shape the rest of the repo uses
# for git operations (see CLAUDE.md "Git Operations"). Network blips
# in CI shouldn't fail a live-update run.
fetch_with_backoff() {
    local attempt=0
    local -a delays=(2 4 8 16)
    while :; do
        if git fetch "${REMOTE}" "${REF}" 2>&1; then
            return 0
        fi
        if (( attempt >= ${#delays[@]} )); then
            return 1
        fi
        sleep "${delays[$attempt]}"
        attempt=$((attempt + 1))
    done
}

if ! fetch_with_backoff; then
    echo "[live-update] git fetch ${REMOTE} ${REF} failed after retries" >&2
    exit "${EXIT_FETCH_FAILED}"
fi

LOCAL_HEAD="$(git rev-parse HEAD)"
REMOTE_HEAD="$(git rev-parse "${REMOTE}/${REF}")"

if [[ "${LOCAL_HEAD}" == "${REMOTE_HEAD}" ]]; then
    echo "[live-update] already at ${REMOTE}/${REF} (${LOCAL_HEAD:0:12}); nothing to apply"
    exit "${EXIT_NO_REBUILD}"
fi

MERGE_BASE="$(git merge-base HEAD "${REMOTE}/${REF}" || true)"
if [[ -z "${MERGE_BASE}" ]]; then
    echo "[live-update] no common ancestor with ${REMOTE}/${REF}; aborting" >&2
    exit "${EXIT_DIVERGED}"
fi

# Collect the changed paths between MERGE_BASE and the fetched ref.
# We classify by the union of pre-fetch HEAD and the new ref so an
# operator who has local commits ahead of main still gets the
# correct verdict for what will land on fast-forward.
mapfile -t CHANGED < <(git diff --name-only "${LOCAL_HEAD}" "${REMOTE_HEAD}" -- || true)
if (( ${#CHANGED[@]} == 0 )); then
    echo "[live-update] no path diffs between local and ${REMOTE}/${REF}; nothing to do"
    exit "${EXIT_NO_REBUILD}"
fi

declare -i DOCS_N=0 HOST_TOOLS_N=0 HOST_TESTS_N=0 KERNEL_N=0
declare -a KERNEL_PATHS=()

for path in "${CHANGED[@]}"; do
    [[ -z "${path}" ]] && continue
    cls="$(classify_path "${path}")"
    if (( VERBOSE )); then
        printf '[live-update]   %-12s  %s\n' "${cls}" "${path}"
    fi
    case "${cls}" in
        DOCS) DOCS_N=$((DOCS_N + 1)) ;;
        HOST-TOOLS) HOST_TOOLS_N=$((HOST_TOOLS_N + 1)) ;;
        HOST-TESTS) HOST_TESTS_N=$((HOST_TESTS_N + 1)) ;;
        KERNEL-IMAGE) KERNEL_N=$((KERNEL_N + 1)); KERNEL_PATHS+=("${path}") ;;
    esac
done

print_legend
printf '[live-update] %s -> %s : %d docs, %d host-tools, %d host-tests, %d kernel-image\n' \
    "${LOCAL_HEAD:0:12}" "${REMOTE_HEAD:0:12}" \
    "${DOCS_N}" "${HOST_TOOLS_N}" "${HOST_TESTS_N}" "${KERNEL_N}"

apply_fast_forward() {
    # Refuse to mutate a dirty working tree. The user can stash and
    # re-run; we don't silently move their work.
    if ! git diff --quiet || ! git diff --cached --quiet; then
        echo "[live-update] working tree is dirty; refusing to --apply (stash and retry)" >&2
        return "${EXIT_DIRTY_TREE}"
    fi
    # Refuse to apply if local has commits the remote doesn't —
    # that's a rebase, not a fast-forward, and live-update should
    # never silently rewrite history.
    local ahead
    ahead="$(git rev-list --count "${REMOTE}/${REF}..HEAD")"
    if [[ "${ahead}" != "0" ]]; then
        echo "[live-update] local is ${ahead} commit(s) ahead of ${REMOTE}/${REF}; rebase manually then re-run" >&2
        return "${EXIT_DIVERGED}"
    fi
    if ! git merge --ff-only "${REMOTE}/${REF}"; then
        echo "[live-update] fast-forward merge failed" >&2
        return "${EXIT_DIVERGED}"
    fi
    echo "[live-update] fast-forwarded $(git rev-parse --abbrev-ref HEAD) to ${REMOTE_HEAD:0:12}"
    return 0
}

if (( APPLY )); then
    apply_fast_forward || exit $?
fi

if (( KERNEL_N > 0 )); then
    echo "[live-update] RESTART REQUIRED — ${KERNEL_N} path(s) feed the kernel image"
    # Show up to 8 example paths so the user can see what triggered
    # the verdict without having to re-run with --verbose.
    local_n=0
    for p in "${KERNEL_PATHS[@]}"; do
        echo "[live-update]   * ${p}"
        local_n=$((local_n + 1))
        if (( local_n >= 8 )); then
            remaining=$((KERNEL_N - local_n))
            if (( remaining > 0 )); then
                echo "[live-update]   ... and ${remaining} more (re-run with --verbose to see all)"
            fi
            break
        fi
    done
    echo "[live-update] next: cmake --build build/<preset> && tools/qemu/run.sh"
    exit "${EXIT_REBUILD_REQUIRED}"
fi

# Reaching here means every changed path is host-only. The running
# QEMU instance still reflects the source state for everything it
# actually loaded.
echo "[live-update] hot reload applied — running kernel image is still current"
if (( HOST_TESTS_N > 0 )); then
    echo "[live-update]   re-run hosted tests: (cd build/<preset> && ctest --output-on-failure)"
fi
if (( DOCS_N > 0 )); then
    echo "[live-update]   docs refreshed: re-open wiki pages if open in an editor"
fi
exit "${EXIT_NO_REBUILD}"
