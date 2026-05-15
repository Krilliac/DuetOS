#!/usr/bin/env bash
# tools/dev/check-local.sh — one-command local CI preflight for DuetOS.

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/../.." && pwd)"
PRESET="x86_64-debug"
RUN_DOCTOR=1
RUN_WIKI=1
RUN_FORMAT=1
RUN_RUST=1
RUN_CONFIGURE=1
RUN_BUILD=0
RUN_CTEST=0
RUN_SMOKE=0
RUN_ANALYZE=0

usage() {
    cat <<'USAGE'
usage: tools/dev/check-local.sh [options]

Default checks: doctor, wiki nav/quality, clang-format dry-run, and CMake
configure for x86_64-debug. Expensive steps are opt-in.

Options:
  --preset <name>   CMake preset/build dir to use (default: x86_64-debug)
  --build           Build the selected preset after configure
  --ctest           Run hosted CTest in build/<preset> (implies --build)
  --smoke           Run QEMU profile smoke via CTest harness (implies --build)
  --analyze         Run static codebase analysis (own + cppcheck + clippy)
  --all             Run build + CTest + QEMU smoke + analyze
  --live            Run doctor in live mode even if --smoke is not selected
  --no-doctor       Skip host-toolchain doctor
  --no-wiki         Skip wiki navigation/quality checks
  --no-format       Skip clang-format dry-run
  --no-rust         Skip cargo fmt + clippy on the Rust workspace
  --no-configure    Skip CMake configure
  -h, --help        Show this help
USAGE
}

DOCTOR_MODE="build"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --preset)
            [[ $# -ge 2 ]] || { echo "check-local.sh: --preset needs a value" >&2; exit 2; }
            PRESET="$2"
            shift 2
            ;;
        --build)
            RUN_BUILD=1
            shift
            ;;
        --ctest)
            RUN_BUILD=1
            RUN_CTEST=1
            shift
            ;;
        --smoke)
            RUN_BUILD=1
            RUN_SMOKE=1
            DOCTOR_MODE="live"
            shift
            ;;
        --analyze)
            RUN_ANALYZE=1
            shift
            ;;
        --all)
            RUN_BUILD=1
            RUN_CTEST=1
            RUN_SMOKE=1
            RUN_ANALYZE=1
            DOCTOR_MODE="live"
            shift
            ;;
        --live)
            DOCTOR_MODE="live"
            shift
            ;;
        --no-doctor)
            RUN_DOCTOR=0
            shift
            ;;
        --no-wiki)
            RUN_WIKI=0
            shift
            ;;
        --no-format)
            RUN_FORMAT=0
            shift
            ;;
        --no-rust)
            RUN_RUST=0
            shift
            ;;
        --no-configure)
            RUN_CONFIGURE=0
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "check-local.sh: unknown argument: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

run_step() {
    local name="$1"
    shift
    printf '\n==> %s\n' "${name}"
    (cd "${REPO_ROOT}" && "$@")
}

if [[ ${RUN_DOCTOR} -eq 1 ]]; then
    run_step "host doctor (${DOCTOR_MODE})" "${REPO_ROOT}/tools/dev/doctor.sh" "--${DOCTOR_MODE}"
fi

if [[ ${RUN_WIKI} -eq 1 ]]; then
    run_step "wiki navigation" "${REPO_ROOT}/tools/check-wiki-nav.sh"
    run_step "wiki quality" "${REPO_ROOT}/tools/check-wiki-quality.sh"
fi

if [[ ${RUN_FORMAT} -eq 1 ]]; then
    run_step "clang-format dry-run" bash -c '
        mapfile -t sources < <(find kernel userland \( -name "*.h" -o -name "*.hpp" -o -name "*.c" -o -name "*.cpp" \) | sort)
        if [[ ${#sources[@]} -eq 0 ]]; then
            echo "No C/C++ sources found"
            exit 0
        fi
        clang-format --dry-run --Werror "${sources[@]}"
    '
fi

if [[ ${RUN_RUST} -eq 1 ]]; then
    # rustfmt + clippy + hosted unit tests gate every kernel-linked
    # Rust crate. cargo is provided by the pinned nightly in
    # /rust-toolchain.toml; if it's not on PATH the doctor step above
    # will have already flagged it.
    if command -v cargo >/dev/null 2>&1; then
        run_step "cargo fmt --check (workspace)" cargo fmt --check --all
        run_step "cargo clippy (workspace)" cargo clippy --workspace --release --locked -- -D warnings
        run_step "rustc --test (host crates)" "${REPO_ROOT}/tools/dev/cargo-host-test.sh"
    else
        printf '\n==> cargo missing — skipping Rust workspace checks\n' >&2
    fi
fi

if [[ ${RUN_CONFIGURE} -eq 1 ]]; then
    run_step "cmake configure (${PRESET})" cmake --preset "${PRESET}"
fi

if [[ ${RUN_BUILD} -eq 1 ]]; then
    run_step "cmake build (${PRESET})" cmake --build "build/${PRESET}" --parallel "$(nproc)"
fi

if [[ ${RUN_CTEST} -eq 1 ]]; then
    run_step "hosted ctest (${PRESET})" bash -c "cd 'build/${PRESET}' && ctest --output-on-failure"
fi

if [[ ${RUN_SMOKE} -eq 1 ]]; then
    run_step "QEMU boot smoke (${PRESET})" "${REPO_ROOT}/tools/test/ctest-boot-smoke.sh" "build/${PRESET}"
fi

if [[ ${RUN_ANALYZE} -eq 1 ]]; then
    run_step "codebase analysis (static)" "${REPO_ROOT}/tools/dev/analyze.sh" --preset "${PRESET}"
fi

printf '\ncheck-local.sh: all selected checks passed for %s\n' "${PRESET}"
