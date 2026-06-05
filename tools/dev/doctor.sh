#!/usr/bin/env bash
# tools/dev/doctor.sh — DuetOS host-toolchain preflight.
#
# This is intentionally read-only: it reports what is missing and prints
# apt package hints, but it does not install packages or mutate the host.

set -euo pipefail

MODE="build"

usage() {
    cat <<'USAGE'
usage: tools/dev/doctor.sh [--build|--live|--ci] [--help]

Checks the local Linux host for the tools DuetOS needs.

Modes:
  --build   required build/format tools only (default)
  --live    build tools plus QEMU/ISO live-boot tools
  --ci      same as --live; intended for local reproduction of CI smoke jobs

The script exits non-zero if a required command for the selected mode is
missing or too old. It never installs packages.
USAGE
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --build)
            MODE="build"
            shift
            ;;
        --live|--ci)
            MODE="live"
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "doctor.sh: unknown argument: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

missing=0

ok() { printf '[ OK ] %s\n' "$*"; }
warn() { printf '[WARN] %s\n' "$*"; }
fail() {
    printf '[FAIL] %s\n' "$*"
    missing=1
}

have_command() {
    command -v "$1" >/dev/null 2>&1
}

first_version_number() {
    "$1" --version 2>/dev/null | sed -nE '1s/[^0-9]*([0-9]+([.][0-9]+){0,2}).*/\1/p'
}

version_at_least() {
    local actual="$1"
    local minimum="$2"

    [[ -n "${actual}" ]] || return 1
    [[ "$(printf '%s\n%s\n' "${minimum}" "${actual}" | sort -V | head -n1)" == "${minimum}" ]]
}

check_command() {
    local cmd="$1"
    local package="$2"
    local minimum="${3:-}"
    local version=""

    if ! have_command "${cmd}"; then
        fail "${cmd} missing (apt: ${package})"
        return
    fi

    if [[ -n "${minimum}" ]]; then
        version="$(first_version_number "${cmd}" || true)"
        if ! version_at_least "${version}" "${minimum}"; then
            fail "${cmd} ${version:-unknown} found, need >= ${minimum} (apt: ${package})"
            return
        fi
        ok "${cmd} ${version}"
    else
        ok "${cmd} ($(command -v "${cmd}"))"
    fi
}

check_any_command() {
    local label="$1"
    local package="$2"
    shift 2

    local cmd
    for cmd in "$@"; do
        if have_command "${cmd}"; then
            ok "${label}: ${cmd} ($(command -v "${cmd}"))"
            return
        fi
    done

    fail "${label} missing; tried: $* (apt: ${package})"
}

check_file_any() {
    local label="$1"
    shift

    local path
    for path in "$@"; do
        if [[ -e "${path}" ]]; then
            ok "${label}: ${path}"
            return
        fi
    done

    fail "${label} missing; install ovmf or point QEMU at an OVMF_CODE image"
}

printf 'DuetOS host preflight (%s mode)\n' "${MODE}"
printf '=================================\n'

check_command bash bash
check_command git git
check_command python3 python3
check_command cmake cmake 3.25
check_command ninja ninja-build
check_command clang clang-18 18
check_command clang++ clang-18 18
check_command clang-format clang-format-18 18
check_any_command "ELF linker" lld-18 ld.lld lld
check_command lld-link lld-18 18
check_any_command "Windows import-library generator" llvm-18 llvm-dlltool llvm-dlltool-18 llvm-dlltool-19 llvm-dlltool-20 x86_64-w64-mingw32-dlltool

# The DLL / vDSO embed scripts invoke the unversioned `llvm-objcopy`
# by name. Ubuntu's llvm-18 ships only `llvm-objcopy-18`, so a bare
# lookup fails until it is symlinked or /usr/lib/llvm-18/bin is on
# PATH -- catch that here instead of ~180 build steps in.
if have_command llvm-objcopy; then
    ok "llvm-objcopy ($(command -v llvm-objcopy))"
elif have_command llvm-objcopy-18; then
    fail "llvm-objcopy missing but llvm-objcopy-18 present -- symlink it (sudo ln -sf /usr/lib/llvm-18/bin/llvm-objcopy /usr/bin/llvm-objcopy) or add /usr/lib/llvm-18/bin to PATH"
else
    fail "llvm-objcopy missing (apt: llvm-18, then symlink /usr/lib/llvm-18/bin/llvm-objcopy into PATH)"
fi

check_command xorriso xorriso
check_command grub-mkrescue grub-common
check_command mcopy mtools

if [[ "${MODE}" == "live" ]]; then
    printf '\nLive-boot tools\n'
    printf -- '---------------\n'
    check_command qemu-system-x86_64 qemu-system-x86
    check_file_any "OVMF firmware" \
        /usr/share/OVMF/OVMF_CODE.fd \
        /usr/share/ovmf/OVMF.fd \
        /usr/share/qemu/OVMF.fd

    if [[ -e /dev/kvm && -r /dev/kvm && -w /dev/kvm ]]; then
        ok "/dev/kvm is accessible"
    elif [[ -e /dev/kvm ]]; then
        warn "/dev/kvm exists but is not readable/writable by this user; QEMU will fall back to TCG or need permissions"
    else
        warn "/dev/kvm is absent; QEMU smoke can still run under TCG, but it will be much slower"
    fi
fi

printf '\nInstall hint (Ubuntu 24.04 baseline):\n'
printf '  sudo apt-get update && sudo apt-get install -y clang-18 lld-18 llvm-18 clang-format-18 cmake ninja-build python3 grub-common grub-pc-bin grub-efi-amd64-bin xorriso mtools'
if [[ "${MODE}" == "live" ]]; then
    printf ' qemu-system-x86 ovmf'
fi
printf '\n'

if [[ ${missing} -ne 0 ]]; then
    printf '\ndoctor.sh: missing or incompatible required tools\n' >&2
    exit 1
fi

printf '\ndoctor.sh: host looks ready for %s workflows\n' "${MODE}"
