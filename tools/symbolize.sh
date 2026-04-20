#!/usr/bin/env bash
#
# Annotate a kernel panic log with symbol names.
#
# The kernel panics print raw hex addresses — RIP, stack quads,
# backtrace frames. Running panic output through this script attaches
# `function+offset (file:line)` to every address it can resolve against
# the kernel ELF's debug info.
#
# Usage:
#     tools/symbolize.sh [KERNEL_ELF] < panic_log.txt
#     tools/qemu/run.sh 2>&1 | tools/symbolize.sh
#
# If KERNEL_ELF is omitted, defaults to
#     build/x86_64-debug/kernel/customos-kernel.elf
#
# Requires llvm-symbolizer (preferred) or addr2line (binutils fallback).
#
# What gets symbolized:
#   - Hex addresses of the form 0xffffffff80XXXXXX (kernel higher-half).
#   - Plus anything else that looks like an 8-byte hex — filtered by
#     the symbolizer's own "is this an address in the ELF" check.
#
# Unresolved addresses (user-mode, low identity, stack values that
# happen to be data not text) are left untouched.

set -euo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

KERNEL_ELF="${1:-${REPO_ROOT}/build/x86_64-debug/kernel/customos-kernel.elf}"

if [[ ! -f "${KERNEL_ELF}" ]]; then
    echo "error: kernel ELF not found: ${KERNEL_ELF}" >&2
    echo "       pass an explicit path or run after a debug build." >&2
    exit 1
fi

# Pick a symbolizer. llvm-symbolizer gives inline-aware output; binutils
# addr2line works too but loses inlined frames.
if command -v llvm-symbolizer >/dev/null 2>&1; then
    SYMBOLIZER="llvm-symbolizer"
    SYMBOLIZER_ARGS=(--obj="${KERNEL_ELF}" --functions=short --demangle --inlines)
elif command -v addr2line >/dev/null 2>&1; then
    SYMBOLIZER="addr2line"
    SYMBOLIZER_ARGS=(-e "${KERNEL_ELF}" -f -C -i)
else
    echo "error: need llvm-symbolizer or addr2line on PATH" >&2
    exit 1
fi

# AWK does the heavy lifting:
#   - Find hex tokens matching the kernel VA pattern.
#   - Pipe each to the symbolizer.
#   - Append "  -> symbol" to the line.
# Shelling out per address is slow but panic logs are small (<1 KiB
# typical) so the overhead is irrelevant.

while IFS= read -r line; do
    # Extract every unique 0xffffffff8XXXXXXX token on the line.
    mapfile -t addrs < <(grep -oE '0xffffffff[0-9a-fA-F]{8,}' <<<"${line}" | sort -u)

    if [[ ${#addrs[@]} -eq 0 ]]; then
        printf '%s\n' "${line}"
        continue
    fi

    printf '%s' "${line}"
    for addr in "${addrs[@]}"; do
        sym=$("${SYMBOLIZER}" "${SYMBOLIZER_ARGS[@]}" "${addr}" 2>/dev/null | head -1)
        if [[ -n "${sym}" && "${sym}" != "??" && "${sym}" != "?? ??:0" ]]; then
            printf '  [%s → %s]' "${addr}" "${sym}"
        fi
    done
    printf '\n'
done
