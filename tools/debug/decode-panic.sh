#!/usr/bin/env bash
#
# Decode a DuetOS panic / crash-dump record from a serial log.
#
# Combines the existing host-side primitives:
#   - tools/debug/symbolize.sh   — replaces every kernel-VA hex with
#                            `[fn+off (file:line)]` (uses
#                            llvm-symbolizer / addr2line).
#   - tools/debug/disasm-at.sh   — opens an objdump window around the
#                            faulting RIP so you can see the
#                            actual instruction stream.
#
# What the kernel itself emits already (so this script is purely
# reuse / offline):
#   - Embedded symbol table — every panic line is annotated with
#     `<hex> [name+0xOFF (file:line)]`. Lookups via the `addr2sym`
#     shell command at runtime; this is the offline equivalent.
#   - Instruction-bytes hex dump at the fault RIP via
#     `[fault-rip] instr@<addr> : <16 bytes>`. The `instr` shell
#     command exposes the same primitive on demand.
#
# Usage:
#     tools/debug/decode-panic.sh [serial-log] [kernel-elf]
#     tools/qemu/run.sh 2>&1 | tools/debug/decode-panic.sh - [kernel-elf]
#
# Defaults:
#     serial-log : build/x86_64-debug/ctest-smoke-serial.log
#                 (or stdin if "-")
#     kernel-elf : build/x86_64-debug/kernel/duetos-kernel.elf
#
# Output:
#   Section 1 — every line between the bracketed
#               `=== DUETOS CRASH DUMP BEGIN ===` and END markers,
#               passed through symbolize.sh.
#   Section 2 — for each `rip       : 0x...` line found, a
#               disassembly window (16 before, 32 after) so you
#               can see the actual fault site + neighbouring
#               instructions.

set -euo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

SERIAL="${1:-${REPO_ROOT}/build/x86_64-debug/ctest-smoke-serial.log}"
KERNEL_ELF="${2:-${REPO_ROOT}/build/x86_64-debug/kernel/duetos-kernel.elf}"

if [[ "${SERIAL}" == "-" ]]; then
    SERIAL=$(mktemp)
    trap 'rm -f "${SERIAL}"' EXIT
    cat > "${SERIAL}"
fi

if [[ ! -f "${SERIAL}" ]]; then
    echo "error: serial log not found: ${SERIAL}" >&2
    exit 1
fi
if [[ ! -f "${KERNEL_ELF}" ]]; then
    echo "error: kernel ELF not found: ${KERNEL_ELF}" >&2
    echo "       build first: cmake --build build/x86_64-debug" >&2
    exit 1
fi

TMPDIR=$(mktemp -d)
trap 'rm -rf "${TMPDIR}"' EXIT
EXTRACTED="${TMPDIR}/dump.txt"

# Pull every BEGIN..END bracketed record out of the log. There can be
# more than one if the panic path itself faulted (the kernel prints a
# fresh BEGIN block from inside the trap dispatcher's own DumpDiagnostics
# fallback). awk handles the multi-record case cleanly.
awk '
    /=== DUETOS CRASH DUMP BEGIN ===/ { in_dump = 1 }
    in_dump { print }
    /=== DUETOS CRASH DUMP END ===/   { in_dump = 0; print "" }
' "${SERIAL}" > "${EXTRACTED}"

if [[ ! -s "${EXTRACTED}" ]]; then
    echo "no crash-dump records found in ${SERIAL}" >&2
    echo "(if the kernel halted before DumpDiagnostics ran, the" >&2
    echo " serial log may stop mid-line — check tail manually.)" >&2
    exit 2
fi

echo "=== Extracted crash-dump records (symbolised) ==="
echo
"${SCRIPT_DIR}/symbolize.sh" "${KERNEL_ELF}" < "${EXTRACTED}"

echo
echo "=== Disassembly windows around every recorded RIP ==="
echo

# Pull each `rip       : 0x...` and `rip:` form out and disassemble
# 16 bytes before, 32 after. Dedup so a multi-record dump that lists
# the same RIP twice (panic from inside panic) only disassembles once.
grep -aoE 'rip[[:space:]]*[:=][[:space:]]*0x[0-9a-fA-F]+' "${EXTRACTED}" \
    | grep -aoE '0x[0-9a-fA-F]+' \
    | sort -u \
    | while read -r rip; do
        # Skip user-mode RIPs — we only have symbols for the kernel.
        # Cheap canonical-high check: kernel VAs are 16 hex digits long
        # (the leading "0x" + 16 chars = 18-char string) AND start with
        # "ffff". Anything shorter or starting elsewhere is a user VA
        # or a low identity-map address — skip it. Avoids the
        # `printf '%d' 0xffff...` 64-bit-signed-overflow trap.
        if [[ ${#rip} -lt 18 ]] || [[ "${rip:0:6}" != "0xffff" ]]; then
            echo "skip non-kernel rip ${rip}"
            continue
        fi
        echo "--- rip ${rip} ---"
        "${SCRIPT_DIR}/disasm-at.sh" "${rip}" 16 32 "${KERNEL_ELF}" || true
        echo
    done
