#!/usr/bin/env bash
#
# Disassemble around a kernel address.
#
# A wrapper around `objdump -d` that takes the kernel ELF + a hex VA
# and prints the disassembly for a window of bytes around it. Useful
# for reading what a faulting RIP from a serial-log panic dump
# actually does, without scrolling through the full kernel disassembly.
#
# Usage:
#     tools/debug/disasm-at.sh <hex-addr> [bytes-before] [bytes-after] [kernel-elf]
#
# Examples:
#     tools/debug/disasm-at.sh 0xffffffff8017a06d
#         16 bytes before, 32 after, against build/x86_64-debug/kernel/duetos-kernel.elf
#
#     tools/debug/disasm-at.sh 0xffffffff801c1ce8 8 8 build/x86_64-release/kernel/duetos-kernel.elf
#         small window against the release build
#
# The same workflow inside a running DuetOS shell:
#     instr <hex-addr> [len-bytes]      — bytes only (no decode)
#     addr2sym <hex-addr>               — function+offset (file:line)
# Together those replace `objdump -d` for casual triage; this script is
# for the offline / "I have a saved panic log" path.
#
# Requires `objdump` (binutils). Falls back to `llvm-objdump` if the GNU
# tool is unavailable.

set -euo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

if [[ $# -lt 1 ]]; then
    cat >&2 <<EOF
usage: $0 <hex-addr> [bytes-before] [bytes-after] [kernel-elf]

  hex-addr      — kernel VA (e.g. 0xffffffff8017a06d). Must be canonical
                  high-half. The "0x" prefix is optional.
  bytes-before  — bytes of context BEFORE addr (default 16).
  bytes-after   — bytes of context AFTER addr (default 32).
  kernel-elf    — path to the kernel ELF
                  (default: build/x86_64-debug/kernel/duetos-kernel.elf).

Example:
    $0 0xffffffff8017a06d 16 32
EOF
    exit 1
fi

ADDR="$1"
BEFORE="${2:-16}"
AFTER="${3:-32}"
KERNEL_ELF="${4:-${REPO_ROOT}/build/x86_64-debug/kernel/duetos-kernel.elf}"

if [[ ! -f "${KERNEL_ELF}" ]]; then
    echo "error: kernel ELF not found: ${KERNEL_ELF}" >&2
    echo "       build first: cmake --build build/x86_64-debug" >&2
    exit 1
fi

if command -v objdump >/dev/null 2>&1; then
    OBJDUMP=objdump
elif command -v llvm-objdump >/dev/null 2>&1; then
    OBJDUMP=llvm-objdump
else
    echo "error: neither objdump nor llvm-objdump is on PATH" >&2
    echo "       install with: sudo apt-get install -y binutils" >&2
    exit 1
fi

# Normalise the address. Bash arithmetic accepts 0x… directly.
NUM_ADDR=$(( ADDR ))
START=$(( NUM_ADDR - BEFORE ))
STOP=$(( NUM_ADDR + AFTER ))
printf 'disasm window: 0x%x .. 0x%x  (centre 0x%x, %d before / %d after)\n' \
    "${START}" "${STOP}" "${NUM_ADDR}" "${BEFORE}" "${AFTER}"
printf 'kernel:        %s\n' "${KERNEL_ELF}"
echo

# `--start-address` / `--stop-address` keep the disassembly window tight
# without parsing 30 MiB of objdump output. -d picks the ELF's text
# section automatically.
"${OBJDUMP}" -d -C \
    --start-address="${START}" \
    --stop-address="${STOP}" \
    "${KERNEL_ELF}" \
    | sed "/^$/d; /file format/d; /Disassembly of section/d"
