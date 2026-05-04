#!/usr/bin/env bash
#
# duetos-gdb-attach.sh — interactive GDB session against the running
# DuetOS kernel.
#
# What it does:
#   1. Starts QEMU (with -DDUETOS_GDB_DEMO=ON if you pass --demo, so
#      the kernel halts on int3 at end of kernel_main and waits for
#      this debugger to attach + continue) in the background.
#   2. Waits for COM2 → tcp::1234 to accept connections.
#   3. Launches `gdb` against the kernel ELF, sets `target remote
#      :1234`, and drops you at the GDB prompt.
#
# Usage:
#   tools/debug/duetos-gdb-attach.sh           # attach to a normally
#                                              # booting kernel; you
#                                              # need to break in via
#                                              # an int3 (or by
#                                              # crashing it) for the
#                                              # session to be useful.
#   tools/debug/duetos-gdb-attach.sh --demo    # builds with
#                                              # DUETOS_GDB_DEMO=ON
#                                              # so the kernel waits
#                                              # for you at the int3.
#
# Env:
#   DUETOS_PRESET    — cmake preset (default x86_64-debug).
#   DUETOS_GDB_PORT  — TCP port (default 1234, must match run.sh).
#   DUETOS_QEMU_LOG  — host file the QEMU stdout goes to (default
#                      /tmp/duetos-qemu.log).
set -euo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

PRESET="${DUETOS_PRESET:-x86_64-debug}"
BUILD_DIR="${REPO_ROOT}/build/${PRESET}"
KERNEL_ELF="${BUILD_DIR}/kernel/duetos-kernel.elf"
GDB_PORT="${DUETOS_GDB_PORT:-1234}"
QEMU_LOG="${DUETOS_QEMU_LOG:-/tmp/duetos-qemu.log}"

DEMO=0
for arg in "$@"; do
    case "$arg" in
        --demo) DEMO=1 ;;
        *) echo "unknown arg: $arg" >&2; exit 2 ;;
    esac
done

# When the demo flag is on we (re)build with DUETOS_GDB_DEMO=ON so
# the kernel fires int3 at end of kernel_main. The script sets it
# OFF on cleanup so a subsequent normal build doesn't keep halting.
cleanup() {
    if [[ "${DEMO}" -eq 1 ]]; then
        cmake --preset "${PRESET}" -DDUETOS_GDB_DEMO=OFF >/dev/null 2>&1 || true
        cmake --build "${BUILD_DIR}" --target duetos-kernel >/dev/null 2>&1 || true
    fi
    if [[ -n "${QEMU_PID:-}" ]] && kill -0 "${QEMU_PID}" 2>/dev/null; then
        kill "${QEMU_PID}" 2>/dev/null || true
        wait "${QEMU_PID}" 2>/dev/null || true
    fi
}
trap cleanup EXIT

if [[ "${DEMO}" -eq 1 ]]; then
    echo "[gdb-attach] configuring DUETOS_GDB_DEMO=ON"
    cmake --preset "${PRESET}" -DDUETOS_GDB_DEMO=ON >/dev/null
    cmake --build "${BUILD_DIR}" --target duetos-kernel >/dev/null
fi

echo "[gdb-attach] starting QEMU (logs → ${QEMU_LOG})"
DUETOS_TIMEOUT="${DUETOS_TIMEOUT:-300}" \
    DUETOS_GDB_PORT="${GDB_PORT}" \
    "${REPO_ROOT}/tools/qemu/run.sh" >"${QEMU_LOG}" 2>&1 &
QEMU_PID=$!

# Wait for QEMU's COM2 TCP server to accept connections. nc -z
# tries a one-shot connect and exits 0 on success. Bound the
# wait so a botched QEMU launch doesn't hang this script forever.
echo -n "[gdb-attach] waiting for tcp::${GDB_PORT} "
for i in $(seq 1 30); do
    if (echo > "/dev/tcp/127.0.0.1/${GDB_PORT}") 2>/dev/null; then
        echo "ok"
        break
    fi
    echo -n "."
    sleep 1
done

if ! [[ -f "${KERNEL_ELF}" ]]; then
    echo "[gdb-attach] error: kernel ELF not found at ${KERNEL_ELF}" >&2
    exit 1
fi

echo "[gdb-attach] launching gdb against ${KERNEL_ELF}"
echo "[gdb-attach] tip: 'continue' to resume; 'detach' to leave kernel running"
exec gdb \
    -ex "file ${KERNEL_ELF}" \
    -ex "target remote :${GDB_PORT}" \
    -ex "set confirm off" \
    -ex "set pagination off"
