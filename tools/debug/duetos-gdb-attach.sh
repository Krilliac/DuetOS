#!/usr/bin/env bash
#
# duetos-gdb-attach.sh — interactive GDB session against the running
# DuetOS kernel.
#
# What it does:
#   1. Starts QEMU (with -DDUETOS_GDB_DEMO=ON if you pass --demo, so
#      the kernel halts on int3 at end of kernel_main and waits for
#      this debugger to attach + continue) in the background.
#   2. Waits for the chosen transport to be ready.
#   3. Launches `gdb` against the kernel ELF, sets `target remote
#      <transport>`, and drops you at the GDB prompt.
#
# Usage:
#   tools/debug/duetos-gdb-attach.sh           # attach over TCP
#                                              # (default; runs QEMU
#                                              # with COM2 → tcp::1234).
#   tools/debug/duetos-gdb-attach.sh --demo    # plus DUETOS_GDB_DEMO=ON
#                                              # so the kernel waits
#                                              # at the int3.
#   tools/debug/duetos-gdb-attach.sh --via-pty # software null-modem:
#                                              # QEMU exposes COM2 as a
#                                              # host pty, GDB attaches
#                                              # via that device file
#                                              # — the same path a real
#                                              # USB-UART would take.
#   tools/debug/duetos-gdb-attach.sh --com /dev/ttyUSB0
#                                              # real-hardware path:
#                                              # don't start QEMU,
#                                              # `target remote
#                                              # /dev/ttyUSB0` directly.
#                                              # For null-modem to
#                                              # actual iron.
#
# Env:
#   DUETOS_PRESET    — cmake preset (default x86_64-debug).
#   DUETOS_GDB_PORT  — TCP port (default 1234, must match run.sh).
#   DUETOS_QEMU_LOG  — host file the QEMU stdout goes to (default
#                      /tmp/duetos-qemu.log).
#   DUETOS_GDB_BAUD  — baud rate for --com / --via-pty (default
#                      115200, matches kernel's COM2 init).
set -euo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

PRESET="${DUETOS_PRESET:-x86_64-debug}"
BUILD_DIR="${REPO_ROOT}/build/${PRESET}"
KERNEL_ELF="${BUILD_DIR}/kernel/duetos-kernel.elf"
GDB_PORT="${DUETOS_GDB_PORT:-1234}"
QEMU_LOG="${DUETOS_QEMU_LOG:-/tmp/duetos-qemu.log}"
BAUD="${DUETOS_GDB_BAUD:-115200}"

DEMO=0
TRANSPORT="tcp"     # tcp | pty | com (com = no-QEMU path)
COM_DEVICE=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --demo)    DEMO=1 ;;
        --via-pty) TRANSPORT="pty" ;;
        --com)
            shift
            if [[ $# -eq 0 ]]; then
                echo "--com requires a device path (e.g. /dev/ttyUSB0)" >&2
                exit 2
            fi
            TRANSPORT="com"
            COM_DEVICE="$1"
            ;;
        *)
            echo "unknown arg: $1" >&2
            exit 2
            ;;
    esac
    shift
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

if ! [[ -f "${KERNEL_ELF}" ]]; then
    echo "[gdb-attach] error: kernel ELF not found at ${KERNEL_ELF}" >&2
    exit 1
fi

# --- Transport: real serial device on the host (no QEMU) ---
if [[ "${TRANSPORT}" == "com" ]]; then
    if ! [[ -c "${COM_DEVICE}" ]]; then
        echo "[gdb-attach] error: ${COM_DEVICE} is not a character device" >&2
        exit 1
    fi
    echo "[gdb-attach] real-hw mode: target remote ${COM_DEVICE} @ ${BAUD} baud"
    exec gdb \
        -ex "file ${KERNEL_ELF}" \
        -ex "set serial baud ${BAUD}" \
        -ex "target remote ${COM_DEVICE}" \
        -ex "set confirm off" \
        -ex "set pagination off"
fi

# --- Transport: QEMU + host pty (software null-modem) ---
if [[ "${TRANSPORT}" == "pty" ]]; then
    echo "[gdb-attach] starting QEMU with COM2 → host pty (logs → ${QEMU_LOG})"
    DUETOS_TIMEOUT="${DUETOS_TIMEOUT:-300}" \
        DUETOS_GDB_TRANSPORT=pty \
        "${REPO_ROOT}/tools/qemu/run.sh" >"${QEMU_LOG}" 2>&1 &
    QEMU_PID=$!

    # Wait for QEMU to print the "char device redirected to /dev/pts/N"
    # line. Bounded so a botched launch doesn't hang us forever.
    PTY_PATH=""
    for _ in $(seq 1 30); do
        if grep -qE "char device redirected to /dev/pts/" "${QEMU_LOG}" 2>/dev/null; then
            PTY_PATH="$(grep -oE '/dev/pts/[0-9]+' "${QEMU_LOG}" | head -n 1)"
            break
        fi
        sleep 1
    done
    if [[ -z "${PTY_PATH}" ]] || ! [[ -c "${PTY_PATH}" ]]; then
        echo "[gdb-attach] error: QEMU never reported a pty path; see ${QEMU_LOG}" >&2
        exit 1
    fi
    echo "[gdb-attach] pty ready at ${PTY_PATH}; attaching gdb @ ${BAUD} baud"
    exec gdb \
        -ex "file ${KERNEL_ELF}" \
        -ex "set serial baud ${BAUD}" \
        -ex "target remote ${PTY_PATH}" \
        -ex "set confirm off" \
        -ex "set pagination off"
fi

# --- Transport: QEMU + TCP (default) ---
echo "[gdb-attach] starting QEMU (logs → ${QEMU_LOG})"
DUETOS_TIMEOUT="${DUETOS_TIMEOUT:-300}" \
    DUETOS_GDB_PORT="${GDB_PORT}" \
    "${REPO_ROOT}/tools/qemu/run.sh" >"${QEMU_LOG}" 2>&1 &
QEMU_PID=$!

# Wait for QEMU's COM2 TCP server to accept connections. Bound the
# wait so a botched QEMU launch doesn't hang this script forever.
echo -n "[gdb-attach] waiting for tcp::${GDB_PORT} "
for _ in $(seq 1 30); do
    if (echo > "/dev/tcp/127.0.0.1/${GDB_PORT}") 2>/dev/null; then
        echo "ok"
        break
    fi
    echo -n "."
    sleep 1
done

echo "[gdb-attach] launching gdb against ${KERNEL_ELF}"
echo "[gdb-attach] tip: 'continue' to resume; 'detach' to leave kernel running"
exec gdb \
    -ex "file ${KERNEL_ELF}" \
    -ex "target remote :${GDB_PORT}" \
    -ex "set confirm off" \
    -ex "set pagination off"
