#!/usr/bin/env bash
#
# duetos-gdb-cmd.sh — non-interactive GDB session against the
# running DuetOS kernel. Designed for AI / scripted debugging:
# you give it a sequence of GDB commands, it runs them, prints
# the output, detaches, and exits.
#
# Boots the kernel with DUETOS_GDB_DEMO=ON so the kernel halts
# on int3 early in kernel_main and the script has a guaranteed
# stop point to run commands against. The DUETOS_GDB_SERVER
# wiring (the actual GDB protocol server on COM2) is independent
# of DEMO and stays on for the x86_64-debug preset by default —
# DEMO is only the "make attach trivially testable" convenience.
#
# Usage:
#   tools/debug/duetos-gdb-cmd.sh                   # default cmds
#   tools/debug/duetos-gdb-cmd.sh "info reg" "bt"   # custom cmds
#   tools/debug/duetos-gdb-cmd.sh -f script.gdb     # commands from file
#
# Each positional arg is a single GDB command (run in order).
# Output is printed to stdout. Exit code is 0 on success.
#
# Env (all optional):
#   DUETOS_PRESET    — cmake preset (default x86_64-debug).
#   DUETOS_GDB_PORT  — TCP port (default 1234, must match run.sh).
#   DUETOS_TIMEOUT   — QEMU max wallclock seconds (default 180).
set -euo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

PRESET="${DUETOS_PRESET:-x86_64-debug}"
BUILD_DIR="${REPO_ROOT}/build/${PRESET}"
KERNEL_ELF="${BUILD_DIR}/kernel/duetos-kernel.elf"
GDB_PORT="${DUETOS_GDB_PORT:-1234}"

CMD_FILE=""
DECLARED_CMDS=()
if [[ "${1:-}" == "-f" ]]; then
    CMD_FILE="${2:?-f needs a path}"
    shift 2
fi
while [[ $# -gt 0 ]]; do
    DECLARED_CMDS+=("$1")
    shift
done

# Default inspection set when caller passes no commands. Picks
# the things an AI most often needs: where are we, what's in
# the registers, what's nearby on the stack, what's around RIP.
if [[ ${#DECLARED_CMDS[@]} -eq 0 && -z "${CMD_FILE}" ]]; then
    DECLARED_CMDS=(
        "info registers"
        "x/16i \$rip"
        "x/16xg \$rsp"
        "bt 10"
    )
fi

cleanup() {
    cmake --preset "${PRESET}" -DDUETOS_GDB_DEMO=OFF >/dev/null 2>&1 || true
    cmake --build "${BUILD_DIR}" --target duetos-kernel >/dev/null 2>&1 || true
    if [[ -n "${QEMU_PID:-}" ]] && kill -0 "${QEMU_PID}" 2>/dev/null; then
        kill "${QEMU_PID}" 2>/dev/null || true
        wait "${QEMU_PID}" 2>/dev/null || true
    fi
}
trap cleanup EXIT

echo "[gdb-cmd] configuring DUETOS_GDB_DEMO=ON" >&2
cmake --preset "${PRESET}" -DDUETOS_GDB_DEMO=ON >/dev/null
cmake --build "${BUILD_DIR}" --target duetos-kernel >/dev/null

echo "[gdb-cmd] starting QEMU" >&2
QEMU_LOG="$(mktemp)"
DUETOS_TIMEOUT="${DUETOS_TIMEOUT:-300}" \
    DUETOS_GDB_PORT="${GDB_PORT}" \
    "${REPO_ROOT}/tools/qemu/run.sh" >"${QEMU_LOG}" 2>&1 &
QEMU_PID=$!

# Wait for COM2 to accept TCP connections.
echo -n "[gdb-cmd] waiting for tcp::${GDB_PORT} " >&2
for i in $(seq 1 30); do
    if (echo > "/dev/tcp/127.0.0.1/${GDB_PORT}") 2>/dev/null; then
        echo "ok" >&2
        break
    fi
    echo -n "." >&2
    sleep 1
done

# Wait for the kernel to actually reach the GDB demo int3 — until
# then `target remote :1234` succeeds (TCP connect works) but the
# stub hasn't fired its stop packet, so any GDB command would just
# hang. We poll the QEMU log for the demo-fire marker.
echo -n "[gdb-cmd] waiting for kernel to reach the GDB demo int3 " >&2
for i in $(seq 1 300); do
    if grep -q "\[gdb-demo\] firing int3" "${QEMU_LOG}" 2>/dev/null; then
        echo "ok" >&2
        break
    fi
    echo -n "." >&2
    sleep 1
done

# Build a one-shot GDB command file.
GDB_SCRIPT="$(mktemp --suffix=.gdb)"
{
    echo "set confirm off"
    echo "set pagination off"
    echo "set print pretty on"
    if [[ -n "${CMD_FILE}" ]]; then
        cat "${CMD_FILE}"
    else
        for c in "${DECLARED_CMDS[@]}"; do
            echo "${c}"
        done
    fi
    # `detach` releases the GDB connection AND lets the kernel
    # resume from the int3 (the stub's resume action defaults to
    # Continue when GDB issues 'D'). Then quit. Avoids the
    # "Cannot execute this command while the target is running"
    # that `continue &` + `detach` would cause.
    echo "detach"
    echo "quit"
} > "${GDB_SCRIPT}"

echo "[gdb-cmd] running ${#DECLARED_CMDS[@]} command(s) via gdb" >&2
echo "----8<---- gdb output ----8<----"
gdb \
    -batch \
    -ex "file ${KERNEL_ELF}" \
    -ex "target remote :${GDB_PORT}" \
    -x "${GDB_SCRIPT}" \
    2>&1 || true
echo "---->8---- gdb output ---->8----"

rm -f "${GDB_SCRIPT}" "${QEMU_LOG}"
