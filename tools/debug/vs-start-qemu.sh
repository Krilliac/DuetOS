#!/usr/bin/env bash
#
# tools/debug/vs-start-qemu.sh — Visual Studio (full IDE) preLaunch
# helper. Same job as vscode-start-qemu.sh, but it must RETURN once
# the GDB server is accepting (so VS proceeds to attach) instead of
# `wait`-ing on QEMU like the VSCode variant does. QEMU is left
# running detached; vs-stop-qemu.sh (postDebug) reaps it.
#
# Modes:
#   debug — normal boot; break in via int3 / DR / a real fault.
#   demo  — kernel halts on int3 at end of kernel_main and waits
#           for the debugger to attach + continue.
set -euo pipefail

mode="${1:-demo}"
case "${mode}" in
    debug|demo) ;;
    *) echo "usage: $0 {debug|demo}" >&2; exit 2 ;;
esac

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
readonly PRESET="${DUETOS_PRESET:-x86_64-debug}"
readonly BUILD_DIR="${REPO_ROOT}/build/${PRESET}"
readonly GDB_PORT="${DUETOS_GDB_PORT:-1234}"
readonly QEMU_LOG="${DUETOS_QEMU_LOG:-/tmp/duetos-qemu.log}"
readonly QEMU_PID_FILE="/tmp/duetos-qemu.pid"

if [[ "${mode}" == "demo" ]]; then
    cmake --preset "${PRESET}" -DDUETOS_GDB_DEMO=ON >/dev/null
else
    cmake --preset "${PRESET}" -DDUETOS_GDB_DEMO=OFF >/dev/null
fi
cmake --build "${BUILD_DIR}" --target duetos-iso >/dev/null

# Reap any orphan QEMU from a failed prior launch.
if [[ -f "${QEMU_PID_FILE}" ]]; then
    old_pid="$(cat "${QEMU_PID_FILE}" 2>/dev/null || true)"
    if [[ -n "${old_pid}" ]] && kill -0 "${old_pid}" 2>/dev/null; then
        kill "${old_pid}" 2>/dev/null || true
        sleep 0.2
    fi
    rm -f "${QEMU_PID_FILE}"
fi

echo "[duetos-qemu] starting QEMU mode=${mode} preset=${PRESET}"
# setsid so QEMU survives this script returning (VS preLaunch exits;
# the detached QEMU keeps the gdb server up for the attach).
setsid env DUETOS_TIMEOUT="${DUETOS_TIMEOUT:-0}" \
    DUETOS_GDB_PORT="${GDB_PORT}" \
    "${REPO_ROOT}/tools/qemu/run.sh" >"${QEMU_LOG}" 2>&1 &
qemu_pid=$!
echo "${qemu_pid}" > "${QEMU_PID_FILE}"

# Block only until the kernel's COM2 GDB server is accepting, then
# return 0 so VS attaches. Do NOT `wait` — VS needs control back.
for _ in $(seq 1 60); do
    if (echo > "/dev/tcp/127.0.0.1/${GDB_PORT}") 2>/dev/null; then
        echo "[duetos-qemu] tcp::${GDB_PORT} ready — VS may attach"
        exit 0
    fi
    if ! kill -0 "${qemu_pid}" 2>/dev/null; then
        echo "[duetos-qemu] QEMU exited before the gdb server came up; see ${QEMU_LOG}" >&2
        exit 1
    fi
    sleep 0.5
done

echo "[duetos-qemu] tcp::${GDB_PORT} never accepted; aborting" >&2
kill "${qemu_pid}" 2>/dev/null || true
exit 1
