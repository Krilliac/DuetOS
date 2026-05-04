#!/usr/bin/env bash
#
# .vscode/start-qemu-bg.sh — VSCode preLaunchTask helper.
#
# Starts QEMU with the GDB server wired in the background, prints
# "tcp::1234 ready" once the COM2 TCP server is accepting (the
# regex VSCode's tasks.json is watching for in `endsPattern`).
#
# Two modes:
#   debug — normal boot, kernel keeps running; you'll need to break
#           in via int3 / DR / a real fault to see anything.
#   demo  — kernel halts on int3 at end of kernel_main, waits for
#           debugger attach + continue.
set -euo pipefail

mode="${1:-debug}"
case "${mode}" in
    debug|demo) ;;
    *) echo "usage: $0 {debug|demo}" >&2; exit 2 ;;
esac

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
readonly PRESET="${DUETOS_PRESET:-x86_64-debug}"
readonly BUILD_DIR="${REPO_ROOT}/build/${PRESET}"
readonly GDB_PORT="${DUETOS_GDB_PORT:-1234}"
readonly QEMU_LOG="${DUETOS_QEMU_LOG:-/tmp/duetos-qemu.log}"
readonly QEMU_PID_FILE="/tmp/duetos-qemu.pid"

# Configure the demo flag according to mode. We always re-run the
# configure step so a stale cache from a prior session can't leave
# DEMO=ON when we want it OFF (or vice versa).
if [[ "${mode}" == "demo" ]]; then
    cmake --preset "${PRESET}" -DDUETOS_GDB_DEMO=ON >/dev/null
else
    cmake --preset "${PRESET}" -DDUETOS_GDB_DEMO=OFF >/dev/null
fi
cmake --build "${BUILD_DIR}" --target duetos-kernel >/dev/null

# Kill any leftover QEMU from a previous launch — VSCode's task
# system can leave orphans behind when a launch fails partway.
if [[ -f "${QEMU_PID_FILE}" ]]; then
    old_pid="$(cat "${QEMU_PID_FILE}" 2>/dev/null || true)"
    if [[ -n "${old_pid}" ]] && kill -0 "${old_pid}" 2>/dev/null; then
        kill "${old_pid}" 2>/dev/null || true
        sleep 0.2
    fi
    rm -f "${QEMU_PID_FILE}"
fi

echo "[duetos-qemu] starting QEMU mode=${mode} preset=${PRESET}"
DUETOS_TIMEOUT="${DUETOS_TIMEOUT:-300}" \
    DUETOS_GDB_PORT="${GDB_PORT}" \
    "${REPO_ROOT}/tools/qemu/run.sh" >"${QEMU_LOG}" 2>&1 &
qemu_pid=$!
echo "${qemu_pid}" > "${QEMU_PID_FILE}"

# Wait for the COM2 TCP server. VSCode's `endsPattern` regex
# matches "tcp::1234 ready" so the launch unblocks once we print it.
for _ in $(seq 1 30); do
    if (echo > "/dev/tcp/127.0.0.1/${GDB_PORT}") 2>/dev/null; then
        echo "[duetos-qemu] tcp::${GDB_PORT} ready"
        # Keep the script alive for the duration of QEMU so VSCode's
        # background-task plumbing sees a long-running process; otherwise
        # the task would terminate and the postDebugTask would run too
        # early.
        wait "${qemu_pid}"
        exit $?
    fi
    sleep 0.5
done

echo "[duetos-qemu] tcp::${GDB_PORT} never accepted; aborting"
kill "${qemu_pid}" 2>/dev/null || true
exit 1
