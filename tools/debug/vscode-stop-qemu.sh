#!/usr/bin/env bash
#
# .vscode/stop-qemu-bg.sh — VSCode postDebugTask helper.
#
# Tears down the QEMU process spawned by start-qemu-bg.sh, runs
# after the debug session ends.
set -euo pipefail

readonly QEMU_PID_FILE="/tmp/duetos-qemu.pid"

if [[ ! -f "${QEMU_PID_FILE}" ]]; then
    echo "[duetos-qemu] no PID file at ${QEMU_PID_FILE}; nothing to kill"
    exit 0
fi

pid="$(cat "${QEMU_PID_FILE}" 2>/dev/null || true)"
rm -f "${QEMU_PID_FILE}"

if [[ -z "${pid}" ]]; then
    echo "[duetos-qemu] PID file empty; nothing to kill"
    exit 0
fi

if kill -0 "${pid}" 2>/dev/null; then
    kill "${pid}" 2>/dev/null || true
    # Brief wait for graceful exit.
    for _ in $(seq 1 10); do
        if ! kill -0 "${pid}" 2>/dev/null; then
            echo "[duetos-qemu] stopped pid=${pid}"
            exit 0
        fi
        sleep 0.2
    done
    # Hard kill if it's still around.
    kill -9 "${pid}" 2>/dev/null || true
    echo "[duetos-qemu] hard-killed pid=${pid}"
else
    echo "[duetos-qemu] pid=${pid} already gone"
fi
