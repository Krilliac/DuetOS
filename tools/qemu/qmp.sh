#!/usr/bin/env bash
# tools/qemu/qmp.sh
#
# Tiny QMP client for the unix socket run.sh exposes
# (${BUILD_DIR}/qmp.sock, added by the DUETOS_QMP path). Lets the dev
# loop inspect / nudge a running guest WITHOUT killing it or fighting
# the serial log:
#
#   qmp.sh status                 — run-state (running / paused / ...)
#   qmp.sh screenshot <out.ppm>   — dump the guest framebuffer
#   qmp.sh powerdown              — raise the ACPI power button
#   qmp.sh quit                   — ask QEMU to exit cleanly
#
# The socket path defaults to build/<preset>/qmp.sock; override with
# DUETOS_QMP_SOCK, or DUETOS_PRESET to pick a different build dir.
# This is a debug convenience, not a CI dependency — the smoke
# harness uses the isa-debug-exit code, not QMP.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PRESET="${DUETOS_PRESET:-x86_64-debug}"
SOCK="${DUETOS_QMP_SOCK:-${REPO_ROOT}/build/${PRESET}/qmp.sock}"

if [[ $# -lt 1 ]]; then
    echo "usage: $0 status | screenshot <out.ppm> | powerdown | quit" >&2
    exit 2
fi

if [[ ! -S "${SOCK}" ]]; then
    echo "error: QMP socket not found: ${SOCK}" >&2
    echo "  is a DUETOS_QMP run.sh guest running for preset ${PRESET}?" >&2
    exit 2
fi

CMD="$1"
shift || true

case "${CMD}" in
    status)     QMP_EXEC='{"execute":"query-status"}' ;;
    quit)       QMP_EXEC='{"execute":"quit"}' ;;
    # Raise the ACPI power button (PWRBTN_STS → SCI). Exercises the
    # guest's ACPI SCI path end to end: a guest that services it
    # powers off (QEMU exits); one that doesn't keeps running. Used
    # by tools/test/env-powerbtn-smoke.sh.
    powerdown)  QMP_EXEC='{"execute":"system_powerdown"}' ;;
    screenshot)
        if [[ $# -ne 1 ]]; then
            echo "usage: $0 screenshot <out.ppm>" >&2
            exit 2
        fi
        OUT="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
        QMP_EXEC=$(printf '{"execute":"screendump","arguments":{"filename":"%s"}}' "${OUT}")
        ;;
    *)
        echo "error: unknown command '${CMD}'" >&2
        exit 2
        ;;
esac

# QMP needs the greeting → qmp_capabilities → command handshake.
# python3 is already a run.sh dependency, so reuse it for the
# line-delimited JSON exchange rather than hand-rolling socat.
python3 - "${SOCK}" "${QMP_EXEC}" <<'PY'
import json
import socket
import sys

sock_path, command = sys.argv[1], sys.argv[2]
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.settimeout(5)
s.connect(sock_path)
f = s.makefile("rwb", buffering=0)


def send(obj):
    f.write((json.dumps(obj) + "\r\n").encode())


def recv_until_return():
    while True:
        line = f.readline()
        if not line:
            raise SystemExit("error: QMP socket closed mid-exchange")
        msg = json.loads(line)
        if "return" in msg or "error" in msg:
            return msg
        # Skip the greeting and any async events.


f.readline()  # greeting
send({"execute": "qmp_capabilities"})
recv_until_return()
send(json.loads(command))
reply = recv_until_return()
print(json.dumps(reply, indent=2))
raise SystemExit(1 if "error" in reply else 0)
PY
