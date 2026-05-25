#!/usr/bin/env bash
#
# WHAT:  Generic QMP command client for the DuetOS unix socket.
# WHY:   Centralises the QMP handshake (greeting → qmp_capabilities → command)
#        so higher-level scripts (qmp-screendump, qmp-sendkey, qmp-click) don't
#        each carry their own copy of the protocol preamble.
# USAGE: qmp-cmd.sh '<json-command>'
#   e.g. qmp-cmd.sh '{"execute":"query-status"}'
#   e.g. qmp-cmd.sh '{"execute":"screendump","arguments":{"filename":"/tmp/out.ppm"}}'
#
# ENV:
#   DUETOS_PRESET      — build preset (default: x86_64-debug)
#   DUETOS_QMP_SOCK    — override socket path entirely
#
# The script exits 0 on a QMP "return" response and 1 on a "error" response
# or connection failure. Response JSON is printed to stdout.

set -euo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

PRESET="${DUETOS_PRESET:-x86_64-debug}"
SOCK="${DUETOS_QMP_SOCK:-${REPO_ROOT}/build/${PRESET}/qmp.sock}"

if [[ $# -ne 1 ]]; then
    echo "usage: $0 '<json-command>'" >&2
    echo "  e.g. $0 '{\"execute\":\"query-status\"}'" >&2
    exit 2
fi

COMMAND="$1"

if [[ ! -S "${SOCK}" ]]; then
    echo "error: QMP socket not found: ${SOCK}" >&2
    echo "  is a DUETOS_QMP=1 run.sh guest running for preset ${PRESET}?" >&2
    exit 1
fi

python3 - "${SOCK}" "${COMMAND}" <<'PY'
import json
import socket
import sys

sock_path, command = sys.argv[1], sys.argv[2]

s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.settimeout(10)
try:
    s.connect(sock_path)
except OSError as e:
    print(f"error: cannot connect to QMP socket {sock_path}: {e}", file=sys.stderr)
    sys.exit(1)

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
        # Skip the QMP greeting and async events.


f.readline()  # greeting banner
send({"execute": "qmp_capabilities"})
recv_until_return()
send(json.loads(command))
reply = recv_until_return()
print(json.dumps(reply, indent=2))
sys.exit(1 if "error" in reply else 0)
PY
