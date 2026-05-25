#!/usr/bin/env bash
#
# WHAT:  Move the mouse and click at (X, Y) in the DuetOS guest framebuffer via QMP.
# WHY:   Lets a controlling agent drive the GUI pointer — click buttons, open menus,
#        select fields — without needing a display or VNC session.
# USAGE: qmp-click.sh X Y [BUTTON]
#   X, Y   — framebuffer pixel coordinates (0-based; typically 0..1023 × 0..767)
#   BUTTON — left (default), right, or middle
#
# The QMP `input-send-event` command bundles pointer-motion + button-down +
# button-up into one RPC call so the guest sees an atomic click, not a partial
# sequence that could be interrupted by a compose pass.
#
# ENV:
#   DUETOS_PRESET      — build preset (default: x86_64-debug)
#   DUETOS_QMP_SOCK    — override QMP socket path
#   DUETOS_FB_WIDTH    — framebuffer width used to scale absolute coords (default: 1024)
#   DUETOS_FB_HEIGHT   — framebuffer height (default: 768)

set -euo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ $# -lt 2 ]]; then
    echo "usage: $0 X Y [BUTTON]" >&2
    echo "  BUTTON: left (default), right, middle" >&2
    exit 2
fi

X="$1"
Y="$2"
BUTTON="${3:-left}"
FB_W="${DUETOS_FB_WIDTH:-1024}"
FB_H="${DUETOS_FB_HEIGHT:-768}"

# Validate button name.
case "${BUTTON}" in
    left|right|middle) ;;
    *)
        echo "error: unknown button '${BUTTON}' — must be left, right, or middle" >&2
        exit 1
        ;;
esac

# Validate coordinates are non-negative integers within framebuffer bounds.
if ! [[ "${X}" =~ ^[0-9]+$ ]] || ! [[ "${Y}" =~ ^[0-9]+$ ]]; then
    echo "error: X and Y must be non-negative integers (got X='${X}' Y='${Y}')" >&2
    exit 1
fi
if [[ "${X}" -ge "${FB_W}" || "${Y}" -ge "${FB_H}" ]]; then
    echo "error: coordinates (${X}, ${Y}) are outside framebuffer ${FB_W}x${FB_H}" >&2
    exit 1
fi

# QMP input-send-event uses absolute coordinates in the range [0, 32767].
# Scale from framebuffer pixels to this range.
python3 - "${X}" "${Y}" "${FB_W}" "${FB_H}" "${BUTTON}" "${SCRIPT_DIR}" <<'PY'
import json
import subprocess
import sys

x_px, y_px, fb_w, fb_h, button, script_dir = (
    int(sys.argv[1]), int(sys.argv[2]),
    int(sys.argv[3]), int(sys.argv[4]),
    sys.argv[5], sys.argv[6],
)

SCALE = 32767
x_abs = int(x_px * SCALE / (fb_w - 1))
y_abs = int(y_px * SCALE / (fb_h - 1))

BTN_MAP = {"left": "Left", "right": "Right", "middle": "Middle"}
btn = BTN_MAP[button]

# Bundle move + button-down + button-up in one input-send-event call.
events = [
    {"type": "abs", "data": {"axis": "x", "value": x_abs}},
    {"type": "abs", "data": {"axis": "y", "value": y_abs}},
    {"type": "btn", "data": {"down": True,  "button": btn}},
    {"type": "btn", "data": {"down": False, "button": btn}},
]
cmd = json.dumps({"execute": "input-send-event", "arguments": {"events": events}})
subprocess.run([f"{script_dir}/qmp-cmd.sh", cmd], check=True)
PY
