#!/usr/bin/env bash
#
# WHAT:  Move the mouse and click at (X, Y) in the DuetOS guest framebuffer via QMP.
# WHY:   Lets a controlling agent drive the GUI pointer — click buttons, open menus,
#        select fields — without needing a display or VNC session.
# USAGE: qmp-click.sh X Y [BUTTON]
#   X, Y   — framebuffer pixel coordinates (0-based; typically 0..1023 × 0..767)
#   BUTTON — left (default), right, or middle
#
# Mouse positioning strategy:
#   QEMU's input-send-event supports two motion modes:
#     abs — absolute position [0..32767]. Requires an absolute input device
#           (usb-tablet) attached to QEMU AND a display backend. Not usable
#           with -display none + usb-mouse (relative device).
#     rel — relative delta from current position. Works with any mouse device
#           and any display mode including headless (-display none).
#   This script uses rel mode: it first sends a large negative delta to move
#   the cursor to the top-left corner (origin reset), then sends a positive
#   delta to reach (X, Y). This gives reliable positioning for headless runs.
#   If DUETOS_ABS_MOUSE=1 is set, the script uses abs mode instead (requires
#   `-device usb-tablet,bus=xhci.0` in the QEMU launch args).
#
# ENV:
#   DUETOS_PRESET      — build preset (default: x86_64-debug)
#   DUETOS_QMP_SOCK    — override QMP socket path
#   DUETOS_FB_WIDTH    — framebuffer width (default: 1024)
#   DUETOS_FB_HEIGHT   — framebuffer height (default: 768)
#   DUETOS_ABS_MOUSE   — 1 = use abs mode (requires usb-tablet device)

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
ABS_MOUSE="${DUETOS_ABS_MOUSE:-0}"

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

python3 - "${X}" "${Y}" "${FB_W}" "${FB_H}" "${BUTTON}" "${SCRIPT_DIR}" "${ABS_MOUSE}" <<'PY'
import json
import subprocess
import sys

x_px, y_px, fb_w, fb_h, button, script_dir, abs_mode = (
    int(sys.argv[1]), int(sys.argv[2]),
    int(sys.argv[3]), int(sys.argv[4]),
    sys.argv[5], sys.argv[6],
    sys.argv[7] == "1",
)

# QMP button names are lowercase.
btn = button  # already "left", "right", or "middle"

def qmp_cmd(cmd_obj):
    cmd = json.dumps(cmd_obj)
    subprocess.run([f"{script_dir}/qmp-cmd.sh", cmd], check=True)

if abs_mode:
    # Absolute mode: requires usb-tablet device and a display backend.
    SCALE = 32767
    x_abs = int(x_px * SCALE / max(fb_w - 1, 1))
    y_abs = int(y_px * SCALE / max(fb_h - 1, 1))
    events = [
        {"type": "abs", "data": {"axis": "x", "value": x_abs}},
        {"type": "abs", "data": {"axis": "y", "value": y_abs}},
        {"type": "btn", "data": {"down": True,  "button": btn}},
        {"type": "btn", "data": {"down": False, "button": btn}},
    ]
    qmp_cmd({"execute": "input-send-event", "arguments": {"events": events}})
else:
    # Relative mode: works with -display none + usb-mouse (default run.sh).
    # Step 1: large negative delta to reset cursor to top-left corner.
    RESET = -65535  # large enough to reach (0,0) from anywhere on screen
    reset_events = [
        {"type": "rel", "data": {"axis": "x", "value": RESET}},
        {"type": "rel", "data": {"axis": "y", "value": RESET}},
    ]
    qmp_cmd({"execute": "input-send-event", "arguments": {"events": reset_events}})

    # Step 2: positive delta to reach target (X, Y).
    move_events = [
        {"type": "rel", "data": {"axis": "x", "value": x_px}},
        {"type": "rel", "data": {"axis": "y", "value": y_px}},
    ]
    qmp_cmd({"execute": "input-send-event", "arguments": {"events": move_events}})

    # Step 3: button press + release.
    click_events = [
        {"type": "btn", "data": {"down": True,  "button": btn}},
        {"type": "btn", "data": {"down": False, "button": btn}},
    ]
    qmp_cmd({"execute": "input-send-event", "arguments": {"events": click_events}})
PY
