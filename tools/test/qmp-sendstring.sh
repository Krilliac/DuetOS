#!/usr/bin/env bash
#
# WHAT:  Type a string into the DuetOS guest one character at a time via QMP.
# WHY:   Lets a controlling agent enter text (usernames, passwords, shell
#        commands) into any focused input field without needing a display.
# USAGE: qmp-sendstring.sh "STRING"
#   STRING is interpreted character-by-character:
#     a-z        → direct qcode (lowercase)
#     A-Z        → shift + lowercase qcode
#     0-9        → direct qcode
#     space      → space
#     \n or ^J   → ret (Enter)
#     .          → period
#     ,          → comma
#     -          → minus
#     _          → shift-minus (underscore)
#     =          → equal
#     +          → shift-equal
#     @          → shift-2
#     !          → shift-1
#     #          → shift-3
#   Unsupported characters are silently skipped (see WARN output).
#
# ENV:
#   DUETOS_PRESET       — build preset (default: x86_64-debug)
#   DUETOS_QMP_SOCK     — override QMP socket path
#   DUETOS_KEY_DELAY_MS — ms between keystrokes (default: 20)

set -euo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ $# -ne 1 ]]; then
    echo "usage: $0 'STRING'" >&2
    exit 2
fi

STRING="$1"
DELAY_MS="${DUETOS_KEY_DELAY_MS:-20}"

# send_key KEY [MODIFIER] — thin wrapper around qmp-sendkey.sh.
# Throttles at ${DELAY_MS} ms per key to avoid kbd FIFO overruns.
send_key() {
    local key="$1"
    local mod="${2:-}"
    if [[ -n "${mod}" ]]; then
        "${SCRIPT_DIR}/qmp-sendkey.sh" "${mod}-${key}"
    else
        "${SCRIPT_DIR}/qmp-sendkey.sh" "${key}"
    fi
    if [[ "${DELAY_MS}" -gt 0 ]]; then
        python3 -c "import time; time.sleep(${DELAY_MS}/1000)"
    fi
}

# Walk STRING byte-by-byte. Python handles the indexing cleanly
# and avoids shell quoting pitfalls with special characters.
python3 - "${STRING}" "${DELAY_MS}" "${SCRIPT_DIR}" <<'PY'
import subprocess
import sys
import time

s, delay_ms, script_dir = sys.argv[1], int(sys.argv[2]), sys.argv[3]
delay = delay_ms / 1000.0

def sendkey(key, modifier=None):
    combo = f"{modifier}-{key}" if modifier else key
    subprocess.run([f"{script_dir}/qmp-sendkey.sh", combo], check=True)
    time.sleep(delay)

SHIFT_MAP = {
    'A': 'a', 'B': 'b', 'C': 'c', 'D': 'd', 'E': 'e', 'F': 'f', 'G': 'g',
    'H': 'h', 'I': 'i', 'J': 'j', 'K': 'k', 'L': 'l', 'M': 'm', 'N': 'n',
    'O': 'o', 'P': 'p', 'Q': 'q', 'R': 'r', 'S': 's', 'T': 't', 'U': 'u',
    'V': 'v', 'W': 'w', 'X': 'x', 'Y': 'y', 'Z': 'z',
    '!': '1', '@': '2', '#': '3', '$': '4', '%': '5',
    '^': '6', '&': '7', '*': '8', '(': '9', ')': '0',
    '_': 'minus', '+': 'equal', '{': 'bracket_left', '}': 'bracket_right',
    '|': 'backslash', ':': 'semicolon', '"': 'apostrophe',
    '<': 'comma', '>': 'period', '?': 'slash',
}

DIRECT_MAP = {
    ' ': 'space', '\n': 'ret', '\t': 'tab',
    '.': 'period', ',': 'comma', '-': 'minus', '=': 'equal',
    ';': 'semicolon', "'": 'apostrophe', '/': 'slash',
    '\\': 'backslash', '[': 'bracket_left', ']': 'bracket_right',
    '`': 'grave',
}

skipped = []
for ch in s:
    if ch.islower() or ch.isdigit():
        sendkey(ch)
    elif ch in SHIFT_MAP:
        sendkey(SHIFT_MAP[ch], 'shift')
    elif ch in DIRECT_MAP:
        sendkey(DIRECT_MAP[ch])
    else:
        skipped.append(repr(ch))

if skipped:
    print(f"warn: qmp-sendstring skipped unsupported chars: {', '.join(skipped)}",
          file=sys.stderr)
PY
