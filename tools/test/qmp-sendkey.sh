#!/usr/bin/env bash
#
# WHAT:  Send a single keypress (or modifier+key combo) to the DuetOS guest via QMP.
# WHY:   Lets a controlling agent drive the GUI keyboard — navigate menus, enter
#        passwords, trigger hotkeys — without needing a display or VNC session.
# USAGE: qmp-sendkey.sh KEY
#   KEY is a QEMU key name or a hyphen-joined modifier+key combo.
#   Examples:
#     qmp-sendkey.sh ret            # Enter
#     qmp-sendkey.sh tab            # Tab
#     qmp-sendkey.sh esc            # Escape
#     qmp-sendkey.sh a              # letter 'a'
#     qmp-sendkey.sh ctrl-alt-t     # Ctrl+Alt+T
#     qmp-sendkey.sh shift-f10      # Shift+F10
#
# ENV:
#   DUETOS_PRESET    — build preset (default: x86_64-debug)
#   DUETOS_QMP_SOCK  — override QMP socket path
#
# Key name validation: rejects unknown tokens against QEMU's documented set.

set -euo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ $# -ne 1 ]]; then
    echo "usage: $0 KEY" >&2
    echo "  e.g. $0 ret   $0 tab   $0 ctrl-alt-t   $0 shift-f5" >&2
    exit 2
fi

INPUT="$1"

# ---------------------------------------------------------------------------
# QEMU key name whitelist. Covers the set documented in qemu-doc + the HAMP
# monitor `sendkey` help. Modifiers must appear before the base key, separated
# by hyphens. A bare modifier (ctrl, alt, shift, meta) is also valid as a
# standalone key.
# ---------------------------------------------------------------------------
readonly VALID_MODIFIERS="ctrl alt shift meta"
readonly VALID_KEYS="
a b c d e f g h i j k l m n o p q r s t u v w x y z
0 1 2 3 4 5 6 7 8 9
f1 f2 f3 f4 f5 f6 f7 f8 f9 f10 f11 f12
ret backspace tab space esc
insert delete home end pgup pgdn
up down left right
ctrl alt shift meta
ctrl_l ctrl_r alt_l alt_r shift_l shift_r
kp_0 kp_1 kp_2 kp_3 kp_4 kp_5 kp_6 kp_7 kp_8 kp_9
kp_enter kp_plus kp_minus kp_multiply kp_divide kp_decimal
kp_comma kp_equals
comma period slash backslash minus equal
semicolon apostrophe grave
bracket_left bracket_right
print sysrq pause scroll_lock caps_lock num_lock
less greater pipe exclamation at hash dollar percent caret ampersand asterisk
left_paren right_paren underscore plus
"

key_valid() {
    local k="$1"
    local w
    for w in ${VALID_KEYS}; do
        [[ "${k}" == "${w}" ]] && return 0
    done
    return 1
}

# Split the input on hyphens and validate each token.
IFS='-' read -ra PARTS <<< "${INPUT}"

KEY_NAMES=""
for part in "${PARTS[@]}"; do
    part_lower="${part,,}"  # bash lowercase
    if ! key_valid "${part_lower}"; then
        echo "error: unknown key token '${part}' in '${INPUT}'" >&2
        echo "       valid tokens include: a-z, 0-9, f1-f12, ret, tab, esc, space," >&2
        echo "       backspace, ctrl, alt, shift, meta, up, down, left, right, ..." >&2
        exit 1
    fi
    if [[ -n "${KEY_NAMES}" ]]; then
        KEY_NAMES="${KEY_NAMES},"
    fi
    KEY_NAMES="${KEY_NAMES}{\"type\":\"qcode\",\"data\":\"${part_lower}\"}"
done

CMD="{\"execute\":\"send-key\",\"arguments\":{\"keys\":[${KEY_NAMES}]}}"
"${SCRIPT_DIR}/qmp-cmd.sh" "${CMD}" > /dev/null
