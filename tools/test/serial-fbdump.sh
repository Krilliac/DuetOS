#!/usr/bin/env bash
#
# WHAT:  Extract a framebuffer PPM image from a DuetOS serial capture.
# WHY:   VBox and bare-metal targets don't have QMP. The `fbdump` kernel shell
#        command encodes the framebuffer as base64-wrapped PPM on COM1; this
#        script decodes it back into a usable image file.
# USAGE: serial-fbdump.sh SERIAL_LOG OUT_PPM
#   SERIAL_LOG — path to a file containing captured COM1 output (the log must
#                include the output of a `fbdump` invocation).
#   OUT_PPM    — destination PPM file path.
#
# The kernel emits:
#   [fbdump-begin]
#   [fbdump] <base64-chunk>
#   [fbdump] <base64-chunk>
#   ...
#   [fbdump-end]
#
# This script extracts the base64 payload, decodes it, validates the PPM
# header, and writes the result to OUT_PPM. Exits 1 on any error.

set -euo pipefail

if [[ $# -ne 2 ]]; then
    echo "usage: $0 SERIAL_LOG OUT_PPM" >&2
    exit 2
fi

SERIAL_LOG="$1"
OUT_PPM="$2"

if [[ ! -f "${SERIAL_LOG}" ]]; then
    echo "error: serial log not found: ${SERIAL_LOG}" >&2
    exit 1
fi

# Check that the sentinels are both present.
if ! grep -q '\[fbdump-begin\]' "${SERIAL_LOG}"; then
    echo "error: no [fbdump-begin] sentinel found in ${SERIAL_LOG}" >&2
    echo "  has the fbdump command been run in the guest?" >&2
    exit 1
fi
if ! grep -q '\[fbdump-end\]' "${SERIAL_LOG}"; then
    echo "error: [fbdump-begin] found but no [fbdump-end] — capture may be incomplete" >&2
    exit 1
fi

# Extract base64 payload: lines between sentinels that start with "[fbdump] ",
# strip the prefix, concatenate, decode.
TMPFILE="$(mktemp /tmp/fbdump-b64.XXXXXX)"
trap 'rm -f "${TMPFILE}"' EXIT

python3 - "${SERIAL_LOG}" "${TMPFILE}" "${OUT_PPM}" <<'PY'
import base64
import re
import sys

log_path, b64_path, ppm_path = sys.argv[1], sys.argv[2], sys.argv[3]

in_dump = False
b64_lines = []

with open(log_path, "r", errors="replace") as f:
    for raw_line in f:
        line = raw_line.rstrip("\r\n")
        if "[fbdump-begin]" in line:
            in_dump = True
            b64_lines = []
            continue
        if "[fbdump-end]" in line:
            in_dump = False
            continue
        if in_dump:
            # Strip the "[fbdump] " prefix; the rest is base64 payload.
            m = re.match(r'\[fbdump\] (.+)', line)
            if m:
                b64_lines.append(m.group(1).strip())

if not b64_lines:
    print("error: no [fbdump] payload lines found between sentinels", file=sys.stderr)
    sys.exit(1)

b64_data = "".join(b64_lines)
try:
    raw_bytes = base64.b64decode(b64_data)
except Exception as e:
    print(f"error: base64 decode failed: {e}", file=sys.stderr)
    sys.exit(1)

# Write decoded bytes to temp path first, then validate.
with open(b64_path, "wb") as f:
    f.write(raw_bytes)

# Validate PPM P6 header: must start with "P6\n" then width height maxval.
if len(raw_bytes) < 10 or not raw_bytes.startswith(b"P6"):
    print(f"error: decoded data does not start with PPM P6 magic (got {raw_bytes[:4]!r})",
          file=sys.stderr)
    sys.exit(1)

# Parse header tokens to verify width/height are sane.
rest = raw_bytes[2:]
tokens = []
i = 0
while len(tokens) < 3 and i < len(rest):
    # Skip whitespace.
    while i < len(rest) and rest[i:i+1] in (b' ', b'\t', b'\r', b'\n'):
        i += 1
    # Skip comment lines.
    if i < len(rest) and rest[i:i+1] == b'#':
        while i < len(rest) and rest[i:i+1] != b'\n':
            i += 1
        continue
    # Read token.
    j = i
    while j < len(rest) and rest[j:j+1] not in (b' ', b'\t', b'\r', b'\n'):
        j += 1
    if j > i:
        tokens.append(int(rest[i:j]))
        i = j

if len(tokens) < 3:
    print(f"error: PPM header truncated (only {len(tokens)} of 3 required tokens)",
          file=sys.stderr)
    sys.exit(1)

width, height, maxval = tokens
if maxval != 255:
    print(f"error: unexpected PPM maxval {maxval} (expected 255)", file=sys.stderr)
    sys.exit(1)

expected_pixel_bytes = width * height * 3
actual_data_bytes = len(raw_bytes)
if actual_data_bytes < expected_pixel_bytes + 10:
    print(f"error: PPM too small: got {actual_data_bytes} bytes "
          f"for {width}x{height} image (need ≥{expected_pixel_bytes + 10})",
          file=sys.stderr)
    sys.exit(1)

import shutil
shutil.copy(b64_path, ppm_path)
print(f"fbdump: decoded {width}x{height} PPM -> {ppm_path} ({actual_data_bytes} bytes)")
PY
