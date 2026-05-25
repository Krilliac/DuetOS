#!/usr/bin/env bash
#
# WHAT:  Capture the live DuetOS framebuffer via QMP screendump.
# WHY:   Lets a controlling agent (Claude Code or a CI harness) see the
#        current desktop state without user-supplied screenshots.
# USAGE: qmp-screendump.sh [OUT_PATH]
#   OUT_PATH defaults to /tmp/duetos-live.ppm
#   Prints the PPM path to stdout on success.
#
# ENV:
#   DUETOS_PRESET    — build preset (default: x86_64-debug)
#   DUETOS_QMP_SOCK  — override QMP socket path
#
# The output PPM is a P6 binary image (raw RGB, 24 bpp) written by QEMU
# from QEMU's perspective — so OUT_PATH must be host-absolute. For a
# Linux/WSL guest, /tmp/... is always a valid host path.

set -euo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

OUT_PATH="${1:-/tmp/duetos-live.ppm}"

# Resolve OUT_PATH to an absolute path so QEMU gets an unambiguous location.
# QEMU writes to the path as seen by the process that launched it (host FS).
if [[ "${OUT_PATH}" != /* ]]; then
    OUT_PATH="$(pwd)/${OUT_PATH}"
fi

# Remove stale output so we can detect a new write.
rm -f "${OUT_PATH}"

"${SCRIPT_DIR}/qmp-cmd.sh" \
    "$(printf '{"execute":"screendump","arguments":{"filename":"%s"}}' "${OUT_PATH}")" \
    > /dev/null

# Verify the file appeared and is large enough to be a real framebuffer dump.
# A 1024x768x3 PPM header + body is ~2.36 MiB; 100 KiB is a conservative floor
# that rejects a zero-byte or truncated write.
if [[ ! -f "${OUT_PATH}" ]]; then
    echo "error: screendump command succeeded but ${OUT_PATH} was not written" >&2
    exit 1
fi

SIZE=$(stat -c%s "${OUT_PATH}" 2>/dev/null || stat -f%z "${OUT_PATH}" 2>/dev/null || echo 0)
if [[ "${SIZE}" -lt 102400 ]]; then
    echo "error: ${OUT_PATH} is only ${SIZE} bytes — likely not a real framebuffer dump" >&2
    exit 1
fi

echo "${OUT_PATH}"
