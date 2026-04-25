#!/usr/bin/env bash
#
# Boot DuetOS in survey mode, capture the cleanroom-trace ring
# buffer to a file.
#
# What "survey mode" means:
#   1. CMake is configured with -DDUETOS_CRTRACE_SURVEY=ON
#      (kernel/core/main.cpp adds an end-of-init dump loop;
#       kernel/fs/ramfs.cpp /etc/profile gains `crtrace show 256`).
#   2. boot/grub/grub.cfg is patched to default=2 timeout=0 so
#      the ISO boots straight into the TTY entry without UI.
#      The original grub.cfg is restored on exit (trap-protected).
#   3. tools/qemu/run.sh boots headless, COM1 -> stdout, captured
#      to $OUT_LOG.
#
# Usage:
#   tools/cleanroom/run-trace-survey.sh [out_log]
#
# Default out_log: build/<preset>/crtrace-survey.log
#
# The script exits non-zero if no `=== CRTRACE BOOT DUMP BEGIN`
# marker is found in the captured serial log.

set -euo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
readonly PRESET="${DUETOS_PRESET:-x86_64-debug}"
readonly BUILD_DIR="${REPO_ROOT}/build/${PRESET}"
readonly GRUB_CFG="${REPO_ROOT}/boot/grub/grub.cfg"
readonly GRUB_BAK="${GRUB_CFG}.preserve.$$"
readonly OUT_LOG="${1:-${BUILD_DIR}/crtrace-survey.log}"
readonly TIMEOUT="${DUETOS_TIMEOUT:-30}"

# Restore grub.cfg on any exit path so an interrupted run doesn't
# leave the tree in survey-default state.
restore_grub() {
    if [[ -f "${GRUB_BAK}" ]]; then
        mv "${GRUB_BAK}" "${GRUB_CFG}"
    fi
}
trap restore_grub EXIT

cp "${GRUB_CFG}" "${GRUB_BAK}"

# Patch grub.cfg to boot TTY by default, with no menu wait. The
# `set timeout=...` and `set default=...` lines are unique to the
# top of the file so a literal sed replace is safe.
sed -i \
    -e 's/^set timeout=.*/set timeout=0/' \
    -e 's/^set default=.*/set default=2/' \
    "${GRUB_CFG}"

# Reconfigure with survey flag if the cache doesn't already
# carry it. Idempotent — `cmake --preset` re-reading is cheap.
cmake --preset "${PRESET}" -DDUETOS_CRTRACE_SURVEY=ON >/dev/null
cmake --build "${BUILD_DIR}" --parallel "$(nproc)" >/dev/null

mkdir -p "$(dirname "${OUT_LOG}")"

DUETOS_TIMEOUT="${TIMEOUT}" "${REPO_ROOT}/tools/qemu/run.sh" \
    > "${OUT_LOG}" 2>&1 || true

if ! grep -q '=== CRTRACE BOOT DUMP BEGIN' "${OUT_LOG}"; then
    echo "error: no CRTRACE BOOT DUMP marker found in ${OUT_LOG}" >&2
    echo "       (DUETOS_CRTRACE_SURVEY did not take, or boot crashed before the dump)" >&2
    tail -50 "${OUT_LOG}" >&2
    exit 1
fi

echo "captured: ${OUT_LOG}"
echo "  CRTRACE entries:" \
    "$(grep -c '^CRTRACE [0-9a-fx]\+ ' "${OUT_LOG}" || true)"
echo "  Decode shell::command hashes with tools/cleanroom/decode_hash.py"
