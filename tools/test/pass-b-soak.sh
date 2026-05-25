#!/usr/bin/env bash
#
# pass-b-soak.sh — Pass B ambient-motion soak (Task 23).
#
# WHAT IT DOES
#   Boots the kernel with DUETOS_PROFILE=login-soak, holds for
#   SOAK_SECONDS seconds (boot ~10 s + 30 s soak window = 45 s default),
#   then asserts on the captured serial log:
#     - no compositor missed-tick warnings
#     - no soft-lockup warnings
#     - no [E] lines from wallpaper / splash / login modules
#
#   The canonical boot-log-analyze.sh runs first (exits non-zero on any
#   non-deliberate regression sentinel it recognises); Pass B specific
#   grep checks follow on top.
#
# USAGE
#   tools/test/pass-b-soak.sh
#
# ENV
#   LOG              — output log path (default: build/pass-b-soak.log)
#   SOAK_SECONDS     — total QEMU timeout in seconds (default: 45;
#                      covers ~10 s boot + 30 s ambient-motion soak)
#   DUETOS_PROFILE   — boot profile passed to run.sh (default: login-soak)
#   DUETOS_LOG_DIR   — log output dir (overrides LOG default if set)
#
# EXIT CODES
#   0 — PASS: no regression detected
#   1 — FAIL: one or more assertions failed
#   2 — tooling missing (run.sh not found / not executable)

set -euo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

SOAK_SECONDS="${SOAK_SECONDS:-45}"
DUETOS_PROFILE="${DUETOS_PROFILE:-login-soak}"

# Log location: honour DUETOS_LOG_DIR if set, otherwise default to build/.
if [[ -n "${DUETOS_LOG_DIR:-}" ]]; then
    LOG_DIR="${DUETOS_LOG_DIR}"
else
    LOG_DIR="${REPO_ROOT}/build"
fi
mkdir -p "${LOG_DIR}"
LOG="${LOG:-${LOG_DIR}/pass-b-soak.log}"

# Tooling guard.
if [[ ! -x "${REPO_ROOT}/tools/qemu/run.sh" ]]; then
    echo "ERROR: ${REPO_ROOT}/tools/qemu/run.sh missing or not executable" >&2
    exit 2
fi

echo "[pass-b-soak] profile=${DUETOS_PROFILE} soak=${SOAK_SECONDS}s log=${LOG}"

# Boot the kernel and capture the serial transcript.
# run.sh exits non-zero on timeout (expected); suppress with || true.
DUETOS_TIMEOUT="${SOAK_SECONDS}" \
DUETOS_PROFILE="${DUETOS_PROFILE}" \
    "${REPO_ROOT}/tools/qemu/run.sh" \
    > "${LOG}" 2>&1 || true

echo "[pass-b-soak] boot complete — analyzing ${LOG}"

# ── Canonical triage ──────────────────────────────────────────────────────────
# boot-log-analyze.sh is the authoritative regression gate (CLAUDE.md).
# It exits 1 if any non-deliberate failure sentinel appears.
ANALYZE="${REPO_ROOT}/tools/test/boot-log-analyze.sh"
if [[ -x "${ANALYZE}" ]]; then
    echo
    echo "=== boot-log-analyze ==="
    if ! bash "${ANALYZE}" "${LOG}"; then
        echo "[pass-b-soak] FAIL: boot-log-analyze flagged a regression" >&2
        exit 1
    fi
fi

# ── Pass B specific checks ────────────────────────────────────────────────────
# grep -c exits 1 on zero matches; || true keeps set -e from aborting.
err_count=$(grep -caE 'wallpaper \[E\]|splash \[E\]|login \[E\]' "${LOG}" || true)
# Count only WARN-level soft-lockup lines that are NOT from the deliberate
# soft-lockup self-test (which uses sentinel task names selftest-42 /
# selftest-99 and is always paired with a "self-test OK" line).
# Pattern: the diag/ subsystem WARN is the canonical signal; the self-test
# entries also match because they're logged by the same path, so subtract
# those out explicitly.
lockup_all=$(grep -caE 'diag/soft-lockup.*soft-lockup' "${LOG}" || true)
lockup_deliberate=$(grep -caE 'selftest-(42|99)' "${LOG}" || true)
lockups=$(( ${lockup_all:-0} - ${lockup_deliberate:-0} ))
missed_ticks=$(grep -caE 'compositor.*missed.?tick' "${LOG}" || true)

# Normalise to 0 in case grep returned empty (e.g. binary-detected file).
err_count="${err_count:-0}"
lockups="${lockups:-0}"
missed_ticks="${missed_ticks:-0}"

echo
echo "[pass-b-soak] counters:"
echo "  wallpaper/splash/login [E] lines : ${err_count}"
echo "  soft-lockup warnings             : ${lockups}"
echo "  compositor missed ticks          : ${missed_ticks}"

if [[ "${err_count}" -gt 0 ]] || [[ "${lockups}" -gt 0 ]] || [[ "${missed_ticks}" -gt 0 ]]; then
    echo
    echo "[pass-b-soak] FAIL — one or more counters > 0; inspect ${LOG}" >&2
    exit 1
fi

echo
echo "[pass-b-soak] PASS"
