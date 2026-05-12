#!/usr/bin/env bash
# tools/test/diff-boot-smoke.sh
#
# Differential-boot harness. Boots one DuetOS smoke profile under
# several emulator configurations (cpu model, accelerator, firmware)
# and diffs the canonical sentinel stream across configs.
#
# The premise: any given bug profile of an emulator paper-overs
# (e.g. TCG's lax handling of an undefined flag, KVM's host-only
# feature exposure, OVMF's specific memory-map shape) is one config.
# If a kernel passes one config but fails another, the divergence
# IS the bug — even if no row hit a forbidden sentinel.
#
# Default matrix (three rows, ~3x the wall-clock of profile-boot-
# smoke for one profile under TCG):
#
#   row A : accel=tcg, cpu=qemu64, firmware=uefi   — baseline
#   row B : accel=tcg, cpu=max,    firmware=uefi   — wide CPUID
#   row C : accel=tcg, cpu=qemu64, firmware=seabios — legacy boot
#
# Accelerator is pinned to `tcg` on every row: KVM hands the guest
# host silicon and would erase the cross-config signal we're after.
# A future slice can add a Bochs row for stricter x86 semantics
# (different bug profile entirely).
#
# Exit codes:
#   0 — every row passed AND every row produced the same canonical
#       sentinel set.
#   1 — one or more rows failed (real regression).
#   2 — rows passed individually but their sentinel sets diverged
#       (config-dependent behaviour — also a bug, but distinct
#       from a single-row crash).
#   3 — environment skip (QEMU not installed, ISO not built, etc.).
#
# Usage: diff-boot-smoke.sh <profile> <cmake-binary-dir>
#   profile: any value profile-boot-smoke.sh accepts
#            (bringup | ring3 | pe-hello | pe-winapi | pe-winkill | linux)

set -eo pipefail

if [[ $# -ne 2 ]]; then
    echo "usage: $0 <profile> <cmake-binary-dir>" >&2
    exit 3
fi

PROFILE="$1"
BIN_DIR="$2"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PROFILE_SCRIPT="${REPO_ROOT}/tools/test/profile-boot-smoke.sh"

if [[ ! -x "${PROFILE_SCRIPT}" ]]; then
    echo "SKIP: ${PROFILE_SCRIPT} not found" >&2
    exit 3
fi
if ! command -v qemu-system-x86_64 > /dev/null 2>&1; then
    echo "SKIP: qemu-system-x86_64 not installed" >&2
    echo "      install via CLAUDE.md's live-test runtime tooling line" >&2
    exit 3
fi
if [[ ! -f "${BIN_DIR}/duetos.iso" ]]; then
    echo "SKIP: ${BIN_DIR}/duetos.iso not built" >&2
    exit 3
fi

# Matrix rows: "tag|accel|cpu|legacy". Pipe-delimited because spaces
# in tag values would split badly under set -e. legacy=1 selects
# SeaBIOS (DUETOS_LEGACY=1); legacy=0 leaves the UEFI default in
# place. Adding a row is one line — keep this list tight; every
# row adds ~one TCG boot's worth of wall-clock to the harness.
ROWS=(
    "A-tcg-qemu64-uefi|tcg|qemu64|0"
    "B-tcg-max-uefi|tcg|max|0"
    "C-tcg-qemu64-seabios|tcg|qemu64|1"
)

# Canonical-sentinel filter. Keeps only structured kernel output —
# the lines the smoke harness asserts on — and normalises away
# noise that's expected to differ between rows even on a healthy
# boot (addresses, timestamps, per-CPU markers, ASLR-randomised
# bases). What's left after filtering is the comparable "shape"
# of the boot.
#
# Patterns intentionally narrow: anything not on this list is
# considered noise. If you add a new structural sentinel to the
# kernel, add a matching pattern here.
filter_canonical() {
    local src="$1"
    local dst="$2"
    grep -aE '^\[(smoke|boot|panic|panic-summary|health|bringup-tail|string-selftest|hexdump-selftest|fs/vfs|hello-pe|hello-winapi|vcruntime140|strings|heap|advapi|perf-counter|heap-resize|calc|files|clock|block|ring3|linux-smoke|linux-elf)\]|boot : metrics|^Hello from ring 3!|^DuetOS v0|^Windows Kill|^exit rc|^pe spawn|^queued task|PANIC|DUETOS CRASH|triple fault|UNRESOLVED' "${src}" \
      | sed -E \
          -e 's/0x[0-9a-fA-F]+/0xX/g' \
          -e 's/\[[0-9]+\.[0-9]+\]/[T]/g' \
          -e 's/\[CPU[0-9]+\]/[CPU]/g' \
          -e 's/(pid|tid|rip|rsp|rbp|cr2)=[0-9a-fA-FxX]+/\1=N/g' \
          -e 's/serial=[0-9a-fA-F]+/serial=N/g' \
          -e 's/mac=([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}/mac=M/g' \
      | LC_ALL=C sort -u > "${dst}"
}

# Run one row. Returns exit status of profile-boot-smoke.sh; writes
# the raw serial log to ${row_log_raw} and the filtered canonical
# stream to ${row_log_canon}. Both are kept on disk for later
# inspection regardless of pass/fail.
run_row() {
    local tag="$1" accel="$2" cpu="$3" legacy="$4"
    local row_dir="${BIN_DIR}/diff-${PROFILE}-${tag}"
    rm -rf "${row_dir}"
    mkdir -p "${row_dir}"

    echo "[diff] row=${tag} accel=${accel} cpu=${cpu} legacy=${legacy}" >&2

    local rc=0
    # profile-boot-smoke.sh writes its serial log to BIN_DIR/smoke-
    # <profile>.log. We want one per row, so each row runs against
    # a per-row scratch BIN_DIR that symlinks the canonical iso /
    # kernel ELF + ovmf vars into place. Cheaper than mutating the
    # canonical BIN_DIR or threading a new env var through.
    ln -sf "${BIN_DIR}/duetos.iso" "${row_dir}/duetos.iso"
    mkdir -p "${row_dir}/kernel"
    if [[ -f "${BIN_DIR}/kernel/duetos-kernel.elf" ]]; then
        ln -sf "${BIN_DIR}/kernel/duetos-kernel.elf" \
               "${row_dir}/kernel/duetos-kernel.elf"
    fi

    local legacy_env=""
    if [[ "${legacy}" == "1" ]]; then
        legacy_env="DUETOS_LEGACY=1"
    fi

    # eval so a row with legacy_env="" doesn't pass an empty arg to
    # env. profile-boot-smoke.sh inherits DUETOS_PRESET / DUETOS_TIMEOUT
    # from our environment if set; we don't override either here.
    set +e
    eval ${legacy_env} \
         DUETOS_ACCEL="${accel}" \
         DUETOS_CPU="${cpu}" \
         "${PROFILE_SCRIPT}" "${PROFILE}" "${row_dir}" \
         > "${row_dir}/runner.log" 2>&1
    rc=$?
    set -e

    # profile-boot-smoke.sh always writes smoke-<profile>.log into
    # its bindir argument. Pick it up from the per-row dir.
    if [[ -f "${row_dir}/smoke-${PROFILE}.log" ]]; then
        cp "${row_dir}/smoke-${PROFILE}.log" "${row_dir}/serial.log"
        filter_canonical "${row_dir}/serial.log" "${row_dir}/canonical.txt"
    else
        : > "${row_dir}/serial.log"
        : > "${row_dir}/canonical.txt"
    fi

    echo "${rc}" > "${row_dir}/rc"
    return "${rc}"
}

# ---- run every row ------------------------------------------------
ROW_TAGS=()
ROW_RCS=()
ROW_DIRS=()
any_fail=0
for spec in "${ROWS[@]}"; do
    IFS='|' read -r tag accel cpu legacy <<< "${spec}"
    set +e
    run_row "${tag}" "${accel}" "${cpu}" "${legacy}"
    rc=$?
    set -e
    ROW_TAGS+=("${tag}")
    ROW_RCS+=("${rc}")
    ROW_DIRS+=("${BIN_DIR}/diff-${PROFILE}-${tag}")
    if [[ "${rc}" -ne 0 && "${rc}" -ne 2 ]]; then
        # rc=2 from profile-boot-smoke = environment skip; surface
        # as a top-level skip rather than a regression.
        any_fail=1
    fi
done

# ---- summarise ----------------------------------------------------
echo
echo "=== diff-boot-smoke: profile=${PROFILE} matrix summary ==="
for i in "${!ROW_TAGS[@]}"; do
    printf '  row=%-24s rc=%s canon=%d lines\n' \
        "${ROW_TAGS[$i]}" "${ROW_RCS[$i]}" \
        "$(wc -l < "${ROW_DIRS[$i]}/canonical.txt" 2>/dev/null || echo 0)"
done

# Any row reporting environment skip on its own (rc=2 from
# profile-boot-smoke) is treated as a harness skip overall — we
# can't compare what we couldn't run.
for rc in "${ROW_RCS[@]}"; do
    if [[ "${rc}" == "2" ]]; then
        echo "SKIP: at least one row reported environment skip"
        exit 3
    fi
done

if [[ "${any_fail}" -ne 0 ]]; then
    echo "FAIL: one or more rows failed; per-row runner.log + serial.log"
    echo "      preserved under ${BIN_DIR}/diff-${PROFILE}-*/"
    for i in "${!ROW_TAGS[@]}"; do
        if [[ "${ROW_RCS[$i]}" -ne 0 ]]; then
            echo "  --- failing row ${ROW_TAGS[$i]} (last 40 lines of runner.log) ---"
            tail -40 "${ROW_DIRS[$i]}/runner.log" || true
        fi
    done
    exit 1
fi

# All rows passed individually. Now diff their canonical streams.
# Pairwise diff against row 0 — if any pair differs, the matrix
# diverges. Three-way `comm` is awkward; pairwise diff is enough
# for a three-row matrix and the diff output is directly readable.
BASE_CANON="${ROW_DIRS[0]}/canonical.txt"
diverged=0
for i in "${!ROW_TAGS[@]}"; do
    if [[ "${i}" == "0" ]]; then continue; fi
    if ! diff -q "${BASE_CANON}" "${ROW_DIRS[$i]}/canonical.txt" > /dev/null; then
        diverged=1
        echo "=== DIVERGE: row[0]=${ROW_TAGS[0]} vs row[${i}]=${ROW_TAGS[$i]} ==="
        diff -u "${BASE_CANON}" "${ROW_DIRS[$i]}/canonical.txt" | head -80 || true
    fi
done

if [[ "${diverged}" -ne 0 ]]; then
    echo "FAIL: rows passed individually but their canonical sentinel sets"
    echo "      diverge. A config-dependent code path is producing different"
    echo "      observable behaviour — investigate before treating any single"
    echo "      row as authoritative."
    exit 2
fi

echo "OK: profile=${PROFILE} matrix converged across ${#ROW_TAGS[@]} configs."
exit 0
