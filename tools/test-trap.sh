#!/usr/bin/env bash
#
# CPU-exception regression test.
#
# Companion to tools/test-panic.sh. Builds the kernel with
# -DCUSTOMOS_TRAP_DEMO=ON (compiles in a deliberate `ud2` at the end
# of kernel_main), boots in QEMU, captures the serial output, then
# verifies the trap dispatcher produces the same extractable crash
# dump shape as core::Panic.
#
# Why a separate script: a CPU exception enters Panic-style dumping
# through a different code path (interrupt delivery → TrapDispatch →
# BeginCrashDump). Keeping this test distinct from test-panic.sh
# means a regression in the trap dispatcher won't masquerade as a
# Panic() regression, and vice versa.
#
# Crash-dump file layout:
#   Trap dumps are bracketed identically to Panic dumps:
#       === CUSTOMOS CRASH DUMP BEGIN ===
#       ...
#       === CUSTOMOS CRASH DUMP END ===
#   so the same awk-based extractor works. Dumps land in
#       build/<preset>/crash-dumps/YYYYMMDD-HHMMSS-trap.dump
#   (the `-trap` suffix distinguishes them from panic dumps).
#
# What the test asserts:
#
#   1. The dump markers bracket a non-empty record.
#   2. The dump subsystem is "arch/traps" (trap-originated, not Panic).
#   3. The dump message is the #UD vector mnemonic.
#   4. The RIP line carries an in-kernel symbolic annotation of the
#      form "[name+0xOFF (path:line)]" — i.e. the embedded symbol
#      table resolves the faulting instruction.
#   5. The backtrace section emits at least one symbolized frame.
#   6. The "--- log ring ---" section shows up so operators can see
#      what the kernel was doing when the fault hit.
#   7. The final "Halting CPU" banner appears.
#
# Usage:
#     tools/test-trap.sh            # build + boot + assert
#     tools/test-trap.sh -q         # quiet on success
#
# Exits 0 on pass, non-zero on any missing assertion.

set -euo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
readonly PRESET="${CUSTOMOS_PRESET:-x86_64-debug}"
readonly BUILD_DIR="${REPO_ROOT}/build/${PRESET}"
readonly DUMP_DIR="${BUILD_DIR}/crash-dumps"

QUIET=0
while (( $# > 0 )); do
    case "$1" in
        -q|--quiet) QUIET=1 ;;
        -h|--help)
            sed -n '2,/^$/p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *)
            echo "unknown arg: $1" >&2; exit 2 ;;
    esac
    shift
done

# Guarantee the flag is reset on exit so subsequent normal builds don't
# inherit the deliberate fault.
cleanup() {
    cmake --preset "${PRESET}" -DCUSTOMOS_TRAP_DEMO=OFF >/dev/null 2>&1 || true
    cmake --build "${BUILD_DIR}" --target customos-kernel -- >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "[test-trap] configuring with CUSTOMOS_TRAP_DEMO=ON"
cmake --preset "${PRESET}" -DCUSTOMOS_TRAP_DEMO=ON >/dev/null

echo "[test-trap] building"
cmake --build "${BUILD_DIR}" >/dev/null

echo "[test-trap] booting (10 s timeout)"
LOG="$(mktemp)"
CUSTOMOS_TIMEOUT=10 "${REPO_ROOT}/tools/qemu/run.sh" >"${LOG}" 2>&1 || true

# ---- dump extraction ----------------------------------------------------

mkdir -p "${DUMP_DIR}"
DUMP_FILE="${DUMP_DIR}/$(date -u +%Y%m%d-%H%M%S)-trap.dump"

awk '
    /=== CUSTOMOS CRASH DUMP BEGIN ===/ { inside = 1 }
    inside                              { print }
    /=== CUSTOMOS CRASH DUMP END ===/   { inside = 0 }
' "${LOG}" > "${DUMP_FILE}"

if [[ ! -s "${DUMP_FILE}" ]]; then
    echo "[test-trap] FAIL — no crash dump captured (markers missing)"
    echo "[test-trap] full serial log:"
    cat "${LOG}"
    rm -f "${LOG}"
    exit 1
fi
echo "[test-trap] crash dump saved: ${DUMP_FILE} ($(wc -c < "${DUMP_FILE}") bytes)"

# ---- assertions ---------------------------------------------------------

fail=0
assert_contains() {
    local pattern="$1"; local what="$2"; local file="${3:-${LOG}}"
    if ! grep -qE "${pattern}" "${file}"; then
        echo "[test-trap] MISSING: ${what}  (pattern: ${pattern})"
        fail=1
    fi
}

# Full-log assertions.
assert_contains '\*\* CPU EXCEPTION \*\*'           "CPU exception banner"
assert_contains '=== CUSTOMOS CRASH DUMP BEGIN ===' "dump begin marker"
assert_contains '=== CUSTOMOS CRASH DUMP END ==='   "dump end marker"
assert_contains '\[panic\] Halting CPU'             "halt banner"

# Dump-file assertions — extractable record contract.
assert_contains '^  version'                                "dump schema version"    "${DUMP_FILE}"
assert_contains '^  subsystem: arch/traps'                  "dump subsystem field"   "${DUMP_FILE}"
assert_contains '^  message  : #UD'                         "dump message field"     "${DUMP_FILE}"
assert_contains '^  symtab_entries : 0x[0-9a-f]*[1-9a-f][0-9a-f]*' \
                                                            "symbol table populated" "${DUMP_FILE}"
assert_contains '^  rip[[:space:]]+: 0x[0-9a-f]+  \[[^ ]+\+0x[0-9a-f]+ \([^)]+\)\]' \
                                                            "rip symbolized inline"  "${DUMP_FILE}"
assert_contains 'backtrace \(up to 16 frames'               "backtrace header"       "${DUMP_FILE}"
assert_contains '^    #0x0+[0-9]  rip=0x[0-9a-f]+  \[[^ ]+\+0x' \
                                                            "backtrace frame symbolized" "${DUMP_FILE}"
assert_contains '\[panic\] --- log ring'                    "log-ring header"        "${DUMP_FILE}"

if [[ "${fail}" -ne 0 ]]; then
    echo "[test-trap] FAIL — full log below:"
    cat "${LOG}"
    echo "[test-trap] extracted dump:"
    cat "${DUMP_FILE}"
    rm -f "${LOG}"
    exit 1
fi

if [[ "${QUIET}" -eq 0 ]]; then
    echo "[test-trap] captured log:"
    echo "----8<----"
    cat "${LOG}"
    echo "---->8----"
    echo "[test-trap] extracted dump: ${DUMP_FILE}"
fi

echo "[test-trap] PASS — trap dispatcher emits extractable crash dump"
rm -f "${LOG}"
