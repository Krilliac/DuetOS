#!/usr/bin/env bash
#
# Panic-path regression test.
#
# Builds the kernel with -DDUETOS_PANIC_DEMO=ON (compiles in a
# deliberate core::Panic at the end of kernel_main), boots in QEMU,
# captures the serial output, then verifies that every expected
# section of the diagnostic dump is present. Restores the build
# flag to OFF on exit so subsequent normal `cmake --build` calls
# produce a kernel that doesn't halt on purpose.
#
# Crash-dump file:
#   The kernel brackets its diagnostic dump with
#       === DUETOS CRASH DUMP BEGIN ===
#       ...
#       === DUETOS CRASH DUMP END ===
#   The test extracts those bytes into
#       build/<preset>/crash-dumps/YYYYMMDD-HHMMSS.dump
#   and asserts against that file. Without a kernel filesystem, serial
#   capture is how "dump files" are produced today — the markers make
#   extraction unambiguous and give host-side tooling a stable contract.
#
# What the test asserts:
#
#   1. The panic banner fires with the expected subsystem tag.
#   2. The crash-dump markers bracket a non-empty record.
#   3. The schema-version field is present and readable.
#   4. The "--- diagnostics ---" block shows up.
#   5. Every control register the dump claims to emit (CR0..CR4,
#      EFER, RFLAGS) has a labelled line.
#   6. The RIP line carries an in-kernel symbolic annotation of the
#      form "[name+0xOFF (path:line)]" — i.e. the embedded symbol
#      table is wired in and resolving.
#   7. The backtrace section emits at least one frame, symbolized.
#   8. The stack dump section emits at least one quad.
#   9. The log-ring section shows up and carries at least one entry
#      from the boot sequence (the klog self-test line is a good
#      stable marker).
#  10. The final "CPU halted" banner appears — i.e. Halt was reached.
#
# Usage:
#     tools/debug/test-panic.sh           # build + boot + assert
#     tools/debug/test-panic.sh -q        # quiet on success (exit 0, no log)
#     tools/debug/test-panic.sh -s        # pipe the panic log through symbolize.sh
#
# Exits 0 on pass, non-zero on any missing assertion.

set -euo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
readonly PRESET="${DUETOS_PRESET:-x86_64-debug}"
readonly BUILD_DIR="${REPO_ROOT}/build/${PRESET}"
readonly DUMP_DIR="${BUILD_DIR}/crash-dumps"

QUIET=0
SYMBOLIZE=0
while (( $# > 0 )); do
    case "$1" in
        -q|--quiet)     QUIET=1 ;;
        -s|--symbolize) SYMBOLIZE=1 ;;
        -h|--help)
            sed -n '2,/^$/p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *)
            echo "unknown arg: $1" >&2; exit 2 ;;
    esac
    shift
done

# Guarantee the flag is reset when we exit, even on assertion failure.
cleanup() {
    cmake --preset "${PRESET}" -DDUETOS_PANIC_DEMO=OFF >/dev/null 2>&1 || true
    cmake --build "${BUILD_DIR}" --target duetos-kernel -- >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "[test-panic] configuring with DUETOS_PANIC_DEMO=ON"
cmake --preset "${PRESET}" -DDUETOS_PANIC_DEMO=ON >/dev/null

echo "[test-panic] building"
cmake --build "${BUILD_DIR}" >/dev/null

# Boot via the qemu-smoke fast-path: a single-entry grub.cfg with
# timeout=0 instead of the 10 s interactive menu, so the QEMU run
# spends its budget actually reaching kernel_main rather than
# waiting on grub. The timeout still has to cover the post-grub
# debug-build init sequence (ramfs build, driver self-tests,
# klog warm-up) before kernel_main's deliberate Panic fires.
echo "[test-panic] booting (90 s timeout, smoke=panic-demo)"
LOG="$(mktemp)"
DUETOS_TIMEOUT=90 DUETOS_SMOKE_PROFILE=panic-demo "${REPO_ROOT}/tools/qemu/run.sh" >"${LOG}" 2>&1 || true

if [[ "${SYMBOLIZE}" -eq 1 ]]; then
    RESOLVED="$(mktemp)"
    "${REPO_ROOT}/tools/debug/symbolize.sh" <"${LOG}" >"${RESOLVED}"
    mv "${RESOLVED}" "${LOG}"
fi

# ---- dump extraction ----------------------------------------------------
# Pull the bytes between the BEGIN/END markers (inclusive) into a
# timestamped file. `awk` is simpler than sed for a ranged extract and
# exits cleanly even if only one marker is present.

mkdir -p "${DUMP_DIR}"
DUMP_FILE="${DUMP_DIR}/$(date -u +%Y%m%d-%H%M%S).dump"

awk '
    /=== DUETOS CRASH DUMP BEGIN ===/ { inside = 1 }
    inside                              { print }
    /=== DUETOS CRASH DUMP END ===/   { inside = 0 }
' "${LOG}" > "${DUMP_FILE}"

if [[ ! -s "${DUMP_FILE}" ]]; then
    echo "[test-panic] FAIL — no crash dump captured (markers missing)"
    echo "[test-panic] full serial log:"
    cat "${LOG}"
    rm -f "${LOG}"
    exit 1
fi
echo "[test-panic] crash dump saved: ${DUMP_FILE} ($(wc -c < "${DUMP_FILE}") bytes)"

# ---- assertions ---------------------------------------------------------

fail=0
assert_contains() {
    local pattern="$1"; local what="$2"; local file="${3:-${LOG}}"
    if ! grep -qE "${pattern}" "${file}"; then
        echo "[test-panic] MISSING: ${what}  (pattern: ${pattern})"
        fail=1
    fi
}

# Full-log assertions (banner, halt marker).
assert_contains '\[panic\] test/panic-demo: DUETOS_PANIC_DEMO enabled' "panic banner"
assert_contains '=== DUETOS CRASH DUMP BEGIN ===' "dump begin marker"
assert_contains '=== DUETOS CRASH DUMP END ==='   "dump end marker"
assert_contains '\[panic\] CPU halted — no recovery' "halt banner"

# Dump-file assertions — everything here must live BETWEEN the markers.
assert_contains '^  version'                                          "dump schema version"    "${DUMP_FILE}"
assert_contains '^  subsystem: test/panic-demo'                       "dump subsystem field"   "${DUMP_FILE}"
assert_contains '^  message  : DUETOS_PANIC_DEMO enabled'           "dump message field"     "${DUMP_FILE}"
assert_contains '^  symtab_entries : 0x[0-9a-f]*[1-9a-f][0-9a-f]*'    "symbol table populated" "${DUMP_FILE}"
assert_contains '\[panic\] --- diagnostics ---'                       "diagnostics header"     "${DUMP_FILE}"
assert_contains '^  uptime[[:space:]]+:'                              "uptime field"           "${DUMP_FILE}"
assert_contains '^  rip[[:space:]]+:'                                 "rip field"              "${DUMP_FILE}"
assert_contains '^  rsp[[:space:]]+:'                                 "rsp field"              "${DUMP_FILE}"
assert_contains '^  rbp[[:space:]]+:'                                 "rbp field"              "${DUMP_FILE}"
assert_contains '^  cr0[[:space:]]+:'                                 "cr0 field"              "${DUMP_FILE}"
assert_contains '^  cr2[[:space:]]+:'                                 "cr2 field"              "${DUMP_FILE}"
assert_contains '^  cr3[[:space:]]+:'                                 "cr3 field"              "${DUMP_FILE}"
assert_contains '^  cr4[[:space:]]+:'                                 "cr4 field"              "${DUMP_FILE}"
assert_contains '^  rflags[[:space:]]+:'                              "rflags field"           "${DUMP_FILE}"
assert_contains '^  efer[[:space:]]+:'                                "efer field"             "${DUMP_FILE}"
assert_contains '^  rip[[:space:]]+: 0x[0-9a-f]+  \[[^ ]+\+0x[0-9a-f]+ \([^)]+\)\]' \
                                                                      "rip symbolized inline"  "${DUMP_FILE}"
assert_contains '^  page-walk for rip=0x[0-9a-f]+ \(cr3=0x[0-9a-f]+\):' \
                                                                      "rip page-walk header"   "${DUMP_FILE}"
assert_contains '^    PML4\[0x[0-9a-f]+\] = 0x[0-9a-f]+ \[[^]]+\]'    "rip page-walk PML4 entry" "${DUMP_FILE}"
assert_contains 'backtrace \(up to 16 frames'                         "backtrace header"       "${DUMP_FILE}"
assert_contains '^    #0x0+[0-9]  rip=0x[0-9a-f]+  \[[^ ]+\+0x' \
                                                                      "backtrace frame symbolized" "${DUMP_FILE}"
assert_contains 'stack \(0x[0-9a-f]+ quads from rsp\)'                "stack-dump header"      "${DUMP_FILE}"
# Stack pointer can live in either the boot identity map (low VA) or the
# higher-half kernel stack arena depending on when the panic fires; match
# either form rather than anchoring on a specific high nibble.
assert_contains '^    \[0x[0-9a-f]+\] = 0x[0-9a-f]+'                  "at least one stack quad" "${DUMP_FILE}"
assert_contains 'return-address pointers \(scan of 0x[0-9a-f]+ quads from rsp\)' \
                                                                      "return-address-pointer header" "${DUMP_FILE}"
assert_contains '^    \[0x[0-9a-f]+\] -> 0x[0-9a-f]+  \[[^ ]+\+0x[0-9a-f]+ \([^)]+\)\]' \
                                                                      "return-address-pointer entry symbolized" "${DUMP_FILE}"
# LBR section is always emitted; the body is either populated entries
# (real Intel hardware) or a single "(unavailable on this CPU)" line
# (TCG QEMU + AMD + pre-Goldmont-Plus Intel). Either way the header
# proves DumpLbr ran.
assert_contains '^  LBR (\(last-branch records|\(unavailable on this CPU\))' \
                                                                      "LBR section header"     "${DUMP_FILE}"
assert_contains '\[panic\] --- log ring'                              "log-ring header"        "${DUMP_FILE}"
# Any timestamped log line proves the ring captured something. We used
# to assert on the klog self-test sanity line, but the ring is bounded
# (last 64 entries) and a longer boot pushes that line off — the boot
# trail itself is plenty of evidence the ring is wired in.
assert_contains '^\[t=[0-9.]+ms\]'                                    "log-ring has at least one timestamped entry" "${DUMP_FILE}"

# Binary minidump assertion. The kernel emits a Windows .dmp via
# debugcon (port 0xE9 → ${BUILD_DIR}/duetos.dmp) on every panic /
# trap. The file should be non-empty and start with the four-byte
# 'MDMP' signature so any debugger (Visual Studio / WinDbg /
# VSCode-cppvsdbg) can open it.
MINIDUMP="${BUILD_DIR}/duetos.dmp"
if [[ ! -s "${MINIDUMP}" ]]; then
    echo "[test-panic] MISSING: minidump file is empty or absent: ${MINIDUMP}"
    fail=1
elif [[ "$(head -c 4 "${MINIDUMP}")" != "MDMP" ]]; then
    echo "[test-panic] MISSING: minidump magic mismatch (expected 'MDMP'); first 16 bytes:"
    od -An -tx1 -N 16 "${MINIDUMP}"
    fail=1
else
    SIZE=$(stat -c %s "${MINIDUMP}")
    echo "[test-panic] minidump OK: ${MINIDUMP} (${SIZE} bytes, MDMP signature verified)"
fi

if [[ "${fail}" -ne 0 ]]; then
    echo "[test-panic] FAIL — full log below:"
    cat "${LOG}"
    echo "[test-panic] extracted dump:"
    cat "${DUMP_FILE}"
    rm -f "${LOG}"
    exit 1
fi

if [[ "${QUIET}" -eq 0 ]]; then
    echo "[test-panic] captured log:"
    echo "----8<----"
    cat "${LOG}"
    echo "---->8----"
    echo "[test-panic] extracted dump: ${DUMP_FILE}"
fi

echo "[test-panic] PASS — all diagnostic sections present"
rm -f "${LOG}"
