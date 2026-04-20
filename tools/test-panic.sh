#!/usr/bin/env bash
#
# Panic-path regression test.
#
# Builds the kernel with -DCUSTOMOS_PANIC_DEMO=ON (compiles in a
# deliberate core::Panic at the end of kernel_main), boots in QEMU,
# captures the serial output, then verifies that every expected
# section of the diagnostic dump is present. Restores the build
# flag to OFF on exit so subsequent normal `cmake --build` calls
# produce a kernel that doesn't halt on purpose.
#
# What the test asserts:
#
#   1. The panic banner fires with the expected subsystem tag.
#   2. The "--- diagnostics ---" block shows up.
#   3. Every control register the dump claims to emit (CR0..CR4,
#      EFER, RFLAGS) has a labelled line.
#   4. The backtrace section emits at least one frame.
#   5. The stack dump section emits at least one quad.
#   6. The log-ring section shows up and carries at least one entry
#      from the boot sequence (the klog self-test line is a good
#      stable marker).
#   7. The final "CPU halted" banner appears — i.e. Halt was reached.
#
# Usage:
#     tools/test-panic.sh           # build + boot + assert
#     tools/test-panic.sh -q        # quiet on success (exit 0, no log)
#     tools/test-panic.sh -s        # pipe the panic log through symbolize.sh
#
# Exits 0 on pass, non-zero on any missing assertion.

set -euo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
readonly PRESET="${CUSTOMOS_PRESET:-x86_64-debug}"
readonly BUILD_DIR="${REPO_ROOT}/build/${PRESET}"

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
    cmake --preset "${PRESET}" -DCUSTOMOS_PANIC_DEMO=OFF >/dev/null 2>&1 || true
    cmake --build "${BUILD_DIR}" --target customos-kernel -- >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "[test-panic] configuring with CUSTOMOS_PANIC_DEMO=ON"
cmake --preset "${PRESET}" -DCUSTOMOS_PANIC_DEMO=ON >/dev/null

echo "[test-panic] building"
cmake --build "${BUILD_DIR}" >/dev/null

echo "[test-panic] booting (10 s timeout)"
LOG="$(mktemp)"
CUSTOMOS_TIMEOUT=10 "${REPO_ROOT}/tools/qemu/run.sh" >"${LOG}" 2>&1 || true

if [[ "${SYMBOLIZE}" -eq 1 ]]; then
    RESOLVED="$(mktemp)"
    "${REPO_ROOT}/tools/symbolize.sh" <"${LOG}" >"${RESOLVED}"
    mv "${RESOLVED}" "${LOG}"
fi

# ---- assertions ---------------------------------------------------------

fail=0
assert_contains() {
    local pattern="$1"; local what="$2"
    if ! grep -qE "${pattern}" "${LOG}"; then
        echo "[test-panic] MISSING: ${what}  (pattern: ${pattern})"
        fail=1
    fi
}

assert_contains '\[panic\] test/panic-demo: CUSTOMOS_PANIC_DEMO enabled' "panic banner"
assert_contains '\[panic\] --- diagnostics ---'                       "diagnostics header"
assert_contains '^  uptime[[:space:]]+:'                              "uptime field"
assert_contains '^  rip[[:space:]]+:'                                 "rip field"
assert_contains '^  rsp[[:space:]]+:'                                 "rsp field"
assert_contains '^  rbp[[:space:]]+:'                                 "rbp field"
assert_contains '^  cr0[[:space:]]+:'                                 "cr0 field"
assert_contains '^  cr2[[:space:]]+:'                                 "cr2 field"
assert_contains '^  cr3[[:space:]]+:'                                 "cr3 field"
assert_contains '^  cr4[[:space:]]+:'                                 "cr4 field"
assert_contains '^  rflags[[:space:]]+:'                              "rflags field"
assert_contains '^  efer[[:space:]]+:'                                "efer field"
assert_contains 'backtrace \(up to 16 frames'                         "backtrace header"
assert_contains '^    #0x0+[0-9]  rip=0x'                             "at least one backtrace frame"
assert_contains 'stack \(0x[0-9a-f]+ quads from rsp\)'                "stack-dump header"
assert_contains '^    \[0x0' "at least one stack quad"
assert_contains '\[panic\] --- log ring'                              "log-ring header"
assert_contains '\[D\] core/klog : debug-level sanity line'           "log-ring entry (klog selftest)"
assert_contains '\[panic\] CPU halted — no recovery'                  "halt banner"

if [[ "${fail}" -ne 0 ]]; then
    echo "[test-panic] FAIL — full log below:"
    cat "${LOG}"
    rm -f "${LOG}"
    exit 1
fi

if [[ "${QUIET}" -eq 0 ]]; then
    echo "[test-panic] captured log:"
    echo "----8<----"
    cat "${LOG}"
    echo "---->8----"
fi

echo "[test-panic] PASS — all diagnostic sections present"
rm -f "${LOG}"
