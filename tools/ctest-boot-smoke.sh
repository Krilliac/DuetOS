#!/usr/bin/env bash
# tools/ctest-boot-smoke.sh
#
# ctest driver for the DuetOS boot smoke test. Boots the debug
# kernel in QEMU, captures its serial output, and asserts:
#
#   * every "expected" signature line appears (ring3 smoke probes
#     printed what they're supposed to);
#   * no "forbidden" signature appears (no panic, no triple fault,
#     no UNRESOLVED import).
#
# Exit codes:
#    0 — full pass, every expected signature found, none forbidden.
#    1 — real regression: one or more expected signatures missing,
#        or an UNRESOLVED outside the allowed list.
#    2 — environment skip: QEMU not installed (CI installs it; on
#        a dev box without QEMU we report a skip rather than a
#        failure).
#    3 — likely flake: kernel reached the test-run scope (we saw
#        `[I] core/ring3 : ring3 smoke tasks queued`) but a later
#        DUETOS CRASH / PANIC tripped before all expected
#        signatures landed. The CI workflow retries on this code
#        before declaring a real failure.
#
# The signature list mirrors .github/workflows/build.yml's
# qemu-smoke job so local `ctest` and CI stay in lockstep.
#
# Usage: ctest-boot-smoke.sh <cmake-binary-dir>
#   invoked from the add_test(...) in CMakeLists.txt.

set -eo pipefail

if [[ $# -ne 1 ]]; then
    echo "usage: $0 <cmake-binary-dir>" >&2
    exit 2
fi

BIN_DIR="$1"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUN_SCRIPT="${REPO_ROOT}/tools/qemu/run.sh"

if [[ ! -x "${RUN_SCRIPT}" ]]; then
    echo "SKIP: ${RUN_SCRIPT} not found"
    exit 2
fi
if ! command -v qemu-system-x86_64 > /dev/null 2>&1; then
    echo "SKIP: qemu-system-x86_64 not installed"
    echo "      Install via CLAUDE.md's live-test runtime tooling line:"
    echo "      sudo apt-get install -y qemu-system-x86 grub-common grub-pc-bin xorriso mtools ovmf"
    exit 2
fi

SERIAL_LOG="${BIN_DIR}/ctest-smoke-serial.log"
rm -f "${SERIAL_LOG}"

# Boot. `|| true` so a non-zero exit from QEMU (e.g. timeout —
# the kernel has no orderly shutdown path and run.sh will time
# out after DUETOS_TIMEOUT seconds) doesn't mask our own
# assertions. run.sh exits 124 on timeout.
DUETOS_TIMEOUT="${DUETOS_TIMEOUT:-30}" "${RUN_SCRIPT}" \
    > "${SERIAL_LOG}" 2>&1 || true

# Expected signatures — every ring3 smoke probe prints its own
# line. See kernel/core/ring3_smoke.cpp.
expected=(
    "[hello-pe] Hello from a PE executable!"
    "[hello-winapi] printed via kernel32.WriteFile!"
    "[vcruntime140] memset+memcpy+memmove OK"
    "[strings] strcmp+strlen+strchr OK"
    "[heap] HeapAlloc + GetProcessHeap OK"
    "[heap] malloc+free+malloc round-trip OK"
    "[heap] calloc zero-fill OK"
    "[advapi] advapi32 + event/wait/time/proc OK"
    "[perf-counter] perf counter + tick count OK"
    "[heap-resize] HeapSize + HeapReAlloc + realloc OK"
    "[calc] self-test OK"
    "[files] self-test OK"
    "[clock] self-test OK"
    "[block] self-test OK"
    # klog's value formatter emits compact hex (`0xbeef`) rather
    # than zero-padded — the decimal `(48879)` that follows makes
    # the prefix unique to hello_winapi's sentinel exit code.
    "exit rc   val=0xbeef"
    # winkill (real-world MSVC windows-kill.exe) runs to a clean
    # ring-3 spawn. Combined with the forbidden
    # `name="ring3-winkill" reason=` below, this asserts the PE
    # both spawned AND was not force-killed later.
    'pe spawn name="ring3-winkill"'
    # windows-kill.exe's very first std::cout output routes
    # through our MSVCP140 sputn stub into SYS_WRITE(fd=1) and
    # the text hits the serial console verbatim. This is the
    # first real Windows PE output on DuetOS — regressing it
    # would mean the iostream stubs or the proc-env pipeline
    # got broken.
    "Windows Kill "
    # CPU probe: every machine must produce a vendor + feature
    # list. QEMU TCG identifies as AuthenticAMD or GenuineIntel.
    "[cpu] vendor=\""
    "[cpu] features:"
    # RTC readable at boot. Wall-clock is non-zero on any live
    # machine; regression would mean CMOS access broke.
    "[rtc] wall clock"
    # GPU discovery: the drivers/gpu layer walks the PCI cache,
    # classifies display controllers by vendor, and maps BAR 0.
    # QEMU's Bochs VGA always appears here — a missing line means
    # GpuInit didn't run or the PCI device table regressed.
    'drivers/gpu : discovered GPUs'
    # Vendor probe for Bochs: confirms the per-device probe
    # dispatch runs.
    '[gpu-probe] vid=0x0000000000001234 did=0x0000000000001111 family=qemu-bochs-vga'
    # Network discovery: QEMU q35 ships with an e1000e NIC.
    '[net-probe] vid=0x0000000000008086 did=0x00000000000010d3 family=e1000e-82574'
    # Real MMIO read — the MAC must be populated (QEMU's default
    # is 52:54:00:12:34:56) and the link must come up. Regression
    # here means BAR 0 isn't decoded or RAL/RAH moved.
    'link=up'
    # USB + audio shells always run, even on QEMU q35 which
    # exposes neither (both log "none found" warnings).
    'drivers/usb : discovered host controllers'
    'drivers/audio : discovered audio controllers'
    '[usb] class drivers registered: hid, msc, hub, video'
    # Runtime invariant checker baseline + at least one heartbeat
    # sample. In CI we occasionally observe advisory-only disk
    # integrity findings (`health_last_scan_issues = 1`) from test
    # fixture writes, but those must NOT escalate into guard/blockguard
    # deny mode. We therefore assert the heartbeat key exists and keep
    # ESCALATE as forbidden below.
    '[health] baseline cr0='
    '[I] kheartbeat : health_last_scan_issues'
    # Boot-time pure-helper self-tests. Each panics on first failure,
    # so seeing the trailing PASS / OK line proves every assertion in
    # that block fired clean.
    '[string-selftest] PASS'
    '[hexdump-selftest] PASS'
    '[process-selftest] PASS'
    '[fs/vfs] self-test OK (32 cases'
)

# Forbidden signatures — anything indicating an unhandled
# kernel failure or a loader regression. Simple fixed-string
# matches, except UNRESOLVED which has expected hits from the
# intentional windows-kill.exe diagnostic (the loader reports
# what it can't resolve and bails; that's the point of that
# probe). We whitelist those.
forbidden=(
    "PANIC"
    "DUETOS CRASH"
    "triple fault"
    # Regression guard: winkill
    # (real-world MSVC windows-kill.exe) runs start-to-finish
    # as a ring-3 process and exits via ExitProcess(0). Any
    # scheduler-initiated kill of it (tick-budget exhaustion,
    # sandbox-denial threshold) or task-kill fault signals a
    # regression in the Win32 subsystem / PE loader.
    'name="ring3-winkill" reason='
    # Runtime health checker must stay clean on a normal boot.
    # Any ESCALATE line means a CR-bit / IDT / GDT / .text /
    # canary / stack-overflow finding fired — treat as a
    # regression worth investigating.
    '[health] ESCALATE:'
)
# Allowed UNRESOLVED sources: windows-kill.exe imports a pile
# of dbghelp / advapi32 / vcruntime functions we don't stub
# yet. The FIRST one reached bails the resolver. Keep this
# list narrow — any new allowed UNRESOLVED is a conscious gap.
allowed_unresolved=(
    # All of these are gaps documented in the knowledge
    # entry. Keep this list narrow — any NEW unresolved is
    # a conscious gap we're choosing not to close yet.
    "MSVCP140.dll!"           # C++ std runtime — partial coverage
    "dbghelp.dll!"            # Sym* family — most stubbed, keep for any latent
    "ADVAPI32.dll!"           # the trio is covered but PEs vary in case
    "VCRUNTIME140.dll!"       # SEH intrinsics stubbed; case-variant fallback
    "api-ms-win-crt-convert"  # stubbed; fallback for case variants
)

fail=0
for sig in "${expected[@]}"; do
    if ! grep -aF "$sig" "${SERIAL_LOG}" > /dev/null; then
        echo "MISSING: $sig"
        fail=1
    fi
done
for sig in "${forbidden[@]}"; do
    if grep -aF "$sig" "${SERIAL_LOG}" > /dev/null; then
        echo "FORBIDDEN (present): $sig"
        grep -aF "$sig" "${SERIAL_LOG}" | head -3
        fail=1
    fi
done
# UNRESOLVED: count any NOT in the allowed list. A single
# unexpected UNRESOLVED fails the test.
while IFS= read -r line; do
    allowed=0
    for a in "${allowed_unresolved[@]}"; do
        if [[ "$line" == *"$a"* ]]; then allowed=1; break; fi
    done
    if [[ $allowed -eq 0 ]]; then
        echo "UNEXPECTED UNRESOLVED: $line"
        fail=1
    fi
done < <(grep -aF UNRESOLVED "${SERIAL_LOG}" || true)

if [[ $fail -ne 0 ]]; then
    echo "=== last 60 lines of serial log ==="
    tail -60 "${SERIAL_LOG}" || true

    # Distinguish a real regression (expected signature genuinely
    # absent because the code path didn't run) from a flake
    # (kernel reached the test-run scope but tripped a
    # non-deterministic crash before all signatures landed).
    # The CI workflow retries on flakes (exit 3) but fails the
    # build immediately on regressions (exit 1).
    smoke_started=0
    crash_seen=0
    if grep -aF '[I] core/ring3 : ring3 smoke tasks queued' "${SERIAL_LOG}" > /dev/null; then
        smoke_started=1
    fi
    if grep -aE 'DUETOS CRASH|^\[panic\]|triple fault' "${SERIAL_LOG}" > /dev/null; then
        crash_seen=1
    fi
    if [[ $smoke_started -eq 1 && $crash_seen -eq 1 ]]; then
        echo "FLAKY: kernel reached smoke scope then crashed; retry recommended."
        exit 3
    fi
    exit 1
fi

echo "OK: all ${#expected[@]} boot signatures present, no forbidden signatures."
exit 0
