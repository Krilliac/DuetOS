#!/usr/bin/env bash
# tools/test/ctest-boot-smoke.sh
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
#        an UNRESOLVED outside the allowed list, or a forbidden
#        signature (PANIC / DUETOS CRASH / triple fault) appeared.
#        Crashes are NEVER retried — a kernel that crashed once on
#        a clean boot path has a real bug, even if the next attempt
#        happens to land all the signatures.
#    2 — environment skip: QEMU not installed (CI installs it; on
#        a dev box without QEMU we report a skip rather than a
#        failure).
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
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
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
# duetos.iso is built only when grub-mkrescue + xorriso are present
# at configure time. Without them, the iso target is disabled and
# a kernel-boot test would have nothing to feed QEMU. Report SKIP
# rather than FAIL — same shape as the qemu-not-installed branch
# above. The cmake configure line that emits "duetos-iso target
# disabled" is the matching message on the build side.
if [[ ! -f "${BIN_DIR}/duetos.iso" ]]; then
    echo "SKIP: ${BIN_DIR}/duetos.iso not built"
    echo "      The iso target is disabled when grub-mkrescue / xorriso are"
    echo "      missing at configure time. Install via CLAUDE.md's live-test"
    echo "      runtime tooling line:"
    echo "      sudo apt-get install -y grub-common grub-pc-bin xorriso mtools"
    exit 2
fi
# run.sh defaults DUETOS_PRESET=x86_64-debug. ctest may have invoked
# us with a different preset's binary dir (the cmake --preset value
# is the basename of BIN_DIR). Pin DUETOS_PRESET so run.sh's
# BUILD_DIR matches the directory the iso lives in.
export DUETOS_PRESET="$(basename "${BIN_DIR}")"

SERIAL_LOG="${BIN_DIR}/ctest-smoke-serial.log"
rm -f "${SERIAL_LOG}"

# Boot. `|| true` so a non-zero exit from QEMU (e.g. timeout —
# the kernel has no orderly shutdown path and run.sh will time
# out after DUETOS_TIMEOUT seconds) doesn't mask our own
# assertions. run.sh exits 124 on timeout.
# Default bumped from 90s → 150s. QEMU TCG on a slower CI host
# routinely needs ~70-90s just to reach the post-smoke phase
# (kernel-heap + paging + SMP + smoke spawn + winkill PE +
# native-app spawns). The 90s default left no headroom; CI runs
# saw flaky "MISSING: Windows Kill" failures when winkill ran
# slightly slower than usual. 150s is comfortable on every
# host the project has tested on while still keeping the smoke
# under 3 minutes wall-clock.
DUETOS_TIMEOUT="${DUETOS_TIMEOUT:-150}" "${RUN_SCRIPT}" \
    > "${SERIAL_LOG}" 2>&1 || true

# Expected signatures — every ring3 smoke probe prints its own
# line. See kernel/proc/ring3_smoke.cpp.
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
    "[settings] self-test OK"
    "[notify] self-test OK"
    "[magnifier] self-test OK"
    "[timezone] self-test OK"
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
    '[fs/vfs] self-test OK (lookup + jail + .. + path_max + VfsResolve)'
    # Disk-installer layout self-test (pure math, no I/O). A
    # regression here means the partition planner drifted.
    '[fs/installer] self-test OK'
    # Portable native ELF apps spawned by main.cpp next to the
    # usershell. Each is a sentinel that regression-traps the
    # native-app pipeline (build → embed → spawn → libc syscall
    # → exit). See `wiki/tooling/Native-Apps.md`.
    '[hello-native] portable native ELF spawned'
    '[nat-calc] all eval cases passed'
    '[nat-sysinfo] report complete'
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

# Boot-banner sniff — read the build flavor + active knobs from
# the first line the kernel emits. Used below to auto-skip
# expected signatures that only appear when their corresponding
# build knob is on. Lets the same smoke driver run uniformly
# against debug, release, and every flavor preset.
banner=$(grep -aF '[boot] DuetOS build flavor:' "${SERIAL_LOG}" | head -1 || true)
selftests_on=0
if [[ "${banner}" == *"+selftests"* ]]; then
    selftests_on=1
fi
echo "smoke: detected banner: ${banner:-<missing>}"
echo "smoke: selftests_on=${selftests_on}"

# Signatures emitted only when DUETOS_BOOT_SELFTESTS is on
# (boot self-tests gated on `kBootSelfTests`). Always present
# in debug; absent in plain release / release-asserts / release-lto.
# Auto-skipped when the banner doesn't show `+selftests`.
selftest_sigs=(
    "[calc] self-test OK"
    "[files] self-test OK"
    "[clock] self-test OK"
    "[block] self-test OK"
    "[settings] self-test OK"
    "[notify] self-test OK"
    "[magnifier] self-test OK"
    "[timezone] self-test OK"
    "[string-selftest] PASS"
    "[hexdump-selftest] PASS"
    "[process-selftest] PASS"
    "[fs/vfs] self-test OK (32 cases"
)

fail=0
for sig in "${expected[@]}"; do
    # Skip selftest signatures when this build had selftests off.
    if [[ ${selftests_on} -eq 0 ]]; then
        is_selftest_sig=0
        for ss in "${selftest_sigs[@]}"; do
            if [[ "$sig" == "$ss" ]]; then is_selftest_sig=1; break; fi
        done
        if [[ ${is_selftest_sig} -eq 1 ]]; then
            continue
        fi
    fi
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

    # Any forbidden signature OR missing expected signature is a
    # regression. The previous "kernel-reached-smoke-scope-then-
    # crashed = flake" exit-3 tier was removed deliberately — a
    # crash on a clean boot path is a real bug, and retrying past
    # it just hides the signal. Callers (CI workflows) should
    # treat this as a single-attempt gate.
    exit 1
fi

echo "OK: all ${#expected[@]} boot signatures present, no forbidden signatures."
exit 0
