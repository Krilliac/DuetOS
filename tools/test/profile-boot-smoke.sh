#!/usr/bin/env bash
# tools/test/profile-boot-smoke.sh
#
# Profile-aware qemu-smoke runner. Boots one DuetOS smoke profile,
# captures its serial output, asserts the per-profile signature
# list, and reports pass / regression / flake / skip via the same
# exit-code contract as ctest-boot-smoke.sh:
#
#   0 — full pass, every expected signature found, none forbidden.
#   1 — real regression: one or more expected signatures missing,
#       or a forbidden signature (PANIC / DUETOS CRASH / triple
#       fault / retired-import resolution failure) appeared. Crashes are NEVER
#       retried — a kernel that crashed once on a clean boot path
#       has a real bug, even if the next attempt happens to land
#       all the signatures.
#   2 — environment skip: QEMU not installed.
#
# The profile names mirror kernel/test/smoke_profile.h (the kernel
# is the source of truth):
#
#   bringup     — kernel boots through bringup-complete, sentinel,
#                 exit. Smallest profile; verifies driver init and
#                 self-tests.
#   ring3       — spawn ring3-smoke-A/B/sandbox; "Hello from ring 3!"
#                 and SYS_WRITE-cap-deny lines.
#   pe-hello    — spawn ring3-hello-pe (freestanding PE).
#   pe-winapi   — spawn ring3-hello-winapi (comprehensive Win32 PE).
#                 Carries the [vcruntime140] / [strings] / [heap] /
#                 [advapi] / [perf-counter] / [calc] / [files] /
#                 [clock] / [block] signatures.
#   pe-threads  — spawn thread_stress + thread2_smoke + thread3_smoke +
#                 syscall_stress; verify real-DLL thread imports, TID-native
#                 context isolation, and exit-code contracts.
#   pe-winkill  — spawn ring3-winkill (real-world MSVC PE).
#                 "pe spawn name=ring3-winkill" + "Windows Kill ".
#   linux       — spawn the seven Linux ABI smokes.
#   cancellation-smp — race four cancellation/lifetime boundaries.
#
# Usage: profile-boot-smoke.sh <profile> <cmake-binary-dir>

set -eo pipefail

if [[ $# -ne 2 ]]; then
    echo "usage: $0 <profile> <cmake-binary-dir>" >&2
    echo "   profile = bringup | ring3 | pe-hello | pe-winapi | pe-threads | pe-winkill | linux | cancellation-smp" >&2
    exit 2
fi

PROFILE="$1"
BIN_DIR="$2"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
RUN_SCRIPT="${REPO_ROOT}/tools/qemu/run.sh"

# Keep the guest topology independent of guest output. The CI matrix supports
# exactly the 2-vCPU and 4-vCPU cancellation-race legs documented below.
EXPECTED_CPUS="${DUETOS_EXPECTED_CPUS:-4}"
case "${EXPECTED_CPUS}" in
    2) QEMU_SMP="2,sockets=1,cores=2,threads=1" ;;
    4) QEMU_SMP="4,sockets=1,cores=2,threads=2" ;;
    *)
        echo "FAIL: invalid DUETOS_EXPECTED_CPUS='${EXPECTED_CPUS}' (supported: 2 or 4)" >&2
        exit 1
        ;;
esac

if [[ ! -x "${RUN_SCRIPT}" ]]; then
    echo "SKIP: ${RUN_SCRIPT} not found"
    exit 2
fi
if ! command -v qemu-system-x86_64 > /dev/null 2>&1; then
    echo "SKIP: qemu-system-x86_64 not installed" >&2
    exit 2
fi

SERIAL_LOG="${BIN_DIR}/smoke-${PROFILE}.log"
rm -f "${SERIAL_LOG}"

# Boot via run.sh with the smoke-profile env var. The script
# regenerates a per-profile ISO with `smoke=<profile>` baked into
# the grub cmdline + adds the isa-debug-exit device. QEMU exits
# cleanly when the kernel reaches the [smoke] complete sentinel
# and writes 0x10 to port 0xf4 (exit status 0x21 = 33). The
# boot-observability slice also exits with hierarchical codes on
# hang / phase-init-fail / panic. On a true hang (no isa-debug-exit
# write at all), run.sh's `timeout --preserve-status` wrapper
# SIGTERMs QEMU. Capture the exit code instead of discarding it.
QEMU_RC=0
DUETOS_TIMEOUT="${DUETOS_TIMEOUT:-480}" \
DUETOS_SMP="${QEMU_SMP}" \
DUETOS_SMOKE_PROFILE="${PROFILE}" \
    "${RUN_SCRIPT}" > "${SERIAL_LOG}" 2>&1 || QEMU_RC=$?

# Decode the run.sh exit status against the kernel's hierarchical
# scheme (kernel/diag/boot_observe.h). QEMU exits (b<<1)|1 for an
# isa-debug-exit byte b; so b = (rc-1)>>1. Top nibble = class, low
# nibble = core::Phase ordinal. Only the four kernel-emitted classes
# are structured — anything else (e.g. SIGTERM-on-timeout → 143) is
# left to the serial-log evidence below, never force-decoded.
PHASE_NAMES=(earlycon physmem paging heap idt apic time percpubsp sched smp drivers vfs userland)
EXIT_CLASS=""   # pass | hung | phase-init-fail | panic | "" (unstructured)
EXIT_PHASE=""
if (( QEMU_RC >= 1 && QEMU_RC <= 255 && QEMU_RC % 2 == 1 )); then
    b=$(((QEMU_RC - 1) / 2))
    cls=$((b & 0xF0))
    ord=$((b & 0x0F))
    if (( ord >= 0 && ord < ${#PHASE_NAMES[@]} )); then
        EXIT_PHASE="${PHASE_NAMES[$ord]}"
    fi
    case "${cls}" in
        16)  [[ "${b}" == "16" ]] && EXIT_CLASS="pass" ;;   # 0x10
        32)  EXIT_CLASS="hung" ;;                            # 0x20
        64)  EXIT_CLASS="phase-init-fail" ;;                 # 0x40
        112) EXIT_CLASS="panic" ;;                           # 0x70
    esac
fi
echo "smoke: qemu_rc=${QEMU_RC} exit_class=${EXIT_CLASS:-<unstructured>} exit_phase=${EXIT_PHASE:-n/a}"

# ----------------------------------------------------------------------
# Per-profile signature lists. The kernel-built ring3 trio prints
# "Hello from ring 3!" and a SYS_WRITE-deny line; the freestanding
# PE prints "[hello-pe] ..."; the comprehensive PE prints the heap /
# string / clock / etc. battery; the real-world PE prints "Windows
# Kill " from std::cout; the Linux smokes print [linux-smoke] /
# [linux-elf] / etc. Each list captures EXACTLY what the kernel
# emits on a clean run for that profile.
# ----------------------------------------------------------------------

# Common signatures for every profile — bringup-complete + the
# [smoke] complete sentinel + a couple of always-emitted boot
# self-tests. The forbidden list is also shared.
common_expected=(
    "boot : metrics bringup-complete"
    "[smoke] profile=${PROFILE} complete"
    "[string-selftest] PASS"
    "[hexdump-selftest] PASS"
    "[fs/vfs] self-test OK"
)
forbidden=(
    "PANIC"
    "DUETOS CRASH"
    "triple fault"
    "[health] ESCALATE:"
    "RETIRED import requires exact real DLL export"
    "RETIRED import uses unrecognized API-set provider"
    "UNRESOLVED kernel-provider ordinal import"
    "FAIL retired kernel32 export unavailable"
    # Any kernel selftest failure, from any subsystem. The kernel has
    # ~370 "[<tag>] FAIL" sites across 105 selftests and none of them
    # could fail a boot before this entry: expected[] names only a
    # handful of PASS lines, so every other selftest could fail
    # silently. Fixed-string match is safe because nothing in kernel/
    # or userland/ emits "] FAILED" / "] FAILURE" to collide with.
    "] FAIL"
)

# `scenario` = the per-profile scenario output (NOT covered by the
# structured [boot-report], which reports boot health only). `expected`
# = common + scenario, used unchanged by the legacy fallback path when
# a kernel predates the [boot-report] block.
case "${PROFILE}" in
    bringup)
        # Nothing user-facing past bringup; boot health IS the test.
        scenario=()
        ;;
    ring3)
        scenario=(
            "DuetOS v0 (ramfs-seeded)"
            "Hello from ring 3!"
            'queued task name="ring3-smoke-A"'
            'queued task name="ring3-smoke-B"'
            'queued task name="ring3-smoke-sandbox"'
        )
        ;;
    pe-hello)
        scenario=(
            "[hello-pe] Hello from a PE executable!"
            'pe spawn name="ring3-hello-pe"'
            # Exception handling. The forbidden "] FAIL" pattern does
            # NOT cover these — their failure lines read
            # "] RESULT FAIL" / "] <case>: FAIL" — so without naming
            # the PASS lines here the whole EH engine could regress
            # on a green boot.
            "[seh_pe] RESULT PASS"
            "[seh_try] except-null-write: PASS"
            "[seh_try] except-div-zero: PASS"
            "[seh_try] finally-on-unwind: PASS"
            "[seh_try] raise-exception: PASS"
            "[seh_try] RESULT PASS"
            "[cxxeh] int-catch: PASS"
            "[cxxeh] class-ref-catch: PASS"
            "[cxxeh] destructor-unwind: PASS"
            "[cxxeh] catch-all: PASS"
            "[cxxeh] RESULT PASS"
            # PE loader directories 9 (TLS) and 13 (delay-load). Same
            # reasoning as the EH block above, and verified the hard
            # way: with ResolveDelayImports stubbed out, delayload_pe
            # printed RESULT FAIL and BOTH this script and
            # boot-log-analyze.sh still exited 0. Naming the PASS
            # lines is the only thing that turns these fixtures into
            # a gate.
            "[tls_pe] tls-callback-before-entry: PASS"
            "[tls_pe] static-tls-template-copied: PASS"
            "[tls_pe] per-thread-tls-template: PASS"
            "[tls_pe] dll-thread-attach: PASS"
            "[tls_pe] per-thread-tls-independence: PASS"
            "[tls_pe] RESULT PASS"
            "[delayload_pe] delay-iat-bound-outside-image: PASS"
            "[delayload_pe] delay-call-returns-real-values: PASS"
            "[delayload_pe] helper-not-invoked: PASS"
            "[delayload_pe] RESULT PASS"
        )
        ;;
    pe-winapi)
        scenario=(
            'pe spawn name="ring3-hello-winapi"'
            "[hello-winapi] printed via kernel32.WriteFile!"
            "[vcruntime140] memset+memcpy+memmove OK"
            "[strings] strcmp+strlen+strchr OK"
            "[winfmt] MulDiv+wsprintfA OK"
            "[winfmt2] GetDateFormat picture OK"
            "[heap] HeapAlloc + GetProcessHeap OK"
            "[heap] malloc+free+malloc round-trip OK"
            "[heap] calloc zero-fill OK"
            "[advapi] advapi32 + event/wait/time/proc OK"
            "[perf-counter] perf counter + tick count OK"
            "[interlocked] InterlockedInc/Dec/XAdd/Xchg/CmpXchg OK"
            "[tls] real TLS (Alloc/Set/Get/Free) OK"
            "[heap-resize] HeapSize + HeapReAlloc + realloc OK"
            "[calculator-selftest] PASS"
            "[files] self-test OK"
            "[clock] self-test OK"
            "[block] self-test OK"
            'pe spawn name="ring3-tls-smoke"'
            "[ring3-tls-smoke] PASS"
            'pe spawn name="ring3-thunk-alias-smoke"'
            "[thunk_alias_smoke] kernel32.dll pseudo-handle PASS"
            "[thunk_alias_smoke] kernelbase.dll pseudo-handle PASS"
            "[thunk_alias_smoke] api-ms-win-core-processthreads-l1-1-0.dll IDs PASS"
            "[thunk_alias_smoke] api-ms-win-core-errorhandling-l1-1-0.dll thread-local last-error PASS"
            "[thunk_alias_smoke] kernelbase/API-set TLS round-trip PASS"
            "[thunk_alias_smoke] TLS generation/concurrent allocation PASS"
            "[thunk_alias_smoke] kernelbase.dll InterlockedExchangeAdd PASS"
            "[thunk_alias_smoke] api-ms-win-core-interlocked-l1-1-0.dll bitwise atomics PASS"
            "[thunk_alias_smoke] api-ms-win-core-interlocked-l1-1-0.dll increment/decrement PASS"
            "[thunk_alias_smoke] kernelbase.dll exchange/compare-exchange PASS"
            "[thunk_alias_smoke] contended core interlocked operations PASS"
            "[thunk_alias_smoke] api-ms-win-core-profile-l1-1-0.dll QPC/QPF PASS"
            "[thunk_alias_smoke] kernelbase.dll GetTickCount PASS"
            "[thunk_alias_smoke] api-ms-win-core-sysinfo-l1-1-0.dll GetTickCount64 PASS"
            "[ring3-thunk-alias-smoke] PASS"
            "exit rc   val=0xbeef"
            "via-dll kernel32.dll!GetCurrentProcess"
            "via-dll kernel32.dll!GetCurrentThread"
            "via-dll kernel32.dll!GetCurrentProcessId"
            "via-dll kernel32.dll!GetCurrentThreadId"
            "via-dll kernel32.dll!GetLastError"
            "via-dll kernel32.dll!SetLastError"
            "via-dll kernel32.dll!TlsAlloc"
            "via-dll kernel32.dll!TlsFree"
            "via-dll kernel32.dll!TlsGetValue"
            "via-dll kernel32.dll!TlsSetValue"
            "via-dll kernel32.dll!InterlockedExchangeAdd"
            "via-dll kernel32.dll!InterlockedIncrement"
            "via-dll kernel32.dll!InterlockedDecrement"
            "via-dll kernel32.dll!InterlockedExchange"
            "via-dll kernel32.dll!InterlockedCompareExchange"
            "via-dll kernelbase.dll!InterlockedExchange"
            "via-dll kernelbase.dll!InterlockedCompareExchange"
            "via-dll kernelbase.dll!TlsGetValue"
            "via-dll kernelbase.dll!TlsSetValue"
            "via-dll kernel32.dll!QueryPerformanceCounter"
            "via-dll kernel32.dll!QueryPerformanceFrequency"
            "via-dll kernel32.dll!GetTickCount"
            "via-dll kernel32.dll!GetTickCount64"
            "via-dll kernelbase.dll!GetCurrentThread"
            "via-dll api-ms-win-core-processthreads-l1-1-0.dll!GetCurrentProcessId"
            "via-dll api-ms-win-core-processthreads-l1-1-0.dll!GetCurrentThreadId"
            "via-dll api-ms-win-core-errorhandling-l1-1-0.dll!GetLastError"
            "via-dll api-ms-win-core-errorhandling-l1-1-0.dll!SetLastError"
            "via-retired-provider kernelbase.dll!InterlockedExchangeAdd -> kernel32.dll"
            "via-retired-provider api-ms-win-core-interlocked-l1-1-0.dll!InterlockedAnd -> kernel32.dll"
            "via-retired-provider api-ms-win-core-interlocked-l1-1-0.dll!InterlockedOr -> kernel32.dll"
            "via-retired-provider api-ms-win-core-interlocked-l1-1-0.dll!InterlockedXor -> kernel32.dll"
            "via-retired-provider api-ms-win-core-interlocked-l1-1-0.dll!InterlockedIncrement -> kernel32.dll"
            "via-retired-provider api-ms-win-core-interlocked-l1-1-0.dll!InterlockedDecrement -> kernel32.dll"
            "via-retired-provider api-ms-win-core-processthreads-l1-1-0.dll!TlsAlloc -> kernel32.dll"
            "via-retired-provider api-ms-win-core-processthreads-l1-1-0.dll!TlsFree -> kernel32.dll"
            "via-retired-provider kernelbase.dll!GetTickCount -> kernel32.dll"
            "via-retired-provider api-ms-win-core-profile-l1-1-0.dll!QueryPerformanceCounter -> kernel32.dll"
            "via-retired-provider api-ms-win-core-profile-l1-1-0.dll!QueryPerformanceFrequency -> kernel32.dll"
            "via-retired-provider api-ms-win-core-sysinfo-l1-1-0.dll!GetTickCount64 -> kernel32.dll"
        )
        ;;
    pe-threads)
        scenario=(
            'pe spawn name="ring3-thread-stress"'
            "[thread-stress] main: PASS"
            'pe spawn name="ring3-thread2-smoke"'
            "[thread2_smoke] GetExitCodeThread     = PASS (0x42)"
            "[ring3-thread2-smoke] PASS"
            'pe spawn name="ring3-thread3-smoke"'
            "[thread3_smoke] local context round-trip= PASS"
            "[thread3_smoke] foreign close/reuse      = PASS"
            "[thread3_smoke] exited context quiescent= PASS"
            "[ring3-thread3-smoke] PASS"
            'pe spawn name="ring3-syscall-stress"'
            "[syscall-stress] main: FreeLibraryAndExitThread(childB)"
            "[syscall-stress] main: PASS"
            "exit rc   val=0xabcde"
            "exit rc   val=0xcafe"
            "via-dll kernel32.dll!CreateThread"
            "via-dll kernel32.dll!ExitThread"
            "via-dll kernel32.dll!FreeLibraryAndExitThread"
            "via-dll kernel32.dll!GetExitCodeThread"
            "via-dll kernel32.dll!InterlockedAnd"
            "via-dll kernel32.dll!InterlockedOr"
            "via-dll kernel32.dll!InterlockedXor"
        )
        ;;
    pe-winkill)
        scenario=(
            'pe spawn name="ring3-winkill"'
            "Windows Kill "
        )
        ;;
    linux)
        scenario=(
            # The LinuxSmoke task's sys_write writes a recognizable
            # banner; the exact line depends on the smoke impls, so we
            # look for the marker always logged from SpawnRing3Linux*.
            'linux'
        )
        ;;
    cancellation-smp)
        scenario=(
            "[cancel-smp] case=publication-barrier PASS"
            "[cancel-smp] case=kmutex-wake PASS"
            "[cancel-smp] case=iocp-timeout PASS"
            "[cancel-smp] case=message-port-close PASS"
            "[cancel-smp] PASS cpus=${EXPECTED_CPUS} cases=4"
        )
        ;;
    *)
        echo "error: unknown profile '${PROFILE}'" >&2
        echo "  valid: bringup ring3 pe-hello pe-winapi pe-threads pe-winkill linux cancellation-smp" >&2
        exit 2
        ;;
esac
expected=("${common_expected[@]}" "${scenario[@]}")

# Boot-banner sniff — selftest pass-marker signatures
# (string/hexdump/fs-vfs) only appear when the build was compiled
# with DUETOS_BOOT_SELFTESTS=ON. Auto-skip them when the banner
# doesn't show `+selftests` so this driver runs uniformly across
# debug, release, and every flavor preset.
banner=$(grep -aF '[boot] DuetOS build flavor:' "${SERIAL_LOG}" | head -1 || true)
selftests_on=0
if [[ "${banner}" == *"+selftests"* ]]; then
    selftests_on=1
fi
echo "smoke: profile=${PROFILE} banner=${banner:-<missing>}"
echo "smoke: selftests_on=${selftests_on}"

selftest_sigs=(
    "[string-selftest] PASS"
    "[hexdump-selftest] PASS"
    "[fs/vfs] self-test OK"
)

# ----------------------------------------------------------------------
# Decision. The forbidden backstop is always on. The structured
# [boot-report] block + the hierarchical exit code are the primary
# gate when present; the legacy full-signature list is the fallback
# for a kernel that predates the boot-observability slice.
# ----------------------------------------------------------------------
fail=0
missing=()

# Forbidden backstop (PANIC / crash / triple fault / health escalate).
for sig in "${forbidden[@]}"; do
    if grep -aF "$sig" "${SERIAL_LOG}" > /dev/null; then
        echo "FORBIDDEN (present): $sig"
        grep -aF "$sig" "${SERIAL_LOG}" | head -3
        fail=1
    fi
done

# Structured-failure evidence. The kernel ALWAYS emits a
# [boot] phase=... STUCK/FAIL (or a panic) serial line *before* it
# TestExits, so the serial line is authoritative and the decoded
# QEMU exit code is only corroborating detail. This matters because a
# SIGTERM-on-timeout exit (143) coincidentally lands in the
# phase-init-fail rc range — decoding rc in isolation would mislabel
# a plain hang. So: trust the serial line; enrich with the rc decode.
struct_line=$(grep -aE '^\[boot\] phase=.* (STUCK|FAIL) ' "${SERIAL_LOG}" | tail -2 || true)
if [[ -n "${struct_line}" ]]; then
    echo "BOOT PHASE FAILURE (qemu_rc=${QEMU_RC}, decoded=${EXIT_CLASS:-?} phase=${EXIT_PHASE:-?}):"
    echo "${struct_line}"
    fail=1
fi

if grep -aqF '[boot-report] begin' "${SERIAL_LOG}"; then
    echo "smoke: gate=structured ([boot-report] present)"
    if ! grep -aF '[boot-report] result=pass' "${SERIAL_LOG}" > /dev/null; then
        missing+=("[boot-report] result=pass")
        fail=1
    fi
    if ! grep -aF "[smoke] profile=${PROFILE} complete" "${SERIAL_LOG}" > /dev/null; then
        missing+=("[smoke] profile=${PROFILE} complete")
        fail=1
    fi
    # The [boot-report] covers boot health only; per-profile scenario
    # output is still asserted explicitly.
    for sig in "${scenario[@]}"; do
        if ! grep -aF "$sig" "${SERIAL_LOG}" > /dev/null; then
            missing+=("$sig")
            fail=1
        fi
    done
else
    echo "smoke: gate=legacy (no [boot-report]; full signature list)"
    for sig in "${expected[@]}"; do
        # Skip selftest-only signatures when this build had selftests off.
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
            missing+=("$sig")
            fail=1
        fi
    done
fi

if [[ $fail -ne 0 ]]; then
    for m in "${missing[@]}"; do
        echo "MISSING: $m"
    done
    echo "=== last 200 lines of serial log (${SERIAL_LOG}) ==="
    tail -200 "${SERIAL_LOG}" || true
    echo "=== smoke marker grep: any [smoke] / [boot] >>>/<<< / [bringup-tail] / [panic] / [panic-summary] lines ==="
    grep -aE '^\[smoke\]|^\[boot\] >>>|^\[boot\] <<<|^\[bringup-tail\]|^\[panic\]|^\[panic-summary\]|DUETOS CRASH' "${SERIAL_LOG}" || true
    # Crash-dump header fields (subsystem / message / value / vector
    # / rip / cr2 / reason). These lines are 2-space-indented inside
    # the `=== DUETOS CRASH DUMP ===` bracket, so the marker grep
    # above misses them. When a verbose post-panic dump (wifi-diag
    # ring, log ring, peer-CPU snapshots, etc.) crowds out the
    # `tail -200` window, these extracted fields stay readable in
    # CI even when the rest of the dump has scrolled off-screen.
    echo "=== crash dump header fields ==="
    grep -aE '^  (subsystem|message  |value    |vector    |vector_name|rip       |cs        |rsp       |cr2       |reason    |rip      |rsp      |rbp      |task     |pid       )[ ]*: ' "${SERIAL_LOG}" | head -25 || true
    # Crash-analysis banner the kernel emits when the faulting RIP
    # is recognisably wild — the banner spells out the likely root
    # cause + next-step checklist (see kernel/util/symbols.cpp).
    grep -aE '^  \[!\] crash analysis|^      hint   :|^      cause\? :|^      next   :' "${SERIAL_LOG}" || true
    echo "=== expected signature presence map ==="
    for sig in "${expected[@]}"; do
        if grep -aF "$sig" "${SERIAL_LOG}" > /dev/null; then
            printf '  PRESENT : %s\n' "$sig"
        else
            printf '  MISSING : %s\n' "$sig"
        fi
    done
    echo "=== relevant ring3 / PE / Linux output (probe payload check) ==="
    grep -aE '^\[hello-pe\]|^\[hello-winapi\]|^\[vcruntime140\]|^\[strings\]|^\[heap\]|^\[advapi\]|^\[perf-counter\]|^\[heap-resize\]|^\[calc\]|^\[files\]|^\[clock\]|^\[block\]|^Hello from ring 3|^DuetOS v0|^Windows Kill|^\[ring3\] pe spawn|exit rc' "${SERIAL_LOG}" | head -40 || true

    # Any forbidden signature OR missing expected signature is a
    # regression. We don't distinguish "crashed-before-sentinel" as
    # a flake any more — if the kernel crashed during a clean boot
    # path, that's a real bug, and retrying past it just hides the
    # signal. The exit-3 retry tier was removed deliberately;
    # callers (CI workflows) should treat this as a single-attempt
    # gate.
    exit 1
fi

echo "OK: profile=${PROFILE} — boot-report result=pass, sentinel + scenario signatures present."
exit 0
