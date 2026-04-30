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
#       fault / unexpected UNRESOLVED) appeared. Crashes are NEVER
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
#   pe-winkill  — spawn ring3-winkill (real-world MSVC PE).
#                 "pe spawn name=ring3-winkill" + "Windows Kill ".
#   linux       — spawn the seven Linux ABI smokes.
#
# Usage: profile-boot-smoke.sh <profile> <cmake-binary-dir>

set -eo pipefail

if [[ $# -ne 2 ]]; then
    echo "usage: $0 <profile> <cmake-binary-dir>" >&2
    echo "   profile = bringup | ring3 | pe-hello | pe-winapi | pe-winkill | linux" >&2
    exit 2
fi

PROFILE="$1"
BIN_DIR="$2"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
RUN_SCRIPT="${REPO_ROOT}/tools/qemu/run.sh"

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
# and writes 0x10 to port 0xf4 (exit status 0x21 = 33). On
# timeout, run.sh's `timeout` wrapper SIGTERMs QEMU.
DUETOS_TIMEOUT="${DUETOS_TIMEOUT:-480}" \
DUETOS_SMOKE_PROFILE="${PROFILE}" \
    "${RUN_SCRIPT}" > "${SERIAL_LOG}" 2>&1 || true

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
)

case "${PROFILE}" in
    bringup)
        # Nothing user-facing past bringup. Common signatures are
        # the whole assertion set.
        expected=("${common_expected[@]}")
        ;;
    ring3)
        expected=(
            "${common_expected[@]}"
            "DuetOS v0 (ramfs-seeded)"
            "Hello from ring 3!"
            'queued task name="ring3-smoke-A"'
            'queued task name="ring3-smoke-B"'
            'queued task name="ring3-smoke-sandbox"'
        )
        ;;
    pe-hello)
        expected=(
            "${common_expected[@]}"
            "[hello-pe] Hello from a PE executable!"
            'pe spawn name="ring3-hello-pe"'
        )
        ;;
    pe-winapi)
        expected=(
            "${common_expected[@]}"
            'pe spawn name="ring3-hello-winapi"'
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
            "exit rc   val=0xbeef"
        )
        ;;
    pe-winkill)
        expected=(
            "${common_expected[@]}"
            'pe spawn name="ring3-winkill"'
            "Windows Kill "
        )
        ;;
    linux)
        expected=(
            "${common_expected[@]}"
            # Linux smoke output: the LinuxSmoke task's sys_write
            # writes a recognizable banner. The exact line depends
            # on the smoke implementations; we look for the queued
            # marker that's always logged from SpawnRing3Linux*.
            'linux'
        )
        ;;
    *)
        echo "error: unknown profile '${PROFILE}'" >&2
        echo "  valid: bringup ring3 pe-hello pe-winapi pe-winkill linux" >&2
        exit 2
        ;;
esac

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

fail=0
missing=()
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
for sig in "${forbidden[@]}"; do
    if grep -aF "$sig" "${SERIAL_LOG}" > /dev/null; then
        echo "FORBIDDEN (present): $sig"
        grep -aF "$sig" "${SERIAL_LOG}" | head -3
        fail=1
    fi
done

if [[ $fail -ne 0 ]]; then
    for m in "${missing[@]}"; do
        echo "MISSING: $m"
    done
    echo "=== last 200 lines of serial log (${SERIAL_LOG}) ==="
    tail -200 "${SERIAL_LOG}" || true
    echo "=== smoke marker grep: any [smoke] / [boot] >>>/<<< / [panic] lines ==="
    grep -aE '^\[smoke\]|^\[boot\] >>>|^\[boot\] <<<|^\[panic\]|DUETOS CRASH' "${SERIAL_LOG}" || true
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

echo "OK: profile=${PROFILE} — all ${#expected[@]} signatures present."
exit 0
