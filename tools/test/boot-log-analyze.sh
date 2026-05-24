#!/usr/bin/env bash
#
# Launcher-agnostic DuetOS boot-log triage.
#
# Every DuetOS post-mortem keys off the COM1 serial transcript, not
# how the VM was launched. This consolidates the grep battery a
# debugging session re-types by hand — the CLAUDE.md "Fix Anything
# You Surface" regression scan, phase timings, self-test PASS/FAIL,
# lockdep inversion pairs, stress/loadtest summary, and the
# hypervisor/SMP banner — into one report that runs on ANY captured
# log: QEMU stdout, VMware/VirtualBox serial-to-file, a real-
# hardware UART capture, whatever.
#
# Usage:
#   tools/test/boot-log-analyze.sh [logfile]
# With no arg it picks the newest of:
#   /tmp/duetos-*.log  build/*/stress-*.log  build/*/*.log
#
# Exit status: 0 if the boot reached a completion sentinel AND no
# non-deliberate failure was found; 1 otherwise. So it doubles as a
# CI / scripted gate, not just a human report.
#
# Reusable rig (CLAUDE.md "Reusable Tooling"). It pairs with the
# launcher-specific rigs (tools/qemu/cpu-probe.sh,
# tools/qemu/smp-loadtest-compare.sh) — those PRODUCE a log on
# QEMU; this CONSUMES one from anywhere.

set -u

LOG="${1:-}"
if [ -z "$LOG" ]; then
    LOG=$(ls -t /tmp/duetos-*.log build/*/stress-*.log build/*/*.log 2>/dev/null | head -1)
fi
if [ -z "$LOG" ] || [ ! -f "$LOG" ]; then
    echo "usage: $0 [logfile]   (no DuetOS serial log found to auto-pick)" >&2
    exit 2
fi

# Serial captures interleave ANSI + the odd multi-CPU byte; -a keeps
# grep treating them as text.
g() { grep -aE "$@" "$LOG"; }
# grep -c always prints a count (0 if none) on stdout; it exits 1
# on zero matches, so do NOT chain `|| echo 0` (that would emit a
# second "0" and corrupt the integer).
gc() { grep -acE "$@" "$LOG" 2>/dev/null; true; }
hr() { printf '%s\n' "------------------------------------------------------------"; }

rc=0

hr
echo "DuetOS boot-log analysis: $LOG"
echo "  size=$(wc -c < "$LOG") bytes   lines=$(wc -l < "$LOG")"
# Hypervisor / accelerator / SMP banner.
accel=$(g 'qemu accel=' | tail -1 | sed 's/.*accel=//')
hyp=$(g -i 'hypervisor.*(detected|vendor|kind)|HypervisorName|under (KVM|TCG|VMware|VirtualBox)' | tail -1)
cpus=$(grep -aoE 'cpus=0x0*[0-9a-f]+' "$LOG" | tail -1)
# Authoritative SMP count: the single-write "[smp] online=N/M"
# sentinel (arch/x86_64/smp.cpp). The per-AP smp.ap_online prints
# interleave under concurrent multi-CPU serial and are NOT a
# reliable count.
smp=$(grep -aoE '\[smp\] online=[0-9]+/[0-9]+' "$LOG" | tail -1)
echo "  accel=${accel:-n/a}  acpi_${cpus:-cpus=?}  ${smp:-[smp] online=?/? (sentinel absent)}"
[ -n "$hyp" ] && echo "  $hyp"

hr
echo "COMPLETION"
done_boot=0
for s in 'boot : metrics bringup-complete' '\[smoke\] profile=.* complete' '^\[stress\] done' 'phase=smp complete'; do
    n=$(gc "$s")
    [ "$n" -gt 0 ] && { echo "  reached: $s  (x$n)"; done_boot=1; }
done
last_t=$(grep -aoE '\[t=[0-9]+\.[0-9]+ms\]' "$LOG" | tail -1)
echo "  last guest timestamp: ${last_t:-<none emitted>}"
if [ "$done_boot" -eq 0 ]; then
    echo "  !! no completion sentinel — boot did not finish (timeout / hang / early fault)"
    rc=1
fi

hr
echo "HEALTH (CLAUDE.md regression scan)"
# Hard failures — never deliberate.
# Includes `recursive-panic` (lowercase): the panic guard emits
# `[recursive-panic] subsys: msg — short-circuiting` when a panic
# fires while another panic is already in progress. The original
# uppercase PANIC banner may have been truncated by the recursive-
# panic halt, so catching only `PANIC` misses these. Observed
# 2026-05-22 in sweep-3 (stack canary corruption during boot-tail
# kheartbeat task creation) — the sweep summary's panic column
# said 0 because the grep was case-sensitive PANIC.
# Also catches the post-fix shape (2026-05-22) where the original
# panic banner finally streams completely now that the dump path
# no longer recurses into the guard page: `[panic-summary]`,
# `** CPU EXCEPTION **`, `#UD Invalid opcode` / `#GP General
# protection` / `#PF Page fault` trap messages, and the
# `[panic] CPU halted` post-dump marker. Without these patterns
# the analyzer silently passed a boot whose `#UD` on an idle
# task dumped a full crash record but never tripped a regression
# signal.
hard_pat='PANIC|TRIPLE|kernel oops|task-kill|#GP at|#PF at|#UD at|unhandled exception|triple fault|recursive-panic|canary corrupted|\[panic-summary\]|\*\* CPU EXCEPTION \*\*|#UD Invalid opcode|#GP General protection|#PF Page fault|\[panic\] CPU halted'
hard=$(g "$hard_pat" \
       | grep -avE 'selftest|self-test|deliberately|injected|expected|sanity line' | head -5)
hardn=$(g "$hard_pat" \
        | grep -acvE 'selftest|self-test|deliberately|injected|expected|sanity line' 2>/dev/null)
if [ "$hardn" -gt 0 ]; then
    echo "  !! $hardn hard fault line(s):"
    echo "$hard" | sed 's/^/     /'
    rc=1
else
    echo "  no panic / triple-fault / oops / task-kill / recursive-panic"
fi
# Error-level lines, minus the known-deliberate self-test scaffolding.
# elf-loader PT_LOAD line is the unwind-guard self-test's deliberate OOM
# injection (always preceded by the `loader.elf_oom` probe fire and
# followed by `[elf-test] unwind-guard PASS`) — production behaviour
# stays ERROR, but the regression scan shouldn't flag the test path.
# `arch/smp : AP never signalled online, giving up` is the documented
# graceful fallback path under QEMU TCG — an AP's 200ms WaitForApOnline
# window can flake under host load and the kernel correctly continues
# with the APs that did come up. The `[smp] online=N/M` sentinel fires
# unconditionally with the real `N`, so determinism is preserved.
errn_skip='selftest\.fault-react|error-level sanity line|net/wireless/(fourway|wdev|eapol)|security/module : start: init failed.*selftest|init : callback failed.*init\.cpp:163|elf-loader : PT_LOAD segment mapping failed mid-load|arch/smp : AP never signalled online, giving up'
errn=$(g '\[E\] ' | grep -acvE "$errn_skip" 2>/dev/null)
echo "  non-deliberate [E] lines: ${errn}"
if [ "$errn" -gt 0 ]; then
    g '\[E\] ' | grep -avE "$errn_skip" | head -4 | sed 's/^/     /'
fi

hr
echo "PHASE TIMINGS"
g 'phase=.* complete' | grep -aoE 'phase=[a-z]+ complete[^[:cntrl:]]*' | tail -20 | sed 's/^/  /'
[ -n "$(g 'phase=.* complete' | head -1)" ] || echo "  (none — TTY/profile boot or pre-phase exit)"

hr
echo "SELF-TESTS"
ok=$(gc 'self-test OK|selftest\] PASS|self-test passed')
skip=$(gc 'self-test SKIP|self-test: .*skip')
failn=$(g 'self-test FAIL|self-test FAILED|selftest.*FAIL' \
        | grep -acvE 'net/wireless/(fourway|wdev|eapol)|deliberately|injected|negative' 2>/dev/null)
echo "  OK=${ok}  SKIP=${skip}  non-deliberate FAIL=${failn}"
if [ "$failn" -gt 0 ]; then
    g 'self-test FAIL|self-test FAILED|selftest.*FAIL' \
      | grep -avE 'net/wireless/(fourway|wdev|eapol)|deliberately|injected|negative' | head -5 | sed 's/^/  !! /'
    rc=1
fi

hr
echo "TACTILITY (chrome tactility Pass A)"
# The chrome-tactility plan added four PASS sentinels: per-effect
# self-tests for blend + shadow + theme-tactility-matrix, plus the
# umbrella line that fires only when all three sub-tests passed.
# Any associated probe fire is a regression even if everything else
# in this section looks green.
tact_blend=$(gc '\[blend-selftest\] PASS')
tact_shadow=$(gc '\[shadow-selftest\] PASS')
tact_matrix=$(gc '\[theme-selftest\] tactility-matrix PASS')
tact_umbrella=$(gc '\[tactility-selftest\] PASS')
tact_probes=$(gc 'blend-range-oob|shadow-atlas-invalid|tactility-theme-mismatch')
echo "  blend=${tact_blend}  shadow=${tact_shadow}  theme-matrix=${tact_matrix}  umbrella=${tact_umbrella}"
echo "  probe fires=${tact_probes}"
if [ "$tact_probes" -gt 0 ]; then
    g 'blend-range-oob|shadow-atlas-invalid|tactility-theme-mismatch' | head -3 | sed 's/^/  !! /'
    rc=1
fi
# Umbrella requires all three sub-tests; if any sub PASS is zero but
# umbrella > 0, that's a wiring bug in the bringup aggregator.
if [ "$tact_umbrella" -gt 0 ] && { [ "$tact_blend" -eq 0 ] || [ "$tact_shadow" -eq 0 ] || [ "$tact_matrix" -eq 0 ]; }; then
    echo "  !! umbrella PASS without all sub-tests (bringup aggregator wiring bug)"
    rc=1
fi

hr
echo "LOCKDEP"
invn=$(gc 'inversion detected')
if [ "$invn" -gt 0 ]; then
    echo "  $invn inversion warning(s); distinct ordered (held,id) pairs:"
    grep -aA1 'inversion detected' "$LOG" \
      | grep -aoE 'newly-acquired="[^"]*"|class="[^"]*"' | paste - - | sort | uniq -c | sed 's/^/   /'
    echo "  (the selftest-A/B pair is the deliberate lockdep self-test; others: see"
    echo "   wiki Roadmap 'Lockdep held-set must be per-task' — global held-stack false positives)"
else
    echo "  no inversions recorded"
fi

hr
echo "STRESS / LOADTEST (if present)"
if g -q '\[stress\] (start|arming)|LOADTEST:'; then
    g '\[stress\] (arming|start|pre|done)|LOADTEST:|workers spawned:|elapsed ticks:|iterations:|ctx switches:|idle ticks:|window complete' \
      | grep -aoE '\[stress\][^[:cntrl:]]*|LOADTEST:[^[:cntrl:]]*|(workers spawned|elapsed ticks|iterations|ctx switches|idle ticks):[ ]*[0-9]+' \
      | tail -16 | sed 's/^/  /'
    g -q '^\[stress\] done' || { echo "  !! stress driver did not emit [stress] done (window unfinished — timeout / hang)"; rc=1; }
else
    echo "  (no stress/loadtest run in this log)"
fi

hr
echo "verdict: $([ "$rc" -eq 0 ] && echo 'OK — completed, no non-deliberate failure' || echo 'ATTENTION — see !! lines above')"
exit "$rc"
