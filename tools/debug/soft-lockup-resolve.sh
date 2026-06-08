#!/usr/bin/env bash
#
# Resolve the RIP / caller addresses printed by the soft-lockup detector
# into function+offset, from a boot/smoke log + the matching kernel ELF.
#
# WHAT
#   When diag::SoftLockupTick fires it now prints a self-pinning line:
#     [soft-lockup] task stuck cpu=0x0 tid=0x8 name="kboot"
#       ticks_in_run=0x65 rip=0xADDR rip-ring=[a,b,...] caller-ring=[c,d,...]
#   `rip-ring`   = the interrupted kernel RIPs over the last few ticks
#                  (newest first) — pins the spin site.
#   `caller-ring`= one frame up from each (return address into the loop
#                  that's calling the leaf) — names WHO is spinning when
#                  the RIP is a leaf helper (e.g. arch::HpetReadCounter).
#   This rig batch-resolves every address in those rings so a wedge is a
#   one-command diagnosis instead of a manual addr2line-per-address slog.
#
# WHY
#   The intermittent "serial wedge" (kboot stuck ~1s, soft-lockup fires
#   with ticks_in_run=101, no further output, host watchdog kills the VM)
#   was historically re-derived by hand every session. The ring + this
#   resolver make the next occurrence self-explaining.
#
# USAGE
#   tools/debug/soft-lockup-resolve.sh [logfile] [kernel.elf]
#   Defaults:
#     logfile    = newest build/*/smoke-*.log or sess-*.serial.log
#     kernel.elf = build/x86_64-debug/kernel/duetos-kernel.elf
#   Env override: DUETOS_KERNEL_ELF=/path/to/duetos-kernel.elf
#
# Reusable rig (CLAUDE.md "Reusable Tooling — Save It, Don't Re-Derive It").
# Pairs with boot-log-analyze.sh / boot-progress-localizer.sh.

set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

LOG="${1:-}"
if [[ -z "$LOG" ]]; then
    LOG="$(ls -t "$ROOT"/build/*/smoke-*.log "$ROOT"/build/*/sess-*.serial.log \
        "$ROOT"/build/*/wedge*.log /tmp/duetos-*.log 2>/dev/null | head -1)"
fi
if [[ -z "$LOG" || ! -f "$LOG" ]]; then
    echo "soft-lockup-resolve: no log file found (pass one explicitly)" >&2
    exit 2
fi

ELF="${2:-${DUETOS_KERNEL_ELF:-$ROOT/build/x86_64-debug/kernel/duetos-kernel.elf}}"
if [[ ! -f "$ELF" ]]; then
    echo "soft-lockup-resolve: kernel ELF not found: $ELF" >&2
    exit 2
fi

echo "log: $LOG"
echo "elf: $ELF"
echo

# Pull soft-lockup lines (strip ANSI), prefer kboot but show all.
mapfile -t LINES < <(sed -E 's/\x1b\[[0-9;]*m//g' "$LOG" | grep -aE 'soft-lockup\] task stuck')
if [[ "${#LINES[@]}" -eq 0 ]]; then
    echo "no [soft-lockup] task-stuck lines in this log — boot was clean (no wedge)."
    exit 0
fi

resolve() {
    # $1 = hex address. Print "addr  func  file:line".
    local a="$1" fn fl
    fn="$(addr2line -f -e "$ELF" "$a" 2>/dev/null | head -1)"
    fl="$(addr2line -e "$ELF" "$a" 2>/dev/null | head -1)"
    printf '    %s  %-44s  %s\n' "$a" "$fn" "$fl"
}

for line in "${LINES[@]}"; do
    echo "=================================================================="
    echo "$line"
    name="$(sed -nE 's/.*name="([^"]*)".*/\1/p' <<<"$line")"
    echo "  task: ${name:-<unknown>}"
    for ring in rip-ring caller-ring caller-bt; do
        addrs="$(sed -nE "s/.*${ring}=\[([^]]*)\].*/\1/p" <<<"$line" | tr ',' ' ')"
        [[ -z "$addrs" ]] && continue
        echo "  ${ring}:"
        for a in $addrs; do
            [[ "$a" == 0x0000000000000000 || "$a" == 0x0 ]] && { echo "    $a  (empty slot)"; continue; }
            resolve "$a"
        done
    done
done
