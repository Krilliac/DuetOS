#!/usr/bin/env bash
#
# triage-truncated-boot.sh — classify a boot that ended without a
# completion sentinel, and tell apart the three failure shapes that
# otherwise look identical ("the log just stops"):
#
#   1. GUEST FAULT      — the DuetOS kernel panicked (a real bug). The
#                         `[panic-precis]` line (emitted first by the
#                         panic path, before any device-heavy step)
#                         carries the root cause even when the full
#                         dump never finishes streaming.
#   2. HOST-EMULATOR    — QEMU itself aborted (e.g. the TCG+SMP
#      ABORT             `qemu_mutex_lock_iothread_impl` BQL assertion).
#                         This kills the VM mid-dump, so a guest fault
#                         underneath it is HIDDEN. The QEMU `-d int`
#                         trace (qemu.log) still records the last guest
#                         exception — we recover vector + RIP from it
#                         so the real bug isn't lost to the host crash.
#   3. HANG / TIMEOUT   — no fault, no abort: the guest wedged (deadlock,
#                         spin, lost wakeup) and the harness timed out.
#
# Why this exists: a host-emulator abort and a guest panic and a hang
# all present as "serial log stops with no sentinel". Conflating them
# wastes a debugging session chasing a kernel bug that was really a
# QEMU bug, or — worse — dismissing a real kernel fault as "just the
# flaky emulator". This script makes the distinction mechanical and
# greppable, and ALWAYS surfaces the guest fault vector/RIP when one
# exists, so the host abort can never fully mask it.
#
# Usage:
#   tools/qemu/triage-truncated-boot.sh <serial.log> [qemu-int.log]
#
# If the qemu.log path is omitted it is guessed from the serial log's
# directory (build/<preset>/qemu.log, ./qemu.log) — the `-d int` trace
# the run.sh / ctest harnesses write by default.
#
# Env:
#   SENTINEL   — completion-sentinel regex (default: smoke / login / idle markers)
#
# Exit codes (so a CI gate can branch on the shape):
#   0  boot completed (sentinel found) — nothing to triage
#   2  HANG / TIMEOUT (truncated, no fault, no abort)
#   3  GUEST FAULT (kernel panic — actionable kernel bug)
#   4  HOST-EMULATOR ABORT (QEMU bug; guest fault, if any, recovered from the trace)
#
# Quick analysis one-liners:
#   tools/qemu/triage-truncated-boot.sh build/x86_64-debug/ctest-smoke-serial.log
#   for L in /tmp/duetos-*.log; do tools/qemu/triage-truncated-boot.sh "$L"; done

set -uo pipefail

SERIAL="${1:-}"
if [[ -z "$SERIAL" || ! -f "$SERIAL" ]]; then
    echo "usage: $0 <serial.log> [qemu-int.log]" >&2
    exit 64
fi

QLOG="${2:-}"
if [[ -z "$QLOG" ]]; then
    sdir="$(cd "$(dirname "$SERIAL")" && pwd)"
    for cand in "$sdir/qemu.log" "./qemu.log" "$sdir/../qemu.log"; do
        [[ -f "$cand" ]] && { QLOG="$cand"; break; }
    done
fi

# A boot that reached this is not truncated. It must be a TERMINAL
# marker — the very last thing a full boot emits — never a mid-boot
# one (so a truncated run can't false-match it). `[pe-compat-smoke]
# battery complete` is the ctest-boot-smoke harness's terminal
# sentinel (its last "expected" signature). Do NOT add mid-boot
# markers here: "[nat-sysinfo] report complete", "idle task online",
# "login-gui" etc. all fire long before the boot finishes and would
# make a truncated run read as COMPLETED.
SENTINEL="${SENTINEL:-\[pe-compat-smoke\] battery complete|smoke.*profile=.*complete|\[smoke\] .*complete}"

if grep -qE "$SENTINEL" "$SERIAL" 2>/dev/null; then
    echo "verdict: COMPLETED — boot reached a completion sentinel; nothing to triage."
    exit 0
fi

echo "=== triage: truncated boot ($SERIAL) ==="

vec_name() {
    case "$1" in
        00) echo "#DE divide-by-zero" ;; 06) echo "#UD invalid-opcode" ;;
        08) echo "#DF double-fault" ;; 0d) echo "#GP general-protection" ;;
        0e) echo "#PF page-fault" ;; 12) echo "#MC machine-check" ;;
        02) echo "NMI" ;; 03) echo "#BP breakpoint" ;;
        *)  echo "vector-0x$1" ;;
    esac
}

# Classify a RIP as wild (the boot-tail wild-frame shapes this tree chases).
# Echoes a descriptive " [WILD: ...]" suffix when wild, nothing when normal.
rip_class() {
    local rip="$1"
    [[ -z "$rip" ]] && { echo ""; return; }
    local r
    r="$(tr 'A-F' 'a-f' <<<"$rip")"
    case "$r" in
        ffffffffffffffff)   echo " [WILD: all-ones / -1]" ; return ;;
        0|0000000000000000) echo " [WILD: null]" ; return ;;
    esac
    # Non-canonical: bits 63:47 must be all-0 or all-1. Cheap prefix test on
    # the top 5 hex nibbles (canonical hi must read 00000 or fffff).
    local hi5="${r:0:5}"
    if [[ "$hi5" != "00000" && "$hi5" != "fffff" && ${#r} -ge 16 ]]; then
        # Are all 8 bytes printable ASCII? -> jumped into string data, the
        # classic "code pointer overwritten by a text buffer" shape.
        local i b d ascii=1
        for ((i=0; i<16; i+=2)); do
            b="${r:i:2}"; d=$((16#$b))
            if (( d<32 || d>=127 )); then ascii=0; break; fi
        done
        if (( ascii )); then
            echo " [WILD: non-canonical, ASCII-string bytes -> code ptr clobbered by text]"
        else
            echo " [WILD: non-canonical]"
        fi
        return
    fi
    echo ""
}

# --- 1. The kernel's own front-loaded cause line, if it escaped. -----------
PRECIS="$(grep -aE "\[panic-precis\]" "$SERIAL" 2>/dev/null | tail -1)"
if [[ -n "$PRECIS" ]]; then
    echo "guest panic-precis : ${PRECIS#*\[panic-precis\] }"
fi

# --- 2. Host-emulator abort signature in the serial stream. ----------------
HOST_ABORT=""
if grep -qaE "qemu_mutex_lock_iothread|Bail out!|assertion failed|qemu-system.*: .*(Aborted|core dumped)" "$SERIAL" 2>/dev/null; then
    HOST_ABORT="$(grep -aE "qemu_mutex_lock_iothread|Bail out!|assertion failed" "$SERIAL" 2>/dev/null | tail -1)"
fi

# --- 3. Guest exceptions from the QEMU -d int trace. -----------------------
# Lines look like:
#   v=0e e=0010 i=0 cpl=0 IP=0008:ffffffffffffffff pc=... CR2=...
# We keep the LAST exception (the terminal state) AND scan the last few
# for the FIRST wild RIP — in a wild-jump cascade the terminal fault is
# usually #PF at -1, but the EARLIER fault (e.g. #GP at a clobbered
# pointer that still holds its garbage value) is the real root lead.
GVEC="" ; GRIP="" ; GCPL="" ; GERR="" ; GCR2=""
ROOTVEC="" ; ROOTRIP=""
if [[ -n "$QLOG" && -f "$QLOG" ]]; then
    LASTX="$(grep -aE "^[[:space:]]*[0-9]+: v=[0-9a-f]{2} " "$QLOG" 2>/dev/null | tail -1)"
    if [[ -n "$LASTX" ]]; then
        GVEC="$(sed -nE 's/.* v=([0-9a-f]{2}) .*/\1/p' <<<"$LASTX")"
        GERR="$(sed -nE 's/.* e=([0-9a-f]+) .*/\1/p' <<<"$LASTX")"
        GCPL="$(sed -nE 's/.* cpl=([0-9]+) .*/\1/p' <<<"$LASTX")"
        GRIP="$(sed -nE 's/.* IP=[0-9a-f]+:([0-9a-f]+).*/\1/p' <<<"$LASTX")"
        GCR2="$(sed -nE 's/.* CR2=([0-9a-f]+).*/\1/p' <<<"$LASTX")"
    fi
    # Earliest wild RIP among the last 8 exceptions that ISN'T -1/null —
    # that is the clobbered-pointer value, the actionable root lead.
    while IFS= read -r xline; do
        local_rip="$(sed -nE 's/.* IP=[0-9a-f]+:([0-9a-f]+).*/\1/p' <<<"$xline")"
        [[ -z "$local_rip" ]] && continue
        case "$(tr 'A-F' 'a-f' <<<"$local_rip")" in
            ffffffffffffffff|0|0000000000000000) continue ;;
        esac
        # First non-trivial wild RIP wins (we read oldest->newest).
        if [[ -n "$(rip_class "$local_rip")" ]]; then
            ROOTRIP="$local_rip"
            ROOTVEC="$(sed -nE 's/.* v=([0-9a-f]{2}) .*/\1/p' <<<"$xline")"
            break
        fi
    done < <(grep -aE "^[[:space:]]*[0-9]+: v=[0-9a-f]{2} " "$QLOG" 2>/dev/null | tail -8)
fi

GUEST_FAULT=0
if [[ -n "$GVEC" ]]; then
    GUEST_FAULT=1
    ring="ring${GCPL:-?}"
    [[ "$GCPL" == "0" ]] && ring="kernel(ring0)"
    [[ "$GCPL" == "3" ]] && ring="user(ring3)"
    echo "guest last fault   : $(vec_name "$GVEC") (v=0x$GVEC) $ring err=0x${GERR:-?} rip=0x${GRIP:-?}$(rip_class "$GRIP")"
    [[ -n "$GCR2" ]] && echo "guest fault cr2    : 0x$GCR2$(rip_class "$GCR2")"
    # The terminal fault in a cascade is usually #PF at -1; the earlier
    # wild RIP (a clobbered pointer that still holds its garbage value)
    # is the actionable root lead. Show it when it differs from the last.
    if [[ -n "$ROOTRIP" && "$ROOTRIP" != "$GRIP" ]]; then
        echo "guest ROOT lead    : $(vec_name "$ROOTVEC") (v=0x$ROOTVEC) rip=0x$ROOTRIP$(rip_class "$ROOTRIP")"
        echo "                     ^ earliest wild RIP — start the root-cause hunt here."
    fi
fi

echo "----------------------------------------------------------------------"

# --- Verdict -------------------------------------------------------------
if [[ -n "$HOST_ABORT" ]]; then
    echo "verdict: HOST-EMULATOR ABORT — the emulator killed the VM mid-run."
    echo "  signature: $HOST_ABORT"
    if [[ "$GUEST_FAULT" == "1" ]]; then
        echo "  NOTE: a GUEST fault is present underneath the host abort (see 'guest last"
        echo "        fault' above). The host crash HID the kernel dump — the guest bug is"
        echo "        the actionable one; the QEMU abort is a separate host-side bug that"
        echo "        only prevents you from seeing the full dump. Reproduce on KVM"
        echo "        (accel=kvm) or real hardware to get the untruncated panic."
    else
        echo "  No guest fault recorded before the abort — likely a pure host/emulator bug."
    fi
    exit 4
fi

if [[ "$GUEST_FAULT" == "1" || -n "$PRECIS" ]]; then
    echo "verdict: GUEST FAULT — the DuetOS kernel panicked (actionable kernel bug)."
    echo "  Use the panic-precis / last-fault RIP above as the lead; symbolise with"
    echo "  addr2line against build/<preset>/kernel/duetos-kernel.elf."
    exit 3
fi

echo "verdict: HANG / TIMEOUT — no fault and no abort; the guest wedged (deadlock,"
echo "  spin, or lost wakeup) and the harness timed out. Last serial line:"
tail -1 "$SERIAL" | sed 's/^/    /'
exit 2
