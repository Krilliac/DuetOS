#!/usr/bin/env python3
"""kbd-repeat-driver.py — driver for desktop-qmp-session.sh.

Injects, via the HMP monitor, both machine-style auto-repeat bursts
(short release->re-press gaps, like VirtualBox host repeat) and
deliberate human double-letters (wider gaps), then asserts the
KbdReaderTask debounce suppressed the former and preserved the
latter. Reads the suppression DEBUG line the guard emits:
  input/kbd : auto-repeat run suppressed; code   val=0x<hex>

Invoked as: python3 kbd-repeat-driver.py <MON_SOCK> <SERIAL_LOG>
Exit 0 = PASS, non-zero = FAIL.
"""
import socket, sys, time

mon_p, slog = sys.argv[1], sys.argv[2]


def logtext():
    try:
        return open(slog, "rb").read().decode("utf-8", "replace")
    except FileNotFoundError:
        return ""


s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
for _ in range(120):
    try:
        s.connect(mon_p); break
    except (FileNotFoundError, ConnectionRefusedError):
        time.sleep(0.25)
time.sleep(0.5)
s.recv(65536)


def key(k):
    s.sendall(("sendkey %s\n" % k).encode())


def burst(k, n, gap):
    for _ in range(n):
        key(k); time.sleep(gap)


mark = len(logtext())

# 1. Fast machine-repeat burst (sub-100ms gaps) — must be suppressed.
burst("a", 8, 0.02)
time.sleep(0.7)
# 2. VBox-like ~60ms-gap repeat — must be suppressed.
burst("c", 6, 0.06)
time.sleep(0.7)
# 3 & 4. Deliberate double-letters — must survive. NOTE: QEMU's HMP
# `sendkey` holds each key down ~100ms before releasing, so the
# release->re-press gap the guard measures is (inter-command sleep -
# ~100ms hold). To model a human double-letter (true release->re-press
# >100ms) we sleep well past the hold: 300ms and 400ms here give
# ~200ms and ~300ms real gaps, both comfortably above the 100ms gate.
key("d"); time.sleep(0.30); key("d")
time.sleep(0.7)
key("e"); time.sleep(0.40); key("e")
time.sleep(2.0)

txt = logtext()[mark:]


def suppressed(code_hex):
    # count "auto-repeat run suppressed; code   val=0x<code>"
    needle = "auto-repeat run suppressed"
    return sum(1 for ln in txt.splitlines() if needle in ln and ("val=0x%s " % code_hex) in ln)


sup_a, sup_c = suppressed("61"), suppressed("63")
sup_d, sup_e = suppressed("64"), suppressed("65")
press_a = txt.count("kbd-ev press code") and txt.count("val=0x61")

print("=== kbd-repeat-driver ===")
print("a: fast burst   -> suppressed runs=%d  (want >=1)" % sup_a)
print("c: 60ms repeat  -> suppressed runs=%d  (want >=1)" % sup_c)
print("d: 200ms double -> suppressed runs=%d  (want 0)" % sup_d)
print("e: 150ms double -> suppressed runs=%d  (want 0)" % sup_e)

ok = sup_a >= 1 and sup_c >= 1 and sup_d == 0 and sup_e == 0
print("RESULT: %s" % ("PASS — machine repeat suppressed, double-letters preserved"
                      if ok else "FAIL — see counts above"))
# Echo a few guard/kbd lines for the log.
for ln in [l for l in txt.splitlines() if "auto-repeat run" in l][:8]:
    print("  " + ln.strip()[-80:])
sys.exit(0 if ok else 1)
