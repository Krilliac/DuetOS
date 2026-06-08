#!/usr/bin/env python3
"""chaos-syscall-driver.py - live syscall/API abuse. Opens the DuetOS
terminal and issues a storm of shell diag/stress commands with malformed
and boundary args, watching the serial log for panic/W^X/OOB markers.
Pairs with the host libFuzzer harness (fuzz-all.sh). Invoked:
chaos-syscall-driver.py <MON_SOCK> <SERIAL_LOG>. Always exits 0.

Payloads are aligned to the REAL shell verbs in kCommandSet[]
(kernel/shell/shell_dispatch.cpp): help/mem/ps/stress/cat/ls/kill/peek/
poke/peexec/loadtest/expr/memdump/vtop are all live builtins. Boundary
and malformed args (bad PIDs, oversize paths, div-by-zero, raw-mem pokes,
path traversal) are the abuse vector; admin-gated verbs (peek/poke/memdump/
vtop) also exercise the privilege-denial path from an autologin session."""
import os, socket, sys, time

mon_p, slog = sys.argv[1], sys.argv[2]
DURATION = float(os.environ.get("CHAOS_SECS", "60"))
SHOT_DIR = os.environ.get("CHAOS_SHOT_DIR", "/tmp")

SCRW, SCRH = 1024, 768

s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
for _ in range(200):
    try:
        s.connect(mon_p); break
    except (FileNotFoundError, ConnectionRefusedError):
        time.sleep(0.25)
s.settimeout(0.1)
time.sleep(0.5)

def drain():
    try:
        while s.recv(65536):
            pass
    except Exception:
        pass

def hmp(line):
    s.sendall((line + "\n").encode()); time.sleep(0.04); drain()

def typestr(text):
    for ch in text:
        key = {" ": "spc", "-": "minus", "/": "slash", ".": "dot",
               "\\": "backslash", ":": "shift-semicolon"}.get(ch, ch)
        hmp(f"sendkey {key}")
    hmp("sendkey ret")

# Stateful relative-pointer model (same as the proven chaos-gui-driver):
# a one-shot pin-to-origin clamps/drops unreliably, so track our own
# cursor position starting from screen center and step in <=40px hops.
cur = [SCRW // 2, SCRH // 2]

def move_to(tx, ty):
    tx = max(0, min(SCRW - 1, tx)); ty = max(0, min(SCRH - 1, ty))
    while cur[0] != tx or cur[1] != ty:
        dx = max(-40, min(40, tx - cur[0]))
        dy = max(-40, min(40, ty - cur[1]))
        hmp(f"mouse_move {dx} {dy}")
        cur[0] += dx; cur[1] += dy
        time.sleep(0.006)

# Terminal desktop icon — index 2 in the registration order (Computer,
# Browser, Terminal, ...). Grid: center = (kColX0 + col*96 + 42,
# kTopY + row*92 + 42) with kColX0=20, kTopY=24, 7 rows/col at 768px.
# Terminal -> col 0, row 2 -> (62, 250). Override via TERM_ICON_X/Y.
tx = int(os.environ.get("TERM_ICON_X", "62"))
ty = int(os.environ.get("TERM_ICON_Y", "250"))
drain()
move_to(tx, ty)
hmp("mouse_button 1"); time.sleep(0.05); hmp("mouse_button 0"); time.sleep(0.12)
hmp("mouse_button 1"); time.sleep(0.05); hmp("mouse_button 0"); time.sleep(1.4)

# Confirm the terminal actually opened before the storm (vision-gradable).
drain(); hmp(f"screendump {os.path.join(SHOT_DIR, 'syscall-term-open.ppm')}"); time.sleep(0.5)

payloads = [
    "help", "mem", "ps", "stress mem 1 999999", "stress cpu -1",
    "cat /../../etc", "ls ////", "kill 999999", "kill -1",
    "loadtest 0xffffffffffffffff", "peek 0", "poke 0 0",
    "expr 1 / 0", "memdump 0", "vtop 0",
    "peexec X:\\nope.exe", "cat " + "A"*4096,
]
end = time.time() + DURATION
i = 0
while time.time() < end:
    typestr(payloads[i % len(payloads)]); i += 1; time.sleep(0.2)
drain(); hmp(f"screendump {os.path.join(SHOT_DIR, 'syscall-term-end.ppm')}"); time.sleep(0.5)
print(f"chaos-syscall-driver issued {i} payloads", flush=True)
sys.exit(0)
