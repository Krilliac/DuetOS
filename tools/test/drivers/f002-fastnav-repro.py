#!/usr/bin/env python3
"""f002-fastnav-repro.py - reproduce F-002 keyboard input-drop at a fast
key rate. Opens the Start menu and navigates to a target app at
F002_KEY_DELAY seconds per key (default 0.06, the rate that USED to drop
keys), screendumping each state. Compare the resulting app to the
expected one: if keys were dropped the highlight lands SHORT and the
wrong app opens.

ENV:
  F002_KEY_DELAY  seconds between key presses (default 0.06)
  F002_TARGET     app id from LAUNCH_NAV (default firewall, a SYSTEM app)
  EXPLORE_SHOT_DIR  dir for screendumps (default /tmp)

Invoked: f002-fastnav-repro.py <MON_SOCK> <SERIAL_LOG>.
"""
import os, socket, sys, time

mon_p, slog = sys.argv[1], sys.argv[2]
SHOT_DIR = os.environ.get("EXPLORE_SHOT_DIR", "/tmp")
DELAY = float(os.environ.get("F002_KEY_DELAY", "0.06"))
TARGET = os.environ.get("F002_TARGET", "firewall")

# root order (activatable): 0 APPS 1 UTILITIES 2 SYSTEM 3 SCREENSHOT 4 POWER
# but see F-003: a planted /APPS shortcut can make USER APPS activatable,
# shifting SYSTEM to root index 3. The repro target chosen below uses the
# nav table; correctness is judged by the OPENED app, not the index.
LAUNCH_NAV = {
    "calculator": (0, 0), "files": (0, 2), "imageview": (0, 6),
    "settings": (2, 0), "netstatus": (2, 5), "firewall": (2, 7), "dbg": (2, 8),
}

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

def key(name, n=1, delay=DELAY):
    for _ in range(n):
        hmp(f"sendkey {name}"); time.sleep(delay)

def shot(name):
    path = os.path.join(SHOT_DIR, f"f002-{name}.ppm")
    drain(); hmp(f"screendump {path}"); time.sleep(0.5); print(f"SHOT {path}", flush=True)

drain()
os.makedirs(SHOT_DIR, exist_ok=True)
root_steps, sub_steps = LAUNCH_NAV[TARGET]
print(f"F-002 repro: target={TARGET} root_steps={root_steps} sub_steps={sub_steps} "
      f"key_delay={DELAY}s", flush=True)
shot("desktop")
key("ctrl-esc"); time.sleep(0.4); shot("menu")
if root_steps:
    key("down", root_steps)
key("right"); time.sleep(0.5); shot("submenu")
if sub_steps:
    key("down", sub_steps)
shot("highlight")  # where the highlight landed BEFORE Enter
key("ret"); time.sleep(1.0)
shot("open")
print("f002-fastnav-repro done for", TARGET, flush=True)
sys.exit(0)
