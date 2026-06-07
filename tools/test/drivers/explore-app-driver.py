#!/usr/bin/env python3
"""explore-app-driver.py - structured single-app exploration for the
usability campaign. Opens EXPLORE_APP, exercises its primary workflow,
screendumps every meaningful state into EXPLORE_SHOT_DIR for vision
grading. Never asserts PASS. Invoked: explore-app-driver.py <MON_SOCK> <SERIAL_LOG>."""
import os, socket, sys, time

mon_p, slog = sys.argv[1], sys.argv[2]
APP = os.environ.get("EXPLORE_APP", "files")
SHOT_DIR = os.environ.get("EXPLORE_SHOT_DIR", "/tmp")
ICON_X = int(os.environ.get("EXPLORE_ICON_X", "62"))
ICON_Y = int(os.environ.get("EXPLORE_ICON_Y", "66"))

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

# QEMU's pointer is relative; the guest clamps to screen, so we mirror that
# and track our own notion of where the cursor is (same model the proven
# chaos-gui-driver uses). A one-shot pin-to-origin drops/clamps unreliably.
cur = [SCRW // 2, SCRH // 2]

def move_to(tx, ty):
    tx = max(0, min(SCRW - 1, tx))
    ty = max(0, min(SCRH - 1, ty))
    while cur[0] != tx or cur[1] != ty:
        dx = max(-40, min(40, tx - cur[0]))
        dy = max(-40, min(40, ty - cur[1]))
        hmp(f"mouse_move {dx} {dy}")
        cur[0] += dx; cur[1] += dy
        time.sleep(0.006)

def click(x, y, btn=1):
    move_to(x, y); hmp(f"mouse_button {btn}"); time.sleep(0.05); hmp("mouse_button 0")

def double_click(x, y):
    click(x, y); time.sleep(0.08); click(x, y)

def shot(name):
    path = os.path.join(SHOT_DIR, f"{APP}-{name}.ppm")
    drain(); hmp(f"screendump {path}"); time.sleep(0.5); print(f"SHOT {path}", flush=True)

drain()
os.makedirs(SHOT_DIR, exist_ok=True)
shot("desktop")
double_click(ICON_X, ICON_Y)
time.sleep(1.5); shot("open")
for k in ["t", "e", "s", "t"]:
    hmp(f"sendkey {k}"); time.sleep(0.05)
shot("typed")
hmp("sendkey ret"); time.sleep(0.5); shot("enter")
hmp("sendkey alt-spc"); time.sleep(0.3); shot("sysmenu")
hmp("sendkey esc"); time.sleep(0.2)
hmp("sendkey alt-f4"); time.sleep(0.5); shot("closed")
print("explore-app-driver done for", APP, flush=True)
sys.exit(0)
