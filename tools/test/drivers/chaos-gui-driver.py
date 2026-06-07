#!/usr/bin/env python3
"""chaos-gui-driver.py — aggressive headless input-storm fuzzer for the
DuetOS desktop / window-manager / compositor.

Drives a live HMP monitor socket (from desktop-qmp-session.sh) with a
torrent of RANDOM-but-VALID input for CHAOS_SECS (default 75s):

  - pointer storms across the full 1024x768 screen (stepped <=40px so
    QEMU does not drop the relative motion),
  - bursts of left/right/middle clicks and click-drags,
  - rapid double-clicks on every desktop icon cell (open all apps,
    churn windows),
  - open + immediately dismiss Start menu / context menus,
  - random key mashing + hotkey combos (ctrl-alt-t, ctrl-shift-c,
    alt-tab-ish, alt-f4),
  - window chrome interaction (drag titlebars, hit close/min/max
    corners, resize-edge drags).

Periodic screendumps land at /tmp/chaos-gui-NN.ppm for visual triage.

Invoked as: python3 chaos-gui-driver.py <MON_SOCK> <SERIAL_LOG>
Always exits 0 — this is a fuzzer; verdict comes from boot-log-analyze
on the serial log + screendump inspection, not this script's rc.
"""
import os
import random
import socket
import sys
import time

mon_p, slog = sys.argv[1], sys.argv[2]
CHAOS_SECS = int(os.environ.get("CHAOS_SECS", "75"))
SEED = int(os.environ.get("CHAOS_SEED", "0xC0FFEE"), 0)
rng = random.Random(SEED)

SCRW, SCRH = 1024, 768

s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
for _ in range(200):
    try:
        s.connect(mon_p)
        break
    except (FileNotFoundError, ConnectionRefusedError):
        time.sleep(0.25)
s.settimeout(0.05)
time.sleep(0.5)


def drain():
    # Keep the monitor's echo backlog from stalling command processing.
    try:
        while s.recv(65536):
            pass
    except Exception:
        pass


drain()

# QEMU's relative pointer needs us to track our own notion of where the
# cursor is; the guest clamps to screen, so we mirror that.
cur = [SCRW // 2, SCRH // 2]


def send(line):
    try:
        s.sendall((line + "\n").encode())
    except Exception:
        pass


def move_to(tx, ty):
    """Step the relative pointer to (tx,ty) in <=40px hops."""
    tx = max(0, min(SCRW - 1, tx))
    ty = max(0, min(SCRH - 1, ty))
    while cur[0] != tx or cur[1] != ty:
        dx = max(-40, min(40, tx - cur[0]))
        dy = max(-40, min(40, ty - cur[1]))
        send("mouse_move %d %d" % (dx, dy))
        cur[0] += dx
        cur[1] += dy
        time.sleep(0.004)


def click(btn=1):
    send("mouse_button %d" % btn)
    time.sleep(0.012)
    send("mouse_button 0")
    time.sleep(0.012)


def dbl(btn=1):
    click(btn)
    time.sleep(0.04)
    click(btn)


def drag(x0, y0, x1, y1, btn=1):
    move_to(x0, y0)
    send("mouse_button %d" % btn)
    time.sleep(0.01)
    # walk to the destination with the button held
    steps = max(abs(x1 - x0), abs(y1 - y0)) // 40 + 1
    for i in range(1, steps + 1):
        ix = x0 + (x1 - x0) * i // steps
        iy = y0 + (y1 - y0) * i // steps
        move_to(ix, iy)
    send("mouse_button 0")
    time.sleep(0.012)


# Desktop icon cell centers. Observed layout from a live screendump:
# two columns at the top-left (Computer/Trash, Browser/Help, ...),
# cellW=84 stride=96, top y=24, row pitch 92, cell center +42.
# 9 icons -> cols {0,1}, rows {0..4}. Hit them all.
ICONS = []
for idx in range(9):
    col, row = idx % 2, idx // 2
    ICONS.append((20 + col * 96 + 42, 24 + row * 92 + 42))

KEYS = list("abcdefghijklmnopqrstuvwxyz0123456789") + [
    "ret", "spc", "esc", "tab", "backspace", "up", "down", "left", "right",
    "delete", "home", "end", "pgup", "pgdn",
]
COMBOS = [
    "ctrl-alt-t", "ctrl-shift-c", "alt-tab", "alt-f4", "ctrl-c", "ctrl-v",
    "ctrl-a", "ctrl-z", "alt-spc", "ctrl-alt-delete", "super_l", "meta_l",
    "ctrl-w", "alt-esc",
]

# Common chrome hit zones relative to a window at (wx,wy,ww). Titlebar
# buttons usually sit at the top-right; we just smash the top band and
# the right/bottom edges of plausible window rects.
SHOT_DIR = "/tmp"
shot_n = 0


def shot():
    global shot_n
    drain()  # clear echo backlog so the screendump command is processed
    send("screendump %s/chaos-gui-%02d.ppm" % (SHOT_DIR, shot_n))
    shot_n += 1
    time.sleep(0.6)  # give QEMU time to render + flush the file
    drain()


def open_all_icons():
    for (ix, iy) in ICONS:
        move_to(ix, iy)
        dbl(1)
        time.sleep(0.03)


def start_menu_thrash():
    # Start button is bottom-left corner of the taskbar.
    move_to(24, SCRH - 14)
    click(1)
    time.sleep(0.05)
    # mash a few keys into whatever opened, then dismiss
    for _ in range(3):
        send("sendkey %s" % rng.choice(KEYS))
        time.sleep(0.02)
    send("sendkey esc")
    time.sleep(0.03)


def context_menu_thrash():
    x, y = rng.randint(120, SCRW - 60), rng.randint(60, SCRH - 80)
    move_to(x, y)
    click(2)  # right-click -> context menu
    time.sleep(0.04)
    # arrow + enter or dismiss
    if rng.random() < 0.5:
        send("sendkey down")
        time.sleep(0.02)
        send("sendkey ret")
    else:
        send("sendkey esc")
    time.sleep(0.03)


def chrome_thrash():
    # Pretend windows live in the upper area; pound titlebar + buttons.
    wx = rng.randint(150, 500)
    wy = rng.randint(40, 200)
    ww = rng.randint(220, 420)
    # titlebar drag (move window)
    drag(wx + ww // 2, wy + 8, wx + ww // 2 + rng.randint(-150, 150),
         wy + 8 + rng.randint(-30, 120), 1)
    # smash the three top-right buttons (min/max/close)
    for bx in (wx + ww - 14, wx + ww - 34, wx + ww - 54):
        move_to(bx, wy + 8)
        click(1)
        time.sleep(0.02)
    # bottom-right resize-edge drag
    drag(wx + ww, wy + 180, wx + ww + rng.randint(-100, 160),
         wy + 180 + rng.randint(-80, 140), 1)


def pointer_storm(n=14):
    for _ in range(n):
        move_to(rng.randint(0, SCRW - 1), rng.randint(0, SCRH - 1))
        if rng.random() < 0.4:
            click(rng.choice([1, 2, 4]))


def key_mash(n=12):
    for _ in range(n):
        if rng.random() < 0.3:
            send("sendkey %s" % rng.choice(COMBOS))
        else:
            send("sendkey %s" % rng.choice(KEYS))
        time.sleep(0.01)


ACTIONS = [
    (open_all_icons, 1),
    (start_menu_thrash, 3),
    (context_menu_thrash, 3),
    (chrome_thrash, 3),
    (pointer_storm, 4),
    (key_mash, 4),
]
WEIGHTED = [a for (a, w) in ACTIONS for _ in range(w)]

print("=== chaos-gui-driver: %ds storm, seed=0x%X ===" % (CHAOS_SECS, SEED), flush=True)
mark_len = 0
try:
    mark_len = len(open(slog, "rb").read())
except Exception:
    pass

t_end = time.time() + CHAOS_SECS
t_next_shot = time.time() + 8
iters = 0
# Prime: open every app once up front so there are windows to churn.
open_all_icons()
shot()
while time.time() < t_end:
    rng.choice(WEIGHTED)()
    iters += 1
    drain()  # flush monitor echo each iteration so commands keep flowing
    if time.time() >= t_next_shot:
        shot()
        t_next_shot = time.time() + 12
shot()

print("chaos storm done: %d action-iterations, %d screendumps" % (iters, shot_n), flush=True)
# Settle so any deferred compositor/WM work flushes to serial.
time.sleep(3)
print("RESULT: chaos run complete (verdict via boot-log-analyze + screendumps)", flush=True)
sys.exit(0)
