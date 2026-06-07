#!/usr/bin/env python3
"""explore-app-driver.py - structured single-app exploration for the
usability campaign. Opens EXPLORE_APP, exercises its primary workflow,
screendumps every meaningful state into EXPLORE_SHOT_DIR for vision
grading. Never asserts PASS. Invoked: explore-app-driver.py <MON_SOCK> <SERIAL_LOG>.

Launch mechanisms (EXPLORE_LAUNCH):
  icon       (default) double-click the app's desktop icon at
             (EXPLORE_ICON_X, EXPLORE_ICON_Y). Only ~9 apps have icons.
  startmenu  keyboard-navigate the built-in Start menu. Works for EVERY
             registered app — the menu is the launch surface of record.
             The kernel start menu (kernel/core/boot_tasks.cpp) is a
             nested submenu structure opened with Ctrl+Esc; arrow keys
             move the highlight (wrapping, skipping separators/disabled
             rows), Right opens a submenu, Enter activates. Pure sendkey,
             no pixel-clicking menu rows -> far more robust than pointer
             targeting of menu geometry. See LAUNCH_NAV for the per-app
             root/submenu/row coordinates."""
import os, socket, sys, time

mon_p, slog = sys.argv[1], sys.argv[2]
APP = os.environ.get("EXPLORE_APP", "files")
SHOT_DIR = os.environ.get("EXPLORE_SHOT_DIR", "/tmp")
LAUNCH = os.environ.get("EXPLORE_LAUNCH", "icon")
ICON_X = int(os.environ.get("EXPLORE_ICON_X", "62"))
ICON_Y = int(os.environ.get("EXPLORE_ICON_Y", "66"))
# Optional app-specific interaction: a comma-separated list of QEMU HMP
# sendkey names typed after the window opens (instead of the default
# "t,e,s,t"). A literal "shot" token captures an intermediate screendump
# named typed-<N>.ppm so multi-step flows (e.g. calculator digit entry,
# settings tab nav) can be graded frame-by-frame. Example:
#   EXPLORE_KEYS="kp_7,kp_8,shot,kp_9,ret"
KEYS = os.environ.get("EXPLORE_KEYS", "t,e,s,t")

SCRW, SCRH = 1024, 768

# Start-menu navigation map. Each app -> (root_steps, submenu_steps),
# both counted in DOWN presses among *activatable* rows (the kernel's
# MenuMoveHover skips separators + disabled rows, so these are stable
# regardless of separator placement). Root rows, in order
# (kernel/core/boot_tasks.cpp StartMenuRebuildAndOpen):
#   0 APPS  1 UTILITIES  2 SYSTEM  3 USER APPS  (sep)  SCREENSHOT  POWER
# USER APPS (row 3) is activatable whenever the /APPS scan found at least
# one shortcut. StartMenuAppsScan plants APPS/SAMPLE.MNF, so in practice
# USER APPS IS activatable (F-003) and the activatable order is:
#   0 APPS  1 UTILITIES  2 SYSTEM  3 USER APPS  4 SCREENSHOT  5 POWER
# Crucially USER APPS sits AFTER SYSTEM, so SYSTEM stays activatable
# index 2 either way — the SYSTEM root_steps below are correct as-is.
# (If a future layout moves USER APPS before SYSTEM, bump those to 3.)
# After Ctrl+Esc the menu auto-hovers row 0; after Right the submenu
# auto-hovers its row 0. So the sequence is:
#   ctrl-esc, down*root_steps, right, down*submenu_steps, ret
# APPS submenu (activatable rows):
#   0 CALCULATOR 1 NOTEPAD 2 FILES 3 CLOCK 4 CALENDAR 5 BROWSER
#   6 IMAGE VIEWER 7 GFX DEMO 8 ABOUT 9 HELP
# UTILITIES submenu:
#   0 HEX VIEWER 1 CHARACTER MAP 2 TERMINAL
# SYSTEM submenu (activatable rows; separators skipped):
#   0 SETTINGS 1 TASK MANAGER 2 SYSTEM MONITOR 3 KERNEL LOG
#   4 NOTIFICATIONS 5 NETWORK STATUS 6 DEVICE MANAGER 7 FIREWALL
#   8 DEBUGGER 9 CYCLE WINDOWS 10 SWITCH TO TTY
LAUNCH_NAV = {
    # APPS submenu (root_steps=0)
    "calculator": (0, 0),
    "notes":      (0, 1),
    "notepad":    (0, 1),
    "files":      (0, 2),
    "clock":      (0, 3),
    "calendar":   (0, 4),
    "browser":    (0, 5),
    "imageview":  (0, 6),
    "gfxdemo":    (0, 7),
    "about":      (0, 8),
    "help":       (0, 9),
    # UTILITIES submenu (root_steps=1)
    "hexview":    (1, 0),
    "charmap":    (1, 1),
    "terminal":   (1, 2),
    # SYSTEM submenu (root_steps=2)
    "settings":   (2, 0),
    "taskman":    (2, 1),
    "taskmanager":(2, 1),
    "sysmon":     (2, 2),
    "logview":    (2, 3),
    "notify_center": (2, 4),
    "notifycenter":  (2, 4),
    "netstatus":  (2, 5),
    "devicemgr":  (2, 6),
    "firewall":   (2, 7),
    "dbg":        (2, 8),
    "debugger":   (2, 8),
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

def key(name, n=1):
    # Inter-key spacing. Pre-F-002 this had to be 0.18s because the
    # kbd-reader's VBox auto-repeat suppressor ran on EVERY host and ate
    # any same-key re-press inside ~100ms of its release — so a fast
    # start-menu nav landed short and opened the wrong app. That
    # suppressor is now VBox-only (kernel/core/boot_tasks.cpp), so on
    # QEMU/real-HW fast keys are delivered verbatim. We keep a modest
    # 0.09s here only to give QEMU's HMP time to flush each sendkey
    # (back-to-back monitor commands can otherwise coalesce); 0.06s
    # nav was verified correct after the fix.
    for _ in range(n):
        hmp(f"sendkey {name}"); time.sleep(0.09)

def shot(name):
    path = os.path.join(SHOT_DIR, f"{APP}-{name}.ppm")
    drain(); hmp(f"screendump {path}"); time.sleep(0.5); print(f"SHOT {path}", flush=True)

def launch_icon():
    double_click(ICON_X, ICON_Y)

def launch_startmenu():
    nav = LAUNCH_NAV.get(APP)
    if nav is None:
        print(f"WARN no start-menu nav entry for {APP}; falling back to icon", flush=True)
        launch_icon(); return
    root_steps, sub_steps = nav
    # Ctrl+Esc toggles the start menu; the kernel auto-hovers root row 0.
    key("ctrl-esc"); time.sleep(0.4); shot("menu")
    if root_steps:
        key("down", root_steps)
    key("right"); time.sleep(0.5); shot("submenu")
    if sub_steps:
        key("down", sub_steps)
    key("ret")

drain()
os.makedirs(SHOT_DIR, exist_ok=True)
shot("desktop")
if LAUNCH == "startmenu":
    launch_startmenu()
else:
    launch_icon()
time.sleep(1.5); shot("open")
shot_seq = 0
for k in [t for t in KEYS.split(",") if t]:
    if k == "shot":
        shot(f"typed-{shot_seq}"); shot_seq += 1; continue
    hmp(f"sendkey {k}"); time.sleep(0.05)
shot("typed")
hmp("sendkey ret"); time.sleep(0.5); shot("enter")
hmp("sendkey alt-spc"); time.sleep(0.3); shot("sysmenu")
hmp("sendkey esc"); time.sleep(0.2)
hmp("sendkey alt-f4"); time.sleep(0.5); shot("closed")
print("explore-app-driver done for", APP, flush=True)
sys.exit(0)
