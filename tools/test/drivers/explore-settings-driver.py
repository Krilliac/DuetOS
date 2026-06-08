#!/usr/bin/env python3
"""explore-settings-driver.py - settings-specific exploration driver for the
DuetOS usability campaign. Opens Settings via the desktop icon, then visits
each of the 5 sub-panels (DSP/SND/KBD/MSE/DT) using number-key panel
switching (SettingsFeedChar '1'..'5'), taking a screendump after each.
Also exercises panel-specific key bindings to probe the apply path.

Usage (from desktop-qmp-session.sh):
  EXPLORE_SHOT_DIR=/tmp/e6-settings \
    tools/test/desktop-qmp-session.sh e6-settings \
    tools/test/drivers/explore-settings-driver.py

Environment:
  EXPLORE_SHOT_DIR   directory for .ppm output (created if absent)
  EXPLORE_ICON_X/Y   desktop icon coordinates (default 62/526 for settings)

Window geometry (from boot_bringup.cpp):
  settings_chrome.x=320, y=100, w=380, h=340
  Title bar = 22px. Client area starts at y=122.
  Tab strip right pane: x=320+112=432, y=122..143 (kTabStripH=22)
  Tab buttons: cover full kTabStripH row, center_y=122+11=133
  Tab i x-center = 432 + 4 + i*(38+4) + 19
  i=0 GEN=455, i=1 DSP=497, i=2 SND=539, i=3 KBD=581, i=4 MSE=623, i=5 DT=665
"""
import os, socket, sys, time

mon_p = sys.argv[1]
slog  = sys.argv[2]

SHOT_DIR = os.environ.get("EXPLORE_SHOT_DIR", "/tmp/e6-settings")
ICON_X   = int(os.environ.get("EXPLORE_ICON_X", "62"))
ICON_Y   = int(os.environ.get("EXPLORE_ICON_Y", "526"))

SCRW, SCRH = 1024, 768

# From boot_bringup.cpp: settings_chrome.x=320, y=100, w=380, h=340
WIN_X, WIN_Y   = 320, 100
WIN_W, WIN_H   = 380, 340
TITLE_H        = 22
CLIENT_Y       = WIN_Y + TITLE_H   # 122

# Center of the client area (for focus clicks that don't hit buttons)
CLIENT_CX = WIN_X + WIN_W // 2    # 510
CLIENT_CY = CLIENT_Y + (WIN_H - TITLE_H) // 2  # 282

# Tab strip geometry (right pane, from kReadoutX=112)
READOUT_X      = WIN_X + 112      # 432
TAB_PAD_X      = 4
TAB_BTN_W      = 38
TAB_BTN_GAP    = 4
TAB_STRIP_H    = 22   # kTabStripH — buttons cover the full strip height
TAB_Y          = CLIENT_Y + TAB_STRIP_H // 2  # 133 — center of full strip

def tab_x(i):
    return READOUT_X + TAB_PAD_X + i * (TAB_BTN_W + TAB_BTN_GAP) + TAB_BTN_W // 2

TAB_CENTERS = [(tab_x(i), TAB_Y) for i in range(6)]
TAB_NAMES   = ["GEN", "DSP", "SND", "KBD", "MSE", "DT"]

# Left-column button column (from kBtnX=8, kBtnY=8, kBtnH=22, kBtnGap=4)
# Buttons are in the client area. Button column center x = WIN_X + 8 + 92//2 = 366
LEFT_BTN_CX = WIN_X + 8 + 46   # 374

# --- socket / HMP helpers ----------------------------------------

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

cur = [(SCRW - 12) // 2, (SCRH - 20) // 2]  # match kernel CursorInit: (w-12)/2, (h-20)/2

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
    move_to(x, y)
    hmp(f"mouse_button {btn}"); time.sleep(0.08)
    hmp("mouse_button 0"); time.sleep(0.08)

def double_click(x, y):
    click(x, y); time.sleep(0.12); click(x, y)

def key(name, n=1):
    for _ in range(n):
        hmp(f"sendkey {name}"); time.sleep(0.20)

def shot(tag):
    os.makedirs(SHOT_DIR, exist_ok=True)
    path = os.path.join(SHOT_DIR, f"settings-{tag}.ppm")
    drain(); hmp(f"screendump {path}"); time.sleep(0.7)
    print(f"SHOT {path}", flush=True)

def focus_client():
    """Click the center of the client area to give settings keyboard focus.
    Avoids buttons (left pane x < WIN_X+104) and tab strip (y < CLIENT_Y+22).
    Target: right pane, below tab strip."""
    # Right pane below tab strip: x=510, y=CLIENT_Y+40=162
    click(WIN_X + 220, CLIENT_Y + 60)
    time.sleep(0.20)

def switch_panel(n):
    """Focus the window, then send number key n (0=GEN,1=DSP,...,5=DT).
    Waits after so the compositor redraws."""
    focus_client()
    hmp(f"sendkey {n}"); time.sleep(0.50)

# --- launch settings via desktop icon ----------------------------

drain()
shot("00-desktop")
double_click(ICON_X, ICON_Y)
time.sleep(2.5)   # wait for window to open and compositor to paint
shot("01-open")   # general panel on first open

# --- Verify window opened and focus ---
# The settings window should now be active. Click its title bar to confirm.
click(WIN_X + 190, WIN_Y + 11)   # title bar center
time.sleep(0.3)

# --- General panel: exercise theme cycling -----------------------
# 't' cycles theme, '0' resets.  These use FeedChar directly.
hmp("sendkey t"); time.sleep(0.35); shot("02-gen-theme-cycled")
hmp("sendkey 0"); time.sleep(0.35); shot("03-gen-reset")

# --- Switch to DSP panel via number key 1 ------------------------
switch_panel("1")
shot("04-dsp-open")
# Exercise B (DPMS blank) and W (wake) — DSP panel keys
hmp("sendkey b"); time.sleep(0.35); shot("05-dsp-blanked")
hmp("sendkey w"); time.sleep(0.35); shot("06-dsp-wake")

# --- Switch to SND panel via number key 2 -----------------------
switch_panel("2")
shot("07-snd-open")
# Exercise M (mute toggle)
hmp("sendkey m"); time.sleep(0.35); shot("08-snd-muted")
hmp("sendkey m"); time.sleep(0.35); shot("09-snd-unmuted")

# --- Switch to KBD panel via number key 3 -----------------------
switch_panel("3")
shot("11-kbd-open")
# Exercise F (faster repeat) and S (slower repeat)
# NOTE: in KBD panel 'f'=faster, 's'=slower, NOT layout switches
hmp("sendkey f"); time.sleep(0.35); shot("12-kbd-faster")
hmp("sendkey s"); time.sleep(0.35); shot("13-kbd-slower")

# --- Switch to MSE panel via number key 4 -----------------------
switch_panel("4")
shot("14-mse-open")
# In MSE panel: '='=sens+16, bracketright=DC+50ms
hmp("sendkey equal"); time.sleep(0.35); shot("15-mse-sens-up")
hmp("sendkey bracketright"); time.sleep(0.35); shot("16-mse-dc-up")

# --- Switch to DT panel via number key 5 ------------------------
switch_panel("5")
shot("18-dt-open")
# In DT panel: bracketright=+1h, bracketleft=-1h
hmp("sendkey bracketright"); time.sleep(0.35); shot("19-dt-tz-plus")
hmp("sendkey bracketleft"); time.sleep(0.35); shot("20-dt-tz-reset")

# --- Tab strip visual verification ------------------------------
# Click each tab button in turn to confirm click-to-switch also works
# when click coordinates are correct.
for i, (tx, ty) in enumerate(TAB_CENTERS):
    click(tx, ty); time.sleep(0.55)
    shot(f"tab-{TAB_NAMES[i].lower()}")

# --- Return to General, close ------------------------------------
switch_panel("0")
shot("22-gen-final")
hmp("sendkey alt-f4"); time.sleep(0.6); shot("23-closed")

print("explore-settings-driver done", flush=True)
sys.exit(0)
