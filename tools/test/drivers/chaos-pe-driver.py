#!/usr/bin/env python3
"""chaos-pe-driver.py — PE spawn/kill storm + handle-table exhaustion driver.

Drives desktop-qmp-session.sh over the HMP monitor. Goal: spawn many
processes/windows as fast as possible (rapid double-clicks on desktop
icons + Start-menu app/PE shortcuts), churn open/close via title-bar X,
and try to exhaust the Win32 ~64/type handle table. Watches the serial
log for spawn vs teardown balance and for crash/wedge/panic markers.

HMP contract (per harness header):
  mouse_move DX DY   relative pointer motion
  mouse_button N     1=left 2=right 4=middle; 0=release (double-click =
                     two quick down/up pairs within the dbl-click window)
  screendump path

This is a chaos/robustness test: it never asserts "PASS"; it dumps the
spawn/release tally + any crash evidence and exits 0 so the harness
preserves the serial log for offline boot-log-analyze.

Invoked as: python3 chaos-pe-driver.py <MON_SOCK> <SERIAL_LOG>
"""
import socket, sys, time

mon_p, slog = sys.argv[1], sys.argv[2]
DURATION = float(__import__("os").environ.get("CHAOS_SECS", "78"))


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
try:
    s.recv(65536)
except Exception:
    pass


def hmp(line):
    s.sendall((line + "\n").encode())


def pin_origin():
    # Relative pointer: drive far negative to clamp at (0,0).
    hmp("mouse_move -4000 -4000")
    time.sleep(0.03)


def move_to(x, y):
    # From origin, step to absolute-ish target (<=40px steps per harness).
    pin_origin()
    dx, dy = x, y
    while dx > 0 or dy > 0:
        sx = min(40, dx); sy = min(40, dy)
        hmp("mouse_move %d %d" % (sx, sy))
        dx -= sx; dy -= sy
        time.sleep(0.012)


def click():
    hmp("mouse_button 1")
    time.sleep(0.03)
    hmp("mouse_button 0")
    time.sleep(0.03)


def dblclick():
    hmp("mouse_button 1"); time.sleep(0.02); hmp("mouse_button 0"); time.sleep(0.04)
    hmp("mouse_button 1"); time.sleep(0.02); hmp("mouse_button 0"); time.sleep(0.05)


def dblclick_at(x, y):
    move_to(x, y)
    dblclick()


def count(txt, needle):
    return txt.count(needle)


print("=== chaos-pe-driver: PE spawn/kill storm (%.0fs) ===" % DURATION, flush=True)
mark = len(logtext())
start = time.time()
deadline = start + DURATION

# Desktop icon grid: kColX0=20, kTopY=24, kColStride=96, kRowPitch=92,
# cell center ~ (col*96 + 48, row*92 + 52). Cover 3 columns x 6 rows.
icon_centers = []
for col in range(3):
    for row in range(6):
        icon_centers.append((20 + col * 96 + 28, 24 + row * 92 + 28))

# Start button: x=4..92 at the bottom taskbar. Screen is 512M/q35 virtio
# default; assume 1024x768-ish -> taskbar near y=740. Probe a band.
START_X = 46
START_Y_BAND = [738, 744, 750, 470, 600]  # bottom + safe mids if res differs

# Start-menu item column: menu opens above the start button along the
# left edge; spray double-clicks down the left column to hit PE/app rows.
MENU_X = 60
MENU_Y_ROWS = [120, 152, 184, 216, 248, 280, 312, 344, 376, 408, 440, 472]

rounds = 0
while time.time() < deadline:
    rounds += 1
    # --- Phase A: desktop-icon double-click storm (window raise churn) ---
    for (ix, iy) in icon_centers:
        if time.time() >= deadline:
            break
        dblclick_at(ix, iy)

    # --- Phase B: Start-menu open + PE/app row spray (real SpawnPeFile) ---
    if time.time() < deadline:
        # open start menu
        for sy in START_Y_BAND[:2]:
            move_to(START_X, sy)
            click()
        time.sleep(0.10)
        for my in MENU_Y_ROWS:
            if time.time() >= deadline:
                break
            move_to(MENU_X, my)
            click()          # single click launches a menu row
            time.sleep(0.02)
        # dismiss any open menu by clicking dead-center desktop
        move_to(400, 300); click()

    # --- Phase C: close churn — click top-right title-bar X of any windows.
    # Windows open at varied rects; spray the top-right corners band.
    if time.time() < deadline:
        for (wx, wy) in [(816, 20), (620, 20), (700, 360), (520, 200), (300, 120)]:
            if time.time() >= deadline:
                break
            move_to(wx, wy)
            click()

    # periodic progress so a wedge is visible in driver stdout
    el = time.time() - start
    txt = logtext()[mark:]
    sp = count(txt, "[win] create")
    rel = count(txt, "[proc] release: done")
    icl = count(txt, "[ui] desktop icon launch")
    print("  t=%4.1fs round=%d  win-create=%d  proc-release-done=%d  icon-launch=%d"
          % (el, rounds, sp, icl, rel), flush=True)

# Settle so trailing teardowns flush to the log.
time.sleep(4.0)
hmp("screendump /tmp/chaos-pe-final.ppm")
time.sleep(0.5)

txt = logtext()[mark:]
full = logtext()

def grepc(t, needle):
    return sum(1 for ln in t.splitlines() if needle in ln)

win_create   = count(txt, "[win] create")
as_freed     = grepc(txt, "[as] regions freed")
rel_done     = count(txt, "[proc] release: done")
rel_post_as  = count(txt, "[proc] release: post-AS")
spawn_ok     = grepc(txt, "LAUNCH OK pid=")
spawn_fail   = grepc(txt, "LAUNCH FAIL")
icon_launch  = count(txt, "[ui] desktop icon launch")
htable_full  = sum(1 for ln in txt.splitlines()
                   if ("handle" in ln.lower() and ("full" in ln.lower() or "exhaust" in ln.lower()
                       or "refus" in ln.lower() or "capacity" in ln.lower())))
htable_oor   = grepc(txt, "Remove: handle out of range")  # deliberate sweep noise

panic   = sum(1 for ln in txt.splitlines() if "PANIC" in ln or "TRIPLE" in ln or "kernel oops" in ln)
gp_uaf  = sum(1 for ln in txt.splitlines()
              if "use-after-free" in ln or "double-free" in ln or "double free" in ln
              or "#GP" in ln or "#PF" in ln or "#UD" in ln)

print("\n=== chaos-pe storm summary ===", flush=True)
print("  rounds executed:            %d" % rounds)
print("  [win] create:               %d" % win_create)
print("  /APPS LAUNCH OK pid=:        %d" % spawn_ok)
print("  /APPS LAUNCH FAIL:           %d" % spawn_fail)
print("  [ui] desktop icon launch:   %d" % icon_launch)
print("  [proc] release: post-AS:    %d" % rel_post_as)
print("  [proc] release: done:       %d" % rel_done)
print("  [as] regions freed:         %d" % as_freed)
print("  handle-table refuse/full:   %d" % htable_full)
print("  handle out-of-range sweep:  %d (deliberate selftest noise)" % htable_oor)
print("  PANIC/TRIPLE/oops:          %d" % panic)
print("  #GP/#PF/#UD/UAF/dbl-free:    %d" % gp_uaf)
print("  --- spawn vs teardown balance ---")
print("  spawn-ish (win_create+spawn_ok) = %d ; teardown (rel_done) = %d"
      % (win_create + spawn_ok, rel_done))

# Echo any genuinely scary lines (filter the known-deliberate sweep).
scary = [ln for ln in txt.splitlines()
         if ("PANIC" in ln or "TRIPLE" in ln or "kernel oops" in ln
             or "use-after-free" in ln or "double free" in ln or "double-free" in ln)]
for ln in scary[:20]:
    print("  !! " + ln.strip()[-100:])

print("RESULT: chaos run complete (see counts; analyze serial log offline)", flush=True)
sys.exit(0)
