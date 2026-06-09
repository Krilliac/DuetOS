#!/usr/bin/env python3
"""browser-explore-driver.py — drive the DuetOS kernel browser to a list of
real websites and screendump what each renders. Uses the desktop-qmp-session
HMP contract: invoked as `driver.py <MON_SOCK> <SERIAL_LOG>`, with the site
list + output dir in the env (SITES, SHOT_DIR).

Launches the browser via the Start menu, then per site: focuses the URL bar
('u'), clears it, types the bare domain (the omnibox classifier routes a
dotted host to navigation — no scheme/'/' needed, handy since HMP sendkey
lacks ':' '/'), presses Enter, waits for fetch+render, and screendumps a PPM.
"""
import os, socket, sys, time

MON = sys.argv[1]
SLOG = sys.argv[2]
SHOT_DIR = os.environ.get("SHOT_DIR", "/root/browser-explore")
SITES = [s.strip() for s in os.environ.get("SITES", "example.com").split(",") if s.strip()]
os.makedirs(SHOT_DIR, exist_ok=True)

s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
for _ in range(200):
    try:
        s.connect(MON); break
    except (FileNotFoundError, ConnectionRefusedError):
        time.sleep(0.25)
s.settimeout(0.2)
time.sleep(0.5)

def drain():
    try:
        while s.recv(65536):
            pass
    except Exception:
        pass

def hmp(line):
    s.sendall((line + "\n").encode()); time.sleep(0.05); drain()

def key(name, n=1):
    for _ in range(n):
        hmp(f"sendkey {name}"); time.sleep(0.09)

def shot(label):
    p = os.path.join(SHOT_DIR, f"{label}.ppm")
    drain(); hmp(f"screendump {p}"); time.sleep(0.6); print(f"SHOT {p}", flush=True)

QC = {".": "dot", "-": "minus"}
def typestr(text):
    for ch in text:
        if ch.isalnum():
            hmp(f"sendkey {ch.lower()}")
        elif ch in QC:
            hmp(f"sendkey {QC[ch]}")
        time.sleep(0.05)

drain()
time.sleep(1.0)
shot("00-desktop")
# Start menu -> APPS submenu (auto-hovers row 0) -> down 5 -> BROWSER -> Enter.
key("ctrl-esc"); time.sleep(0.5); shot("00-menu")
key("right"); time.sleep(0.5); shot("00-apps-submenu")
key("down", 5)
key("ret"); time.sleep(2.0); shot("01-browser-open")

for i, site in enumerate(SITES, start=1):
    key("u"); time.sleep(0.3)                 # View -> UrlEdit (focus URL bar)
    key("backspace", 80); time.sleep(0.2)     # clear any prior URL
    typestr(site); time.sleep(0.3)
    shot(f"{i:02d}-{site}-typed")
    key("ret")                                # classify + StartFetch
    time.sleep(14)                            # DNS+TCP+TLS+verify+render (recv cap 30s)
    shot(f"{i:02d}-{site}-result")
    print(f"NAV {site} done", flush=True)

print("EXPLORE COMPLETE", flush=True)
