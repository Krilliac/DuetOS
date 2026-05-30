#!/usr/bin/env python3
"""
winver-shot-driver.py — desktop-qmp-session.sh driver that captures the
framebuffer a few times after the deferred peexec spawns winver.exe, so
the ShellAboutW "About DuetOS" window is visible in at least one shot.

Invoked by desktop-qmp-session.sh as:
    python3 winver-shot-driver.py <MON_SOCK> <SERIAL_LOG>

Env:
    WINVER_SHOT_DIR  — directory to drop PPM screendumps into
                       (default: same dir as SERIAL_LOG).
    WINVER_SHOTS     — number of shots (default 4), spaced WINVER_GAP s.
    WINVER_GAP       — seconds between shots (default 4).

The peexec spawn is deferred (waits for async storage), so the about
window typically appears ~10-20s after bringup-complete. The session
harness already slept DUETOS_SETTLE before invoking us; we then take a
short burst of shots to bracket the window's lifetime.
"""
import os
import socket
import sys
import time


def hmp(sock, line):
    sock.sendall((line + "\n").encode())
    time.sleep(0.3)
    try:
        return sock.recv(65536).decode("utf-8", "replace")
    except Exception:
        return ""


def main():
    mon_path = sys.argv[1]
    serial_log = sys.argv[2]
    shot_dir = os.environ.get("WINVER_SHOT_DIR", os.path.dirname(os.path.abspath(serial_log)))
    shots = int(os.environ.get("WINVER_SHOTS", "4"))
    gap = float(os.environ.get("WINVER_GAP", "4"))
    os.makedirs(shot_dir, exist_ok=True)

    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(mon_path)
    time.sleep(0.5)
    try:
        s.recv(65536)  # greeting
    except Exception:
        pass

    written = []
    for i in range(shots):
        out = os.path.join(shot_dir, "winver-shot-%d.ppm" % i)
        try:
            os.remove(out)
        except FileNotFoundError:
            pass
        hmp(s, "screendump %s" % out)
        time.sleep(0.6)
        if os.path.exists(out) and os.path.getsize(out) > 102400:
            written.append(out)
            print("[winver-shot] wrote %s (%d bytes)" % (out, os.path.getsize(out)), flush=True)
        else:
            print("[winver-shot] shot %d missing/short" % i, flush=True)
        if i != shots - 1:
            time.sleep(gap)

    # Report whether the serial shows ShellAboutW was reached.
    try:
        log = open(serial_log, "rb").read().decode("utf-8", "replace")
    except FileNotFoundError:
        log = ""
    if "ShellAboutW" in log:
        print("[winver-shot] serial mentions ShellAboutW", flush=True)
    if "[win create]" in log or "DoWinCreate" in log:
        print("[winver-shot] serial shows a window was created", flush=True)

    s.close()
    print("[winver-shot] done; %d shots captured" % len(written), flush=True)
    sys.exit(0 if written else 4)


if __name__ == "__main__":
    main()
