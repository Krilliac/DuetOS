#!/usr/bin/env python3
"""chaos-shot-probe.py — minimal probe: inject a little input, then try a
screendump and capture the HMP monitor's reply so we learn the correct
path/semantics for screendump under -display none -vga virtio.

Invoked as: python3 chaos-shot-probe.py <MON_SOCK> <SERIAL_LOG>
"""
import socket
import sys
import time

mon_p = sys.argv[1]
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
for _ in range(200):
    try:
        s.connect(mon_p)
        break
    except (FileNotFoundError, ConnectionRefusedError):
        time.sleep(0.25)
s.settimeout(1.5)
time.sleep(0.5)


def drain():
    out = b""
    try:
        while True:
            b = s.recv(65536)
            if not b:
                break
            out += b
    except socket.timeout:
        pass
    return out.decode("utf-8", "replace")


print("GREETING:\n" + drain())


def cmd(line):
    s.sendall((line + "\n").encode())
    time.sleep(0.3)
    return drain()


# A little input so something is on screen.
for _ in range(20):
    s.sendall(b"mouse_move 40 0\n")
    time.sleep(0.005)
s.sendall(b"mouse_button 1\n"); time.sleep(0.02); s.sendall(b"mouse_button 0\n")
time.sleep(0.3)

print("--- info version ---\n" + cmd("info version"))
print("--- screendump /tmp/probe.ppm ---\n" + cmd("screendump /tmp/probe.ppm"))
print("--- screendump abs ---\n" + cmd("screendump /root/source/DuetOS/build/x86_64-debug/probe2.ppm"))
print("--- info block (cwd hint) ---\n" + cmd("info roms")[:400])
sys.exit(0)
