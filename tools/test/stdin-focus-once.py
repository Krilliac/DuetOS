#!/usr/bin/env python3
"""Prove one QEMU keyboard command reaches only the foreground usershell."""

from __future__ import annotations

import re
import socket
import sys
import time
from pathlib import Path


COMMAND = "help"
USERSHELL_RESULT = "commands: help, pid, echo <args>, exit"
KERNEL_SHELL_RESULT = "AVAILABLE COMMANDS:"
ANSI = re.compile(rb"\x1b\[[0-9;]*[A-Za-z]")

DIRECT_KEYS = {
    " ": "spc",
    "_": "shift-minus",
}


def serial_bytes(path: Path) -> bytes:
    try:
        return path.read_bytes()
    except OSError:
        return b""


def normalized(raw: bytes) -> str:
    return ANSI.sub(b"", raw).decode("utf-8", "replace").replace("\r\n", "\n").replace("\r", "\n")


def wait_for(path: Path, marker: str, timeout: float) -> bool:
    deadline = time.time() + timeout
    needle = marker.encode()
    while time.time() < deadline:
        if needle in ANSI.sub(b"", serial_bytes(path)):
            return True
        time.sleep(0.25)
    return False


def send(monitor: socket.socket, command: str, delay: float = 0.08) -> None:
    monitor.sendall((command + "\n").encode())
    time.sleep(delay)


def type_line(monitor: socket.socket, line: str) -> None:
    for char in line:
        if char in DIRECT_KEYS:
            key = DIRECT_KEYS[char]
        elif char.isascii() and (char.islower() or char.isdigit()):
            key = char
        else:
            raise ValueError(f"unsupported test character: {char!r}")
        send(monitor, f"sendkey {key}")
    send(monitor, "sendkey ret", delay=0.25)


def main() -> int:
    if len(sys.argv) != 3:
        print(f"usage: {sys.argv[0]} MONITOR_SOCKET SERIAL_LOG", file=sys.stderr)
        return 2

    monitor_path = Path(sys.argv[1])
    serial_path = Path(sys.argv[2])
    if not wait_for(serial_path, "DuetOS userland shell v0", 30.0) or not wait_for(serial_path, "duet$ ", 30.0):
        print("FAIL: usershell prompt did not become ready", file=sys.stderr)
        return 3

    baseline_deadline = time.time() + 5.0
    baseline = serial_bytes(serial_path)
    while not baseline and time.time() < baseline_deadline:
        time.sleep(0.1)
        baseline = serial_bytes(serial_path)
    if not baseline:
        print("FAIL: serial log was not readable after usershell became ready", file=sys.stderr)
        return 4
    start = len(baseline)
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as monitor:
        monitor.settimeout(5.0)
        monitor.connect(str(monitor_path))
        monitor.recv(4096)
        # usershell does not yet implement history. The foreground router must
        # consume this unsupported control key without inserting "[A" into the
        # command buffer or changing the background kernel-shell history.
        send(monitor, "sendkey up", delay=0.25)
        type_line(monitor, COMMAND)

        deadline = time.time() + 30.0
        delta = ""
        while time.time() < deadline:
            delta = normalized(serial_bytes(serial_path)[start:])
            if USERSHELL_RESULT in delta and "duet$ " in delta:
                break
            time.sleep(0.25)

        send(monitor, "quit", delay=0.05)

    usershell_count = delta.count(USERSHELL_RESULT)
    kernel_shell_count = delta.count(KERNEL_SHELL_RESULT)
    if usershell_count != 1 or kernel_shell_count != 0:
        print(
            "FAIL: expected one usershell help result and no kernel-shell help result; "
            f"usershell_results={usershell_count} kernel_shell_results={kernel_shell_count}",
            file=sys.stderr,
        )
        print(delta[-2000:], file=sys.stderr)
        return 1

    print("PASS: foreground usershell consumed help exactly once; kernel shell did not execute it")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
