#!/usr/bin/env python3
"""
One-off BSOD capture harness.

Boots the kernel under QEMU with a monitor unix socket exposed,
waits for the windowed Terminal to come up, sends `panic-test`
over the serial line, watches for the BSOD render log line, then
issues a `screendump` via the monitor to capture the framebuffer.
Converts the resulting PPM to PNG so a multimodal viewer can see
it.

Run from the repo root: python3 tools/test/capture-bsod.py
"""

from __future__ import annotations

import fcntl
import os
import select
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
PRESET = os.environ.get("DUETOS_PRESET", "x86_64-debug")
BUILD = REPO / "build" / PRESET
ISO = BUILD / "duetos.iso"
def _find_ovmf() -> tuple[str, str]:
    candidates = [
        ("/usr/share/OVMF/OVMF_CODE.fd", "/usr/share/OVMF/OVMF_VARS.fd"),
        ("/usr/share/OVMF/OVMF_CODE_4M.fd", "/usr/share/OVMF/OVMF_VARS_4M.fd"),
        ("/usr/share/ovmf/OVMF.fd", "/usr/share/ovmf/OVMF.fd"),
    ]
    for code, vars_ in candidates:
        if Path(code).exists() and Path(vars_).exists():
            return code, vars_
    raise FileNotFoundError("OVMF firmware not found in /usr/share/OVMF*")


OVMF_CODE, OVMF_VARS_SRC = _find_ovmf()
OVMF_VARS_COPY = BUILD / "ovmf-vars.fd"
NVME_IMAGE = BUILD / "nvme0.img"
SATA_IMAGE = BUILD / "sata0.img"

MON_SOCK = "/tmp/duetos-bsod-mon.sock"
PPM_OUT = "/tmp/duetos-bsod.ppm"
PNG_OUT = "/tmp/duetos-bsod.png"
SERIAL_LOG = "/tmp/duetos-bsod-serial.log"


def ensure_disks() -> None:
    BUILD.mkdir(parents=True, exist_ok=True)
    if not OVMF_VARS_COPY.exists():
        shutil.copy(OVMF_VARS_SRC, OVMF_VARS_COPY)
    for p, size in ((NVME_IMAGE, 16 * 1024 * 1024), (SATA_IMAGE, 16 * 1024 * 1024)):
        if not p.exists():
            with open(p, "wb") as f:
                f.truncate(size)


def qemu_args() -> list[str]:
    return [
        "qemu-system-x86_64",
        "-no-reboot",
        "-no-shutdown",
        "-machine", "q35,accel=tcg",
        "-cpu", "max",
        "-m", "512",
        "-drive", f"if=pflash,format=raw,readonly=on,file={OVMF_CODE}",
        "-drive", f"if=pflash,format=raw,file={OVMF_VARS_COPY}",
        "-device", "isa-debug-exit,iobase=0xf4,iosize=0x01",
        "-drive", f"file={NVME_IMAGE},if=none,id=nvme0,format=raw",
        "-device", "nvme,serial=cafebabe,drive=nvme0",
        "-device", "ahci,id=ahci1",
        "-drive", f"file={SATA_IMAGE},if=none,id=sata0,format=raw",
        "-device", "ide-hd,bus=ahci1.0,drive=sata0",
        "-device", "qemu-xhci,id=xhci",
        "-device", "usb-kbd,bus=xhci.0",
        "-device", "usb-mouse,bus=xhci.0",
        "-netdev", "user,id=net0",
        "-device", "e1000e,netdev=net0,mac=52:54:00:12:34:56",
        "-cdrom", str(ISO),
        "-boot", "d",
        "-vga", "virtio",
        "-display", "none",
        "-serial", "stdio",
        "-monitor", f"unix:{MON_SOCK},server,nowait",
    ]


def make_nonblocking(fd: int) -> None:
    flags = fcntl.fcntl(fd, fcntl.F_GETFL)
    fcntl.fcntl(fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)


def wait_for_marker(fd: int, marker: bytes, timeout_s: float, log_path: str | None = None) -> tuple[bool, bytes]:
    """Read from non-blocking fd until `marker` substring is seen or timeout.

    Appends every chunk read to log_path if provided, so we can
    inspect serial output post-hoc."""
    buf = bytearray()
    deadline = time.monotonic() + timeout_s
    log_f = open(log_path, "ab") if log_path else None
    try:
        while time.monotonic() < deadline:
            ready, _, _ = select.select([fd], [], [], 0.5)
            if fd in ready:
                try:
                    chunk = os.read(fd, 65536)
                except BlockingIOError:
                    continue
                if not chunk:
                    time.sleep(0.05)
                    continue
                buf.extend(chunk)
                if log_f:
                    log_f.write(chunk)
                    log_f.flush()
                if marker in buf:
                    return True, bytes(buf)
    finally:
        if log_f:
            log_f.close()
    return False, bytes(buf)


def monitor_command(cmd: str, settle_s: float = 1.0) -> str:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(MON_SOCK)
    s.settimeout(2.0)
    # Drain QEMU's greeting.
    time.sleep(0.2)
    try:
        s.recv(8192)
    except socket.timeout:
        pass
    s.sendall((cmd + "\n").encode())
    time.sleep(settle_s)
    chunks: list[bytes] = []
    try:
        while True:
            chunk = s.recv(8192)
            if not chunk:
                break
            chunks.append(chunk)
    except socket.timeout:
        pass
    s.close()
    return b"".join(chunks).decode("utf-8", errors="replace")


def main() -> int:
    if not ISO.exists():
        print(f"error: ISO not found at {ISO}; build it first", file=sys.stderr)
        return 1

    ensure_disks()
    for p in (MON_SOCK, PPM_OUT, PNG_OUT, SERIAL_LOG):
        try:
            os.unlink(p)
        except FileNotFoundError:
            pass

    print("[harness] launching QEMU")
    qemu = subprocess.Popen(
        qemu_args(),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        cwd=str(REPO),
        bufsize=0,
    )
    assert qemu.stdin is not None
    assert qemu.stdout is not None
    make_nonblocking(qemu.stdout.fileno())

    # Boot to a stable late-boot marker. The terminal app's
    # selftest line is the last grep-friendly milestone before
    # the steady-state idle loop.
    print("[harness] waiting for [terminal-selftest] PASS...")
    ok, _ = wait_for_marker(qemu.stdout.fileno(), b"[terminal-selftest] PASS",
                             timeout_s=120.0, log_path=SERIAL_LOG)
    if not ok:
        print("[harness] FAIL: never saw [terminal-selftest] PASS")
        print(f"          tail of {SERIAL_LOG}:")
        os.system(f"tail -40 {SERIAL_LOG}")
        qemu.kill()
        return 2

    # Let the boot quiesce a couple of seconds so the prompt is
    # rendered and the serial-input pump is consuming stdin.
    time.sleep(4.0)

    print("[harness] sending 'panic-test' over serial")
    qemu.stdin.write(b"panic-test\n")
    qemu.stdin.flush()

    print("[harness] waiting for [bsod] rendered...")
    ok, captured = wait_for_marker(qemu.stdout.fileno(), b"[bsod] rendered",
                                    timeout_s=30.0, log_path=SERIAL_LOG)
    if not ok:
        print("[harness] FAIL: never saw [bsod] rendered. Tail of serial log:")
        os.system(f"tail -50 {SERIAL_LOG}")
        qemu.kill()
        return 3

    time.sleep(1.5)

    print(f"[harness] issuing screendump -> {PPM_OUT}")
    response = monitor_command(f"screendump {PPM_OUT}")
    if not Path(PPM_OUT).exists():
        print("[harness] FAIL: screendump did not produce a file")
        print("monitor response was:")
        print(response[:1000])
        qemu.kill()
        return 4

    print(f"[harness] converting to PNG -> {PNG_OUT}")
    cv = subprocess.run(["convert", PPM_OUT, PNG_OUT], capture_output=True)
    if cv.returncode != 0:
        print("[harness] convert failed:", cv.stderr.decode())
        qemu.kill()
        return 5

    qemu.kill()
    try:
        qemu.wait(timeout=10)
    except subprocess.TimeoutExpired:
        pass
    print(f"[harness] OK: {PNG_OUT}")
    print(f"          PPM size: {Path(PPM_OUT).stat().st_size} bytes")
    print(f"          PNG size: {Path(PNG_OUT).stat().st_size} bytes")
    return 0


if __name__ == "__main__":
    sys.exit(main())
