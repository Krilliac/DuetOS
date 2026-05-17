#!/usr/bin/env python3
#
# duetos-gdb-monitor.py — DuetOS-aware `monitor` client for the
# in-kernel GDB server. Speaks the raw GDB remote-serial protocol
# (stdlib sockets only) and drives the `duet <verb>` command
# surface via `qRcmd`, so you get capability bitsets, IPC handle
# tables, the Win32 window list, probes / kdbg / watch control,
# etc. — none of which stock `gdb` can express.
#
# It mirrors duetos-gdb-cmd.sh: by default it rebuilds with
# DUETOS_GDB_DEMO=ON (a guaranteed early int3 stop — qRcmd is only
# dispatched while the target is stopped, exactly like stock
# `monitor`), boots QEMU, connects, runs the command(s), then
# detaches so the kernel resumes, and restores DEMO=OFF.
#
# Usage:
#   tools/debug/duetos-gdb-monitor.py                 # 'duet help' then 'duet ps'
#   tools/debug/duetos-gdb-monitor.py ps
#   tools/debug/duetos-gdb-monitor.py caps 0
#   tools/debug/duetos-gdb-monitor.py reg HKLM 'Software\Microsoft\Windows NT\CurrentVersion'
#   tools/debug/duetos-gdb-monitor.py probe list
#   tools/debug/duetos-gdb-monitor.py --no-boot ps    # attach to an already-running QEMU
#
# Args after any flags are joined into one `duet <...>` command.
# Output is printed to stdout; exit 0 on a well-formed reply.
#
# Env (all optional):
#   DUETOS_PRESET    — cmake preset (default x86_64-debug).
#   DUETOS_GDB_PORT  — TCP port (default 1234, must match run.sh).
#   DUETOS_TIMEOUT   — QEMU max wallclock seconds (default 300).

import os
import socket
import subprocess
import sys
import tempfile
import time

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
PRESET = os.environ.get("DUETOS_PRESET", "x86_64-debug")
BUILD_DIR = os.path.join(REPO_ROOT, "build", PRESET)
GDB_PORT = int(os.environ.get("DUETOS_GDB_PORT", "1234"))
HOST = "127.0.0.1"


# ---- RSP framing ----------------------------------------------------------

def _csum(payload: bytes) -> int:
    return sum(payload) & 0xFF


def rsp_send(sock: socket.socket, payload: str) -> None:
    raw = payload.encode("latin-1")
    pkt = b"$" + raw + b"#" + f"{_csum(raw):02x}".encode("ascii")
    for _ in range(4):
        sock.sendall(pkt)
        ack = sock.recv(1)
        if ack == b"+":
            return
        if ack == b"-":
            continue
        # Some stubs run no-ack; treat anything else as "delivered"
        # and push the byte back by handling it in the next recv.
        sock.setblocking(True)
        return
    raise RuntimeError("gdb stub NAK'd packet 4x: " + payload)


def rsp_recv(sock: socket.socket) -> str:
    # Skip stray acks, find '$', read to '#', consume 2 csum hex.
    buf = bytearray()
    state = "idle"
    while True:
        b = sock.recv(1)
        if not b:
            raise RuntimeError("gdb stub closed the connection")
        c = b[0]
        if state == "idle":
            if c == ord("$"):
                buf.clear()
                state = "body"
        elif state == "body":
            if c == ord("#"):
                state = "csum"
                csum_left = 2
                csum = b""
            else:
                buf.append(c)
        elif state == "csum":
            csum += bytes([c])
            csum_left -= 1
            if csum_left == 0:
                sock.sendall(b"+")
                return buf.decode("latin-1")


def monitor(sock: socket.socket, text: str) -> str:
    rsp_send(sock, "qRcmd," + text.encode("latin-1").hex())
    chunks = []
    while True:
        reply = rsp_recv(sock)
        if reply == "":
            return "(unsupported: not a 'duet' command — try: help)"
        if reply == "OK":
            return "".join(chunks) if chunks else "(ok)"
        if reply and reply[0] == "O":
            # Console-output chunk (forward-compat with v2 streaming).
            chunks.append(bytes.fromhex(reply[1:]).decode("latin-1"))
            continue
        if reply and reply[0] == "E" and len(reply) <= 4:
            return "(error " + reply + ")"
        return "".join(chunks) + bytes.fromhex(reply).decode("latin-1")


# ---- QEMU lifecycle -------------------------------------------------------

def _cmake_demo(value: str) -> None:
    subprocess.run(["cmake", "--preset", PRESET, f"-DDUETOS_GDB_DEMO={value}"],
                   cwd=REPO_ROOT, check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    # Build the default (ALL) target, NOT just duetos-kernel:
    # run.sh boots ${BUILD_DIR}/duetos.iso, and the iso is a
    # separate `duetos-iso ALL` custom target. Rebuilding only the
    # kernel would leave a stale iso (no demo int3) and the stop
    # wait would time out.
    subprocess.run(["cmake", "--build", BUILD_DIR],
                   cwd=REPO_ROOT, check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def boot_qemu():
    print("[mon] configuring DUETOS_GDB_DEMO=ON", file=sys.stderr)
    _cmake_demo("ON")
    log = tempfile.NamedTemporaryFile(prefix="duetos-mon-", suffix=".log", delete=False)
    env = dict(os.environ,
               DUETOS_TIMEOUT=os.environ.get("DUETOS_TIMEOUT", "300"),
               DUETOS_GDB_PORT=str(GDB_PORT))
    print("[mon] starting QEMU", file=sys.stderr)
    proc = subprocess.Popen([os.path.join(REPO_ROOT, "tools", "qemu", "run.sh")],
                            cwd=REPO_ROOT, stdout=log, stderr=subprocess.STDOUT, env=env)
    return proc, log.name


def wait_for_stop(log_path: str) -> None:
    print(f"[mon] waiting for tcp::{GDB_PORT} + demo int3 ", end="", file=sys.stderr)
    for _ in range(300):
        try:
            with socket.create_connection((HOST, GDB_PORT), timeout=1):
                pass
            try:
                with open(log_path, "r", errors="ignore") as f:
                    if "[gdb-demo] firing int3" in f.read():
                        print(" ok", file=sys.stderr)
                        return
            except OSError:
                pass
        except OSError:
            pass
        print(".", end="", file=sys.stderr, flush=True)
        time.sleep(1)
    print(" timeout", file=sys.stderr)
    raise RuntimeError("kernel never reached the GDB demo int3")


def main() -> int:
    argv = sys.argv[1:]
    no_boot = False
    if argv and argv[0] == "--no-boot":
        no_boot = True
        argv = argv[1:]

    cmds = [" ".join(argv)] if argv else ["help", "ps"]

    proc = None
    log_path = None
    try:
        if not no_boot:
            proc, log_path = boot_qemu()
            wait_for_stop(log_path)

        with socket.create_connection((HOST, GDB_PORT), timeout=10) as sock:
            sock.sendall(b"+")  # ack any pending stop packet
            rsp_send(sock, "?")
            halt = rsp_recv(sock)
            if not (halt.startswith("S") or halt.startswith("T")):
                print(f"[mon] unexpected halt reply: {halt!r}", file=sys.stderr)

            rc = 0
            for c in cmds:
                full = c if c.startswith("duet") else "duet " + c
                print(f"==== monitor {full} ====")
                out = monitor(sock, full)
                print(out)
                if out.startswith("(error") or "not a 'duet'" in out:
                    rc = 1

            rsp_send(sock, "D")  # detach → kernel resumes from int3
            return rc
    finally:
        if not no_boot:
            try:
                _cmake_demo("OFF")
            except Exception:
                pass
        if proc is not None and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
        if log_path and os.path.exists(log_path):
            os.unlink(log_path)


if __name__ == "__main__":
    sys.exit(main())
