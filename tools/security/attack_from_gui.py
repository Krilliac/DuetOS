#!/usr/bin/env python3
"""
attack_from_gui.py — Red-team harness.

Boots DuetOS headlessly in QEMU, drives the GUI login screen, logs in
as a user, and then runs a battery of attack probes through the shell
that the keyboard reader forwards to. Every probe is designed to answer
ONE question: "what happens if an interactive user with this role does
THIS thing?" Evidence is collected as:

  1. The kernel serial transcript (klog + shell input echo + selected
     stdout emitters like reboot/halt/shutdown).
  2. Framebuffer screenshots taken at key moments.

Orchestration uses the QEMU HMP monitor on a Unix socket. Keystrokes go
through the monitor's `sendkey` verb, which targets the PS/2 keyboard
emulated by q35.

Usage:
    tools/security/attack_from_gui.py [admin|guest] [--preset NAME]

The role selects which seed account to log in as (both ship in the
kernel image — admin/admin and guest with empty password). Output goes
to build/<preset>/security/attack-from-gui/.
"""

import argparse
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent


def log(msg: str) -> None:
    print(f"[harness] {msg}", flush=True)


def monitor_connect(path: Path, attempts: int = 50) -> socket.socket:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    for _ in range(attempts):
        try:
            s.connect(str(path))
            return s
        except (FileNotFoundError, ConnectionRefusedError):
            time.sleep(0.2)
    raise RuntimeError(f"monitor socket never appeared: {path}")


def send(sock: socket.socket, cmd: str, delay: float = 0.12) -> None:
    sock.sendall((cmd + "\n").encode())
    time.sleep(delay)


# PS/2 key-name map for `sendkey`. QEMU accepts a "-" separated chord,
# one keyname per physical key. We only need printable ASCII + Enter +
# Tab + Backspace for the login gate and the shell.
QEMU_KEY_MAP = {
    " ": "spc",
    "-": "minus",
    "=": "equal",
    "/": "slash",
    "\\": "backslash",
    ".": "dot",
    ",": "comma",
    ";": "semicolon",
    "'": "apostrophe",
    "`": "grave_accent",
    "[": "bracket_left",
    "]": "bracket_right",
    "\n": "ret",
    "\t": "tab",
}


def sendkey_for_char(sock: socket.socket, ch: str) -> None:
    if ch in QEMU_KEY_MAP:
        send(sock, f"sendkey {QEMU_KEY_MAP[ch]}")
        return
    if ch.isdigit() or (ch.isalpha() and ch.islower()):
        send(sock, f"sendkey {ch}")
        return
    if ch.isalpha() and ch.isupper():
        send(sock, f"sendkey shift-{ch.lower()}")
        return
    # Punctuation that needs shift on a US layout — translate one at a
    # time. Keep this list conservative; anything missing here would
    # show up as "[harness] unmapped key 'X'" so we notice.
    shifted = {
        "!": "1", "@": "2", "#": "3", "$": "4", "%": "5",
        "^": "6", "&": "7", "*": "8", "(": "9", ")": "0",
        "_": "minus", "+": "equal", "{": "bracket_left",
        "}": "bracket_right", ":": "semicolon", '"': "apostrophe",
        "<": "comma", ">": "dot", "?": "slash", "|": "backslash",
        "~": "grave_accent",
    }
    if ch in shifted:
        send(sock, f"sendkey shift-{shifted[ch]}")
        return
    print(f"[harness] unmapped key '{ch}' (ord={ord(ch)})", flush=True)


def type_string(sock: socket.socket, text: str, per_char_pause: float = 0.04) -> None:
    for ch in text:
        sendkey_for_char(sock, ch)
        time.sleep(per_char_pause)


def type_line(sock: socket.socket, text: str) -> None:
    type_string(sock, text)
    send(sock, "sendkey ret", delay=0.25)


def screendump(sock: socket.socket, dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    send(sock, f"screendump {dest}", delay=0.8)


def wait_for_serial_line(serial_log: Path, marker: str, timeout: float) -> bool:
    # Serial log carries ANSI colour escapes + CRLF/CR/LF mixed line
    # terminators (the klog colouriser emits CR+LF inside a single
    # logical line; the shell echo emits raw LF). Work in bytes,
    # strip ANSI, look for the marker anywhere.
    import re
    ansi = re.compile(rb"\x1b\[[0-9;]*[A-Za-z]")
    deadline = time.time() + timeout
    needle = marker.encode()
    while time.time() < deadline:
        if serial_log.is_file():
            try:
                blob = serial_log.read_bytes()
            except OSError:
                blob = b""
            if needle in ansi.sub(b"", blob):
                return True
        time.sleep(0.5)
    return False


def launch_qemu(preset: str, workdir: Path) -> subprocess.Popen:
    build_dir = REPO_ROOT / "build" / preset
    iso = build_dir / "duetos.iso"
    if not iso.is_file():
        raise SystemExit(f"ISO not built: {iso}")
    serial_log = workdir / "serial.log"
    monitor_sock = workdir / "monitor.sock"
    nvme_img = workdir / "nvme0.img"
    sata_img = workdir / "sata0.img"
    for p in (serial_log, monitor_sock, nvme_img, sata_img):
        if p.exists():
            p.unlink()
    subprocess.check_call(
        ["python3", str(REPO_ROOT / "tools/qemu/make-gpt-image.py"), str(nvme_img)]
    )
    subprocess.check_call(
        ["python3", str(REPO_ROOT / "tools/qemu/make-gpt-image.py"), str(sata_img)]
    )
    ovmf_code = "/usr/share/OVMF/OVMF_CODE_4M.fd"
    ovmf_vars_template = "/usr/share/OVMF/OVMF_VARS_4M.fd"
    ovmf_vars_copy = workdir / "ovmf-vars.fd"
    subprocess.check_call(["cp", ovmf_vars_template, str(ovmf_vars_copy)])
    cmd = [
        "qemu-system-x86_64",
        "-machine", "q35",
        "-cpu", "max",
        "-m", "512M",
        # Use VNC (loopback only, no actual connection) rather than
        # "-display none". QEMU's `sendkey` HMP verb routes through
        # the console input fabric which is only bound when a display
        # backend is present; with "-display none" the keypresses are
        # silently dropped. VNC :99 on 127.0.0.1 never gets a real
        # viewer — we just need QEMU to think it has a UI.
        "-display", "vnc=127.0.0.1:99",
        "-serial", f"file:{serial_log}",
        "-monitor", f"unix:{monitor_sock},server,nowait",
        "-no-reboot", "-no-shutdown",
        "-drive", f"file={nvme_img},if=none,id=nvme0,format=raw",
        "-device", "nvme,serial=cafebabe,drive=nvme0",
        "-device", "ahci,id=ahci1",
        "-drive", f"file={sata_img},if=none,id=sata0,format=raw",
        "-device", "ide-hd,bus=ahci1.0,drive=sata0",
        "-device", "qemu-xhci,id=xhci",
        "-device", "usb-kbd,bus=xhci.0",
        "-device", "usb-mouse,bus=xhci.0",
        "-netdev", "user,id=net0",
        "-device", "e1000e,netdev=net0,mac=52:54:00:12:34:56",
        "-drive", f"if=pflash,format=raw,readonly=on,file={ovmf_code}",
        "-drive", f"if=pflash,format=raw,file={ovmf_vars_copy}",
        "-cdrom", str(iso),
        "-boot", "d",
    ]
    return subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def serial_tail(serial_log: Path, n: int = 4096) -> str:
    if not serial_log.is_file():
        return ""
    text = serial_log.read_text(errors="ignore")
    return text[-n:]


def pentest_run(role: str, password: str, preset: str) -> int:
    workdir = REPO_ROOT / "build" / preset / "security" / f"attack-from-gui-{role}"
    workdir.mkdir(parents=True, exist_ok=True)
    serial_log = workdir / "serial.log"
    monitor_sock = workdir / "monitor.sock"

    log(f"launching QEMU (role={role})")
    qemu = launch_qemu(preset, workdir)
    try:
        log("waiting for login gate marker on serial")
        if not wait_for_serial_line(serial_log, "login : gate up", timeout=180):
            log("login gate never armed; dumping tail:")
            sys.stdout.write(serial_tail(serial_log, 2000))
            return 1
        # Settle so the GUI has painted the login panel.
        time.sleep(3.0)

        mon = monitor_connect(monitor_sock)
        try:
            screendump(mon, workdir / "01-login.ppm")

            # --- Attack 0: brute-force bait — wrong credentials first ---
            log("probe 00: wrong-password attempt")
            type_string(mon, role)
            send(mon, "sendkey tab")
            type_string(mon, "definitely-wrong")
            send(mon, "sendkey ret", delay=0.8)
            time.sleep(1.0)
            screendump(mon, workdir / "02-login-failed.ppm")

            # --- Log in cleanly ---
            log(f"probe 01: login as {role}")
            # Login UI: after a failed attempt the username field is
            # refocused (blank) and the status message says 'LOGIN
            # FAILED'. Re-type the credentials.
            type_string(mon, role)
            send(mon, "sendkey tab")
            type_string(mon, password)
            send(mon, "sendkey ret", delay=1.0)
            if not wait_for_serial_line(serial_log, "session opened", timeout=25):
                log("login never succeeded; dumping tail:")
                sys.stdout.write(serial_tail(serial_log, 2000))
                return 2
            time.sleep(2.0)
            screendump(mon, workdir / "03-desktop.ppm")

            # --- Attack probes as a plain shell user ---
            probes = [
                # (label, line, settle_seconds)
                ("whoami",    "whoami",                  0.5),
                ("users",     "users",                   0.5),
                # Privilege-enforcement probes: these should be denied
                # for a non-admin. For admin they succeed.
                ("useradd",   "useradd mallory pwn admin", 0.5),
                ("userdel",   "userdel admin",           0.5),
                ("passwd-force", "passwd admin owned --force", 0.5),
                # Unprivileged-but-scary commands: should they be open
                # to any logged-in user? We record the answer.
                ("msr-efer",  "msr c0000080",            0.5),
                ("guard",     "guard status",            0.5),
                ("memdump-kernel", "memdump ffffffff80000000 64", 0.5),
                ("heap",      "heap",                    0.5),
                ("paging",    "paging",                  0.5),
                ("lspci",     "lspci",                   0.5),
                ("breakpoints", "bp list",               0.5),
                ("linuxexec-noent", "linuxexec /nope",   0.5),
                # Input-handling / parser probes.
                ("pipe-bomb", "echo a|echo b|echo c|echo d", 0.5),
                ("long-line", "echo " + ("A" * 200),     0.5),
                ("hist-bad",  "!9999",                   0.5),
                # The crown jewel: can a non-admin halt the box?
                # (We run this LAST so the session can continue up
                # until this point.)
                ("halt",      "halt",                    2.0),
            ]
            for label, line, settle in probes:
                log(f"probe: {label}  <<< {line!r}")
                type_line(mon, line)
                time.sleep(settle)
                screendump(mon, workdir / f"probe-{label}.ppm")
                # If the kernel halted, bail — no more input will take.
                if "user invoked halt" in serial_tail(serial_log, 4000):
                    log("kernel acknowledged halt; stopping further probes")
                    break

            # Final transcript snapshot.
            (workdir / "serial.snapshot.txt").write_text(
                serial_log.read_text(errors="ignore")
            )
            log(f"artefacts in {workdir}")
            return 0
        finally:
            try:
                send(mon, "quit", delay=0.2)
            except OSError:
                pass
            mon.close()
    finally:
        qemu.terminate()
        try:
            qemu.wait(timeout=5)
        except subprocess.TimeoutExpired:
            qemu.kill()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("role", nargs="?", default="admin",
                    choices=("admin", "guest"))
    ap.add_argument("--preset", default="x86_64-debug")
    args = ap.parse_args()
    password = "admin" if args.role == "admin" else ""
    return pentest_run(args.role, password, args.preset)


if __name__ == "__main__":
    sys.exit(main())
