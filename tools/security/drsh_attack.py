#!/usr/bin/env python3
"""Non-destructive DRSH wire attack smoke suite.

The suite validates hostile framing and pre-auth starvation behavior without
running guest shell commands other than a tiny liveness canary for post-test
health checks.
Disruptive OS-command probes live in drsh_os_attack.py and require an explicit
destructive opt-in there.
"""

from __future__ import annotations

import argparse
import os
import socket
import struct
import sys
import time

from drsh_wire import (
    CH_CONTROL,
    DRSH_HMAC_TAG_BYTES,
    DRSH_MAGIC,
    DRSH_NONCE_BYTES,
    DRSH_VERSION,
    FRAME_AUTH,
    FRAME_AUTH_FAIL,
    FRAME_DISCONNECT,
    FRAME_HELLO_C,
    FRAME_PING,
    FRAME_PONG,
    DrshDisconnected,
    DrshProtocolError,
    DrshSession,
    build_frame,
    compute_auth_response,
    derive_pmk,
    recv_frame,
    tcp_connect,
    wait_for_clean_close,
)

SETTLE_SECONDS = 0.1
SLOWLORIS_RETRY_TIMEOUT = 20.0


def record(results: list[tuple[str, bool, str]], name: str, ok: bool, detail: str = "") -> None:
    print(f"{'PASS' if ok else 'FAIL'} {name} {detail}".strip(), flush=True)
    results.append((name, ok, detail))


def connect_session(host: str, port: int, password: bytes, timeout: float) -> DrshSession:
    last_error: BaseException | None = None
    for _attempt in range(3):
        try:
            return DrshSession.connect(host, port, password, timeout=timeout)
        except DrshProtocolError:
            raise
        except (DrshDisconnected, OSError) as error:
            last_error = error
            time.sleep(SETTLE_SECONDS)
    assert last_error is not None
    raise last_error


def health(results: list[tuple[str, bool, str]], name: str, host: str, port: int, password: bytes) -> None:
    session: DrshSession | None = None
    output = ""
    try:
        session = connect_session(host, port, password, timeout=5.0)
        session.open_shell()
        # Keep the post-attack liveness canary intentionally small. `help`
        # can produce enough output on a slow TCG guest to consume the whole
        # timeout window and strand DRSH v0's single authenticated session.
        output = session.run_shell_command("id", timeout=10.0)
    finally:
        if session is not None:
            session.close()
    time.sleep(SETTLE_SECONDS)
    record(results, name, len(output.strip()) > 0, f"bytes={len(output)}")


def malformed_hello(results: list[tuple[str, bool, str]], host: str, port: int, password: bytes) -> None:
    sock = tcp_connect(host, port, timeout=2.0)
    sock.sendall(build_frame(FRAME_HELLO_C, CH_CONTROL, b"bad"))
    sock.settimeout(2.5)
    try:
        frame_type, _channel, _payload, _mac, _header = recv_frame(sock)
        ok = frame_type in (FRAME_AUTH_FAIL, FRAME_DISCONNECT)
        detail = f"frame={frame_type}"
    except (socket.timeout, ConnectionResetError, DrshDisconnected, DrshProtocolError, OSError) as error:
        ok = True
        detail = type(error).__name__
    finally:
        sock.close()
        time.sleep(SETTLE_SECONDS)
    record(results, "malformed_hello_refused", ok, detail)
    health(results, "health_after_malformed", host, port, password)


def replay_auth(results: list[tuple[str, bool, str]], host: str, port: int, password: bytes) -> None:
    nonce_c = os.urandom(DRSH_NONCE_BYTES)
    first = tcp_connect(host, port, timeout=2.0)
    first.sendall(build_frame(FRAME_HELLO_C, CH_CONTROL, struct.pack(">IH", DRSH_MAGIC, DRSH_VERSION) + nonce_c))
    _type, _channel, payload, _mac, _header = recv_frame(first)
    nonce_s = payload[6:]
    _type, _channel, challenge, _mac, _header = recv_frame(first)
    pmk = derive_pmk(password, nonce_s)
    auth = compute_auth_response(pmk, nonce_s, nonce_c, challenge)
    first.close()
    time.sleep(SETTLE_SECONDS)

    second = tcp_connect(host, port, timeout=2.0)
    second.sendall(build_frame(FRAME_HELLO_C, CH_CONTROL, struct.pack(">IH", DRSH_MAGIC, DRSH_VERSION) + nonce_c))
    _type, _channel, _payload, _mac, _header = recv_frame(second)
    _type, _channel, challenge2, _mac, _header = recv_frame(second)
    second.sendall(build_frame(FRAME_AUTH, CH_CONTROL, auth))
    frame_type, _channel, _payload, _mac, _header = recv_frame(second)
    second.close()
    time.sleep(SETTLE_SECONDS)
    record(results, "replay_auth_rejected", frame_type == FRAME_AUTH_FAIL and challenge2 != challenge)
    health(results, "health_after_replay", host, port, password)


def bad_mac(results: list[tuple[str, bool, str]], host: str, port: int, password: bytes) -> None:
    session = connect_session(host, port, password, timeout=2.0)
    session.sock.sendall(struct.pack(">BBH", FRAME_PING, CH_CONTROL, 0) + (b"X" * DRSH_HMAC_TAG_BYTES))
    session.sock.settimeout(2.0)
    ok = True
    try:
        data = session.sock.recv(64)
        ok = not data or data[0] != FRAME_PONG
        detail = f"bytes={len(data)}"
    except (socket.timeout, ConnectionResetError, OSError) as error:
        ok = not isinstance(error, socket.timeout)
        detail = type(error).__name__
    finally:
        session.sock.close()
        time.sleep(SETTLE_SECONDS)
    record(results, "bad_mac_session_refused", ok, detail)
    health(results, "health_after_bad_mac", host, port, password)


def unknown_frame(results: list[tuple[str, bool, str]], host: str, port: int, password: bytes) -> None:
    session = connect_session(host, port, password, timeout=2.0)
    session.send_authenticated(99, CH_CONTROL, b"")
    ok = wait_for_clean_close(session, timeout=2.0)
    session.sock.close()
    time.sleep(SETTLE_SECONDS)
    record(results, "unknown_frame_disconnects", ok)
    health(results, "health_after_unknown_frame", host, port, password)


def slowloris(results: list[tuple[str, bool, str]], host: str, port: int, password: bytes) -> None:
    holder = tcp_connect(host, port, timeout=2.0)
    try:
        start = time.time()
        try:
            # The guest-side pre-auth timeout is intentionally short in
            # scheduler ticks, but under TCG a handful of guest ticks can be
            # several wall-clock seconds while the serial log is busy. Give the
            # security property enough host time to show up: the silent holder
            # must age out and a real admin handshake must then complete.
            probe = DrshSession.connect(host, port, password, timeout=SLOWLORIS_RETRY_TIMEOUT)
            probe.close()
            record(results, "slowloris_parallel_auth_after_timeout", True, f"latency={time.time() - start:.2f}s")
        except Exception as error:
            record(
                results,
                "slowloris_parallel_auth_after_timeout",
                False,
                f"{type(error).__name__} latency={time.time() - start:.2f}s",
            )
    finally:
        holder.close()
        time.sleep(SETTLE_SECONDS)
    health(results, "health_after_slowloris_release", host, port, password)


def main() -> int:
    parser = argparse.ArgumentParser(description="Non-destructive DRSH wire attack smoke suite")
    parser.add_argument("--host", default=os.environ.get("DRSH_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("DRSH_PORT", "4322")))
    parser.add_argument("--password", default=os.environ.get("DRSH_PASSWORD", "test"))
    args = parser.parse_args()

    password = args.password.encode("utf-8")
    results: list[tuple[str, bool, str]] = []
    health(results, "baseline_auth_shell", args.host, args.port, password)
    malformed_hello(results, args.host, args.port, password)
    replay_auth(results, args.host, args.port, password)
    bad_mac(results, args.host, args.port, password)
    unknown_frame(results, args.host, args.port, password)
    slowloris(results, args.host, args.port, password)

    failed = [result for result in results if not result[1]]
    print(f"SUMMARY passed={len(results) - len(failed)} failed={len(failed)}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
