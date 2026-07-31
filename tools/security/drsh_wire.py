#!/usr/bin/env python3
"""Strict host-side framing for DuetOS Remote SHell (DRSH).

This module is deliberately transport-only: it validates the published DRSH
wire contract, drives one authenticated session, and has no knowledge of the
individual validation scenarios that use it.  Both host-side harnesses import
it so handshake and counter rules have one implementation.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import socket
import struct
import time
from dataclasses import dataclass
from typing import Callable, Optional, Tuple


DRSH_MAGIC = 0x44525348
DRSH_VERSION = 0x0001
DRSH_MAX_PAYLOAD = 4096
DRSH_NONCE_BYTES = 16
DRSH_CHALLENGE_BYTES = 32
DRSH_HMAC_TAG_BYTES = 16
DRSH_ENC_KEY_BYTES = 16
DRSH_MAC_KEY_BYTES = 32
DRSH_CTR_BYTES = 16
DRSH_PBKDF_ITERS = 4096
DRSH_PMK_BYTES = 32
DRSH_FRAME_HDR = 4

FRAME_HELLO_C = 1
FRAME_HELLO_S = 2
FRAME_CHALLENGE = 3
FRAME_AUTH = 4
FRAME_AUTH_OK = 5
FRAME_AUTH_FAIL = 6
FRAME_CHANNEL_OPEN = 10
FRAME_CHANNEL_ACK = 11
FRAME_CHANNEL_DENY = 12
FRAME_CHANNEL_DATA = 13
FRAME_CHANNEL_CLOSE = 14
FRAME_DISCONNECT = 20
FRAME_PING = 30
FRAME_PONG = 31

CH_CONTROL = 0
CH_SHELL = 1
CH_DESKTOP = 2
KIND_SHELL = 0
KIND_DESKTOP = 1
SHELL_PROMPT = b"drsh$ "


class DrshProtocolError(RuntimeError):
    """A peer frame failed the published DRSH wire contract."""


class DrshDisconnected(ConnectionError):
    """The peer closed the byte stream before a complete frame arrived."""


def require_crypto() -> None:
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes  # noqa: F401
    except ImportError as error:
        raise RuntimeError("DRSH authenticated transport requires: pip install cryptography") from error


def tcp_connect(host: str, port: int, timeout: float = 5.0) -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    sock.connect((host, port))
    return sock


def recv_exact(sock: socket.socket, count: int) -> bytes:
    data = bytearray()
    while len(data) < count:
        chunk = sock.recv(count - len(data))
        if not chunk:
            raise DrshDisconnected("peer closed")
        data.extend(chunk)
    return bytes(data)


def build_frame(frame_type: int, channel: int, payload: bytes, mac: Optional[bytes] = None) -> bytes:
    if not 0 <= frame_type <= 0xFF or not 0 <= channel <= 0xFF:
        raise ValueError("frame type and channel must fit in one byte")
    if len(payload) > DRSH_MAX_PAYLOAD:
        raise ValueError(f"payload exceeds DRSH maximum of {DRSH_MAX_PAYLOAD} bytes")
    header = struct.pack(">BBH", frame_type, channel, len(payload))
    if mac is None:
        mac = b"\x00" * DRSH_HMAC_TAG_BYTES
    if len(mac) != DRSH_HMAC_TAG_BYTES:
        raise ValueError("invalid DRSH MAC length")
    return header + payload + mac


def recv_frame(sock: socket.socket) -> Tuple[int, int, bytes, bytes, bytes]:
    header = recv_exact(sock, DRSH_FRAME_HDR)
    frame_type, channel, payload_len = struct.unpack(">BBH", header)
    if payload_len > DRSH_MAX_PAYLOAD:
        raise DrshProtocolError(f"peer payload length {payload_len} exceeds {DRSH_MAX_PAYLOAD}")
    payload = recv_exact(sock, payload_len) if payload_len else b""
    mac = recv_exact(sock, DRSH_HMAC_TAG_BYTES)
    return frame_type, channel, payload, mac, header


def derive_pmk(password: bytes, nonce_s: bytes) -> bytes:
    if len(nonce_s) != DRSH_NONCE_BYTES:
        raise ValueError("invalid server nonce length")
    return hashlib.pbkdf2_hmac("sha256", password, b"DRSH-PMK" + nonce_s, DRSH_PBKDF_ITERS, DRSH_PMK_BYTES)


def compute_auth_response(pmk: bytes, nonce_s: bytes, nonce_c: bytes, challenge: bytes) -> bytes:
    return hmac.new(pmk, b"DRSH-AUTH" + nonce_s + nonce_c + challenge, hashlib.sha256).digest()


def derive_session_keys(pmk: bytes, nonce_s: bytes, nonce_c: bytes) -> Tuple[bytes, bytes, bytes, bytes]:
    def kdf(tag: bytes) -> bytes:
        return hmac.new(pmk, tag + nonce_s + nonce_c, hashlib.sha256).digest()

    return (
        kdf(b"DRSH-ENC")[:DRSH_ENC_KEY_BYTES],
        kdf(b"DRSH-MAC")[:DRSH_MAC_KEY_BYTES],
        kdf(b"DRSH-IVS")[:DRSH_CTR_BYTES],
        kdf(b"DRSH-IVC")[:DRSH_CTR_BYTES],
    )


def increment_ctr(counter: bytes, blocks: int) -> bytes:
    if len(counter) != DRSH_CTR_BYTES:
        raise ValueError("invalid DRSH counter length")
    if blocks < 0:
        raise ValueError("counter increment must be non-negative")
    return ((int.from_bytes(counter, "big") + blocks) & ((1 << 128) - 1)).to_bytes(DRSH_CTR_BYTES, "big")


def aes_ctr_xor(key: bytes, counter: bytes, data: bytes) -> bytes:
    require_crypto()
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    cipher = Cipher(algorithms.AES(key), modes.CTR(counter))
    cryptor = cipher.encryptor()
    return cryptor.update(data) + cryptor.finalize()


def compute_frame_mac(mac_key: bytes, header: bytes, ciphertext: bytes) -> bytes:
    return hmac.new(mac_key, header + ciphertext, hashlib.sha256).digest()[:DRSH_HMAC_TAG_BYTES]


@dataclass
class DrshSession:
    """One authenticated DRSH connection with independent directional CTRs."""

    sock: socket.socket
    enc_key: bytes
    mac_key: bytes
    ctr_s2c: bytes
    ctr_c2s: bytes
    active_channel: Optional[int] = None
    closed: bool = False

    @classmethod
    def connect(cls, host: str, port: int, password: bytes, timeout: float = 5.0) -> "DrshSession":
        return cls.establish(tcp_connect(host, port, timeout), password)

    @classmethod
    def establish(cls, sock: socket.socket, password: bytes, nonce_c: Optional[bytes] = None) -> "DrshSession":
        require_crypto()
        nonce_c = os.urandom(DRSH_NONCE_BYTES) if nonce_c is None else nonce_c
        if len(nonce_c) != DRSH_NONCE_BYTES:
            raise ValueError("invalid client nonce length")

        hello = struct.pack(">IH", DRSH_MAGIC, DRSH_VERSION) + nonce_c
        sock.sendall(build_frame(FRAME_HELLO_C, CH_CONTROL, hello))

        frame_type, channel, payload, mac, _ = recv_frame(sock)
        if frame_type != FRAME_HELLO_S or channel != CH_CONTROL or len(payload) != 6 + DRSH_NONCE_BYTES:
            raise DrshProtocolError("invalid ServerHello frame")
        if mac != b"\x00" * DRSH_HMAC_TAG_BYTES:
            raise DrshProtocolError("pre-auth ServerHello has a nonzero MAC")
        magic, version = struct.unpack(">IH", payload[:6])
        if magic != DRSH_MAGIC or version != DRSH_VERSION:
            raise DrshProtocolError("unsupported ServerHello magic or version")
        nonce_s = payload[6:]

        frame_type, channel, challenge, mac, _ = recv_frame(sock)
        if frame_type != FRAME_CHALLENGE or channel != CH_CONTROL or len(challenge) != DRSH_CHALLENGE_BYTES:
            raise DrshProtocolError("invalid Challenge frame")
        if mac != b"\x00" * DRSH_HMAC_TAG_BYTES:
            raise DrshProtocolError("pre-auth Challenge has a nonzero MAC")

        pmk = derive_pmk(password, nonce_s)
        auth = compute_auth_response(pmk, nonce_s, nonce_c, challenge)
        sock.sendall(build_frame(FRAME_AUTH, CH_CONTROL, auth))

        enc_key, mac_key, ctr_s2c, ctr_c2s = derive_session_keys(pmk, nonce_s, nonce_c)
        frame_type, channel, ciphertext, mac, header = recv_frame(sock)
        if frame_type == FRAME_AUTH_FAIL:
            if channel != CH_CONTROL or ciphertext or mac != b"\x00" * DRSH_HMAC_TAG_BYTES:
                raise DrshProtocolError("invalid AUTH_FAIL frame")
            raise DrshProtocolError("server rejected credentials")
        expected_mac = compute_frame_mac(mac_key, header, ciphertext)
        if not hmac.compare_digest(mac, expected_mac):
            raise DrshProtocolError("authenticated AUTH_OK frame failed MAC validation")
        if frame_type != FRAME_AUTH_OK or channel != CH_CONTROL or ciphertext:
            raise DrshProtocolError("invalid authenticated AUTH_OK frame")
        return cls(sock, enc_key, mac_key, ctr_s2c, ctr_c2s)

    def _ensure_open(self) -> None:
        if self.closed:
            raise DrshDisconnected("DRSH session is closed")

    def send_authenticated(self, frame_type: int, channel: int, plaintext: bytes) -> None:
        self._ensure_open()
        if len(plaintext) > DRSH_MAX_PAYLOAD:
            raise ValueError(f"payload exceeds DRSH maximum of {DRSH_MAX_PAYLOAD} bytes")
        header = struct.pack(">BBH", frame_type, channel, len(plaintext))
        ciphertext = aes_ctr_xor(self.enc_key, self.ctr_c2s, plaintext) if plaintext else b""
        mac = compute_frame_mac(self.mac_key, header, ciphertext)
        self.sock.sendall(header + ciphertext + mac)
        self.ctr_c2s = increment_ctr(self.ctr_c2s, (len(plaintext) + 15) // 16)

    def recv_authenticated(self) -> Tuple[int, int, bytes]:
        self._ensure_open()
        frame_type, channel, ciphertext, mac, header = recv_frame(self.sock)
        expected_mac = compute_frame_mac(self.mac_key, header, ciphertext)
        if not hmac.compare_digest(mac, expected_mac):
            self.closed = True
            try:
                self.sock.close()
            finally:
                raise DrshProtocolError("post-auth DRSH frame failed MAC validation")
        plaintext = aes_ctr_xor(self.enc_key, self.ctr_s2c, ciphertext) if ciphertext else b""
        self.ctr_s2c = increment_ctr(self.ctr_s2c, (len(ciphertext) + 15) // 16)
        return frame_type, channel, plaintext

    def expect_authenticated(self, expected_type: int, expected_channel: int) -> bytes:
        frame_type, channel, plaintext = self.recv_authenticated()
        if frame_type != expected_type or channel != expected_channel:
            raise DrshProtocolError(
                f"unexpected post-auth frame type={frame_type} channel={channel}; "
                f"expected type={expected_type} channel={expected_channel}"
            )
        return plaintext

    def open_shell(self) -> None:
        if self.active_channel is not None:
            raise DrshProtocolError("a DRSH channel is already active")
        self.send_authenticated(FRAME_CHANNEL_OPEN, CH_CONTROL, bytes([KIND_SHELL]))
        channel_id = self.expect_authenticated(FRAME_CHANNEL_ACK, CH_CONTROL)
        if channel_id != bytes([CH_SHELL]):
            raise DrshProtocolError("invalid shell channel ACK payload")
        greeting = self.expect_authenticated(FRAME_CHANNEL_DATA, CH_SHELL)
        if greeting != SHELL_PROMPT:
            raise DrshProtocolError("shell channel did not begin with the DRSH prompt")
        self.active_channel = CH_SHELL

    def run_shell_command(self, command: str, timeout: float = 3.0) -> str:
        if self.active_channel != CH_SHELL:
            raise DrshProtocolError("shell channel is not open")
        self.send_authenticated(FRAME_CHANNEL_DATA, CH_SHELL, (command + "\n").encode("utf-8"))
        old_timeout = self.sock.gettimeout()
        self.sock.settimeout(timeout)
        try:
            output = []
            while True:
                frame_type, channel, plaintext = self.recv_authenticated()
                if frame_type == FRAME_DISCONNECT:
                    self.closed = True
                    raise DrshDisconnected("server disconnected during shell command")
                if frame_type != FRAME_CHANNEL_DATA or channel != CH_SHELL:
                    raise DrshProtocolError("unexpected frame while waiting for shell response")
                if plaintext == SHELL_PROMPT:
                    return b"".join(output).decode("utf-8", errors="replace")
                output.append(plaintext)
        finally:
            if not self.closed:
                self.sock.settimeout(old_timeout)

    def close(self) -> None:
        if self.closed:
            return
        try:
            if self.active_channel is not None:
                self.send_authenticated(FRAME_CHANNEL_CLOSE, self.active_channel, b"")
        except (OSError, DrshProtocolError):
            pass
        finally:
            self.closed = True
            self.sock.close()


def wait_for_clean_close(session: DrshSession, timeout: float = 2.0) -> bool:
    """Return true only for an authenticated orderly disconnect or EOF."""
    old_timeout = session.sock.gettimeout()
    session.sock.settimeout(timeout)
    try:
        frame_type, channel, plaintext = session.recv_authenticated()
        if frame_type == FRAME_DISCONNECT and channel == CH_CONTROL and not plaintext:
            session.closed = True
            return True
        return False
    except (DrshDisconnected, socket.timeout):
        session.closed = True
        return True
    finally:
        if not session.closed:
            session.sock.settimeout(old_timeout)
