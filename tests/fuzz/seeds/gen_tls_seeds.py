#!/usr/bin/env python3
# DuetOS TLS 1.2 record/handshake fuzz seed generator.
#
# WHAT  Emits valid TLS 1.2 byte streams covering each of the
#       five parser entry points fuzz_tls dispatches to. Each
#       seed prepends a one-byte selector picking the parser to
#       exercise, then a real protocol message:
#         sel=0  -> TlsPeekRecord       (5-byte record header
#                                         + an Application-Data body)
#         sel=1  -> TlsPeekHandshake    (4-byte handshake header
#                                         + a ClientHello body)
#         sel=2  -> TlsParseServerHello (server-random + cipher
#                                         + extensions list)
#         sel=3  -> TlsParseCertificateLeaf (3-byte total length
#                                         + per-cert 3-byte length
#                                         + a real DER cert)
#         sel=4  -> TlsParseServerHelloDone (0-byte body)
#         sel=7  -> chain: peek-record + peek-handshake on the
#                                         same buffer (default arm)
#
# WHY   TLS records are length-prefix-stacked four levels deep
#       (record -> handshake -> Certificate-list -> per-cert);
#       random mutation cannot bootstrap a coherent 4-level
#       length chain. Seeds get all five parsers into the
#       inner loops on cycle 1.
#
# USAGE  python3 gen_tls_seeds.py <out_dir>

import base64
import os
import sys


# Same RSA-2048 self-signed cert used by gen_x509_seeds.py.
# Kept inline here so this generator is self-contained; if both
# scripts run in the same build, they share content but a
# regression in one doesn't silently propagate to the other.
EMBEDDED_CERT_B64 = (
    "MIIDGTCCAgGgAwIBAgIUDbkaUsIgx9IAak7L8jDEEhw24nowDQYJKoZIhvcNAQEL"
    "BQAwGzEZMBcGA1UEAwwQRHVldE9TLUZ1enotUm9vdDAgFw0yNjA1MjYyMjE4MTla"
    "GA8yMTM1MTIwMTIyMTgxOVowGzEZMBcGA1UEAwwQRHVldE9TLUZ1enotUm9vdDCC"
    "ASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL+PTV1rYFAR6tXau6WWIhEe"
    "+oEMJ8Jbr/7aa2DMhkzZd30LDgVNbr49x0bbCbyY5qHwqALZBVqls2ACCb1gpKVP"
    "ywCxynz4CLUGvAaXwNCnO2mMY4NwY4ZlOixfeRuj/08HqgrAYNDOrStDPs0EolK1"
    "OlRfCvEgeL3Y9gsmhilombOmRAYgd6LBnJVNp7ltS60ZC6lxoy3Hki2EguL0yQxg"
    "csoRYCepQrsFc5vlA/v78vsD+LLD8kIqJKRMWAW30RMoTbm5t0WF+ktruQGRLhaw"
    "JQsMwh4v8564zIbQbqgwQ8T+SsIFXJUDkqE12Ktn42Hz+UXOjs6g7jckClvONacC"
    "AwEAAaNTMFEwHQYDVR0OBBYEFIBJB/oSl8/t54NF6ma9EhNc1SVCMB8GA1UdIwQY"
    "MBaAFIBJB/oSl8/t54NF6ma9EhNc1SVCMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZI"
    "hvcNAQELBQADggEBAHb3Vol0I4u+ovIwyhK7HdlSMgjYTd270SLxfnhmQgAjvqke"
    "fI7LT7Izp2ePGZ2qLxeXl+38FJ4tcp5fKLnJhayACxDRY4ofTdcTLRZGm1AYFkaS"
    "uQMc40J1jWU/jz4tBEZj00Wl6+HtIGImuaAVcD6hePWK4RTJwN7rgBKikD1NUijN"
    "UR0aHq4jAgZfexWFgcEkvACUdp8PQ3la2Km/R/UxquSIiEokU4Ze0Oa7of7K9xJ1"
    "tmIhJYF8ZmVQ9Thp60lp9iyQMtQZM4i8k6L07MV+JbilJkvqvwcruLTevrWWQu3i"
    "LBkld0ajPvddqJjtgHDHE9K53MEVM4bZQGrkajY="
)


def record(content_type: int, payload: bytes) -> bytes:
    # 5-byte record header: type + version(2) + length(2 BE).
    return bytes([content_type, 0x03, 0x03,
                  (len(payload) >> 8) & 0xFF, len(payload) & 0xFF]) + payload


def handshake(hs_type: int, body: bytes) -> bytes:
    # 4-byte handshake header: type + length(3 BE).
    return bytes([hs_type,
                  (len(body) >> 16) & 0xFF,
                  (len(body) >> 8) & 0xFF,
                  len(body) & 0xFF]) + body


def client_hello_body() -> bytes:
    # Minimal ClientHello: version + 32-byte random + session_id
    # length(0) + cipher_suites length(2) + 1 suite + compression
    # length(1) + null compression. No extensions.
    body = bytes([0x03, 0x03])                # client_version TLS 1.2
    body += bytes(range(32))                   # 32-byte client_random
    body += bytes([0x00])                      # session_id length = 0
    body += bytes([0x00, 0x02])                # cipher_suites length
    body += bytes([0x00, 0x9C])                # TLS_RSA_WITH_AES_128_GCM_SHA256
    body += bytes([0x01, 0x00])                # compression: length=1, null
    return body


def server_hello_body() -> bytes:
    body = bytes([0x03, 0x03])
    body += bytes(range(32))                   # server_random (use 0..31)
    body += bytes([0x00])                      # session_id length = 0
    body += bytes([0x00, 0x9C])                # selected cipher
    body += bytes([0x00])                      # compression: null
    return body


def certificate_message_body() -> bytes:
    cert = base64.b64decode(EMBEDDED_CERT_B64)
    # Per-cert wrapper: 3-byte length + cert.
    one = bytes([(len(cert) >> 16) & 0xFF,
                 (len(cert) >> 8) & 0xFF,
                 len(cert) & 0xFF]) + cert
    # Outer wrapper: 3-byte total length of the cert list.
    return bytes([(len(one) >> 16) & 0xFF,
                  (len(one) >> 8) & 0xFF,
                  len(one) & 0xFF]) + one


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "corpus/tls"
    os.makedirs(out, exist_ok=True)

    # sel=0 -> TlsPeekRecord on an Application-Data record.
    open(os.path.join(out, "peek_record.bin"), "wb").write(
        bytes([0x00]) + record(23, b"hello-from-fuzz"))

    # sel=1 -> TlsPeekHandshake on a ClientHello body.
    open(os.path.join(out, "peek_handshake.bin"), "wb").write(
        bytes([0x01]) + handshake(1, client_hello_body()))

    # sel=2 -> TlsParseServerHello body.
    open(os.path.join(out, "server_hello.bin"), "wb").write(
        bytes([0x02]) + server_hello_body())

    # sel=3 -> TlsParseCertificateLeaf body (3-byte total + per-cert + DER).
    open(os.path.join(out, "certificate.bin"), "wb").write(
        bytes([0x03]) + certificate_message_body())

    # sel=4 -> TlsParseServerHelloDone body (must be 0 bytes).
    open(os.path.join(out, "server_hello_done.bin"), "wb").write(
        bytes([0x04]))  # selector only, no body

    # sel=7 -> chain (record-then-handshake) on the same buffer.
    chain = record(22, handshake(1, client_hello_body()))
    open(os.path.join(out, "chain_record_handshake.bin"), "wb").write(
        bytes([0x07]) + chain)

    print(f"seeded {out}: {len(os.listdir(out))} files")


if __name__ == "__main__":
    main()
