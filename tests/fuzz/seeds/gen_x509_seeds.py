#!/usr/bin/env python3
# DuetOS X.509 certificate fuzz seed generator.
#
# WHAT  Emits real DER-encoded X.509 v3 RSA certificates so
#       fuzz_x509 walks the full TBSCertificate / SPKI /
#       signature structure on cycle 1 instead of bouncing off
#       the outer SEQUENCE-of-three-INTEGERS gate. Uses openssl
#       as a subprocess to generate a self-signed cert (build-
#       time dep, available on every reasonable dev host); falls
#       back to an embedded reference cert if openssl is
#       unavailable, so a sandboxed `python3 gen_x509_seeds.py`
#       still produces a working corpus.
#
# WHY   The roadmap "Fuzz harness — next parser targets" list
#       called out X.509 specifically. The fuzz_x509 harness has
#       been in tree since the ASN.1 + X.509 slice, but without
#       seeds it could only exercise the outermost asn1::Read of
#       a SEQUENCE; the TBS walker, the SPKI RSA-public-key
#       split, and the signature-bitstring decoder were
#       unreached. A real cert seed unlocks every parse path.
#
# USAGE  python3 gen_x509_seeds.py <out_dir>

import base64
import os
import shutil
import subprocess
import sys
import tempfile


# Embedded reference cert — used when openssl is unavailable.
# A real self-signed RSA-2048 cert with CN=DuetOS-Fuzz-Root,
# valid 2026 to 2135. Pre-generated 2026-05-26 via
# `openssl req -x509 -newkey rsa:2048 -days 40000 -nodes
#  -subj '/CN=DuetOS-Fuzz-Root' | openssl x509 -outform DER
#  | base64`. Stored as base64 so the file stays text-grep-
# friendly and survives a `tr -d '\r'` round-trip on Windows
# checkouts. Validated with `openssl x509 -inform DER`.
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


def openssl_cert() -> bytes:
    """Generate a fresh self-signed RSA-2048 cert via openssl."""
    if shutil.which("openssl") is None:
        return b""
    with tempfile.TemporaryDirectory() as td:
        key_pem = os.path.join(td, "k.pem")
        cert_pem = os.path.join(td, "c.pem")
        try:
            subprocess.run([
                "openssl", "req", "-x509",
                "-newkey", "rsa:2048",
                "-days", "40000",
                "-nodes",
                "-subj", "/CN=DuetOS-Fuzz-Seed",
                "-keyout", key_pem,
                "-out", cert_pem,
            ], check=True, capture_output=True)
        except subprocess.CalledProcessError:
            return b""
        # PEM -> DER.
        try:
            r = subprocess.run([
                "openssl", "x509",
                "-in", cert_pem,
                "-outform", "DER",
            ], check=True, capture_output=True)
            return r.stdout
        except subprocess.CalledProcessError:
            return b""


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "corpus/x509"
    os.makedirs(out, exist_ok=True)

    # Primary seed: a freshly-generated self-signed RSA cert via
    # openssl, when available. This walks every parser path with
    # a real RSA-2048 SPKI and a real PKCS#1v1.5 signature bit
    # string.
    fresh = openssl_cert()
    if fresh:
        open(os.path.join(out, "self_signed_rsa.der"), "wb").write(fresh)

    # Fallback / belt-and-braces seed: the embedded reference
    # cert. Always present in the corpus regardless of host
    # toolchain. Catches a regression where the openssl path
    # silently drops to empty (broken openssl install, sandbox
    # blocking subprocess) without losing fuzz coverage.
    embedded = base64.b64decode(EMBEDDED_CERT_B64)
    open(os.path.join(out, "reference.der"), "wb").write(embedded)

    # Truncated reference cert (first 128 bytes) — exercises the
    # parser's short-input path. asn1::Read should bail cleanly
    # without OOB-reading past the buffer.
    open(os.path.join(out, "truncated_128.der"), "wb").write(embedded[:128])

    print(f"seeded {out}: {len(os.listdir(out))} files")


if __name__ == "__main__":
    main()
