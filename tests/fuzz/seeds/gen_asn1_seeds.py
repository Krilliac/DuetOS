#!/usr/bin/env python3
# DuetOS ASN.1 / DER fuzz seed generator.
#
# WHAT  Emits hand-built DER (Distinguished Encoding Rules) byte
#       streams covering the four structural variants the asn1
#       reader (kernel/crypto/asn1.cpp) must walk:
#         - short-form length INTEGER (tag 0x02, len < 128),
#         - long-form length OCTET STRING (tag 0x04, len in
#           the 128..255 range that needs the 0x81 length prefix),
#         - SEQUENCE of two INTEGERs (constructed; exercises
#           ForEachInSequence + child-overruns-parent gate),
#         - SEQUENCE containing an OID (RSA-encryption — the
#           x509-side OidEquals path),
#         - nested SEQUENCE (depth-2 walker) — the deepest
#           legal path the fuzz_asn1 harness recurses into.
#
# WHY   ASN.1 is the second-richest parser fuzz surface per the
#       roadmap. Without seeds the fuzzer wastes most of its
#       budget guessing valid DER tag/length encodings. A handful
#       of valid TLVs lets the inverse work — start from a real
#       parse and mutate around it — so the tag/length walker,
#       the long-form length decode, the child-overrun guard,
#       and the OID/INTEGER helpers all see real coverage.
#
# USAGE  python3 gen_asn1_seeds.py <out_dir>

import os
import sys


# DER tag bytes.
TAG_INTEGER = 0x02
TAG_OCTET_STRING = 0x04
TAG_NULL = 0x05
TAG_OID = 0x06
TAG_SEQUENCE = 0x30  # constructed | SEQUENCE


def der_length(n: int) -> bytes:
    """DER length encoding (short form < 128, long form otherwise)."""
    if n < 0x80:
        return bytes([n])
    body = []
    while n:
        body.insert(0, n & 0xFF)
        n >>= 8
    return bytes([0x80 | len(body)]) + bytes(body)


def tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + der_length(len(value)) + value


def integer(n: int) -> bytes:
    # DER INTEGER: big-endian, with a leading 0x00 if the top bit
    # of the first content byte is set (so it's not interpreted
    # as a negative-signed value).
    if n == 0:
        return tlv(TAG_INTEGER, b"\x00")
    body = []
    v = n
    while v:
        body.insert(0, v & 0xFF)
        v >>= 8
    if body[0] & 0x80:
        body = [0x00] + body
    return tlv(TAG_INTEGER, bytes(body))


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "corpus/asn1"
    os.makedirs(out, exist_ok=True)

    # 1) Short-form INTEGER.
    open(os.path.join(out, "int_short.der"), "wb").write(integer(0x42))

    # 2) Long-form OCTET STRING (200 bytes of payload — forces the
    # 0x81 length prefix).
    open(os.path.join(out, "octet_long.der"), "wb").write(
        tlv(TAG_OCTET_STRING, b"A" * 200))

    # 3) SEQUENCE of two INTEGERs (the canonical "INTEGER pair"
    # shape used by RSA public keys + ECDSA signatures).
    open(os.path.join(out, "seq_int_pair.der"), "wb").write(
        tlv(TAG_SEQUENCE, integer(0xC10000001) + integer(0x10001)))

    # 4) AlgorithmIdentifier-shape SEQUENCE { OID rsaEncryption,
    # NULL }. Exercises the OID compare + NULL parser path.
    rsa_oid = bytes([0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01])
    open(os.path.join(out, "algo_id_rsa.der"), "wb").write(
        tlv(TAG_SEQUENCE, tlv(TAG_OID, rsa_oid) + tlv(TAG_NULL, b"")))

    # 5) Nested SEQUENCE (depth 2) — exercises the harness's
    # one-level recursion gate at fuzz_asn1.cpp:30.
    inner = tlv(TAG_SEQUENCE, integer(1) + integer(2))
    open(os.path.join(out, "seq_nested.der"), "wb").write(
        tlv(TAG_SEQUENCE, inner + integer(3)))

    print(f"seeded {out}: {len(os.listdir(out))} files")


if __name__ == "__main__":
    main()
