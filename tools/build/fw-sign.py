#!/usr/bin/env python3
"""DuetOS firmware-package signing tool.

Reads a DUETFWPK-format firmware package (header + payload), computes
SHA-256(header || payload), signs that digest with the supplied RSA
private key using PKCS#1 v1.5 padding, and emits the original package
with a fixed-size signature trailer appended.

Trailer format (16 bytes header + sig_len bytes payload, all LE):
    offset  size  field
    0       4     magic "FWSG"
    4       2     trailer_version (=1)
    6       2     hash_alg (1=SHA-256)
    8       2     sig_alg  (1=RSA-PKCS1-v1.5)
    10      2     sig_len  (256 for RSA-2048)
    12      2     pubkey_id (=1 dev trust root)
    14      2     reserved (=0)
    16..    N     signature bytes (RSA-modulus-width)

Usage:
    fw-sign.py --in pkg.bin --out pkg-signed.bin \
        --key tools/build/fw-signing-keys/dev-fw-signing-private.pem \
        --pubkey-id 1

Self-test mode (used by the kernel's FwPackageSelfTest fixture):
    fw-sign.py --emit-test-fixture > kernel/loader/firmware_package_test_vectors.h
"""

import argparse
import struct
import sys
from hashlib import sha256
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed


TRAILER_MAGIC = b"FWSG"
TRAILER_VERSION = 1
HASH_ALG_SHA256 = 1
SIG_ALG_RSA_PKCS1_V15 = 1
TRAILER_HEADER_BYTES = 16

FW_PACKAGE_HEADER_BYTES = 160
FW_PACKAGE_MAGIC = b"DUETFWPK"


def sign(package: bytes, priv_key, pubkey_id: int) -> bytes:
    if len(package) < FW_PACKAGE_HEADER_BYTES:
        raise ValueError("package shorter than 160-byte envelope header")
    if package[:8] != FW_PACKAGE_MAGIC:
        raise ValueError("package magic mismatch")

    payload_off = struct.unpack_from("<I", package, 20)[0]
    payload_size = struct.unpack_from("<I", package, 24)[0]
    if payload_off + payload_size > len(package):
        raise ValueError("payload bounds escape package")

    # Sign SHA-256(header[0..160] || payload[0..payload_size]). The
    # signature trailer itself is NOT included in the signed digest
    # (it carries the signature). The header digest field (offset 32)
    # IS included because it's an integrity-bound representation of
    # the payload that future code may consult before reaching the
    # payload bytes themselves.
    h = sha256()
    h.update(package[:FW_PACKAGE_HEADER_BYTES])
    h.update(package[payload_off : payload_off + payload_size])
    digest = h.digest()

    # Use Prehashed: `digest` is already SHA-256(header || payload), so we
    # need PKCS#1 v1.5 to wrap it directly without re-hashing. Passing
    # `hashes.SHA256()` (instead of Prehashed) would make Python sign
    # SHA-256(SHA-256(message)), which the kernel verify (single-hash)
    # would correctly reject.
    sig = priv_key.sign(digest, padding.PKCS1v15(), Prehashed(hashes.SHA256()))
    sig_len = len(sig)
    if sig_len != priv_key.key_size // 8:
        raise RuntimeError(f"sig_len {sig_len} unexpected for key_size {priv_key.key_size}")

    trailer = bytearray(TRAILER_HEADER_BYTES + sig_len)
    trailer[0:4] = TRAILER_MAGIC
    struct.pack_into("<HHHHHH", trailer, 4,
                     TRAILER_VERSION, HASH_ALG_SHA256, SIG_ALG_RSA_PKCS1_V15,
                     sig_len, pubkey_id, 0)
    trailer[TRAILER_HEADER_BYTES:] = sig

    # If the source package already had a trailer appended (re-signing),
    # strip the previous one before appending the new signature. We
    # detect by looking at the bytes immediately after the payload.
    sig_search_off = payload_off + payload_size
    if len(package) >= sig_search_off + 4 and package[sig_search_off:sig_search_off + 4] == TRAILER_MAGIC:
        package = package[:sig_search_off]

    return package + bytes(trailer)


def build_test_fixture(priv_key, dev_pubkey_id: int) -> str:
    """Produce the C header baked into the kernel self-test.

    Generates a deterministic test package + signs it + emits both
    the signed-bytes and a checksum so the self-test can verify the
    same path the production loader walks at runtime.
    """
    payload = bytes([0x88, 0x54, 0x48, 0x43, 0x01, 0x02, 0x03, 0x04,
                     0x10, 0x20, 0x30, 0x40, 0xA5, 0x5A, 0xC3, 0x3C])

    pkg = bytearray(FW_PACKAGE_HEADER_BYTES + len(payload))
    pkg[0:8] = FW_PACKAGE_MAGIC
    struct.pack_into("<H", pkg, 8, 1)  # version
    struct.pack_into("<H", pkg, 10, FW_PACKAGE_HEADER_BYTES)
    struct.pack_into("<H", pkg, 12, 3)  # family = Ath9kHtc
    pkg[14] = 1  # source_kind = OpenSource
    flags = (1 << 0) | (1 << 1) | (1 << 2) | (1 << 5)
    struct.pack_into("<I", pkg, 16, flags)
    struct.pack_into("<I", pkg, 20, FW_PACKAGE_HEADER_BYTES)
    struct.pack_into("<I", pkg, 24, len(payload))
    struct.pack_into("<I", pkg, 28, 0x20260508)

    digest = sha256(payload).digest()
    pkg[32:64] = digest

    name = b"ath9k-htc-custom"
    pkg[64 : 64 + len(name)] = name
    upstream = b"qca/open-ath9k-htc-firmware"
    pkg[96 : 96 + len(upstream)] = upstream

    pkg[FW_PACKAGE_HEADER_BYTES:] = payload

    signed = sign(bytes(pkg), priv_key, dev_pubkey_id)

    sig_off = FW_PACKAGE_HEADER_BYTES + len(payload) + TRAILER_HEADER_BYTES
    sig_bytes = signed[sig_off:]
    if len(sig_bytes) != 256:
        raise RuntimeError(f"unexpected sig length {len(sig_bytes)}")

    lines = []
    lines.append("// AUTO-GENERATED by tools/build/fw-sign.py --emit-test-fixture")
    lines.append("// DO NOT EDIT BY HAND. Re-run with the dev keypair to regenerate.")
    lines.append("//")
    lines.append("// This file holds the pre-signed test fixture used by")
    lines.append("// FwPackageSelfTest: a deterministic ath9k-htc-style envelope")
    lines.append("// signed with tools/build/fw-signing-keys/dev-fw-signing-private.pem,")
    lines.append("// verifiable with the kFwTrustRootModulusBE constant in")
    lines.append("// kernel/loader/firmware_package_trust.h.")
    lines.append("")
    lines.append("#pragma once")
    lines.append("")
    lines.append("#include \"util/types.h\"")
    lines.append("")
    lines.append("namespace duetos::core::testvec")
    lines.append("{")
    lines.append("")
    lines.append(f"// Signed test package (unsigned envelope + 16-byte trailer + 256-byte RSA sig).")
    lines.append(f"inline constexpr u32 kFwTestPackageBytes = {len(signed)};")
    lines.append("inline constexpr u8 kFwTestPackage[] = {")
    for i in range(0, len(signed), 16):
        row = ", ".join(f"0x{b:02X}" for b in signed[i : i + 16])
        comma = "," if i + 16 < len(signed) else ""
        lines.append(f"    {row}{comma}")
    lines.append("};")
    lines.append("")
    lines.append("} // namespace duetos::core::testvec")
    return "\n".join(lines) + "\n"


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--in", dest="inp", help="input firmware package (.bin)")
    ap.add_argument("--out", dest="outp", help="output signed package")
    ap.add_argument("--key", dest="key", default="tools/build/fw-signing-keys/dev-fw-signing-private.pem",
                    help="RSA private key (PEM, PKCS#8)")
    ap.add_argument("--pubkey-id", dest="pubkey_id", type=int, default=1,
                    help="trust-root key id (1=dev, 2+=prod)")
    ap.add_argument("--emit-test-fixture", action="store_true",
                    help="emit kernel/loader/firmware_package_test_vectors.h on stdout")
    args = ap.parse_args()

    with open(args.key, "rb") as f:
        priv_key = serialization.load_pem_private_key(f.read(), password=None)

    if args.emit_test_fixture:
        sys.stdout.write(build_test_fixture(priv_key, args.pubkey_id))
        return 0

    if not args.inp or not args.outp:
        ap.error("--in and --out are required unless --emit-test-fixture is set")

    package = Path(args.inp).read_bytes()
    signed = sign(package, priv_key, args.pubkey_id)
    Path(args.outp).write_bytes(signed)
    print(f"signed: {len(package)} -> {len(signed)} bytes ({args.outp})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
