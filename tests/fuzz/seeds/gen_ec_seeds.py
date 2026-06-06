#!/usr/bin/env python3
# DuetOS EC public-key (SEC1 point) fuzz seed generator.
#
# WHAT  Emits uncompressed SEC1 EC points (0x04 || X || Y) that pass
#       ParsePublicKey's prefix + length + coordinate-range + on-curve
#       gates: the NIST P-256 generator point (65 bytes) and the
#       NIST P-384 generator point (97 bytes), both guaranteed
#       on-curve. Plus a 0x04-prefixed all-zero point that clears the
#       prefix/length gate but fails the on-curve test (the rejection
#       leg). fuzz_ec drives both curves on every input.
#
# WHY   ParsePublicKey rejects anything that is not 0x04 + two field-
#       width coordinates inside [0, p) that satisfy y^2 = x^3+ax+b,
#       so a blind mutator almost never reaches the heavy on-curve
#       bigint arithmetic. A valid generator-point seed puts the
#       fuzzer one mutation away from the coordinate import + on-curve
#       test — exactly the attacker-reachable TLS-cert path.
#
# USAGE  python3 gen_ec_seeds.py <out_dir>

import os
import sys

# NIST P-256 (secp256r1) generator G (SEC1 §2.4, FIPS 186-4 D.1.2.3).
P256_GX = bytes.fromhex("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296")
P256_GY = bytes.fromhex("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5")

# NIST P-384 (secp384r1) generator G (FIPS 186-4 D.1.2.4).
P384_GX = bytes.fromhex(
    "aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e0"
    "82542a385502f25dbf55296c3a545e3872760ab7"
)
P384_GY = bytes.fromhex(
    "3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113"
    "b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f"
)


def main() -> None:
    out = sys.argv[1] if len(sys.argv) > 1 else "corpus/ec"
    os.makedirs(out, exist_ok=True)
    seeds = {
        "p256_generator.bin": b"\x04" + P256_GX + P256_GY,
        "p384_generator.bin": b"\x04" + P384_GX + P384_GY,
        # 0x04 + zero coords: passes prefix/length, fails on-curve.
        "p256_zero.bin": b"\x04" + bytes(64),
    }
    for name, data in seeds.items():
        with open(os.path.join(out, name), "wb") as fh:
            fh.write(data)
    print(f"seeded {out}: {len(os.listdir(out))} files")


if __name__ == "__main__":
    main()
