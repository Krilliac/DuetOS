#!/usr/bin/env python3
# DuetOS gzip / zlib fuzz seed generator.
#
# WHAT  Emits seeds for fuzz_gzip, which dispatches on the first
#       input byte:
#         (data[0] & 1) == 0  ->  GzipInflate (RFC 1952)
#         (data[0] & 1) == 1  ->  ZlibInflate (RFC 1950)
#       The remainder `data[1..]` is the body. So each seed
#       prepends a one-byte selector + a real gzip-1952 or
#       zlib-1950 stream so fuzz_gzip starts past the header
#       walker and exercises both wrappers + their checksum gates
#       (CRC-32 / Adler-32) on real input.
#
# WHY   The gzip header alone is 10 bytes of magic+flags+timestamp
#       before the DEFLATE payload, with optional FEXTRA / FNAME /
#       FCOMMENT / FHCRC fields and a CRC-32 + ISIZE trailer.
#       zlib is shorter (2-byte CMF/FLG + optional preset
#       dictionary + 4-byte Adler-32) but its FCHECK bit-level
#       validation is non-trivial. Neither is reachable by raw
#       mutation in a useful fuzz budget. One real seed each
#       converts "wandering near the gate" into "fuzzing the
#       body and the checksum gates".
#
# USAGE  python3 gen_gzip_seeds.py <out_dir>

import gzip
import io
import os
import sys
import zlib


def gzip_stream(payload: bytes) -> bytes:
    buf = io.BytesIO()
    # mtime=0 makes the seed reproducible across runs.
    with gzip.GzipFile(fileobj=buf, mode="wb", compresslevel=9, mtime=0) as g:
        g.write(payload)
    return buf.getvalue()


def zlib_stream(payload: bytes) -> bytes:
    return zlib.compress(payload, level=9)


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "corpus/gzip"
    os.makedirs(out, exist_ok=True)

    # Selector byte 0x00 -> GzipInflate path. Small payload covers
    # the gzip 10-byte fixed header + DEFLATE body + CRC-32 trailer.
    open(os.path.join(out, "gz_short.bin"), "wb").write(
        b"\x00" + gzip_stream(b"hello, gzip world\n"))

    # Longer gzip payload — exercises the inflater across multiple
    # DEFLATE blocks and the ISIZE trailer.
    long_payload = (b"DuetOS gzip fuzz seed corpus. " * 200)
    open(os.path.join(out, "gz_long.bin"), "wb").write(
        b"\x02" + gzip_stream(long_payload))  # 0x02 & 1 == 0 -> gzip

    # Selector byte 0x01 -> ZlibInflate path. Same short payload.
    open(os.path.join(out, "zlib_short.bin"), "wb").write(
        b"\x01" + zlib_stream(b"hello, zlib world\n"))

    # Longer zlib payload — exercises Adler-32 over a non-trivial
    # body.
    open(os.path.join(out, "zlib_long.bin"), "wb").write(
        b"\x03" + zlib_stream(long_payload))  # 0x03 & 1 == 1 -> zlib

    print(f"seeded {out}: {len(os.listdir(out))} files")


if __name__ == "__main__":
    main()
