#!/usr/bin/env python3
# DuetOS DEFLATE fuzz seed generator.
#
# WHAT  Emits several raw RFC-1951 DEFLATE streams so fuzz_deflate
#       (kernel/util/deflate.{h,cpp}::DeflateInflate) starts past
#       the bit-level header decode and exercises:
#         - a Stored block walker (BTYPE=00, LEN/NLEN gate),
#         - a Fixed-Huffman block (BTYPE=01) over real data,
#         - a Dynamic-Huffman block (BTYPE=10, full HLIT/HDIST/
#           HCLEN code-length-of-code-lengths chain).
#       Each is emitted as a separate seed so libFuzzer's
#       coverage-guided mutator splits the corpus across all
#       three top-level block decoder paths.
#
# WHY   Without a seed the harness starts from random bytes and
#       has to bootstrap a 3-bit BTYPE + valid Huffman header by
#       chance. That's many minutes of fuzz budget for code paths
#       a one-off seed reaches in microseconds. Per the roadmap
#       "DEFLATE / gzip / zip — the single richest fuzz surface"
#       this is the highest-leverage seed work on the parser list.
#
# USAGE  python3 gen_deflate_seeds.py <out_dir>

import os
import sys
import zlib


def stored_block(payload: bytes) -> bytes:
    # Use zlib at compression-level 0 (Stored) and strip the
    # 2-byte zlib header + 4-byte Adler-32 trailer so what's left
    # is the raw DEFLATE Stored block(s).
    z = zlib.compress(payload, level=0)
    # zlib wrapper: 2-byte header at front, 4-byte Adler32 at end.
    return z[2:-4]


def fixed_huffman(payload: bytes) -> bytes:
    # Default zlib compression uses dynamic Huffman, but on small
    # inputs it can pick fixed. Strip wrapper bytes as above; the
    # resulting raw DEFLATE may be a mix of fixed-Huffman and
    # stored blocks depending on libz heuristics — both are
    # in-scope for the inflater.
    z = zlib.compress(payload, level=9)
    return z[2:-4]


def dynamic_huffman(payload: bytes) -> bytes:
    # Long, varied payload forces zlib to emit a Dynamic-Huffman
    # block (BTYPE=10) with a real HLIT / HDIST / HCLEN code-
    # length-of-code-lengths chain — the corner with the most
    # parser state to fuzz.
    z = zlib.compress(payload, level=9)
    return z[2:-4]


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "corpus/deflate"
    os.makedirs(out, exist_ok=True)

    # Stored block.
    open(os.path.join(out, "stored.bin"), "wb").write(
        stored_block(b"hello, deflate stored block\n"))

    # Tiny payload — zlib likes Fixed-Huffman here.
    open(os.path.join(out, "fixed_short.bin"), "wb").write(
        fixed_huffman(b"abcdef" * 4))

    # Longer payload with varied byte frequencies — forces Dynamic-
    # Huffman code-length table emission.
    body = (b"The quick brown fox jumps over the lazy dog. "
            b"Pack my box with five dozen liquor jugs. "
            b"Sphinx of black quartz, judge my vow. " * 16)
    open(os.path.join(out, "dynamic_long.bin"), "wb").write(
        dynamic_huffman(body))

    # Edge: an empty payload's DEFLATE stream is a single
    # final stored block with LEN=NLEN=0 — exercises the
    # zero-length copy path in the stored-block walker.
    open(os.path.join(out, "empty.bin"), "wb").write(stored_block(b""))

    print(f"seeded {out}: {len(os.listdir(out))} files")


if __name__ == "__main__":
    main()
