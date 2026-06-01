#!/usr/bin/env python3
#
# DuetOS — baseline-JPEG known-answer fixture generator for the
# kernel/web JPEG decoder self-test (kernel/web/jpeg_selftest.cpp).
#
# Emits the C++ `constexpr u8 kJpeg...[] = { ... };` byte arrays
# (written to kernel/web/jpeg_fixtures.inc) for a small set of
# baseline JPEGs, plus the host-libjpeg reference pixel values the
# self-test asserts against (within a lossy tolerance). The fixtures
# are produced by Pillow (which wraps libjpeg-turbo), the same
# library the kernel decoder is validated against — so a decoder bug
# cannot pass by agreeing with itself.
#
# Fixtures:
#   kJpegColor420  — 16x16 RGB photo-like gradient, 4:2:0 subsampling
#   kJpegGray      — 8x8 single-component grayscale
#   kJpegColor422  — 16x8 RGB gradient, 4:2:2 subsampling
#   kJpegProgressive — 8x8 SOF2 progressive (rejection fixture)
#
# Usage:  python3 tools/test/gen-jpeg-fixtures.py [out.inc]
#   Default out path: kernel/web/jpeg_fixtures.inc
#
# Deps:  Pillow  (pip install pillow).  No other deps.
#
# After regenerating, paste the printed reference pixel values back
# into jpeg_selftest.cpp's PixelNear(...) asserts if they changed.

import sys
import os

try:
    from PIL import Image
except ImportError:
    sys.stderr.write("error: Pillow is required (pip install pillow)\n")
    sys.exit(1)

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
DEFAULT_OUT = os.path.join(REPO, "kernel", "web", "jpeg_fixtures.inc")

TMP = "/tmp/duetos-jpeg-fixtures"


def make_color420(path):
    w, h = 16, 16
    img = Image.new("RGB", (w, h))
    px = img.load()
    for y in range(h):
        for x in range(w):
            px[x, y] = ((x * 16) & 0xFF, (y * 16) & 0xFF, ((x + y) * 8) & 0xFF)
    img.save(path, "JPEG", quality=80, subsampling="4:2:0", progressive=False)


def make_gray(path):
    w, h = 8, 8
    img = Image.new("L", (w, h))
    px = img.load()
    for y in range(h):
        for x in range(w):
            px[x, y] = (x * 32 + y * 4) & 0xFF
    img.save(path, "JPEG", quality=85, progressive=False)


def make_color422(path):
    w, h = 16, 8
    img = Image.new("RGB", (w, h))
    px = img.load()
    for y in range(h):
        for x in range(w):
            px[x, y] = ((x * 15) & 0xFF, (255 - x * 15) & 0xFF, (y * 30) & 0xFF)
    img.save(path, "JPEG", quality=80, subsampling="4:2:2", progressive=False)


def make_progressive(path):
    img = Image.new("RGB", (8, 8), (120, 60, 200))
    img.save(path, "JPEG", quality=80, progressive=True)


def carr(name, data):
    s = f"constexpr u8 {name}[] = {{\n"
    for i in range(0, len(data), 16):
        s += "    " + ", ".join(f"0x{b:02X}" for b in data[i : i + 16]) + ",\n"
    s += "};\n"
    return s


def refpoints(path, pts):
    """Decode `path` through Pillow/libjpeg and read RGB at sample points."""
    img = Image.open(path).convert("RGB")
    w, h = img.size
    px = img.load()
    out = [f"// {os.path.basename(path)}: {w}x{h}, host libjpeg reference RGB:"]
    for (x, y) in pts:
        r, g, b = px[x, y]
        out.append(f"//   ({x},{y}) = {r},{g},{b}")
    return "\n".join(out)


def main():
    out_path = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_OUT
    os.makedirs(TMP, exist_ok=True)

    jobs = [
        ("kJpegColor420", make_color420, "color.jpg",
         [(0, 0), (15, 0), (0, 15), (15, 15), (8, 8)]),
        ("kJpegGray", make_gray, "gray.jpg",
         [(0, 0), (7, 0), (0, 7), (7, 7), (4, 4)]),
        ("kJpegColor422", make_color422, "c422.jpg",
         [(0, 0), (15, 0), (0, 7), (15, 7), (8, 4)]),
        ("kJpegProgressive", make_progressive, "prog.jpg", [(0, 0)]),
    ]

    header = (
        "// Auto-generated baseline-JPEG fixtures for jpeg_selftest.cpp.\n"
        "// Provenance + generator command are documented in jpeg_selftest.cpp.\n"
        "// Generated on the dev host with Python Pillow (libjpeg-turbo) via\n"
        "// tools/test/gen-jpeg-fixtures.py. DO NOT hand-edit; regenerate.\n\n"
    )

    body = header
    for name, fn, fname, _ in jobs:
        fpath = os.path.join(TMP, fname)
        fn(fpath)
        body += carr(name, open(fpath, "rb").read()) + "\n"

    with open(out_path, "w") as f:
        f.write(body)
    print(f"wrote {out_path} ({len(body)} bytes)")
    print("\nReference pixel values (paste into jpeg_selftest.cpp asserts):\n")
    for name, _, fname, pts in jobs:
        print(refpoints(os.path.join(TMP, fname), pts))
        print()


if __name__ == "__main__":
    main()
