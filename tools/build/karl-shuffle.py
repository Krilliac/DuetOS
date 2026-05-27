#!/usr/bin/env python3
"""karl-shuffle.py — KARL (Kernel Address Randomized Link) object-order shuffle.

What:
    Reads a kernel source/object path list (one per line) from stdin, applies
    a seeded random shuffle, prints the shuffled list to stdout.

Why:
    OpenBSD-style KARL: re-link the kernel image in a different .o order on
    every build. A single function-pointer leak no longer exposes the layout
    of every OTHER function — every build has a different in-binary offset
    map. Strict complement to runtime KASLR (which randomizes the BASE; KARL
    randomizes the OFFSETS from the base).

How:
    Stable input is `find ... | sort` style (caller responsibility). Output is
    deterministic given a fixed seed (`random.seed(seed)`), which matters for
    reproducible-build investigations.

    Sources that MUST stay in declared position are NOT passed through this
    script — the CMake side appends them post-shuffle. In practice that means
    the generated TUs (`symbols_generated.cpp`, `kernel_elf_blob.S`) keep
    their pinned trailing slot; the boot trampoline (`arch/x86_64/boot.S`) is
    pulled into `.text.boot` by the linker script regardless of input order,
    so it shuffles harmlessly with the rest.

Usage:
    echo -e "a.cpp\\nb.cpp\\nc.cpp" | karl-shuffle.py --seed 1234
    karl-shuffle.py --seed 1234 < paths.txt > paths.shuffled.txt

    Also writes a side-band hash + summary to the path given via
    --record FILE so a panic dump (or a forensic build artefact) can pin
    which exact order produced this kernel image.

Args:
    --seed N   integer seed for random.seed(N). Required.
    --record P optional path to write a "<seed>\\n<sha256>\\n<count>" record.

Exit code: 0 on success, non-zero on bad input.
"""
import argparse
import hashlib
import random
import sys
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--seed", type=int, required=True,
                        help="Integer seed for the shuffle (must be stable across builds for reproducibility)")
    parser.add_argument("--record", type=Path, default=None,
                        help="Optional path to write seed + order hash for triage")
    args = parser.parse_args()

    lines = [ln.rstrip("\r\n") for ln in sys.stdin]
    # Drop trailing blank line(s); CMake's list_to_stdin pattern can introduce one.
    while lines and lines[-1] == "":
        lines.pop()

    if not lines:
        sys.stderr.write("karl-shuffle: empty input list\n")
        return 1

    # Seed first, THEN sort the input to a canonical order, THEN shuffle.
    # Sorting input first removes any host-dependent order from the upstream
    # `file(GLOB_RECURSE)` (CMake docs say "the order is not guaranteed");
    # without it, two boxes running the same seed would still diverge.
    lines.sort()

    rng = random.Random(args.seed)
    rng.shuffle(lines)

    out = "\n".join(lines) + "\n"
    sys.stdout.write(out)

    if args.record is not None:
        digest = hashlib.sha256(out.encode("utf-8")).hexdigest()
        args.record.parent.mkdir(parents=True, exist_ok=True)
        with args.record.open("w") as f:
            f.write(f"seed={args.seed}\n")
            f.write(f"sha256={digest}\n")
            f.write(f"count={len(lines)}\n")

    return 0


if __name__ == "__main__":
    sys.exit(main())
