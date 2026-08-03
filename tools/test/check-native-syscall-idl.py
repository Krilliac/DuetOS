#!/usr/bin/env python3
"""Fail when the native syscall IDL, generated files, or legacy bridge drift."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def main() -> int:
    root = Path(__file__).resolve().parents[2]
    generator = root / "tools/build/gen-native-syscall-abi.py"
    completed = subprocess.run(
        [sys.executable, str(generator), "--root", str(root), "--check", "--check-legacy"],
        cwd=root,
        check=False,
    )
    return completed.returncode


if __name__ == "__main__":
    raise SystemExit(main())
