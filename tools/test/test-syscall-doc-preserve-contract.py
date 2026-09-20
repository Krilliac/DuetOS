#!/usr/bin/env python3
"""Regression contract for lossless syscall ABI wiki synchronization."""

from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
GENERATOR = ROOT / "tools" / "build" / "gen-syscall-doc.py"


class SyscallDocPreserveContractTests(unittest.TestCase):
    def test_existing_curated_cells_survive_and_new_rows_are_generated(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            syscall_h = temp / "syscall.h"
            names_def = temp / "syscall_names.def"
            existing = temp / "Syscall-ABI.md"
            syscall_h.write_text(
                """enum class Syscall {
    // SYS_OLD: rdi = generated argument. Returns generated value.
    SYS_OLD = 1,
    // SYS_NEW: rsi = fresh argument. Returns fresh value.
    SYS_NEW = 2,
};
""",
                encoding="utf-8",
            )
            names_def.write_text("X(SYS_OLD, 1)\nX(SYS_NEW, 2)\n", encoding="utf-8")
            existing.write_text(
                """<!-- AUTO:syscall_args -->
| # | Symbol | Args | Returns |
|---|--------|------|---------|
| 1 | `SYS_OLD` | curated arguments | curated return contract |
<!-- /AUTO:syscall_args -->
""",
                encoding="utf-8",
            )

            completed = subprocess.run(
                [
                    sys.executable,
                    str(GENERATOR),
                    "--syscall-h",
                    str(syscall_h),
                    "--names-def",
                    str(names_def),
                    "--existing",
                    str(existing),
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=True,
            )

        self.assertIn("| 1 | `SYS_OLD` | curated arguments | curated return contract |", completed.stdout)
        self.assertIn("| 2 | `SYS_NEW` | `rsi` = fresh argument | fresh value |", completed.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
