#!/usr/bin/env python3
"""Integration contract for CreateProcess executable-token parsing."""

from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
KERNEL32_FS = ROOT / "userland" / "libs" / "kernel32" / "kernel32_fs.c"
CMAKE = ROOT / "kernel" / "CMakeLists.txt"


def function_body(source: str, signature: str) -> str:
    match = re.search(signature, source)
    if match is None:
        raise AssertionError(f"missing function matching {signature!r}")
    start = source.find("{", match.end())
    if start < 0:
        raise AssertionError(f"missing body for {signature!r}")
    depth = 0
    for index in range(start, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[start + 1 : index]
    raise AssertionError(f"unterminated body for {signature!r}")


class CreateProcessCommandLineContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = KERNEL32_FS.read_text(encoding="utf-8")
        cls.cmake = CMAKE.read_text(encoding="utf-8")

    def test_ansi_path_is_extracted_then_normalized_before_spawn(self) -> None:
        body = function_body(self.source, r"BOOL\s+CreateProcessA\s*\(")
        self.assertIn("Win32ExtractCreateProcessExecutableA", body)
        self.assertIn("NormalizePathA(executable, path", body)
        self.assertLess(body.index("Win32ExtractCreateProcessExecutableA"), body.index("NormalizePathA(executable, path"))
        self.assertLess(body.index("NormalizePathA(executable, path"), body.index("SYS_PROCESS_SPAWN"))
        self.assertNotIn("path = lpCommandLine", body)
        self.assertIn('#include "createprocess_cmdline.h"', self.source)

    def test_wide_path_uses_bounded_shared_contract_without_lossy_low_byte_loop(self) -> None:
        body = function_body(self.source, r"BOOL\s+CreateProcessW\s*\(")
        self.assertIn("Win32ExtractCreateProcessExecutableW", body)
        self.assertIn("return CreateProcessA(path", body)
        self.assertNotIn("src[i] & 0xFF", body)

    def test_normalization_reports_truncation_and_header_rebuilds_kernel32(self) -> None:
        normalize = function_body(self.source, r"int\s+NormalizePathA\s*\(")
        self.assertIn("const int complete = (in[0] == '\\0')", normalize)
        self.assertIn("return complete", normalize)
        self.assertIn('userland/libs/kernel32/createprocess_cmdline.h', self.cmake)


if __name__ == "__main__":
    unittest.main(verbosity=2)
