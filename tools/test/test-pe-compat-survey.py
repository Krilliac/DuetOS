#!/usr/bin/env python3
"""Regression tests for PE compatibility survey surface discovery."""

from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("pe-compat-survey.py")
SPEC = importlib.util.spec_from_file_location("pe_compat_survey", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
SURVEY = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = SURVEY
SPEC.loader.exec_module(SURVEY)


class LoadSurfaceTests(unittest.TestCase):
    def test_ws2_32_x64_directory_is_not_misclassified_as_i386(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            x64 = repo / "userland" / "libs" / "ws2_32"
            x86 = repo / "userland" / "libs" / "ws2_32_32"
            x64.mkdir(parents=True)
            x86.mkdir()
            (x64 / "ws2_32.def").write_text(
                "LIBRARY ws2_32.dll\nEXPORTS\n    WSAStartup\n",
                encoding="utf-8",
            )
            (x86 / "ws2_32_32.def").write_text(
                "LIBRARY ws2_32.dll\nEXPORTS\n    socket\n",
                encoding="utf-8",
            )

            surface, _ = SURVEY.load_surface(repo)

            self.assertEqual(surface[64]["ws2_32.dll"], {"WSAStartup"})
            self.assertEqual(surface[32]["ws2_32.dll"], {"socket"})


if __name__ == "__main__":
    unittest.main(verbosity=2)
