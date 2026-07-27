#!/usr/bin/env python3
"""Safety-policy regression tests for gen-fix-patches.py."""

from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("gen-fix-patches.py")
SPEC = importlib.util.spec_from_file_location("gen_fix_patches", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
GEN = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = GEN
SPEC.loader.exec_module(GEN)


class RetiredImportManifestTests(unittest.TestCase):
    def manifest_path(self, root: Path) -> Path:
        return root / GEN._RETIRED_IMPORTS_PATH

    def test_missing_manifest_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(FileNotFoundError, "safety manifest is missing"):
                GEN.load_retired_imports(Path(tmp))

    def test_empty_manifest_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = self.manifest_path(Path(tmp))
            path.parent.mkdir(parents=True)
            path.write_text("// no retired imports\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "no valid entries"):
                GEN.load_retired_imports(Path(tmp))

    def test_valid_four_wave_manifest_preserves_function_case(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = self.manifest_path(Path(tmp))
            path.parent.mkdir(parents=True)
            names = (
                "CreateThread",
                "ExitThread",
                "FreeLibraryAndExitThread",
                "GetExitCodeThread",
                "GetCurrentProcess",
                "GetCurrentThread",
                "GetCurrentProcessId",
                "GetCurrentThreadId",
                "GetLastError",
                "SetLastError",
                "InterlockedExchangeAdd",
                "InterlockedAnd",
                "InterlockedOr",
                "InterlockedXor",
                "QueryPerformanceCounter",
                "QueryPerformanceFrequency",
                "GetTickCount",
                "GetTickCount64",
            )
            path.write_text(
                "".join(
                    f'DUETOS_RETIRED_KERNEL32_IMPORT("{name}")\n'
                    for name in names
                ),
                encoding="utf-8",
            )
            self.assertEqual(
                GEN.load_retired_imports(Path(tmp)),
                {
                    (provider, name)
                    for name in names
                    for provider in ("kernel32.dll", "kernelbase.dll")
                },
            )

    def test_malformed_mixed_manifest_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = self.manifest_path(Path(tmp))
            path.parent.mkdir(parents=True)
            path.write_text(
                'DUETOS_RETIRED_KERNEL32_IMPORT("CreateThread")\n'
                'DUETOS_RETIRED_KERNEL32_IMPORT("ExitThread"\n',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "malformed retired-import safety manifest line"):
                GEN.load_retired_imports(Path(tmp))

    def test_duplicate_manifest_entry_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = self.manifest_path(Path(tmp))
            path.parent.mkdir(parents=True)
            path.write_text(
                'DUETOS_RETIRED_KERNEL32_IMPORT("CreateThread")\n'
                'DUETOS_RETIRED_KERNEL32_IMPORT("CreateThread")\n',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "duplicate retired-import manifest entry"):
                GEN.load_retired_imports(Path(tmp))


if __name__ == "__main__":
    unittest.main()
