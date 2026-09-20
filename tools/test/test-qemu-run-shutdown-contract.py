#!/usr/bin/env python3
"""Contract for QEMU shutdown handling in the shared launcher."""

from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


class QemuRunShutdownContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.runner = (ROOT / "tools/qemu/run.sh").read_text(encoding="utf-8")

    def test_smoke_profiles_allow_guest_test_exit_to_terminate_qemu(self) -> None:
        self.assertIn('SMOKE_PROFILE="${DUETOS_SMOKE_PROFILE:-}"', self.runner)
        self.assertIn('DUETOS_SMOKE_ISO:-', self.runner)
        self.assertIn('SHUTDOWN_ARGS=()', self.runner)
        self.assertIn('if [[ -n "${SMOKE_PROFILE}" || -n "${DUETOS_SMOKE_ISO:-}" ]]', self.runner)
        self.assertIn('"${SHUTDOWN_ARGS[@]}"', self.runner)

    def test_interactive_launcher_keeps_shutdown_state_for_diagnostics(self) -> None:
        self.assertIn('SHUTDOWN_ARGS=(-no-shutdown)', self.runner)
        self.assertIn('echo "[run.sh] smoke profile: allowing QEMU to exit on guest TestExit"', self.runner)

    def test_timeout_cannot_be_misreported_as_a_clean_qemu_exit(self) -> None:
        self.assertNotIn("--preserve-status", self.runner)
        self.assertIn("--kill-after=5", self.runner)


if __name__ == "__main__":
    unittest.main()
