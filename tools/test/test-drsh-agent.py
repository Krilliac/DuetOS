#!/usr/bin/env python3
"""Behavior tests for the authenticated DRSH shell agent."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools" / "security"))

from drsh_agent import parse_args  # noqa: E402


class DrshAgentCliTests(unittest.TestCase):
    def test_cli_uses_a_tcg_safe_connect_timeout(self) -> None:
        args = parse_args(["--profile", "recon"])
        self.assertEqual(args.connect_timeout, 15.0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
