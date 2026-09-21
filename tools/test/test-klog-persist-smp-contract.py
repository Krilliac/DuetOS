#!/usr/bin/env python3
"""Contract: klog persistence producers never enter shared FAT32 state."""

from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
KLOG = (ROOT / "kernel/log/klog.cpp").read_text(encoding="utf-8")
PERSIST = (ROOT / "kernel/log/klog_persist.cpp").read_text(encoding="utf-8")
PERSIST_H = (ROOT / "kernel/log/klog_persist.h").read_text(encoding="utf-8")
RING_PATH = ROOT / "kernel/log/klog_pending_ring.h"
PROFILE = (ROOT / "tools/test/profile-boot-smoke.sh").read_text(encoding="utf-8")
BOCHS = (ROOT / "tools/test/bochs-smoke.sh").read_text(encoding="utf-8")
CTEST = (ROOT / "tools/test/ctest-boot-smoke.sh").read_text(encoding="utf-8")
HOST_CMAKE = (ROOT / "tests/host/CMakeLists.txt").read_text(encoding="utf-8")
WORKFLOW = (ROOT / ".github/workflows/build.yml").read_text(encoding="utf-8")


def function_body(source: str, signature: str) -> str:
    start = source.index(signature)
    brace = source.index("{", start)
    depth = 0
    for index in range(brace, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[brace + 1 : index]
    raise AssertionError(f"unterminated function: {signature}")


class ProducerContract(unittest.TestCase):
    def test_line_sink_only_validates_and_enqueues(self) -> None:
        body = function_body(PERSIST, "void LineSink(")
        self.assertIn("klog_pending::Enqueue", body)
        self.assertNotIn("FlushArea", body)
        self.assertNotIn("Fat32", body)
        self.assertNotIn("g_area_files", body)
        self.assertNotIn("CurrentCpu", body)

    def test_shared_line_accumulator_is_retired(self) -> None:
        self.assertNotIn("g_current_log_level", KLOG)
        self.assertNotIn("g_current_log_area", KLOG)
        self.assertNotIn("g_line_accum", KLOG)
        self.assertIn("EmitTeeLine", KLOG)

    def test_sink_publication_is_atomic(self) -> None:
        self.assertIn("__atomic_load_n(&g_line_sink,", KLOG)
        self.assertIn("__atomic_store_n(&g_line_sink,", KLOG)
        replay = function_body(KLOG, "void SetLogLineSink(")
        self.assertIn("__atomic_load_n(&g_line_sink_min_level", replay)
        self.assertIn("replay_min_level", replay)


class ConsumerContract(unittest.TestCase):
    def test_fixed_ring_uses_sequence_publication(self) -> None:
        self.assertTrue(RING_PATH.is_file())
        ring = RING_PATH.read_text(encoding="utf-8")
        self.assertIn("kCapacity = 256", ring)
        self.assertIn("kClaimAttempts = 8", ring)
        self.assertIn("__ATOMIC_RELEASE", ring)
        self.assertIn("__ATOMIC_ACQUIRE", ring)
        self.assertIn("sequence", ring)
        self.assertNotIn("for (;;)", ring)

    def test_flush_has_atomic_single_consumer_gate_and_bounded_drain(self) -> None:
        body = function_body(PERSIST, "bool FlushAllAreas(")
        owned = function_body(PERSIST, "void FlushAllAreasOwned(")
        self.assertIn("guard.TryAcquire", body)
        self.assertIn("__atomic_compare_exchange_n(&g_flush_active", PERSIST)
        self.assertRegex(owned, r"drained\s*<\s*klog_pending::kCapacity")
        self.assertIn("klog_pending::Dequeue", owned)
        self.assertNotIn("g_in_flush", PERSIST)

    def test_public_flush_reports_gate_contention(self) -> None:
        self.assertIn("bool KlogPersistFlush();", PERSIST_H)
        self.assertIn("bool KlogPersistFlush()", PERSIST)

    def test_install_never_resets_a_published_queue(self) -> None:
        body = function_body(PERSIST, "bool KlogPersistInstall(")
        installed_check = body.index("__atomic_load_n(&g_installed")
        initialize = body.index("klog_pending::Initialize")
        publish = body.index("SetLogLineSink(LineSink)")
        self.assertLess(installed_check, initialize)
        self.assertLess(initialize, publish)
        self.assertNotIn("SetLogLineSink(nullptr)", body)

    def test_selftest_marker_has_an_explicit_queue_verdict(self) -> None:
        body = function_body(PERSIST, "void KlogPersistSelfTest(")
        first_drain = body.index("FlushAllAreasOwned")
        enqueue = body.index("klog_pending::Enqueue", first_drain)
        self.assertLess(first_drain, enqueue)
        self.assertIn("self-test FAILED (marker queue full)", body)


class GateContract(unittest.TestCase):
    def test_queue_has_native_concurrency_coverage(self) -> None:
        self.assertIn("add_host_test(klog_pending_ring)", HOST_CMAKE)

    def test_boot_gates_reject_queue_overflow(self) -> None:
        marker = "[klog-persist] pending queue full"
        for source in (PROFILE, BOCHS, CTEST):
            self.assertIn(marker, source)

    def test_contract_is_wired_into_hosted_ci(self) -> None:
        self.assertIn("python3 tools/test/test-klog-persist-smp-contract.py", WORKFLOW)


if __name__ == "__main__":
    unittest.main(verbosity=2)
