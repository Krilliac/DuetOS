#!/usr/bin/env python3
"""Deterministic hostile tests for verify-boot-verdict.py."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
VERIFIER_PATH = ROOT / "tools/test/verify-boot-verdict.py"
SPEC = importlib.util.spec_from_file_location("duetos_verify_boot_verdict", VERIFIER_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot load {VERIFIER_PATH}")
VERIFIER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFIER)

COMPLETION = "[smoke] profile=bringup complete"


def good_lines(*, cpus: int = 2, include_exit: bool = True) -> list[bytes]:
    lines = [
        b"DuetOS boot",
        f"[smp] online={cpus}/{cpus}".encode("ascii"),
        b"[boot-report] result=pass",
        COMPLETION.encode("ascii"),
    ]
    if include_exit:
        lines.append(b"smoke: qemu_rc=33 exit_class=pass exit_phase=n/a")
    return lines


class BootVerdictTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.path = Path(self.tempdir.name) / "boot.log"

    def write_lines(self, lines: list[bytes], *, newline: bytes = b"\n", terminate: bool = True) -> None:
        payload = newline.join(lines)
        if terminate:
            payload += newline
        self.path.write_bytes(payload)

    def verify(self, *, cpus: int = 2, exit_class: str = "pass") -> dict[str, object]:
        return VERIFIER.verify_boot_log(
            self.path,
            expected_cpus=cpus,
            completion_sentinel=COMPLETION,
            expected_exit_class=exit_class,
        )

    def assert_code(self, code: str, *, cpus: int = 2, exit_class: str = "pass") -> None:
        with self.assertRaises(VERIFIER.VerdictError) as raised:
            self.verify(cpus=cpus, exit_class=exit_class)
        self.assertEqual(code, raised.exception.code)

    def test_exact_two_cpu_pass_is_machine_reportable(self) -> None:
        self.write_lines(good_lines())
        result = self.verify()
        self.assertEqual(True, result["ok"])
        self.assertEqual("pass", result["code"])
        self.assertEqual((2, 2), (result["smp_online"], result["smp_total"]))
        self.assertEqual((33, "pass"), (result["qemu_rc"], result["exit_class"]))

    def test_crlf_is_accepted_without_weakening_exact_lines(self) -> None:
        self.write_lines(good_lines(), newline=b"\r\n")
        self.assertTrue(self.verify()["ok"])

    def test_benign_panic_word_in_boot_annotation_is_not_terminal(self) -> None:
        lines = good_lines()
        lines.insert(1, b"[boot] Exercising VA-region classifier (panic / trap dump annotation).")
        self.write_lines(lines)
        self.assertTrue(self.verify()["ok"])

    def test_benign_crash_dump_words_in_minidump_skip_are_not_terminal(self) -> None:
        lines = good_lines()
        lines.insert(1, b"[minidump] disk-persist self-test SKIP (no DuetOS crash-dump reservation)")
        self.write_lines(lines)
        self.assertTrue(self.verify()["ok"])

    def test_ap_fallback_is_not_a_multicore_pass(self) -> None:
        lines = good_lines()
        lines[1:2] = [
            b"[E] arch/smp : AP never signalled online, giving up",
            b"[smp] online=1/2",
        ]
        self.write_lines(lines)
        self.assert_code("forbidden_signature")

    def test_online_or_total_mismatch_fails_closed(self) -> None:
        for sentinel in (b"[smp] online=1/2", b"[smp] online=2/3"):
            with self.subTest(sentinel=sentinel):
                lines = good_lines()
                lines[1] = sentinel
                self.write_lines(lines)
                self.assert_code("smp_count_mismatch")

    def test_empty_and_nonverdict_logs_cannot_pass(self) -> None:
        self.path.write_bytes(b"")
        self.assert_code("empty_log")
        self.write_lines([b"PASS=0 FAIL=0", b"nothing executed"])
        self.assert_code("missing_smp")

    def test_late_timeout_after_completion_is_rejected(self) -> None:
        lines = good_lines(include_exit=False)
        lines.extend(
            [
                b"qemu-system-x86_64: terminating on signal 15 from pid 7 (timeout)",
                b"smoke: qemu_rc=124 exit_class=<unstructured> exit_phase=n/a",
            ]
        )
        self.write_lines(lines)
        self.assert_code("forbidden_signature")

    def test_nonpass_exit_record_is_rejected_even_when_not_required(self) -> None:
        lines = good_lines()
        lines[-1] = b"smoke: qemu_rc=125 exit_class=panic exit_phase=smp"
        self.write_lines(lines)
        self.assert_code("exit_not_pass", exit_class="not-applicable")

    def test_required_exit_record_cannot_be_omitted(self) -> None:
        self.write_lines(good_lines(include_exit=False))
        self.assert_code("missing_exit_record")

    def test_records_must_follow_producer_and_host_append_order(self) -> None:
        cases = (
            (
                [
                    b"[boot-report] result=pass",
                    b"[smp] online=2/2",
                    COMPLETION.encode("ascii"),
                    b"smoke: qemu_rc=33 exit_class=pass exit_phase=n/a",
                ],
                "boot report before SMP",
            ),
            (
                [
                    b"[smp] online=2/2",
                    COMPLETION.encode("ascii"),
                    b"[boot-report] result=pass",
                    b"smoke: qemu_rc=33 exit_class=pass exit_phase=n/a",
                ],
                "completion before boot report",
            ),
            (
                [
                    b"[smp] online=2/2",
                    b"[boot-report] result=pass",
                    b"smoke: qemu_rc=33 exit_class=pass exit_phase=n/a",
                    COMPLETION.encode("ascii"),
                ],
                "host exit before completion",
            ),
        )
        for lines, label in cases:
            with self.subTest(label=label):
                self.write_lines(lines)
                self.assert_code("record_order")

    def test_not_applicable_exit_contract_allows_serial_only_log(self) -> None:
        self.write_lines(good_lines(include_exit=False))
        result = self.verify(exit_class="not-applicable")
        self.assertEqual("not-applicable", result["exit_class"])
        self.assertIsNone(result["qemu_rc"])

    def test_duplicate_and_conflicting_smp_records_are_rejected(self) -> None:
        for extra, code in (
            (b"[smp] online=2/2", "duplicate_smp"),
            (b"[smp] online=1/2", "conflicting_smp"),
        ):
            with self.subTest(code=code):
                lines = good_lines()
                lines.insert(2, extra)
                self.write_lines(lines)
                self.assert_code(code)

    def test_duplicate_and_conflicting_boot_reports_are_rejected(self) -> None:
        for extra, code in (
            (b"[boot-report] result=pass", "duplicate_boot_report"),
            (b"[boot-report] result=fail", "conflicting_boot_report"),
        ):
            with self.subTest(code=code):
                lines = good_lines()
                lines.insert(3, extra)
                self.write_lines(lines)
                self.assert_code(code)

    def test_duplicate_or_wrong_profile_completion_is_rejected(self) -> None:
        lines = good_lines()
        lines.insert(4, COMPLETION.encode("ascii"))
        self.write_lines(lines)
        self.assert_code("duplicate_completion")

        lines = good_lines()
        lines[3] = b"[smoke] profile=ring3 complete"
        self.write_lines(lines)
        self.assert_code("conflicting_completion")

    def test_duplicate_or_conflicting_exit_records_are_rejected(self) -> None:
        lines = good_lines()
        lines.append(lines[-1])
        self.write_lines(lines)
        self.assert_code("duplicate_exit_record")

        lines = good_lines()
        lines.append(b"smoke: qemu_rc=125 exit_class=panic exit_phase=smp")
        self.write_lines(lines)
        self.assert_code("conflicting_exit_record")

    def test_missing_core_sentinels_are_rejected_individually(self) -> None:
        cases = (
            (1, "missing_smp"),
            (2, "missing_boot_report"),
            (3, "missing_completion"),
        )
        for index, code in cases:
            with self.subTest(code=code):
                lines = good_lines()
                del lines[index]
                self.write_lines(lines)
                self.assert_code(code)

    def test_malformed_or_huge_smp_numbers_are_rejected(self) -> None:
        for sentinel in (
            b"[smp] online=999999999999999999999999/2",
            b"[smp] online=2/999999999999999999999999",
            b"prefix [smp] online=2/2",
            b"[smp] online=2/",
            b"[smp] online=0/0",
            b"[smp] online=33/33",
        ):
            with self.subTest(sentinel=sentinel):
                lines = good_lines()
                lines[1] = sentinel
                self.write_lines(lines)
                self.assert_code("malformed_smp")

    def test_malformed_boot_and_exit_records_are_rejected(self) -> None:
        lines = good_lines()
        lines[2] = b"[boot-report] result=pass trailing"
        self.write_lines(lines)
        self.assert_code("malformed_boot_report")

        lines = good_lines()
        lines[-1] = b"smoke: qemu_rc=999999999999999 exit_class=pass exit_phase=n/a"
        self.write_lines(lines)
        self.assert_code("malformed_exit_record")

    def test_truncated_lf_and_crlf_records_are_rejected(self) -> None:
        self.write_lines(good_lines(), terminate=False)
        self.assert_code("truncated_log")

        self.path.write_bytes(b"\r\n".join(good_lines()) + b"\r")
        self.assert_code("truncated_log")

    def test_line_and_file_size_limits_are_enforced(self) -> None:
        self.write_lines([b"x" * (VERIFIER.MAX_LINE_BYTES + 1)])
        self.assert_code("line_too_long")

        with self.path.open("wb") as stream:
            stream.seek(VERIFIER.MAX_LOG_BYTES)
            stream.write(b"\n")
        self.assert_code("input_too_large")

    def test_expected_values_are_bounded_and_explicit(self) -> None:
        self.write_lines(good_lines())
        for cpus in (0, VERIFIER.MAX_EXPECTED_CPUS + 1):
            with self.subTest(cpus=cpus):
                self.assert_code("invalid_expected_cpus", cpus=cpus)
        self.assert_code("invalid_expected_exit_class", exit_class="hung")

        with self.assertRaises(VERIFIER.VerdictError) as raised:
            VERIFIER.verify_boot_log(
                self.path,
                expected_cpus=2,
                completion_sentinel="x" * (VERIFIER.MAX_COMPLETION_BYTES + 1),
                expected_exit_class="pass",
            )
        self.assertEqual("invalid_completion", raised.exception.code)

    def test_forbidden_panic_and_fault_signatures_are_rejected_anywhere(self) -> None:
        for forbidden in (
            b"PANIC: scheduler",
            b"Kernel panic - not syncing",
            b"[panic] scheduler invariant",
            b"[panic-summary] scheduler invariant",
            b"[panic-precis] scheduler invariant",
            b"[recursive-panic] scheduler invariant",
            b"=== DUETOS CRASH DUMP BEGIN ===",
            b"=== DUETOS CRASH DUMP END ===",
            b"Triple fault",
            b"kernel oops in scheduler",
            b"[task-kill] ring-3 task took #GP General protection",
            b"#GP at RIP=0x1",
            b"#PF at RIP=0x2",
            b"#UD at RIP=0x3",
            b"** CPU EXCEPTION **",
            b"#UD Invalid opcode",
            b"#GP General protection",
            b"#PF Page fault",
            b"stack canary corrupted",
            b"General Protection Fault",
            b"[health] ESCALATE: boot",
            b"[boot] phase=smp FAIL ec=0x40",
            b"[crypto] FAIL bad vector",
        ):
            with self.subTest(forbidden=forbidden):
                lines = good_lines()
                lines.insert(4, forbidden)
                self.write_lines(lines)
                self.assert_code("forbidden_signature")

    def test_cli_emits_one_compact_json_object_and_shell_status(self) -> None:
        self.write_lines(good_lines())
        command = [
            sys.executable,
            str(VERIFIER_PATH),
            str(self.path),
            "--expected-cpus",
            "2",
            "--completion-sentinel",
            COMPLETION,
            "--expected-exit-class",
            "pass",
        ]
        completed = subprocess.run(command, check=False, capture_output=True, text=True)
        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertEqual("", completed.stderr)
        self.assertEqual(1, len(completed.stdout.splitlines()))
        self.assertTrue(json.loads(completed.stdout)["ok"])

        lines = good_lines()
        lines[1] = b"[smp] online=1/2"
        self.write_lines(lines)
        completed = subprocess.run(command, check=False, capture_output=True, text=True)
        self.assertEqual(1, completed.returncode)
        payload = json.loads(completed.stdout)
        self.assertFalse(payload["ok"])
        self.assertEqual("smp_count_mismatch", payload["code"])


if __name__ == "__main__":
    unittest.main()
