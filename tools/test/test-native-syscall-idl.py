#!/usr/bin/env python3
"""Hostile-schema and determinism tests for gen-native-syscall-abi.py."""

from __future__ import annotations

import copy
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
GENERATOR = ROOT / "tools/build/gen-native-syscall-abi.py"
SPEC = importlib.util.spec_from_file_location("duetos_native_syscall_idl", GENERATOR)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot load {GENERATOR}")
IDL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(IDL)


class NativeSyscallIdlTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.document = json.loads((ROOT / "abi/native_syscalls.json").read_text(encoding="utf-8"))

    def assert_invalid(self, mutate) -> None:
        document = copy.deepcopy(self.document)
        mutate(document)
        with self.assertRaises(IDL.IdlError):
            IDL.validate_document(document)

    def test_repository_idl_is_complete_and_matches_legacy_bridge(self) -> None:
        rows = IDL.validate_document(self.document)
        self.assertEqual(225, len(rows))
        self.assertEqual((0, "SYS_EXIT"), (rows[0]["number"], rows[0]["name"]))
        self.assertEqual((228, "SYS_SERVICE_CONTROL"), (rows[-1]["number"], rows[-1]["name"]))
        IDL.verify_legacy(ROOT, rows)

    def test_bootstrap_is_deterministic(self) -> None:
        first = IDL.bootstrap_document(
            ROOT / "kernel/syscall/syscall.h",
            ROOT / "kernel/syscall/syscall_names.def",
            ROOT / "kernel/syscall/cap_table.def",
        )
        second = IDL.bootstrap_document(
            ROOT / "kernel/syscall/syscall.h",
            ROOT / "kernel/syscall/syscall_names.def",
            ROOT / "kernel/syscall/cap_table.def",
        )
        self.assertEqual(first, second)
        self.assertEqual(
            IDL.expected_outputs(ROOT, self.document),
            IDL.expected_outputs(ROOT, copy.deepcopy(self.document)),
        )

    def test_policy_json_is_canonical_complete_and_current(self) -> None:
        rows = IDL.validate_document(self.document)
        policy_path = ROOT / "docs/native-syscall-policy.json"
        rendered = IDL.expected_outputs(ROOT, self.document)[policy_path]
        policy = json.loads(rendered)

        self.assertEqual(
            {"abi", "schema", "schema_version", "syscalls"},
            set(policy),
        )
        self.assertEqual(IDL.ABI_NAME, policy["abi"])
        self.assertEqual(IDL.SCHEMA_NAME, policy["schema"])
        self.assertEqual(IDL.SCHEMA_VERSION, policy["schema_version"])
        self.assertEqual(rows, policy["syscalls"])
        self.assertEqual(
            json.dumps(policy, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
            rendered,
        )
        self.assertEqual(rendered, policy_path.read_text(encoding="utf-8"))

        reordered = copy.deepcopy(self.document)
        reordered["syscalls"] = [dict(reversed(tuple(row.items()))) for row in reordered["syscalls"]]
        self.assertEqual(
            rendered,
            IDL.expected_outputs(ROOT, reordered)[policy_path],
        )

    def test_duplicate_and_out_of_order_numbers_fail_closed(self) -> None:
        self.assert_invalid(lambda doc: doc["syscalls"][1].__setitem__("number", doc["syscalls"][0]["number"]))
        self.assert_invalid(lambda doc: doc["syscalls"].__setitem__(slice(0, 2), list(reversed(doc["syscalls"][:2]))))

    def test_policy_metadata_cannot_be_implicit_or_contradictory(self) -> None:
        self.assert_invalid(lambda doc: doc["syscalls"][0].pop("authorization"))

        def static_without_caps(doc) -> None:
            doc["syscalls"][0]["authorization"]["mode"] = "static"
            doc["syscalls"][0]["authorization"]["capabilities"] = []

        self.assert_invalid(static_without_caps)

        def dynamic_with_caps(doc) -> None:
            doc["syscalls"][0]["authorization"]["mode"] = "dynamic"
            doc["syscalls"][0]["authorization"]["capabilities"] = ["kCapDebug"]

        self.assert_invalid(dynamic_with_caps)

    def test_argument_contract_rejects_duplicates_and_wrong_order(self) -> None:
        row_index = next(i for i, row in enumerate(self.document["syscalls"]) if len(row["arguments"]) >= 2)

        def duplicate_register(doc) -> None:
            args = doc["syscalls"][row_index]["arguments"]
            args[1]["register"] = args[0]["register"]

        self.assert_invalid(duplicate_register)

        def reverse_registers(doc) -> None:
            args = doc["syscalls"][row_index]["arguments"]
            args[0], args[1] = args[1], args[0]

        self.assert_invalid(reverse_registers)

    def test_check_mode_detects_missing_or_stale_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifact = root / "generated.txt"
            expected = {artifact: "expected\n"}
            with self.assertRaises(IDL.IdlError):
                IDL.write_or_check(expected, check=True)
            artifact.write_text("stale\n", encoding="utf-8")
            with self.assertRaises(IDL.IdlError):
                IDL.write_or_check(expected, check=True)
            artifact.write_text("expected\n", encoding="utf-8")
            IDL.write_or_check(expected, check=True)

    def test_check_mode_detects_policy_json_drift(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            outputs = IDL.expected_outputs(root, self.document)
            IDL.write_or_check(outputs, check=False)
            policy_path = root / "docs/native-syscall-policy.json"
            policy_path.write_text(policy_path.read_text(encoding="utf-8") + " ", encoding="utf-8")
            with self.assertRaisesRegex(IDL.IdlError, r"docs/native-syscall-policy\.json"):
                IDL.write_or_check(outputs, check=True)


if __name__ == "__main__":
    unittest.main()
