#!/usr/bin/env python3
"""Hostile parser and repository tests for native-syscall-dispatch-bijection.py."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
AUDITOR_PATH = ROOT / "tools/test/native-syscall-dispatch-bijection.py"
SPEC = importlib.util.spec_from_file_location("duetos_native_syscall_dispatch_bijection", AUDITOR_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot load {AUDITOR_PATH}")
AUDITOR = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = AUDITOR
SPEC.loader.exec_module(AUDITOR)


def idl_text(rows: list[tuple[str, int, str]]) -> str:
    return json.dumps(
        {
            "schema": "fixture",
            "schema_version": 1,
            "syscalls": [{"name": name, "number": number, "status": status} for name, number, status in rows],
        }
    )


def enum_text(rows: list[tuple[str, int]]) -> str:
    entries = "\n".join(f"    {name} = {number}," for name, number in rows)
    return f"enum SyscallNumber : u64\n{{\n{entries}\n}};\n"


VALID_ROWS = [
    ("SYS_ALPHA", 0, "implemented"),
    ("SYS_RESERVED_ONE", 1, "reserved"),
    ("SYS_BETA", 2, "implemented"),
    ("SYS_GAMMA", 3, "implemented"),
]
VALID_ENUM = [(name, number) for name, number, _status in VALID_ROWS]
VALID_SOURCE = r'''
void Dispatch(u64 num, Frame* frame)
{
    // case SYS_COMMENT: { switch (num) { }
    const char* ignored = "case SYS_STRING: } default:";
    const char* raw = R"tag(case SYS_RAW: { switch (num) })tag";
#define FAKE_CASE case SYS_PREPROCESSOR: {
    switch (num)
    {
    case SYS_ALPHA:
        handlers::DoAlpha(frame);
        return;
    case SYS_BETA:
    {
        switch (frame->rdi)
        {
        case 0:
            return;
        case SYS_ALPHA: // Nested cases do not belong to switch(num).
            return;
        default:
            return;
        }
    }
    case SyscallNumber::SYS_GAMMA:
    {
        if (frame == nullptr)
            return;
        frame->rax = 3;
        return;
    }
    default:
        return;
    }
}
'''


class NativeSyscallDispatchBijectionTests(unittest.TestCase):
    def audit_fixture(
        self,
        rows: list[tuple[str, int, str]] = VALID_ROWS,
        enum_rows: list[tuple[str, int]] = VALID_ENUM,
        source: str = VALID_SOURCE,
    ):
        return AUDITOR.audit_texts(
            idl_text(rows), enum_text(enum_rows), source, "fixture.json", "fixture.h", "fixture.cpp"
        )

    def test_valid_fixture_is_deterministic_and_classified(self) -> None:
        first = self.audit_fixture()
        second = self.audit_fixture()
        self.assertEqual(first, second)
        self.assertTrue(first["ok"])
        self.assertEqual([], first["errors"])
        self.assertEqual(
            {"dispatch": 3, "enum": 4, "idl": 4, "implemented": 3, "reserved": 1, "retired": 0},
            first["counts"],
        )
        self.assertEqual(1, first["default_case_count"])
        self.assertEqual([], first["unassigned_numbers"])
        self.assertEqual(
            [{"name": "SYS_RESERVED_ONE", "number": 1, "status": "reserved"}], first["nonimplemented"]
        )

        cases = {row["name"]: row for row in first["cases"]}
        self.assertEqual("delegated_call", cases["SYS_ALPHA"]["classification"])
        self.assertEqual("handlers::DoAlpha", cases["SYS_ALPHA"]["delegate"])
        self.assertEqual("multiplexer", cases["SYS_BETA"]["classification"])
        self.assertEqual("inline", cases["SYS_GAMMA"]["classification"])
        self.assertEqual({"delegated_call": 1, "inline": 1, "multiplexer": 1}, first["classification_counts"])

    def test_idl_rejects_duplicate_names_numbers_order_and_status(self) -> None:
        with self.assertRaisesRegex(AUDITOR.AuditError, "duplicate syscall name"):
            AUDITOR.parse_idl(
                idl_text([("SYS_ALPHA", 0, "implemented"), ("SYS_ALPHA", 1, "implemented")]), "fixture"
            )
        with self.assertRaisesRegex(AUDITOR.AuditError, "is shared"):
            AUDITOR.parse_idl(
                idl_text([("SYS_ALPHA", 0, "implemented"), ("SYS_BETA", 0, "implemented")]), "fixture"
            )
        with self.assertRaisesRegex(AUDITOR.AuditError, "strictly ordered"):
            AUDITOR.parse_idl(
                idl_text([("SYS_BETA", 2, "implemented"), ("SYS_ALPHA", 0, "implemented")]), "fixture"
            )
        with self.assertRaisesRegex(AUDITOR.AuditError, "unsupported status"):
            AUDITOR.parse_idl(idl_text([("SYS_ALPHA", 0, "maybe")]), "fixture")

    def test_enum_rejects_duplicates_expressions_and_ambiguous_declarations(self) -> None:
        with self.assertRaisesRegex(AUDITOR.AuditError, "duplicate enum name"):
            AUDITOR.parse_enum(enum_text([("SYS_ALPHA", 0), ("SYS_ALPHA", 1)]), "fixture")
        with self.assertRaisesRegex(AUDITOR.AuditError, "is shared"):
            AUDITOR.parse_enum(enum_text([("SYS_ALPHA", 0), ("SYS_BETA", 0)]), "fixture")
        with self.assertRaisesRegex(AUDITOR.AuditError, "unsupported SyscallNumber entry"):
            AUDITOR.parse_enum("enum SyscallNumber : u64 { SYS_ALPHA = 1 + 1, };", "fixture")
        with self.assertRaisesRegex(AUDITOR.AuditError, "expected one SyscallNumber enum"):
            AUDITOR.parse_enum(enum_text([("SYS_ALPHA", 0)]) * 2, "fixture")

    def test_switch_ignores_nested_and_lexically_hidden_cases(self) -> None:
        cases, default_count = AUDITOR.parse_dispatch(VALID_SOURCE, "fixture")
        self.assertEqual(["SYS_ALPHA", "SYS_BETA", "SYS_GAMMA"], [case.name for case in cases])
        self.assertEqual(1, default_count)

    def test_switch_rejects_duplicate_numeric_and_ambiguous_switches(self) -> None:
        duplicate = VALID_SOURCE.replace(
            "    default:\n        return;\n    }",
            "    case SYS_ALPHA:\n        return;\n    default:\n        return;\n    }",
            1,
        )
        with self.assertRaisesRegex(AUDITOR.AuditError, "duplicate dispatch case SYS_ALPHA"):
            AUDITOR.parse_dispatch(duplicate, "fixture")

        numeric = VALID_SOURCE.replace("case SYS_ALPHA:", "case 0:", 1)
        with self.assertRaisesRegex(AUDITOR.AuditError, "unsupported syscall case label"):
            AUDITOR.parse_dispatch(numeric, "fixture")

        ambiguous = (
            VALID_SOURCE
            + "\nvoid Other(u64 num) { switch (num) { case SYS_ALPHA: return; default: return; } }\n"
        )
        with self.assertRaisesRegex(AUDITOR.AuditError, r"expected one switch\(num\), found 2"):
            AUDITOR.parse_dispatch(ambiguous, "fixture")

    def test_bijection_reports_missing_extra_reserved_and_default_errors(self) -> None:
        missing_enum = [row for row in VALID_ENUM if row[0] != "SYS_GAMMA"]
        report = self.audit_fixture(enum_rows=missing_enum)
        self.assertFalse(report["ok"])
        self.assertIn("IDL SYS_GAMMA=3 is missing from SyscallNumber", report["errors"])

        missing_case = VALID_SOURCE.replace(
            "    case SyscallNumber::SYS_GAMMA:\n"
            "    {\n"
            "        if (frame == nullptr)\n"
            "            return;\n"
            "        frame->rax = 3;\n"
            "        return;\n"
            "    }\n",
            "",
        )
        report = self.audit_fixture(source=missing_case)
        self.assertIn("implemented syscall SYS_GAMMA=3 has no dispatch case", report["errors"])

        reserved_case = VALID_SOURCE.replace(
            "    default:\n        return;\n    }",
            "    case SYS_RESERVED_ONE:\n        return;\n    default:\n        return;\n    }",
            1,
        )
        report = self.audit_fixture(source=reserved_case)
        self.assertTrue(
            any(
                error.startswith("reserved syscall SYS_RESERVED_ONE=1 has a dispatch case")
                for error in report["errors"]
            )
        )

        extra_case = VALID_SOURCE.replace(
            "    default:\n        return;\n    }",
            "    case SYS_EXTRA:\n        return;\n    default:\n        return;\n    }",
            1,
        )
        report = self.audit_fixture(source=extra_case)
        self.assertTrue(any(error.startswith("dispatch case SYS_EXTRA") for error in report["errors"]))

        no_default = VALID_SOURCE.replace("    default:\n        return;\n    }\n}\n", "    }\n}\n", 1)
        report = self.audit_fixture(source=no_default)
        self.assertIn("dispatch switch must contain exactly one top-level default, found 0", report["errors"])

    def test_lexer_rejects_unterminated_literals_comments_and_token_flood(self) -> None:
        with self.assertRaisesRegex(AUDITOR.AuditError, "unterminated quoted literal"):
            AUDITOR.lex_cpp('switch (num) { const char* value = "case SYS_BAD:', "fixture")
        with self.assertRaisesRegex(AUDITOR.AuditError, "unterminated block comment"):
            AUDITOR.lex_cpp("switch (num) { /* case SYS_BAD:", "fixture")
        original_limit = AUDITOR.MAX_TOKENS
        try:
            AUDITOR.MAX_TOKENS = 4
            with self.assertRaisesRegex(AUDITOR.AuditError, "token limit"):
                AUDITOR.lex_cpp("one two three four five", "fixture")
        finally:
            AUDITOR.MAX_TOKENS = original_limit

    def test_bounded_reader_and_report_mode(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "oversized.txt"
            path.write_bytes(b"12345")
            with self.assertRaisesRegex(AUDITOR.AuditError, "exceeds 4 bytes"):
                AUDITOR.read_bounded_text(path, 4, "fixture")

        quiet = subprocess.run(
            [sys.executable, str(AUDITOR_PATH), "--root", str(ROOT)],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(0, quiet.returncode, quiet.stderr)
        self.assertEqual("", quiet.stdout)
        self.assertEqual("", quiet.stderr)

        reported = subprocess.run(
            [sys.executable, str(AUDITOR_PATH), "--root", str(ROOT), "--report"],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(0, reported.returncode, reported.stderr)
        self.assertEqual("", reported.stderr)
        self.assertEqual(1, len(reported.stdout.splitlines()))
        parsed = json.loads(reported.stdout)
        self.assertTrue(parsed["ok"])
        self.assertEqual(228, parsed["counts"]["idl"])

    def test_cli_failure_is_text_by_default_and_json_only_on_report(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            empty_root = Path(directory)
            quiet = subprocess.run(
                [sys.executable, str(AUDITOR_PATH), "--root", str(empty_root)],
                cwd=ROOT,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(1, quiet.returncode)
            self.assertEqual("", quiet.stdout)
            self.assertIn("native-syscall-dispatch-bijection:", quiet.stderr)
            self.assertFalse(quiet.stderr.lstrip().startswith("{"))

            reported = subprocess.run(
                [sys.executable, str(AUDITOR_PATH), "--root", str(empty_root), "--report"],
                cwd=ROOT,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(1, reported.returncode)
            self.assertEqual("", reported.stderr)
            self.assertEqual(1, len(reported.stdout.splitlines()))
            payload = json.loads(reported.stdout)
            self.assertFalse(payload["ok"])
            self.assertTrue(payload["errors"])

    def test_repository_bijection_and_migration_landmarks(self) -> None:
        report = AUDITOR.audit_repository(ROOT)
        self.assertTrue(report["ok"], report["errors"])
        self.assertEqual(
            {"dispatch": 228, "enum": 228, "idl": 228, "implemented": 228, "reserved": 0, "retired": 0},
            report["counts"],
        )
        self.assertEqual([176, 177, 178, 179], report["unassigned_numbers"])
        self.assertEqual(228, sum(report["classification_counts"].values()))
        cases = {row["name"]: row for row in report["cases"]}
        self.assertEqual("delegated_call", cases["SYS_FILE_OPEN"]["classification"])
        self.assertEqual("subsystems::win32::DoFileOpen", cases["SYS_FILE_OPEN"]["delegate"])
        self.assertEqual("multiplexer", cases["SYS_SOCKET_OP"]["classification"])
        self.assertEqual("inline", cases["SYS_EXIT"]["classification"])


if __name__ == "__main__":
    unittest.main()
