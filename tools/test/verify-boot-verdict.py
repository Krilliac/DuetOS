#!/usr/bin/env python3
"""Fail closed on one preserved DuetOS boot-verdict log.

The verifier intentionally consumes a single bounded file. Callers that need
the profile runner's decoded QEMU exit record must append that host-produced
line after the captured serial completion in the same artifact before invoking
this tool.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import BinaryIO, Iterator


MAX_LOG_BYTES = 32 * 1024 * 1024
MAX_LINE_BYTES = 16 * 1024
MAX_LOG_LINES = 1_000_000
MAX_COMPLETION_BYTES = 512
MAX_EXPECTED_CPUS = 32

EXPECTED_EXIT_CLASSES = ("pass", "not-applicable")

SMP_PREFIX = b"[smp] online="
SMP_RE = re.compile(rb"^\[smp\] online=([0-9]{1,2})/([0-9]{1,2})$")
BOOT_REPORT_PREFIX = b"[boot-report] result="
BOOT_REPORT_RE = re.compile(rb"^\[boot-report\] result=([a-z][a-z0-9_-]{0,31})$")
EXIT_PREFIX = b"smoke: qemu_rc="
EXIT_RE = re.compile(
    rb"^smoke: qemu_rc=([0-9]{1,3}) "
    rb"exit_class=([a-z][a-z0-9-]{0,31}|<unstructured>) "
    rb"exit_phase=([A-Za-z0-9?_.<>/-]{1,32})$"
)
SMOKE_COMPLETION_RE = re.compile(rb"^\[smoke\] profile=([a-z0-9-]{1,32}) complete$")

# Panic diagnostics are discussed by ordinary boot prose, so match only the
# terminal banners emitted by Panic() and conventional kernel panic records.
FORBIDDEN_PATTERNS = (
    (
        "panic",
        re.compile(
            rb"^\s*(?:"
            rb"panic(?:\s*(?::|-)|$)"
            rb"|kernel\s+panic\b"
            rb"|\[(?:panic|panic-summary|panic-precis|recursive-panic)\](?:\s|$)"
            rb")",
            re.IGNORECASE,
        ),
    ),
    (
        "duetos_crash",
        re.compile(rb"^=== DUETOS CRASH DUMP (?:BEGIN|END) ===$", re.IGNORECASE),
    ),
    ("triple_fault", re.compile(rb"triple fault", re.IGNORECASE)),
    ("kernel_oops", re.compile(rb"kernel oops", re.IGNORECASE)),
    ("task_kill", re.compile(rb"\[task-kill\]", re.IGNORECASE)),
    ("x86_fault_at", re.compile(rb"#(?:GP|PF|UD) at(?: |$)")),
    (
        "cpu_exception",
        re.compile(
            rb"\*\* CPU EXCEPTION \*\*|#UD Invalid opcode|#GP General protection|#PF Page fault",
            re.IGNORECASE,
        ),
    ),
    ("general_protection_fault", re.compile(rb"general protection fault", re.IGNORECASE)),
    ("unhandled_fault", re.compile(rb"unhandled (?:exception|fault)", re.IGNORECASE)),
    ("canary_corruption", re.compile(rb"canary corrupted", re.IGNORECASE)),
    ("health_escalation", re.compile(rb"\[health\] ESCALATE:")),
    ("boot_phase_failure", re.compile(rb"^\[boot\] phase=.* (?:STUCK|FAIL)(?: |$)")),
    ("selftest_failure", re.compile(rb"\] FAIL(?: |$)")),
    ("ap_fallback", re.compile(rb"AP never signalled online", re.IGNORECASE)),
    (
        "qemu_timeout",
        re.compile(rb"terminating on signal 15|timed out|timeout expired", re.IGNORECASE),
    ),
)


class VerdictError(Exception):
    """A bounded, machine-reportable verification failure."""

    def __init__(self, code: str, detail: str, *, line: int | None = None) -> None:
        super().__init__(detail)
        self.code = code
        self.detail = detail
        self.line = line

    def payload(self) -> dict[str, object]:
        result: dict[str, object] = {
            "code": self.code,
            "detail": self.detail,
            "ok": False,
        }
        if self.line is not None:
            result["line"] = self.line
        return result


def _bounded_lines(path: Path) -> Iterator[tuple[int, bytes]]:
    try:
        metadata = path.stat()
    except OSError as exc:
        raise VerdictError("input_unreadable", f"cannot stat input: {exc}") from exc

    if not path.is_file():
        raise VerdictError("input_not_regular", "input is not a regular file")
    if metadata.st_size == 0:
        raise VerdictError("empty_log", "boot log is empty")
    if metadata.st_size > MAX_LOG_BYTES:
        raise VerdictError(
            "input_too_large",
            f"boot log exceeds {MAX_LOG_BYTES} bytes",
        )

    try:
        stream: BinaryIO
        with path.open("rb") as stream:
            total = 0
            line_number = 0
            while True:
                raw = stream.readline(MAX_LINE_BYTES + 2)
                if raw == b"":
                    break

                line_number += 1
                if line_number > MAX_LOG_LINES:
                    raise VerdictError(
                        "too_many_lines",
                        f"boot log exceeds {MAX_LOG_LINES} lines",
                        line=line_number,
                    )

                total += len(raw)
                if total > MAX_LOG_BYTES:
                    raise VerdictError(
                        "input_too_large",
                        f"boot log exceeds {MAX_LOG_BYTES} bytes while reading",
                        line=line_number,
                    )

                if not raw.endswith(b"\n"):
                    if len(raw) > MAX_LINE_BYTES:
                        raise VerdictError(
                            "line_too_long",
                            f"line exceeds {MAX_LINE_BYTES} bytes",
                            line=line_number,
                        )
                    raise VerdictError(
                        "truncated_log",
                        "final record is not newline terminated",
                        line=line_number,
                    )

                line = raw[:-1]
                if line.endswith(b"\r"):
                    line = line[:-1]
                if len(line) > MAX_LINE_BYTES:
                    raise VerdictError(
                        "line_too_long",
                        f"line exceeds {MAX_LINE_BYTES} bytes",
                        line=line_number,
                    )
                if b"\x00" in line:
                    raise VerdictError(
                        "nul_byte",
                        "NUL byte found in boot log",
                        line=line_number,
                    )
                yield line_number, line
    except VerdictError:
        raise
    except OSError as exc:
        raise VerdictError("input_unreadable", f"cannot read input: {exc}") from exc


def _record_unique(
    kind: str,
    records: list[tuple[object, int]],
    value: object,
    line_number: int,
) -> None:
    if records:
        previous_value, previous_line = records[0]
        code = f"duplicate_{kind}" if previous_value == value else f"conflicting_{kind}"
        raise VerdictError(
            code,
            f"{kind} record at line {line_number} conflicts with line {previous_line}",
            line=line_number,
        )
    records.append((value, line_number))


def _validate_expectations(
    expected_cpus: int,
    completion_sentinel: str,
    expected_exit_class: str,
) -> bytes:
    if not 1 <= expected_cpus <= MAX_EXPECTED_CPUS:
        raise VerdictError(
            "invalid_expected_cpus",
            f"expected CPU count must be in 1..{MAX_EXPECTED_CPUS}",
        )
    if expected_exit_class not in EXPECTED_EXIT_CLASSES:
        raise VerdictError(
            "invalid_expected_exit_class",
            "expected exit class must be pass or not-applicable",
        )
    if not completion_sentinel:
        raise VerdictError("invalid_completion", "completion sentinel must not be empty")
    if "\n" in completion_sentinel or "\r" in completion_sentinel:
        raise VerdictError("invalid_completion", "completion sentinel must be one line")
    try:
        encoded = completion_sentinel.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise VerdictError("invalid_completion", "completion sentinel is not valid UTF-8") from exc
    if len(encoded) > MAX_COMPLETION_BYTES:
        raise VerdictError(
            "invalid_completion",
            f"completion sentinel exceeds {MAX_COMPLETION_BYTES} bytes",
        )
    return encoded


def verify_boot_log(
    path: Path,
    *,
    expected_cpus: int,
    completion_sentinel: str,
    expected_exit_class: str,
) -> dict[str, object]:
    """Verify one bounded boot artifact and return a compact verdict payload."""

    completion_bytes = _validate_expectations(
        expected_cpus,
        completion_sentinel,
        expected_exit_class,
    )
    expected_is_smoke_completion = SMOKE_COMPLETION_RE.fullmatch(completion_bytes) is not None

    smp_records: list[tuple[object, int]] = []
    boot_report_records: list[tuple[object, int]] = []
    completion_records: list[tuple[object, int]] = []
    exit_records: list[tuple[object, int]] = []

    for line_number, line in _bounded_lines(path):
        for signature, pattern in FORBIDDEN_PATTERNS:
            if pattern.search(line):
                raise VerdictError(
                    "forbidden_signature",
                    f"forbidden signature: {signature}",
                    line=line_number,
                )

        if SMP_PREFIX in line:
            match = SMP_RE.fullmatch(line)
            if match is None:
                raise VerdictError(
                    "malformed_smp",
                    "malformed or non-exact SMP sentinel",
                    line=line_number,
                )
            online = int(match.group(1))
            total = int(match.group(2))
            if online == 0 or total == 0 or online > MAX_EXPECTED_CPUS or total > MAX_EXPECTED_CPUS:
                raise VerdictError(
                    "malformed_smp",
                    f"SMP counts must be in 1..{MAX_EXPECTED_CPUS}",
                    line=line_number,
                )
            _record_unique("smp", smp_records, (online, total), line_number)

        if BOOT_REPORT_PREFIX in line:
            match = BOOT_REPORT_RE.fullmatch(line)
            if match is None:
                raise VerdictError(
                    "malformed_boot_report",
                    "malformed or non-exact boot-report sentinel",
                    line=line_number,
                )
            result = match.group(1).decode("ascii")
            _record_unique("boot_report", boot_report_records, result, line_number)

        if line == completion_bytes:
            _record_unique("completion", completion_records, completion_sentinel, line_number)
        elif expected_is_smoke_completion:
            other_completion = SMOKE_COMPLETION_RE.fullmatch(line)
            if other_completion is not None:
                other = line.decode("ascii")
                raise VerdictError(
                    "conflicting_completion",
                    f"unexpected smoke completion sentinel: {other}",
                    line=line_number,
                )

        if EXIT_PREFIX in line:
            match = EXIT_RE.fullmatch(line)
            if match is None:
                raise VerdictError(
                    "malformed_exit_record",
                    "malformed or non-exact decoded QEMU exit record",
                    line=line_number,
                )
            qemu_rc = int(match.group(1))
            exit_class = match.group(2).decode("ascii")
            exit_phase = match.group(3).decode("ascii")
            _record_unique(
                "exit_record",
                exit_records,
                (qemu_rc, exit_class, exit_phase),
                line_number,
            )

    if not smp_records:
        raise VerdictError("missing_smp", "exact SMP online sentinel is missing")
    online, total = smp_records[0][0]
    if online != expected_cpus or total != expected_cpus:
        raise VerdictError(
            "smp_count_mismatch",
            f"expected {expected_cpus}/{expected_cpus}, observed {online}/{total}",
            line=smp_records[0][1],
        )

    if not boot_report_records:
        raise VerdictError("missing_boot_report", "boot-report result sentinel is missing")
    boot_result = boot_report_records[0][0]
    if boot_result != "pass":
        raise VerdictError(
            "boot_report_not_pass",
            f"boot-report result is {boot_result}",
            line=boot_report_records[0][1],
        )

    if not completion_records:
        raise VerdictError("missing_completion", "completion sentinel is missing")

    smp_line = smp_records[0][1]
    boot_report_line = boot_report_records[0][1]
    completion_line = completion_records[0][1]
    if not smp_line < boot_report_line < completion_line:
        raise VerdictError(
            "record_order",
            "required order is SMP sentinel, boot-report pass, completion sentinel",
        )

    qemu_rc: int | None = None
    observed_exit_class: str | None = None
    if exit_records:
        if exit_records[0][1] <= completion_line:
            raise VerdictError(
                "record_order",
                "decoded host exit record must follow the serial completion sentinel",
                line=exit_records[0][1],
            )
        qemu_rc, observed_exit_class, _ = exit_records[0][0]
        if qemu_rc != 33 or observed_exit_class != "pass":
            raise VerdictError(
                "exit_not_pass",
                f"expected qemu_rc=33 exit_class=pass, observed qemu_rc={qemu_rc} exit_class={observed_exit_class}",
                line=exit_records[0][1],
            )

    if expected_exit_class == "pass" and not exit_records:
        raise VerdictError(
            "missing_exit_record",
            "decoded qemu_rc=33 exit_class=pass record is missing",
        )

    return {
        "boot_report": "pass",
        "code": "pass",
        "completion": completion_sentinel,
        "exit_class": observed_exit_class or "not-applicable",
        "expected_cpus": expected_cpus,
        "ok": True,
        "qemu_rc": qemu_rc,
        "smp_online": online,
        "smp_total": total,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("log", type=Path, help="preserved serial/runner boot log")
    parser.add_argument("--expected-cpus", type=int, required=True)
    parser.add_argument("--completion-sentinel", required=True)
    parser.add_argument(
        "--expected-exit-class",
        choices=EXPECTED_EXIT_CLASSES,
        required=True,
        help="pass requires the decoded qemu_rc=33 record; not-applicable does not",
    )
    return parser


def _emit(payload: dict[str, object]) -> None:
    print(json.dumps(payload, ensure_ascii=True, separators=(",", ":"), sort_keys=True))


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        payload = verify_boot_log(
            args.log,
            expected_cpus=args.expected_cpus,
            completion_sentinel=args.completion_sentinel,
            expected_exit_class=args.expected_exit_class,
        )
    except VerdictError as exc:
        _emit(exc.payload())
        return 1
    _emit(payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
