#!/usr/bin/env python3
"""Gate the native syscall IDL, legacy enum, and dispatcher case bijection.

The v1 IDL migration still leaves the dispatch switch handwritten.  This tool
is a deliberately bounded bridge: it proves that every implemented IDL row has
one exact enum value and one top-level ``switch (num)`` case, while reserved or
retired rows have no dispatch case.  It also emits a deterministic migration
classification for each case without pretending to parse all of C++.

Default operation is a quiet gate.  ``--report`` is the only mode that writes
compact JSON to stdout; failures otherwise go to stderr.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence


MAX_IDL_BYTES = 2 * 1024 * 1024
MAX_HEADER_BYTES = 2 * 1024 * 1024
MAX_SOURCE_BYTES = 8 * 1024 * 1024
MAX_TOKENS = 1_000_000
MAX_SYSCALL_ROWS = 4096
MAX_SYSCALL_NUMBER = 0xFFFF

SYSCALL_NAME_RE = re.compile(r"SYS_[A-Z0-9_]+\Z")
INTEGER_RE = re.compile(r"(?:0[xX][0-9A-Fa-f]+|[0-9]+)(?:[uUlL]*)\Z")
IDENTIFIER_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
IDL_STATUSES = {"implemented", "reserved", "retired"}

CONTROL_CALL_NAMES = {
    "alignof",
    "catch",
    "decltype",
    "for",
    "if",
    "noexcept",
    "requires",
    "sizeof",
    "static_assert",
    "switch",
    "while",
}
CONTROL_FLOW_NAMES = {"catch", "do", "for", "goto", "if", "switch", "try", "while"}


class AuditError(RuntimeError):
    """Raised when a bounded input cannot be parsed safely."""


@dataclass(frozen=True)
class Token:
    value: str
    offset: int
    line: int


@dataclass(frozen=True)
class IdlRow:
    name: str
    number: int
    status: str


@dataclass(frozen=True)
class EnumRow:
    name: str
    number: int
    line: int


@dataclass(frozen=True)
class DispatchCase:
    name: str
    line: int
    classification: str
    delegate: str | None


def read_bounded_text(path: Path, limit: int, label: str) -> str:
    """Read one UTF-8 input without allowing an accidental unbounded slurp."""

    try:
        size = path.stat().st_size
    except OSError as exc:
        raise AuditError(f"cannot stat {label} {path}: {exc}") from exc
    if size > limit:
        raise AuditError(f"{label} exceeds {limit} bytes: {path}")
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise AuditError(f"cannot read {label} {path}: {exc}") from exc
    if len(raw) > limit:
        raise AuditError(f"{label} exceeds {limit} bytes while reading: {path}")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise AuditError(f"{label} is not valid UTF-8: {path}:{exc.start}") from exc


def _skip_quoted(text: str, start: int, quote: str, line: int, source: str) -> tuple[int, int]:
    index = start + 1
    while index < len(text):
        char = text[index]
        if char == "\\":
            if index + 1 >= len(text):
                break
            if text[index + 1] == "\n":
                line += 1
            index += 2
            continue
        if char == quote:
            return index + 1, line
        if char == "\n":
            raise AuditError(f"{source}:{line}: unterminated quoted literal")
        index += 1
    raise AuditError(f"{source}:{line}: unterminated quoted literal")


def _raw_string_prefix_length(text: str, index: int) -> int:
    for prefix in ("u8R\"", "uR\"", "UR\"", "LR\"", "R\""):
        if text.startswith(prefix, index):
            return len(prefix)
    return 0


def _skip_raw_string(text: str, start: int, prefix_length: int, line: int, source: str) -> tuple[int, int]:
    delimiter_start = start + prefix_length
    open_paren = text.find("(", delimiter_start, min(len(text), delimiter_start + 17))
    if open_paren < 0:
        raise AuditError(f"{source}:{line}: malformed raw-string delimiter")
    delimiter = text[delimiter_start:open_paren]
    if any(char.isspace() or char in "\\()" for char in delimiter):
        raise AuditError(f"{source}:{line}: malformed raw-string delimiter")
    terminator = ")" + delimiter + '"'
    end = text.find(terminator, open_paren + 1)
    if end < 0:
        raise AuditError(f"{source}:{line}: unterminated raw string")
    final = end + len(terminator)
    line += text[start:final].count("\n")
    return final, line


def lex_cpp(text: str, source: str) -> list[Token]:
    """Tokenize only the C++ structure needed by the bounded audit.

    Comments, literals, and preprocessor directives are discarded so fake
    ``case`` labels or braces in hostile text cannot affect nesting.
    """

    tokens: list[Token] = []
    index = 0
    line = 1
    at_line_start = True
    length = len(text)

    def append(value: str, offset: int, token_line: int) -> None:
        tokens.append(Token(value, offset, token_line))
        if len(tokens) > MAX_TOKENS:
            raise AuditError(f"{source}: token limit {MAX_TOKENS} exceeded")

    while index < length:
        char = text[index]
        if char.isspace():
            if char == "\n":
                line += 1
                at_line_start = True
            index += 1
            continue

        if at_line_start and char == "#":
            while index < length:
                newline = text.find("\n", index)
                if newline < 0:
                    index = length
                    break
                continued = text[index:newline].rstrip("\r").endswith("\\")
                index = newline + 1
                line += 1
                if not continued:
                    break
            at_line_start = True
            continue

        if text.startswith("//", index):
            newline = text.find("\n", index + 2)
            index = length if newline < 0 else newline
            continue
        if text.startswith("/*", index):
            end = text.find("*/", index + 2)
            if end < 0:
                raise AuditError(f"{source}:{line}: unterminated block comment")
            segment = text[index : end + 2]
            line += segment.count("\n")
            if "\n" in segment:
                at_line_start = True
            index = end + 2
            continue

        raw_prefix_length = _raw_string_prefix_length(text, index)
        if raw_prefix_length != 0:
            index, line = _skip_raw_string(text, index, raw_prefix_length, line, source)
            at_line_start = False
            continue
        if char in {'"', "'"}:
            index, line = _skip_quoted(text, index, char, line, source)
            at_line_start = False
            continue

        token_line = line
        token_start = index
        if char.isalpha() or char == "_":
            index += 1
            while index < length and (text[index].isalnum() or text[index] == "_"):
                index += 1
            append(text[token_start:index], token_start, token_line)
        elif char.isdigit():
            index += 1
            while index < length and (text[index].isalnum() or text[index] in "_'"):
                index += 1
            append(text[token_start:index], token_start, token_line)
        elif text.startswith("::", index) or text.startswith("->", index):
            append(text[index : index + 2], token_start, token_line)
            index += 2
        else:
            append(char, token_start, token_line)
            index += 1
        at_line_start = False
    return tokens


def _find_matching(tokens: Sequence[Token], opening: int, open_value: str, close_value: str, source: str) -> int:
    if opening >= len(tokens) or tokens[opening].value != open_value:
        raise AuditError(f"{source}: internal delimiter mismatch")
    depth = 0
    for index in range(opening, len(tokens)):
        if tokens[index].value == open_value:
            depth += 1
        elif tokens[index].value == close_value:
            depth -= 1
            if depth == 0:
                return index
            if depth < 0:
                break
    raise AuditError(f"{source}:{tokens[opening].line}: unmatched {open_value}")


def _parse_integer(token: Token, source: str) -> int:
    if not INTEGER_RE.fullmatch(token.value):
        raise AuditError(f"{source}:{token.line}: expected a literal integer, got {token.value!r}")
    literal = re.sub(r"[uUlL]+\Z", "", token.value)
    number = int(literal, 0)
    if number > MAX_SYSCALL_NUMBER:
        raise AuditError(f"{source}:{token.line}: syscall number {number} exceeds {MAX_SYSCALL_NUMBER}")
    return number


def parse_idl(text: str, source: str) -> list[IdlRow]:
    try:
        document = json.loads(text)
    except json.JSONDecodeError as exc:
        raise AuditError(f"{source}:{exc.lineno}: invalid JSON: {exc.msg}") from exc
    if not isinstance(document, dict) or not isinstance(document.get("syscalls"), list):
        raise AuditError(f"{source}: root.syscalls must be an array")
    raw_rows = document["syscalls"]
    if not raw_rows or len(raw_rows) > MAX_SYSCALL_ROWS:
        raise AuditError(f"{source}: syscall row count must be 1..{MAX_SYSCALL_ROWS}")

    rows: list[IdlRow] = []
    names: set[str] = set()
    numbers: dict[int, str] = {}
    previous_number = -1
    for index, raw in enumerate(raw_rows):
        where = f"{source}:syscalls[{index}]"
        if not isinstance(raw, dict):
            raise AuditError(f"{where}: row must be an object")
        name = raw.get("name")
        number = raw.get("number")
        status = raw.get("status")
        if not isinstance(name, str) or SYSCALL_NAME_RE.fullmatch(name) is None:
            raise AuditError(f"{where}: invalid syscall name")
        if isinstance(number, bool) or not isinstance(number, int) or not 0 <= number <= MAX_SYSCALL_NUMBER:
            raise AuditError(f"{where}: number must be an integer in 0..{MAX_SYSCALL_NUMBER}")
        if status not in IDL_STATUSES:
            raise AuditError(f"{where}: unsupported status {status!r}")
        if name in names:
            raise AuditError(f"{where}: duplicate syscall name {name}")
        if number in numbers:
            raise AuditError(f"{where}: number {number} is shared by {numbers[number]} and {name}")
        if number <= previous_number:
            raise AuditError(f"{where}: rows must be strictly ordered by number")
        names.add(name)
        numbers[number] = name
        previous_number = number
        rows.append(IdlRow(name, number, status))
    return rows


def _enum_body(tokens: Sequence[Token], source: str) -> tuple[int, int]:
    candidates: list[tuple[int, int]] = []
    for index, token in enumerate(tokens):
        if token.value != "enum":
            continue
        cursor = index + 1
        if cursor < len(tokens) and tokens[cursor].value in {"class", "struct"}:
            cursor += 1
        if cursor >= len(tokens) or tokens[cursor].value != "SyscallNumber":
            continue
        while cursor < len(tokens) and tokens[cursor].value not in {"{", ";"}:
            cursor += 1
        if cursor >= len(tokens) or tokens[cursor].value != "{":
            raise AuditError(f"{source}:{token.line}: SyscallNumber enum has no body")
        candidates.append((cursor, _find_matching(tokens, cursor, "{", "}", source)))
    if len(candidates) != 1:
        raise AuditError(f"{source}: expected one SyscallNumber enum, found {len(candidates)}")
    return candidates[0]


def parse_enum(text: str, source: str) -> list[EnumRow]:
    tokens = lex_cpp(text, source)
    opening, closing = _enum_body(tokens, source)
    segments: list[list[Token]] = []
    start = opening + 1
    depth = 0
    for index in range(opening + 1, closing):
        value = tokens[index].value
        if value in {"(", "[", "{"}:
            depth += 1
        elif value in {")",
            "]",
            "}",
        }:
            depth -= 1
            if depth < 0:
                raise AuditError(f"{source}:{tokens[index].line}: malformed enum expression")
        elif value == "," and depth == 0:
            if start < index:
                segments.append(list(tokens[start:index]))
            start = index + 1
    if start < closing:
        segments.append(list(tokens[start:closing]))
    if not segments or len(segments) > MAX_SYSCALL_ROWS:
        raise AuditError(f"{source}: SyscallNumber enum row count must be 1..{MAX_SYSCALL_ROWS}")

    rows: list[EnumRow] = []
    names: set[str] = set()
    numbers: dict[int, str] = {}
    for segment in segments:
        values = [token.value for token in segment]
        if len(segment) != 3 or values[1] != "=" or SYSCALL_NAME_RE.fullmatch(values[0]) is None:
            raise AuditError(f"{source}:{segment[0].line}: unsupported SyscallNumber entry {' '.join(values)!r}")
        name = values[0]
        number = _parse_integer(segment[2], source)
        if name in names:
            raise AuditError(f"{source}:{segment[0].line}: duplicate enum name {name}")
        if number in numbers:
            raise AuditError(
                f"{source}:{segment[0].line}: enum number {number} is shared by {numbers[number]} and {name}"
            )
        names.add(name)
        numbers[number] = name
        rows.append(EnumRow(name, number, segment[0].line))
    return rows


def _syscall_switch_body(tokens: Sequence[Token], source: str) -> tuple[int, int]:
    candidates: list[tuple[int, int]] = []
    for index, token in enumerate(tokens):
        if token.value != "switch" or index + 1 >= len(tokens) or tokens[index + 1].value != "(":
            continue
        paren_close = _find_matching(tokens, index + 1, "(", ")", source)
        condition = [item.value for item in tokens[index + 2 : paren_close]]
        while len(condition) >= 2 and condition[0] == "(" and condition[-1] == ")":
            condition = condition[1:-1]
        if condition != ["num"]:
            continue
        brace_open = paren_close + 1
        if brace_open >= len(tokens) or tokens[brace_open].value != "{":
            raise AuditError(f"{source}:{token.line}: switch(num) has no braced body")
        candidates.append((brace_open, _find_matching(tokens, brace_open, "{", "}", source)))
    if len(candidates) != 1:
        raise AuditError(f"{source}: expected one switch(num), found {len(candidates)}")
    return candidates[0]


def _parse_case_name(label: Sequence[Token], source: str) -> str:
    if not label:
        raise AuditError(f"{source}: empty syscall case label")
    values = [token.value for token in label]
    if len(values) == 1 and SYSCALL_NAME_RE.fullmatch(values[0]) is not None:
        return values[0]

    cursor = 0
    if values[0] == "::":
        cursor = 1
    expect_identifier = True
    while cursor < len(values):
        value = values[cursor]
        if expect_identifier:
            if IDENTIFIER_RE.fullmatch(value) is None:
                break
        elif value != "::":
            break
        expect_identifier = not expect_identifier
        cursor += 1
    if cursor == len(values) and not expect_identifier and SYSCALL_NAME_RE.fullmatch(values[-1]) is not None:
        return values[-1]
    raise AuditError(f"{source}:{label[0].line}: unsupported syscall case label {' '.join(values)!r}")


def _qualified_call_target(tokens: Sequence[Token], open_paren: int) -> str | None:
    if open_paren == 0 or IDENTIFIER_RE.fullmatch(tokens[open_paren - 1].value) is None:
        return None
    final = tokens[open_paren - 1].value
    if final in CONTROL_CALL_NAMES:
        return None
    parts = [final]
    cursor = open_paren - 2
    while cursor >= 1 and tokens[cursor].value == "::" and IDENTIFIER_RE.fullmatch(tokens[cursor - 1].value):
        parts.insert(0, tokens[cursor - 1].value)
        cursor -= 2
    return "::".join(parts)


def classify_case(body: Sequence[Token]) -> tuple[str, str | None]:
    values = [token.value for token in body]
    if "switch" in values:
        return "multiplexer", None

    calls: list[str] = []
    for index, token in enumerate(body):
        if token.value != "(":
            continue
        target = _qualified_call_target(body, index)
        if target is not None:
            calls.append(target)
    if len(calls) == 1 and "return" in values and not any(value in CONTROL_FLOW_NAMES for value in values):
        return "delegated_call", calls[0]
    return "inline", None


def parse_dispatch(text: str, source: str) -> tuple[list[DispatchCase], int]:
    tokens = lex_cpp(text, source)
    opening, closing = _syscall_switch_body(tokens, source)
    markers: list[tuple[str, str | None, int, int, int]] = []
    depth = 1
    index = opening + 1
    while index < closing:
        value = tokens[index].value
        if value == "{":
            depth += 1
        elif value == "}":
            depth -= 1
            if depth < 1:
                raise AuditError(f"{source}:{tokens[index].line}: malformed switch body")
        elif depth == 1 and value in {"case", "default"}:
            marker_index = index
            if value == "default":
                if index + 1 >= closing or tokens[index + 1].value != ":":
                    raise AuditError(f"{source}:{tokens[index].line}: malformed default label")
                markers.append(("default", None, tokens[index].line, marker_index, index + 1))
                index += 1
            else:
                label_start = index + 1
                cursor = label_start
                nested = 0
                while cursor < closing:
                    item = tokens[cursor].value
                    if item in {"(", "["}:
                        nested += 1
                    elif item in {")",
                        "]",
                    }:
                        nested -= 1
                    elif item == ":" and nested == 0:
                        break
                    elif item in {"{", "}"} and nested == 0:
                        raise AuditError(f"{source}:{tokens[index].line}: unterminated case label")
                    cursor += 1
                if cursor >= closing:
                    raise AuditError(f"{source}:{tokens[index].line}: unterminated case label")
                name = _parse_case_name(tokens[label_start:cursor], source)
                markers.append(("case", name, tokens[index].line, marker_index, cursor))
                index = cursor
        index += 1

    default_count = sum(1 for marker in markers if marker[0] == "default")
    cases: list[DispatchCase] = []
    seen: dict[str, int] = {}
    for marker_index, marker in enumerate(markers):
        kind, name, line, _start, colon = marker
        if kind != "case" or name is None:
            continue
        if name in seen:
            raise AuditError(f"{source}:{line}: duplicate dispatch case {name}; first at line {seen[name]}")
        seen[name] = line
        body_end = markers[marker_index + 1][3] if marker_index + 1 < len(markers) else closing
        classification, delegate = classify_case(tokens[colon + 1 : body_end])
        cases.append(DispatchCase(name, line, classification, delegate))
    if not cases:
        raise AuditError(f"{source}: switch(num) contains zero syscall cases")
    return cases, default_count


def audit_texts(
    idl_text: str,
    header_text: str,
    source_text: str,
    idl_source: str = "abi/native_syscalls.json",
    header_source: str = "kernel/syscall/syscall.h",
    dispatch_source: str = "kernel/syscall/syscall.cpp",
) -> dict[str, Any]:
    idl_rows = parse_idl(idl_text, idl_source)
    enum_rows = parse_enum(header_text, header_source)
    dispatch_cases, default_count = parse_dispatch(source_text, dispatch_source)

    errors: list[str] = []
    idl_by_name = {row.name: row for row in idl_rows}
    enum_by_name = {row.name: row for row in enum_rows}
    case_by_name = {case.name: case for case in dispatch_cases}

    for row in idl_rows:
        enum_row = enum_by_name.get(row.name)
        if enum_row is None:
            errors.append(f"IDL {row.name}={row.number} is missing from SyscallNumber")
        elif enum_row.number != row.number:
            errors.append(f"IDL {row.name}={row.number} disagrees with enum value {enum_row.number}")
    for row in enum_rows:
        if row.name not in idl_by_name:
            errors.append(f"enum {row.name}={row.number} is missing from the IDL")

    for row in idl_rows:
        case = case_by_name.get(row.name)
        if row.status == "implemented" and case is None:
            errors.append(f"implemented syscall {row.name}={row.number} has no dispatch case")
        elif row.status != "implemented" and case is not None:
            errors.append(f"{row.status} syscall {row.name}={row.number} has a dispatch case at line {case.line}")
    for case in dispatch_cases:
        if case.name not in idl_by_name:
            errors.append(f"dispatch case {case.name} at line {case.line} is missing from the IDL")

    if default_count != 1:
        errors.append(f"dispatch switch must contain exactly one top-level default, found {default_count}")

    errors = sorted(set(errors))
    idl_numbers = {row.number for row in idl_rows}
    minimum = min(idl_numbers)
    maximum = max(idl_numbers)
    unassigned = [number for number in range(minimum, maximum + 1) if number not in idl_numbers]
    nonimplemented = [
        {"name": row.name, "number": row.number, "status": row.status}
        for row in idl_rows
        if row.status != "implemented"
    ]

    case_report: list[dict[str, Any]] = []
    classification_counts = {"delegated_call": 0, "inline": 0, "multiplexer": 0}
    def case_sort_key(item: DispatchCase) -> tuple[int, str]:
        enum_row = enum_by_name.get(item.name)
        return (MAX_SYSCALL_NUMBER if enum_row is None else enum_row.number, item.name)

    for case in sorted(dispatch_cases, key=case_sort_key):
        enum_row = enum_by_name.get(case.name)
        row: dict[str, Any] = {
            "classification": case.classification,
            "line": case.line,
            "name": case.name,
            "number": None if enum_row is None else enum_row.number,
        }
        if case.delegate is not None:
            row["delegate"] = case.delegate
        case_report.append(row)
        classification_counts[case.classification] += 1

    return {
        "cases": case_report,
        "classification_counts": classification_counts,
        "counts": {
            "dispatch": len(dispatch_cases),
            "enum": len(enum_rows),
            "implemented": sum(row.status == "implemented" for row in idl_rows),
            "idl": len(idl_rows),
            "reserved": sum(row.status == "reserved" for row in idl_rows),
            "retired": sum(row.status == "retired" for row in idl_rows),
        },
        "default_case_count": default_count,
        "errors": errors,
        "nonimplemented": nonimplemented,
        "ok": not errors,
        "unassigned_numbers": unassigned,
    }


def audit_repository(root: Path) -> dict[str, Any]:
    idl = root / "abi/native_syscalls.json"
    header = root / "kernel/syscall/syscall.h"
    dispatch = root / "kernel/syscall/syscall.cpp"
    return audit_texts(
        read_bounded_text(idl, MAX_IDL_BYTES, "native syscall IDL"),
        read_bounded_text(header, MAX_HEADER_BYTES, "syscall header"),
        read_bounded_text(dispatch, MAX_SOURCE_BYTES, "syscall dispatcher"),
        str(idl),
        str(header),
        str(dispatch),
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--report", action="store_true", help="emit compact deterministic JSON to stdout")
    args = parser.parse_args(argv)

    try:
        report = audit_repository(args.root.resolve())
    except AuditError as exc:
        if args.report:
            print(json.dumps({"errors": [str(exc)], "ok": False}, separators=(",", ":"), sort_keys=True))
        else:
            print(f"native-syscall-dispatch-bijection: {exc}", file=sys.stderr)
        return 1

    if args.report:
        print(json.dumps(report, separators=(",", ":"), sort_keys=True))
    elif not report["ok"]:
        for error in report["errors"]:
            print(f"native-syscall-dispatch-bijection: {error}", file=sys.stderr)
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
