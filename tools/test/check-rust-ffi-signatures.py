#!/usr/bin/env python3
"""Fail closed when a Rust export and its hand-written C header disagree.

This is a source-level ABI gate.  It compares every ``#[no_mangle]`` or
``#[export_name]`` Rust ``extern`` function in each workspace member with the
same member's C/C++ header declaration.  It deliberately checks only facts
that are representable without invoking a compiler: symbol set, ABI spelling,
return type, arity, scalar widths, pointer depth, and pointee constness.

Struct field layout is a separate contract and is not inferred here.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


MAX_WORKSPACE_MEMBERS = 128
MAX_SOURCE_FILES = 20_000
MAX_FILE_BYTES = 8 * 1024 * 1024
MAX_PARAMETERS = 128
MAX_TYPE_DEPTH = 16
ALLOWED_ABIS = frozenset({"C"})

EXPORT_START_RE = re.compile(
    r"(?P<attrs>(?:\s*#\s*\[[^\]]+\]\s*)+)"
    r"(?P<prefix>(?:(?:pub(?:\s*\([^)]*\))?)\s+)?"
    r"(?P<unsafe>unsafe\s+)?extern(?:\s*\"(?P<abi>[A-Za-z0-9_-]+)\")?\s+fn\s+)"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\(",
    re.MULTILINE,
)
EXPORT_NAME_RE = re.compile(r"export_name\s*=\s*\"([A-Za-z_][A-Za-z0-9_]*)\"")
EXPORT_ATTRIBUTE_RE = re.compile(
    r"^[ \t]*#\s*\[[^\]\r\n]*(?:no_mangle|export_name)[^\]\r\n]*\]",
    re.MULTILINE,
)
STATIC_EXPORT_RE = re.compile(
    r"(?P<attrs>(?:\s*#\s*\[[^\]]+\]\s*)+)"
    r"(?:(?:pub(?:\s*\([^)]*\))?)\s+)?static\s+(?:mut\s+)?"
    r"[A-Za-z_][A-Za-z0-9_]*\s*:",
    re.MULTILINE,
)
HEADER_DECL_RE = re.compile(
    r"\b(?P<name>(?:duetos|duetfs)_[A-Za-z_][A-Za-z0-9_]*)\s*"
    r"\((?P<params>[^;{}]*)\)\s*;",
    re.DOTALL,
)


# All entries collapse to an ABI-level scalar spelling.  Project-native names
# stay distinct where their semantic width matters (notably usize/isize).
SCALAR_ALIASES = {
    "void": "void",
    "()": "void",
    "bool": "bool",
    "u8": "u8",
    "uint8_t": "u8",
    "unsignedchar": "u8",
    "c_uchar": "u8",
    "i8": "i8",
    "int8_t": "i8",
    "signedchar": "i8",
    "c_schar": "i8",
    "c_char": "i8",
    "u16": "u16",
    "uint16_t": "u16",
    "unsignedshort": "u16",
    "c_ushort": "u16",
    "i16": "i16",
    "int16_t": "i16",
    "short": "i16",
    "signedshort": "i16",
    "c_short": "i16",
    "u32": "u32",
    "uint32_t": "u32",
    "unsignedint": "u32",
    "c_uint": "u32",
    "i32": "i32",
    "int32_t": "i32",
    "int": "i32",
    "signedint": "i32",
    "c_int": "i32",
    "u64": "u64",
    "uint64_t": "u64",
    "unsignedlonglong": "u64",
    "c_ulonglong": "u64",
    "i64": "i64",
    "int64_t": "i64",
    "longlong": "i64",
    "signedlonglong": "i64",
    "c_longlong": "i64",
    "usize": "usize",
    "size_t": "usize",
    "isize": "isize",
    "ptrdiff_t": "isize",
    "c_void": "void",
}


# DuetFS predates the Duetos* naming convention.  Its Rust-side ABI mirrors use
# explicit prefixes while its C++ header exposes shorter names in a namespace.
# These are names only: signature parity still checks pointer depth/constness.
NAMED_TYPE_ALIASES: dict[str, dict[str, str]] = {
    "kernel/fs/duetfs": {
        "DuetFsDevice": "Device",
        "DuetFsLookupResult": "LookupResult",
        "DuetFsDirEntry": "DirEntry",
        "DuetFsFsckReport": "FsckReport",
    }
}


@dataclass(frozen=True)
class Finding:
    code: str
    path: str
    line: int
    message: str


@dataclass(frozen=True)
class TypeShape:
    kind: str
    name: str = ""
    access: str = ""
    inner: "TypeShape | None" = None

    @staticmethod
    def value(name: str) -> "TypeShape":
        return TypeShape("value", name=name)

    @staticmethod
    def pointer(access: str, inner: "TypeShape") -> "TypeShape":
        return TypeShape("pointer", access=access, inner=inner)

    def render(self) -> str:
        if self.kind == "value":
            return self.name
        assert self.inner is not None
        return f"*{self.access} {self.inner.render()}"


@dataclass(frozen=True)
class Signature:
    member: str
    name: str
    path: Path
    line: int
    abi: str
    result: TypeShape
    parameters: tuple[TypeShape, ...]


class ParseFailure(ValueError):
    pass


def strip_comments(text: str) -> str:
    """Remove nested Rust/C comments while retaining offsets and strings."""
    output = list(text)
    index = 0
    state = "code"
    depth = 0
    while index < len(text):
        current = text[index]
        following = text[index + 1] if index + 1 < len(text) else ""
        if state == "code":
            if current == '"':
                state = "string"
            elif current == "'":
                # Do not confuse Rust lifetimes with character literals.
                if re.match(r"'(?:\\.|[^\\'])'", text[index : index + 5]):
                    state = "character"
            elif current == "/" and following == "/":
                output[index] = output[index + 1] = " "
                index += 1
                state = "line_comment"
            elif current == "/" and following == "*":
                output[index] = output[index + 1] = " "
                index += 1
                state = "block_comment"
                depth = 1
        elif state in {"string", "character"}:
            delimiter = '"' if state == "string" else "'"
            if current == "\\":
                index += 1
            elif current == delimiter:
                state = "code"
        elif state == "line_comment":
            if current == "\n":
                state = "code"
            else:
                output[index] = " "
        elif state == "block_comment":
            if current == "/" and following == "*":
                output[index] = output[index + 1] = " "
                index += 1
                depth += 1
            elif current == "*" and following == "/":
                output[index] = output[index + 1] = " "
                index += 1
                depth -= 1
                if depth == 0:
                    state = "code"
            elif current != "\n":
                output[index] = " "
        index += 1
    return "".join(output)


def matching_delimiter(text: str, opening: int, left: str, right: str) -> int | None:
    depth = 0
    for index in range(opening, len(text)):
        if text[index] == left:
            depth += 1
            if depth > MAX_TYPE_DEPTH * 4:
                return None
        elif text[index] == right:
            depth -= 1
            if depth == 0:
                return index
            if depth < 0:
                return None
    return None


def split_top_level(text: str) -> list[str]:
    parts: list[str] = []
    start = 0
    depths = {"(": 0, "[": 0, "<": 0}
    closes = {")": "(", "]": "[", ">": "<"}
    for index, character in enumerate(text):
        if character in depths:
            depths[character] += 1
        elif character in closes:
            key = closes[character]
            if depths[key] == 0:
                raise ParseFailure(f"unbalanced delimiter {character!r}")
            depths[key] -= 1
        elif character == "," and not any(depths.values()):
            parts.append(text[start:index].strip())
            start = index + 1
    if any(depths.values()):
        raise ParseFailure("unterminated nested declarator")
    tail = text[start:].strip()
    if tail:
        parts.append(tail)
    if len(parts) > MAX_PARAMETERS:
        raise ParseFailure(f"signature exceeds {MAX_PARAMETERS} parameters")
    return parts


def canonical_value_name(raw: str) -> str:
    name = re.sub(r"\b(?:core|std)::ffi::", "", raw.strip())
    name = re.sub(r"\s+", "", name)
    if "::" in name:
        name = name.rsplit("::", 1)[1]
    return SCALAR_ALIASES.get(name, name)


def parse_rust_type(raw: str, depth: int = 0) -> TypeShape:
    if depth > MAX_TYPE_DEPTH:
        raise ParseFailure(f"Rust type nesting exceeds {MAX_TYPE_DEPTH}")
    text = raw.strip()
    pointer = re.match(r"^\*\s*(const|mut)\s+(.+)$", text, re.DOTALL)
    if pointer:
        return TypeShape.pointer(pointer.group(1), parse_rust_type(pointer.group(2), depth + 1))
    if text in {"", "()"}:
        return TypeShape.value("void")
    if text == "!":
        return TypeShape.value("never")
    if any(token in text for token in ("&", "[", "]", "(", ")", "<", ">")):
        raise ParseFailure(f"unsupported Rust FFI type {text!r}")
    return TypeShape.value(canonical_value_name(text))


def parse_c_type(raw: str, array_dimensions: int = 0) -> TypeShape:
    text = raw.strip()
    if not text:
        raise ParseFailure("missing C/C++ type")
    if any(token in text for token in ("(", ")", "&", "[", "]", "<", ">")):
        raise ParseFailure(f"unsupported C/C++ declarator {text!r}")
    if re.search(r"\b(?:volatile|restrict|__restrict|__restrict__)\b", text):
        raise ParseFailure(f"unsupported C/C++ qualifier in {text!r}")
    text = re.sub(r"\b(?:struct|class|enum)\s+", "", text)
    pieces = text.split("*")
    if len(pieces) - 1 + array_dimensions > MAX_TYPE_DEPTH:
        raise ParseFailure(f"C/C++ type nesting exceeds {MAX_TYPE_DEPTH}")

    base_piece = pieces[0]
    base_const = bool(re.search(r"\bconst\b", base_piece))
    base_piece = re.sub(r"\bconst\b", "", base_piece)
    base_piece = re.sub(r"\s+", "", base_piece)
    if not base_piece:
        raise ParseFailure(f"missing pointee/base type in {raw!r}")
    shape = TypeShape.value(canonical_value_name(base_piece))

    # In ``const u8**``, const qualifies u8; subsequent empty pointer
    # qualifier groups mean mutable pointees.  In ``u8* const*``, the const
    # after the first star qualifies that pointer as the next pointee.
    target_const = base_const
    for qualifier in pieces[1:]:
        unknown = re.sub(r"\bconst\b", "", qualifier).strip()
        if unknown:
            raise ParseFailure(f"unsupported pointer qualifier {qualifier!r} in {raw!r}")
        shape = TypeShape.pointer("const" if target_const else "mut", shape)
        target_const = bool(re.search(r"\bconst\b", qualifier))

    # A function parameter declared as T name[N] adjusts to T*.  Additional
    # dimensions would require representing pointer-to-array and are rejected.
    if array_dimensions > 1:
        raise ParseFailure("multidimensional C array parameters are unsupported")
    if array_dimensions == 1:
        shape = TypeShape.pointer("const" if target_const else "mut", shape)
    return shape


def parse_rust_parameter(raw: str) -> TypeShape:
    if ":" not in raw:
        raise ParseFailure(f"Rust parameter lacks a type: {raw!r}")
    name, type_text = raw.split(":", 1)
    if not re.fullmatch(r"\s*(?:mut\s+)?[A-Za-z_][A-Za-z0-9_]*\s*", name):
        raise ParseFailure(f"unsupported Rust parameter pattern {name.strip()!r}")
    return parse_rust_type(type_text)


def parse_c_parameter(raw: str) -> TypeShape:
    text = re.sub(r"\s*=.*$", "", raw.strip(), flags=re.DOTALL)
    if not text or text == "void":
        raise ParseFailure("void/empty must be the entire parameter list")
    if "(*" in text or re.search(r"\(\s*\*", text):
        raise ParseFailure(f"inline function-pointer declarator is unsupported: {text!r}")
    match = re.match(
        r"^(?P<type>.+?)(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*"
        r"(?P<arrays>(?:\[[^\]]*\]\s*)*)$",
        text,
        re.DOTALL,
    )
    if not match:
        raise ParseFailure(f"cannot separate C/C++ parameter name in {text!r}")
    type_text = match.group("type").strip()
    if type_text.endswith("::"):
        raise ParseFailure(f"invalid C/C++ parameter type {type_text!r}")
    dimensions = match.group("arrays").count("[")
    return parse_c_type(type_text, dimensions)


def read_text(path: Path) -> str:
    try:
        size = path.stat().st_size
    except OSError as error:
        raise ParseFailure(f"cannot stat file: {error}") from error
    if size > MAX_FILE_BYTES:
        raise ParseFailure(f"file exceeds {MAX_FILE_BYTES} bytes")
    try:
        return path.read_text(encoding="utf-8", errors="strict")
    except (OSError, UnicodeError) as error:
        raise ParseFailure(f"cannot read UTF-8 file: {error}") from error


def parse_rust_exports_text(member: str, path: Path, original: str) -> list[Signature]:
    code = strip_comments(original)
    signatures: list[Signature] = []
    covered_attribute_ranges: list[tuple[int, int]] = []
    for match in EXPORT_START_RE.finditer(code):
        attrs = match.group("attrs")
        if "no_mangle" not in attrs and "export_name" not in attrs:
            continue
        covered_attribute_ranges.append((match.start("attrs"), match.end()))
        opening = match.end() - 1
        closing = matching_delimiter(code, opening, "(", ")")
        if closing is None:
            raise ParseFailure("unterminated Rust export parameter list")
        body = code.find("{", closing)
        semicolon = code.find(";", closing)
        terminators = [position for position in (body, semicolon) if position >= 0]
        if not terminators:
            raise ParseFailure("Rust export lacks a body or declaration terminator")
        end = min(terminators)
        tail = code[closing + 1 : end].strip()
        if tail:
            if not tail.startswith("->"):
                raise ParseFailure(f"unsupported Rust return clause {tail!r}")
            result = parse_rust_type(tail[2:])
        else:
            result = TypeShape.value("void")
        raw_parameters = split_top_level(code[opening + 1 : closing])
        parameters = tuple(parse_rust_parameter(parameter) for parameter in raw_parameters)
        export_name = EXPORT_NAME_RE.search(attrs)
        name = export_name.group(1) if export_name else match.group("name")
        signatures.append(
            Signature(
                member=member,
                name=name,
                path=path,
                line=original.count("\n", 0, match.start("prefix")) + 1,
                abi=match.group("abi") or "C",
                result=result,
                parameters=parameters,
            )
        )
    # Scalar statics are outside function-signature parity, but recognizing
    # them prevents the fail-closed export-attribute sweep from misclassifying
    # the four intentional DuetFS constants.
    for match in STATIC_EXPORT_RE.finditer(code):
        attrs = match.group("attrs")
        if "no_mangle" in attrs or "export_name" in attrs:
            covered_attribute_ranges.append((match.start("attrs"), match.end()))
    for attribute in EXPORT_ATTRIBUTE_RE.finditer(code):
        if not any(start <= attribute.start() < end for start, end in covered_attribute_ranges):
            line = original.count("\n", 0, attribute.start()) + 1
            raise ParseFailure(f"line {line}: export attribute is not attached to a recognized extern function/static")
    return signatures


def parse_header_declarations_text(member: str, path: Path, original: str) -> list[Signature]:
    code = strip_comments(original)
    signatures: list[Signature] = []
    for match in HEADER_DECL_RE.finditer(code):
        boundary = (
            max(
                code.rfind(";", 0, match.start("name")),
                code.rfind("{", 0, match.start("name")),
                code.rfind("}", 0, match.start("name")),
            )
            + 1
        )
        return_text = code[boundary : match.start("name")].strip()
        return_text = re.sub(r"\b(?:extern\s+\"C\"|inline|static|constexpr)\b", "", return_text).strip()
        result = parse_c_type(return_text)
        parameter_text = match.group("params").strip()
        if parameter_text in {"", "void"}:
            parameters: tuple[TypeShape, ...] = ()
        else:
            parameters = tuple(parse_c_parameter(parameter) for parameter in split_top_level(parameter_text))
        signatures.append(
            Signature(
                member=member,
                name=match.group("name"),
                path=path,
                line=original.count("\n", 0, match.start("name")) + 1,
                abi="C",
                result=result,
                parameters=parameters,
            )
        )
    return signatures


def canonical_named_shape(member: str, shape: TypeShape) -> TypeShape:
    if shape.kind == "value":
        mapped = NAMED_TYPE_ALIASES.get(member, {}).get(shape.name, shape.name)
        return TypeShape.value(mapped)
    assert shape.inner is not None
    return TypeShape.pointer(shape.access, canonical_named_shape(member, shape.inner))


def compare_signatures(rust: Signature, header: Signature) -> list[str]:
    mismatches: list[str] = []
    if rust.abi not in ALLOWED_ABIS:
        mismatches.append(f"unsupported Rust ABI {rust.abi!r}")
    rust_result = canonical_named_shape(rust.member, rust.result)
    header_result = canonical_named_shape(header.member, header.result)
    if rust_result != header_result:
        mismatches.append(f"return Rust={rust_result.render()} C={header_result.render()}")
    if len(rust.parameters) != len(header.parameters):
        mismatches.append(f"arity Rust={len(rust.parameters)} C={len(header.parameters)}")
    for index, (rust_parameter, header_parameter) in enumerate(zip(rust.parameters, header.parameters)):
        rust_shape = canonical_named_shape(rust.member, rust_parameter)
        header_shape = canonical_named_shape(header.member, header_parameter)
        if rust_shape != header_shape:
            mismatches.append(
                f"parameter {index + 1} Rust={rust_shape.render()} C={header_shape.render()}"
            )
    return mismatches


def repo_relative(root: Path, path: Path) -> str:
    try:
        return path.resolve().relative_to(root).as_posix()
    except (OSError, ValueError):
        return path.as_posix()


def add_finding(findings: list[Finding], code: str, root: Path, path: Path, line: int, message: str) -> None:
    findings.append(Finding(code, repo_relative(root, path), line, message))


def workspace_members(root: Path) -> list[tuple[str, Path]]:
    manifest = root / "Cargo.toml"
    try:
        with manifest.open("rb") as stream:
            parsed = tomllib.load(stream)
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise ParseFailure(f"cannot parse {manifest}: {error}") from error
    raw_members = parsed.get("workspace", {}).get("members")
    if not isinstance(raw_members, list) or not all(isinstance(member, str) for member in raw_members):
        raise ParseFailure("Cargo.toml workspace.members must be an array of strings")
    if not raw_members or len(raw_members) > MAX_WORKSPACE_MEMBERS:
        raise ParseFailure(f"workspace member count must be 1..{MAX_WORKSPACE_MEMBERS}")
    members: list[tuple[str, Path]] = []
    seen: set[str] = set()
    for raw_member in raw_members:
        normalized = Path(raw_member).as_posix().rstrip("/")
        if normalized in seen:
            raise ParseFailure(f"duplicate workspace member {normalized}")
        seen.add(normalized)
        directory = (root / normalized).resolve()
        try:
            directory.relative_to(root)
        except ValueError as error:
            raise ParseFailure(f"workspace member escapes repository: {raw_member}") from error
        if not directory.is_dir() or not (directory / "Cargo.toml").is_file():
            raise ParseFailure(f"workspace member is missing: {normalized}")
        members.append((normalized, directory))
    return sorted(members)


def collect_signatures(root: Path) -> tuple[list[Signature], list[Signature], list[Finding]]:
    findings: list[Finding] = []
    rust_signatures: list[Signature] = []
    header_signatures: list[Signature] = []
    file_count = 0
    for member, directory in workspace_members(root):
        for patterns, parser, sink in (
            (("*.rs",), parse_rust_exports_text, rust_signatures),
            (("*.h", "*.hh", "*.hpp", "*.hxx"), parse_header_declarations_text, header_signatures),
        ):
            paths = {path for pattern in patterns for path in directory.rglob(pattern)}
            for path in sorted(paths, key=lambda item: item.as_posix()):
                if "target" in path.parts:
                    continue
                file_count += 1
                if file_count > MAX_SOURCE_FILES:
                    raise ParseFailure(f"source inventory exceeds {MAX_SOURCE_FILES} files")
                if path.is_symlink():
                    add_finding(findings, "RFS001", root, path, 0, "FFI source/header may not be a symlink")
                    continue
                try:
                    sink.extend(parser(member, path, read_text(path)))
                except ParseFailure as error:
                    add_finding(findings, "RFS002", root, path, 0, str(error))
    return rust_signatures, header_signatures, findings


def index_unique(
    root: Path,
    signatures: Iterable[Signature],
    side: str,
    findings: list[Finding],
) -> dict[tuple[str, str], Signature]:
    indexed: dict[tuple[str, str], Signature] = {}
    for signature in signatures:
        key = (signature.member, signature.name)
        previous = indexed.get(key)
        if previous is not None:
            add_finding(
                findings,
                "RFS003",
                root,
                signature.path,
                signature.line,
                f"duplicate {side} declaration {signature.name}; first at "
                f"{repo_relative(root, previous.path)}:{previous.line}",
            )
            continue
        indexed[key] = signature
    return indexed


def audit(root: Path) -> tuple[list[Finding], dict[str, int]]:
    rust_signatures, header_signatures, findings = collect_signatures(root)
    rust_by_key = index_unique(root, rust_signatures, "Rust", findings)
    header_by_key = index_unique(root, header_signatures, "header", findings)

    for key in sorted(rust_by_key.keys() - header_by_key.keys()):
        signature = rust_by_key[key]
        add_finding(
            findings,
            "RFS004",
            root,
            signature.path,
            signature.line,
            f"Rust export {signature.name} lacks a same-crate C header declaration",
        )
    for key in sorted(header_by_key.keys() - rust_by_key.keys()):
        signature = header_by_key[key]
        add_finding(
            findings,
            "RFS005",
            root,
            signature.path,
            signature.line,
            f"C header declaration {signature.name} lacks a same-crate Rust export",
        )
    for key in sorted(rust_by_key.keys() & header_by_key.keys()):
        rust = rust_by_key[key]
        header = header_by_key[key]
        for mismatch in compare_signatures(rust, header):
            add_finding(
                findings,
                "RFS006",
                root,
                header.path,
                header.line,
                f"{header.name}: {mismatch}; Rust at {repo_relative(root, rust.path)}:{rust.line}",
            )

    findings.sort(key=lambda item: (item.code, item.path, item.line, item.message))
    summary = {
        "workspace_members": len(workspace_members(root)),
        "rust_functions": len(rust_by_key),
        "header_functions": len(header_by_key),
        "matched_functions": len(rust_by_key.keys() & header_by_key.keys()),
        "findings": len(findings),
    }
    return findings, summary


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--report", action="store_true", help="print deterministic JSON summary on success")
    parser.add_argument("--max-findings", type=int, default=100)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    root = args.repo_root.resolve()
    try:
        findings, summary = audit(root)
    except ParseFailure as error:
        print(f"check-rust-ffi-signatures: ERROR: {error}", file=sys.stderr)
        return 2
    if findings:
        for finding in findings[: max(args.max_findings, 0)]:
            location = finding.path + (f":{finding.line}" if finding.line else "")
            print(f"{finding.code} {location}: {finding.message}")
        if len(findings) > max(args.max_findings, 0):
            print(f"... {len(findings) - max(args.max_findings, 0)} additional finding(s) omitted")
        print(f"check-rust-ffi-signatures: FAIL ({len(findings)} finding(s))")
        return 1
    if args.report:
        print(json.dumps(summary, sort_keys=True, separators=(",", ":")))
    else:
        print(
            "check-rust-ffi-signatures: PASS "
            f"({summary['matched_functions']} functions across {summary['workspace_members']} members)"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
