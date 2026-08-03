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
import os
import re
import stat
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


MAX_WORKSPACE_MEMBERS = 128
MAX_SOURCE_FILES = 20_000
MAX_FILE_BYTES = 8 * 1024 * 1024
MAX_TOTAL_INPUT_BYTES = 64 * 1024 * 1024
MAX_SIGNATURE_RECORDS = 10_000
MAX_FINDINGS = 20_000
MAX_PARAMETERS = 128
MAX_TYPE_DEPTH = 16
MAX_DIAGNOSTIC_CHARS = 2_048
ALLOWED_ABIS = frozenset({"C"})
CANONICAL_CARGO_CONFIG = Path(".cargo/config.toml")
CANONICAL_RUST_TOOLCHAIN = Path("rust-toolchain.toml")
EXPECTED_CARGO_CONFIG = {
    "build": {"target": "x86_64-unknown-none"},
    "unstable": {
        "build-std": ["core", "alloc"],
        "build-std-features": ["compiler-builtins-mem"],
    },
}
EXPECTED_RUST_TOOLCHAIN = {
    "toolchain": {
        "channel": "nightly-2026-01-15",
        "components": ["rust-src"],
        "targets": ["x86_64-unknown-none"],
        "profile": "minimal",
    }
}
SKIP_DIRECTORIES = frozenset({".git", "target", "__pycache__"})
RUST_SUFFIXES = frozenset({".rs"})
HEADER_SUFFIXES = frozenset({".h", ".hh", ".hpp", ".hxx"})
WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT = 0x400
WINDOWS_REPARSE_TAG_NAME_SURROGATE = 0x20000000

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
EXTERN_LINKAGE_BLOCK_RE = re.compile(
    r'\bextern\s*"(?P<abi>[A-Za-z0-9_+.-]+)"\s*\{'
)
EXTERN_LINKAGE_RE = re.compile(r'\bextern\s*"(?P<abi>[A-Za-z0-9_+.-]+)"')
RUST_CALLBACK_FIELD_RE = re.compile(
    r"\bpub\s+(?P<field>[A-Za-z_][A-Za-z0-9_]*)\s*:\s*"
    r"Option\s*<\s*(?P<unsafe>unsafe\s+)?extern(?:\s*\"(?P<abi>[A-Za-z0-9_-]+)\")?\s+fn\s*\(",
    re.MULTILINE,
)
HEADER_CALLBACK_ALIAS_RE = re.compile(
    r"\busing\s+(?P<alias>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*"
    r"(?P<result>[A-Za-z_][A-Za-z0-9_: \t]*)\s*\(\s*\*\s*\)\s*"
    r"\((?P<params>[^;{}]*)\)\s*;",
    re.DOTALL,
)
RUST_PATH_ATTRIBUTE_RE = re.compile(r"#\s*\[[^\]]*\bpath\s*=", re.DOTALL)
RUST_CODE_INCLUDE_RE = re.compile(r"\binclude\s*!\s*[({[]")


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


@dataclass(frozen=True)
class CallbackSignature:
    member: str
    container: str
    field: str
    path: Path
    line: int
    abi: str
    result: TypeShape
    parameters: tuple[TypeShape, ...]


class ParseFailure(ValueError):
    pass


class BudgetExceeded(ParseFailure):
    pass


@dataclass
class TraversalBudget:
    limit: int
    visited: int = 0
    byte_limit: int = MAX_TOTAL_INPUT_BYTES
    visited_bytes: int = 0
    signature_limit: int = MAX_SIGNATURE_RECORDS
    signatures: int = 0

    def count(self) -> None:
        self.visited += 1
        if self.visited > self.limit:
            raise BudgetExceeded(f"source inventory exceeds {self.limit} visited entries")

    def count_bytes(self, amount: int) -> None:
        if amount < 0:
            raise BudgetExceeded("workspace input has a negative byte size")
        self.visited_bytes += amount
        if self.visited_bytes > self.byte_limit:
            raise BudgetExceeded(f"workspace inputs exceed {self.byte_limit} aggregate bytes")

    def count_signatures(self, amount: int) -> None:
        self.signatures += amount
        if self.signatures > self.signature_limit:
            raise BudgetExceeded(f"signature inventory exceeds {self.signature_limit} records")


def bounded_message(message: str) -> str:
    """Keep child-process diagnostics deterministic and memory bounded."""
    normalized = message.replace("\r", "\\r").replace("\n", "\\n")
    if len(normalized) <= MAX_DIAGNOSTIC_CHARS:
        return normalized
    return normalized[:MAX_DIAGNOSTIC_CHARS] + "... diagnostic truncated"


def bounded_repr(value: str) -> str:
    if len(value) <= MAX_DIAGNOSTIC_CHARS:
        return repr(value)
    return repr(value[:MAX_DIAGNOSTIC_CHARS] + "... diagnostic truncated")


def mask_span(output: list[str], start: int, end: int) -> None:
    """Blank one half-open source span without changing offsets or lines."""
    for index in range(start, end):
        if output[index] not in {"\r", "\n"}:
            output[index] = " "


def quoted_literal_end(text: str, opening: int, delimiter: str) -> int | None:
    index = opening + 1
    while index < len(text):
        current = text[index]
        if current == "\\":
            index += 2
            continue
        if current == delimiter:
            return index + 1
        if current in {"\r", "\n"}:
            return None
        index += 1
    return None


def character_literal_end(text: str, opening: int) -> int | None:
    lifetime = re.match(r"'[A-Za-z_][A-Za-z0-9_]*", text[opening:])
    if lifetime:
        token_end = opening + lifetime.end()
        if token_end >= len(text) or text[token_end] != "'":
            return None
    return quoted_literal_end(text, opening, "'")


def syntax_literal_role(output: list[str], opening: int) -> str | None:
    prefix = "".join(output[max(0, opening - 128) : opening])
    if re.search(r"\bextern\s*$", prefix):
        return "abi"
    if re.search(r"\bexport_name\s*=\s*$", prefix):
        return "export_name"
    return None


def mask_comments_and_literals(text: str, preserve_syntax_literals: bool) -> str:
    """Mask comments and literals while preserving byte and line offsets."""
    output = list(text)
    index = 0
    while index < len(text):
        following = text[index + 1] if index + 1 < len(text) else ""

        if text[index] == "/" and following == "/":
            end = text.find("\n", index + 2)
            if end < 0:
                end = len(text)
            mask_span(output, index, end)
            index = end
            continue

        if text[index] == "/" and following == "*":
            depth = 1
            end = index + 2
            while end < len(text) and depth:
                if text.startswith("/*", end):
                    depth += 1
                    end += 2
                elif text.startswith("*/", end):
                    depth -= 1
                    end += 2
                else:
                    end += 1
            if depth:
                raise ParseFailure("unterminated block comment")
            mask_span(output, index, end)
            index = end
            continue

        token_boundary = index == 0 or not (text[index - 1].isalnum() or text[index - 1] == "_")
        if token_boundary:
            rust_raw = re.match(r'(?:br|cr|r)(?P<hashes>#{0,255})"', text[index:])
            if rust_raw:
                hashes = rust_raw.group("hashes")
                close = '"' + hashes
                content_start = index + rust_raw.end()
                closing = text.find(close, content_start)
                if closing < 0:
                    raise ParseFailure("unterminated Rust raw string literal")
                end = closing + len(close)
                mask_span(output, index, end)
                index = end
                continue

            cpp_raw = re.match(
                r'(?:u8|u|U|L)?R"(?P<delimiter>[^ ()\\\t\v\f\r\n]{0,16})\(',
                text[index:],
            )
            if cpp_raw:
                delimiter = cpp_raw.group("delimiter")
                close = ")" + delimiter + '"'
                content_start = index + cpp_raw.end()
                closing = text.find(close, content_start)
                if closing < 0:
                    raise ParseFailure("unterminated C++ raw string literal")
                end = closing + len(close)
                mask_span(output, index, end)
                index = end
                continue

        if text[index] == '"':
            end = quoted_literal_end(text, index, '"')
            if end is None:
                raise ParseFailure("unterminated ordinary string literal")
            role = syntax_literal_role(output, index) if preserve_syntax_literals else None
            value = text[index + 1 : end - 1]
            preserve = (role == "abi" and re.fullmatch(r"[A-Za-z0-9_+.-]+", value)) or (
                role == "export_name" and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", value)
            )
            if not preserve:
                mask_span(output, index, end)
            index = end
            continue

        if text[index] == "'":
            # Rust lifetimes have no closing quote; C++ multi-character
            # literals do. Mask the latter without consuming `'a`/`'static`.
            end = character_literal_end(text, index)
            if end is not None:
                mask_span(output, index, end)
                index = end
                continue

        index += 1
    return "".join(output)


def preprocessor_condition(directive: str, body: str) -> bool:
    expression = re.sub(r"\s+", "", body)
    while expression.startswith("(") and expression.endswith(")"):
        expression = expression[1:-1]

    if directive in {"ifdef", "ifndef"}:
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", expression):
            raise ParseFailure(f"unsupported #{directive} expression {bounded_repr(body.strip())}")
        if expression != "__cplusplus":
            raise ParseFailure(f"unknown preprocessor symbol in #{directive}: {expression}")
        value = True
        return value if directive == "ifdef" else not value

    integer = re.fullmatch(r"([01])(?:[uUlL]*)", expression)
    if integer:
        return integer.group(1) == "1"
    if expression in {"__cplusplus", "defined(__cplusplus)", "defined__cplusplus"}:
        return True
    if expression in {"!__cplusplus", "!defined(__cplusplus)", "!defined__cplusplus"}:
        return False
    raise ParseFailure(f"unsupported preprocessor condition {bounded_repr(body.strip())}")


def mask_preprocessor_regions(text: str) -> str:
    """Evaluate the bounded C++ linkage wrappers and mask inactive text."""
    probe = mask_comments_and_literals(text, preserve_syntax_literals=False)
    output = list(text)
    lines = probe.splitlines(keepends=True)
    offsets: list[tuple[int, int]] = []
    cursor = 0
    for line in lines:
        offsets.append((cursor, cursor + len(line)))
        cursor += len(line)
    if cursor < len(text):
        offsets.append((cursor, len(text)))

    stack: list[dict[str, bool]] = []
    active = True
    line_index = 0
    while line_index < len(offsets):
        start, end = offsets[line_index]
        physical = probe[start:end].rstrip("\r\n")
        hash_mark = re.match(r"^[ \t]*#", physical)
        rust_attribute = hash_mark is not None and physical[hash_mark.end() :].lstrip().startswith(("[", "!["))
        if hash_mark is None or rust_attribute:
            if not active:
                mask_span(output, start, end)
            line_index += 1
            continue

        logical_parts: list[str] = []
        final_line = line_index
        while True:
            part_start, part_end = offsets[final_line]
            part = probe[part_start:part_end].rstrip("\r\n")
            continued = part.rstrip().endswith("\\")
            logical_parts.append(part.rstrip()[:-1] if continued else part)
            mask_span(output, part_start, part_end)
            if not continued:
                break
            final_line += 1
            if final_line >= len(offsets):
                raise ParseFailure("unterminated preprocessor line continuation")

        logical = " ".join(logical_parts)
        directive_match = re.match(r"^[ \t]*#[ \t]*(?P<name>[A-Za-z_][A-Za-z0-9_]*)(?P<body>.*)$", logical)
        if directive_match:
            directive = directive_match.group("name")
            body = directive_match.group("body").strip()
            if directive in {"if", "ifdef", "ifndef"}:
                parent_active = active
                condition = preprocessor_condition(directive, body) if parent_active else False
                frame = {
                    "parent_active": parent_active,
                    "branch_taken": condition,
                    "active": parent_active and condition,
                    "saw_else": False,
                }
                stack.append(frame)
                active = frame["active"]
            elif directive == "elif":
                if not stack:
                    raise ParseFailure("#elif without matching #if")
                frame = stack[-1]
                if frame["saw_else"]:
                    raise ParseFailure("#elif after #else")
                condition = (
                    preprocessor_condition("if", body)
                    if frame["parent_active"] and not frame["branch_taken"]
                    else False
                )
                frame["active"] = frame["parent_active"] and not frame["branch_taken"] and condition
                frame["branch_taken"] = frame["branch_taken"] or condition
                active = frame["active"]
            elif directive == "else":
                if not stack:
                    raise ParseFailure("#else without matching #if")
                frame = stack[-1]
                if frame["saw_else"] or body:
                    raise ParseFailure("invalid or duplicate #else")
                frame["saw_else"] = True
                frame["active"] = frame["parent_active"] and not frame["branch_taken"]
                frame["branch_taken"] = True
                active = frame["active"]
            elif directive == "endif":
                if not stack:
                    raise ParseFailure("#endif without matching #if")
                if body:
                    raise ParseFailure("invalid tokens after #endif")
                frame = stack.pop()
                active = frame["parent_active"]

        line_index = final_line + 1

    if stack:
        raise ParseFailure("unterminated preprocessor conditional")
    return "".join(output)


def strip_comments(text: str, *, preprocess: bool = True) -> str:
    """Return an offset-preserving code view with non-code decoys masked."""
    preprocessed = mask_preprocessor_regions(text) if preprocess else text
    return mask_comments_and_literals(preprocessed, preserve_syntax_literals=True)


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


def extern_linkage_block_ranges(code: str) -> list[tuple[int, int, str]]:
    ranges: list[tuple[int, int, str]] = []
    for match in EXTERN_LINKAGE_BLOCK_RE.finditer(code):
        opening = code.find("{", match.start(), match.end())
        closing = matching_delimiter(code, opening, "{", "}")
        if closing is None:
            raise ParseFailure(f"unterminated extern {match.group('abi')!r} linkage block")
        ranges.append((opening + 1, closing, match.group("abi")))
    return ranges


def has_c_linkage(
    code: str,
    position: int,
    declaration_start: int,
    ranges: list[tuple[int, int, str]],
) -> bool:
    direct = list(EXTERN_LINKAGE_RE.finditer(code[declaration_start:position]))
    if direct:
        return direct[-1].group("abi") == "C"
    containing = [(start, end, abi) for start, end, abi in ranges if start <= position < end]
    if not containing:
        return False
    # Nested linkage specifications are legal; the innermost one owns the
    # declaration's language linkage.
    return max(containing, key=lambda item: item[0])[2] == "C"


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
        raise ParseFailure(f"unsupported Rust FFI type {bounded_repr(text)}")
    return TypeShape.value(canonical_value_name(text))


def parse_c_type(raw: str, array_dimensions: int = 0) -> TypeShape:
    text = raw.strip()
    if not text:
        raise ParseFailure("missing C/C++ type")
    if any(token in text for token in ("(", ")", "&", "[", "]", "<", ">")):
        raise ParseFailure(f"unsupported C/C++ declarator {bounded_repr(text)}")
    if re.search(r"\b(?:volatile|restrict|__restrict|__restrict__)\b", text):
        raise ParseFailure(f"unsupported C/C++ qualifier in {bounded_repr(text)}")
    text = re.sub(r"\b(?:struct|class|enum)\s+", "", text)
    pieces = text.split("*")
    if len(pieces) - 1 + array_dimensions > MAX_TYPE_DEPTH:
        raise ParseFailure(f"C/C++ type nesting exceeds {MAX_TYPE_DEPTH}")

    base_piece = pieces[0]
    base_const = bool(re.search(r"\bconst\b", base_piece))
    base_piece = re.sub(r"\bconst\b", "", base_piece)
    base_piece = re.sub(r"\s+", "", base_piece)
    if not base_piece:
        raise ParseFailure(f"missing pointee/base type in {bounded_repr(raw)}")
    shape = TypeShape.value(canonical_value_name(base_piece))

    # In ``const u8**``, const qualifies u8; subsequent empty pointer
    # qualifier groups mean mutable pointees.  In ``u8* const*``, the const
    # after the first star qualifies that pointer as the next pointee.
    target_const = base_const
    for qualifier in pieces[1:]:
        unknown = re.sub(r"\bconst\b", "", qualifier).strip()
        if unknown:
            raise ParseFailure(
                f"unsupported pointer qualifier {bounded_repr(qualifier)} in {bounded_repr(raw)}"
            )
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
        raise ParseFailure(f"Rust parameter lacks a type: {bounded_repr(raw)}")
    name, type_text = raw.split(":", 1)
    if not re.fullmatch(r"\s*(?:mut\s+)?[A-Za-z_][A-Za-z0-9_]*\s*", name):
        raise ParseFailure(f"unsupported Rust parameter pattern {bounded_repr(name.strip())}")
    return parse_rust_type(type_text)


def parse_c_parameter(raw: str) -> TypeShape:
    text = re.sub(r"\s*=.*$", "", raw.strip(), flags=re.DOTALL)
    if not text or text == "void":
        raise ParseFailure("void/empty must be the entire parameter list")
    if "(*" in text or re.search(r"\(\s*\*", text):
        raise ParseFailure(f"inline function-pointer declarator is unsupported: {bounded_repr(text)}")
    match = re.match(
        r"^(?P<type>.+?)(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*"
        r"(?P<arrays>(?:\[[^\]]*\]\s*)*)$",
        text,
        re.DOTALL,
    )
    if not match:
        raise ParseFailure(f"cannot separate C/C++ parameter name in {bounded_repr(text)}")
    type_text = match.group("type").strip()
    if type_text.endswith("::"):
        raise ParseFailure(f"invalid C/C++ parameter type {bounded_repr(type_text)}")
    dimensions = match.group("arrays").count("[")
    return parse_c_type(type_text, dimensions)


def read_text(path: Path) -> str:
    try:
        with path.open("rb") as stream:
            encoded = stream.read(MAX_FILE_BYTES + 1)
    except OSError as error:
        raise ParseFailure(f"cannot read file: {error}") from error
    if len(encoded) > MAX_FILE_BYTES:
        raise ParseFailure(f"file exceeds {MAX_FILE_BYTES} bytes")
    try:
        return encoded.decode("utf-8", errors="strict")
    except UnicodeError as error:
        raise ParseFailure(f"cannot read UTF-8 file: {error}") from error


def parse_rust_exports_text(
    member: str,
    path: Path,
    original: str,
    budget: TraversalBudget | None = None,
) -> list[Signature]:
    code = strip_comments(original, preprocess=False)
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
                raise ParseFailure(f"unsupported Rust return clause {bounded_repr(tail)}")
            result = parse_rust_type(tail[2:])
        else:
            result = TypeShape.value("void")
        raw_parameters = split_top_level(code[opening + 1 : closing])
        parameters = tuple(parse_rust_parameter(parameter) for parameter in raw_parameters)
        export_name = EXPORT_NAME_RE.search(attrs)
        name = export_name.group(1) if export_name else match.group("name")
        if budget is not None:
            budget.count_signatures(1)
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


def parse_header_declarations_text(
    member: str,
    path: Path,
    original: str,
    budget: TraversalBudget | None = None,
) -> list[Signature]:
    code = strip_comments(original)
    linkage_ranges = extern_linkage_block_ranges(code)
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
        if not has_c_linkage(code, match.start("name"), boundary, linkage_ranges):
            line = original.count("\n", 0, match.start("name")) + 1
            raise ParseFailure(f"line {line}: {match.group('name')} lacks lexical extern \"C\" linkage")
        return_text = code[boundary : match.start("name")].strip()
        return_text = re.sub(r"\b(?:extern\s+\"C\"|inline|static|constexpr)\b", "", return_text).strip()
        result = parse_c_type(return_text)
        parameter_text = match.group("params").strip()
        if parameter_text in {"", "void"}:
            parameters: tuple[TypeShape, ...] = ()
        else:
            parameters = tuple(parse_c_parameter(parameter) for parameter in split_top_level(parameter_text))
        if budget is not None:
            budget.count_signatures(1)
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


def parse_rust_callbacks_text(
    member: str,
    path: Path,
    original: str,
    budget: TraversalBudget | None = None,
) -> list[CallbackSignature]:
    aliases = NAMED_TYPE_ALIASES.get(member, {})
    if not aliases:
        return []
    code = strip_comments(original, preprocess=False)
    callbacks: list[CallbackSignature] = []
    for rust_container, c_container in aliases.items():
        struct_match = re.search(rf"\bstruct\s+{re.escape(rust_container)}\s*\{{", code)
        if struct_match is None:
            continue
        opening = code.find("{", struct_match.start(), struct_match.end())
        closing = matching_delimiter(code, opening, "{", "}")
        if closing is None:
            raise ParseFailure(f"unterminated Rust ABI struct {rust_container}")
        body = code[opening + 1 : closing]
        for match in RUST_CALLBACK_FIELD_RE.finditer(body):
            parameter_opening = opening + 1 + match.end() - 1
            parameter_closing = matching_delimiter(code, parameter_opening, "(", ")")
            if parameter_closing is None or parameter_closing > closing:
                raise ParseFailure(f"unterminated callback field {rust_container}.{match.group('field')}")
            option_close_match = re.search(r"(?<!-)>\s*,?", code[parameter_closing + 1 : closing])
            if option_close_match is None:
                raise ParseFailure(f"unterminated Option callback field {rust_container}.{match.group('field')}")
            option_closing = parameter_closing + 1 + option_close_match.start()
            tail = code[parameter_closing + 1 : option_closing].strip()
            if tail:
                if not tail.startswith("->"):
                    raise ParseFailure(
                        f"unsupported callback return clause for {rust_container}.{match.group('field')}"
                    )
                result = parse_rust_type(tail[2:])
            else:
                result = TypeShape.value("void")
            parameters = tuple(
                parse_rust_parameter(parameter)
                for parameter in split_top_level(code[parameter_opening + 1 : parameter_closing])
            )
            if budget is not None:
                budget.count_signatures(1)
            absolute_start = opening + 1 + match.start()
            callbacks.append(
                CallbackSignature(
                    member=member,
                    container=c_container,
                    field=match.group("field"),
                    path=path,
                    line=original.count("\n", 0, absolute_start) + 1,
                    abi=match.group("abi") or "C",
                    result=result,
                    parameters=parameters,
                )
            )
    return callbacks


def parse_header_callbacks_text(
    member: str,
    path: Path,
    original: str,
    budget: TraversalBudget | None = None,
) -> list[CallbackSignature]:
    aliases = NAMED_TYPE_ALIASES.get(member, {})
    if not aliases:
        return []
    code = strip_comments(original)
    linkage_ranges = extern_linkage_block_ranges(code)
    callback_aliases: dict[str, tuple[TypeShape, tuple[TypeShape, ...], int, int]] = {}
    for match in HEADER_CALLBACK_ALIAS_RE.finditer(code):
        boundary = max(code.rfind(";", 0, match.start()), code.rfind("{", 0, match.start()), code.rfind("}", 0, match.start())) + 1
        if not has_c_linkage(code, match.start(), boundary, linkage_ranges):
            line = original.count("\n", 0, match.start()) + 1
            raise ParseFailure(f"line {line}: callback alias {match.group('alias')} lacks lexical extern \"C\" linkage")
        parameter_text = match.group("params").strip()
        parameters = (
            ()
            if parameter_text in {"", "void"}
            else tuple(parse_c_parameter(parameter) for parameter in split_top_level(parameter_text))
        )
        callback_aliases[match.group("alias")] = (
            parse_c_type(match.group("result")),
            parameters,
            match.start(),
            original.count("\n", 0, match.start()) + 1,
        )

    callbacks: list[CallbackSignature] = []
    if not callback_aliases:
        return callbacks
    alias_pattern = "|".join(re.escape(name) for name in sorted(callback_aliases, key=len, reverse=True))
    field_re = re.compile(rf"\b(?P<alias>{alias_pattern})\s+(?P<field>[A-Za-z_][A-Za-z0-9_]*)\s*;")
    for c_container in aliases.values():
        struct_match = re.search(rf"\bstruct\s+{re.escape(c_container)}\s*\{{", code)
        if struct_match is None:
            continue
        opening = code.find("{", struct_match.start(), struct_match.end())
        closing = matching_delimiter(code, opening, "{", "}")
        if closing is None:
            raise ParseFailure(f"unterminated C ABI struct {c_container}")
        body = code[opening + 1 : closing]
        for match in field_re.finditer(body):
            result, parameters, _, _ = callback_aliases[match.group("alias")]
            if budget is not None:
                budget.count_signatures(1)
            absolute_start = opening + 1 + match.start()
            callbacks.append(
                CallbackSignature(
                    member=member,
                    container=c_container,
                    field=match.group("field"),
                    path=path,
                    line=original.count("\n", 0, absolute_start) + 1,
                    abi="C",
                    result=result,
                    parameters=parameters,
                )
            )
    return callbacks


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
        return path.relative_to(root).as_posix()
    except ValueError:
        try:
            return path.resolve().relative_to(root).as_posix()
        except (OSError, ValueError):
            return path.as_posix()


def add_finding(findings: list[Finding], code: str, root: Path, path: Path, line: int, message: str) -> None:
    if len(findings) >= MAX_FINDINGS:
        raise BudgetExceeded(f"finding inventory exceeds {MAX_FINDINGS} records")
    findings.append(Finding(code, repo_relative(root, path), line, bounded_message(message)))


def read_toml(path: Path, budget: TraversalBudget | None = None) -> dict:
    try:
        with path.open("rb") as stream:
            encoded = stream.read(MAX_FILE_BYTES + 1)
    except OSError as error:
        raise ParseFailure(f"cannot read {path}: {error}") from error
    if len(encoded) > MAX_FILE_BYTES:
        raise ParseFailure(f"manifest exceeds {MAX_FILE_BYTES} bytes: {path}")
    if budget is not None:
        budget.count_bytes(len(encoded))
    try:
        return tomllib.loads(encoded.decode("utf-8", errors="strict"))
    except (UnicodeError, tomllib.TOMLDecodeError) as error:
        raise ParseFailure(f"cannot parse {path}: {error}") from error


def lstat_path(path: Path) -> os.stat_result:
    try:
        return path.lstat()
    except OSError as error:
        raise ParseFailure(f"cannot stat {path}: {error}") from error


def windows_reparse_is_unsafe(attributes: int, tag: int | None) -> bool:
    if not attributes & WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT:
        return False
    if tag is None or tag == 0:
        return True
    return bool(tag & WINDOWS_REPARSE_TAG_NAME_SURROGATE)


def is_unsafe_reparse(path: Path, metadata: os.stat_result) -> bool:
    attributes = getattr(metadata, "st_file_attributes", 0)
    if windows_reparse_is_unsafe(attributes, getattr(metadata, "st_reparse_tag", None)):
        return True
    if not stat.S_ISDIR(metadata.st_mode):
        return False
    junction_probe = getattr(path, "is_junction", None)
    if junction_probe is None:
        return False
    try:
        return bool(junction_probe())
    except OSError as error:
        raise ParseFailure(f"cannot inspect directory reparse state for {path}: {error}") from error


def resolve_contained(root: Path, member_root: Path, path: Path) -> Path:
    try:
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise ParseFailure(f"cannot resolve workspace path {path}: {error}") from error
    try:
        resolved.relative_to(root)
        resolved.relative_to(member_root)
    except ValueError as error:
        raise ParseFailure(f"workspace input escapes its member or repository: {path}") from error
    return resolved


def checked_member_directory(root: Path, raw_member: str) -> tuple[str, Path]:
    member_path = Path(raw_member)
    if (
        not raw_member
        or member_path.is_absolute()
        or ".." in member_path.parts
        or any(token in raw_member for token in ("*", "?", "[", "]", ";", "\r", "\n"))
    ):
        raise ParseFailure(f"workspace member must be an exact safe path: {bounded_repr(raw_member)}")

    normalized = member_path.as_posix().rstrip("/")
    if not normalized or normalized == ".":
        raise ParseFailure(f"workspace member must name a child directory: {bounded_repr(raw_member)}")
    current = root
    for part in member_path.parts:
        if part in {"", "."}:
            continue
        current = current / part
        metadata = lstat_path(current)
        if stat.S_ISLNK(metadata.st_mode):
            raise ParseFailure(f"workspace member directory may not traverse a symlink: {current}")
        if not stat.S_ISDIR(metadata.st_mode):
            raise ParseFailure(f"workspace member path component is not a directory: {current}")
        if is_unsafe_reparse(current, metadata):
            raise ParseFailure(
                f"workspace member directory may not traverse a junction/name-surrogate reparse point: {current}"
            )

    directory = resolve_contained(root, root, current)
    manifest = directory / "Cargo.toml"
    manifest_metadata = lstat_path(manifest)
    if stat.S_ISLNK(manifest_metadata.st_mode):
        raise ParseFailure(f"workspace member manifest may not be a symlink: {manifest}")
    if not stat.S_ISREG(manifest_metadata.st_mode):
        raise ParseFailure(f"workspace member manifest is not a regular file: {manifest}")
    return normalized, directory


def workspace_members(root: Path, budget: TraversalBudget) -> list[tuple[str, Path]]:
    manifest = root / "Cargo.toml"
    manifest_metadata = lstat_path(manifest)
    if stat.S_ISLNK(manifest_metadata.st_mode):
        raise ParseFailure(f"workspace manifest may not be a symlink: {manifest}")
    if not stat.S_ISREG(manifest_metadata.st_mode):
        raise ParseFailure(f"workspace manifest is not a regular file: {manifest}")
    parsed = read_toml(manifest, budget)
    raw_members = parsed.get("workspace", {}).get("members")
    if not isinstance(raw_members, list) or not all(isinstance(member, str) for member in raw_members):
        raise ParseFailure("Cargo.toml workspace.members must be an array of strings")
    if not raw_members or len(raw_members) > MAX_WORKSPACE_MEMBERS:
        raise ParseFailure(f"workspace member count must be 1..{MAX_WORKSPACE_MEMBERS}")
    members: list[tuple[str, Path]] = []
    seen_names: set[str] = set()
    seen_directories: set[Path] = set()
    for raw_member in raw_members:
        normalized, directory = checked_member_directory(root, raw_member)
        if normalized in seen_names or directory in seen_directories:
            raise ParseFailure(f"duplicate workspace member {normalized}")
        seen_names.add(normalized)
        seen_directories.add(directory)
        members.append((normalized, directory))
    return sorted(members)


def manifest_dependency_tables(data: dict) -> list[tuple[str, dict]]:
    tables: list[tuple[str, dict]] = []
    for name in ("dependencies", "dev-dependencies", "build-dependencies"):
        table = data.get(name)
        if isinstance(table, dict):
            tables.append((name, table))
    targets = data.get("target")
    if isinstance(targets, dict):
        for target_name, target in targets.items():
            if not isinstance(target, dict):
                continue
            for name in ("dependencies", "dev-dependencies", "build-dependencies"):
                table = target.get(name)
                if isinstance(table, dict):
                    tables.append((f"target.{target_name}.{name}", table))
    return tables


def validate_dependency_table(
    root: Path,
    owner: Path,
    label: str,
    table: dict,
    packages: dict[Path, str],
) -> None:
    for alias, specification in table.items():
        if not isinstance(specification, dict) or "path" not in specification:
            continue
        raw_path = specification.get("path")
        if not isinstance(raw_path, str) or not raw_path or raw_path != raw_path.strip():
            raise ParseFailure(f"[{label}] dependency {alias} has an invalid local path")
        unresolved = owner / raw_path
        try:
            unresolved.absolute().relative_to(root)
            resolved = unresolved.resolve(strict=True)
            resolved.relative_to(root)
        except (OSError, ValueError) as error:
            raise ParseFailure(f"[{label}] dependency {alias} escapes the audited workspace: {error}") from error
        package = packages.get(resolved)
        if package is None:
            raise ParseFailure(f"[{label}] dependency {alias} is not an explicit audited workspace member")
        expected_package = specification.get("package", alias)
        if expected_package != package:
            raise ParseFailure(
                f"[{label}] dependency {alias} names {expected_package!r}, member package is {package!r}"
            )


def validate_compilation_graph(
    root: Path,
    members: list[tuple[str, Path]],
    budget: TraversalBudget,
) -> None:
    manifests: dict[Path, dict] = {}
    packages: dict[Path, str] = {}
    for _, directory in members:
        manifest = directory / "Cargo.toml"
        data = read_toml(manifest, budget)
        manifests[directory] = data
        package = data.get("package")
        package_name = package.get("name") if isinstance(package, dict) else None
        if not isinstance(package_name, str) or not package_name:
            raise ParseFailure(f"workspace member has no [package].name: {manifest}")
        packages[directory] = package_name

    root_data = read_toml(root / "Cargo.toml", budget)
    if root_data.get("patch") or root_data.get("replace"):
        raise ParseFailure("workspace patch/replace tables are not permitted")
    workspace = root_data.get("workspace")
    workspace_dependencies = workspace.get("dependencies") if isinstance(workspace, dict) else None
    if isinstance(workspace_dependencies, dict):
        validate_dependency_table(root, root, "workspace.dependencies", workspace_dependencies, packages)

    member_map = dict(members)
    working_directory = member_map.get("kernel/rust", members[0][1])
    canonical_config = root / CANONICAL_CARGO_CONFIG
    current = working_directory
    while True:
        cargo_config = current / ".cargo" / "config"
        cargo_config_toml = current / ".cargo" / "config.toml"
        if cargo_config.exists() and cargo_config_toml.exists():
            raise ParseFailure(f"Cargo config and config.toml both exist at one search level: {current}")
        for config in (cargo_config, cargo_config_toml):
            if config.exists() and config != canonical_config:
                raise ParseFailure(f"only repository-root .cargo/config.toml is permitted: {config}")
        for toolchain in (current / "rust-toolchain", current / "rust-toolchain.toml"):
            if toolchain.exists() and toolchain != root / CANONICAL_RUST_TOOLCHAIN:
                raise ParseFailure(f"only repository-root rust-toolchain.toml is permitted: {toolchain}")
        if current == root:
            break
        current = current.parent

    if not canonical_config.is_file():
        raise ParseFailure(f"canonical Cargo config is missing: {canonical_config}")
    if read_toml(canonical_config, budget) != EXPECTED_CARGO_CONFIG:
        raise ParseFailure("repository Cargo config must contain only the canonical target and build-std policy")
    canonical_toolchain = root / CANONICAL_RUST_TOOLCHAIN
    if not canonical_toolchain.is_file():
        raise ParseFailure(f"canonical Rust toolchain is missing: {canonical_toolchain}")
    if read_toml(canonical_toolchain, budget) != EXPECTED_RUST_TOOLCHAIN:
        raise ParseFailure(
            "repository Rust toolchain must contain only the canonical dated channel, component, target, and profile"
        )

    for _, directory in members:
        data = manifests[directory]
        package = data.get("package")
        if isinstance(package, dict) and package.get("build") not in (None, False):
            raise ParseFailure(f"custom package.build target is not permitted: {directory / 'Cargo.toml'}")
        if (directory / "build.rs").is_file():
            raise ParseFailure(f"build.rs is not permitted in the kernel Rust workspace: {directory}")
        for table_name in ("lib", "bin", "example", "test", "bench"):
            target = data.get(table_name)
            targets = target if isinstance(target, list) else [target]
            if any(isinstance(entry, dict) and "path" in entry for entry in targets):
                raise ParseFailure(f"custom [{table_name}] path is not permitted: {directory / 'Cargo.toml'}")
        if data.get("patch") or data.get("replace"):
            raise ParseFailure(f"member patch/replace tables are not permitted: {directory / 'Cargo.toml'}")
        for label, table in manifest_dependency_tables(data):
            validate_dependency_table(root, directory, label, table, packages)


def walk_member_signature_inputs(
    root: Path,
    member_root: Path,
    budget: TraversalBudget,
    findings: list[Finding],
) -> list[Path]:
    """Stream one member tree once, pruning generated trees before descent."""
    pending = [member_root]
    retained: list[Path] = []
    while pending:
        directory = pending.pop()
        try:
            with os.scandir(directory) as entries:
                for entry in entries:
                    budget.count()
                    path = Path(entry.path)
                    try:
                        metadata = entry.stat(follow_symlinks=False)
                    except OSError as error:
                        raise ParseFailure(f"cannot stat workspace entry {path}: {error}") from error

                    if stat.S_ISLNK(metadata.st_mode) or is_unsafe_reparse(path, metadata):
                        add_finding(
                            findings,
                            "RFS001",
                            root,
                            path,
                            0,
                            "workspace input may not be a symlink or name-surrogate reparse point",
                        )
                        continue

                    if stat.S_ISDIR(metadata.st_mode):
                        if directory == member_root and entry.name in SKIP_DIRECTORIES:
                            continue
                        pending.append(resolve_contained(root, member_root, path))
                        continue

                    if not stat.S_ISREG(metadata.st_mode):
                        add_finding(findings, "RFS001", root, path, 0, "workspace input must be a regular file")
                        continue

                    suffix = path.suffix
                    if suffix not in RUST_SUFFIXES and suffix not in HEADER_SUFFIXES:
                        continue
                    budget.count_bytes(metadata.st_size)
                    retained.append(resolve_contained(root, member_root, path))
        except OSError as error:
            raise ParseFailure(f"cannot scan workspace directory {directory}: {error}") from error
    return sorted(retained, key=lambda path: path.as_posix())


def validate_rust_source_graph(path: Path, original: str) -> None:
    code = strip_comments(original, preprocess=False)
    if RUST_PATH_ATTRIBUTE_RE.search(code):
        raise ParseFailure("#[path] and cfg_attr(path=...) are outside the audited source graph")
    if RUST_CODE_INCLUDE_RE.search(code):
        raise ParseFailure("include! code is not permitted; keep module sources in the owning member tree")


def collect_signatures(
    root: Path,
    members: list[tuple[str, Path]],
    budget: TraversalBudget,
) -> tuple[list[Signature], list[Signature], list[CallbackSignature], list[CallbackSignature], list[Finding]]:
    findings: list[Finding] = []
    rust_signatures: list[Signature] = []
    header_signatures: list[Signature] = []
    rust_callbacks: list[CallbackSignature] = []
    header_callbacks: list[CallbackSignature] = []
    for member, directory in members:
        for path in walk_member_signature_inputs(root, directory, budget, findings):
            try:
                original = read_text(path)
                if path.suffix in RUST_SUFFIXES:
                    validate_rust_source_graph(path, original)
                    rust_signatures.extend(parse_rust_exports_text(member, path, original, budget))
                    rust_callbacks.extend(parse_rust_callbacks_text(member, path, original, budget))
                else:
                    header_signatures.extend(parse_header_declarations_text(member, path, original, budget))
                    header_callbacks.extend(parse_header_callbacks_text(member, path, original, budget))
            except BudgetExceeded:
                raise
            except ParseFailure as error:
                add_finding(findings, "RFS002", root, path, 0, str(error))
                continue
    return rust_signatures, header_signatures, rust_callbacks, header_callbacks, findings


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


def index_unique_callbacks(
    root: Path,
    callbacks: Iterable[CallbackSignature],
    side: str,
    findings: list[Finding],
) -> dict[tuple[str, str, str], CallbackSignature]:
    indexed: dict[tuple[str, str, str], CallbackSignature] = {}
    for callback in callbacks:
        key = (callback.member, callback.container, callback.field)
        previous = indexed.get(key)
        if previous is not None:
            add_finding(
                findings,
                "RFS003",
                root,
                callback.path,
                callback.line,
                f"duplicate {side} callback {callback.container}.{callback.field}; first at "
                f"{repo_relative(root, previous.path)}:{previous.line}",
            )
            continue
        indexed[key] = callback
    return indexed


def compare_callbacks(rust: CallbackSignature, header: CallbackSignature) -> list[str]:
    return compare_signatures(
        Signature(
            member=rust.member,
            name=rust.field,
            path=rust.path,
            line=rust.line,
            abi=rust.abi,
            result=rust.result,
            parameters=rust.parameters,
        ),
        Signature(
            member=header.member,
            name=header.field,
            path=header.path,
            line=header.line,
            abi=header.abi,
            result=header.result,
            parameters=header.parameters,
        ),
    )


def audit(
    root: Path,
    max_inventory_entries: int = MAX_SOURCE_FILES,
    max_input_bytes: int = MAX_TOTAL_INPUT_BYTES,
    max_signature_records: int = MAX_SIGNATURE_RECORDS,
) -> tuple[list[Finding], dict[str, int]]:
    try:
        root = root.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise ParseFailure(f"cannot resolve repository root {root}: {error}") from error
    if max_inventory_entries < 1:
        raise ParseFailure("source inventory entry limit must be positive")
    if max_input_bytes < 1 or max_signature_records < 1:
        raise ParseFailure("source byte and signature inventory limits must be positive")
    budget = TraversalBudget(
        max_inventory_entries,
        byte_limit=max_input_bytes,
        signature_limit=max_signature_records,
    )
    members = workspace_members(root, budget)
    validate_compilation_graph(root, members, budget)
    rust_signatures, header_signatures, rust_callbacks, header_callbacks, findings = collect_signatures(
        root, members, budget
    )
    rust_by_key = index_unique(root, rust_signatures, "Rust", findings)
    header_by_key = index_unique(root, header_signatures, "header", findings)
    rust_callbacks_by_key = index_unique_callbacks(root, rust_callbacks, "Rust", findings)
    header_callbacks_by_key = index_unique_callbacks(root, header_callbacks, "header", findings)

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

    for key in sorted(rust_callbacks_by_key.keys() - header_callbacks_by_key.keys()):
        callback = rust_callbacks_by_key[key]
        add_finding(
            findings,
            "RFS007",
            root,
            callback.path,
            callback.line,
            f"Rust callback {callback.container}.{callback.field} lacks a same-crate C header field",
        )
    for key in sorted(header_callbacks_by_key.keys() - rust_callbacks_by_key.keys()):
        callback = header_callbacks_by_key[key]
        add_finding(
            findings,
            "RFS008",
            root,
            callback.path,
            callback.line,
            f"C header callback {callback.container}.{callback.field} lacks a same-crate Rust field",
        )
    for key in sorted(rust_callbacks_by_key.keys() & header_callbacks_by_key.keys()):
        rust_callback = rust_callbacks_by_key[key]
        header_callback = header_callbacks_by_key[key]
        for mismatch in compare_callbacks(rust_callback, header_callback):
            add_finding(
                findings,
                "RFS009",
                root,
                header_callback.path,
                header_callback.line,
                f"{header_callback.container}.{header_callback.field}: {mismatch}; Rust at "
                f"{repo_relative(root, rust_callback.path)}:{rust_callback.line}",
            )

    findings.sort(key=lambda item: (item.code, item.path, item.line, item.message))
    summary = {
        "workspace_members": len(members),
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
