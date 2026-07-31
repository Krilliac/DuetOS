#!/usr/bin/env python3
"""Audit Rust workspace build truth and the hand-written C FFI boundary.

The CMake integration also uses the two emit modes.  Those modes print only
normalized paths and fail on workspace/build-graph errors; the default audit
additionally fails on FFI safety findings so existing debt stays visible.
"""

from __future__ import annotations

import argparse
import re
import sys
import tempfile
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


AGGREGATE_MEMBER = Path("kernel/rust")
MAX_WORKSPACE_MEMBERS = 128
MAX_INVENTORY_FILES = 20_000
ALLOWED_EXPORT_ABIS = frozenset({"C", "C-unwind", "system"})

# A safe exported Rust function is permitted only when its exact symbol is in
# this set and its signature remains scalar-only.  Pointer-taking exports must
# instead be declared `unsafe extern` with an approved ABI; do not add them here.
SCALAR_SAFE_EXPORTS = frozenset(
    {
        "DUETFS_KIND_DIR",
        "DUETFS_KIND_FILE",
        "DUETFS_KIND_UNUSED",
        "DUETFS_ROOT_NODE_ID",
        "duetos_ntfs_decode_mft_record_size",
    }
)

# These immutable scalar symbols intentionally keep the Rust constants linked;
# the C header exposes matching enum constants rather than extern objects.
HEADER_DECLARATION_EXEMPT_EXPORTS = frozenset(
    {
        "DUETFS_KIND_DIR",
        "DUETFS_KIND_FILE",
        "DUETFS_KIND_UNUSED",
        "DUETFS_ROOT_NODE_ID",
    }
)

BUILD_SUFFIXES = frozenset(
    {
        ".rs",
        ".h",
        ".hh",
        ".hpp",
        ".hxx",
        ".c",
        ".cc",
        ".cpp",
        ".s",
        ".S",
        ".asm",
        ".ld",
        ".lds",
    }
)
SKIP_DIRS = frozenset({".git", "target", "__pycache__"})
SCALAR_TYPES = frozenset(
    {
        "bool",
        "u8",
        "u16",
        "u32",
        "u64",
        "u128",
        "usize",
        "i8",
        "i16",
        "i32",
        "i64",
        "i128",
        "isize",
        "f32",
        "f64",
        "c_char",
        "c_schar",
        "c_uchar",
        "c_short",
        "c_ushort",
        "c_int",
        "c_uint",
        "c_long",
        "c_ulong",
        "c_longlong",
        "c_ulonglong",
        "c_float",
        "c_double",
    }
)

EXPORT_START_RE = re.compile(
    r"(?P<attrs>(?:\s*#\s*\[[^\]]+\]\s*)+)"
    r"(?P<prefix>(?:(?:pub(?:\s*\([^)]*\))?)\s+)?"
    r"(?P<unsafe>unsafe\s+)?extern(?:\s*\"(?P<abi>[A-Za-z0-9_-]+)\")?\s+fn\s+)"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\(",
    re.MULTILINE,
)
STATIC_EXPORT_RE = re.compile(
    r"(?P<attrs>(?:\s*#\s*\[[^\]]+\]\s*)+)"
    r"(?:(?:pub(?:\s*\([^)]*\))?)\s+)?static\s+(?P<mutable>mut\s+)?"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*:\s*(?P<type>[^=;]+)=",
    re.MULTILINE,
)
EXPORT_ATTRIBUTE_RE = re.compile(
    r"^[ \t]*#\s*\[[^\]\r\n]*(?:no_mangle|export_name)[^\]\r\n]*\]",
    re.MULTILINE,
)
EXPORT_NAME_RE = re.compile(r"export_name\s*=\s*\"([A-Za-z_][A-Za-z0-9_]*)\"")
FUNCTION_START_RE = re.compile(
    r"\bfn\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*"
    r"(?P<generics><[^>{;()]*>)?\s*\(",
    re.MULTILINE,
)
HEADER_DECL_RE = re.compile(
    r"\b(?P<name>(?:duetos|duetfs)_[A-Za-z_][A-Za-z0-9_]*)\s*"
    r"\((?P<params>[^;{}]*)\)\s*;",
    re.DOTALL,
)
INCLUDE_MACRO_RE = re.compile(r"\binclude(?:_bytes|_str)?!\s*\(")
INCLUDE_LITERAL_RE = re.compile(
    r"\binclude(?:_bytes|_str)?!\s*\(\s*\"(?P<path>[^\"\r\n]+)\"\s*\)"
)


@dataclass(frozen=True)
class Issue:
    severity: str
    code: str
    path: str
    line: int
    message: str


@dataclass(frozen=True)
class Crate:
    member: str
    directory: Path
    manifest: Path
    package: str


@dataclass(frozen=True)
class Export:
    crate: Crate
    path: Path
    line: int
    name: str
    kind: str
    abi: str | None
    signature: str
    is_unsafe: bool
    has_raw_pointer: bool
    scalar_only: bool


@dataclass
class Inventory:
    root: Path
    aggregate: Crate | None
    crates: list[Crate]
    inputs: list[Path]
    exports: list[Export]
    header_names: dict[str, set[str]]
    issues: list[Issue]


def repo_relative(root: Path, path: Path) -> str:
    try:
        return path.resolve().relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


def add_issue(
    issues: list[Issue],
    severity: str,
    code: str,
    root: Path,
    path: Path,
    message: str,
    line: int = 0,
) -> None:
    issues.append(Issue(severity, code, repo_relative(root, path), line, message))


def read_toml(root: Path, path: Path, issues: list[Issue]) -> dict:
    try:
        with path.open("rb") as stream:
            return tomllib.load(stream)
    except (OSError, tomllib.TOMLDecodeError) as error:
        add_issue(issues, "error", "BUILD001", root, path, f"cannot parse manifest: {error}")
        return {}


def strip_comments(text: str) -> str:
    """Remove Rust/C comments while retaining strings and line positions."""
    output = list(text)
    index = 0
    state = "code"
    block_depth = 0
    while index < len(text):
        current = text[index]
        next_char = text[index + 1] if index + 1 < len(text) else ""
        if state == "code":
            if current == '"':
                state = "string"
            elif current == "'":
                # Lifetimes are not character literals.  Treat only quoted
                # single characters/escapes as character strings.
                tail = text[index : index + 5]
                if re.match(r"'(?:\\.|[^\\'])'", tail):
                    state = "char"
            elif current == "/" and next_char == "/":
                output[index] = output[index + 1] = " "
                index += 1
                state = "line_comment"
            elif current == "/" and next_char == "*":
                output[index] = output[index + 1] = " "
                index += 1
                state = "block_comment"
                block_depth = 1
        elif state == "string":
            if current == "\\":
                index += 1
            elif current == '"':
                state = "code"
        elif state == "char":
            if current == "\\":
                index += 1
            elif current == "'":
                state = "code"
        elif state == "line_comment":
            if current == "\n":
                state = "code"
            else:
                output[index] = " "
        elif state == "block_comment":
            if current == "/" and next_char == "*":
                output[index] = output[index + 1] = " "
                index += 1
                block_depth += 1
            elif current == "*" and next_char == "/":
                output[index] = output[index + 1] = " "
                index += 1
                block_depth -= 1
                if block_depth == 0:
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
        elif text[index] == right:
            depth -= 1
            if depth == 0:
                return index
    return None


def split_top_level(text: str) -> list[str]:
    parts: list[str] = []
    start = 0
    depths = {"(": 0, "[": 0, "<": 0}
    closes = {")": "(", "]": "[", ">": "<"}
    for index, character in enumerate(text):
        if character in depths:
            depths[character] += 1
        elif character in closes and depths[closes[character]] > 0:
            depths[closes[character]] -= 1
        elif character == "," and not any(depths.values()):
            parts.append(text[start:index].strip())
            start = index + 1
    tail = text[start:].strip()
    if tail:
        parts.append(tail)
    return parts


def canonical_type(raw_type: str) -> str:
    cleaned = re.sub(r"\b(?:core|std)::ffi::", "", raw_type.strip())
    return re.sub(r"\s+", "", cleaned)


def is_scalar_signature(parameters: str, return_text: str) -> bool:
    for parameter in split_top_level(parameters):
        if not parameter:
            continue
        if ":" not in parameter:
            return False
        parameter_type = canonical_type(parameter.split(":", 1)[1])
        if parameter_type not in SCALAR_TYPES:
            return False

    normalized_return = return_text.strip()
    if not normalized_return:
        return True
    if not normalized_return.startswith("->"):
        return False
    return_type = canonical_type(normalized_return[2:])
    return return_type == "()" or return_type == "!" or return_type in SCALAR_TYPES


def parse_exports(root: Path, crate: Crate, rust_path: Path, issues: list[Issue]) -> list[Export]:
    try:
        original = rust_path.read_text(encoding="utf-8", errors="strict")
    except (OSError, UnicodeError) as error:
        add_issue(issues, "error", "BUILD002", root, rust_path, f"cannot read Rust source: {error}")
        return []
    code = strip_comments(original)
    exports: list[Export] = []
    covered_attribute_ranges: list[tuple[int, int]] = []
    for match in EXPORT_START_RE.finditer(code):
        attrs = match.group("attrs")
        if "no_mangle" not in attrs and "export_name" not in attrs:
            continue
        opening = match.end() - 1
        closing = matching_delimiter(code, opening, "(", ")")
        if closing is None:
            add_issue(issues, "error", "FFI000", root, rust_path, "unterminated exported function signature")
            continue
        terminators = [position for position in (code.find("{", closing), code.find(";", closing)) if position >= 0]
        end = min(terminators) if terminators else len(code)
        return_text = code[closing + 1 : end].strip()
        parameters = code[opening + 1 : closing]
        signature = re.sub(r"\s+", " ", code[match.start("prefix") : end].strip())
        export_name = EXPORT_NAME_RE.search(attrs)
        name = export_name.group(1) if export_name else match.group("name")
        has_raw_pointer = bool(re.search(r"\*\s*(?:const|mut)\b", parameters + " " + return_text))
        covered_attribute_ranges.append((match.start("attrs"), match.end()))
        exports.append(
            Export(
                crate=crate,
                path=rust_path,
                line=original.count("\n", 0, match.start("prefix")) + 1,
                name=name,
                kind="function",
                abi=match.group("abi") or "C",
                signature=signature,
                is_unsafe=bool(match.group("unsafe")),
                has_raw_pointer=has_raw_pointer,
                scalar_only=is_scalar_signature(parameters, return_text),
            )
        )
    for match in STATIC_EXPORT_RE.finditer(code):
        attrs = match.group("attrs")
        if "no_mangle" not in attrs and "export_name" not in attrs:
            continue
        export_name = EXPORT_NAME_RE.search(attrs)
        name = export_name.group(1) if export_name else match.group("name")
        static_type = canonical_type(match.group("type"))
        covered_attribute_ranges.append((match.start("attrs"), match.end()))
        exports.append(
            Export(
                crate=crate,
                path=rust_path,
                line=original.count("\n", 0, match.start()) + 1,
                name=name,
                kind="static_mut" if match.group("mutable") else "static",
                abi=None,
                signature=re.sub(r"\s+", " ", match.group(0).strip()),
                is_unsafe=False,
                has_raw_pointer=bool(re.search(r"\*\s*(?:const|mut)\b", match.group("type"))),
                scalar_only=static_type in SCALAR_TYPES,
            )
        )
    for attribute in EXPORT_ATTRIBUTE_RE.finditer(code):
        if any(start <= attribute.start() < end for start, end in covered_attribute_ranges):
            continue
        add_issue(
            issues,
            "finding",
            "FFI015",
            root,
            rust_path,
            "export attribute is not attached to an understood extern function or scalar static",
            original.count("\n", 0, attribute.start()) + 1,
        )
    return exports


def find_unconstrained_lifetimes(root: Path, rust_path: Path, issues: list[Issue]) -> None:
    try:
        original = rust_path.read_text(encoding="utf-8", errors="strict")
    except (OSError, UnicodeError):
        return
    code = strip_comments(original)
    for match in FUNCTION_START_RE.finditer(code):
        generics = match.group("generics") or ""
        lifetime_names = set(re.findall(r"'([A-Za-z_][A-Za-z0-9_]*)", generics))
        opening = match.end() - 1
        closing = matching_delimiter(code, opening, "(", ")")
        if closing is None:
            continue
        body = code.find("{", closing)
        if body < 0:
            continue
        parameters = code[opening + 1 : closing]
        return_text = code[closing + 1 : body]
        if not re.search(r"\*\s*(?:const|mut)\b", parameters):
            continue
        returned_lifetimes = set(re.findall(r"&\s*'([A-Za-z_][A-Za-z0-9_]*)", return_text))
        unconstrained = sorted((returned_lifetimes & lifetime_names) | (returned_lifetimes & {"static"}))
        for lifetime in unconstrained:
            if lifetime != "static" and re.search(rf"&\s*'{re.escape(lifetime)}\b", parameters):
                continue
            line = original.count("\n", 0, match.start()) + 1
            add_issue(
                issues,
                "finding",
                "FFI003",
                root,
                rust_path,
                f"{match.group('name')} manufactures unconstrained lifetime '{lifetime} from a raw pointer",
                line,
            )


def parse_header_names(root: Path, header: Path, issues: list[Issue]) -> set[str]:
    try:
        original = header.read_text(encoding="utf-8", errors="strict")
    except (OSError, UnicodeError) as error:
        add_issue(issues, "error", "BUILD003", root, header, f"cannot read FFI header: {error}")
        return set()
    code = strip_comments(original)
    names: set[str] = set()
    for match in HEADER_DECL_RE.finditer(code):
        declaration_start = (
            max(
                code.rfind(";", 0, match.start()),
                code.rfind("{", 0, match.start()),
                code.rfind("}", 0, match.start()),
            )
            + 1
        )
        declaration = code[declaration_start : match.end()]
        if re.search(r"\b(?:typedef|static\s+inline)\b", declaration):
            continue
        names.add(match.group("name"))
    return names


def relevant_input(path: Path) -> bool:
    if any(part in SKIP_DIRS for part in path.parts):
        return False
    if path.name in {"Cargo.toml", "build.rs"}:
        return True
    if len(path.parts) >= 2 and path.parts[-2] == ".cargo" and path.name in {"config", "config.toml"}:
        return True
    return path.suffix in BUILD_SUFFIXES


def resolve_include_literals(root: Path, rust_path: Path, issues: list[Issue]) -> set[Path]:
    try:
        original = rust_path.read_text(encoding="utf-8", errors="strict")
    except (OSError, UnicodeError):
        return set()
    code = strip_comments(original)
    literal_starts = {match.start() for match in INCLUDE_LITERAL_RE.finditer(code)}
    for match in INCLUDE_MACRO_RE.finditer(code):
        if match.start() not in literal_starts:
            add_issue(
                issues,
                "error",
                "BUILD004",
                root,
                rust_path,
                "include!/include_bytes!/include_str! must use a literal path so CMake can track it",
                original.count("\n", 0, match.start()) + 1,
            )
    includes: set[Path] = set()
    for match in INCLUDE_LITERAL_RE.finditer(code):
        candidate = (rust_path.parent / match.group("path")).resolve()
        try:
            candidate.relative_to(root)
        except ValueError:
            add_issue(issues, "error", "BUILD005", root, rust_path, "include macro escapes the repository")
            continue
        if not candidate.is_file():
            add_issue(
                issues,
                "error",
                "BUILD006",
                root,
                rust_path,
                f"included file does not exist: {match.group('path')}",
            )
            continue
        includes.add(candidate)
    return includes


def build_inventory(root: Path, aggregate_manifest: Path) -> Inventory:
    issues: list[Issue] = []
    root_manifest = root / "Cargo.toml"
    root_data = read_toml(root, root_manifest, issues)
    workspace = root_data.get("workspace")
    raw_members = workspace.get("members") if isinstance(workspace, dict) else None
    if not isinstance(raw_members, list) or not all(isinstance(member, str) for member in raw_members):
        add_issue(
            issues,
            "error",
            "BUILD007",
            root,
            root_manifest,
            "[workspace].members must be an explicit string list",
        )
        raw_members = []
    if len(raw_members) > MAX_WORKSPACE_MEMBERS:
        add_issue(
            issues,
            "error",
            "BUILD008",
            root,
            root_manifest,
            f"workspace exceeds {MAX_WORKSPACE_MEMBERS} members",
        )
        raw_members = []

    crates: list[Crate] = []
    seen_directories: set[Path] = set()
    seen_packages: set[str] = set()
    for raw_member in raw_members:
        member_path = Path(raw_member)
        if (
            member_path.is_absolute()
            or ".." in member_path.parts
            or any(token in raw_member for token in ("*", "?", "[", "]", ";", "\r", "\n"))
        ):
            add_issue(
                issues,
                "error",
                "BUILD009",
                root,
                root_manifest,
                f"workspace member must be an exact safe path: {raw_member!r}",
            )
            continue
        directory = (root / raw_member).resolve()
        try:
            directory.relative_to(root)
        except ValueError:
            add_issue(
                issues,
                "error",
                "BUILD010",
                root,
                root_manifest,
                f"workspace member escapes repository: {raw_member}",
            )
            continue
        manifest = directory / "Cargo.toml"
        data = read_toml(root, manifest, issues)
        package_table = data.get("package")
        package = package_table.get("name") if isinstance(package_table, dict) else None
        if not isinstance(package, str) or not package:
            add_issue(issues, "error", "BUILD011", root, manifest, "member has no [package].name")
            continue
        if directory in seen_directories or package in seen_packages:
            add_issue(issues, "error", "BUILD012", root, manifest, f"duplicate member path or package name: {package}")
            continue
        seen_directories.add(directory)
        seen_packages.add(package)
        crates.append(Crate(raw_member.replace("\\", "/").rstrip("/"), directory, manifest, package))

    aggregate_path = aggregate_manifest.resolve().parent
    aggregate = next((crate for crate in crates if crate.directory == aggregate_path), None)
    if aggregate is None:
        add_issue(issues, "error", "BUILD013", root, aggregate_manifest, "aggregate crate is not a workspace member")
    else:
        aggregate_data = read_toml(root, aggregate.manifest, issues)
        dependencies = aggregate_data.get("dependencies")
        dependency_paths: dict[Path, str] = {}
        if not isinstance(dependencies, dict):
            add_issue(
                issues,
                "error",
                "BUILD014",
                root,
                aggregate.manifest,
                "aggregate crate needs a [dependencies] table",
            )
            dependencies = {}
        for alias, specification in dependencies.items():
            if not isinstance(specification, dict) or not isinstance(specification.get("path"), str):
                add_issue(
                    issues,
                    "error",
                    "BUILD015",
                    root,
                    aggregate.manifest,
                    f"aggregate dependency {alias} must be a local path",
                )
                continue
            dependency_path = (aggregate.directory / specification["path"]).resolve()
            if dependency_path in dependency_paths:
                add_issue(
                    issues,
                    "error",
                    "BUILD026",
                    root,
                    aggregate.manifest,
                    f"aggregate aliases one member as both {dependency_paths[dependency_path]} and {alias}",
                )
                continue
            dependency_paths[dependency_path] = alias
            target = next((crate for crate in crates if crate.directory == dependency_path), None)
            if target is None:
                add_issue(
                    issues,
                    "error",
                    "BUILD016",
                    root,
                    aggregate.manifest,
                    f"aggregate dependency {alias} is not a workspace member",
                )
                continue
            expected_package = specification.get("package", alias)
            if expected_package != target.package:
                add_issue(
                    issues,
                    "error",
                    "BUILD017",
                    root,
                    aggregate.manifest,
                    f"aggregate dependency {alias} names {expected_package}, member package is {target.package}",
                )
        expected_paths = {crate.directory for crate in crates if crate != aggregate}
        missing = sorted(expected_paths - set(dependency_paths), key=lambda path: path.as_posix())
        extra = sorted(set(dependency_paths) - expected_paths, key=lambda path: path.as_posix())
        for path in missing:
            add_issue(
                issues,
                "error",
                "BUILD018",
                root,
                aggregate.manifest,
                f"aggregate omits workspace member {repo_relative(root, path)}",
            )
        for path in extra:
            add_issue(
                issues,
                "error",
                "BUILD019",
                root,
                aggregate.manifest,
                f"aggregate has non-member dependency {repo_relative(root, path)}",
            )

        aggregate_source = aggregate.directory / "src" / "lib.rs"
        try:
            aggregate_text = strip_comments(aggregate_source.read_text(encoding="utf-8", errors="strict"))
        except (OSError, UnicodeError) as error:
            add_issue(issues, "error", "BUILD020", root, aggregate_source, f"cannot read aggregate source: {error}")
            aggregate_text = ""
        for dependency_path, alias in sorted(dependency_paths.items(), key=lambda item: item[1]):
            if dependency_path in expected_paths and not re.search(
                rf"\bpub\s+use\s+{re.escape(alias)}\b", aggregate_text
            ):
                add_issue(
                    issues,
                    "error",
                    "BUILD021",
                    root,
                    aggregate_source,
                    f"aggregate does not re-export dependency {alias}",
                )

    required_root_inputs = [
        root_manifest,
        root / "Cargo.lock",
        root / ".cargo" / "config.toml",
        root / "rust-toolchain.toml",
    ]
    inputs: set[Path] = set()
    for required in required_root_inputs:
        if not required.is_file():
            add_issue(issues, "error", "BUILD022", root, required, "required workspace build input is missing")
        elif required.is_symlink():
            add_issue(issues, "error", "BUILD027", root, required, "workspace build inputs may not be symlinks")
        else:
            inputs.add(required.resolve())

    rust_sources: dict[str, list[Path]] = {}
    header_names: dict[str, set[str]] = {}
    exports: list[Export] = []
    for crate in crates:
        crate_inputs: list[Path] = []
        headers: list[Path] = []
        sources: list[Path] = []
        for path in crate.directory.rglob("*"):
            if len(inputs) + len(crate_inputs) > MAX_INVENTORY_FILES:
                add_issue(
                    issues,
                    "error",
                    "BUILD023",
                    root,
                    crate.directory,
                    f"inventory exceeds {MAX_INVENTORY_FILES} files",
                )
                break
            if not path.is_file() or not relevant_input(path.relative_to(crate.directory)):
                continue
            if path.is_symlink():
                add_issue(issues, "error", "BUILD027", root, path, "workspace build inputs may not be symlinks")
                continue
            resolved = path.resolve()
            try:
                resolved.relative_to(root)
            except ValueError:
                add_issue(issues, "error", "BUILD028", root, path, "workspace build input escapes repository")
                continue
            crate_inputs.append(resolved)
            if path.suffix == ".rs":
                sources.append(resolved)
            if path.suffix in {".h", ".hh", ".hpp", ".hxx"}:
                headers.append(resolved)
        if not sources:
            add_issue(issues, "error", "BUILD024", root, crate.manifest, "workspace member has no Rust source")
        rust_sources[crate.member] = sorted(sources, key=lambda path: path.as_posix())
        inputs.update(crate_inputs)
        declared: set[str] = set()
        for header in sorted(headers, key=lambda path: path.as_posix()):
            declared.update(parse_header_names(root, header, issues))
        header_names[crate.member] = declared
        for source in rust_sources[crate.member]:
            exports.extend(parse_exports(root, crate, source, issues))
            find_unconstrained_lifetimes(root, source, issues)
            inputs.update(resolve_include_literals(root, source, issues))

    exports_by_crate: dict[str, set[str]] = {}
    export_locations: dict[str, Export] = {}
    for rust_export in exports:
        exports_by_crate.setdefault(rust_export.crate.member, set()).add(rust_export.name)
        previous = export_locations.get(rust_export.name)
        if previous is not None:
            add_issue(
                issues,
                "finding",
                "FFI004",
                root,
                rust_export.path,
                f"duplicate exported symbol {rust_export.name}; first at "
                f"{repo_relative(root, previous.path)}:{previous.line}",
                rust_export.line,
            )
        else:
            export_locations[rust_export.name] = rust_export

        if rust_export.kind == "function" and rust_export.abi not in ALLOWED_EXPORT_ABIS:
            add_issue(
                issues,
                "finding",
                "FFI014",
                root,
                rust_export.path,
                f"export {rust_export.name} uses unsupported extern ABI {rust_export.abi!r}",
                rust_export.line,
            )
        if rust_export.kind != "function" and (rust_export.has_raw_pointer or rust_export.kind == "static_mut"):
            add_issue(
                issues,
                "finding",
                "FFI010",
                root,
                rust_export.path,
                f"exported object {rust_export.name} must be an immutable C scalar",
                rust_export.line,
            )
        elif rust_export.has_raw_pointer and not rust_export.is_unsafe:
            add_issue(
                issues,
                "finding",
                "FFI001",
                root,
                rust_export.path,
                f"raw-pointer export {rust_export.name} must be declared unsafe extern \"C\"",
                rust_export.line,
            )
        elif not rust_export.is_unsafe:
            if rust_export.name not in SCALAR_SAFE_EXPORTS:
                add_issue(
                    issues,
                    "finding",
                    "FFI002",
                    root,
                    rust_export.path,
                    f"safe export {rust_export.name} is not in SCALAR_SAFE_EXPORTS",
                    rust_export.line,
                )
            elif not rust_export.scalar_only:
                add_issue(
                    issues,
                    "finding",
                    "FFI005",
                    root,
                    rust_export.path,
                    f"allowlisted safe export {rust_export.name} is no longer scalar-only",
                    rust_export.line,
                )

    for allowlisted in sorted(SCALAR_SAFE_EXPORTS):
        rust_export = export_locations.get(allowlisted)
        if rust_export is None:
            add_issue(
                issues,
                "finding",
                "FFI006",
                root,
                root_manifest,
                f"stale scalar-safe allowlist entry {allowlisted}",
            )
        elif rust_export.is_unsafe or not rust_export.scalar_only:
            add_issue(
                issues,
                "finding",
                "FFI007",
                root,
                rust_export.path,
                f"invalid scalar-safe allowlist entry {allowlisted}",
                rust_export.line,
            )

    for exempt in sorted(HEADER_DECLARATION_EXEMPT_EXPORTS):
        rust_export = export_locations.get(exempt)
        if rust_export is None:
            add_issue(issues, "finding", "FFI011", root, root_manifest, f"stale header-declaration exemption {exempt}")
        elif rust_export.kind != "static" or exempt not in SCALAR_SAFE_EXPORTS:
            add_issue(
                issues,
                "finding",
                "FFI012",
                root,
                rust_export.path,
                f"invalid header-declaration exemption {exempt}",
                rust_export.line,
            )

    if aggregate is not None:
        for crate in crates:
            if crate == aggregate:
                continue
            declared = header_names.get(crate.member, set())
            exported = exports_by_crate.get(crate.member, set())
            expected_declarations = exported - HEADER_DECLARATION_EXEMPT_EXPORTS
            for name in sorted(expected_declarations - declared):
                rust_export = export_locations[name]
                add_issue(
                    issues,
                    "finding",
                    "FFI008",
                    root,
                    rust_export.path,
                    f"Rust export {name} has no declaration in this crate's include headers",
                    rust_export.line,
                )
            for name in sorted(declared - expected_declarations):
                add_issue(
                    issues,
                    "finding",
                    "FFI009",
                    root,
                    crate.directory,
                    f"C header declaration {name} has no Rust export in this crate",
                )

    add_issue(
        issues,
        "finding",
        "FFI013",
        root,
        root / "tools" / "test" / "check-rust-ffi.py",
        "canonical C/Rust arity, type, and pointer-constness parity is not implemented; symbol names only",
    )

    return Inventory(
        root=root,
        aggregate=aggregate,
        crates=sorted(crates, key=lambda crate: crate.member),
        inputs=sorted(inputs, key=lambda path: path.as_posix()),
        exports=sorted(exports, key=lambda item: (item.crate.member, item.name, item.line)),
        header_names=header_names,
        issues=sorted(issues, key=lambda issue: (issue.severity, issue.code, issue.path, issue.line, issue.message)),
    )


def print_issues(issues: Iterable[Issue], limit: int) -> int:
    count = 0
    for issue in issues:
        count += 1
        if count <= limit:
            location = issue.path + (f":{issue.line}" if issue.line else "")
            print(f"{issue.severity.upper()} {issue.code} {location}: {issue.message}")
    if count > limit:
        print(f"... {count - limit} additional issue(s) omitted; use --max-findings to raise the cap")
    return count


def run_self_tests() -> int:
    fixture = r'''
#[no_mangle]
extern "C" fn private_raw(ptr: *const u8) -> bool { !ptr.is_null() }

#[export_name = "renamed_private"]
pub(crate) unsafe extern "C" fn scoped_raw(ptr: *const u8) -> bool { !ptr.is_null() }

#[no_mangle]
extern "system" fn private_system(value: u32) -> u32 { value }

#[export_name = "private_unwind"]
pub(super) unsafe extern "C-unwind" fn scoped_unwind(ptr: *const u8) -> bool { !ptr.is_null() }

#[no_mangle]
extern "stdcall" fn private_unknown(value: u32) -> u32 { value }

#[no_mangle]
static PRIVATE_SCALAR: u32 = 7;

#[no_mangle]
fn unsupported_rust_abi(value: u32) -> u32 { value }

unsafe fn raw_static(ptr: *const u8, len: usize) -> &'static [u8] {
    unsafe { core::slice::from_raw_parts(ptr, len) }
}

fn tied_lifetime<'a>(borrowed: &'a [u8], _ptr: *const u8) -> &'a [u8] { borrowed }
'''
    try:
        with tempfile.TemporaryDirectory(prefix="duetos-rust-ffi-") as scratch:
            root = Path(scratch).resolve()
            crate_dir = root / "fixture"
            crate_dir.mkdir()
            source = crate_dir / "lib.rs"
            source.write_text(fixture, encoding="utf-8", newline="\n")
            crate = Crate("fixture", crate_dir, crate_dir / "Cargo.toml", "fixture")
            issues: list[Issue] = []
            exports = {item.name: item for item in parse_exports(root, crate, source, issues)}
            assert set(exports) == {
                "private_raw",
                "renamed_private",
                "private_system",
                "private_unwind",
                "private_unknown",
                "PRIVATE_SCALAR",
            }
            assert exports["private_raw"].has_raw_pointer
            assert not exports["private_raw"].is_unsafe
            assert exports["renamed_private"].is_unsafe
            assert exports["private_system"].abi == "system"
            assert exports["private_unwind"].abi == "C-unwind"
            assert exports["private_unknown"].abi not in ALLOWED_EXPORT_ABIS
            assert exports["PRIVATE_SCALAR"].kind == "static"
            assert any(issue.code == "FFI015" for issue in issues)

            find_unconstrained_lifetimes(root, source, issues)
            lifetime_messages = [issue.message for issue in issues if issue.code == "FFI003"]
            assert any(message.startswith("raw_static ") for message in lifetime_messages)
            assert not any(message.startswith("tied_lifetime ") for message in lifetime_messages)
    except (AssertionError, OSError) as error:
        print(f"check-rust-ffi self-test: FAIL: {error}", file=sys.stderr)
        return 1
    print("check-rust-ffi self-test: PASS")
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--aggregate-manifest", type=Path)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--emit-cmake-deps", action="store_true", help="print normalized build-input paths")
    mode.add_argument(
        "--emit-cmake-member-dirs",
        action="store_true",
        help="print normalized workspace member directories",
    )
    mode.add_argument("--self-test", action="store_true", help="run parser negative fixtures")
    parser.add_argument("--max-findings", type=int, default=200)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.self_test:
        return run_self_tests()
    root = args.repo_root.resolve()
    aggregate_manifest = (args.aggregate_manifest or root / AGGREGATE_MEMBER / "Cargo.toml").resolve()
    inventory = build_inventory(root, aggregate_manifest)
    build_errors = [issue for issue in inventory.issues if issue.severity == "error"]

    if args.emit_cmake_deps or args.emit_cmake_member_dirs:
        if build_errors:
            for issue in build_errors:
                location = issue.path + (f":{issue.line}" if issue.line else "")
                print(f"{issue.code} {location}: {issue.message}", file=sys.stderr)
            return 1
        paths = inventory.inputs if args.emit_cmake_deps else [crate.directory for crate in inventory.crates]
        for path in paths:
            if ";" in path.as_posix():
                print(f"BUILD025 path cannot be represented in a CMake list: {path}", file=sys.stderr)
                return 1
            print(path.as_posix())
        return 0

    subsystem_count = len(inventory.crates) - (1 if inventory.aggregate is not None else 0)
    header_count = sum(len(names) for names in inventory.header_names.values())
    print(
        "Rust FFI inventory: "
        f"{len(inventory.crates)} workspace members, "
        f"{subsystem_count} aggregate subsystem dependencies, "
        f"{len(inventory.inputs)} build inputs, "
        f"{len(inventory.exports)} Rust exports, "
        f"{header_count} C header symbol declarations"
    )
    issue_count = print_issues(inventory.issues, max(1, args.max_findings))
    if issue_count:
        print(f"check-rust-ffi: FAIL ({issue_count} issue(s))")
        return 1
    print("check-rust-ffi: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
