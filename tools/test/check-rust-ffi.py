#!/usr/bin/env python3
"""Audit Rust workspace build truth and the hand-written C FFI boundary.

The CMake integration also uses the two emit modes.  Those modes print only
normalized paths and fail on workspace/build-graph errors; the default audit
additionally fails on FFI safety findings so existing debt stays visible.
"""

from __future__ import annotations

import argparse
import os
import re
import stat
import subprocess
import sys
import tempfile
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


AGGREGATE_MEMBER = Path("kernel/rust")
SIGNATURE_CHECKER = Path("tools/test/check-rust-ffi-signatures.py")
SIGNATURE_CHECK_TIMEOUT_SECONDS = 60
MAX_WORKSPACE_MEMBERS = 128
MAX_INVENTORY_FILES = 20_000
MAX_INPUT_FILE_BYTES = 8 * 1024 * 1024
MAX_INVENTORY_BYTES = 64 * 1024 * 1024
MAX_CMAKE_OUTPUT_BYTES = 4 * 1024 * 1024
MAX_CMAKE_PATH_CHARS = 4_096
MAX_FFI_RECORDS = 20_000
MAX_ISSUE_RECORDS = 2_048
MAX_DIAGNOSTIC_CHARS = 2_048
WINDOWS_FILE_ATTRIBUTE_DIRECTORY = 0x10
WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT = 0x400
WINDOWS_REPARSE_TAG_NAME_SURROGATE = 0x20000000
ALLOWED_EXPORT_ABIS = frozenset({"C"})
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
INCLUDE_MACRO_RE = re.compile(
    r"\b(?P<macro>include|include_bytes|include_str)\s*!\s*(?P<delimiter>[({[])"
)
INCLUDE_LITERAL_RE = re.compile(
    r"\b(?P<macro>include|include_bytes|include_str)\s*!\s*\(\s*\"(?P<path>[^\"\r\n]+)\"\s*\)"
)
RUST_PATH_ATTRIBUTE_RE = re.compile(r"#\s*\[[^\]]*\bpath\s*=", re.DOTALL)


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


class InventoryBudgetExceeded(RuntimeError):
    pass


@dataclass
class RecordBudget:
    limit: int = MAX_FFI_RECORDS
    used: int = 0

    def count(self) -> None:
        self.used += 1
        if self.used > self.limit:
            raise InventoryBudgetExceeded(f"FFI inventory exceeds {self.limit} export/header records")


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
    if len(issues) >= MAX_ISSUE_RECORDS:
        raise InventoryBudgetExceeded(f"audit diagnostics exceed {MAX_ISSUE_RECORDS} records")
    normalized = message.replace("\r", "\\r").replace("\n", "\\n")
    if len(normalized) > MAX_DIAGNOSTIC_CHARS:
        marker = (
            "... signature diagnostics truncated"
            if "signature diagnostics truncated" in normalized
            else "... diagnostic truncated"
        )
        normalized = normalized[: MAX_DIAGNOSTIC_CHARS - len(marker)] + marker
    rendered_path = repo_relative(root, path)
    if len(rendered_path) > MAX_CMAKE_PATH_CHARS:
        rendered_path = rendered_path[:MAX_CMAKE_PATH_CHARS] + "... path truncated"
    issues.append(Issue(severity, code, rendered_path, line, normalized))


def read_utf8_bounded(path: Path) -> str:
    with path.open("rb") as stream:
        raw = stream.read(MAX_INPUT_FILE_BYTES + 1)
    if len(raw) > MAX_INPUT_FILE_BYTES:
        raise ValueError(f"input exceeds {MAX_INPUT_FILE_BYTES} bytes")
    return raw.decode("utf-8", errors="strict")


def windows_reparse_is_unsafe(attributes: int, tag: int | None) -> bool:
    if not attributes & WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT:
        return False
    if tag is None or tag == 0:
        return True
    return bool(tag & WINDOWS_REPARSE_TAG_NAME_SURROGATE)


def path_is_link_or_reparse(path: Path) -> bool:
    metadata = path.lstat()
    attributes = getattr(metadata, "st_file_attributes", 0)
    tag = getattr(metadata, "st_reparse_tag", None)
    return stat.S_ISLNK(metadata.st_mode) or windows_reparse_is_unsafe(attributes, tag)


def first_link_component(root: Path, path: Path) -> Path | None:
    """Return the first existing link/reparse component below root."""
    absolute = path.absolute()
    try:
        relative = absolute.relative_to(root)
    except ValueError:
        return absolute
    current = root
    for part in relative.parts:
        current /= part
        try:
            if path_is_link_or_reparse(current):
                return current
        except FileNotFoundError:
            return None
    return None


def collect_member_files(
    root: Path,
    directory: Path,
    issues: list[Issue],
    visited_entries: list[int],
    visited_bytes: list[int],
) -> tuple[list[Path], bool]:
    """Stream one member tree with a global hard entry bound and no links."""
    files: list[Path] = []
    pending = [directory]
    while pending:
        current = pending.pop()
        try:
            entries = os.scandir(current)
        except OSError as error:
            add_issue(issues, "error", "BUILD029", root, current, f"cannot scan workspace member: {error}")
            return files, False
        with entries:
            try:
                for entry in entries:
                    visited_entries[0] += 1
                    if visited_entries[0] > MAX_INVENTORY_FILES:
                        add_issue(
                            issues,
                            "error",
                            "BUILD023",
                            root,
                            directory,
                            f"workspace traversal exceeds {MAX_INVENTORY_FILES} entries",
                        )
                        return files, True

                    path = Path(entry.path)
                    try:
                        metadata = entry.stat(follow_symlinks=False)
                        attributes = getattr(metadata, "st_file_attributes", 0)
                        is_directory = entry.is_dir(follow_symlinks=False) or bool(
                            attributes & WINDOWS_FILE_ATTRIBUTE_DIRECTORY
                        )
                        is_link = entry.is_symlink() or windows_reparse_is_unsafe(
                            attributes, getattr(metadata, "st_reparse_tag", None)
                        )
                        if is_link:
                            add_issue(
                                issues,
                                "error",
                                "BUILD027",
                                root,
                                path,
                                "workspace build inputs may not contain symlinks or name-surrogate reparse points",
                            )
                            continue
                        if is_directory:
                            if current != directory or entry.name not in SKIP_DIRS:
                                pending.append(path)
                            continue
                        if not entry.is_file(follow_symlinks=False):
                            add_issue(
                                issues,
                                "error",
                                "BUILD029",
                                root,
                                path,
                                "unsupported non-file workspace entry",
                            )
                            continue
                        if metadata.st_size < 0 or metadata.st_size > MAX_INPUT_FILE_BYTES:
                            add_issue(
                                issues,
                                "error",
                                "BUILD030",
                                root,
                                path,
                                f"workspace file exceeds {MAX_INPUT_FILE_BYTES} bytes",
                            )
                            continue
                        visited_bytes[0] += metadata.st_size
                        if visited_bytes[0] > MAX_INVENTORY_BYTES:
                            add_issue(
                                issues,
                                "error",
                                "BUILD031",
                                root,
                                directory,
                                f"workspace inputs exceed {MAX_INVENTORY_BYTES} bytes",
                            )
                            return files, True
                        resolved = path.resolve(strict=True)
                        resolved.relative_to(root)
                        files.append(resolved)
                    except (OSError, ValueError) as error:
                        add_issue(
                            issues,
                            "error",
                            "BUILD028",
                            root,
                            path,
                            f"workspace entry cannot be retained safely: {error}",
                        )
            except OSError as error:
                add_issue(issues, "error", "BUILD029", root, current, f"workspace scan failed: {error}")
                return files, False
    return files, False


def check_signature_parity(
    root: Path,
    checker: Path,
    issues: list[Issue],
    timeout_seconds: float = SIGNATURE_CHECK_TIMEOUT_SECONDS,
) -> None:
    """Run the independently tested canonical C/Rust signature gate."""
    try:
        with tempfile.TemporaryFile() as diagnostic_stream:
            result = subprocess.run(
                [sys.executable, str(checker), "--repo-root", str(root)],
                cwd=root,
                stdout=diagnostic_stream,
                stderr=subprocess.STDOUT,
                timeout=timeout_seconds,
                check=False,
            )
            if result.returncode != 0:
                diagnostic_stream.seek(0)
                diagnostic_bytes = diagnostic_stream.read(16_385)
    except (OSError, subprocess.SubprocessError) as error:
        add_issue(
            issues,
            "error",
            "FFI013",
            root,
            checker,
            f"cannot execute canonical signature parity gate: {error}",
        )
        return

    if result.returncode == 0:
        return

    diagnostic = diagnostic_bytes[:16_384].decode("utf-8", errors="replace").strip()
    if len(diagnostic_bytes) > 16_384:
        diagnostic += "\n... signature diagnostics truncated"
    if not diagnostic:
        diagnostic = "no diagnostic output"
    add_issue(
        issues,
        "error",
        "FFI013",
        root,
        checker,
        f"canonical signature parity gate exited {result.returncode}:\n{diagnostic}",
    )


def read_toml(root: Path, path: Path, issues: list[Issue]) -> dict:
    try:
        return tomllib.loads(read_utf8_bounded(path))
    except (OSError, UnicodeError, ValueError, tomllib.TOMLDecodeError) as error:
        add_issue(issues, "error", "BUILD001", root, path, f"cannot parse manifest: {error}")
        return {}


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


def validate_local_dependency_table(
    root: Path,
    manifest: Path,
    owner_directory: Path,
    label: str,
    table: dict,
    crates_by_directory: dict[Path, Crate],
    issues: list[Issue],
) -> None:
    for alias, specification in table.items():
        if not isinstance(specification, dict) or "path" not in specification:
            continue
        raw_path = specification.get("path")
        if not isinstance(raw_path, str) or not raw_path or raw_path != raw_path.strip():
            add_issue(
                issues,
                "error",
                "BUILD033",
                root,
                manifest,
                f"[{label}] dependency {alias} has an invalid local path",
            )
            continue
        unresolved = owner_directory / raw_path
        try:
            unresolved.absolute().relative_to(root)
            linked_component = first_link_component(root, unresolved)
            if linked_component is not None:
                raise ValueError(f"path traverses {linked_component}")
            resolved = unresolved.resolve(strict=True)
            resolved.relative_to(root)
        except (OSError, ValueError) as error:
            add_issue(
                issues,
                "error",
                "BUILD033",
                root,
                manifest,
                f"[{label}] dependency {alias} escapes the audited workspace: {error}",
            )
            continue
        target = crates_by_directory.get(resolved)
        if target is None:
            add_issue(
                issues,
                "error",
                "BUILD033",
                root,
                manifest,
                f"[{label}] dependency {alias} is not an explicit audited workspace member",
            )
            continue
        expected_package = specification.get("package", alias)
        if expected_package != target.package:
            add_issue(
                issues,
                "error",
                "BUILD033",
                root,
                manifest,
                f"[{label}] dependency {alias} names {expected_package!r}, member package is {target.package!r}",
            )


def validate_manifest_compilation_graph(
    root: Path,
    crate: Crate,
    data: dict,
    crates_by_directory: dict[Path, Crate],
    issues: list[Issue],
) -> None:
    package = data.get("package")
    if isinstance(package, dict) and package.get("build") not in (None, False):
        add_issue(
            issues,
            "error",
            "BUILD032",
            root,
            crate.manifest,
            "custom package.build targets are outside the audited compilation graph",
        )
    if (crate.directory / "build.rs").is_file():
        add_issue(
            issues,
            "error",
            "BUILD032",
            root,
            crate.manifest,
            "build.rs is not permitted in the kernel Rust workspace",
        )

    for table_name in ("lib", "bin", "example", "test", "bench"):
        target = data.get(table_name)
        targets = target if isinstance(target, list) else [target]
        for entry in targets:
            if isinstance(entry, dict) and "path" in entry:
                add_issue(
                    issues,
                    "error",
                    "BUILD032",
                    root,
                    crate.manifest,
                    f"custom [{table_name}] path is outside the conventional audited source graph",
                )

    if data.get("patch") or data.get("replace"):
        add_issue(
            issues,
            "error",
            "BUILD034",
            root,
            crate.manifest,
            "manifest patch/replace tables are not permitted in the kernel Rust workspace",
        )
    for label, table in manifest_dependency_tables(data):
        validate_local_dependency_table(
            root, crate.manifest, crate.directory, label, table, crates_by_directory, issues
        )


def ancestor_file_candidates(root: Path, working_directory: Path, names: tuple[str, ...]) -> list[Path]:
    candidates: list[Path] = []
    current = working_directory.resolve()
    while True:
        current.relative_to(root)
        candidates.extend(current / name for name in names)
        if current == root:
            break
        current = current.parent
    return candidates


def cargo_config_candidates(root: Path, working_directory: Path) -> list[Path]:
    return ancestor_file_candidates(root, working_directory, (".cargo/config", ".cargo/config.toml"))


def rustup_toolchain_candidates(root: Path, working_directory: Path) -> list[Path]:
    return ancestor_file_candidates(root, working_directory, ("rust-toolchain", "rust-toolchain.toml"))


def validate_cargo_execution_environment(
    root: Path,
    cargo_working_directory: Path,
    cargo_home: Path,
    issues: list[Issue],
) -> None:
    try:
        working_directory = cargo_working_directory.resolve(strict=True)
        home = cargo_home.resolve(strict=True)
    except OSError as error:
        add_issue(
            issues,
            "error",
            "BUILD041",
            root,
            cargo_working_directory,
            f"controlled Cargo execution directory is unavailable: {error}",
        )
        return
    if not working_directory.is_dir() or not home.is_dir():
        add_issue(
            issues,
            "error",
            "BUILD041",
            root,
            cargo_working_directory,
            "controlled Cargo working directory and Cargo home must be directories",
        )
        return
    try:
        working_directory.relative_to(root)
    except ValueError:
        pass
    else:
        add_issue(
            issues,
            "error",
            "BUILD041",
            root,
            working_directory,
            "controlled Cargo working directory must be outside the repository configuration ancestry",
        )

    candidates: list[Path] = []
    current = working_directory
    while True:
        candidates.extend((current / ".cargo" / "config", current / ".cargo" / "config.toml"))
        if current.parent == current:
            break
        current = current.parent
    candidates.extend((home / "config", home / "config.toml"))
    for candidate in candidates:
        if candidate.exists():
            add_issue(
                issues,
                "error",
                "BUILD041",
                root,
                candidate,
                "ambient Cargo config is forbidden on the controlled execution search path",
            )


def validate_canonical_cargo_config(root: Path, path: Path, issues: list[Issue]) -> None:
    data = read_toml(root, path, issues)
    if data != EXPECTED_CARGO_CONFIG:
        add_issue(
            issues,
            "error",
            "BUILD039",
            root,
            path,
            "repository Cargo config must contain only the canonical target and build-std policy",
        )


def validate_canonical_rust_toolchain(root: Path, path: Path, issues: list[Issue]) -> None:
    data = read_toml(root, path, issues)
    if data != EXPECTED_RUST_TOOLCHAIN:
        add_issue(
            issues,
            "error",
            "BUILD040",
            root,
            path,
            "repository Rust toolchain must contain only the canonical dated channel, component, target, and profile",
        )


def validate_retained_input_budget(root: Path, inputs: Iterable[Path], issues: list[Issue]) -> None:
    total_bytes = 0
    for path in sorted(set(inputs), key=lambda item: item.as_posix()):
        try:
            size = path.stat().st_size
        except OSError as error:
            add_issue(issues, "error", "BUILD029", root, path, f"cannot stat retained build input: {error}")
            continue
        if size < 0 or size > MAX_INPUT_FILE_BYTES:
            add_issue(
                issues,
                "error",
                "BUILD030",
                root,
                path,
                f"workspace file exceeds {MAX_INPUT_FILE_BYTES} bytes",
            )
            continue
        total_bytes += size
        if total_bytes > MAX_INVENTORY_BYTES:
            add_issue(
                issues,
                "error",
                "BUILD031",
                root,
                path,
                f"retained workspace inputs exceed {MAX_INVENTORY_BYTES} bytes",
            )
            return


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


def parse_exports(
    root: Path,
    crate: Crate,
    rust_path: Path,
    issues: list[Issue],
    record_budget: RecordBudget | None = None,
) -> list[Export]:
    try:
        original = read_utf8_bounded(rust_path)
    except (OSError, UnicodeError, ValueError) as error:
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
        if record_budget is not None:
            record_budget.count()
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
        if record_budget is not None:
            record_budget.count()
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
        original = read_utf8_bounded(rust_path)
    except (OSError, UnicodeError, ValueError):
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


def parse_header_names(
    root: Path,
    header: Path,
    issues: list[Issue],
    record_budget: RecordBudget | None = None,
) -> set[str]:
    try:
        original = read_utf8_bounded(header)
    except (OSError, UnicodeError, ValueError) as error:
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
        if record_budget is not None:
            record_budget.count()
        names.add(match.group("name"))
    return names


def relevant_input(path: Path) -> bool:
    if path.parts and path.parts[0] in SKIP_DIRS:
        return False
    if path.name in {"Cargo.toml", "build.rs"}:
        return True
    if len(path.parts) >= 2 and path.parts[-2] == ".cargo" and path.name in {"config", "config.toml"}:
        return True
    return path.suffix in BUILD_SUFFIXES


def cmake_path_protocol_error(path: Path) -> str | None:
    rendered = path.as_posix()
    if len(rendered) > MAX_CMAKE_PATH_CHARS:
        return f"path exceeds {MAX_CMAKE_PATH_CHARS} characters"
    if ";" in rendered:
        return "path contains a CMake list separator"
    if "\r" in rendered or "\n" in rendered:
        return "path contains a line separator"
    if rendered != rendered.strip() or any(part != part.strip() for part in path.parts):
        return "path has leading or trailing whitespace"
    return None


def resolve_include_literals(root: Path, member_root: Path, rust_path: Path, issues: list[Issue]) -> set[Path]:
    try:
        original = read_utf8_bounded(rust_path)
    except (OSError, UnicodeError, ValueError):
        return set()
    code = strip_comments(original)
    for match in RUST_PATH_ATTRIBUTE_RE.finditer(code):
        add_issue(
            issues,
            "error",
            "BUILD032",
            root,
            rust_path,
            "#[path] and cfg_attr(path=...) are outside the conventional audited source graph",
            original.count("\n", 0, match.start()) + 1,
        )
    literal_starts = {match.start() for match in INCLUDE_LITERAL_RE.finditer(code)}
    for match in INCLUDE_MACRO_RE.finditer(code):
        if match.start() not in literal_starts:
            add_issue(
                issues,
                "error",
                "BUILD004",
                root,
                rust_path,
                "include!/include_bytes!/include_str! must use a parenthesized literal path so CMake can track it",
                original.count("\n", 0, match.start()) + 1,
            )
    includes: set[Path] = set()
    for match in INCLUDE_LITERAL_RE.finditer(code):
        unresolved = rust_path.parent / match.group("path")
        try:
            unresolved.absolute().relative_to(root)
        except ValueError:
            add_issue(issues, "error", "BUILD005", root, rust_path, "include macro escapes the repository")
            continue
        try:
            linked_component = first_link_component(root, unresolved)
        except OSError as error:
            add_issue(issues, "error", "BUILD029", root, rust_path, f"cannot inspect include path: {error}")
            continue
        if linked_component is not None:
            add_issue(
                issues,
                "error",
                "BUILD027",
                root,
                linked_component,
                "include path may not contain symlinks or reparse points",
            )
            continue
        try:
            candidate = unresolved.resolve(strict=True)
            candidate.relative_to(root)
        except ValueError:
            add_issue(issues, "error", "BUILD005", root, rust_path, "include macro escapes the repository")
            continue
        except OSError:
            add_issue(
                issues,
                "error",
                "BUILD006",
                root,
                rust_path,
                f"included file does not exist: {match.group('path')}",
            )
            continue
        if not candidate.is_file():
            add_issue(
                issues,
                "error",
                "BUILD006",
                root,
                rust_path,
                f"included path is not a regular file: {match.group('path')}",
            )
            continue
        if match.group("macro") == "include":
            try:
                candidate.relative_to(member_root)
            except ValueError:
                add_issue(
                    issues,
                    "error",
                    "BUILD032",
                    root,
                    rust_path,
                    "include! code must remain inside its owning workspace member",
                    original.count("\n", 0, match.start()) + 1,
                )
                continue
            if candidate.suffix != ".rs":
                add_issue(
                    issues,
                    "error",
                    "BUILD032",
                    root,
                    rust_path,
                    "include! code must name an in-member .rs source",
                    original.count("\n", 0, match.start()) + 1,
                )
                continue
        includes.add(candidate)
    return includes


def build_inventory(
    root: Path,
    aggregate_manifest: Path,
    cargo_working_directory: Path | None = None,
    cargo_home: Path | None = None,
) -> Inventory:
    issues: list[Issue] = []
    root_manifest = root / "Cargo.toml"
    try:
        root_manifest_link = first_link_component(root, root_manifest)
    except OSError as error:
        add_issue(issues, "error", "BUILD029", root, root_manifest, f"cannot inspect root manifest path: {error}")
        root_manifest_link = root_manifest
    if root_manifest_link is not None:
        add_issue(
            issues,
            "error",
            "BUILD027",
            root,
            root_manifest_link,
            "workspace manifest path may not contain symlinks or reparse points",
        )
        root_data: dict = {}
    else:
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
            or raw_member != raw_member.strip()
            or any(part != part.strip() for part in member_path.parts)
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
        unresolved_directory = root / member_path
        try:
            linked_component = first_link_component(root, unresolved_directory)
        except OSError as error:
            add_issue(
                issues,
                "error",
                "BUILD029",
                root,
                unresolved_directory,
                f"cannot inspect workspace member path: {error}",
            )
            continue
        if linked_component is not None:
            add_issue(
                issues,
                "error",
                "BUILD027",
                root,
                linked_component,
                f"workspace member path may not contain symlinks or reparse points: {raw_member}",
            )
            continue
        try:
            directory = unresolved_directory.resolve(strict=True)
        except OSError as error:
            add_issue(issues, "error", "BUILD010", root, unresolved_directory, f"workspace member is missing: {error}")
            continue
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
        try:
            manifest_link = first_link_component(root, manifest)
        except OSError as error:
            add_issue(issues, "error", "BUILD029", root, manifest, f"cannot inspect member manifest path: {error}")
            continue
        if manifest_link is not None:
            add_issue(
                issues,
                "error",
                "BUILD027",
                root,
                manifest_link,
                "member manifest path may not contain symlinks or reparse points",
            )
            continue
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

    crates_by_directory = {crate.directory: crate for crate in crates}
    if root_data.get("patch") or root_data.get("replace"):
        add_issue(
            issues,
            "error",
            "BUILD034",
            root,
            root_manifest,
            "workspace patch/replace tables are not permitted in the kernel Rust workspace",
        )
    workspace_dependencies = workspace.get("dependencies") if isinstance(workspace, dict) else None
    if isinstance(workspace_dependencies, dict):
        validate_local_dependency_table(
            root,
            root_manifest,
            root,
            "workspace.dependencies",
            workspace_dependencies,
            crates_by_directory,
            issues,
        )
    for crate in crates:
        validate_manifest_compilation_graph(
            root, crate, read_toml(root, crate.manifest, issues), crates_by_directory, issues
        )

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
            aggregate_text = strip_comments(read_utf8_bounded(aggregate_source))
        except (OSError, UnicodeError, ValueError) as error:
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
        root / SIGNATURE_CHECKER,
    ]
    inputs: set[Path] = set()
    for required in required_root_inputs:
        try:
            linked_component = first_link_component(root, required)
        except OSError as error:
            add_issue(issues, "error", "BUILD029", root, required, f"cannot inspect required input path: {error}")
            continue
        if linked_component is not None:
            add_issue(
                issues,
                "error",
                "BUILD027",
                root,
                linked_component,
                "workspace build input path may not contain symlinks or reparse points",
            )
        elif not required.is_file():
            add_issue(issues, "error", "BUILD022", root, required, "required workspace build input is missing")
        else:
            try:
                resolved = required.resolve(strict=True)
                resolved.relative_to(root)
                inputs.add(resolved)
            except (OSError, ValueError) as error:
                add_issue(issues, "error", "BUILD028", root, required, f"required input escapes repository: {error}")

    if aggregate is not None:
        config_candidates = cargo_config_candidates(root, aggregate.directory)
        canonical_config = root / CANONICAL_CARGO_CONFIG
        for index in range(0, len(config_candidates), 2):
            extensionless = config_candidates[index]
            toml_config = config_candidates[index + 1]
            if extensionless.exists() and toml_config.exists():
                add_issue(
                    issues,
                    "error",
                    "BUILD035",
                    root,
                    extensionless.parent,
                    "Cargo config and config.toml both exist at one search level",
                )
        for candidate in config_candidates:
            if not candidate.exists():
                continue
            if candidate != canonical_config:
                add_issue(
                    issues,
                    "error",
                    "BUILD039",
                    root,
                    candidate,
                    "only the repository-root .cargo/config.toml is permitted",
                )
                continue
            try:
                linked_component = first_link_component(root, candidate)
                if linked_component is not None:
                    raise ValueError(f"path traverses {linked_component}")
                resolved = candidate.resolve(strict=True)
                resolved.relative_to(root)
                if not resolved.is_file():
                    raise ValueError("Cargo config input is not a regular file")
                inputs.add(resolved)
            except (OSError, ValueError) as error:
                add_issue(
                    issues,
                    "error",
                    "BUILD028",
                    root,
                    candidate,
                    f"Cargo config input cannot be retained safely: {error}",
                )
        if canonical_config.is_file():
            validate_canonical_cargo_config(root, canonical_config, issues)

        canonical_toolchain = root / CANONICAL_RUST_TOOLCHAIN
        for candidate in rustup_toolchain_candidates(root, aggregate.directory):
            if candidate.exists() and candidate != canonical_toolchain:
                add_issue(
                    issues,
                    "error",
                    "BUILD037",
                    root,
                    candidate,
                    "only the repository-root rust-toolchain.toml override is permitted",
                )
        if canonical_toolchain.is_file():
            validate_canonical_rust_toolchain(root, canonical_toolchain, issues)

    if (cargo_working_directory is None) != (cargo_home is None):
        add_issue(
            issues,
            "error",
            "BUILD041",
            root,
            root,
            "controlled Cargo working directory and Cargo home must be supplied together",
        )
    elif cargo_working_directory is not None and cargo_home is not None:
        validate_cargo_execution_environment(root, cargo_working_directory, cargo_home, issues)

    rust_sources: dict[str, list[Path]] = {}
    header_names: dict[str, set[str]] = {}
    exports: list[Export] = []
    record_budget = RecordBudget()
    visited_entries = [0]
    visited_bytes = [0]
    traversal_exhausted = False
    for crate in crates:
        crate_inputs: list[Path] = []
        headers: list[Path] = []
        sources: list[Path] = []
        member_files, traversal_exhausted = collect_member_files(
            root, crate.directory, issues, visited_entries, visited_bytes
        )
        for path in member_files:
            if not relevant_input(path.relative_to(crate.directory)):
                continue
            crate_inputs.append(path)
            if path.suffix == ".rs":
                sources.append(path)
            if path.suffix in {".h", ".hh", ".hpp", ".hxx"}:
                headers.append(path)
        if traversal_exhausted:
            break
        if not sources:
            add_issue(issues, "error", "BUILD024", root, crate.manifest, "workspace member has no Rust source")
        rust_sources[crate.member] = sorted(sources, key=lambda path: path.as_posix())
        inputs.update(crate_inputs)
        declared: set[str] = set()
        for header in sorted(headers, key=lambda path: path.as_posix()):
            declared.update(parse_header_names(root, header, issues, record_budget))
        header_names[crate.member] = declared
        for source in rust_sources[crate.member]:
            exports.extend(parse_exports(root, crate, source, issues, record_budget))
            find_unconstrained_lifetimes(root, source, issues)
            inputs.update(resolve_include_literals(root, crate.directory, source, issues))

    validate_retained_input_budget(root, inputs, issues)

    if traversal_exhausted:
        for crate in crates:
            rust_sources.setdefault(crate.member, [])
            header_names.setdefault(crate.member, set())

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

    signature_checker = root / SIGNATURE_CHECKER
    try:
        signature_checker_link = first_link_component(root, signature_checker)
    except OSError:
        signature_checker_link = signature_checker
    if (
        not any(issue.severity == "error" for issue in issues)
        and signature_checker_link is None
        and signature_checker.is_file()
    ):
        check_signature_parity(root, signature_checker, issues)

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
    global MAX_INPUT_FILE_BYTES, MAX_INVENTORY_BYTES, MAX_INVENTORY_FILES

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
            assert exports["private_system"].abi not in ALLOWED_EXPORT_ABIS
            assert exports["private_unwind"].abi not in ALLOWED_EXPORT_ABIS
            assert exports["private_unknown"].abi not in ALLOWED_EXPORT_ABIS
            assert exports["PRIVATE_SCALAR"].kind == "static"
            assert any(issue.code == "FFI015" for issue in issues)

            find_unconstrained_lifetimes(root, source, issues)
            lifetime_messages = [issue.message for issue in issues if issue.code == "FFI003"]
            assert any(message.startswith("raw_static ") for message in lifetime_messages)
            assert not any(message.startswith("tied_lifetime ") for message in lifetime_messages)

            passing_checker = root / "passing-signature-checker.py"
            passing_checker.write_text("raise SystemExit(0)\n", encoding="utf-8", newline="\n")
            parity_issues: list[Issue] = []
            check_signature_parity(root, passing_checker, parity_issues)
            assert parity_issues == []

            failing_checker = root / "failing-signature-checker.py"
            failing_checker.write_text(
                'print("RFS006 include/demo.h:7: parameter mismatch")\nraise SystemExit(1)\n',
                encoding="utf-8",
                newline="\n",
            )
            check_signature_parity(root, failing_checker, parity_issues)
            assert len(parity_issues) == 1
            assert parity_issues[0].severity == "error"
            assert parity_issues[0].code == "FFI013"
            assert "RFS006 include/demo.h:7" in parity_issues[0].message

            timeout_checker = root / "timeout-signature-checker.py"
            timeout_checker.write_text("import time\ntime.sleep(2)\n", encoding="utf-8", newline="\n")
            timeout_issues: list[Issue] = []
            check_signature_parity(root, timeout_checker, timeout_issues, timeout_seconds=0.05)
            assert len(timeout_issues) == 1
            assert timeout_issues[0].severity == "error"
            assert timeout_issues[0].code == "FFI013"

            noisy_checker = root / "noisy-signature-checker.py"
            noisy_checker.write_text(
                'print("X" * 20000)\nraise SystemExit(1)\n', encoding="utf-8", newline="\n"
            )
            noisy_issues: list[Issue] = []
            check_signature_parity(root, noisy_checker, noisy_issues)
            assert len(noisy_issues) == 1
            assert "signature diagnostics truncated" in noisy_issues[0].message
            assert len(noisy_issues[0].message) < 16_500

            assert cmake_path_protocol_error(Path("safe/member/lib.rs")) is None
            assert cmake_path_protocol_error(Path("bad;member/lib.rs")) is not None
            assert cmake_path_protocol_error(Path("bad\nmember/lib.rs")) is not None
            assert cmake_path_protocol_error(Path("member/trailing ")) is not None
            assert not windows_reparse_is_unsafe(0, None)
            assert windows_reparse_is_unsafe(WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT, None)
            assert windows_reparse_is_unsafe(WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT, 0xA000000C)
            assert not windows_reparse_is_unsafe(WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT, 0x9000001A)

            bounded_records = RecordBudget(limit=1)
            bounded_issues: list[Issue] = []
            try:
                parse_exports(root, crate, source, bounded_issues, bounded_records)
            except InventoryBudgetExceeded:
                pass
            else:
                raise AssertionError("FFI record budget did not fail closed")

            graph_member = root / "graph-member"
            graph_member.mkdir()
            graph_source = graph_member / "lib.rs"
            graph_source.write_text('#[path = "alternate.rs"]\nmod alternate;\n', encoding="utf-8", newline="\n")
            graph_issues: list[Issue] = []
            resolve_include_literals(root, graph_member, graph_source, graph_issues)
            assert any(issue.code == "BUILD032" for issue in graph_issues)

            hostile_include = graph_member / "hostile-include.rs"
            hostile_include.write_text(
                'const BYTES: &[u8] = include_bytes /* gap */ ! { "../outside.bin" };\n',
                encoding="utf-8",
                newline="\n",
            )
            include_issues: list[Issue] = []
            assert resolve_include_literals(root, graph_member, hostile_include, include_issues) == set()
            assert any(issue.code == "BUILD004" for issue in include_issues)

            expected_toolchain_candidates = {
                graph_member / "rust-toolchain",
                graph_member / "rust-toolchain.toml",
                root / "rust-toolchain",
                root / "rust-toolchain.toml",
            }
            assert set(rustup_toolchain_candidates(root, graph_member)) == expected_toolchain_candidates

            canonical_config = root / CANONICAL_CARGO_CONFIG
            canonical_config.parent.mkdir()
            canonical_config.write_text(
                '[build]\ntarget="x86_64-unknown-none"\n'
                '[unstable]\nbuild-std=["core","alloc"]\n'
                'build-std-features=["compiler-builtins-mem"]\n',
                encoding="utf-8",
                newline="\n",
            )
            config_issues: list[Issue] = []
            validate_canonical_cargo_config(root, canonical_config, config_issues)
            assert config_issues == []
            canonical_config.write_text('[build]\nrustc-wrapper="outside"\n', encoding="utf-8", newline="\n")
            validate_canonical_cargo_config(root, canonical_config, config_issues)
            assert any(issue.code == "BUILD039" for issue in config_issues)

            canonical_toolchain = root / CANONICAL_RUST_TOOLCHAIN
            canonical_toolchain.write_text(
                '[toolchain]\nchannel="nightly-2026-01-15"\ncomponents=["rust-src"]\n'
                'targets=["x86_64-unknown-none"]\nprofile="minimal"\n',
                encoding="utf-8",
                newline="\n",
            )
            toolchain_issues: list[Issue] = []
            validate_canonical_rust_toolchain(root, canonical_toolchain, toolchain_issues)
            assert toolchain_issues == []
            canonical_toolchain.write_text(
                '[toolchain]\nchannel="nightly"\ncomponents=["rust-src"]\n'
                'targets=["x86_64-unknown-none"]\nprofile="minimal"\n',
                encoding="utf-8",
                newline="\n",
            )
            validate_canonical_rust_toolchain(root, canonical_toolchain, toolchain_issues)
            assert any(issue.code == "BUILD040" for issue in toolchain_issues)

            with tempfile.TemporaryDirectory(prefix="duetos-cargo-sandbox-") as cargo_scratch:
                cargo_root = Path(cargo_scratch).resolve()
                cargo_work = cargo_root / "work"
                cargo_home = cargo_root / "home"
                cargo_work.mkdir()
                cargo_home.mkdir()
                cargo_issues: list[Issue] = []
                validate_cargo_execution_environment(root, cargo_work, cargo_home, cargo_issues)
                assert cargo_issues == []
                (cargo_work / ".cargo").mkdir()
                (cargo_work / ".cargo" / "config.toml").write_text(
                    '[build]\nrustc-wrapper="outside"\n', encoding="utf-8", newline="\n"
                )
                validate_cargo_execution_environment(root, cargo_work, cargo_home, cargo_issues)
                assert any(issue.code == "BUILD041" for issue in cargo_issues)

            retained_one = root / "retained-one"
            retained_two = root / "retained-two"
            retained_one.write_bytes(b"123")
            retained_two.write_bytes(b"456")
            original_total_limit = MAX_INVENTORY_BYTES
            try:
                MAX_INVENTORY_BYTES = 5
                retained_issues: list[Issue] = []
                validate_retained_input_budget(root, {retained_one, retained_two}, retained_issues)
                assert any(issue.code == "BUILD031" for issue in retained_issues)
            finally:
                MAX_INVENTORY_BYTES = original_total_limit

            walk_root = root / "walk"
            walk_root.mkdir()
            (walk_root / "kept.rs").write_text("pub fn kept() {}\n", encoding="utf-8", newline="\n")
            (walk_root / "target").mkdir()
            (walk_root / "target" / "ignored.rs").write_text(
                "compile_error!(\"must stay pruned\");\n", encoding="utf-8", newline="\n"
            )
            nested_target = walk_root / "src" / "target"
            nested_target.mkdir(parents=True)
            (nested_target / "mod.rs").write_text("pub fn audited() {}\n", encoding="utf-8", newline="\n")
            walk_issues: list[Issue] = []
            walked, exhausted = collect_member_files(root, walk_root, walk_issues, [0], [0])
            assert not exhausted
            assert {path.relative_to(walk_root).as_posix() for path in walked} == {
                "kept.rs",
                "src/target/mod.rs",
            }
            assert walk_issues == []

            link_target = root / "link-target"
            link_target.mkdir()
            linked_directory = walk_root / "linked-directory"
            try:
                linked_directory.symlink_to(link_target, target_is_directory=True)
            except OSError:
                pass  # Windows without Developer Mode cannot create this fixture.
            else:
                walk_issues = []
                walked, exhausted = collect_member_files(root, walk_root, walk_issues, [0], [0])
                assert not exhausted
                assert all(path.name != "linked-directory" for path in walked)
                assert any(issue.code == "BUILD027" for issue in walk_issues)

            capped_root = root / "capped"
            capped_root.mkdir()
            for index in range(5):
                (capped_root / f"entry-{index}.rs").write_text("", encoding="utf-8")
            original_limit = MAX_INVENTORY_FILES
            try:
                MAX_INVENTORY_FILES = 3
                cap_issues: list[Issue] = []
                _, exhausted = collect_member_files(root, capped_root, cap_issues, [0], [0])
                assert exhausted
                assert any(issue.code == "BUILD023" for issue in cap_issues)
            finally:
                MAX_INVENTORY_FILES = original_limit

            oversized_root = root / "oversized"
            oversized_root.mkdir()
            (oversized_root / "large.rs").write_text("12345", encoding="utf-8")
            original_file_limit = MAX_INPUT_FILE_BYTES
            try:
                MAX_INPUT_FILE_BYTES = 4
                size_issues: list[Issue] = []
                _, exhausted = collect_member_files(root, oversized_root, size_issues, [0], [0])
                assert not exhausted
                assert any(issue.code == "BUILD030" for issue in size_issues)
            finally:
                MAX_INPUT_FILE_BYTES = original_file_limit

            total_root = root / "total-bytes"
            total_root.mkdir()
            (total_root / "one.rs").write_text("123", encoding="utf-8")
            (total_root / "two.rs").write_text("456", encoding="utf-8")
            original_total_limit = MAX_INVENTORY_BYTES
            try:
                MAX_INVENTORY_BYTES = 5
                total_issues: list[Issue] = []
                _, exhausted = collect_member_files(root, total_root, total_issues, [0], [0])
                assert exhausted
                assert any(issue.code == "BUILD031" for issue in total_issues)
            finally:
                MAX_INVENTORY_BYTES = original_total_limit
    except (AssertionError, OSError) as error:
        print(f"check-rust-ffi self-test: FAIL: {error}", file=sys.stderr)
        return 1
    print("check-rust-ffi self-test: PASS")
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--aggregate-manifest", type=Path)
    parser.add_argument("--cargo-working-directory", type=Path)
    parser.add_argument("--cargo-home", type=Path)
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
    try:
        inventory = build_inventory(
            root,
            aggregate_manifest,
            args.cargo_working_directory,
            args.cargo_home,
        )
    except InventoryBudgetExceeded as error:
        print(f"BUILD038 bounded inventory exhausted: {error}", file=sys.stderr)
        return 2
    build_errors = [issue for issue in inventory.issues if issue.severity == "error"]

    if args.emit_cmake_deps or args.emit_cmake_member_dirs:
        if build_errors:
            diagnostic_limit = min(len(build_errors), 200)
            for issue in build_errors[:diagnostic_limit]:
                location = issue.path + (f":{issue.line}" if issue.line else "")
                print(f"{issue.code} {location}: {issue.message}", file=sys.stderr)
            if len(build_errors) > diagnostic_limit:
                print(f"... {len(build_errors) - diagnostic_limit} additional build error(s) omitted", file=sys.stderr)
            return 1
        paths = inventory.inputs if args.emit_cmake_deps else [crate.directory for crate in inventory.crates]
        rendered_paths: list[str] = []
        output_bytes = 0
        for path in paths:
            protocol_error = cmake_path_protocol_error(path)
            if protocol_error is not None:
                print(f"BUILD025 path cannot be represented safely ({protocol_error}): {path}", file=sys.stderr)
                return 1
            rendered = path.as_posix()
            output_bytes += len(rendered.encode("utf-8")) + 1
            if output_bytes > MAX_CMAKE_OUTPUT_BYTES:
                print(
                    f"BUILD036 CMake dependency output exceeds {MAX_CMAKE_OUTPUT_BYTES} bytes",
                    file=sys.stderr,
                )
                return 1
            rendered_paths.append(rendered)
        print("\n".join(rendered_paths))
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
