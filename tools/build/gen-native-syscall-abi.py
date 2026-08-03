#!/usr/bin/env python3
"""Generate and verify the versioned DuetOS native syscall inventory.

The JSON IDL is the migration source for native syscall identity, policy,
tracing, fuzzing, and userland number constants.  During the strangler phase,
``--check-legacy`` also proves that the handwritten enum/name/capability tables
have not diverged from it.  Consumers can move to the generated artifacts one
at a time without creating a second silently-drifting ABI description.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any


SCHEMA_NAME = "duetos.native-syscalls"
SCHEMA_VERSION = 1
ABI_NAME = "duetos-native-x86_64"
REGISTER_ORDER = ("rdi", "rsi", "rdx", "r10", "r8", "r9")
REGISTER_INDEX = {name: index for index, name in enumerate(REGISTER_ORDER)}
NAME_RE = re.compile(r"SYS_[A-Z0-9_]+\Z")
ENUM_RE = re.compile(r"^\s*(SYS_[A-Z0-9_]+)\s*=\s*(0x[0-9A-Fa-f]+|\d+)\s*,", re.MULTILINE)
NAMES_RE = re.compile(r"^\s*X\(\s*(SYS_[A-Z0-9_]+)\s*,\s*(0x[0-9A-Fa-f]+|\d+)\s*\)", re.MULTILINE)
CAP_ROW_RE = re.compile(r"^\s*X\(\s*(SYS_[A-Z0-9_]+)\s*,\s*(.+)\)\s*$")
CAP_NAME_RE = re.compile(r"::duetos::core::(kCap[A-Za-z0-9_]+)")
ARG_RE = re.compile(r"\b(rdi|rsi|rdx|r10|r8|r9)\s*=\s*", re.IGNORECASE)
RETURN_RE = re.compile(r"\breturns?\s+([^.;]+)", re.IGNORECASE)

AUTH_MODES = {"none", "static", "dynamic"}
OBJECT_RIGHT_MODES = {"none", "static", "dynamic"}
ARG_KINDS = {"scalar", "handle", "user_pointer", "user_buffer", "size", "flags", "identifier"}
FUZZ_PROFILES = {"scalar", "pointer", "buffer", "handle", "mixed"}


class IdlError(RuntimeError):
    """Raised for an IDL or legacy-drift failure."""


def fail(message: str) -> None:
    raise IdlError(message)


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except OSError as exc:
        fail(f"cannot read {path}: {exc}")


def strip_c_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
    return re.sub(r"//[^\n]*", "", text)


def parse_number_map(pattern: re.Pattern[str], text: str, source: str) -> dict[str, int]:
    result: dict[str, int] = {}
    numbers: dict[int, str] = {}
    for match in pattern.finditer(text):
        name = match.group(1)
        number = int(match.group(2), 0)
        if name in result:
            fail(f"{source}: duplicate symbol {name}")
        if number in numbers:
            fail(f"{source}: number {number} is shared by {numbers[number]} and {name}")
        result[name] = number
        numbers[number] = name
    if not result:
        fail(f"{source}: parsed zero syscall rows")
    return result


def parse_cap_table(text: str, source: str) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    for line_no, line in enumerate(strip_c_comments(text).splitlines(), start=1):
        if not line.strip():
            continue
        match = CAP_ROW_RE.match(line)
        if not match:
            continue
        name, expression = match.groups()
        caps = CAP_NAME_RE.findall(expression)
        if not caps:
            fail(f"{source}:{line_no}: {name} has no recognizable capability")
        if len(set(caps)) != len(caps):
            fail(f"{source}:{line_no}: {name} repeats a capability")
        if name in result:
            fail(f"{source}:{line_no}: duplicate policy row for {name}")
        result[name] = caps
    return result


def adjacent_enum_docs(text: str) -> dict[str, str]:
    docs: dict[str, str] = {}
    pending: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("//"):
            pending.append(stripped[2:].strip())
            continue
        match = re.match(r"\s*(SYS_[A-Z0-9_]+)\s*=\s*(?:0x[0-9A-Fa-f]+|\d+)\s*,", line)
        if match:
            docs[match.group(1)] = " ".join(pending).strip()
            pending = []
            continue
        if stripped:
            pending = []
    return docs


def extract_arguments(doc: str) -> list[dict[str, str]]:
    matches = list(ARG_RE.finditer(doc))
    arguments: list[dict[str, str]] = []
    for index, match in enumerate(matches):
        register = match.group(1).lower()
        if any(arg["register"] == register for arg in arguments):
            continue
        end = matches[index + 1].start() if index + 1 < len(matches) else len(doc)
        description = doc[match.end() : end].strip(" ,;.-")
        # A register clause ends at the first sentence/semicolon.  Without
        # this boundary, prose such as "Returns an event handle" would make
        # the preceding boolean argument look like a handle to the fuzzer.
        description = re.split(r"[.;]|,\s*(?=returns?\b)", description, maxsplit=1, flags=re.IGNORECASE)[0].strip(
            " ,-"
        )
        if len(description) > 180:
            description = description[:177].rstrip() + "..."
        lowered = description.lower()
        if "handle" in lowered:
            kind = "handle"
        elif "buffer" in lowered or "array" in lowered:
            kind = "user_buffer"
        elif "pointer" in lowered or "user " in lowered or "address" in lowered or " va" in lowered:
            kind = "user_pointer"
        elif "size" in lowered or "length" in lowered or "count" in lowered:
            kind = "size"
        elif "flag" in lowered or "mask" in lowered or "option" in lowered:
            kind = "flags"
        elif "pid" in lowered or "tid" in lowered or "index" in lowered or " id" in lowered:
            kind = "identifier"
        else:
            kind = "scalar"
        arguments.append(
            {
                "register": register,
                "kind": kind,
                "description": description or "Legacy documentation does not describe this argument.",
            }
        )
    arguments.sort(key=lambda item: REGISTER_INDEX[item["register"]])
    return arguments


def extract_return(doc: str) -> str:
    match = RETURN_RE.search(doc)
    if not match:
        return "Legacy documentation does not state the return contract."
    result = match.group(1).strip()
    return result[:240].rstrip() + ("..." if len(result) > 240 else "")


def trace_category(name: str) -> str:
    stem = name.removeprefix("SYS_")
    families = (
        (("FILE_", "DIR_", "STAT", "READ", "WRITE"), "filesystem"),
        (("WIN_", "GDI_", "GFX_", "VK_"), "graphics"),
        (("SOCKET_",), "network"),
        (("PROCESS_", "THREAD_", "SPAWN", "EXECVE", "GETPID", "GETPROCID", "PRIORITY_"), "process"),
        (("VM_", "VMAP", "VUNMAP", "VIRTUAL_", "HEAP"), "memory"),
        (("MUTEX_", "EVENT_", "SEM_", "WAIT_", "WAKE_", "IOCP_", "NAMED_", "QUEUE_", "DRAIN_"), "ipc"),
        (("TLS_", "FLS_", "FIBER_"), "runtime"),
        (("AUDIO_",), "audio"),
        (("DEBUG_", "BP_", "DIAG_", "SYSTEM_PERFORMANCE"), "diagnostic"),
        (("GETTIME_", "NOW_", "SLEEP_", "PERF_", "ST_TO_", "FT_TO_"), "time"),
    )
    for prefixes, category in families:
        if any(stem.startswith(prefix) for prefix in prefixes):
            return category
    return "system"


def fuzz_profile(arguments: list[dict[str, str]]) -> str:
    kinds = {arg["kind"] for arg in arguments}
    pointer = bool(kinds & {"user_pointer", "user_buffer"})
    handle = "handle" in kinds
    if pointer and handle:
        return "mixed"
    if "user_buffer" in kinds:
        return "buffer"
    if "user_pointer" in kinds:
        return "pointer"
    if handle:
        return "handle"
    return "scalar"


def bootstrap_document(syscall_h: Path, names_def: Path, cap_table: Path) -> dict[str, Any]:
    header_text = read_text(syscall_h)
    enum_map = parse_number_map(ENUM_RE, header_text, str(syscall_h))
    names_map = parse_number_map(NAMES_RE, read_text(names_def), str(names_def))
    extra_names = sorted(set(names_map) - set(enum_map))
    changed_names = sorted(name for name in set(names_map) & set(enum_map) if names_map[name] != enum_map[name])
    if extra_names or changed_names:
        fail(
            "legacy syscall_names.def contradicts the enum: "
            f"extra={extra_names}, renumbered={changed_names}"
        )
    cap_map = parse_cap_table(read_text(cap_table), str(cap_table))
    unknown_caps = sorted(set(cap_map) - set(enum_map))
    if unknown_caps:
        fail(f"capability table contains unknown syscall(s): {', '.join(unknown_caps)}")

    docs = adjacent_enum_docs(header_text)
    rows: list[dict[str, Any]] = []
    for name, number in sorted(enum_map.items(), key=lambda item: item[1]):
        doc = docs.get(name, "")
        arguments = extract_arguments(doc)
        caps = cap_map.get(name, [])
        if caps:
            authorization: dict[str, Any] = {
                "mode": "static",
                "capabilities": caps,
                "owner": "kernel/syscall/cap_gate.cpp",
                "rationale": "The generated pre-dispatch capability gate requires every listed capability.",
            }
        else:
            authorization = {
                "mode": "dynamic",
                "capabilities": [],
                "owner": "kernel/syscall/syscall.cpp",
                "rationale": "The dispatcher or delegated handler owns argument-dependent or intentionally open policy.",
            }
        has_handle = any(arg["kind"] == "handle" for arg in arguments)
        rights = {
            "mode": "dynamic" if has_handle else "none",
            "rights": [],
            "owner": "delegated handler" if has_handle else "none",
            "rationale": (
                "The delegated typed-handle lookup enforces rights after hostile token decoding."
                if has_handle
                else "No handle argument is declared by the migrated ABI documentation."
            ),
        }
        rows.append(
            {
                "number": number,
                "name": name,
                "status": "implemented",
                "authorization": authorization,
                "object_rights": rights,
                "trace": {"category": trace_category(name), "sensitive": False},
                "fuzz": {"enabled": True, "profile": fuzz_profile(arguments)},
                "arguments": arguments,
                "returns": extract_return(doc),
                "summary": doc[:400] if doc else "No adjacent legacy documentation was available during migration.",
            }
        )

    return {
        "schema": SCHEMA_NAME,
        "schema_version": SCHEMA_VERSION,
        "abi": ABI_NAME,
        "calling_convention": {
            "number_register": "rax",
            "argument_registers": list(REGISTER_ORDER),
            "return_register": "rax",
        },
        "migration": {
            "legacy_number_source": "kernel/syscall/syscall.h",
            "legacy_name_source": "kernel/syscall/syscall_names.def",
            "legacy_policy_source": "kernel/syscall/cap_table.def",
            "dynamic_policy_requires_owner_audit": True,
        },
        "syscalls": rows,
    }


def require_string(value: Any, where: str) -> str:
    if not isinstance(value, str) or not value.strip():
        fail(f"{where}: expected a non-empty string")
    return value


def validate_document(document: Any) -> list[dict[str, Any]]:
    if not isinstance(document, dict):
        fail("IDL root must be an object")
    if document.get("schema") != SCHEMA_NAME or document.get("schema_version") != SCHEMA_VERSION:
        fail(f"IDL must declare {SCHEMA_NAME} schema version {SCHEMA_VERSION}")
    if document.get("abi") != ABI_NAME:
        fail(f"IDL abi must be {ABI_NAME}")
    convention = document.get("calling_convention")
    if not isinstance(convention, dict) or convention.get("number_register") != "rax" or convention.get(
        "argument_registers"
    ) != list(REGISTER_ORDER) or convention.get("return_register") != "rax":
        fail("calling_convention does not match the frozen x86_64 native ABI")
    rows = document.get("syscalls")
    if not isinstance(rows, list) or not rows:
        fail("IDL syscalls must be a non-empty array")

    seen_names: set[str] = set()
    seen_numbers: set[int] = set()
    previous_number = -1
    for index, row in enumerate(rows):
        where = f"syscalls[{index}]"
        if not isinstance(row, dict):
            fail(f"{where}: row must be an object")
        name = require_string(row.get("name"), f"{where}.name")
        if not NAME_RE.fullmatch(name):
            fail(f"{where}.name: invalid native syscall symbol {name!r}")
        number = row.get("number")
        if not isinstance(number, int) or isinstance(number, bool) or number < 0 or number > 0x7FFFFFFF:
            fail(f"{where}.number: expected a non-negative 31-bit integer")
        if number <= previous_number:
            fail(f"{where}.number: rows must be strictly increasing")
        previous_number = number
        if name in seen_names or number in seen_numbers:
            fail(f"{where}: duplicate name or number")
        seen_names.add(name)
        seen_numbers.add(number)
        if row.get("status") not in {"implemented", "reserved", "retired"}:
            fail(f"{where}.status: unsupported status")

        auth = row.get("authorization")
        if not isinstance(auth, dict) or auth.get("mode") not in AUTH_MODES:
            fail(f"{where}.authorization: invalid mode")
        caps = auth.get("capabilities")
        if not isinstance(caps, list) or any(not isinstance(cap, str) or not re.fullmatch(r"kCap[A-Za-z0-9_]+", cap) for cap in caps):
            fail(f"{where}.authorization.capabilities: invalid capability list")
        if len(set(caps)) != len(caps):
            fail(f"{where}.authorization.capabilities: duplicate capability")
        require_string(auth.get("owner"), f"{where}.authorization.owner")
        require_string(auth.get("rationale"), f"{where}.authorization.rationale")
        if auth["mode"] == "static" and not caps:
            fail(f"{where}.authorization: static policy needs at least one capability")
        if auth["mode"] != "static" and caps:
            fail(f"{where}.authorization: only static policy may list capabilities")

        rights = row.get("object_rights")
        if not isinstance(rights, dict) or rights.get("mode") not in OBJECT_RIGHT_MODES:
            fail(f"{where}.object_rights: invalid mode")
        right_names = rights.get("rights")
        if not isinstance(right_names, list) or any(not isinstance(item, str) or not item for item in right_names):
            fail(f"{where}.object_rights.rights: invalid list")
        if rights["mode"] != "static" and right_names:
            fail(f"{where}.object_rights: only static mode may list rights")
        require_string(rights.get("owner"), f"{where}.object_rights.owner")
        require_string(rights.get("rationale"), f"{where}.object_rights.rationale")

        trace = row.get("trace")
        if not isinstance(trace, dict):
            fail(f"{where}.trace: expected object")
        require_string(trace.get("category"), f"{where}.trace.category")
        if not isinstance(trace.get("sensitive"), bool):
            fail(f"{where}.trace.sensitive: expected boolean")
        fuzz = row.get("fuzz")
        if not isinstance(fuzz, dict) or not isinstance(fuzz.get("enabled"), bool) or fuzz.get(
            "profile"
        ) not in FUZZ_PROFILES:
            fail(f"{where}.fuzz: invalid fuzz metadata")

        arguments = row.get("arguments")
        if not isinstance(arguments, list):
            fail(f"{where}.arguments: expected array")
        seen_registers: set[str] = set()
        previous_register = -1
        for arg_index, argument in enumerate(arguments):
            arg_where = f"{where}.arguments[{arg_index}]"
            if not isinstance(argument, dict):
                fail(f"{arg_where}: expected object")
            register = argument.get("register")
            if register not in REGISTER_INDEX or register in seen_registers:
                fail(f"{arg_where}.register: invalid or duplicate register")
            if REGISTER_INDEX[register] <= previous_register:
                fail(f"{arg_where}.register: arguments are not in calling-convention order")
            previous_register = REGISTER_INDEX[register]
            seen_registers.add(register)
            if argument.get("kind") not in ARG_KINDS:
                fail(f"{arg_where}.kind: unsupported argument kind")
            require_string(argument.get("description"), f"{arg_where}.description")
        require_string(row.get("returns"), f"{where}.returns")
        require_string(row.get("summary"), f"{where}.summary")
    return rows


def enum_token(value: str) -> str:
    return "".join(part.capitalize() for part in value.split("_"))


def capability_expression(row: dict[str, Any]) -> str:
    caps = row["authorization"]["capabilities"]
    if not caps:
        return "0ULL"
    return " | ".join(f"(1ULL << ::duetos::core::{cap})" for cap in caps)


def render_def(rows: list[dict[str, Any]]) -> str:
    lines = [
        "// Generated by tools/build/gen-native-syscall-abi.py from abi/native_syscalls.json.",
        "// Do not edit this file by hand.",
        "// DUETOS_NATIVE_SYSCALL(name, number, auth, cap_mask, object_rights, trace, fuzz)",
        "",
    ]
    for row in rows:
        lines.append(
            "DUETOS_NATIVE_SYSCALL(%s, %d, %s, %s, %s, %s, %s)"
            % (
                row["name"],
                row["number"],
                enum_token(row["authorization"]["mode"]),
                capability_expression(row),
                enum_token(row["object_rights"]["mode"]),
                enum_token(row["trace"]["category"]),
                enum_token(row["fuzz"]["profile"]),
            )
        )
    return "\n".join(lines) + "\n"


def render_userland_header(rows: list[dict[str, Any]]) -> str:
    lines = [
        "#pragma once",
        "",
        "/* Generated from abi/native_syscalls.json. Do not edit by hand. */",
        # Allman brace, per /.clang-format — the CI format gate scans every
        # header under userland/, generated ones included, so emitting K&R
        # here fails the build rather than merely looking inconsistent.
        "enum duet_native_syscall_number",
        "{",
    ]
    for row in rows:
        lines.append(f"    DUET_{row['name']} = {row['number']},")
    lines.extend(("};", ""))
    return "\n".join(lines)


def render_names_def(rows: list[dict[str, Any]]) -> str:
    lines = [
        "// Generated by tools/build/gen-native-syscall-abi.py from abi/native_syscalls.json.",
        "// Do not edit this file by hand. Each row is compile-time checked against",
        "// SyscallNumber by kernel/syscall/syscall_names.h during the IDL migration.",
        "",
    ]
    lines.extend(f"X({row['name']}, {row['number']})" for row in rows)
    lines.append("")
    return "\n".join(lines)


def render_cap_table(rows: list[dict[str, Any]]) -> str:
    lines = [
        "// Generated by tools/build/gen-native-syscall-abi.py from abi/native_syscalls.json.",
        "// Do not edit this file by hand. Rows here are unconditional static",
        "// capability gates; dynamic argument-dependent policy stays with the",
        "// owner named by the IDL and generated policy inventory.",
        "",
    ]
    for row in rows:
        if row["authorization"]["mode"] == "static":
            lines.append(f"X({row['name']}, {capability_expression(row)})")
    lines.append("")
    return "\n".join(lines)


def markdown_cell(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ")


def render_policy_markdown(rows: list[dict[str, Any]]) -> str:
    lines = [
        "# Native syscall policy inventory",
        "",
        "_Generated from `abi/native_syscalls.json`; do not edit by hand._",
        "",
        "| # | Symbol | Authorization | Object rights | Trace | Fuzz | Arguments |",
        "| ---: | --- | --- | --- | --- | --- | --- |",
    ]
    for row in rows:
        auth = row["authorization"]
        auth_text = auth["mode"]
        if auth["capabilities"]:
            auth_text += ": " + ", ".join(auth["capabilities"])
        rights = row["object_rights"]
        rights_text = rights["mode"]
        if rights["rights"]:
            rights_text += ": " + ", ".join(rights["rights"])
        args = "; ".join(f"`{arg['register']}` {arg['kind']}" for arg in row["arguments"]) or "none"
        lines.append(
            f"| {row['number']} | `{row['name']}` | {markdown_cell(auth_text)} | "
            f"{markdown_cell(rights_text)} | {markdown_cell(row['trace']['category'])} | "
            f"{markdown_cell(row['fuzz']['profile'])} | {markdown_cell(args)} |"
        )
    lines.append("")
    return "\n".join(lines)


def render_policy_json(rows: list[dict[str, Any]]) -> str:
    policy = {
        "schema": SCHEMA_NAME,
        "schema_version": SCHEMA_VERSION,
        "abi": ABI_NAME,
        "syscalls": rows,
    }
    return json.dumps(policy, indent=2, ensure_ascii=False, sort_keys=True) + "\n"


def expected_outputs(root: Path, document: dict[str, Any]) -> dict[Path, str]:
    rows = validate_document(document)
    return {
        root / "kernel/syscall/syscall_names.def": render_names_def(rows),
        root / "kernel/syscall/cap_table.def": render_cap_table(rows),
        root / "kernel/syscall/syscall_idl_generated.def": render_def(rows),
        root / "userland/libc/include/duet/syscall_numbers_generated.h": render_userland_header(rows),
        root / "docs/native-syscall-policy.json": render_policy_json(rows),
        root / "docs/native-syscall-policy.md": render_policy_markdown(rows),
    }


def verify_legacy(root: Path, rows: list[dict[str, Any]]) -> None:
    idl_map = {row["name"]: row["number"] for row in rows}
    enum_path = root / "kernel/syscall/syscall.h"
    names_path = root / "kernel/syscall/syscall_names.def"
    caps_path = root / "kernel/syscall/cap_table.def"
    enum_map = parse_number_map(ENUM_RE, read_text(enum_path), str(enum_path))
    names_map = parse_number_map(NAMES_RE, read_text(names_path), str(names_path))
    if idl_map != enum_map:
        missing = sorted(set(idl_map) - set(enum_map))
        extra = sorted(set(enum_map) - set(idl_map))
        changed = sorted(name for name in set(idl_map) & set(enum_map) if idl_map[name] != enum_map[name])
        fail(f"IDL/syscall.h drift: missing={missing}, extra={extra}, renumbered={changed}")
    if idl_map != names_map:
        fail("IDL/syscall_names.def drift detected")

    legacy_caps = parse_cap_table(read_text(caps_path), str(caps_path))
    idl_caps = {
        row["name"]: row["authorization"]["capabilities"]
        for row in rows
        if row["authorization"]["mode"] == "static"
    }
    if idl_caps != legacy_caps:
        missing = sorted(set(idl_caps) - set(legacy_caps))
        extra = sorted(set(legacy_caps) - set(idl_caps))
        changed = sorted(name for name in set(idl_caps) & set(legacy_caps) if idl_caps[name] != legacy_caps[name])
        fail(f"IDL/cap_table.def drift: missing={missing}, extra={extra}, changed={changed}")


def write_or_check(outputs: dict[Path, str], check: bool) -> None:
    stale: list[str] = []
    for path, content in outputs.items():
        if check:
            if not path.is_file() or read_text(path) != content:
                stale.append(path.as_posix())
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8", newline="\n")
        print(f"wrote {path}")
    if stale:
        fail("generated syscall artifacts are stale: " + ", ".join(stale))


def parse_args() -> argparse.Namespace:
    root_default = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=root_default)
    parser.add_argument("--idl", type=Path)
    parser.add_argument("--bootstrap-from-legacy", action="store_true")
    parser.add_argument("--check", action="store_true", help="verify generated files without writing")
    parser.add_argument("--check-legacy", action="store_true", help="also compare the migration-era handwritten tables")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    root = args.root.resolve()
    idl_path = args.idl.resolve() if args.idl else root / "abi/native_syscalls.json"
    try:
        if args.bootstrap_from_legacy:
            if args.check:
                fail("--bootstrap-from-legacy and --check are mutually exclusive")
            document = bootstrap_document(
                root / "kernel/syscall/syscall.h",
                root / "kernel/syscall/syscall_names.def",
                root / "kernel/syscall/cap_table.def",
            )
            validate_document(document)
            idl_path.parent.mkdir(parents=True, exist_ok=True)
            idl_path.write_text(json.dumps(document, indent=2, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n")
            print(f"bootstrapped {idl_path}")
        else:
            try:
                document = json.loads(read_text(idl_path))
            except json.JSONDecodeError as exc:
                fail(f"{idl_path}:{exc.lineno}:{exc.colno}: invalid JSON: {exc.msg}")
        rows = validate_document(document)
        if args.check_legacy:
            verify_legacy(root, rows)
        write_or_check(expected_outputs(root, document), args.check)
        mode = "verified" if args.check else "generated"
        print(f"native syscall IDL: {mode} {len(rows)} rows (schema v{SCHEMA_VERSION})")
        return 0
    except IdlError as exc:
        print(f"native syscall IDL: FAIL: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
