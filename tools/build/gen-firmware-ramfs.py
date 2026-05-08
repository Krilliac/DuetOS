#!/usr/bin/env python3
"""Generate a ramfs subtree for installer-staged firmware packages.

Usage:
    gen-firmware-ramfs.py <staging-dir-or-empty> <output-header>

The staging directory maps directly under /lib/firmware in the trusted ramfs.
For example:

    <staging>/duetos/open/ath9k-htc/htc_9271.fw.duetfw

becomes:

    /lib/firmware/duetos/open/ath9k-htc/htc_9271.fw.duetfw

The generator deliberately embeds only regular files. Directory and basename
validation is strict so an installer manifest cannot smuggle absolute paths or
parent traversals into the kernel's seed filesystem.
"""

from __future__ import annotations

import argparse
import hashlib
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

_SYMBOL_RE = re.compile(r"[^A-Za-z0-9_]")
_SAFE_NAME_RE = re.compile(r"^[A-Za-z0-9._+@=-][A-Za-z0-9._+@= -]*$")


@dataclass
class DirNode:
    name: str
    dirs: dict[str, "DirNode"] = field(default_factory=dict)
    files: list[Path] = field(default_factory=list)


def symbol_for(prefix: str, rel: str) -> str:
    digest = hashlib.sha256(rel.encode("utf-8")).hexdigest()[:12]
    stem = _SYMBOL_RE.sub("_", rel).strip("_") or "root"
    return f"{prefix}_{stem}_{digest}"


def cxx_string(value: str) -> str:
    out = '"'
    for ch in value:
        code = ord(ch)
        if ch == "\\":
            out += "\\\\"
        elif ch == '"':
            out += '\\"'
        elif ch == "\n":
            out += "\\n"
        elif ch == "\r":
            out += "\\r"
        elif ch == "\t":
            out += "\\t"
        elif 32 <= code <= 126:
            out += ch
        else:
            out += f"\\x{code:02X}"
    out += '"'
    return out


def validate_part(part: str, rel: Path) -> None:
    if not part or part in {".", ".."}:
        raise ValueError(f"invalid firmware path component in {rel!s}")
    if "/" in part or "\\" in part or "\0" in part:
        raise ValueError(f"invalid separator in firmware path component {part!r}")
    if not _SAFE_NAME_RE.match(part):
        raise ValueError(
            f"unsupported firmware path component {part!r}; use letters, digits, '.', '_', '-', '+', '@', '=', or spaces"
        )


def collect_files(staging: Path | None) -> list[Path]:
    if staging is None:
        return []
    if not staging.exists():
        raise FileNotFoundError(f"firmware staging directory not found: {staging}")
    if not staging.is_dir():
        raise NotADirectoryError(f"firmware staging path is not a directory: {staging}")

    files: list[Path] = []
    for path in sorted(staging.rglob("*")):
        if path.is_file():
            rel = path.relative_to(staging)
            if rel.is_absolute() or any(part in {"", ".", ".."} for part in rel.parts):
                raise ValueError(f"invalid firmware relative path: {rel!s}")
            for part in rel.parts:
                validate_part(part, rel)
            files.append(rel)
        elif not path.is_dir():
            raise ValueError(f"firmware staging entry is not a regular file or directory: {path}")
    return files


def insert(root: DirNode, rel: Path) -> None:
    node = root
    for part in rel.parts[:-1]:
        node = node.dirs.setdefault(part, DirNode(part))
    node.files.append(rel)


def emit_file(lines: list[str], staging: Path, rel: Path) -> tuple[str, str]:
    rel_str = rel.as_posix()
    sym = symbol_for("kFwFile", rel_str)
    data = (staging / rel).read_bytes()
    lines.append(f"inline constexpr unsigned char {sym}_bytes[] = {{")
    if data:
        for row_start in range(0, len(data), 16):
            row = data[row_start : row_start + 16]
            lines.append("    " + ", ".join(f"0x{b:02X}" for b in row) + ",")
    lines.append("};")
    lines.append("")
    node_sym = f"{sym}_node"
    lines.append(f"inline constinit RamfsNode {node_sym} = {{")
    lines.append(f"    .name = {cxx_string(rel.name)},")
    lines.append("    .type = RamfsNodeType::kFile,")
    lines.append("    .children = nullptr,")
    lines.append(f"    .file_bytes = {sym}_bytes,")
    lines.append(f"    .file_size = sizeof({sym}_bytes),")
    lines.append("};")
    lines.append("")
    return rel.name, node_sym


def emit_dir(lines: list[str], staging: Path, node: DirNode, rel_prefix: str) -> str:
    child_entries: list[tuple[str, str]] = []

    for dirname in sorted(node.dirs):
        child = node.dirs[dirname]
        child_rel = f"{rel_prefix}/{dirname}" if rel_prefix else dirname
        child_sym = emit_dir(lines, staging, child, child_rel)
        child_entries.append((dirname, child_sym))

    for rel in sorted(node.files, key=lambda p: p.name):
        child_entries.append(emit_file(lines, staging, rel))

    child_entries.sort(key=lambda pair: pair[0])
    dir_rel = rel_prefix or "firmware"
    child_sym = symbol_for("kFwDirChildren", dir_rel)
    node_sym = "kFirmwareRamfsNode" if not rel_prefix else symbol_for("kFwDir", dir_rel)

    lines.append(f"inline const RamfsNode* const {child_sym}[] = {{")
    for _name, sym in child_entries:
        lines.append(f"    &{sym},")
    lines.append("    nullptr,")
    lines.append("};")
    lines.append("")
    lines.append(f"inline constinit RamfsNode {node_sym} = {{")
    lines.append(f"    .name = {cxx_string(node.name)},")
    lines.append("    .type = RamfsNodeType::kDir,")
    lines.append(f"    .children = {child_sym},")
    lines.append("    .file_bytes = nullptr,")
    lines.append("    .file_size = 0,")
    lines.append("};")
    lines.append("")
    return node_sym


def generate(staging_arg: str, output: Path) -> None:
    staging = Path(staging_arg).resolve() if staging_arg else None
    rel_files = collect_files(staging)

    root = DirNode("firmware")
    if staging is not None:
        for rel in rel_files:
            insert(root, rel)

    lines: list[str] = []
    lines.append("// AUTO-GENERATED by tools/build/gen-firmware-ramfs.py. DO NOT EDIT.")
    lines.append("// Installer-staged firmware root: " + (str(staging) if staging is not None else "<none>"))
    lines.append(f"// Embedded firmware files: {len(rel_files)}")
    lines.append("#pragma once")
    lines.append("")
    lines.append('#include "fs/ramfs.h"')
    lines.append("")
    lines.append("namespace duetos::fs::generated")
    lines.append("{")
    lines.append("")
    emit_dir(lines, staging or Path("."), root, "")
    lines.append("} // namespace duetos::fs::generated")
    lines.append("")

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text("\n".join(lines))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("staging_dir", help="directory to map under /lib/firmware, or empty string for an empty tree")
    parser.add_argument("output", type=Path, help="generated C++ header")
    args = parser.parse_args()

    try:
        generate(args.staging_dir, args.output)
    except Exception as exc:  # noqa: BLE001 - CLI should report cleanly.
        print(f"gen-firmware-ramfs.py: error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
