#!/usr/bin/env python3
"""Reject direct access to published Process capability storage."""

from __future__ import annotations

import argparse
import re
from pathlib import Path


DIRECT_CAPS = re.compile(
    r"(?:->|\.)(?:caps|cap_ceiling|cap_leases)\b(?!\s*\[)"
    r"|(?:->|\.)(?:cap_lease_deadline_ns|cap_lease_generation)\b"
)
SPAWN_ROWS = {"SYS_SPAWN", "SYS_PROCESS_SPAWN", "SYS_PROCESS_SPAWN_EX"}

ALLOWED_DIRECT = {
    "kernel/proc/process.cpp": (
        re.compile(
            r"(?:process|mutable_process)->"
            r"(?:caps|cap_ceiling|cap_leases|cap_lease_deadline_ns|cap_lease_generation)\b"
        ),
        re.compile(r"p->(?:caps|cap_ceiling|cap_leases)\b"),
    ),
    "kernel/syscall/cap_gate.cpp": (
        re.compile(r"(?:empty|trusted|promoted|renewed|expiring|clockless)\.(?:caps|cap_ceiling)\s*="),
    ),
    "kernel/security/broker.cpp": (
        re.compile(r"synth\.(?:caps|cap_ceiling)\s*="),
    ),
    "kernel/security/grace.cpp": (
        re.compile(r"process\.(?:caps|cap_ceiling)\s*="),
    ),
    "kernel/shell/shell_security.cpp": (
        re.compile(r"g_shell_proc\.cap_ceiling\s*=\s*duetos::core::CapSetTrusted\(\)"),
    ),
    "kernel/subsystems/win32/token_syscall.cpp": (
        re.compile(r"(?:disable_all|remove|disable|shell_off)\.cap_ceiling\s*="),
    ),
    # Keyboard-state Caps Lock flag, unrelated to core::CapSet.
    "kernel/drivers/virtio/virtio_input.cpp": (
        re.compile(r"g_input\.caps\b"),
    ),
}


def strip_comments(text: str) -> str:
    """Replace C/C++ comments with spaces while preserving line numbers."""
    out: list[str] = []
    i = 0
    in_block = False
    while i < len(text):
        if in_block:
            if text.startswith("*/", i):
                out.extend((" ", " "))
                i += 2
                in_block = False
            else:
                out.append("\n" if text[i] == "\n" else " ")
                i += 1
            continue
        if text.startswith("/*", i):
            out.extend((" ", " "))
            i += 2
            in_block = True
            continue
        if text.startswith("//", i):
            while i < len(text) and text[i] != "\n":
                out.append(" ")
                i += 1
            continue
        out.append(text[i])
        i += 1
    return "".join(out)


def scan_direct_access(repo: Path) -> list[str]:
    violations: list[str] = []
    for path in sorted((repo / "kernel").rglob("*")):
        if path.suffix not in {".cpp", ".h"}:
            continue
        rel = path.relative_to(repo).as_posix()
        stripped = strip_comments(path.read_text(encoding="utf-8", errors="replace"))
        for line_no, line in enumerate(stripped.splitlines(), start=1):
            if not DIRECT_CAPS.search(line):
                continue
            if any(pattern.search(line) for pattern in ALLOWED_DIRECT.get(rel, ())):
                continue
            violations.append(f"{rel}:{line_no}: direct Process capability access: {line.strip()}")
    return violations


def scan_spawn_rows(repo: Path) -> list[str]:
    table = strip_comments((repo / "kernel/syscall/cap_table.def").read_text(encoding="utf-8"))
    found: dict[str, str] = {}
    for match in re.finditer(r"X\((SYS_[A-Z0-9_]+),\s*([^\n]+)\)", table):
        name, expression = match.groups()
        if name in SPAWN_ROWS:
            found[name] = re.sub(r"\s+", "", expression)

    fs_read = "(1ULL<<::duetos::core::kCapFsRead)"
    spawn_thread = "(1ULL<<::duetos::core::kCapSpawnThread)"
    expected = {f"{fs_read}|{spawn_thread}", f"{spawn_thread}|{fs_read}"}
    violations = []
    for name in sorted(SPAWN_ROWS):
        if found.get(name) not in expected:
            violations.append(f"kernel/syscall/cap_table.def: {name} must require exactly FsRead|SpawnThread")
    return violations


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parents[2],
        help="DuetOS repository root",
    )
    args = parser.parse_args()
    repo = args.root.resolve()

    violations = scan_direct_access(repo) + scan_spawn_rows(repo)
    if violations:
        print("\n".join(violations))
        print(f"capability static scan: FAIL ({len(violations)} violation(s))")
        return 1
    print("capability static scan: PASS (published Process caps are helper-only; spawn masks are exact)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
