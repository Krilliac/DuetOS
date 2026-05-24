#!/usr/bin/env python3
"""One-shot helper: inject the per-theme tactility intensity matrix into
each Theme literal in kernel/drivers/video/theme.cpp.

Per the chrome-tactility design spec §7.2, the 10 themes carry different
tactility settings; HighContrast and Amber opt out, Duet variants lean
in, Classic/DuetClassic sit between. This script walks the file line-by-
line tracking brace depth (Theme literals contain nested `{...}` for the
role_title / role_client arrays), and inserts the 7 new designated
initializers immediately before each theme's closing `};` at depth 0.
Idempotent — re-running on an already-transformed file is a no-op (the
marker line `// chrome tactility (Pass A)` is the test).

Run once from the repo root:
    python3 tools/build/inject-tactility-matrix.py
"""

from __future__ import annotations
import pathlib
import re
import sys

# Per-spec matrix. Keys match the .name = "..." string in each Theme
# literal; values are the 7 designated initializers in the order they
# appear in struct Theme.
MATRIX: dict[str, list[str]] = {
    "classic":      ["true",  "80",  "40",  "100", "100", "0x245EDC", "false"],
    "amber":        ["false", "0",   "0",   "0",   "0",   "0xF5B73A", "false"],
    "slate10":      ["true",  "200", "100", "255", "255", "0x0078D4", "true"],
    "duet":         ["true",  "255", "128", "255", "255", "0x2DD4BF", "true"],
    "duetlight":    ["true",  "100", "50",  "200", "200", "0x0F9B8A", "true"],
    "duetblue":     ["true",  "255", "128", "255", "255", "0x0078D4", "true"],
    "duetviolet":   ["true",  "255", "128", "255", "255", "0x9B59B6", "true"],
    "duetgreen":    ["true",  "255", "128", "255", "255", "0xF5B73A", "true"],
    "duetclassic":  ["true",  "160", "80",  "200", "200", "0",        "false"],
    "highcontrast": ["false", "0",   "0",   "0",   "0",   "0xFFFFFF", "false"],
}

FIELD_NAMES = [
    ".tactility_enabled",
    ".shadow_intensity_active",
    ".shadow_intensity_inactive",
    ".hover_lift_alpha",
    ".press_alpha",
    ".focus_glow_colour",
    ".cursor_microshadow_enabled",
]

THEME_OPEN_RE = re.compile(r"^constexpr Theme \w+ = \{")
NAME_RE = re.compile(r'^\s*\.name = "(\w+)",')


def format_block(theme_name: str) -> list[str]:
    """Return the lines to splice in just before the closing `};`."""
    values = MATRIX[theme_name]
    out = ["", "    // chrome tactility (Pass A) - per-theme matrix"]
    for name, value in zip(FIELD_NAMES, values):
        out.append(f"    {name} = {value},")
    return out


def main() -> int:
    path = pathlib.Path("kernel/drivers/video/theme.cpp")
    if not path.exists():
        print(f"ERROR: not found: {path}", file=sys.stderr)
        return 2

    src = path.read_text()
    if "// chrome tactility (Pass A)" in src:
        print("already transformed — exiting (idempotent no-op)")
        return 0

    lines = src.splitlines(keepends=False)
    out_lines: list[str] = []
    in_theme = False
    depth = 0
    current_name: str | None = None
    matched: set[str] = set()

    for line in lines:
        if not in_theme and THEME_OPEN_RE.match(line):
            in_theme = True
            depth = 1  # opening { on this same line
            current_name = None
            out_lines.append(line)
            continue

        if in_theme:
            if current_name is None:
                m = NAME_RE.match(line)
                if m:
                    current_name = m.group(1)

            opens = line.count("{")
            closes = line.count("}")
            new_depth = depth + opens - closes

            # Closing the theme literal — splice block before this line.
            if new_depth == 0 and line.startswith("};"):
                if current_name and current_name in MATRIX:
                    out_lines.extend(format_block(current_name))
                    matched.add(current_name)
                elif current_name:
                    print(f"WARN: unknown theme '{current_name}' — skipped", file=sys.stderr)
                else:
                    print(f"WARN: theme literal had no .name — skipped", file=sys.stderr)
                out_lines.append(line)
                in_theme = False
                depth = 0
                current_name = None
                continue

            depth = new_depth
            out_lines.append(line)
            continue

        out_lines.append(line)

    if not matched:
        print("ERROR: no Theme literals matched", file=sys.stderr)
        return 3

    missing = set(MATRIX) - matched
    if missing:
        print(f"ERROR: spec themes missing from file: {sorted(missing)}", file=sys.stderr)
        return 4

    # Preserve trailing newline if the original had one.
    tail = "\n" if src.endswith("\n") else ""
    path.write_text("\n".join(out_lines) + tail)
    print(f"wrote {path} — {len(matched)} theme literals extended")
    return 0


if __name__ == "__main__":
    sys.exit(main())
