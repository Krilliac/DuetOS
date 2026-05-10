#!/usr/bin/env python3
"""Extract per-syscall arg/return docs from kernel/syscall/syscall.h.

Output is a markdown table with columns (#, name, args, return,
notes) suitable for embedding inside the AUTO:syscall_args block
of wiki/specifications/Syscall-ABI.md.

The kernel's syscall.h carries human-written doc-comments
immediately above each `SYS_NAME = N,` enum entry. The format the
maintainer convention follows is:

    // SYS_NAME: <prose with `rdi = ...`, `rsi = ...`, `Returns ...`>
    SYS_NAME = 42,

This script greps that pair, extracts whatever the comment said
about args + return, and emits a row per enum entry. Entries
without a doc-comment get a placeholder so the table stays
exhaustive.

T13-03 acceptance: "New syscall work can detect ABI number
collisions from the table." The auto-emitted table cross-checks
against syscall_names.def at the top of the file (the script
warns on number drift).
"""

from __future__ import annotations
import argparse
import os
import re
import sys

ENUM_RE = re.compile(r'^\s*(SYS_[A-Z0-9_]+)\s*=\s*(\d+)\s*,', re.MULTILINE)
NAMES_RE = re.compile(r'^\s*X\(\s*(SYS_[A-Z0-9_]+)\s*,\s*(\d+)\s*\)', re.MULTILINE)
ARG_LINE_RE = re.compile(r'(rdi|rsi|rdx|r10|r8|r9)\s*=\s*([^.,;]+)', re.IGNORECASE)
RETURN_LINE_RE = re.compile(r'returns?\s+([^.;]+)', re.IGNORECASE)


def read_text(path):
    with open(path, 'r', encoding='utf-8') as f:
        return f.read()


def parse_enum(text):
    """Return [(name, number, doc_block_lines)]."""
    rows = []
    lines = text.split('\n')
    pending_doc = []
    for i, line in enumerate(lines):
        # Track adjacent `//` comment block above the enum entry.
        stripped = line.strip()
        if stripped.startswith('//'):
            pending_doc.append(stripped[2:].strip())
            continue
        m = re.match(r'\s*(SYS_[A-Z0-9_]+)\s*=\s*(\d+)\s*,', line)
        if m:
            rows.append((m.group(1), int(m.group(2)), pending_doc[:]))
            pending_doc = []
            continue
        # Reset on blank lines / non-comment non-enum lines.
        pending_doc = []
    return rows


def parse_names_def(text):
    """Return {name: number} from syscall_names.def."""
    out = {}
    for m in NAMES_RE.finditer(text):
        out[m.group(1)] = int(m.group(2))
    return out


def extract_args(doc_lines):
    """Pull `rdi = ..., rsi = ...` style chunks out of the doc."""
    blob = ' '.join(doc_lines)
    pieces = []
    seen = set()
    for m in ARG_LINE_RE.finditer(blob):
        reg = m.group(1).lower()
        if reg in seen:
            continue
        seen.add(reg)
        desc = m.group(2).strip()
        # Trim long descriptions to keep table cells readable.
        if len(desc) > 60:
            desc = desc[:57] + '...'
        pieces.append(f'`{reg}` = {desc}')
    if not pieces:
        return '—'
    return '; '.join(pieces)


def extract_return(doc_lines):
    """Pull the `Returns ...` clause out of the doc."""
    blob = ' '.join(doc_lines)
    m = RETURN_LINE_RE.search(blob)
    if not m:
        return '—'
    s = m.group(1).strip()
    if len(s) > 80:
        s = s[:77] + '...'
    return s


def emit_table(enum_rows, names_map, warn_drift=True):
    out = ['| # | Symbol | Args | Returns |',
           '|---|--------|------|---------|']
    for name, number, doc in enum_rows:
        if warn_drift and name in names_map and names_map[name] != number:
            print(f'WARN: number drift for {name}: enum={number} vs names_def={names_map[name]}',
                  file=sys.stderr)
        args = extract_args(doc)
        rv = extract_return(doc)
        out.append(f'| {number} | `{name}` | {args} | {rv} |')
    return '\n'.join(out)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--syscall-h', default='kernel/syscall/syscall.h')
    ap.add_argument('--names-def', default='kernel/syscall/syscall_names.def')
    ap.add_argument('--out', help='output markdown file; default = stdout')
    args = ap.parse_args()

    enum_rows = parse_enum(read_text(args.syscall_h))
    names_map = parse_names_def(read_text(args.names_def))
    table = emit_table(enum_rows, names_map)

    if args.out:
        with open(args.out, 'w', encoding='utf-8') as f:
            f.write(table)
            f.write('\n')
    else:
        print(table)


if __name__ == '__main__':
    main()
