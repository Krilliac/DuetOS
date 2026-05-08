#!/usr/bin/env python3
"""
Read KERNEL.FIX and emit reviewable source patches for the gaps it
recorded. The kernel itself never auto-applies fixes (Decision #016);
this is a host-side script that converts journal records into
candidate patches for human review.

For each unique journal record:

  * UnmappedThunk where (dll, fn) is NOT in thunks_table.inc -> emit
    a unified diff that adds a row pointing at kOffMissLogger (safe
    default: returns 0, emits a per-call miss log so the reviewer
    can see whether the call actually matters).

  * UnmappedThunk where (dll, fn) IS in thunks_table.inc but the
    table points at a generic noop offset (kOffReturnZero /
    kOffReturnOne / kOffCritSecNop / kOffGetProcessHeap) -> emit a
    named-equivalent bytecode patch at a fresh offset so the runtime
    classifier stops re-journaling an accepted placeholder.

  * UnknownSyscall -> emit a markdown implementation brief with the
    syscall number and journal context. Unknown syscall semantics are
    ABI work, not safe mechanical source patches.

  * StubMarker / GapMarker / SoftFaultRecov / LoaderReject -> emit
    a detector-specific implementation brief pointing at the source pin.

  * Optional marker manifests from gen-fix-markers.py -> emit
    observability patches that add FIX_NOTE_STUB/FIX_NOTE_GAP macros
    for safe in-function `// STUB:` / `// GAP:` markers that are not
    yet represented in the runtime journal.

By default, dry-run: writes .patch files under --out and prints a
markdown summary to stdout. With --apply, prompts y/n before each
`git apply`. Patches are unified diffs against the current tree;
re-running after applying is safe (already-applied rows are
detected and skipped).

Usage:
    tools/build/gen-fix-patches.py KERNEL.FIX [--out=fix-patches/]
    tools/build/gen-fix-patches.py KERNEL.FIX --apply
    tools/build/gen-fix-patches.py KERNEL.FIX --apply --yes  # no prompts
"""

from __future__ import annotations

import argparse
import json
import re
import struct
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

FILE_MAGIC = 0x4A584946  # 'FIXJ'
FILE_VERSION = 1
RECORD_MAGIC = 0x52584946  # 'FIXR'
RECORD_STRIDE = 128
MAX_RECORDS = 1024

DETECTORS = {
    0: "none",
    1: "stub",
    2: "gap",
    3: "unknown_syscall",
    4: "unmapped_thunk",
    5: "soft_fault_recov",
    6: "loader_reject",
}

HEADER_FMT = struct.Struct("<IIII")
RECORD_FMT = struct.Struct("<IIQQQQIHBB40s40s")
assert RECORD_FMT.size == RECORD_STRIDE


@dataclass
class FixRecord:
    seq: int
    ts_ns: int
    caller_rip: int
    ctx_a: int
    ctx_b: int
    repeat: int
    severity: int
    detector: int
    flags: int
    source_pin: str
    hint: str

    @property
    def detector_name(self) -> str:
        return DETECTORS.get(self.detector, f"detector#{self.detector}")

    @property
    def audited(self) -> bool:
        return bool(self.flags & 0x01)


@dataclass
class FixMarker:
    file: str
    line: int
    kind: str
    comment: str
    has_macro: bool


def read_records(path: str) -> list[FixRecord]:
    """Parse a KERNEL.FIX file into a list of FixRecord.

    Patch generation deliberately accepts only the current, exact file
    ABI. A stale/newer/truncated journal can otherwise produce patches
    for the wrong records, which is worse than producing no patch at
    all. Torn record payloads with bad per-record magic are skipped
    after the enclosing file has passed size/version validation.
    """
    with open(path, "rb") as fh:
        data = fh.read()
    if len(data) < HEADER_FMT.size:
        raise ValueError(f"{path}: file too short ({len(data)} bytes)")
    magic, version, count, reserved = HEADER_FMT.unpack(data[: HEADER_FMT.size])
    if magic != FILE_MAGIC:
        raise ValueError(f"{path}: bad magic 0x{magic:08x}")
    if version != FILE_VERSION:
        raise ValueError(f"{path}: unsupported version {version} (expected {FILE_VERSION})")
    if reserved != 0:
        raise ValueError(f"{path}: reserved header word is 0x{reserved:08x} (expected 0)")
    if count > MAX_RECORDS:
        raise ValueError(f"{path}: record count {count} exceeds journal capacity {MAX_RECORDS}")
    expected = HEADER_FMT.size + count * RECORD_STRIDE
    if len(data) != expected:
        raise ValueError(
            f"{path}: size {len(data)} != header({HEADER_FMT.size})"
            f" + {count} records * {RECORD_STRIDE}"
        )
    records: list[FixRecord] = []
    cursor = HEADER_FMT.size
    torn = 0
    for _ in range(count):
        chunk = data[cursor : cursor + RECORD_STRIDE]
        fields = RECORD_FMT.unpack(chunk)
        rmagic = fields[0]
        cursor += RECORD_STRIDE
        if rmagic != RECORD_MAGIC:
            torn += 1
            continue  # torn / panic-context noise
        records.append(
            FixRecord(
                seq=fields[1],
                ts_ns=fields[2],
                caller_rip=fields[3],
                ctx_a=fields[4],
                ctx_b=fields[5],
                repeat=fields[6],
                severity=fields[7],
                detector=fields[8],
                flags=fields[9],
                source_pin=fields[10].split(b"\x00", 1)[0].decode("utf-8", "replace"),
                hint=fields[11].split(b"\x00", 1)[0].decode("utf-8", "replace"),
            )
        )
    if torn:
        print(f"# {path}: skipped {torn} torn record(s) (bad magic)", file=sys.stderr)
    return records


def load_markers(path: Path) -> list[FixMarker]:
    """Load a gen-fix-markers.py JSON manifest."""
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"# warn: couldn't read markers manifest {path}: {exc}", file=sys.stderr)
        return []
    markers: list[FixMarker] = []
    if not isinstance(raw, list):
        print(f"# warn: markers manifest {path} is not a JSON array", file=sys.stderr)
        return markers
    for row in raw:
        if not isinstance(row, dict):
            continue
        try:
            markers.append(
                FixMarker(
                    file=str(row["file"]),
                    line=int(row["line"]),
                    kind=str(row["kind"]).upper(),
                    comment=str(row.get("comment", "")),
                    has_macro=bool(row.get("has_macro", False)),
                )
            )
        except (KeyError, TypeError, ValueError):
            continue
    return markers


# ---------------------------------------------------------------- thunks index

_THUNKS_TABLE_PATH = "kernel/subsystems/win32/thunks_table.inc"
_THUNKS_CPP_PATH = "kernel/subsystems/win32/thunks.cpp"
_THUNKS_BYTECODE_PATH = "kernel/subsystems/win32/thunks_bytecode.inc"

# Generic noop offsets: an entry resolving to one of these is a
# placeholder, not a real implementation. Mirrors the runtime
# classifier in kernel/subsystems/win32/thunks.cpp.
_NOOP_OFFSETS = {"kOffReturnZero", "kOffReturnOne", "kOffCritSecNop", "kOffGetProcessHeap"}

# Bytecode templates for "named-equivalent" noops. Every offset in
# _NOOP_OFFSETS must either have a template here or an explicit note in
# plan_actions(). Each entry gives the bytes that produce identical
# behaviour to the generic/noop-ish offset on the left, plus a one-line
# ASM comment for the patched bytecode block. The classifier in
# thunks.cpp checks the offset *value*, so aliasing isn't enough — we
# MUST emit fresh bytes at a new offset to break out of the noop set.
_NOOP_TEMPLATES = {
    "kOffReturnZero": {
        "bytes": [0x31, 0xC0, 0xC3],
        "asm": "xor eax, eax; ret  ; named-equivalent of kOffReturnZero",
    },
    "kOffReturnOne": {
        "bytes": [0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3],
        "asm": "mov eax, 1; ret    ; named-equivalent of kOffReturnOne",
    },
    "kOffCritSecNop": {
        "bytes": [0xC3],
        "asm": "ret                 ; named-equivalent of kOffCritSecNop",
    },
    "kOffGetProcessHeap": {
        "bytes": [0x48, 0xC7, 0xC0, 0x00, 0x00, 0x00, 0x50, 0xC3],
        "asm": "mov rax, 0x50000000; ret  ; named-equivalent of kOffGetProcessHeap",
    },
}


def load_thunks_table(repo_root: Path) -> dict[tuple[str, str], str]:
    """Parse thunks_table.inc into a {(dll_lower, fn): kOff*}.

    Case for dll matches the runtime lookup (dll comparison is
    case-insensitive); case for fn is preserved (function lookup is
    case-sensitive). Multiple registrations for the same key keep the
    first match (mirrors Win32ThunksLookupLinear).
    """
    path = repo_root / _THUNKS_TABLE_PATH
    table: dict[tuple[str, str], str] = {}
    if not path.exists():
        return table
    pattern = re.compile(r'\{"([^"]+)",\s*"([^"]+)",\s*(kOff[A-Za-z0-9_]+)\}')
    for line in path.read_text(encoding="utf-8").splitlines():
        for m in pattern.finditer(line):
            key = (m.group(1).lower(), m.group(2))
            table.setdefault(key, m.group(3))
    return table


# ---------------------------------------------------------------- pin parsing


def parse_thunk_pin(pin: str) -> tuple[str, str] | None:
    """Split a `<dll>!<fn>` source_pin into (dll, fn).

    Honours the loader's truncation behaviour: it drops the trailing
    `.dll` from the dll component to fit longer apiset names, so we
    re-attach the suffix here for table lookup. Returns None if the
    pin doesn't look like dll!fn (e.g. selftest pins).
    """
    if "!" not in pin:
        return None
    dll, fn = pin.split("!", 1)
    if not dll or not fn:
        return None
    if not dll.lower().endswith(".dll"):
        dll = dll + ".dll"
    return dll, fn


def parse_syscall_pin(pin: str) -> int | None:
    """Extract the syscall number from a `syscall#<hex>` pin."""
    m = re.match(r"syscall#([0-9a-fA-F]+)$", pin)
    if not m:
        return None
    return int(m.group(1), 16)


# ---------------------------------------------------------------- patch synthesis


def synth_thunk_patch(dll: str, fn: str, seq: int, repo_root: Path) -> str | None:
    """Generate a unified diff that appends a thunks_table.inc row.

    The new row points at kOffMissLogger (safe catch-all: returns 0 +
    emits one [win32-miss] log per call), so the reviewer can decide
    later whether to upgrade to a real thunk or accept the noop.

    Returns None if we can't read the existing file.
    """
    path = repo_root / _THUNKS_TABLE_PATH
    if not path.exists():
        return None
    lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
    # Find the closing region: the last brace that ends the array.
    # We want to insert just before it. The file is intended to be
    # `#include`d into a `constexpr ThunkEntry kThunksTable[] = { ... }`,
    # so the last meaningful line is typically a trailing entry.
    # Insert immediately before the last non-blank, non-comment line
    # that already looks like a thunk entry.
    insert_at = None
    for i in range(len(lines) - 1, -1, -1):
        s = lines[i].strip()
        if s and not s.startswith("//"):
            insert_at = i + 1
            break
    if insert_at is None:
        insert_at = len(lines)

    new_line = (
        f'    {{"{dll}", "{fn}", kOffMissLogger}}, '
        f"// GAP: auto-added from fix journal seq={seq} — implement thunk\n"
    )

    # Build a hunk that shows 3 lines of context above (when
    # available) plus our insertion. Standard unified-diff format.
    ctx_start = max(0, insert_at - 3)
    ctx_lines = lines[ctx_start:insert_at]
    after_lines = lines[insert_at : insert_at + 3]

    old_count = len(ctx_lines) + len(after_lines)
    new_count = old_count + 1

    diff_lines: list[str] = []
    diff_lines.append(f"--- a/{_THUNKS_TABLE_PATH}\n")
    diff_lines.append(f"+++ b/{_THUNKS_TABLE_PATH}\n")
    diff_lines.append(
        f"@@ -{ctx_start + 1},{old_count} +{ctx_start + 1},{new_count} @@\n"
    )
    for ln in ctx_lines:
        diff_lines.append(" " + ln)
    diff_lines.append("+" + new_line)
    for ln in after_lines:
        diff_lines.append(" " + ln)
    return "".join(diff_lines)


def _hunk_replace_line(file_rel: str, lines: list[str], idx: int, new_line: str) -> str:
    """Build a single-line-replacement hunk for `lines[idx]` -> new_line."""
    ctx_start = max(0, idx - 3)
    pre = lines[ctx_start:idx]
    post = lines[idx + 1 : idx + 4]
    old_count = len(pre) + 1 + len(post)
    new_count = old_count
    out: list[str] = []
    out.append(f"--- a/{file_rel}\n")
    out.append(f"+++ b/{file_rel}\n")
    out.append(f"@@ -{ctx_start + 1},{old_count} +{ctx_start + 1},{new_count} @@\n")
    for ln in pre:
        out.append(" " + ln)
    out.append("-" + lines[idx])
    out.append("+" + new_line)
    for ln in post:
        out.append(" " + ln)
    return "".join(out)


def _hunk_insert_lines(file_rel: str, lines: list[str], idx: int, inserts: list[str]) -> str:
    """Build a hunk that inserts `inserts` before `lines[idx]`."""
    ctx_start = max(0, idx - 3)
    pre = lines[ctx_start:idx]
    post = lines[idx : idx + 3]
    old_count = len(pre) + len(post)
    new_count = old_count + len(inserts)
    out: list[str] = []
    out.append(f"--- a/{file_rel}\n")
    out.append(f"+++ b/{file_rel}\n")
    out.append(f"@@ -{ctx_start + 1},{old_count} +{ctx_start + 1},{new_count} @@\n")
    for ln in pre:
        out.append(" " + ln)
    for ln in inserts:
        out.append("+" + ln)
    for ln in post:
        out.append(" " + ln)
    return "".join(out)


def _const_name_from_export(fn: str, existing_consts: set[str]) -> str | None:
    """Return a collision-free kOff* name for a generated thunk.

    Export names can contain leading underscores, stdcall suffixes, or
    other punctuation. Keep alphanumeric runs, preserve readable casing,
    and append a stable suffix if the natural name already exists (for
    example GetProcessHeap -> kOffGetProcessHeapNamedNoop).
    """
    cleaned = fn.lstrip("_")
    parts = re.findall(r"[A-Za-z0-9]+", cleaned)
    if not parts:
        return None
    base = "".join(part[:1].upper() + part[1:] for part in parts)
    if not base:
        return None
    candidate = "kOff" + base
    if candidate not in existing_consts:
        return candidate
    suffixes = ("NamedNoop", "AcceptedNoop", "FixJournalNoop")
    for suffix in suffixes:
        suffixed = candidate + suffix
        if suffixed not in existing_consts:
            return suffixed
    return None

def synth_named_noop_patch(
    dll: str, fn: str, current_const: str, seq: int, repo_root: Path
) -> str | None:
    """Multi-file patch: introduce a named-equivalent offset for an
    entry currently resolving to a generic noop (kOffReturnZero etc.)
    so the loader's classifier stops surfacing it as a journal record.

    Touches three files:
      * thunks_bytecode.inc — append the bytes for the named offset
      * thunks.cpp           — declare the new constant + bump size assert
      * thunks_table.inc     — point the row at the new constant

    Returns None if the inputs aren't consistent (e.g. current
    size assertion not parseable, source row not found).
    """
    tmpl = _NOOP_TEMPLATES.get(current_const)
    if tmpl is None:
        return None

    # 1. Parse the current size assertion from thunks.cpp.
    cpp_path = repo_root / _THUNKS_CPP_PATH
    bc_path = repo_root / _THUNKS_BYTECODE_PATH
    tbl_path = repo_root / _THUNKS_TABLE_PATH
    if not (cpp_path.exists() and bc_path.exists() and tbl_path.exists()):
        return None
    cpp_lines = cpp_path.read_text(encoding="utf-8").splitlines(keepends=True)
    existing_consts = set(
        re.findall(r"constexpr\s+u32\s+(kOff[A-Za-z0-9_]+)\s*=", "".join(cpp_lines))
    )
    size_re = re.compile(
        r"static_assert\(sizeof\(kThunksBytes\) == (0x[0-9a-fA-F]+),"
    )
    size_idx = None
    current_size = None
    for i, ln in enumerate(cpp_lines):
        m = size_re.search(ln)
        if m:
            size_idx = i
            current_size = int(m.group(1), 16)
            break
    if size_idx is None or current_size is None:
        return None

    # 2. Synthesise a collision-free constant name from the export name.
    # Leading underscores and punctuation are normal in PE exports; keep
    # the generated identifier readable while avoiding existing kOff*
    # declarations such as the real kOffGetProcessHeap.
    new_const = _const_name_from_export(fn, existing_consts)
    if new_const is None:
        return None
    new_offset = current_size
    new_bytes = tmpl["bytes"]
    new_size = current_size + len(new_bytes)

    # 3. Build the bytecode hunk: append a comment + the new bytes
    # at the end of thunks_bytecode.inc (right after the last
    # existing entry).
    bc_lines = bc_path.read_text(encoding="utf-8").splitlines(keepends=True)
    # Append after the last non-blank line.
    bc_insert_idx = len(bc_lines)
    for i in range(len(bc_lines) - 1, -1, -1):
        if bc_lines[i].strip():
            bc_insert_idx = i + 1
            break
    asm_comment = tmpl["asm"]
    bytes_hex = ", ".join(f"0x{b:02X}" for b in new_bytes)
    bc_inserts = [
        "\n",
        f"    // --- {fn} (offset 0x{new_offset:X}, {len(new_bytes)} bytes) ----------\n",
        f"    // Auto-added from fix journal seq={seq}. {asm_comment}\n",
        f"    // {dll}!{fn} formerly resolved to {current_const}; the named\n",
        f"    // offset breaks out of the noop classifier so the journal\n",
        f"    // stops re-recording it. Replace these bytes with a real\n",
        f"    // implementation when one lands.\n",
        f"    {bytes_hex}, // 0x{new_offset:X} {asm_comment.split(';')[0].strip()}\n",
    ]
    bc_hunk = _hunk_insert_lines(_THUNKS_BYTECODE_PATH, bc_lines, bc_insert_idx, bc_inserts)

    # 4. cpp hunk: bump the size assertion and add a new constant
    # before it.
    new_size_line = re.sub(r"0x[0-9a-fA-F]+", f"0x{new_size:X}", cpp_lines[size_idx], count=1)
    cpp_size_hunk = _hunk_replace_line(_THUNKS_CPP_PATH, cpp_lines, size_idx, new_size_line)
    # Insert the constant declaration just before the kThunksBytes[]
    # array definition. We find that line by string match — keeping
    # the search local to the file we already loaded.
    bytes_arr_idx = None
    for i, ln in enumerate(cpp_lines):
        if "constexpr u8 kThunksBytes[]" in ln:
            bytes_arr_idx = i
            break
    if bytes_arr_idx is None:
        return None
    const_inserts = [
        f"// Auto-added from fix journal seq={seq} — named-equivalent of {current_const}.\n",
        f"constexpr u32 {new_const} = 0x{new_offset:X}; // {len(new_bytes)} bytes\n",
        "\n",
    ]
    cpp_const_hunk = _hunk_insert_lines(_THUNKS_CPP_PATH, cpp_lines, bytes_arr_idx, const_inserts)

    # 5. Table hunk: rewrite the row for (dll, fn) to use new_const.
    tbl_lines = tbl_path.read_text(encoding="utf-8").splitlines(keepends=True)
    row_re = re.compile(
        r'(\{\s*"' + re.escape(dll) + r'"\s*,\s*"' + re.escape(fn) + r'"\s*,\s*)'
        + re.escape(current_const) + r'(\s*\})'
    )
    tbl_idx = None
    for i, ln in enumerate(tbl_lines):
        if row_re.search(ln):
            tbl_idx = i
            break
    if tbl_idx is None:
        return None
    new_tbl_line = row_re.sub(r"\1" + new_const + r"\2", tbl_lines[tbl_idx])
    tbl_hunk = _hunk_replace_line(_THUNKS_TABLE_PATH, tbl_lines, tbl_idx, new_tbl_line)

    return tbl_hunk + cpp_const_hunk + cpp_size_hunk + bc_hunk


_MARKER_SOURCE_SUFFIXES = {".c", ".cc", ".cpp"}
_FIX_JOURNAL_INCLUDE = '#include "diag/fix_journal.h"\n'
_MARKER_SKIP_REASONS = {
    "kernel/mm/dma.cpp:122": (
        "architecture-deferred cache-maintenance marker in a DMA hot path; "
        "recording every sync would add journal lock traffic to normal device I/O"
    ),
}


def _escape_cpp_string(value: str) -> str:
    """Escape `value` as the contents of a C/C++ string literal."""
    out: list[str] = []
    for ch in value:
        if ch == "\\":
            out.append("\\\\")
        elif ch == '"':
            out.append('\\"')
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\t":
            out.append("\\t")
        elif ord(ch) < 0x20:
            out.append(f"\\x{ord(ch):02x}")
        else:
            out.append(ch)
    return "".join(out)


def _leading_spaces(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def _line_is_marker(line: str) -> bool:
    return re.match(r"^\s*//\s*(STUB|GAP):", line) is not None


def _hunk_add_fix_journal_include(file_rel: str, lines: list[str]) -> str:
    """Return an include hunk for diag/fix_journal.h, or empty if present."""
    if any('"diag/fix_journal.h"' in ln for ln in lines):
        return ""
    include_indices = [i for i, ln in enumerate(lines) if ln.startswith("#include ")]
    if not include_indices:
        return ""
    insert_at = include_indices[-1] + 1
    return _hunk_insert_lines(file_rel, lines, insert_at, [_FIX_JOURNAL_INCLUDE])


def synth_marker_observability_patch(marker: FixMarker, repo_root: Path) -> str | None:
    """Generate a patch that makes a source STUB/GAP marker observable.

    This intentionally handles only low-risk in-function markers in
    kernel-owned .c/.cc/.cpp files. Header comments, namespace-scope
    markers, and userland markers are skipped because inserting a
    statement there could change declarations or break freestanding DLL
    builds. The generated patch adds the fix-journal include when needed
    and inserts a FIX_NOTE_* macro after the marker's contiguous comment
    block.
    """
    if marker.has_macro:
        return None
    if marker.kind not in ("STUB", "GAP"):
        return None
    file_rel = marker.file
    pin = f"{file_rel}:{marker.line}"
    if pin in _MARKER_SKIP_REASONS:
        return None
    if not file_rel.startswith("kernel/"):
        return None
    path = repo_root / file_rel
    if path.suffix not in _MARKER_SOURCE_SUFFIXES or not path.exists():
        return None
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines(keepends=True)
    idx = marker.line - 1
    if idx < 0 or idx >= len(lines):
        return None
    if not _line_is_marker(lines[idx]):
        return None

    indent = _leading_spaces(lines[idx])
    if indent == 0:
        # Very likely file/namespace scope. A macro statement would be invalid.
        return None

    insert_at = idx + 1
    while insert_at < len(lines):
        stripped = lines[insert_at].strip()
        if not stripped:
            insert_at += 1
            continue
        if stripped.startswith("//") and not _line_is_marker(lines[insert_at]):
            insert_at += 1
            continue
        break
    if insert_at >= len(lines):
        return None
    next_line = lines[insert_at]
    if _leading_spaces(next_line) < indent or next_line.lstrip().startswith(("}", "#")):
        return None

    hint = marker.comment.strip() or f"observed {marker.kind.lower()} marker"
    macro = (
        " " * indent
        + f'FIX_NOTE_{marker.kind}("{_escape_cpp_string(pin)}", "{_escape_cpp_string(hint)}");\n'
    )
    include_hunk = _hunk_add_fix_journal_include(file_rel, lines)
    macro_hunk = _hunk_insert_lines(file_rel, lines, insert_at, [macro])
    return include_hunk + macro_hunk


def plan_marker_actions(markers: list[FixMarker], repo_root: Path) -> list[Action]:
    actions: list[Action] = []
    seen: set[tuple[str, int, str]] = set()
    for marker in markers:
        key = (marker.file, marker.line, marker.kind)
        if key in seen or marker.has_macro:
            continue
        seen.add(key)
        diff = synth_marker_observability_patch(marker, repo_root)
        title = f"Make `{marker.file}:{marker.line}` {marker.kind} marker observable"
        if diff:
            safe_file = re.sub(r"[^A-Za-z0-9_.-]+", "-", marker.file)
            actions.append(
                Action(
                    kind="patch",
                    title=title,
                    body=diff,
                    filename=f"marker-{safe_file}-{marker.line}.patch",
                )
            )
        else:
            pin = f"{marker.file}:{marker.line}"
            reason = _MARKER_SKIP_REASONS.get(
                pin, "likely header/userland/namespace scope or unusual control flow"
            )
            actions.append(
                Action(
                    kind="note",
                    title=f"Review unobservable marker `{marker.file}:{marker.line}`",
                    body=(
                        f"`{marker.file}:{marker.line}` is a `{marker.kind}` marker without a "
                        f"nearby `FIX_NOTE_{marker.kind}` macro, but it is not safe for the "
                        f"generator to patch automatically ({reason}). Add an observable macro "
                        f"manually if runtime coverage should feed the fix journal. Comment: "
                        f"{marker.comment or '(none)'}"
                    ),
                    filename=None,
                )
            )
    return actions


_SYSCALL_PATH = "kernel/syscall/syscall.cpp"


def synth_syscall_brief(r: FixRecord, num: int) -> str:
    """Generate a markdown implementation brief for an unknown syscall.

    Unlike thunks-table misses, syscall semantics cannot be safely
    repaired with a mechanical source patch. A new switch arm changes
    the kernel ABI surface and must be implemented from the intended NT
    or native contract, so the self-fix output stays advisory and carries
    all journal context needed for a reviewer to write the real fix.
    """
    return (
        f"Runtime reached syscall `0x{num:x}` with no dispatcher arm. "
        f"Do not auto-scaffold a permanent `-ENOSYS` case: that only "
        f"turns an unknown ABI gap into a known stub. Implement the "
        f"intended syscall contract in `{_SYSCALL_PATH}` near the main "
        f"switch default arm that records `UnknownSyscall`.\n\n"
        f"Journal context:\n"
        f"- seq: `{r.seq}`\n"
        f"- repeat: `{r.repeat}`\n"
        f"- source_pin: `{r.source_pin}`\n"
        f"- caller_rip: `0x{r.caller_rip:016x}`\n"
        f"- ctx_a: `0x{r.ctx_a:016x}`\n"
        f"- ctx_b: `0x{r.ctx_b:016x}`\n"
        f"- hint: `{r.hint or '(none)'}`\n"
    )


# ---------------------------------------------------------------- per-record action


@dataclass
class Action:
    kind: str  # "patch" | "note"
    title: str
    body: str  # diff text or markdown explanation
    filename: str | None  # for "patch" kind, the .patch filename


def plan_actions(records: list[FixRecord], thunks_index: dict, repo_root: Path) -> list[Action]:
    actions: list[Action] = []
    seen: set[tuple[str, str]] = set()
    for r in records:
        key = (r.detector_name, r.source_pin)
        if key in seen:
            continue
        seen.add(key)
        if r.audited:
            continue  # reviewer already triaged

        if r.detector_name == "unmapped_thunk":
            parsed = parse_thunk_pin(r.source_pin)
            if not parsed:
                continue
            dll, fn = parsed
            existing = thunks_index.get((dll.lower(), fn))
            if existing is None:
                diff = synth_thunk_patch(dll, fn, r.seq, repo_root)
                if diff:
                    fname = f"thunk-{dll.replace('.dll', '')}-{fn}.patch".replace("/", "_")
                    actions.append(
                        Action(
                            kind="patch",
                            title=f"Add thunk row for `{dll}!{fn}`",
                            body=diff,
                            filename=fname,
                        )
                    )
            elif existing in _NOOP_OFFSETS:
                # Auto-emit the multi-file "named-equivalent" patch
                # — same bytecode at a fresh offset under a new
                # kOff<Name>, so the loader's noop classifier
                # (which compares by offset value) stops surfacing
                # the entry. The reviewer can later swap the bytes
                # for a real implementation without changing the
                # IAT contract.
                diff = synth_named_noop_patch(dll, fn, existing, r.seq, repo_root)
                if diff:
                    fname = (
                        f"named-noop-{dll.replace('.dll', '')}-{fn}.patch"
                    ).replace("/", "_")
                    actions.append(
                        Action(
                            kind="patch",
                            title=(
                                f"Promote `{dll}!{fn}` from `{existing}` to a "
                                f"named-equivalent offset"
                            ),
                            body=diff,
                            filename=fname,
                        )
                    )
                else:
                    actions.append(
                        Action(
                            kind="note",
                            title=f"`{dll}!{fn}` resolves to noop `{existing}`",
                            body=(
                                f"Could not auto-generate a named-equivalent "
                                f"patch for `{existing}`. Add the bytecode + "
                                f"constant + table row by hand, or extend "
                                f"`_NOOP_TEMPLATES` in this script to cover "
                                f"this kOff*."
                            ),
                            filename=None,
                        )
                    )
            else:
                # Already real — journal probably caught it before
                # the row landed; nothing to do.
                pass

        elif r.detector_name == "unknown_syscall":
            num = parse_syscall_pin(r.source_pin)
            if num is None:
                continue
            actions.append(
                Action(
                    kind="note",
                    title=f"Implement syscall #0x{num:x}",
                    body=synth_syscall_brief(r, num),
                    filename=None,
                )
            )

        elif r.detector_name in ("stub", "gap"):
            actions.append(
                Action(
                    kind="note",
                    title=f"Visit `{r.source_pin}` ({r.detector_name})",
                    body=(
                        f"`{r.source_pin}` was reached at runtime; the source pin "
                        f"already names the file:line. Open it and either complete "
                        f"the implementation (STUB) or document why the GAP is "
                        f"acceptable for v0. Hint: {r.hint or '(none)'}."
                    ),
                    filename=None,
                )
            )
        elif r.detector_name == "soft_fault_recov":
            actions.append(
                Action(
                    kind="note",
                    title=f"Soft-fault recovery hit: `{r.source_pin}`",
                    body=(
                        f"A retry-with-backoff path succeeded after at least one "
                        f"failure at `{r.source_pin}`. Investigate root cause; "
                        f"the journal pin identifies the call site. Hint: "
                        f"{r.hint or '(none)'}."
                    ),
                    filename=None,
                )
            )
        elif r.detector_name == "loader_reject":
            actions.append(
                Action(
                    kind="note",
                    title=f"PE/ELF loader rejected: `{r.source_pin}`",
                    body=(
                        f"The loader rejected an image with status `{r.source_pin}`. "
                        f"Extending the loader to handle the status is the fix shape; "
                        f"see `kernel/loader/pe_loader.cpp` for the reject taxonomy. "
                        f"Hint: {r.hint or '(none)'}."
                    ),
                    filename=None,
                )
            )
    return actions


# ---------------------------------------------------------------- output


def write_patches(actions: list[Action], out_dir: Path) -> list[Path]:
    """Write each patch action to a file under out_dir; return paths."""
    out_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for i, a in enumerate(actions):
        if a.kind != "patch" or not a.filename:
            continue
        p = out_dir / f"{i:04d}-{a.filename}"
        p.write_text(a.body, encoding="utf-8")
        written.append(p)
    return written


def render_markdown(actions: list[Action], patch_paths: list[Path]) -> str:
    out: list[str] = []
    out.append("# DuetOS Fix Journal — Patch Plan")
    out.append("")
    patches = [a for a in actions if a.kind == "patch"]
    notes = [a for a in actions if a.kind == "note"]
    out.append(f"**{len(patches)} patches** generated, **{len(notes)} notes** for human review.")
    out.append("")
    if patch_paths:
        out.append(f"Patches written to `{patch_paths[0].parent}/`. Apply with:")
        out.append("")
        out.append("```sh")
        out.append(f"git apply {patch_paths[0].parent}/*.patch")
        out.append("```")
        out.append("")
    if patches:
        out.append("## Patches")
        out.append("")
        for a in patches:
            out.append(f"### {a.title}")
            out.append("")
            out.append("```diff")
            out.append(a.body.rstrip("\n"))
            out.append("```")
            out.append("")
    if notes:
        out.append("## Notes (no auto-patch)")
        out.append("")
        for a in notes:
            out.append(f"### {a.title}")
            out.append("")
            out.append(a.body)
            out.append("")
    return "\n".join(out)


def apply_patch(patch_path: Path, repo_root: Path, assume_yes: bool) -> bool:
    """Run `git apply` on a patch. Prompts unless assume_yes is True.

    Returns True if applied, False if skipped or failed.
    """
    if not assume_yes:
        try:
            ans = input(f"apply {patch_path.name}? [y/N] ").strip().lower()
        except EOFError:
            ans = ""
        if ans != "y":
            print(f"  -> skipped {patch_path.name}", file=sys.stderr)
            return False
    res = subprocess.run(
        ["git", "apply", "--check", str(patch_path)],
        cwd=repo_root,
        capture_output=True,
        text=True,
    )
    if res.returncode != 0:
        print(f"  -> {patch_path.name}: git apply --check failed:", file=sys.stderr)
        print(res.stderr, file=sys.stderr)
        return False
    res = subprocess.run(
        ["git", "apply", str(patch_path)],
        cwd=repo_root,
        capture_output=True,
        text=True,
    )
    if res.returncode != 0:
        print(f"  -> {patch_path.name}: git apply failed:", file=sys.stderr)
        print(res.stderr, file=sys.stderr)
        return False
    print(f"  -> applied {patch_path.name}", file=sys.stderr)
    return True


# ---------------------------------------------------------------- CLI


def find_repo_root() -> Path:
    """Walk up from this script until we find the git root."""
    here = Path(__file__).resolve().parent
    for cand in [here, *here.parents]:
        if (cand / ".git").exists():
            return cand
    return Path.cwd()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("files", nargs="+", help="KERNEL.FIX (and rotation siblings)")
    ap.add_argument(
        "--out", type=Path, default=Path("fix-patches"),
        help="directory for emitted .patch files (default: fix-patches/)",
    )
    ap.add_argument(
        "--apply", action="store_true",
        help="run `git apply` on each patch after writing it (prompts unless --yes)",
    )
    ap.add_argument(
        "--markers",
        type=Path,
        default=None,
        help="optional gen-fix-markers.py JSON manifest; emits observability patches for safe unmacroed markers",
    )
    ap.add_argument(
        "--yes", action="store_true",
        help="skip confirmation prompts for --apply (DANGER)",
    )
    args = ap.parse_args()

    repo_root = find_repo_root()
    thunks_index = load_thunks_table(repo_root)
    print(
        f"# loaded {len(thunks_index)} thunks_table.inc entries from {repo_root}",
        file=sys.stderr,
    )

    all_records: list[FixRecord] = []
    for path in args.files:
        try:
            recs = read_records(path)
        except (FileNotFoundError, ValueError) as exc:
            print(f"# skip {path}: {exc}", file=sys.stderr)
            continue
        all_records.extend(recs)
    if not all_records and not args.markers:
        print("# no readable fix-journal files", file=sys.stderr)
        return 1

    actions = plan_actions(all_records, thunks_index, repo_root)
    if args.markers:
        markers = load_markers(args.markers)
        marker_actions = plan_marker_actions(markers, repo_root)
        print(
            f"# loaded {len(markers)} marker(s) from {args.markers}; "
            f"generated {len(marker_actions)} marker action(s)",
            file=sys.stderr,
        )
        actions.extend(marker_actions)
    patch_paths = write_patches(actions, args.out)
    print(render_markdown(actions, patch_paths))

    if args.apply and patch_paths:
        print(f"# applying {len(patch_paths)} patch(es)", file=sys.stderr)
        applied = 0
        for p in patch_paths:
            if apply_patch(p, repo_root, args.yes):
                applied += 1
        print(f"# applied {applied}/{len(patch_paths)} patch(es)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
