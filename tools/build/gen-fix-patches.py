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
import shutil
import struct
import subprocess
import sys
from dataclasses import dataclass, field
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
    7: "cap_denial",
    8: "trap_capture",
    9: "user_fault",
    10: "kassert_fail",
}

# x86_64 trap vectors that fire as TrapCapture records. The kernel's
# trap dispatcher only records the panic-bound vectors here — recovered
# faults route through SoftFaultRecov instead.
TRAP_VECTOR_NAMES = {
    0: "#DE (divide by zero)",
    1: "#DB (debug)",
    3: "#BP (breakpoint)",
    4: "#OF (overflow)",
    5: "#BR (bound range)",
    6: "#UD (undefined opcode)",
    7: "#NM (device not available)",
    8: "#DF (double fault)",
    10: "#TS (invalid TSS)",
    11: "#NP (segment not present)",
    12: "#SS (stack-segment fault)",
    13: "#GP (general protection)",
    14: "#PF (page fault)",
    16: "#MF (x87 FPE)",
    17: "#AC (alignment check)",
    18: "#MC (machine check)",
    19: "#XM (SIMD FPE)",
}

# Page-fault error-code bit decode (vector 14 specifically). Bits
# match the AMD64 SDM §8.2.15 / Intel SDM §6.15.
PF_ERROR_BITS = [
    (1 << 0, "PRESENT", "page was present"),
    (1 << 1, "WRITE", "write access"),
    (1 << 2, "USER", "ring-3 access"),
    (1 << 3, "RSVD", "reserved bit set in PTE"),
    (1 << 4, "INSTR", "instruction fetch"),
    (1 << 5, "PK", "protection-key violation"),
    (1 << 15, "SGX", "SGX violation"),
]


def decode_pf_error_code(err: int) -> tuple[str, str]:
    """Return (short_flags, long_description) for a #PF error code.

    short_flags is a compact letter set ('rwu' etc.) suitable for a
    one-line label; long_description is a human sentence for the brief.
    """
    short: list[str] = []
    long_parts: list[str] = []
    for bit, label, desc in PF_ERROR_BITS:
        if err & bit:
            short.append(label[0].lower())
            long_parts.append(desc)
    if not short:
        return ("?", "no decoded error-code bits")
    return ("".join(short), ", ".join(long_parts))


def is_selftest_record(source_pin: str) -> bool:
    """True for the synthetic records `FixJournalSelfTest()` injects to
    validate the journal mechanism (one per detector + an auto-pin
    probe). These are NOT real gaps: their pins (`selftest/stub.cpp:1`,
    `selftest!ThunkSelftest`, `selftest/syscall#999`, …, and the
    auto-derived `…FixJournalSelfTest()+0xNN`) point at no real source.
    Treating them as gaps produces actively harmful candidate patches —
    e.g. a thunk-table row for a fake `selftest.dll` that, if applied
    in CI, corrupts the Win32 ABI table. They are filtered before any
    action is planned. See `kernel/diag/fix_journal.cpp`
    `FixJournalSelfTest()` for the injected pin set.
    """
    p = source_pin.strip()
    # `selftest` followed by a path/dll/syscall/domain separator is
    # the synthetic shape: `selftest/stub.cpp:1`, `selftest!Thunk…`,
    # `selftest/syscall#999`, and `selftest.fault-react` (the
    # FaultReactSelfTest domain). No real source pin starts that way
    # (real pins are `kernel/...`, `drivers/...`, `dll!Fn`, …). The
    # auto-pinned probe record carries the function name instead.
    return (
        p == "selftest"
        or bool(re.match(r"selftest[/!.#:\s]", p))
        or "FixJournalSelfTest" in p
        or "FaultReactSelfTest" in p
    )

# FaultKind enum from kernel/diag/fault_react.h. Used by the
# SoftFaultRecov template to decode `ctx_a` for records that come
# out of `FaultReactDispatch` (RetryNow / RestartDomain branches).
# Records with `source_pin == "trap.recov"` come from the trap-
# context extable path and use `caller_rip` instead.
FAULT_KIND_NAMES = {
    0: "device-timeout",
    1: "dma-error",
    2: "unexpected-status",
    3: "firmware-lied",
    4: "internal-invariant",
    5: "hung",
    6: "retry-exhausted",
    7: "kernel-page-fault",
    8: "user-page-fault",
    9: "memory-corruption",
    10: "stack-canary-failed",
    11: "soft-lockup",
    12: "unknown",
}

# Per-FaultKind suggested next-action templates. Each line is the
# headline advice rendered into the markdown brief; the detail
# beneath comes from the per-record fields.
FAULT_KIND_FOLLOWUP = {
    "device-timeout": (
        "Extend the per-device timeout budget OR add a device-quirks "
        "entry for the responder. A recurring DeviceTimeout that "
        "recovers via retry usually means the spec-defined timeout "
        "was too tight for this silicon revision."
    ),
    "dma-error": (
        "Audit the DMA descriptor build path for cache-line alignment "
        "and the IOMMU permission window. A single DmaError that "
        "recovered via domain restart is usually a stale TLB entry; "
        "repeats under sustained load mean the descriptor itself is "
        "wrong."
    ),
    "unexpected-status": (
        "The device returned a status word the driver couldn't decode. "
        "Add the observed status to the device's status-decoder table "
        "(if the value is in the spec) or to the device-quirks list "
        "(if it's a vendor extension). Repeated recoveries with the "
        "same caller_rip mean the decoder is missing a real spec "
        "value, not a vendor quirk."
    ),
    "firmware-lied": (
        "A device descriptor / capability word is inconsistent with "
        "later behaviour. Tighten the bring-up validation so the "
        "kernel rejects the device early rather than restarting "
        "the domain at first use."
    ),
    "internal-invariant": (
        "A subsystem state machine entered an invalid state and the "
        "domain restarted. Trace the invariant back to its writers "
        "(grep the offending field). A recurring InternalInvariant "
        "means a writer is missing a transition; a one-off may be "
        "a torn read across a missing memory barrier."
    ),
    "hung": (
        "A subsystem thread missed its watchdog deadline. If the "
        "subsystem is a poller, audit the poll budget. If it's an "
        "IRQ-driven worker, check whether the wake path is racing "
        "the sleep path."
    ),
    "retry-exhausted": (
        "RetryWithBackoff gave up. Either the underlying operation "
        "is fundamentally broken (treat as a hard fault, not a "
        "retry candidate) or the budget needs a separate per-call-"
        "site `RetryPolicy` that admits more attempts."
    ),
    "user-page-fault": (
        "A ring-3 task touched memory it had no right to. The "
        "dispatcher killed it (Class C) and recorded the recovery; "
        "the userland fix lives in the task itself. Repeated "
        "recoveries with the same `source` may indicate a "
        "kernel/user ABI mismatch the kernel can detect earlier "
        "(e.g. a syscall arg validation gap)."
    ),
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
    # True when this record's (detector, source_pin) pair did not
    # appear in any rotation-baseline file. Set by main() when the
    # caller passes prior boots on argv after the current KERNEL.FIX.
    # Defaults True so single-file invocations (no baseline) treat
    # every record as NEW — which is the right framing for a first-
    # ever cycle.
    is_new: bool = True

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


def _hunk_replace_with_block(file_rel: str, lines: list[str], idx: int,
                             new_lines: list[str]) -> str:
    """Build a hunk that replaces `lines[idx]` with the multi-line block
    `new_lines` (each entry already terminated with '\\n')."""
    ctx_start = max(0, idx - 3)
    pre = lines[ctx_start:idx]
    post = lines[idx + 1 : idx + 4]
    old_count = len(pre) + 1 + len(post)
    new_count = len(pre) + len(new_lines) + len(post)
    out: list[str] = []
    out.append(f"--- a/{file_rel}\n")
    out.append(f"+++ b/{file_rel}\n")
    out.append(f"@@ -{ctx_start + 1},{old_count} +{ctx_start + 1},{new_count} @@\n")
    for ln in pre:
        out.append(" " + ln)
    out.append("-" + lines[idx])
    for ln in new_lines:
        out.append("+" + ln)
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
    "kernel/diag/fault_inject.cpp:57": (
        "namespace-scope assumption note on a constexpr VA constant, not a "
        "reachable runtime branch; there is no statement context to instrument"
    ),
    "kernel/drivers/virtio/virtio_pci.cpp:238": (
        "DRIVER_OK on the transport-only negotiate path is correct as written "
        "(per-device drivers install queues before they need I/O); this is a "
        "design-boundary note, not a behavioural gap, so a journal record here "
        "would be permanent false noise on every virtio device probe"
    ),
    "kernel/subsystems/translation/translate.cpp:595": (
        "the GAP annotates the absent NtSetDefaultLocale counterpart, not the "
        "NtQueryDefaultLocale function it sits in (which is complete); wiring "
        "the Query path would mis-attribute the gap to the wrong call site"
    ),
    "kernel/subsystems/translation/translate.cpp:610": (
        "the GAP annotates the absent NtSetDefaultUILanguage counterpart, not "
        "the NtQueryDefaultUILanguage function it sits in (which is complete); "
        "wiring the Query path would mis-attribute the gap to the wrong call site"
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


# Default minimum repeat_count before the marker-log-upgrade patch
# generator considers a STUB/GAP hit "hot" enough to add a
# KLOG_ONCE_WARN line next to its FIX_NOTE_*. Tunable via
# `--marker-log-threshold N` on the CLI.
DEFAULT_MARKER_LOG_THRESHOLD = 10


def _subsys_label_from_pin(pin_path: str) -> str:
    """Derive a klog subsys label from the path component of a source pin.

    Examples (pin is the leading `path/file.cpp` of `path/file.cpp:Func`):
      `sched/sched.cpp` -> `sched`
      `acpi/aml.cpp` -> `acpi`
      `drivers/net/iwlwifi_rings.cpp` -> `drivers/net`
      `arch/x86_64/timer.cpp` -> `arch/x86_64`

    The result is what `KLOG_ONCE_WARN(<subsys>, ...)` expects: a short,
    grep-able identifier for the area. Not perfect (the codebase uses
    several conventions — `arch/timer` in some places, `arch/x86_64` in
    others — but the generated label is stable per-pin and the reviewer
    can edit before applying.
    """
    parts = pin_path.rsplit("/", 1)
    if len(parts) == 1:
        # Bare filename — fall back to the stem.
        return Path(parts[0]).stem
    return parts[0]


def _try_resolve_pin_to_file(pin: str, repo_root: Path) -> tuple[Path, str] | None:
    """Resolve a FixRecord source_pin to (absolute_path, function_name).

    The pin format used by FIX_NOTE_* call sites is `<path>:<Function>`.
    `<path>` may be either fully-qualified (`kernel/foo/bar.cpp`) or
    kernel-relative (`foo/bar.cpp` — the bulk of the codebase). Returns
    None on parse / lookup failure.
    """
    if ":" not in pin:
        return None
    path_part, _, func = pin.partition(":")
    if not path_part or not func:
        return None
    # `func+0xOFF` is the auto-pin fallback — not a real function name.
    if re.search(r"\+0x[0-9a-fA-F]+$", func):
        return None
    candidate = repo_root / path_part
    if not candidate.exists():
        candidate = repo_root / "kernel" / path_part
        if not candidate.exists():
            return None
    return candidate, func


def synth_marker_log_upgrade_patch(r: FixRecord, repo_root: Path) -> str | None:
    """Insert a `KLOG_ONCE_WARN` next to a hot FIX_NOTE_STUB/GAP call.

    Triggered for a StubMarker / GapMarker record whose `repeat_count`
    is high enough to justify promoting the silent dfix-only record
    into a serial-visible "this gap is being hit hard" line on the
    *next* boot. The patch is additive observability — no control-flow
    change, idempotent (a second pass is a no-op once the KLOG_ONCE_WARN
    already lives next to the FIX_NOTE_*).

    The discipline mirrors CLAUDE.md "Diagnostic Logging — Keep It,
    Gate It, Probe It": KLOG_ONCE_WARN fires once per call site per
    boot, so even a 10000x deny storm produces one log line, not a
    firehose.

    Returns the unified diff, or None if:
      * pin doesn't parse / file not found
      * no `FIX_NOTE_*` call with this pin string was found in the file
      * a `KLOG_ONCE_WARN` already exists in the 4-line window after
        the FIX_NOTE_* (idempotency)
    """
    pin = r.source_pin
    resolved = _try_resolve_pin_to_file(pin, repo_root)
    if resolved is None:
        return None
    path, _func = resolved
    if path.suffix not in _MARKER_SOURCE_SUFFIXES:
        return None

    file_rel = path.relative_to(repo_root).as_posix()
    raw = path.read_text(encoding="utf-8", errors="replace")
    lines = raw.splitlines(keepends=True)

    # Locate the FIX_NOTE_*("...pin...", ...) line. The pin string in
    # the record was captured verbatim from the macro call, so a
    # substring match against the quoted pin in source is reliable.
    # Use the pin as it appears in the record; clang-format may have
    # wrapped the call across two lines, so look for the quoted pin
    # specifically rather than the whole `FIX_NOTE_*(` token.
    quoted = f'"{pin}"'
    fix_line_idx = -1
    for i, ln in enumerate(lines):
        if quoted in ln and ("FIX_NOTE_STUB" in ln or "FIX_NOTE_GAP" in ln or
                             # clang-format may have left the macro name
                             # on the previous line and only the pin on
                             # this line. Detect by walking back one.
                             (i > 0 and ("FIX_NOTE_STUB" in lines[i - 1] or
                                         "FIX_NOTE_GAP" in lines[i - 1]))):
            fix_line_idx = i
            break
    if fix_line_idx < 0:
        return None

    # Walk forward to the end of the FIX_NOTE_* statement (line ending
    # in `);`). The macro is a `do { ... } while (0)` so the closing
    # `;` is unambiguous.
    end_idx = fix_line_idx
    while end_idx < len(lines):
        if lines[end_idx].rstrip().endswith(");"):
            break
        end_idx += 1
    if end_idx >= len(lines):
        return None

    insert_at = end_idx + 1

    # Idempotency: if the next 4 lines already contain a KLOG_ONCE_WARN
    # or any klog macro that names this pin, skip. The check is
    # deliberately loose — we want to avoid stacking duplicate logs
    # even if the operator hand-edited a related KLOG_WARN.
    for j in range(insert_at, min(insert_at + 4, len(lines))):
        if "KLOG_ONCE_WARN" in lines[j] or "KLOG_ONCE_INFO" in lines[j]:
            return None

    indent = _leading_spaces(lines[fix_line_idx])
    if indent == 0:
        return None

    # Build the new line. Subsys derived from pin's path component;
    # hint kept short (FIX_NOTE_*'s hint was already 39 chars max so
    # any further trimming preserves the operator's original wording).
    pin_path = pin.split(":", 1)[0] if ":" in pin else pin
    subsys = _subsys_label_from_pin(pin_path)
    hint = (r.hint or pin).strip()
    msg = f"fix-journal hot: {hint}"
    # KLOG_ONCE_WARN signature: (subsys, msg). String escaping uses the
    # same _escape_cpp_string helper that synth_marker_observability_patch
    # already uses for inserted macros.
    new_line = (
        " " * indent
        + f'KLOG_ONCE_WARN("{_escape_cpp_string(subsys)}", "{_escape_cpp_string(msg)}");\n'
    )

    # Insert + add the klog.h include if missing.
    klog_include = '#include "log/klog.h"\n'
    include_hunk = ""
    if not any('"log/klog.h"' in ln for ln in lines):
        include_indices = [i for i, ln in enumerate(lines) if ln.startswith("#include ")]
        if include_indices:
            include_insert_at = include_indices[-1] + 1
            include_hunk = _hunk_insert_lines(file_rel, lines, include_insert_at, [klog_include])
            # Adjust insert_at to account for the include hunk shifting
            # the line numbers downward — but since `_hunk_insert_lines`
            # operates on the live `lines` list passed by reference, we
            # need to refetch the index after the include is virtually
            # added. Easier: build the two hunks against the same
            # original `lines` since the line numbers are computed from
            # the pre-insertion file content (which is what `git apply`
            # also wants on `--- a/...` side).
    macro_hunk = _hunk_insert_lines(file_rel, lines, insert_at, [new_line])
    return include_hunk + macro_hunk


# `case 0xNN:` body template for the unknown-syscall stub patch. Lives
# at module scope so the test harness can exercise the substitution
# without re-deriving it. Indentation is 4 spaces (matches the existing
# arms in kernel/syscall/syscall.cpp's main switch).
#
# The body uses `FixJournalRecord(...)` directly rather than the
# parameterless `FIX_NOTE_STUB(...)` macro because the macro can't
# carry detector-specific context — and the first two argument
# registers (`rdi`, `rsi`) are exactly the context a reviewer needs to
# triage the call. ctx_a = rdi, ctx_b = rsi. Higher args (rdx / r10 /
# r8 / r9) drop into the journal's caller_rip resolution / GDB attach.
_UNKNOWN_SYSCALL_STUB_BODY = """\
    case 0x{num:x}u:
    {{
        // STUB: syscall 0x{num:x} observed via fix-journal but not yet
        // implemented. The arm exists so dedup attributes future hits
        // to this site (not the catch-all `UnknownSyscall` arm) and so
        // a future implementer can flip the body to real semantics
        // without touching the dispatch table.
        //
        // ctx_a / ctx_b capture the first two arg registers (rdi/rsi)
        // so the reviewer sees what's being called with, not just
        // that 0x{num:x} fired. Higher args reach the brief via
        // caller_rip resolution.
        (void)::duetos::diag::FixJournalRecord(
            ::duetos::diag::FixDetector::StubMarker, "syscall:0x{num:x}",
            "implement syscall 0x{num:x}", frame->rdi, frame->rsi);
        frame->rax = static_cast<u64>(kSysErrnoENOSYS);
        return;
    }}

"""


def synth_unknown_syscall_stub_patch(r: FixRecord, num: int, repo_root: Path) -> str | None:
    """Insert a per-syscall stub arm before the unknown-syscall default.

    The arm records a `StubMarker` with pin `syscall:0xNN` (specific to
    this number, distinct from the catch-all `UnknownSyscall:syscall#NN`
    record) so a future boot's report shows the reviewer has
    *acknowledged* the syscall without yet implementing it. The return
    value (`-ENOSYS`) is identical to the catch-all's, so there's no
    semantic delta for the calling EXE; only the journal record kind
    and dedup key change.

    Why this is safer than the typical "auto-add a switch arm" pattern:
      * The arm body is a NAMED placeholder, not a guessed implementation.
      * It returns the same error code the catch-all already returned,
        so applying the patch can't break a workload that was previously
        getting consistent `-ENOSYS`.
      * The FIX_NOTE_STUB marker keeps the gap visible in dfix and in
        the next boot's report — the patch doesn't pretend the syscall
        is handled.

    Returns None if the dispatch file isn't in the expected shape (no
    recognisable default arm, or the arm already exists).
    """
    path = repo_root / _SYSCALL_PATH
    if not path.exists():
        return None
    raw = path.read_text(encoding="utf-8", errors="replace")
    lines = raw.splitlines(keepends=True)

    # Idempotency: refuse to add an arm whose case constant already
    # exists. The catch-all default + the per-arm `case 0xNN:` line are
    # both candidates — match either form.
    case_decimal = f"case {num}:"
    case_hex = f"case 0x{num:x}u:"
    case_hex_upper = f"case 0x{num:X}u:"
    for ln in lines:
        s = ln.strip()
        if case_decimal in s or case_hex in s or case_hex_upper in s:
            return None
        # Also detect `case SYS_FOO:` resolving to this number — we
        # can't evaluate the macro, but the catch-all's
        # `FixJournalRecord(UnknownSyscall, ...)` only fires when the
        # number falls past every named arm, so if the journal saw
        # an UnknownSyscall for this `num` then by definition there
        # is no SYS_* arm for it. No further check needed.

    # Locate the catch-all default arm — the one with the
    # `FixDetector::UnknownSyscall` call. There are several `default:`
    # cases in the file (in inner switches), so pin specifically on
    # the one that records the UnknownSyscall detector.
    target_idx = -1
    for i, ln in enumerate(lines):
        if "FixDetector::UnknownSyscall" in ln:
            # Walk backwards to the enclosing `default:` line. The
            # default arm holds a substantial pin-building block above
            # the FixJournalRecord call (~60 lines in the current
            # syscall.cpp), so the search window is wide.
            for j in range(i, max(i - 200, -1), -1):
                if lines[j].lstrip().startswith("default:"):
                    target_idx = j
                    break
            if target_idx > 0:
                break
    if target_idx < 0:
        return None

    # Insert the new case arm right before the `default:` line. Use 4
    # spaces of indent (matching the existing arms).
    insertion = _UNKNOWN_SYSCALL_STUB_BODY.format(num=num).splitlines(keepends=True)
    file_rel = path.relative_to(repo_root).as_posix()
    return _hunk_insert_lines(file_rel, lines, target_idx, insertion)


def synth_syscall_brief(r: FixRecord, num: int, stub_patch_planned: bool = False) -> str:
    """Generate a markdown implementation brief for an unknown syscall.

    Syscall semantics are ABI work — a switch arm with a real body
    changes the kernel/userland contract and must be designed from the
    intended NT or native specification. This brief carries the journal
    context the reviewer needs to start that work.

    When `stub_patch_planned` is True (the synthesiser also produced an
    additive observability arm via `synth_unknown_syscall_stub_patch`),
    the brief points at that patch as the FIRST step — apply it to get
    arg-aware records on the next boot, then design the real
    implementation against the captured rdi/rsi values.
    """
    out: list[str] = []
    out.append(f"Runtime reached syscall `0x{num:x}` with no dispatcher arm.")
    if stub_patch_planned:
        out.append("")
        out.append(
            f"**A companion patch (`syscall-stub-0x{num:x}.patch`) is "
            f"included alongside this brief.** Apply it to add an "
            f"acknowledged `case 0x{num:x}u:` arm that records "
            f"`StubMarker:syscall:0x{num:x}` with the first two arg "
            f"registers (`rdi`, `rsi`) captured as ctx_a/ctx_b. The arm "
            f"returns the same `-ENOSYS` the catch-all already did — "
            f"applying the patch is **observation-only**, not a "
            f"semantic fix. With it landed, the next boot's record "
            f"shows what the caller is passing, which is the missing "
            f"context for designing the real implementation."
        )
        out.append("")
        out.append(
            "Then implement the real syscall contract by flipping the "
            "arm's body. No further dispatch-table work is needed."
        )
    else:
        out.append("")
        out.append(
            f"Implement the intended syscall contract in "
            f"`{_SYSCALL_PATH}` near the main switch default arm that "
            f"records `UnknownSyscall`. (The companion auto-patch was "
            f"either suppressed via `--no-syscall-stub` or the "
            f"synthesiser couldn't locate the default arm.)"
        )
    out.append("")
    out.append("Journal context:")
    out.append(f"- seq: `{r.seq}`")
    out.append(f"- repeat: `{r.repeat}`")
    out.append(f"- source_pin: `{r.source_pin}`")
    out.append(f"- caller_rip: `0x{r.caller_rip:016x}`")
    out.append(f"- ctx_a: `0x{r.ctx_a:016x}`")
    out.append(f"- ctx_b: `0x{r.ctx_b:016x}`")
    out.append(f"- hint: `{r.hint or '(none)'}`")
    return "\n".join(out) + "\n"


@dataclass
class SymbolResolver:
    """Resolve kernel RIPs to `function (file:line)` via addr2line.

    Single-shot: collect every RIP a record set references, run one
    `addr2line` invocation with all of them, build a dict, and let
    callers `.resolve(rip)` against it. Avoids the per-record fork
    overhead while keeping the rest of the pipeline addr2line-tool-
    agnostic — `llvm-addr2line` is preferred for its richer demangling
    and inlining info, with binutils `addr2line` as the fallback.

    A None elf_path produces a no-op resolver: `.resolve()` returns
    the empty string. Lets the call sites stay unconditional and
    keeps the pre-existing "no kernel ELF supplied" workflow valid.
    """

    elf_path: Path | None = None
    _table: dict[int, str] = field(default_factory=dict)
    _missing_tool_logged: bool = field(default=False)

    @staticmethod
    def _select_tool() -> str | None:
        for candidate in ("llvm-addr2line", "addr2line"):
            if shutil.which(candidate):
                return candidate
        return None

    def prime(self, rips: list[int]) -> None:
        """Populate the table for the given RIPs.

        Skips zero / unmapped values up-front; addr2line emits
        '?? at ??:0' for those, which adds noise without adding
        signal."""
        if self.elf_path is None:
            return
        if not self.elf_path.exists():
            print(f"# kernel ELF not found: {self.elf_path}", file=sys.stderr)
            return
        unique = sorted({r for r in rips if r != 0 and r >> 48 == 0xFFFF})
        if not unique:
            return
        tool = self._select_tool()
        if tool is None:
            if not self._missing_tool_logged:
                print(
                    "# warn: neither llvm-addr2line nor addr2line is on PATH; "
                    "skipping symbol resolution",
                    file=sys.stderr,
                )
                self._missing_tool_logged = True
            return
        try:
            args = [tool, "-e", str(self.elf_path), "-f", "-i", "-p", "-C", "-s"]
            args.extend(f"0x{r:x}" for r in unique)
            out = subprocess.run(
                args,
                check=False,
                capture_output=True,
                text=True,
                timeout=30,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            print(f"# warn: addr2line invocation failed: {exc}", file=sys.stderr)
            return
        # `-p -i` produces one line per address (top frame); inline
        # frames continue on subsequent lines indented with " (inlined by)".
        # We keep only the top frame for each requested address — the
        # display is best-effort, not a full backtrace.
        lines = [ln for ln in out.stdout.splitlines() if ln and not ln.startswith(" (inlined by)")]
        for rip, line in zip(unique, lines):
            self._table[rip] = line.strip()
        print(
            f"# resolved {len(self._table)}/{len(unique)} RIP(s) "
            f"via {tool} against {self.elf_path}",
            file=sys.stderr,
        )

    def resolve(self, rip: int) -> str:
        """Return a human display for `rip`, or empty string if unknown.

        The returned form is whatever addr2line printed, e.g.
        `Foo::Bar() at file.cpp:123` or `?? at ??:0` for an
        unresolvable address. Callers decide whether to embed it
        inline in the brief.
        """
        if rip == 0:
            return ""
        return self._table.get(rip, "")


def _new_tag(r: FixRecord) -> str:
    """Title decoration showing whether the record is new this cycle.

    Returns ` [NEW]` (with the leading space) when the record's
    (detector, source_pin) pair did not appear in any rotation
    baseline. Empty string when the record is RESEEN. Title-decoration
    style chosen so multi-record reports scan as "show me the NEW
    rows first" without losing context for the others.
    """
    return " [NEW]" if r.is_new else ""


def _priority_tier(repeat: int, kind_label: str = "recovery") -> tuple[str, str]:
    """Generic LOW/MEDIUM/HIGH bucketing by repeat_count.

    Used by every note-shaped detector that wants the same tiering
    (StubMarker, GapMarker, LoaderReject, SoftFaultRecov). The
    `kind_label` is folded into the message so each detector
    surfaces the same band with detector-specific framing.
    """
    if repeat <= 2:
        return ("LOW", f"expected one-off; note for awareness ({kind_label})")
    if repeat <= 10:
        return ("MEDIUM", f"repeated {kind_label}: investigate when convenient")
    return ("HIGH", f"hot {kind_label}: workaround likely masking a real bug — fix or upgrade the policy")


def _soft_fault_priority(repeat: int) -> tuple[str, str]:
    """Soft-fault flavour of `_priority_tier` — kept under the original
    name to preserve internal call-site signatures. `repeat <= 2`
    returns LOW, etc. The wording is SoftFaultRecov-specific because
    the brief framing asks the reviewer about a "workaround" rather
    than a "marker hit."
    """
    if repeat <= 2:
        return ("LOW", "expected one-off; note for awareness")
    if repeat <= 10:
        return ("MEDIUM", "investigate: repeated recovery may indicate a real flake")
    return ("HIGH", "WARNING: hot path; the workaround is masking a real bug — fix or upgrade the policy")


# Per-PeStatus follow-up advice. Pin format from the kernel side is
# `loader/pe:<PeStatusName>` (kernel/loader/pe_loader.cpp:1620). Each
# entry is the actionable "where to look in source" for that reject
# class. Statuses not listed fall through to a generic message.
PE_REJECT_FOLLOWUP = {
    "TooSmall": "The PE buffer is shorter than a DOS stub. The image is malformed; reject is correct, no source change needed unless the producer (a loader / network path) is feeding truncated bytes.",
    "BadDosMagic": "Bytes 0-1 are not 'MZ'. Either a non-PE blob reached PeLoad (a producer-side bug) or a real PE was corrupted in transit.",
    "BadLfanewBounds": "The DOS stub's e_lfanew points past EOF — corrupted PE. Reject is correct.",
    "BadNtSignature": "PE\\0\\0 missing at e_lfanew. Reject is correct; investigate the producer.",
    "BadMachine": "Image targets a machine other than IMAGE_FILE_MACHINE_AMD64 (0x8664). To support more architectures (i386 / ARM64), gate machine validation in `kernel/loader/pe_loader.cpp` and add the per-machine entry stubs.",
    "NotPe32Plus": "OptionalHeader.Magic != 0x20B (PE32+ AMD64). For 32-bit PE (Magic 0x10B) support, lift the magic check and add a 32-bit OptionalHeader parser path.",
    "SectionAlignUnsup": "SectionAlignment != 4096. Most production PEs use 4 KiB; non-4 KiB section alignment is rare (custom PEs / packed binaries). Add multi-alignment support in section walking + page mapping.",
    "FileAlignUnsup": "FileAlignment is not a power-of-2 in [512, 4096]. Same shape as SectionAlignUnsup — rare; extend if a target PE actually trips it.",
    "SectionCountZero": "PE has zero sections. Either a malformed file or an image relying on a section-less init path (uncommon).",
    "OptHeaderOutOfBounds": "SizeOfOptionalHeader is shorter than required. Malformed PE.",
    "SectionOutOfBounds": "A section's raw data extends past EOF. Malformed PE.",
    "ImportsPresent": "Imports directory is non-empty AND at least one import is unresolved. **Most fixable** of the reject classes — usually means a thunks_table.inc row is missing. Check the UnmappedThunk records in this report; they identify the specific DLL!fn pairs to add.",
    "RelocsNonEmpty": "Base reloc directory is non-empty. The PE was linked at an ImageBase that conflicts with the kernel's mapping; v0 doesn't walk the .reloc table. **Fix shape:** implement a base-reloc walker in `kernel/loader/pe_loader.cpp`. Required to load PEs that don't link with `/FIXED:NO` set inversely.",
    "TlsPresent": "TLS Directory non-empty. v0 tolerates this only when the callbacks array is empty (MSVC's placeholder). If real TLS callbacks are needed, see TlsCallbacksUnsupported below.",
    "TlsCallbacksUnsupported": "TLS Directory has at least one non-null callback VA. **Fix shape:** add a ring-3 thunk that calls each callback before entry — the kernel needs to walk the callback array, allocate a small bootstrap stub in user memory, and route process entry through it. Significant slice (think DLL TLS init).",
    "StubsPageAllocFail": "Out of physical memory during PE load — the stubs page (the kernel-side stub trampolines) couldn't allocate. Investigate frame-allocator pressure under PE load; this isn't a loader-policy gap, it's a system-resource failure.",
    "ImageBaseOutOfRange": "ImageBase or ImageBase+SizeOfImage is outside the canonical user low half (>0x00007FFFFFFFFFFF). This is a hostile / malformed PE — the reject IS the fix. Repeated hits are an attack signal worth feeding to the security log.",
}


def synth_loader_reject_brief(r: FixRecord, resolver: SymbolResolver | None = None) -> Action:
    """Generate a per-status brief for a LoaderReject record.

    The kernel side records the pin as `loader/pe:<PeStatusName>` and
    stuffs the PeStatus enum value in ctx_a + the file_len in ctx_b
    (kernel/loader/pe_loader.cpp:1634). We split off the status name
    and surface the per-status fix shape from PE_REJECT_FOLLOWUP.

    Two patches the generator does NOT auto-apply, by design:
      - A 'fix the malformed PE' patch — the kernel is right to
        reject it, the bug is producer-side.
      - A 'land RelocsNonEmpty support' patch — that's a real
        kernel slice that needs human design choices.
    Both surfaces would harm by pretending mechanical fixes exist.
    """
    priority, priority_note = _priority_tier(r.repeat, kind_label="loader rejection")
    status = ""
    if r.source_pin.startswith("loader/pe:"):
        status = r.source_pin[len("loader/pe:"):]

    lines: list[str] = []
    lines.append(f"**Priority: {priority}** — {priority_note}")
    lines.append("")
    lines.append(f"PE loader rejected an image with status `{status or r.source_pin}` "
                 f"({r.repeat} occurrence(s) since boot, image_size={r.ctx_b} bytes).")
    lines.append("")

    followup = PE_REJECT_FOLLOWUP.get(status)
    if followup:
        lines.append(f"**What this status means + fix shape:**")
        lines.append("")
        lines.append(followup)
    else:
        lines.append(
            f"Status `{status}` is not in the per-status follow-up "
            f"table; the kernel rejected for a reason this script "
            f"doesn't recognise. Either the kernel added a new "
            f"PeStatus enumerator without updating this table, or "
            f"the on-disk record is from a different version. Pin: "
            f"`{r.source_pin}`."
        )

    if r.repeat >= 5:
        lines.append("")
        lines.append(
            f"**Recurring rejection ({r.repeat}× since boot)** — the "
            f"same PE shape is being retried. Investigate the producer "
            f"(retry loop in a userland tool, a smoke test re-running "
            f"the same broken binary)."
        )

    # Caller RIP — for a LoaderReject, this is the loader's own RIP
    # at the reject site, useful as a breadcrumb to confirm which
    # rejection branch fired.
    if resolver is not None:
        sym = resolver.resolve(r.caller_rip)
        if sym and not sym.startswith("?? "):
            lines.append("")
            lines.append(f"Loader site: `{sym}` (rip=`0x{r.caller_rip:016x}`)")

    lines.append("")
    lines.append("---")
    lines.append("Journal record:")
    lines.append("```")
    lines.append(f"seq         = {r.seq}")
    lines.append(f"repeat      = {r.repeat}")
    lines.append(f"caller_rip  = 0x{r.caller_rip:016x}")
    lines.append(f"ctx_a       = 0x{r.ctx_a:016x}  (PeStatus enum value)")
    lines.append(f"ctx_b       = 0x{r.ctx_b:016x}  (file_len)")
    lines.append(f"source_pin  = {r.source_pin!r}")
    lines.append(f"hint        = {r.hint!r}")
    lines.append("```")

    title = f"Loader reject [{priority}]{_new_tag(r)} `{status or r.source_pin}` (×{r.repeat})"
    return Action(kind="note", title=title, body="\n".join(lines), filename=None)


# ---------------------------------------------------------------- TrapCapture

# Recognised fault-pattern signatures: (trap_kind, error_code_match,
# faulting_addr_match) -> (label, defensive_fix_template).
#
# These match common kernel-fault classes the patch generator can
# propose targeted defensive patches for. Each entry is intentionally
# narrow: a pattern that's CONFIDENTLY recognisable, mapped to a fix
# shape that's CONFIDENTLY additive (a guard added BEFORE the faulting
# operation, never replacing it). The brief always presents the
# proposed fix wrapped in a "REVIEW" framing so a human approves.
#
# Format of each fix template line:
#   "<context>": [
#       ("recognised condition",
#        "before-line",
#        "code suggestion (multi-line, '%s' substituted with the
#         source line that faulted)"),
#   ]
TRAP_FIX_TEMPLATES = {
    "null_deref_read": (
        "Null-pointer dereference (read) — CR2 in the low page "
        "(< 0x1000), error_code has PRESENT=0 and WRITE=0.",
        "Add a null-pointer guard BEFORE the dereference. Common shape:",
        "if (ptr == nullptr) { /* return / log / RESULT_TRY_OUT */ }\n"
        "{faulting_line}",
    ),
    "null_deref_write": (
        "Null-pointer dereference (write) — CR2 in the low page "
        "(< 0x1000), error_code has WRITE=1 and PRESENT=0.",
        "Add a null-pointer guard BEFORE the store. Common shape:",
        "if (ptr == nullptr) { /* return / log / RESULT_TRY_OUT */ }\n"
        "{faulting_line}",
    ),
    "stack_overflow": (
        "Kernel stack overflow — CR2 within the guard-page region of "
        "the per-task kstack. Usually caused by uncontrolled recursion "
        "or a single large stack allocation.",
        "Audit the call site for unbounded recursion. If a single "
        "frame is huge, convert to heap allocation:",
        "// REVIEW: convert large local to kheap allocation or smaller chunked I/O\n"
        "{faulting_line}",
    ),
    "user_pointer_smap": (
        "Kernel touched a user-space address directly. The fault is "
        "SMAP catching the bypass; the right fix is to route through "
        "CopyToUser / CopyFromUser.",
        "Wrap the access in the user-pointer mediator:",
        "// REVIEW: route through mm::CopyFromUser / CopyToUser\n"
        "if (!mm::CopyFromUser(&kernel_buf, user_ptr, len)) {{ return -EFAULT; }}\n",
    ),
    "div_by_zero": (
        "Divide by zero (#DE) — the divisor expression evaluated to 0.",
        "Add a guard before the division. Common shape:",
        "if (divisor == 0) { /* return / propagate ErrorCode::InvalidArgument */ }\n"
        "{faulting_line}",
    ),
    "undefined_opcode": (
        "Undefined opcode (#UD) — the byte sequence at RIP is not a "
        "valid x86_64 instruction. Usually: (a) a wild branch into a "
        "data region, (b) a function-pointer table corruption, or (c) "
        "a deliberate ud2 from an assert / KASSERT macro that was meant "
        "to fire.",
        "Audit the call path. If (c), the surfaced assertion is the "
        "real bug — fix the upstream invariant, not the trap site.",
        "// REVIEW: #UD usually means a wild jump or a deliberate KASSERT/ud2 firing.\n"
        "// If this code path was reached unexpectedly, audit the\n"
        "// invariant the upstream caller is violating.\n",
    ),
    "general_protection": (
        "General protection (#GP) — privileged instruction in ring 3, "
        "non-canonical address load, segment-selector violation, or "
        "MSR access denied.",
        "GP fault classes vary widely. Common kernel triggers:",
        "// REVIEW: #GP at this RIP — likely a non-canonical address\n"
        "// (sign-extended high bits not matching), a privileged\n"
        "// instruction in the wrong ring, or an invalid MSR\n"
        "// number. Add a range/canonical check before the load.\n",
    ),
}


def classify_trap(vector: int, error_code: int, cr2: int) -> str | None:
    """Map a (vector, error_code, cr2) tuple to a fix-template key.

    Returns the key into `TRAP_FIX_TEMPLATES`, or None if the pattern
    isn't confidently recognised (in which case the brief still
    surfaces all captured fields but doesn't propose a fix).
    """
    if vector == 14:  # #PF
        write = bool(error_code & (1 << 1))
        user = bool(error_code & (1 << 2))
        present = bool(error_code & (1 << 0))
        # Null deref: low-page CR2 (within first 4 KiB) AND
        # PRESENT=0 (page wasn't mapped).
        if cr2 < 0x1000 and not present and not user:
            return "null_deref_write" if write else "null_deref_read"
        # SMAP: ring-0 fault on a CR2 in canonical user range
        # (< 0x0000800000000000). PRESENT=1 means the page existed
        # but SMAP blocked the access.
        if not user and cr2 != 0 and cr2 < 0x0000800000000000 and present:
            return "user_pointer_smap"
        # Stack overflow: CR2 near the kstack guard region. The
        # kstack guard is one page below the kstack base; without
        # the runtime layout the classifier can only flag "this
        # looks like a guard-page hit" if CR2 is on a page boundary
        # AND the trapping RIP is inside a leaf function. We
        # conservatively flag based on guard alignment.
        if not user and (cr2 & 0xFFF) == 0:
            return "stack_overflow"
        return None
    if vector == 0:
        return "div_by_zero"
    if vector == 6:
        return "undefined_opcode"
    if vector == 13:
        return "general_protection"
    return None


def read_source_context(file_path: Path, line: int, window: int = 8) -> list[str]:
    """Return ±window lines around `line` from `file_path`, with line
    numbers prepended. Empty list on read failure.

    The window is wider than the marker-observability synth uses (3)
    because for a fault-site brief the reviewer benefits from seeing
    the surrounding block / function context, not just the immediate
    statement.
    """
    try:
        text = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    src_lines = text.splitlines()
    if line < 1 or line > len(src_lines):
        return []
    start = max(0, line - 1 - window)
    end = min(len(src_lines), line + window)
    out: list[str] = []
    width = len(str(end))
    for i in range(start, end):
        marker = ">>" if (i + 1) == line else "  "
        out.append(f"{marker} {str(i + 1).rjust(width)} | {src_lines[i]}")
    return out


def _resolve_source_path(addr2line_path: str, repo_root: Path) -> Path | None:
    """Convert an addr2line file path into a real on-disk path.

    addr2line emits paths in several shapes depending on how the ELF
    was built:
      * absolute compile-time path (`/home/user/DuetOS/kernel/foo.cpp`)
      * repo-relative path (`kernel/foo.cpp`)
      * basename only (`foo.cpp`) — when DWARF was stripped of CWD
    Try each form in order; for the basename-only case, glob the tree
    once and cache the first hit. Returns None if no match.
    """
    if not addr2line_path:
        return None
    p = Path(addr2line_path)
    if p.is_absolute() and p.exists():
        return p
    candidate = repo_root / addr2line_path
    if candidate.exists():
        return candidate
    # Basename-only fall-back: walk the source-bearing roots looking
    # for a unique match. Limited to known top-level dirs so a stray
    # basename from a third-party include doesn't pull in a wrong
    # match.
    base = p.name
    if "/" not in addr2line_path:
        for top in ("kernel", "userland", "drivers", "subsystems", "boot"):
            root = repo_root / top
            if not root.exists():
                continue
            for hit in root.rglob(base):
                if hit.is_file():
                    return hit
    return None


def disassemble_at(elf_path: Path | None, rip: int, count: int = 4) -> list[str]:
    """Disassemble `count` instructions starting at `rip` from the kernel
    ELF via objdump. Empty list on failure or when no ELF was supplied.

    Falls back gracefully — disassembly is a NICE-TO-HAVE in the brief;
    the source-context excerpt + register fields stay useful without it.
    """
    if elf_path is None or not elf_path.exists():
        return []
    tool = shutil.which("objdump") or shutil.which("llvm-objdump")
    if tool is None:
        return []
    try:
        # objdump --disassemble=<symbol> doesn't take an address; we
        # use --start-address / --stop-address to bound the window.
        # 4 typical x86_64 instructions average ~12 bytes; 48 byte
        # window is a safe upper bound.
        stop = rip + max(16, count * 12)
        res = subprocess.run(
            [tool, "-d", "-M", "intel", "--no-show-raw-insn",
             f"--start-address=0x{rip:x}", f"--stop-address=0x{stop:x}",
             str(elf_path)],
            check=False, capture_output=True, text=True, timeout=15,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    # Keep only the instruction lines (start with whitespace + hex addr).
    out: list[str] = []
    for ln in res.stdout.splitlines():
        m = re.match(r"^\s+([0-9a-f]+):\s+(.+)$", ln)
        if m:
            out.append(f"  0x{m.group(1)}: {m.group(2)}")
            if len(out) >= count:
                break
    return out


def synth_trap_capture_brief(r: FixRecord, resolver: SymbolResolver | None = None,
                             elf_path: Path | None = None,
                             repo_root: Path | None = None) -> Action:
    """Generate a fault-site brief for a TrapCapture record.

    Pulls together every layer of evidence the offline pipeline can
    extract for the trapping site:
      * symbol (addr2line `function (file:line)`)
      * ±8 lines of source context around the fault line
      * 4 instructions disassembled at the faulting RIP
      * decoded error_code bits (page-fault flag set, etc.)
      * classified fix pattern + proposed defensive shape (when the
        pattern is recognised)

    Decision #016: the proposed shape is wrapped in REVIEW framing
    and embedded as text in the brief — never auto-applied to the
    source. A reviewer reads, decides if the guess is right, and
    writes the real fix manually.
    """
    vector = int((r.ctx_a >> 32) & 0xff)
    error_code = int(r.ctx_a & 0xffffffff)
    cr2 = r.ctx_b
    vec_name = TRAP_VECTOR_NAMES.get(vector, f"vector={vector}")

    out: list[str] = []
    repeat_label = "first occurrence" if r.repeat <= 1 else f"repeated {r.repeat}× (post-panic re-trap?)"
    out.append(f"**Trap `{vec_name}` at RIP `0x{r.caller_rip:016x}`** — {repeat_label}.")
    out.append("")

    # Resolve RIP → file:line via addr2line.
    sym_line = ""
    file_part = ""
    line_part = 0
    if resolver is not None:
        sym = resolver.resolve(r.caller_rip)
        if sym and not sym.startswith("?? "):
            sym_line = sym
            out.append(f"Symbol: `{sym}`")
            # Try to extract `(file:line)` from the addr2line output.
            m = re.search(r"\(([^)]+):(\d+)\)|\bat\s+(\S+):(\d+)", sym)
            if m:
                file_part = m.group(1) or m.group(3) or ""
                try:
                    line_part = int(m.group(2) or m.group(4))
                except (TypeError, ValueError):
                    line_part = 0

    # Decoded error code (#PF specifically; other vectors carry an
    # error code with different bit semantics but we don't decode
    # them here).
    if vector == 14:
        short, longd = decode_pf_error_code(error_code)
        out.append(f"CR2: `0x{cr2:016x}`")
        out.append(f"Error code: `0x{error_code:x}` ({short} — {longd})")
    elif vector in (13, 17):  # #GP / #AC carry segment selectors
        out.append(f"Error code: `0x{error_code:x}` (segment selector / index)")
    else:
        if error_code != 0:
            out.append(f"Error code: `0x{error_code:x}`")
    out.append("")

    # Source context window.
    resolved_source: Path | None = None
    if file_part and line_part > 0 and repo_root is not None:
        resolved_source = _resolve_source_path(file_part, repo_root)
        if resolved_source is not None:
            ctx = read_source_context(resolved_source, line_part, window=8)
            if ctx:
                rel = resolved_source.relative_to(repo_root) if resolved_source.is_relative_to(repo_root) else resolved_source
                out.append(f"**Source context** (`{rel}:{line_part}`):")
                out.append("")
                out.append("```cpp")
                out.extend(ctx)
                out.append("```")
                out.append("")

    # Disassembly window.
    disasm = disassemble_at(elf_path, r.caller_rip, count=4)
    if disasm:
        out.append("**Disassembly at fault RIP**:")
        out.append("")
        out.append("```asm")
        out.extend(disasm)
        out.append("```")
        out.append("")

    # Classified fault pattern + proposed shape.
    pattern = classify_trap(vector, error_code, cr2)
    if pattern is not None and pattern in TRAP_FIX_TEMPLATES:
        condition, before_line, template = TRAP_FIX_TEMPLATES[pattern]
        out.append(f"**Recognised pattern**: {condition}")
        out.append("")
        out.append(before_line)
        out.append("")
        out.append("```cpp")
        # Substitute {faulting_line} with the actual faulting source
        # line if we resolved one; else leave the placeholder.
        sub = ""
        if resolved_source is not None and line_part > 0:
            try:
                src = resolved_source.read_text(encoding="utf-8", errors="replace").splitlines()
                if 0 < line_part <= len(src):
                    sub = src[line_part - 1].strip()
            except OSError:
                pass
        rendered = template.replace("{faulting_line}", sub or "<faulting expression>")
        out.append(rendered)
        out.append("```")
        out.append("")
        out.append(
            "**REVIEW**: This is a *proposed* defensive shape, not an "
            "auto-applied fix (Decision #016). Confirm the pattern "
            "match is correct for this site before adopting the "
            "guard — a `nullptr` may be the legitimate empty case "
            "the caller relies on, a SMAP fault may be a legitimate "
            "user-pointer access that needs a different fix, etc."
        )
    else:
        out.append(
            f"**No automatic fix-pattern match** for vector={vector}, "
            f"err=0x{error_code:x}, cr2=0x{cr2:x}. The captured "
            f"source + disassembly windows above are the reviewer's "
            f"starting point."
        )
    out.append("")

    out.append("---")
    out.append("Journal record:")
    out.append("```")
    out.append(f"seq         = {r.seq}")
    out.append(f"repeat      = {r.repeat}")
    out.append(f"caller_rip  = 0x{r.caller_rip:016x}  (faulting RIP)")
    out.append(f"ctx_a       = 0x{r.ctx_a:016x}  (vector<<32 | error_code)")
    out.append(f"ctx_b       = 0x{r.ctx_b:016x}  (CR2 for #PF; 0 otherwise)")
    out.append(f"source_pin  = {r.source_pin!r}")
    out.append(f"hint        = {r.hint!r}")
    out.append("```")

    title = f"Trap `{vec_name}` at `{r.source_pin}`{_new_tag(r)}"
    return Action(kind="note", title=title, body="\n".join(out), filename=None)


# =================================================================
# Real semantic-change patch generators for runtime-observed faults.
# =================================================================
#
# Every generator in this block follows the same discipline:
#   1. Resolve caller_rip / source_pin to a real `(file, line)`.
#   2. Read the source line to confirm the expected pattern (a
#      pointer deref, an allocation assignment, a division, etc.).
#   3. Generate a unified diff that REPLACES that line with a
#      guarded version, wrapping the change in `#if 0 ... #endif`
#      so applying the patch is BEHAVIOURALLY a no-op until the
#      reviewer affirmatively flips the gate.
#   4. Refuse to fire (return None) when the source line doesn't
#      match the expected shape — the patch generator MUST NOT
#      produce a wrong candidate; a brief-only fallback is always
#      strictly better than a confidently-wrong diff.
#
# The `#if 0` brake is the same shape as synth_kassert_demote_patch:
# applying the patch makes the proposal visible in source review,
# without changing kernel behaviour. The reviewer then flips it.


# Regex to extract the dereferenced pointer name from a faulting
# source line. Matches `foo->bar`, `(*foo).bar`, `*foo`, and the
# write variants. Captures the bare identifier so the guard can
# reference it. Conservative: only matches simple identifiers, not
# expressions — a complex faulting line falls through to brief-only.
_DEREF_PTR_RE = re.compile(
    r"\b(?P<ptr>[A-Za-z_][A-Za-z0-9_]*)\s*"
    r"(?:->|\[\s*[^\]]+\s*\]\s*=|\.[A-Za-z_])"
)
_STAR_DEREF_RE = re.compile(
    r"\*\(?\s*(?P<ptr>[A-Za-z_][A-Za-z0-9_]*)"
)

# Regex to find the divisor side of a division expression. The kernel
# style uses `a / b` or `a % b` with whitespace; we extract the rhs
# identifier. Won't recognise complex expressions like `a / (b + c)`;
# those fall through to brief-only.
_DIV_OP_RE = re.compile(
    r"[/%]\s*(?P<div>[A-Za-z_][A-Za-z0-9_]*)\b"
)


def _detect_return_type(lines: list[str], statement_idx: int) -> str | None:
    """Walk backwards from `statement_idx` to the enclosing function
    header line. Return one of:
      'result'   — function returns Result<...>
      'void'     — function returns void
      'pointer'  — function returns T*
      'integer'  — function returns int / u32 / i64 / errno-like
      None       — couldn't tell
    The classification picks the right "graceful return" shape for
    the guard the synthesiser emits.
    """
    for j in range(statement_idx, max(statement_idx - 80, -1), -1):
        ln = lines[j]
        stripped_no_comment = re.sub(r"//.*$", "", ln).rstrip()
        if "Result<" in ln:
            return "result"
        if re.match(r"^\s*void\s+\w+\s*\(", ln) or re.match(r"^void\s+\w+\s*\(", ln):
            return "void"
        # Pointer return: `T* funcname(` at column 0
        if re.match(r"^[A-Za-z_][A-Za-z0-9_:<>]*\s*\*\s+\w+\s*\(", ln):
            return "pointer"
        # Integer return: `int funcname(` / `i64 funcname(` / `u32 funcname(`
        if re.match(r"^(int|i32|i64|u32|u64|i8|i16|u8|u16|long|short|size_t|ssize_t)\s+\w+\s*\(", ln):
            return "integer"
        if stripped_no_comment.endswith("}") and j != statement_idx and _leading_spaces(ln) == 0:
            return None  # Walked out of enclosing function.
    return None


def _guard_return_for(return_type: str | None, comment: str) -> str | None:
    """Return the "graceful return" statement matching the function's
    return type. None when there's no safe equivalent."""
    if return_type == "result":
        return "        return ::duetos::core::Err{::duetos::core::ErrorCode::InvalidState};"
    if return_type == "void":
        return f"        return;  // {comment}"
    if return_type == "pointer":
        return f"        return nullptr;  // {comment}"
    if return_type == "integer":
        return f"        return -1;  // {comment}"
    return None


def _gated_guard_diff(
    file_rel: str,
    lines: list[str],
    line_idx: int,
    cond_expr: str,
    return_stmt: str,
    klog_subsys: str,
    klog_msg: str,
    review_header: list[str],
) -> str:
    """Build a `#if 0 ... #endif`-gated guard block REPLACING the
    line at `line_idx`. Same shape across detector kinds — the
    only thing that varies is the condition + return statement.
    """
    indent = _leading_spaces(lines[line_idx])
    sp = " " * indent
    target_line = lines[line_idx]
    new_block: list[str] = []
    for header in review_header:
        new_block.append(f"{sp}// {header}\n")
    new_block.append(f"{sp}#if 0\n")
    new_block.append(f"{sp}if ({cond_expr})\n")
    new_block.append(f"{sp}{{\n")
    new_block.append(
        f'{sp}    KLOG_ONCE_WARN("{_escape_cpp_string(klog_subsys)}", '
        f'"{_escape_cpp_string(klog_msg)}");\n'
    )
    new_block.append(f"{return_stmt}\n")
    new_block.append(f"{sp}}}\n")
    new_block.append(target_line if target_line.endswith("\n") else target_line + "\n")
    new_block.append(f"{sp}#else\n")
    new_block.append(target_line if target_line.endswith("\n") else target_line + "\n")
    new_block.append(f"{sp}#endif\n")
    return _hunk_replace_with_block(file_rel, lines, line_idx, new_block)


def synth_trap_null_deref_patch(r: FixRecord, resolver: SymbolResolver | None,
                                repo_root: Path) -> str | None:
    """Generate a real applicable patch that inserts a null-pointer
    guard BEFORE the source line that took a #PF null-dereference.

    Pattern recognition:
      * detector == trap_capture
      * vector == 14 (#PF)
      * CR2 in the low page (< 0x1000)
      * source line contains a recognisable pointer dereference

    The patch wraps the change in `#if 0` (the brake) and renders:
      if (ptr == nullptr) {
          KLOG_ONCE_WARN("<subsys>", "<msg>");
          return <type-appropriate graceful>;
      }
      <original line>

    Refuses to fire when:
      * Source line doesn't parse to a single dereferenced identifier
      * The enclosing function's return type isn't one of
        {Result, void, pointer, integer} (no safe graceful return)
      * A KLOG_ONCE_WARN with this subsys already exists nearby
        (idempotency — re-running won't stack)
    """
    if resolver is None:
        return None
    vector = int((r.ctx_a >> 32) & 0xff)
    cr2 = r.ctx_b
    if vector != 14 or cr2 >= 0x1000:
        return None

    sym = resolver.resolve(r.caller_rip)
    if not sym or sym.startswith("?? "):
        return None
    m = re.search(r"\(([^)]+):(\d+)\)|\bat\s+(\S+):(\d+)", sym)
    if not m:
        return None
    file_part = m.group(1) or m.group(3) or ""
    try:
        line_part = int(m.group(2) or m.group(4))
    except (TypeError, ValueError):
        return None
    if not file_part or line_part <= 0:
        return None

    path = _resolve_source_path(file_part, repo_root)
    if path is None or path.suffix not in _MARKER_SOURCE_SUFFIXES:
        return None
    raw = path.read_text(encoding="utf-8", errors="replace")
    lines = raw.splitlines(keepends=True)
    if line_part > len(lines):
        return None

    target = lines[line_part - 1]
    ptr_match = _DEREF_PTR_RE.search(target) or _STAR_DEREF_RE.search(target)
    if ptr_match is None:
        return None
    ptr_name = ptr_match.group("ptr")

    rt = _detect_return_type(lines, line_part - 1)
    return_stmt = _guard_return_for(rt, f"null-deref guard from fix-journal")
    if return_stmt is None:
        return None

    # Idempotency check.
    klog_subsys = file_part.rsplit("/", 1)[0] if "/" in file_part else Path(file_part).stem
    win_start = max(0, line_part - 5)
    win_end = min(len(lines), line_part + 5)
    for j in range(win_start, win_end):
        if "KLOG_ONCE_WARN" in lines[j] and ptr_name in lines[j]:
            return None

    file_rel = path.relative_to(repo_root).as_posix()
    review_header = [
        f"REVIEW: null-deref guard synthesised by fix-journal cycle.",
        f"Trap #PF at CR2=0x{cr2:x} (repeat={r.repeat}). The guard below",
        f"covers the case `{ptr_name} == nullptr`. Flip the `#if 0` to `#if 1`",
        f"to activate; the legitimate-null caller may need a different shape.",
    ]
    return _gated_guard_diff(
        file_rel, lines, line_part - 1,
        cond_expr=f"{ptr_name} == nullptr",
        return_stmt=return_stmt,
        klog_subsys=klog_subsys,
        klog_msg=f"null-deref guard fired: {ptr_name} was null",
        review_header=review_header,
    )


def synth_trap_div_zero_patch(r: FixRecord, resolver: SymbolResolver | None,
                              repo_root: Path) -> str | None:
    """Generate a real applicable patch that inserts a divisor != 0
    guard BEFORE the source line that took a #DE divide-by-zero.

    Same #if 0-gated discipline as synth_trap_null_deref_patch.
    Refuses to fire when the source line doesn't expose a single
    identifier on the rhs of `/` or `%`.
    """
    if resolver is None:
        return None
    vector = int((r.ctx_a >> 32) & 0xff)
    if vector != 0:  # #DE only
        return None

    sym = resolver.resolve(r.caller_rip)
    if not sym or sym.startswith("?? "):
        return None
    m = re.search(r"\(([^)]+):(\d+)\)|\bat\s+(\S+):(\d+)", sym)
    if not m:
        return None
    file_part = m.group(1) or m.group(3) or ""
    try:
        line_part = int(m.group(2) or m.group(4))
    except (TypeError, ValueError):
        return None
    if not file_part or line_part <= 0:
        return None

    path = _resolve_source_path(file_part, repo_root)
    if path is None or path.suffix not in _MARKER_SOURCE_SUFFIXES:
        return None
    raw = path.read_text(encoding="utf-8", errors="replace")
    lines = raw.splitlines(keepends=True)
    if line_part > len(lines):
        return None

    target = lines[line_part - 1]
    div_match = _DIV_OP_RE.search(target)
    if div_match is None:
        return None
    div_name = div_match.group("div")

    rt = _detect_return_type(lines, line_part - 1)
    return_stmt = _guard_return_for(rt, f"div-zero guard from fix-journal")
    if return_stmt is None:
        return None

    klog_subsys = file_part.rsplit("/", 1)[0] if "/" in file_part else Path(file_part).stem
    win_start = max(0, line_part - 5)
    win_end = min(len(lines), line_part + 5)
    for j in range(win_start, win_end):
        if "KLOG_ONCE_WARN" in lines[j] and div_name in lines[j]:
            return None

    file_rel = path.relative_to(repo_root).as_posix()
    review_header = [
        f"REVIEW: divide-zero guard synthesised by fix-journal cycle.",
        f"Trap #DE (repeat={r.repeat}). Guard below covers `{div_name} == 0`.",
        f"Flip the `#if 0` to `#if 1` to activate; a legitimate zero may",
        f"need a different shape (saturation, alternative computation).",
    ]
    return _gated_guard_diff(
        file_rel, lines, line_part - 1,
        cond_expr=f"{div_name} == 0",
        return_stmt=return_stmt,
        klog_subsys=klog_subsys,
        klog_msg=f"div-zero guard fired: {div_name} was 0",
        review_header=review_header,
    )


# Regex matching a kernel allocation assignment like:
#   auto* p = KMalloc(...);
#   Foo* f = static_cast<Foo*>(KMalloc(...));
#   void* mem = KMallocAligned(...);
# Captures the variable name so the synthesised guard can reference it.
_ALLOC_ASSIGN_RE = re.compile(
    r"^\s*(?:[A-Za-z_][\w:<>\s,]*?\*\s*|auto\s*\*?\s*)"
    r"(?P<var>[A-Za-z_]\w*)\s*=\s*[^;]*\b"
    r"(?:KMalloc|KMallocAligned|KCalloc|AllocateFrame|AllocateFrameNode|KZalloc)\s*\("
)


def synth_oom_nullcheck_patch(r: FixRecord, resolver: SymbolResolver | None,
                              repo_root: Path) -> str | None:
    """Generate a real applicable patch that inserts a nullcheck AFTER
    an allocation site whose primitive returned null (recorded by
    kheap.cpp / frame_allocator.cpp via FixJournalRecordAtCaller).

    The new FixJournalRecordAtCaller wiring means `caller_rip` is now
    the upstream `auto* p = KMalloc(...);` line — addr2line resolves
    to that statement and the synthesiser inserts:

      auto* p = KMalloc(...);
      #if 0
      if (p == nullptr) {
          KLOG_ONCE_WARN("subsys", "OOM nullcheck fired: p");
          return Err{OutOfMemory};
      }
      #endif

    Refuses to fire when:
      * Source line doesn't match the allocation-assignment shape.
      * Function return type isn't `Result<...>` (the only graceful
        return for an OOM is propagating ErrorCode::OutOfMemory).
      * A nullcheck already follows the allocation within 4 lines.
    """
    if resolver is None:
        return None
    if r.source_pin not in ("mm/kheap", "mm/frame-alloc"):
        return None

    sym = resolver.resolve(r.caller_rip)
    if not sym or sym.startswith("?? "):
        return None
    m = re.search(r"\(([^)]+):(\d+)\)|\bat\s+(\S+):(\d+)", sym)
    if not m:
        return None
    file_part = m.group(1) or m.group(3) or ""
    try:
        line_part = int(m.group(2) or m.group(4))
    except (TypeError, ValueError):
        return None
    if not file_part or line_part <= 0:
        return None

    path = _resolve_source_path(file_part, repo_root)
    if path is None or path.suffix not in _MARKER_SOURCE_SUFFIXES:
        return None
    raw = path.read_text(encoding="utf-8", errors="replace")
    lines = raw.splitlines(keepends=True)
    if line_part > len(lines):
        return None

    target = lines[line_part - 1]
    alloc = _ALLOC_ASSIGN_RE.match(target)
    if alloc is None:
        return None
    var = alloc.group("var")

    rt = _detect_return_type(lines, line_part - 1)
    if rt != "result":
        return None  # OOM nullcheck only safe in Result-returning fns

    # Idempotency: skip if the next 4 lines already check var for null.
    for j in range(line_part, min(line_part + 4, len(lines))):
        if re.search(rf"\b{re.escape(var)}\b\s*==\s*nullptr", lines[j]):
            return None
        if re.search(rf"!\s*{re.escape(var)}\b", lines[j]):
            return None

    indent = _leading_spaces(target)
    sp = " " * indent
    new_block = []
    new_block.append(target if target.endswith("\n") else target + "\n")
    new_block.append(f"{sp}// REVIEW: OOM nullcheck synthesised by fix-journal cycle.\n")
    new_block.append(
        f"{sp}// `{r.source_pin}` returned null at this call site (repeat={r.repeat}).\n"
    )
    new_block.append(f"{sp}// Flip the `#if 0` to `#if 1` to activate the check.\n")
    new_block.append(f"{sp}#if 0\n")
    new_block.append(f"{sp}if ({var} == nullptr)\n")
    new_block.append(f"{sp}{{\n")
    new_block.append(
        f'{sp}    KLOG_ONCE_WARN("{_escape_cpp_string(r.source_pin)}", '
        f'"OOM nullcheck fired: {var} == nullptr");\n'
    )
    new_block.append(
        f"{sp}    return ::duetos::core::Err{{::duetos::core::ErrorCode::OutOfMemory}};\n"
    )
    new_block.append(f"{sp}}}\n")
    new_block.append(f"{sp}#endif\n")

    file_rel = path.relative_to(repo_root).as_posix()
    # Replace the allocation line with [original + nullcheck block].
    return _hunk_replace_with_block(file_rel, lines, line_part - 1, new_block)


def synth_user_fault_brief(r: FixRecord, resolver: SymbolResolver | None = None) -> Action:
    """Generate a brief for a ring-3 UserFault record.

    The caller_rip is a USER address; addr2line against the kernel
    ELF won't resolve it. The brief captures the vector / error code
    / CR2 decoding (same as TrapCapture) AND emits triage paths a
    reviewer can take:

    1. If the same task is firing repeatedly: the EXE is wild-jumping
       on every spawn — investigate the binary itself or the PE
       loader's relocation pass for the EXE.
    2. If many distinct RIPs from one task: the EXE is heap-corrupting
       a function-pointer table — investigate the heap allocator path
       the EXE uses.
    3. If many distinct tasks at the same RIP: a shared DLL is wrong
       — investigate the DLL's exports / thunks_table.inc entries.

    Patch generation here is deliberately conservative — generating
    code in response to a userland crash would mean either changing
    a USER binary (out of repo scope) or quirking the loader (a
    semantic change requiring per-EXE analysis). Brief only.
    """
    vector = int((r.ctx_a >> 32) & 0xff)
    error_code = int(r.ctx_a & 0xffffffff)
    cr2 = r.ctx_b
    vec_name = TRAP_VECTOR_NAMES.get(vector, f"vector={vector}")

    out: list[str] = []
    repeat_label = "first observation" if r.repeat <= 1 else f"{r.repeat} crashes since boot"
    out.append(f"**Ring-3 `{vec_name}` at user RIP `0x{r.caller_rip:016x}`** — {repeat_label}.")
    out.append("")
    out.append(
        "The kernel killed the offending ring-3 task (a .dmp was "
        "egressed via debugcon and persisted to the NVMe crash-dump "
        "reserved region — open it in WinDbg / VS Code for the full "
        "GPR + stack frame). This record persists the *fact of the "
        "crash* into the journal so a chronically-broken PE/ELF "
        "binary is visible across boots."
    )
    out.append("")

    if vector == 14:
        short, longd = decode_pf_error_code(error_code)
        out.append(f"CR2: `0x{cr2:016x}`")
        out.append(f"Error code: `0x{error_code:x}` ({short} — {longd})")
    elif error_code != 0:
        out.append(f"Error code: `0x{error_code:x}`")
    out.append("")

    out.append("**Triage paths:**")
    out.append("")
    out.append(
        "1. *Same task firing repeatedly.* The EXE is wild-jumping on "
        "every spawn — wider context in `dmesg` ('task : '/'pid :' "
        "fields next to each fault). Often a broken PE relocation, a "
        "missing import that resolved to a wild address, or a CRT "
        "init path that ran on a half-initialized heap."
    )
    out.append(
        "2. *Many distinct user RIPs from one task.* The EXE is "
        "heap-corrupting a function-pointer table — the most common "
        "shape is a vtable smash from a `delete[]` on a malloc'd "
        "buffer (or vice versa). Cross-reference with leak-detector "
        "records."
    )
    out.append(
        "3. *Many distinct tasks at the same user RIP.* A shared DLL "
        "is wrong — the same call site in `kernel32` / `ntdll` / a "
        "vendored DLL fails in every consumer. Likely a missing or "
        "mis-implemented thunk; cross-reference UnmappedThunk "
        "records in this journal."
    )
    out.append("")

    # Pattern hints — if CR2 looks like a known wild-pointer
    # sentinel, name it.
    if vector == 14:
        if cr2 == 0xFFFFFFFFFFFFFFFF or cr2 == 0xFFFFFFFF00000000:
            out.append(
                "**CR2 sentinel**: `0x{cr2:x}` is a wild `(u32)-1` "
                "zero-extended — the EXE dereferenced a `(unsigned)-1` "
                "that the caller didn't recognise as a 'no result' "
                "sentinel.".format(cr2=cr2)
            )
            out.append("")
        elif cr2 == 0xCCCCCCCCCCCCCCCC or cr2 == 0xDEADBEEFDEADBEEF:
            out.append(
                f"**CR2 sentinel**: `0x{cr2:x}` is a recognisable "
                "uninitialized-memory poison value. The EXE read a "
                "field that nothing wrote — investigate the heap "
                "allocator path the EXE uses or a missing init in "
                "the constructor."
            )
            out.append("")

    out.append("---")
    out.append("Journal record:")
    out.append("```")
    out.append(f"seq         = {r.seq}")
    out.append(f"repeat      = {r.repeat}")
    out.append(f"caller_rip  = 0x{r.caller_rip:016x}  (USER RIP — kernel ELF won't resolve)")
    out.append(f"ctx_a       = 0x{r.ctx_a:016x}  (vector<<32 | error_code)")
    out.append(f"ctx_b       = 0x{r.ctx_b:016x}  (CR2 for #PF; 0 otherwise)")
    out.append(f"source_pin  = {r.source_pin!r}")
    out.append(f"hint        = {r.hint!r}")
    out.append("```")

    title = f"User-fault `{vec_name}` (×{r.repeat}){_new_tag(r)}"
    return Action(kind="note", title=title, body="\n".join(out), filename=None)


# Repeat-count threshold above which a KASSERT brief proposes
# converting the assertion to a graceful return — at this rate the
# invariant is clearly not holding in practice and the right fix is
# usually to handle the case explicitly rather than panic.
DEFAULT_KASSERT_DEMOTE_THRESHOLD = 3


def synth_kassert_brief(r: FixRecord, resolver: SymbolResolver | None = None,
                        repo_root: Path | None = None,
                        demote_threshold: int = DEFAULT_KASSERT_DEMOTE_THRESHOLD) -> Action:
    """Generate a brief for a KassertFail record (a fired KASSERT or
    explicit core::Panic call).

    The caller_rip is the KASSERT statement (or the Panic call site).
    addr2line typically resolves it to the exact line. The brief
    captures the source context around the assert AND — for a
    recurring assert (repeat >= demote_threshold) — proposes a
    *defensive* conversion shape: replace the KASSERT with a graceful
    return + a KLOG_ONCE_WARN. A recurring assert is by definition
    an invariant the upstream caller violates; panicking on it
    converts a recoverable miss into a halt.

    Per Decision #016 the proposed shape is REVIEW-framed text in
    the brief — the reviewer reads, decides whether the invariant
    can legitimately be relaxed, and applies the demotion (or fixes
    the upstream caller) by hand.
    """
    out: list[str] = []
    repeat_label = "first observation" if r.repeat <= 1 else f"{r.repeat} fires since boot"
    out.append(f"**KASSERT / Panic** in subsystem `{r.source_pin}` — {repeat_label}.")
    out.append("")
    out.append(f"Message: `{r.hint}`")
    if r.ctx_b != 0:
        out.append(f"Captured value (PanicWithValue ctx_b): `0x{r.ctx_b:x}` ({r.ctx_b})")
    out.append("")

    # Resolve caller_rip → file:line.
    file_part = ""
    line_part = 0
    if resolver is not None:
        sym = resolver.resolve(r.caller_rip)
        if sym and not sym.startswith("?? "):
            out.append(f"Assert site: `{sym}`")
            m = re.search(r"\(([^)]+):(\d+)\)|\bat\s+(\S+):(\d+)", sym)
            if m:
                file_part = m.group(1) or m.group(3) or ""
                try:
                    line_part = int(m.group(2) or m.group(4))
                except (TypeError, ValueError):
                    line_part = 0

    # Source context window — same shape as TrapCapture.
    resolved_source: Path | None = None
    if file_part and line_part > 0 and repo_root is not None:
        resolved_source = _resolve_source_path(file_part, repo_root)
        if resolved_source is not None:
            ctx = read_source_context(resolved_source, line_part, window=8)
            if ctx:
                rel = (
                    resolved_source.relative_to(repo_root)
                    if resolved_source.is_relative_to(repo_root)
                    else resolved_source
                )
                out.append("")
                out.append(f"**Source context** (`{rel}:{line_part}`):")
                out.append("")
                out.append("```cpp")
                out.extend(ctx)
                out.append("```")
                out.append("")

    # Proposed conversion shape for recurring asserts.
    if r.repeat >= demote_threshold:
        # Extract the faulting line text for substitution.
        sub = ""
        if resolved_source is not None and line_part > 0:
            try:
                src = resolved_source.read_text(encoding="utf-8", errors="replace").splitlines()
                if 0 < line_part <= len(src):
                    sub = src[line_part - 1].strip()
            except OSError:
                pass

        out.append(
            f"**Recurring assert ({r.repeat}× since boot)** — the "
            f"invariant is clearly not holding in practice. Proposed "
            f"defensive conversion:"
        )
        out.append("")
        out.append("```cpp")
        out.append("// REVIEW: KASSERT is firing repeatedly; consider:")
        out.append("//")
        out.append(f"//   Before:  {sub or '<the KASSERT statement>'}")
        out.append("//   After:   if (!(cond)) {")
        out.append(
            f"//                KLOG_ONCE_WARN(\"{_escape_cpp_string(r.source_pin)}\", "
            f"\"demoted assert: {_escape_cpp_string(r.hint[:50])}\");"
        )
        out.append("//                /* graceful return / propagate an error code */")
        out.append("//                return ::duetos::core::Err{::duetos::core::ErrorCode::InvalidState};")
        out.append("//            }")
        out.append("```")
        out.append("")
        out.append(
            "**REVIEW**: Demoting a KASSERT removes a kernel "
            "invariant check — the call site that violates the "
            "invariant may be relying on the panic to surface the "
            "bug. Confirm the assert is genuinely too strict (the "
            "case it catches is a *legitimate* condition the caller "
            "can recover from) BEFORE demoting. The alternative — "
            "fix the upstream caller so the invariant holds — is "
            "almost always the right answer."
        )
        out.append("")

    out.append("---")
    out.append("Journal record:")
    out.append("```")
    out.append(f"seq         = {r.seq}")
    out.append(f"repeat      = {r.repeat}")
    out.append(f"caller_rip  = 0x{r.caller_rip:016x}  (Panic call site)")
    out.append(f"ctx_a       = 0x{r.ctx_a:016x}  (= caller_rip)")
    out.append(f"ctx_b       = 0x{r.ctx_b:016x}  (PanicWithValue value; 0 for plain Panic)")
    out.append(f"source_pin  = {r.source_pin!r}  (subsystem)")
    out.append(f"hint        = {r.hint!r}  (assertion message)")
    out.append("```")

    title = f"KASSERT [{r.source_pin}] (×{r.repeat}){_new_tag(r)} — `{r.hint[:60]}`"
    return Action(kind="note", title=title, body="\n".join(out), filename=None)


# Regex that locates a KASSERT / KASSERT_WITH_VALUE call. Captures
# (full_call_text, condition, subsys, msg). The condition can span
# commas inside (e.g. `foo(a, b) == 0`); we rely on the fact that
# every KASSERT line ends with `, "subsys", "msg")` so we anchor on
# the closing quoted args.
_KASSERT_RE = re.compile(
    r'\b(KASSERT(?:_WITH_VALUE)?)\s*\((.*?),\s*"([^"]*)"\s*,\s*"([^"]*)"'
    r'(?:\s*,\s*([^)]+))?\)\s*;?'
)


def synth_kassert_demote_patch(r: FixRecord, resolver: SymbolResolver | None,
                               repo_root: Path) -> str | None:
    """Generate a unified diff that demotes a high-repeat KASSERT to a
    KLOG_ONCE_WARN + graceful return.

    This is the only place in the fix-journal pipeline that mutates
    *kernel semantics* — every other auto-patch is additive
    observability. The demotion is gated on:
      * repeat_count >= the demote threshold (default 3; the user
        asked for the threshold to be visible so it's --kassert-demote
        on the CLI),
      * the source line at caller_rip resolves to a single recognisable
        KASSERT or KASSERT_WITH_VALUE call (we don't try to demote
        macros nested inside ?:, function calls, etc.),
      * the surrounding function returns a Result<T, E> or a similar
        result-style type — we conservatively detect this by checking
        that the enclosing function signature contains "Result<"
        ANYWHERE on the line introducing the function. When we can't
        confirm a Result return type the patch is suppressed (the
        graceful-return shape needs a typed Err{...}; a void-return
        function would need a different shape we don't try to guess).

    The generated patch is wrapped in `// REVIEW:` comments AND the
    actual demotion is gated behind `#if 0 ... #endif` so applying
    the patch DOES NOT change behaviour until a reviewer also flips
    the `#if 0` to `#if 1`. That's a deliberate brake: a mechanical
    KASSERT demotion that silently shipped into the kernel would
    convert an audible bug into a silent one.
    """
    if resolver is None:
        return None

    sym = resolver.resolve(r.caller_rip)
    if not sym or sym.startswith("?? "):
        return None
    m = re.search(r"\(([^)]+):(\d+)\)|\bat\s+(\S+):(\d+)", sym)
    if not m:
        return None
    file_part = m.group(1) or m.group(3) or ""
    try:
        line_part = int(m.group(2) or m.group(4))
    except (TypeError, ValueError):
        return None
    if not file_part or line_part <= 0:
        return None

    path = _resolve_source_path(file_part, repo_root)
    if path is None or not path.exists():
        return None
    if path.suffix not in _MARKER_SOURCE_SUFFIXES:
        return None

    raw = path.read_text(encoding="utf-8", errors="replace")
    lines = raw.splitlines(keepends=True)
    if line_part > len(lines):
        return None

    target_line = lines[line_part - 1]
    km = _KASSERT_RE.search(target_line)
    if km is None:
        # Try one line earlier — clang-format may have wrapped the
        # KASSERT across two lines, in which case addr2line gives the
        # statement's leading line.
        if line_part >= 2:
            target_line = lines[line_part - 2] + lines[line_part - 1]
            km = _KASSERT_RE.search(target_line)
            if km is None:
                return None
            line_part -= 1
            target_line = lines[line_part - 1]
        else:
            return None

    macro = km.group(1)
    condition = km.group(2).strip()
    subsys = km.group(3)
    msg = km.group(4)
    value_arg = (km.group(5) or "").strip() if macro == "KASSERT_WITH_VALUE" else ""

    # Conservative Result-return check: scan back up to 80 lines for a
    # function-header line containing `Result<` BEFORE the next
    # outer `}` at column 0. If we don't see one, suppress.
    returns_result = False
    for j in range(line_part - 1, max(line_part - 80, -1), -1):
        ln = lines[j]
        # A function definition header is a non-indented line ending in `{`
        # (after stripping `// ...` comments).
        stripped = re.sub(r"//.*$", "", ln).rstrip()
        if "Result<" in ln:
            returns_result = True
            break
        if stripped.endswith("}") and j != line_part - 1 and _leading_spaces(ln) == 0:
            # Walked past the enclosing function without seeing
            # Result<. Stop.
            break
    if not returns_result:
        return None

    # Idempotency: if the source line ALREADY contains a sibling
    # `KLOG_ONCE_WARN` for this subsys+msg, skip.
    window_start = max(0, line_part - 5)
    window_end = min(len(lines), line_part + 5)
    for j in range(window_start, window_end):
        if "KLOG_ONCE_WARN" in lines[j] and subsys in lines[j]:
            return None

    indent = _leading_spaces(target_line)
    if indent == 0:
        return None

    # Build the demotion block. We wrap it in `#if 0` so applying the
    # patch is safe — the reviewer must affirmatively flip the gate
    # to take the new behaviour.
    sp = " " * indent
    err_code = "InvalidState"
    new_block = []
    new_block.append(f"{sp}// REVIEW: KASSERT demoted by fix-journal cycle (recurring assert,\n")
    new_block.append(f"{sp}// repeat={r.repeat}). Flip the `#if 0` below to `#if 1` to\n")
    new_block.append(f"{sp}// activate the demotion; leave it at `#if 0` to revert to the\n")
    new_block.append(f"{sp}// original panicking behaviour. Verify the caller can recover\n")
    new_block.append(f"{sp}// from a `{err_code}` error before activating.\n")
    new_block.append(f"{sp}#if 0\n")
    new_block.append(f"{sp}if (!({condition}))\n")
    new_block.append(f"{sp}{{\n")
    new_block.append(
        f'{sp}    KLOG_ONCE_WARN("{_escape_cpp_string(subsys)}", '
        f'"demoted KASSERT: {_escape_cpp_string(msg)}");\n'
    )
    new_block.append(
        f"{sp}    return ::duetos::core::Err{{::duetos::core::ErrorCode::{err_code}}};\n"
    )
    new_block.append(f"{sp}}}\n")
    new_block.append(f"{sp}#else\n")
    # Reproduce the original line verbatim so the diff is balanced.
    new_block.append(target_line if target_line.endswith("\n") else target_line + "\n")
    new_block.append(f"{sp}#endif\n")

    file_rel = path.relative_to(repo_root).as_posix()
    return _hunk_replace_with_block(file_rel, lines, line_part - 1, new_block)


def synth_cap_denial_brief(r: FixRecord, resolver: SymbolResolver | None = None) -> Action:
    """Generate a brief for a CapDenial record (cap-audit ring mirror).

    Source pin shape is `cap.<MissingCapName>` (the kernel records
    `CapName(event.missing)` after the `cap.` prefix). ctx_a carries
    the syscall number that tripped the gate; ctx_b carries the proc
    id of the caller. Repeat is the number of times THIS (cap,
    syscall) pair was denied since the journal interned the row.

    Cap denials are inherently policy questions — a brief is the
    right artefact, not a patch. There are three legitimate fixes
    the reviewer might land:

      1. The caller is a sandboxed binary correctly being denied
         (e.g. a Win32 PE asking for kCapFsWrite without grant). No
         source change needed; the deny is the contract working.
      2. The caller is a kernel helper that should hold the cap but
         doesn't (proc spawn / boot RBAC dropped it). Fix the grant
         at the spawn site or in `RbacInit`.
      3. The cap surface itself is too coarse for the syscall —
         split the cap or add a finer gate in the syscall handler.

    The brief lays out which of the three this looks like, given
    the repeat shape, and leaves the choice to the reviewer.
    """
    priority, priority_note = _priority_tier(r.repeat, kind_label="cap denial")
    cap_name = ""
    if r.source_pin.startswith("cap."):
        cap_name = r.source_pin[len("cap."):]

    lines: list[str] = []
    lines.append(f"**Priority: {priority}** — {priority_note}")
    lines.append("")
    lines.append(
        f"Capability `{cap_name or '(unknown)'}` was missing for "
        f"syscall `0x{r.ctx_a:x}` issued by proc `{r.ctx_b}`. "
        f"`{r.repeat}` denial(s) since boot for this (cap, syscall) pair."
    )
    lines.append("")
    lines.append("**Choose the fix shape:**")
    lines.append("")
    lines.append(
        "1. *Deny is correct.* The caller is sandboxed / untrusted "
        "and lacks the cap by design. No source change — `dfix "
        "mark-done` the record and move on. A recurring high-repeat "
        "denial here is a signal the workload itself is misbehaving."
    )
    lines.append(
        "2. *Grant is missing.* The caller is a kernel-spawned "
        f"process that should hold `{cap_name or 'this cap'}` but "
        f"doesn't. Inspect the spawn site (typically "
        f"`kernel/proc/spawn.cpp` or `kernel/core/main.cpp`) and add "
        f"the cap to the profile, OR extend the RBAC role at "
        f"`kernel/security/rbac.cpp:RbacInit` to grant it."
    )
    lines.append(
        f"3. *Cap is too coarse.* `{cap_name or 'This cap'}` covers "
        f"more than this caller needs. Split into a finer gate at "
        f"the syscall handler (`kernel/syscall/cap_gate.cpp` + the "
        f"`Cap` enum in `kernel/proc/process.h`). ABI work — only "
        f"warranted if a third-party binary needs the partial "
        f"grant and won't accept the coarse one."
    )

    if r.repeat >= 100:
        lines.append("")
        lines.append(
            f"**Deny storm ({r.repeat}× since boot)** — the caller "
            f"is retrying. Cross-reference `kernel/security/cap_audit.cpp` "
            f"`CapAuditCopyRecentDenials` for the per-call sequence + "
            f"tick to localise the loop."
        )

    # Caller RIP — useful when the denial came from a kernel-helper
    # spawn site (option 2) so the reviewer sees which thread.
    if resolver is not None:
        sym = resolver.resolve(r.caller_rip)
        if sym and not sym.startswith("?? "):
            lines.append("")
            lines.append(f"Recorder site: `{sym}` (rip=`0x{r.caller_rip:016x}`)")

    lines.append("")
    lines.append("---")
    lines.append("Journal record:")
    lines.append("```")
    lines.append(f"seq         = {r.seq}")
    lines.append(f"repeat      = {r.repeat}")
    lines.append(f"caller_rip  = 0x{r.caller_rip:016x}")
    lines.append(f"ctx_a       = 0x{r.ctx_a:016x}  (syscall number)")
    lines.append(f"ctx_b       = 0x{r.ctx_b:016x}  (proc_id)")
    lines.append(f"source_pin  = {r.source_pin!r}")
    lines.append(f"hint        = {r.hint!r}")
    lines.append("```")

    title = f"Cap denial [{priority}]{_new_tag(r)} `{cap_name or r.source_pin}` (×{r.repeat})"
    return Action(kind="note", title=title, body="\n".join(lines), filename=None)


def synth_marker_hit_brief(r: FixRecord, resolver: SymbolResolver | None = None) -> Action:
    """Generate a tier-aware brief for a StubMarker / GapMarker hit.

    Both detectors record:
      - source_pin: the file:line ("kernel/foo.cpp:42") OR an
        auto-derived `func+0xOFF` if the recorder didn't supply
        one (auto-derivation is KASLR-stable via the embedded
        symbol table — see fix_journal.h:121).
      - hint: the `// STUB:` / `// GAP:` comment text.
      - caller_rip: where in the kernel the marker fired.
      - repeat: how many times this site was reached.

    Tiering: a STUB hit once is "this code is reachable, look at
    it"; a STUB hit 100× is "this is a hot path masquerading as
    incomplete." Same scale as SoftFaultRecov / LoaderReject.

    Two extra bits of polish vs the prior generic note:
      - resolver-driven addr2line lookup so an auto-derived
        `func+0xOFF` pin gets a `(file.cpp:line)` tail when a
        kernel ELF is supplied;
      - GapMarker upgrade hint when repeat is high — a marker
        flagged "happy path works, edge unimpl" but firing
        repeatedly is probably actually a STUB.
    """
    is_stub = r.detector_name == "stub"
    label = "STUB" if is_stub else "GAP"
    priority, priority_note = _priority_tier(r.repeat, kind_label=f"{label} marker hit")

    lines: list[str] = []
    lines.append(f"**Priority: {priority}** — {priority_note}")
    lines.append("")

    sym = resolver.resolve(r.caller_rip) if resolver is not None else ""
    if sym and not sym.startswith("?? "):
        lines.append(f"Source pin: `{r.source_pin}`")
        lines.append(f"Resolved:   `{sym}` (rip=`0x{r.caller_rip:016x}`)")
    else:
        lines.append(f"Source pin: `{r.source_pin}` (rip=`0x{r.caller_rip:016x}`)")
    lines.append("")
    lines.append(f"`// {label}:` marker reached at runtime — repeat_count = **{r.repeat}**.")
    lines.append("")
    if is_stub:
        lines.append(
            "**Recommended next step:** open the source pin and replace "
            "the STUB body with the documented behaviour. The presence of "
            "the marker here means the runtime did NOT do the right thing "
            "even on the v0 happy path — every caller along this trail "
            "saw incorrect behaviour."
        )
    else:
        lines.append(
            "**Recommended next step:** open the source pin and decide "
            "whether the gap is still acceptable. GAPs are 'happy path "
            "works, edge case missing' — the runtime hit IS the happy "
            "path, so the marker is doing its job. The fix is to "
            "implement the documented edge case OR to remove the "
            "marker once the gap is no longer relevant."
        )
        if r.repeat >= 10:
            lines.append("")
            lines.append(
                f"**Heads-up: repeat={r.repeat} is high for a GAP.** A "
                f"GAP that fires this often probably isn't a 'happy "
                f"path works' marker — it's a STUB in disguise. "
                f"Consider converting `// GAP:` → `// STUB:` so the "
                f"surface inventory accurately reflects 'broken on "
                f"the hot path' rather than 'documented edge case.'"
            )

    lines.append("")
    lines.append(f"Marker text: {r.hint!r}")

    lines.append("")
    lines.append("---")
    lines.append("Journal record:")
    lines.append("```")
    lines.append(f"seq         = {r.seq}")
    lines.append(f"repeat      = {r.repeat}")
    lines.append(f"caller_rip  = 0x{r.caller_rip:016x}")
    lines.append(f"source_pin  = {r.source_pin!r}")
    lines.append(f"hint        = {r.hint!r}")
    lines.append("```")

    title = f"{label} marker [{priority}]{_new_tag(r)} at `{r.source_pin}` (×{r.repeat})"
    return Action(kind="note", title=title, body="\n".join(lines), filename=None)


def synth_soft_fault_recov_brief(r: FixRecord, resolver: SymbolResolver | None = None) -> Action:
    """Generate a structured markdown brief for a SoftFaultRecov record.

    SoftFaultRecov has two production producers (kernel/diag/fix_journal.h
    documents both):

      1. `source_pin == "trap.recov"` — the trap-context extable-fixup
         path in `kernel/arch/x86_64/traps.cpp`. `caller_rip` holds the
         faulting RIP (the kernel-mode #PF / #GP that was caught);
         `ctx_a` holds the same RIP (deferred-record path stores it
         in both slots). `ctx_b` is unused. The reviewer's lever is
         `addr2line` on `caller_rip` against the kernel ELF.

      2. `source_pin` shaped like a subsystem id (e.g. `drivers/usb/xhci`,
         `kernel/health`, `diag/soft-lockup`) — the fault-react
         dispatcher's RetryNow / RestartDomain branches. `ctx_a` holds
         the FaultKind (decoded via FAULT_KIND_NAMES); `ctx_b` holds
         either the attempt_count (RetryNow) or the FaultDomainId
         (RestartDomain). `hint` discriminates which branch fired:
         "fault-react: caller-retry advised; ..." vs
         "fault-react: domain restarted; ...".

    The brief is a `kind="note"` Action — SoftFaultRecov never has a
    safe mechanical patch (the right fix is always domain-specific
    and human-judged), so the output is advisory by design. Decision
    #016 forbids the kernel from auto-applying anything anyway.
    """
    priority, priority_note = _soft_fault_priority(r.repeat)
    is_trap = r.source_pin.strip() == "trap.recov"
    is_retry = r.hint.startswith("fault-react: caller-retry")
    is_restart = r.hint.startswith("fault-react: domain restarted")
    is_kill = r.hint.startswith("fault-react: process killed")

    lines: list[str] = []
    lines.append(f"**Priority: {priority}** — {priority_note}")
    lines.append("")
    lines.append(f"Recovery has fired **{r.repeat}** time(s) since boot at this site.")
    lines.append("")

    if is_trap:
        lines.append("### Source: extable trap-recovery path")
        lines.append("")
        lines.append(
            "A kernel-mode #PF or #GP at the faulting RIP below was caught "
            "by an extable row, the fixup ran, and execution resumed. The "
            "kernel image at boot installed a safe-touch helper (e.g. the "
            "user-copy fault fixup) that knew how to recover."
        )
        lines.append("")
        # If the resolver populated a symbol for this RIP, surface it
        # inline so the reviewer doesn't have to round-trip through
        # symbolize.sh. The resolver returns whatever addr2line printed
        # (e.g. `CopyFromUser at kernel/mm/copy_user.cpp:142`); a
        # `?? at ??:0` answer is filtered out as no-info.
        fault_sym = resolver.resolve(r.caller_rip) if resolver is not None else ""
        fixup_sym = resolver.resolve(r.ctx_a) if resolver is not None else ""
        if fault_sym and not fault_sym.startswith("?? "):
            lines.append(f"- Faulting RIP: `0x{r.caller_rip:016x}` — {fault_sym}")
        else:
            lines.append(f"- Faulting RIP: `0x{r.caller_rip:016x}`")
        if fixup_sym and not fixup_sym.startswith("?? "):
            lines.append(f"- Fixup RIP:    `0x{r.ctx_a:016x}` — {fixup_sym} (jumped to)")
        else:
            lines.append(f"- Fixup RIP:    `0x{r.ctx_a:016x}` (jumped to)")
        lines.append("")
        lines.append("**Recommended next step:**")
        lines.append("")
        if fault_sym and not fault_sym.startswith("?? "):
            lines.append(
                f"1. Inspect the touch site at `{fault_sym}`. If the "
                f"touch is on user memory, verify the caller validated "
                f"the pointer first. If the touch is on kernel memory, "
                f"the fault probably indicates a stale mapping or a "
                f"torn allocation — fix the producer, do not rely on "
                f"the extable to keep absorbing it."
            )
        else:
            lines.append(
                "1. Resolve the faulting RIP to a source line:\n"
                "   ```sh\n"
                f"   tools/debug/symbolize.sh build/x86_64-debug/kernel/duetos-kernel.elf 0x{r.caller_rip:x}\n"
                "   ```\n"
                "2. Inspect the touch site. If the touch is on user memory, "
                "verify the caller validated the pointer first. If the touch "
                "is on kernel memory, the fault probably indicates a stale "
                "mapping or a torn allocation — fix the producer, do not "
                "rely on the extable to keep absorbing it."
            )
        if r.repeat >= 10:
            lines.append(
                "**Hot path** — at this repeat_count the fixup is no "
                "longer an exception path; consider replacing the raw "
                "touch with a `Try*` variant that returns "
                "`Result<T, FaultKind>` instead of relying on extable "
                "rescue."
            )
    elif is_retry:
        kind_name = FAULT_KIND_NAMES.get(r.ctx_a, f"fault-kind#{r.ctx_a}")
        followup = FAULT_KIND_FOLLOWUP.get(kind_name, "")
        lines.append("### Source: fault-react `RetryNow` branch")
        lines.append("")
        lines.append(
            f"The fault-react dispatcher told the caller in `{r.source_pin}` "
            f"to retry a `{kind_name}` (Class D / transient hardware). The "
            f"caller's previous attempt count was **{r.ctx_b}** before the "
            f"recovery."
        )
        lines.append("")
        lines.append(f"- Subsystem source: `{r.source_pin}`")
        lines.append(f"- FaultKind:        `{kind_name}` (ctx_a=0x{r.ctx_a:x})")
        lines.append(f"- Attempt count:    `{r.ctx_b}`")
        lines.append(f"- Severity:         `{r.severity}`")
        if followup:
            lines.append("")
            lines.append("**Recommended next step:** " + followup)
        if r.ctx_b >= 3:
            lines.append("")
            lines.append(
                "**Heads-up:** attempt_count ≥ 3 means the caller has "
                "burned multiple retries before recovery. Consider "
                "wrapping the call in `RetryWithBackoff` "
                "(`kernel/diag/recovery.h`) so the budget is bounded "
                "and the policy is one-line auditable."
            )
    elif is_restart:
        kind_name = FAULT_KIND_NAMES.get(r.ctx_a, f"fault-kind#{r.ctx_a}")
        followup = FAULT_KIND_FOLLOWUP.get(kind_name, "")
        lines.append("### Source: fault-react `RestartDomain` branch")
        lines.append("")
        lines.append(
            f"The fault-react dispatcher restarted fault-domain "
            f"**id={r.ctx_b}** in response to a `{kind_name}` reported "
            f"by `{r.source_pin}`. The domain marker fired; the "
            f"watchdog will pick the restart up on its next tick."
        )
        lines.append("")
        lines.append(f"- Subsystem source: `{r.source_pin}`")
        lines.append(f"- FaultKind:        `{kind_name}` (ctx_a=0x{r.ctx_a:x})")
        lines.append(f"- FaultDomainId:    `{r.ctx_b}`")
        lines.append(f"- Severity:         `{r.severity}`")
        if followup:
            lines.append("")
            lines.append("**Recommended next step:** " + followup)
        if r.repeat >= 5:
            lines.append("")
            lines.append(
                "**Restart loop suspected** — five-plus restarts of the "
                "same domain in one boot means the restart isn't fixing "
                "the underlying state. Either the fault is non-transient "
                "(promote the Class B reaction to Halt for this kind), "
                "or the domain's re-init path isn't actually clearing "
                "the failing condition (audit the per-domain "
                "`SubsystemRestart` callback)."
            )
    elif is_kill:
        kind_name = FAULT_KIND_NAMES.get(r.ctx_a, f"fault-kind#{r.ctx_a}")
        followup = FAULT_KIND_FOLLOWUP.get(kind_name, "")
        lines.append("### Source: fault-react `KillProcess` branch")
        lines.append("")
        lines.append(
            f"The fault-react dispatcher signalled the offending task "
            f"(pid={r.ctx_b}) for termination after a `{kind_name}` "
            f"reported by `{r.source_pin}`. This is the Class-C "
            f"recovery path — the kernel kept running, the user "
            f"task got killed."
        )
        lines.append("")
        lines.append(f"- Subsystem source: `{r.source_pin}`")
        lines.append(f"- FaultKind:        `{kind_name}` (ctx_a=0x{r.ctx_a:x})")
        lines.append(f"- Victim pid:       `{r.ctx_b}`")
        lines.append(f"- Severity:         `{r.severity}`")
        if followup:
            lines.append("")
            lines.append("**Recommended next step:** " + followup)
        if r.repeat >= 5:
            lines.append("")
            lines.append(
                "**Kill loop suspected** — five-plus same-pin kills in "
                "one boot suggests a service supervisor (init, a "
                "watchdog, a respawning daemon) is restarting the "
                "offending task and it's hitting the same fault each "
                "cycle. Investigate the producer of the user-mode "
                "fault: the kernel's reject is correct; the fix is "
                "in userland or at the syscall-arg validation seam."
            )
    else:
        lines.append("### Source: unrecognised SoftFaultRecov producer")
        lines.append("")
        lines.append(
            f"Pin `{r.source_pin}` doesn't match either documented "
            f"producer (`trap.recov` extable path or fault-react "
            f"dispatcher pin). Either a new producer was added without "
            f"updating this template, or the record is from an older "
            f"kernel. Hint: `{r.hint or '(none)'}`."
        )

    lines.append("")
    lines.append("---")
    lines.append("Journal record:")
    lines.append("```")
    lines.append(f"seq         = {r.seq}")
    lines.append(f"repeat      = {r.repeat}")
    lines.append(f"ts_ns       = {r.ts_ns}")
    lines.append(f"caller_rip  = 0x{r.caller_rip:016x}")
    lines.append(f"ctx_a       = 0x{r.ctx_a:016x}")
    lines.append(f"ctx_b       = 0x{r.ctx_b:016x}")
    lines.append(f"source_pin  = {r.source_pin!r}")
    lines.append(f"hint        = {r.hint!r}")
    lines.append(f"severity    = {r.severity}")
    lines.append("```")

    title = f"Soft-fault recovery [{priority}]{_new_tag(r)} at `{r.source_pin}` (×{r.repeat})"
    return Action(kind="note", title=title, body="\n".join(lines), filename=None)


# ------------------------------------------------- fault-react probe patch

_FAULT_REACT_CPP = "kernel/diag/fault_react.cpp"
_PROBES_H = "kernel/debug/probes.h"
_PROBES_CPP = "kernel/debug/probes.cpp"
_FR_PROBE_ID = "kFaultReactRecover"
_FR_PROBE_NAME = "diag.fault_react_recover"
_PROBES_INCLUDE = '#include "debug/probes.h"\n'
_FR_RECORD_ANCHOR = "::duetos::diag::FixJournalRecordSev("


def _insert_include_sorted(file_rel: str, lines: list[str], include_line: str) -> str:
    """Insert `include_line` into the quoted-include block in sorted
    position. `.clang-format` sets `SortIncludes: false`, so this is
    cosmetic-only — but a sorted insert keeps the emitted patch
    reviewable. Returns "" if the include is already present.
    """
    want = re.search(r'"([^"]+)"', include_line)
    if want is None:
        return ""
    want_path = want.group(1)
    inc_idx: list[int] = []
    for i, ln in enumerate(lines):
        m = re.match(r'^#include\s+"([^"]+)"', ln)
        if m is None:
            continue
        if m.group(1) == want_path:
            return ""  # already included
        inc_idx.append(i)
    if not inc_idx:
        return ""
    # Pick the include whose path sorts after ours within the LAST
    # contiguous quoted-include run (the project groups the file's
    # own header first, then a blank, then the dependency block).
    run: list[int] = [inc_idx[-1]]
    for i in reversed(inc_idx[:-1]):
        if run[-1] - i == 1:
            run.append(i)
        else:
            break
    run.sort()
    insert_at = run[-1] + 1
    for i in run:
        m = re.match(r'^#include\s+"([^"]+)"', lines[i])
        if m and m.group(1) > want_path:
            insert_at = i
            break
    return _hunk_insert_lines(file_rel, lines, insert_at, [include_line])


def synth_fault_react_probe_patch(repo_root: Path) -> str | None:
    """Emit a candidate patch that hardens the fault-react recovery
    dispatch so a *detected runtime fault* (the RetryNow /
    RestartDomain / KillProcess branches in `fault_react.cpp`) is
    GDB-breakable and leaves a `[probe]` line.

    This is the mechanically-sound shape of "emit modified code in
    response to a detected runtime fault" under Design-Decision #016:
    the patch is **additive observability only** — it never changes
    control flow, never swallows a fault, never guesses semantics,
    and is applied by a human / CI, never by the running kernel. It
    is exactly the discipline CLAUDE.md "Diagnostic Logging — Keep
    It, Gate It, Probe It" prescribes for a recurring fault path.

    Three coordinated files (all anchored on stable existing text so
    the patch compiles by construction):

      * probes.h   — new `ProbeId::kFaultReactRecover` before kCount
      * probes.cpp — matching `kProbeTable` row before the closing
                      brace (keeps the size `static_assert` balanced)
      * fault_react.cpp — `#include "debug/probes.h"` + a
                      `KBP_PROBE_V(...)` next to each of the three
                      `FixJournalRecordSev` recovery records

    Idempotent: returns None if the probe already exists (so
    re-running after apply is a no-op), or if any anchor is missing
    (fall back to the advisory brief — never emit a patch we cannot
    place correctly).
    """
    h_path = repo_root / _PROBES_H
    c_path = repo_root / _PROBES_CPP
    fr_path = repo_root / _FAULT_REACT_CPP
    if not (h_path.exists() and c_path.exists() and fr_path.exists()):
        return None

    h_lines = h_path.read_text(encoding="utf-8").splitlines(keepends=True)
    c_lines = c_path.read_text(encoding="utf-8").splitlines(keepends=True)
    fr_lines = fr_path.read_text(encoding="utf-8").splitlines(keepends=True)

    # Idempotency: already wired anywhere → nothing to do.
    if any(_FR_PROBE_ID in ln for ln in h_lines):
        return None

    # --- probes.h: insert the enum member just before `kCount`.
    kcount_idx = None
    for i, ln in enumerate(h_lines):
        if re.match(r"^\s*kCount\b", ln):
            kcount_idx = i
            break
    if kcount_idx is None:
        return None
    enum_inserts = [
        "    // Fault-react dispatcher took a recovery decision\n",
        "    // (RetryNow / RestartDomain / KillProcess) for a\n",
        "    // detected runtime fault. ArmedLog so a clean boot is\n",
        "    // silent and an attached GDB can `b\n",
        "    // duetos::debug::ProbeFire` to halt the instant a fault\n",
        "    // recovery fires; the packed value carries the FaultKind.\n",
        f"    {_FR_PROBE_ID},\n",
        "\n",
    ]
    h_hunk = _hunk_insert_lines(_PROBES_H, h_lines, kcount_idx, enum_inserts)

    # --- probes.cpp: insert the row before the `};` that closes
    # kProbeTable (the line right before the size static_assert).
    sa_idx = None
    for i, ln in enumerate(c_lines):
        if "static_assert(sizeof(kProbeTable)" in ln:
            sa_idx = i
            break
    if sa_idx is None:
        return None
    brace_idx = None
    for i in range(sa_idx - 1, -1, -1):
        if c_lines[i].strip() == "};":
            brace_idx = i
            break
        if c_lines[i].strip():
            break  # only a blank line may sit between `};` and the assert
    if brace_idx is None:
        return None
    row = (
        f'    {{ProbeId::{_FR_PROBE_ID}, "{_FR_PROBE_NAME}", '
        f"ProbeArm::ArmedLog}},\n"
    )
    c_hunk = _hunk_insert_lines(_PROBES_CPP, c_lines, brace_idx, [row])

    # --- fault_react.cpp: include + a probe next to every record.
    inc_hunk = _insert_include_sorted(_FAULT_REACT_CPP, fr_lines, _PROBES_INCLUDE)
    record_idx = [
        i for i, ln in enumerate(fr_lines) if _FR_RECORD_ANCHOR in ln
    ]
    if not record_idx:
        return None
    # If a KBP_PROBE already sits next to a record, treat the file as
    # hand-wired and bail rather than double-instrument.
    for i in record_idx:
        window = "".join(fr_lines[max(0, i - 3):i])
        if "KBP_PROBE" in window:
            return None
    probe_stmt = (
        f"        KBP_PROBE_V(::duetos::debug::ProbeId::{_FR_PROBE_ID}, "
        f"ev.kind);\n"
    )
    # Hunks for the same file must be emitted in ascending original-
    # line order; the include sits near the top, records far below.
    fr_hunks = inc_hunk
    for i in record_idx:
        fr_hunks += _hunk_insert_lines(_FAULT_REACT_CPP, fr_lines, i, [probe_stmt])

    return h_hunk + c_hunk + fr_hunks


# ---------------------------------------------------------------- per-record action


@dataclass
class Action:
    kind: str  # "patch" | "note"
    title: str
    body: str  # diff text or markdown explanation
    filename: str | None  # for "patch" kind, the .patch filename


def plan_actions(records: list[FixRecord], thunks_index: dict, repo_root: Path,
                 resolver: SymbolResolver | None = None,
                 marker_log_threshold: int = DEFAULT_MARKER_LOG_THRESHOLD,
                 enable_syscall_stub: bool = True,
                 enable_marker_log: bool = True,
                 elf_path: Path | None = None,
                 kassert_demote_threshold: int = DEFAULT_KASSERT_DEMOTE_THRESHOLD,
                 enable_kassert_demote: bool = False,
                 enable_trap_guards: bool = False,
                 enable_oom_nullcheck: bool = False) -> list[Action]:
    actions: list[Action] = []
    seen: set[tuple[str, str]] = set()
    fault_react_probe_done = False
    for r in records:
        key = (r.detector_name, r.source_pin)
        if key in seen:
            continue
        seen.add(key)
        if r.audited:
            continue  # reviewer already triaged
        if is_selftest_record(r.source_pin):
            continue  # synthetic FixJournalSelfTest noise — never a real gap

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
            # Try the additive observability patch first so the brief
            # can reflect whether it's coming.
            stub_diff = None
            if enable_syscall_stub:
                stub_diff = synth_unknown_syscall_stub_patch(r, num, repo_root)
            actions.append(
                Action(
                    kind="note",
                    title=f"Implement syscall #0x{num:x}{_new_tag(r)}",
                    body=synth_syscall_brief(r, num, stub_patch_planned=stub_diff is not None),
                    filename=None,
                )
            )
            # Additive observability patch: per-syscall stub arm so the
            # next boot's record kind flips from `UnknownSyscall` (the
            # catch-all) to `StubMarker:syscall:0xNN` (this acknowledged
            # arm). Same -ENOSYS return; the reviewer flips the body to
            # real semantics later. Skipped if disabled or if the
            # synthesiser couldn't locate the catch-all default arm.
            if stub_diff:
                actions.append(
                    Action(
                        kind="patch",
                        title=(
                            f"Add stub arm for syscall 0x{num:x}"
                            f" (acknowledged; returns -ENOSYS){_new_tag(r)}"
                        ),
                        body=stub_diff,
                        filename=f"syscall-stub-0x{num:x}.patch",
                    )
                )

        elif r.detector_name in ("stub", "gap"):
            actions.append(synth_marker_hit_brief(r, resolver))
            # Additive observability patch: for a hot marker (>=N hits)
            # add a `KLOG_ONCE_WARN` line next to the existing
            # `FIX_NOTE_*` so the gap is visible at serial level on the
            # NEXT boot, without operators needing to dfix-poll. Skipped
            # if disabled, if repeat is below the threshold, or if the
            # synthesiser couldn't resolve the pin / find the macro
            # call / detected an existing KLOG_ONCE_*.
            if enable_marker_log and r.repeat >= marker_log_threshold:
                log_diff = synth_marker_log_upgrade_patch(r, repo_root)
                if log_diff:
                    safe_pin = re.sub(r"[^A-Za-z0-9_.-]+", "-", r.source_pin)
                    actions.append(
                        Action(
                            kind="patch",
                            title=(
                                f"Add KLOG_ONCE_WARN next to hot "
                                f"{r.detector_name} at `{r.source_pin}` "
                                f"(×{r.repeat}){_new_tag(r)}"
                            ),
                            body=log_diff,
                            filename=f"marker-log-{safe_pin}.patch",
                        )
                    )
        elif r.detector_name == "soft_fault_recov":
            actions.append(synth_soft_fault_recov_brief(r, resolver))
            # A fault-react recovery record IS a detected runtime
            # fault (RetryNow / RestartDomain / KillProcess). Emit
            # the GDB-probe hardening patch once per run so the next
            # occurrence of *any* fault-react decision is breakable
            # and WARN-logged. The brief above stays — the patch is
            # observability scaffolding, not the root-cause fix.
            if not fault_react_probe_done and r.hint.startswith("fault-react:"):
                fault_react_probe_done = True
                diff = synth_fault_react_probe_patch(repo_root)
                if diff:
                    actions.append(
                        Action(
                            kind="patch",
                            title=(
                                "Harden fault-react recovery dispatch with a "
                                "GDB probe (additive; #016-safe)"
                            ),
                            body=diff,
                            filename="fault-react-recover-probe.patch",
                        )
                    )
            # OOM nullcheck patch — only for OOM-shaped soft_fault
            # records (kheap / frame-allocator), gated by
            # --enable-oom-nullcheck. The new
            # FixJournalRecordAtCaller wiring on kheap.cpp /
            # frame_allocator.cpp captures the UPSTREAM allocation
            # site as caller_rip, so addr2line resolves to the
            # `auto* p = KMalloc(...)` line the synthesiser keys
            # off. Gated `#if 0` so applying is a no-op.
            if enable_oom_nullcheck and r.source_pin in ("mm/kheap", "mm/frame-alloc"):
                oom_diff = synth_oom_nullcheck_patch(r, resolver, repo_root)
                if oom_diff:
                    safe = re.sub(r"[^A-Za-z0-9_.-]+", "-", r.source_pin)
                    actions.append(
                        Action(
                            kind="patch",
                            title=(
                                f"Insert OOM nullcheck after `{r.source_pin}` "
                                f"allocation site (×{r.repeat}; gated "
                                f"`#if 0`){_new_tag(r)}"
                            ),
                            body=oom_diff,
                            filename=f"oom-nullcheck-{safe}.patch",
                        )
                    )
        elif r.detector_name == "loader_reject":
            actions.append(synth_loader_reject_brief(r, resolver))
        elif r.detector_name == "cap_denial":
            actions.append(synth_cap_denial_brief(r, resolver))
        elif r.detector_name == "trap_capture":
            actions.append(synth_trap_capture_brief(r, resolver, elf_path, repo_root))
            # Real applicable patches gated behind --enable-trap-guards.
            # Each one wraps the change in `#if 0 ... #endif` so applying
            # is a no-op until the reviewer flips the gate.
            if enable_trap_guards:
                null_diff = synth_trap_null_deref_patch(r, resolver, repo_root)
                if null_diff:
                    safe = re.sub(r"[^A-Za-z0-9_.-]+", "-", r.source_pin)
                    actions.append(
                        Action(
                            kind="patch",
                            title=(
                                f"Insert null-deref guard at `{r.source_pin}` "
                                f"(×{r.repeat}; gated `#if 0`){_new_tag(r)}"
                            ),
                            body=null_diff,
                            filename=f"trap-null-guard-{safe}.patch",
                        )
                    )
                div_diff = synth_trap_div_zero_patch(r, resolver, repo_root)
                if div_diff:
                    safe = re.sub(r"[^A-Za-z0-9_.-]+", "-", r.source_pin)
                    actions.append(
                        Action(
                            kind="patch",
                            title=(
                                f"Insert divide-zero guard at `{r.source_pin}` "
                                f"(×{r.repeat}; gated `#if 0`){_new_tag(r)}"
                            ),
                            body=div_diff,
                            filename=f"trap-divzero-guard-{safe}.patch",
                        )
                    )
        elif r.detector_name == "user_fault":
            actions.append(synth_user_fault_brief(r, resolver))
        elif r.detector_name == "kassert_fail":
            actions.append(synth_kassert_brief(r, resolver, repo_root,
                                               demote_threshold=kassert_demote_threshold))
            # Optional, opt-in: emit an actual demote patch (KASSERT
            # -> if-guard + KLOG_ONCE_WARN + Err{...}, gated behind
            # `#if 0` so applying the patch is safe and the
            # reviewer affirmatively flips the gate). Only fires
            # for recurring asserts AND only when a Result-return
            # signature is detected nearby.
            if enable_kassert_demote and r.repeat >= kassert_demote_threshold:
                demote_diff = synth_kassert_demote_patch(r, resolver, repo_root)
                if demote_diff:
                    safe_subsys = re.sub(r"[^A-Za-z0-9_.-]+", "-", r.source_pin)
                    actions.append(
                        Action(
                            kind="patch",
                            title=(
                                f"Demote recurring KASSERT in `{r.source_pin}` "
                                f"to graceful return (×{r.repeat}; "
                                f"gated behind `#if 0`){_new_tag(r)}"
                            ),
                            body=demote_diff,
                            filename=f"kassert-demote-{safe_subsys}.patch",
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
    ap.add_argument(
        "--kernel-elf",
        type=Path,
        default=None,
        help=(
            "kernel ELF (preferably the debug build) used to resolve "
            "caller_rip / ctx_a addresses to `function (file:line)` for "
            "trap.recov records. Optional — if omitted, the briefs print "
            "raw hex and a symbolize.sh hint."
        ),
    )
    ap.add_argument(
        "--marker-log-threshold",
        type=int,
        default=DEFAULT_MARKER_LOG_THRESHOLD,
        help=(
            f"min repeat_count for the marker-log-upgrade patch "
            f"(KLOG_ONCE_WARN next to a FIX_NOTE_*) to fire on a "
            f"hot stub/gap marker. Default: {DEFAULT_MARKER_LOG_THRESHOLD}. "
            f"Lower to surface less-hot gaps; raise to keep the patch "
            f"set focused on the noisiest."
        ),
    )
    ap.add_argument(
        "--no-syscall-stub",
        action="store_true",
        help=(
            "disable per-syscall stub-arm generation for unknown-syscall "
            "records. Brief is still emitted. Use when a smoke profile "
            "is exercising a known-experimental syscall range and the "
            "extra arms would mask the ABI work in progress."
        ),
    )
    ap.add_argument(
        "--no-marker-log",
        action="store_true",
        help=(
            "disable the KLOG_ONCE_WARN auto-upgrade patches for hot "
            "stub/gap markers. Brief is still emitted. Use to keep "
            "the patch set minimal for a docs-only or refactor-only "
            "review cycle."
        ),
    )
    ap.add_argument(
        "--enable-kassert-demote",
        action="store_true",
        help=(
            "OPT-IN: also emit `kassert-demote-<subsys>.patch` files "
            "for recurring KassertFail records. The generated patch "
            "converts a `KASSERT(cond, ...)` into a defensive `if "
            "(!(cond)) { KLOG_ONCE_WARN(...); return Err{...}; }` "
            "block, gated behind `#if 0` so applying the patch does "
            "NOT change behaviour until the reviewer also flips the "
            "`#if 0` to `#if 1`. Off by default because KASSERT "
            "demotion is a semantic change (a kernel invariant check "
            "becomes a soft error), and even with the `#if 0` brake "
            "it warrants explicit opt-in."
        ),
    )
    ap.add_argument(
        "--kassert-demote-threshold",
        type=int,
        default=DEFAULT_KASSERT_DEMOTE_THRESHOLD,
        help=(
            f"min repeat_count for the KASSERT demote patch + brief "
            f"proposal to fire. Default: {DEFAULT_KASSERT_DEMOTE_THRESHOLD}. "
            f"The brief always renders the recurring-assert proposal "
            f"text at this threshold; the actual code patch additionally "
            f"requires --enable-kassert-demote."
        ),
    )
    ap.add_argument(
        "--enable-trap-guards",
        action="store_true",
        help=(
            "OPT-IN: also emit `trap-null-guard-*.patch` and "
            "`trap-divzero-guard-*.patch` files for TrapCapture records "
            "whose source line matches a recognisable pointer-deref / "
            "division pattern. Each generated patch wraps a guard "
            "(`if (ptr == nullptr) { ... }` or `if (divisor == 0) { ... }`) "
            "behind `#if 0 ... #endif` so applying the patch is "
            "behaviourally a no-op until the reviewer flips the gate. "
            "Off by default because the guard inserted may not match "
            "the surrounding control-flow's expectations (a legitimate "
            "null deref under a debug assert, a divisor that's a "
            "compile-time constant, etc.)."
        ),
    )
    ap.add_argument(
        "--enable-oom-nullcheck",
        action="store_true",
        help=(
            "OPT-IN: also emit `oom-nullcheck-*.patch` files for "
            "soft_fault_recov records with mm/kheap or mm/frame-alloc "
            "source pins. The synthesiser uses the upstream caller_rip "
            "(captured by FixJournalRecordAtCaller from inside the "
            "primitive's OOM path) to locate the `auto* p = KMalloc(...)` "
            "site and inserts an `if (p == nullptr) { return Err{OutOfMemory}; }` "
            "block behind `#if 0` immediately after the assignment. "
            "Only fires when the enclosing function is Result-returning."
        ),
    )
    ap.add_argument(
        "--enable-all-patches",
        action="store_true",
        help=(
            "shortcut: equivalent to passing every --enable-* flag "
            "(--enable-kassert-demote --enable-trap-guards "
            "--enable-oom-nullcheck). Use when running the full "
            "automation cycle: run OS -> journal records -> "
            "gen-fix-patches with everything on -> review the .patch "
            "files -> apply + flip the per-patch `#if 0` brake."
        ),
    )
    args = ap.parse_args()
    if args.enable_all_patches:
        args.enable_kassert_demote = True
        args.enable_trap_guards = True
        args.enable_oom_nullcheck = True

    repo_root = find_repo_root()
    thunks_index = load_thunks_table(repo_root)
    print(
        f"# loaded {len(thunks_index)} thunks_table.inc entries from {repo_root}",
        file=sys.stderr,
    )

    # Treat args.files[0] as the CURRENT boot and any subsequent
    # files as prior-boot rotation baselines (KERNEL.F0..F3 by
    # convention). Each current-boot record is classified NEW if no
    # prior file carries a record with the same (detector,
    # source_pin) key, else RESEEN. Single-file invocations skip
    # the classification — every record stays is_new=True, which
    # matches the framing "this is the first cycle, everything is
    # new from the reviewer's POV."
    current_records: list[FixRecord] = []
    baseline_keys: set[tuple[str, str]] = set()
    for idx, path in enumerate(args.files):
        try:
            recs = read_records(path)
        except (FileNotFoundError, ValueError) as exc:
            print(f"# skip {path}: {exc}", file=sys.stderr)
            continue
        if idx == 0:
            current_records.extend(recs)
        else:
            for r in recs:
                baseline_keys.add((r.detector_name, r.source_pin))
    if baseline_keys:
        new_count = 0
        for r in current_records:
            if (r.detector_name, r.source_pin) in baseline_keys:
                r.is_new = False
            else:
                new_count += 1
        print(
            f"# baseline: {len(baseline_keys)} (detector, pin) keys from prior boots; "
            f"NEW this boot: {new_count}/{len(current_records)}",
            file=sys.stderr,
        )
    all_records = current_records
    if not all_records and not args.markers:
        print("# no readable fix-journal files", file=sys.stderr)
        return 1

    resolver = SymbolResolver(elf_path=args.kernel_elf)
    if args.kernel_elf is not None:
        # Prime once with every kernel-RIP any record references —
        # one batched addr2line call covers the whole batch instead
        # of N forks. SoftFaultRecov records carry both `caller_rip`
        # AND `ctx_a` (which holds the faulting RIP for trap.recov);
        # every other detector contributes just `caller_rip`. The
        # resolver itself filters out non-kernel addresses up front.
        rips: list[int] = []
        for r in all_records:
            rips.append(r.caller_rip)
            if r.detector_name == "soft_fault_recov":
                rips.append(r.ctx_a)
        resolver.prime(rips)

    actions = plan_actions(
        all_records,
        thunks_index,
        repo_root,
        resolver,
        marker_log_threshold=args.marker_log_threshold,
        enable_syscall_stub=not args.no_syscall_stub,
        enable_marker_log=not args.no_marker_log,
        elf_path=args.kernel_elf,
        kassert_demote_threshold=args.kassert_demote_threshold,
        enable_kassert_demote=args.enable_kassert_demote,
        enable_trap_guards=args.enable_trap_guards,
        enable_oom_nullcheck=args.enable_oom_nullcheck,
    )
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
