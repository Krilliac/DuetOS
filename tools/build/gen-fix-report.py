#!/usr/bin/env python3
"""
Read a KERNEL.FIX binary fix-journal file (or several) and print a
markdown report grouping records by detector and source pin so a
reviewer (typically a Claude session) can triage gaps without
attaching a live debugger.

Usage:
    tools/build/gen-fix-report.py KERNEL.FIX [KERNEL.F0 ...]

The on-disk format is documented in
`kernel/diag/fix_journal_persist.h`:

    [u32 magic 'FIXJ' = 0x4A584946]
    [u32 version = 1]
    [u32 record_count]
    [u32 reserved]
    [FixRecord * record_count]

Each FixRecord is 128 bytes; layout matches
`kernel/diag/fix_journal.h` exactly. We unpack with `struct` rather
than reinventing a parser so a layout change in the kernel surfaces
as a Python error rather than silently misaligning fields.
"""

from __future__ import annotations

import argparse
import struct
import sys
from collections import defaultdict
from dataclasses import dataclass

FILE_MAGIC = 0x4A584946  # 'FIXJ'
RECORD_MAGIC = 0x52584946  # 'FIXR'
RECORD_STRIDE = 128

# Detector names — match `FixDetectorName()` in fix_journal.cpp.
DETECTORS = {
    0: "none",
    1: "stub",
    2: "gap",
    3: "unknown_syscall",
    4: "unmapped_thunk",
    5: "soft_fault_recov",
    6: "loader_reject",
}

# struct.Struct format for the file header (16 bytes).
HEADER_FMT = struct.Struct("<IIII")

# struct.Struct format for a single FixRecord (128 bytes).
# Field order MUST match `struct FixRecord` in fix_journal.h:
#   u32 magic, u32 seq, u64 ts_ns, u64 caller_rip, u64 ctx_a,
#   u64 ctx_b, u32 repeat_count, u16 severity, u8 detector,
#   u8 flags, char source_pin[40], char hint[40].
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


def read_records(path: str) -> tuple[int, list[FixRecord]]:
    """Return (file_version, records) read from `path`."""
    with open(path, "rb") as fh:
        data = fh.read()
    if len(data) < HEADER_FMT.size:
        raise ValueError(f"{path}: file too short ({len(data)} bytes)")
    magic, version, count, _reserved = HEADER_FMT.unpack(data[: HEADER_FMT.size])
    if magic != FILE_MAGIC:
        raise ValueError(f"{path}: bad magic 0x{magic:08x} (expected FIXJ)")
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
        (
            rmagic,
            seq,
            ts_ns,
            caller_rip,
            ctx_a,
            ctx_b,
            repeat,
            severity,
            detector,
            flags,
            source_pin,
            hint,
        ) = RECORD_FMT.unpack(chunk)
        # Bad magic on a record == torn write or out-of-bounds
        # noise inside the reserved region (panic-context lock-free
        # snapshot can produce these). Skip rather than abort —
        # the rest of the file is still useful.
        if rmagic != RECORD_MAGIC:
            torn += 1
            cursor += RECORD_STRIDE
            continue
        records.append(
            FixRecord(
                seq=seq,
                ts_ns=ts_ns,
                caller_rip=caller_rip,
                ctx_a=ctx_a,
                ctx_b=ctx_b,
                repeat=repeat,
                severity=severity,
                detector=detector,
                flags=flags,
                source_pin=source_pin.split(b"\x00", 1)[0].decode("utf-8", "replace"),
                hint=hint.split(b"\x00", 1)[0].decode("utf-8", "replace"),
            )
        )
        cursor += RECORD_STRIDE
    if torn:
        print(f"# {path}: skipped {torn} torn record(s) (bad magic)", file=sys.stderr)
    return version, records


def render_markdown(boots: list[tuple[str, int, list[FixRecord]]]) -> str:
    """Render a single combined report covering one or more boots."""
    out: list[str] = []
    out.append("# DuetOS Fix Journal Report")
    out.append("")
    out.append(
        "Generated from KERNEL.FIX (and rotation siblings if multiple boots "
        "were passed). Each row is a unique (detector, source_pin) gap "
        "observed at runtime; the kernel never auto-applies fixes — humans "
        "or Claude sessions review and convert journal entries into real "
        "source patches."
    )
    out.append("")

    # Header table — one row per boot.
    out.append("## Boots")
    out.append("")
    out.append("| File | Version | Records | Audited |")
    out.append("|------|---------|---------|---------|")
    for path, version, recs in boots:
        audited = sum(1 for r in recs if r.audited)
        out.append(f"| `{path}` | {version} | {len(recs)} | {audited} |")
    out.append("")

    # Group by detector across all boots, dedup by source_pin (sum
    # repeat counts; mark audited if any boot audited the row).
    by_detector: dict[str, dict[str, dict]] = defaultdict(lambda: defaultdict(dict))
    for path, _ver, recs in boots:
        for r in recs:
            slot = by_detector[r.detector_name].setdefault(
                r.source_pin,
                {
                    "repeat": 0,
                    "boots": set(),
                    "hint": r.hint,
                    "audited": False,
                    "first_seq": r.seq,
                    "first_caller": r.caller_rip,
                },
            )
            slot["repeat"] += r.repeat
            slot["boots"].add(path)
            if r.hint and not slot["hint"]:
                slot["hint"] = r.hint
            if r.audited:
                slot["audited"] = True

    out.append("## Gaps by Detector")
    out.append("")
    for det in sorted(by_detector.keys()):
        rows = by_detector[det]
        if not rows:
            continue
        out.append(f"### `{det}` ({len(rows)} unique pins)")
        out.append("")
        out.append("| Source Pin | Repeat | Boots | Audited | First Caller | Hint |")
        out.append("|------------|--------|-------|---------|--------------|------|")
        for pin in sorted(
            rows.keys(), key=lambda k: (-rows[k]["repeat"], k)
        ):
            slot = rows[pin]
            audited = "yes" if slot["audited"] else "no"
            caller = f"0x{slot['first_caller']:016x}"
            hint = slot["hint"] or "(none)"
            out.append(
                f"| `{pin}` | {slot['repeat']} | {len(slot['boots'])} |"
                f" {audited} | `{caller}` | {hint} |"
            )
        out.append("")

    out.append("## Triage Workflow")
    out.append("")
    out.append(
        "1. Pick the highest-repeat row in each detector — it's the gap "
        "the running kernel hits most.\n"
        "2. Open the source pin (`path:line` or `dll!fn`) and decide if "
        "the right fix is to implement the missing path, route through an "
        "existing primitive, or accept the gap (then tell `dfix mark-done` "
        "to filter it out).\n"
        "3. Land the source fix as a normal commit; the runtime journal "
        "is observe-only — no auto-apply, per Design-Decision #016."
    )
    return "\n".join(out)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("files", nargs="+", help="KERNEL.FIX (and rotation siblings)")
    args = ap.parse_args()

    boots: list[tuple[str, int, list[FixRecord]]] = []
    for path in args.files:
        try:
            ver, recs = read_records(path)
        except (FileNotFoundError, ValueError) as exc:
            print(f"# skip {path}: {exc}", file=sys.stderr)
            continue
        boots.append((path, ver, recs))

    if not boots:
        print("# no readable fix-journal files", file=sys.stderr)
        return 1

    print(render_markdown(boots))
    return 0


if __name__ == "__main__":
    sys.exit(main())
