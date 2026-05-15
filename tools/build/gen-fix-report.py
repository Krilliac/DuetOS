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
import json
import re
import struct
import sys
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

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


def _is_selftest_record(source_pin: str) -> bool:
    """True for the synthetic records `FixJournalSelfTest()` injects to
    validate the journal mechanism. They point at no real source
    (`selftest/stub.cpp:1`, `selftest!ThunkSelftest`, the auto-pinned
    `…FixJournalSelfTest()+0xNN`, …) so they are excluded from the
    report; the patch generator filters the same set. Keep this
    predicate in sync with `gen-fix-patches.py:is_selftest_record`.
    """
    p = source_pin.strip()
    return (
        p == "selftest"
        or bool(re.match(r"selftest[/!.#:\s]", p))
        or "FixJournalSelfTest" in p
        or "FaultReactSelfTest" in p
    )


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


def load_markers(path: Path) -> list[dict]:
    """Load a marker manifest produced by gen-fix-markers.py."""
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"# warn: couldn't read markers manifest {path}: {exc}", file=sys.stderr)
        return []


def render_marker_section(markers: list[dict], boots: list[tuple[str, int, list[FixRecord]]]) -> list[str]:
    """Cross-reference source markers against observed runtime records.

    A marker is "ever observed" if any record's source_pin starts with
    the marker's file path or contains the marker line — the recorder
    sites use file:line or file:Function naming so a substring check
    on file path is the most robust we can do without an explicit pin
    tagging convention.
    """
    if not markers:
        return []
    observed_pins = set()
    for _path, _ver, recs in boots:
        for r in recs:
            observed_pins.add(r.source_pin)

    out: list[str] = []
    out.append("## Marker Drift")
    out.append("")
    out.append(
        "Each row is a `// STUB:` / `// GAP:` comment in the source tree. "
        "`Observable` is true when the marker has a `FIX_NOTE_*` macro on a "
        "following line — i.e. the kernel can journal it at runtime. "
        "`Observed` is true when at least one fix-journal record's "
        "`source_pin` references the marker's file."
    )
    out.append("")
    out.append("| File:Line | Kind | Observable | Observed | Comment |")
    out.append("|-----------|------|-----------|----------|---------|")
    for m in sorted(markers, key=lambda r: (r["file"], r["line"])):
        # Heuristic match: any observed pin that contains the file
        # path. The recorder convention is "<file>:<func>" or
        # "<dir>/<file>:<func>", so a substring test on the trailing
        # filename catches the common cases without false positives
        # on bare function names.
        fname = Path(m["file"]).stem
        observed = any(fname in pin for pin in observed_pins)
        obs_flag = "✅" if m["has_macro"] else "—"
        seen_flag = "✅" if observed else "—"
        comment = m["comment"][:60] + ("…" if len(m["comment"]) > 60 else "")
        out.append(
            f"| `{m['file']}:{m['line']}` | {m['kind']} | {obs_flag} | {seen_flag} | {comment} |"
        )
    out.append("")

    total = len(markers)
    obs = sum(1 for m in markers if m["has_macro"])
    seen = sum(1 for m in markers if any(Path(m["file"]).stem in pin for pin in observed_pins))
    out.append(
        f"**Summary:** {total} markers in source — "
        f"{obs} observable ({total - obs} comment-only); "
        f"{seen} ever observed at runtime."
    )
    out.append("")
    return out


def render_markdown(
    boots: list[tuple[str, int, list[FixRecord]]],
    markers: list[dict] | None = None,
) -> str:
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
            if _is_selftest_record(r.source_pin):
                continue  # synthetic FixJournalSelfTest validation noise
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

    if markers:
        out.extend(render_marker_section(markers, boots))

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
        "is observe-only — no auto-apply, per Design-Decision #016.\n"
        "4. Cross-reference the **Marker Drift** table (when a manifest "
        "is supplied via `--markers`): rows with `Observable=—` need a "
        "`FIX_NOTE_*` macro added; rows with `Observable=✅` and "
        "`Observed=—` are cold paths or unreachable dead code worth "
        "investigating."
    )
    return "\n".join(out)


def load_baseline(path: Path) -> set[tuple[str, str]]:
    """Load a baseline file as a set of (detector, source_pin) tuples.

    Format is one record per line: `<detector>\\t<source_pin>`. Lines
    starting with `#` are comments. Missing baseline file is treated
    as empty (first run on a fresh tree).
    """
    if not path.exists():
        return set()
    out: set[tuple[str, str]] = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split("\t", 1)
        if len(parts) == 2:
            out.add((parts[0], parts[1]))
    return out


def save_baseline(path: Path, boots: list[tuple[str, int, list[FixRecord]]]) -> int:
    """Write a baseline file covering every (detector, source_pin)
    pair in any of the supplied boots. Returns the number of unique
    pairs written."""
    pairs: set[tuple[str, str]] = set()
    for _path, _ver, recs in boots:
        for r in recs:
            pairs.add((r.detector_name, r.source_pin))
    lines = [
        "# DuetOS fix-journal baseline — pairs already triaged at this commit.",
        "# Re-run gen-fix-report.py with --baseline=<this file> to see only NEW gaps.",
        "# Format: <detector>\\t<source_pin> per line.",
        "",
    ]
    for det, pin in sorted(pairs):
        lines.append(f"{det}\t{pin}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return len(pairs)


def filter_against_baseline(
    boots: list[tuple[str, int, list[FixRecord]]],
    baseline: set[tuple[str, str]],
) -> list[tuple[str, int, list[FixRecord]]]:
    """Drop records whose (detector, source_pin) is in baseline.

    Keeps the boot tuple shape so downstream rendering stays
    unchanged. A boot whose every record was filtered ends up with
    an empty record list — the rendered report still shows the boot
    in the header table so the reviewer sees it ran clean.
    """
    out: list[tuple[str, int, list[FixRecord]]] = []
    for path, ver, recs in boots:
        kept = [r for r in recs if (r.detector_name, r.source_pin) not in baseline]
        out.append((path, ver, kept))
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("files", nargs="+", help="KERNEL.FIX (and rotation siblings)")
    ap.add_argument(
        "--markers",
        type=Path,
        default=None,
        help="optional marker manifest (gen-fix-markers.py output) for cross-reference",
    )
    ap.add_argument(
        "--baseline",
        type=Path,
        default=None,
        help=(
            "baseline file of (detector, source_pin) pairs to filter out — only "
            "records NOT in the baseline appear in the report. Use to surface "
            "drift between runs."
        ),
    )
    ap.add_argument(
        "--save-baseline",
        type=Path,
        default=None,
        help=(
            "write a baseline file covering every record across the supplied "
            "files; suitable as a future --baseline argument."
        ),
    )
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

    if args.save_baseline:
        n = save_baseline(args.save_baseline, boots)
        print(f"# wrote baseline with {n} pairs to {args.save_baseline}", file=sys.stderr)

    if args.baseline:
        before = sum(len(r) for _p, _v, r in boots)
        baseline = load_baseline(args.baseline)
        boots = filter_against_baseline(boots, baseline)
        after = sum(len(r) for _p, _v, r in boots)
        print(
            f"# baseline {args.baseline}: {len(baseline)} pairs, filtered "
            f"{before - after}/{before} records",
            file=sys.stderr,
        )

    markers = load_markers(args.markers) if args.markers else []
    print(render_markdown(boots, markers))
    return 0


if __name__ == "__main__":
    sys.exit(main())
