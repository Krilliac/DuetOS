#!/usr/bin/env python3
# gen-fix-trend.py — cross-boot trend analyser for the fix journal.
#
# WHY THIS EXISTS:
#   gen-fix-report.py shows you what's wrong RIGHT NOW. gen-fix-patches.py
#   tells you what mechanical fix to apply. Neither tells you whether
#   your last change *helped*: did the gap you tried to fix actually
#   stop firing? Did fixing one gap unblock other gaps that now hit?
#   Did a code change introduce a regression that's recording into a
#   new pin?
#
#   This tool answers those questions by reading every KERNEL.F[0-3]
#   rotation sibling that the in-kernel persistence layer leaves
#   behind, ordering them by their newest record's ts_ns, and
#   classifying each unique (detector, source_pin) tuple:
#
#     NEW         — in the latest journal, absent from every older one.
#                   The most recent code change either added the
#                   instrumentation or broke a code path that's now
#                   firing.
#     RESOLVED    — present in at least one older journal, absent from
#                   the latest. The most recent code change either
#                   removed the instrumentation or fixed the underlying
#                   path so it no longer fires.
#     PERSISTENT  — present in the latest AND at least one older. With
#                   a repeat-count trajectory (growing / stable /
#                   decreasing) so the reviewer can prioritise.
#     REGRESSION  — present in an older journal, gone in a middle one,
#                   back in the latest. Indicates a flaky condition.
#
# USAGE:
#   tools/build/gen-fix-trend.py KERNEL.F3 KERNEL.F2 KERNEL.F1 KERNEL.F0 KERNEL.FIX
#
#   Order is OLDEST → NEWEST (matches how the kernel's RotateChain
#   ages files: KERNEL.FIX is always the current boot's snapshot;
#   KERNEL.F0 is the most recent prior boot; KERNEL.F3 is the oldest).
#
# OUTPUT: markdown to stdout. Exit code 0 always (this is observational
# — the kernel never auto-applies, the host tool never gates CI).
#
# The on-disk record format is the same as gen-fix-report.py /
# gen-fix-patches.py read — see kernel/diag/fix_journal.h.

import argparse
import struct
import sys
from dataclasses import dataclass

HEADER_FMT = struct.Struct("<IIII")
RECORD_FMT = struct.Struct("<IIQQQQIHBB40s40s")
FILE_MAGIC = 0x4A584946  # 'FIXJ' little-endian
FILE_VERSION = 1
RECORD_MAGIC = 0x52584946  # 'FIXR' little-endian — must match kernel/diag/fix_journal.h
RECORD_STRIDE = 128
MAX_RECORDS = 1024

DETECTOR_NAMES = {
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


@dataclass
class Record:
    detector: int
    detector_name: str
    source_pin: str
    repeat: int
    seq: int
    ts_ns: int
    caller_rip: int


@dataclass
class Boot:
    path: str
    records: list[Record]
    newest_ts: int  # max ts_ns across records; 0 for empty journals


def read_boot(path: str) -> Boot | None:
    """Parse one FIXJ file. Returns None on any structural problem."""
    try:
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError as exc:
        print(f"# skip {path}: {exc}", file=sys.stderr)
        return None
    if len(data) < HEADER_FMT.size:
        print(f"# skip {path}: too short ({len(data)} bytes)", file=sys.stderr)
        return None
    magic, version, count, reserved = HEADER_FMT.unpack(data[: HEADER_FMT.size])
    if magic != FILE_MAGIC or version != FILE_VERSION or reserved != 0:
        print(f"# skip {path}: bad header", file=sys.stderr)
        return None
    if count > MAX_RECORDS:
        print(f"# skip {path}: implausible record count {count}", file=sys.stderr)
        return None
    expected = HEADER_FMT.size + count * RECORD_STRIDE
    if len(data) != expected:
        print(f"# skip {path}: size {len(data)} != expected {expected}", file=sys.stderr)
        return None

    records: list[Record] = []
    cursor = HEADER_FMT.size
    newest = 0
    for _ in range(count):
        chunk = data[cursor : cursor + RECORD_STRIDE]
        cursor += RECORD_STRIDE
        fields = RECORD_FMT.unpack(chunk)
        if fields[0] != RECORD_MAGIC:
            continue  # torn row from a panic-context write
        pin = fields[10].rstrip(b"\x00").decode("latin-1")
        det = fields[8]
        records.append(
            Record(
                detector=det,
                detector_name=DETECTOR_NAMES.get(det, f"det{det}"),
                source_pin=pin,
                repeat=fields[6],
                seq=fields[1],
                ts_ns=fields[2],
                caller_rip=fields[3],
            )
        )
        if fields[2] > newest:
            newest = fields[2]
    return Boot(path=path, records=records, newest_ts=newest)


def is_selftest_pin(pin: str) -> bool:
    """Mirror gen-fix-report.py's selftest filter — synthetic records
    from FixJournalSelfTest() should not pollute trend analysis.
    Kept in sync with gen-fix-report.py:_is_selftest_record."""
    import re
    p = pin.strip()
    return (
        p == "selftest"
        or bool(re.match(r"selftest[/!.#:\s]", p))
        or "FixJournalSelfTest" in p
        or "FaultReactSelfTest" in p
    )


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Cross-boot trend analyser for the DuetOS fix journal."
    )
    ap.add_argument("files", nargs="+", help="FIXJ files in OLDEST → NEWEST order")
    ap.add_argument(
        "--include-selftest",
        action="store_true",
        help="Don't filter out FixJournalSelfTest synthetic records",
    )
    args = ap.parse_args()

    boots: list[Boot] = []
    for p in args.files:
        b = read_boot(p)
        if b is None:
            continue
        if not args.include_selftest:
            b.records = [r for r in b.records if not is_selftest_pin(r.source_pin)]
        boots.append(b)

    if not boots:
        print("# no parseable journals; nothing to trend")
        return 0

    # Order by newest_ts so passing files out-of-order still works.
    # Within ties (empty journals all have ts=0), preserve input order.
    boots.sort(key=lambda b: (b.newest_ts, args.files.index(b.path)))
    current = boots[-1]
    priors = boots[:-1]

    def key_of(r: Record) -> tuple[int, str]:
        return (r.detector, r.source_pin)

    current_map: dict[tuple[int, str], Record] = {key_of(r): r for r in current.records}
    prior_maps: list[dict[tuple[int, str], Record]] = [
        {key_of(r): r for r in b.records} for b in priors
    ]

    new_keys: list[tuple[int, str]] = []
    persistent_keys: list[tuple[int, str]] = []
    resolved_keys: list[tuple[int, str]] = []
    regression_keys: list[tuple[int, str]] = []

    # Current → classify as NEW / PERSISTENT / REGRESSION.
    for k in current_map:
        present_in_any_prior = any(k in m for m in prior_maps)
        if not present_in_any_prior:
            new_keys.append(k)
            continue
        # PERSISTENT if also in the immediately-previous boot.
        prev_has = bool(prior_maps) and k in prior_maps[-1]
        if prev_has:
            persistent_keys.append(k)
        else:
            # Was in an older boot, absent in the immediate prior,
            # back in current → REGRESSION (a flaky condition).
            regression_keys.append(k)

    # Prior unions → RESOLVED is in any prior, absent in current.
    seen_in_any_prior: set[tuple[int, str]] = set()
    for m in prior_maps:
        seen_in_any_prior |= set(m.keys())
    for k in seen_in_any_prior:
        if k not in current_map:
            resolved_keys.append(k)

    print(f"# DuetOS Fix Journal Trend Report")
    print()
    print(f"Cross-boot diff across {len(boots)} journal(s); current=`{current.path}` "
          f"(ts_ns={current.newest_ts}); priors (oldest first): "
          + ", ".join(f"`{b.path}`" for b in priors) + ".")
    print()
    print(f"- **NEW**         {len(new_keys)} gap(s) recorded for the first time this boot")
    print(f"- **PERSISTENT**  {len(persistent_keys)} gap(s) in both current and most-recent prior")
    print(f"- **REGRESSION**  {len(regression_keys)} gap(s) absent in the most-recent prior but back now")
    print(f"- **RESOLVED**    {len(resolved_keys)} gap(s) previously seen, not in current")
    print()

    def fmt_pin(k: tuple[int, str]) -> str:
        det_name = DETECTOR_NAMES.get(k[0], f"det{k[0]}")
        return f"`{det_name}:{k[1]}`"

    if new_keys:
        print("## NEW (regressions or freshly-instrumented sites)")
        print()
        print("| Detector + pin | Repeat |")
        print("|----------------|--------|")
        for k in sorted(new_keys):
            r = current_map[k]
            print(f"| {fmt_pin(k)} | {r.repeat} |")
        print()

    if regression_keys:
        print("## REGRESSION (gone in last boot, back this boot — flaky)")
        print()
        print("| Detector + pin | Repeat | Last seen |")
        print("|----------------|--------|-----------|")
        for k in sorted(regression_keys):
            r = current_map[k]
            # Find the most-recent prior boot where it appeared.
            last_seen_path = "<none>"
            for b in reversed(priors):
                if k in {key_of(rr) for rr in b.records}:
                    last_seen_path = b.path
                    break
            print(f"| {fmt_pin(k)} | {r.repeat} | `{last_seen_path}` |")
        print()

    if persistent_keys:
        print("## PERSISTENT (in current AND most-recent prior — high triage value)")
        print()
        print("| Detector + pin | Current repeat | Prior repeat | Trajectory |")
        print("|----------------|----------------|--------------|------------|")
        for k in sorted(persistent_keys, key=lambda kk: -current_map[kk].repeat):
            cur = current_map[k]
            prv = prior_maps[-1][k]
            if cur.repeat > prv.repeat:
                traj = f"+{cur.repeat - prv.repeat} (growing)"
            elif cur.repeat < prv.repeat:
                traj = f"{cur.repeat - prv.repeat} (decreasing)"
            else:
                traj = "stable"
            print(f"| {fmt_pin(k)} | {cur.repeat} | {prv.repeat} | {traj} |")
        print()

    if resolved_keys:
        print("## RESOLVED (was in a prior boot, gone in current)")
        print()
        print("If you applied a fix between boots, this is the cycle confirming the gap stopped firing.")
        print()
        print("| Detector + pin |")
        print("|----------------|")
        for k in sorted(resolved_keys):
            print(f"| {fmt_pin(k)} |")
        print()

    return 0


if __name__ == "__main__":
    sys.exit(main())
