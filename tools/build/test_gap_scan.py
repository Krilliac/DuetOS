"""Unit test for gap-scan.py (Phase C static gap discovery).

Asserts the scanner reports un-annotated gap-shaped sites and excludes
sites that already carry a // GAP: / // STUB: / FIX_NOTE_ annotation.

Run: python3 tools/build/test_gap_scan.py   (or via pytest)
"""

import json
import subprocess
import sys
import textwrap
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
SCANNER = REPO / "tools" / "build" / "gap-scan.py"


def run_scan(tmp: Path) -> list[dict]:
    out = tmp / "cand.json"
    subprocess.check_call([sys.executable, str(SCANNER), "--root", str(tmp), "--out", str(out)])
    return json.loads(out.read_text())


def test_reports_only_unannotated(tmp_path: Path) -> None:
    f = tmp_path / "k.cpp"
    f.write_text(
        textwrap.dedent(
            """\
            long annotated_gap()
            {
                // GAP: known, deliberately deferred
                return kStatusNotImplemented;
            }

            long bare_gap()
            {
                return kStatusNotImplemented;
            }

            long todo_site()
            {
                // TODO: wire this up
                return 0;
            }
            """
        )
    )
    cands = run_scan(tmp_path)
    funcs = {c["function"] for c in cands}
    kinds = {c["pattern_kind"] for c in cands}
    # bare_gap is un-annotated -> reported.
    assert "bare_gap" in funcs, f"bare_gap missing; got {funcs}"
    # annotated_gap has a // GAP: within the window -> excluded.
    assert "annotated_gap" not in funcs, f"annotated_gap should be excluded; got {funcs}"
    # the TODO site is reported as its own kind.
    assert "todo_fixme" in kinds, f"todo not detected; got {kinds}"


def test_empty_tree(tmp_path: Path) -> None:
    assert run_scan(tmp_path) == []


if __name__ == "__main__":
    import tempfile

    failures = 0
    for name, fn in list(globals().items()):
        if name.startswith("test_") and callable(fn):
            with tempfile.TemporaryDirectory() as d:
                try:
                    fn(Path(d))
                    print(f"PASS {name}")
                except AssertionError as e:
                    failures += 1
                    print(f"FAIL {name}: {e}")
    print("[gap-scan-test]", "PASS" if failures == 0 else f"FAIL ({failures})")
    sys.exit(1 if failures else 0)
