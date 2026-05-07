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
    markdown note explaining the entry is a placeholder and how to
    either upgrade to a real implementation or mark it accepted.

  * UnknownSyscall -> emit a unified diff that scaffolds an explicit
    case in syscall.cpp's main switch returning -ENOSYS, with a
    TODO marker for the reviewer to flesh out.

  * StubMarker / GapMarker / SoftFaultRecov / LoaderReject -> emit
    a markdown note pointing at the source pin.

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
import re
import struct
import subprocess
import sys
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

FILE_MAGIC = 0x4A584946  # 'FIXJ'
RECORD_MAGIC = 0x52584946  # 'FIXR'
RECORD_STRIDE = 128

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


def read_records(path: str) -> list[FixRecord]:
    """Parse a KERNEL.FIX file into a list of FixRecord."""
    with open(path, "rb") as fh:
        data = fh.read()
    if len(data) < HEADER_FMT.size:
        raise ValueError(f"{path}: file too short ({len(data)} bytes)")
    magic, _ver, count, _rsvd = HEADER_FMT.unpack(data[: HEADER_FMT.size])
    if magic != FILE_MAGIC:
        raise ValueError(f"{path}: bad magic 0x{magic:08x}")
    records: list[FixRecord] = []
    cursor = HEADER_FMT.size
    for _ in range(count):
        chunk = data[cursor : cursor + RECORD_STRIDE]
        fields = RECORD_FMT.unpack(chunk)
        rmagic = fields[0]
        cursor += RECORD_STRIDE
        if rmagic != RECORD_MAGIC:
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
    return records


# ---------------------------------------------------------------- thunks index

_THUNKS_TABLE_PATH = "kernel/subsystems/win32/thunks_table.inc"

# Generic noop offsets: an entry resolving to one of these is a
# placeholder, not a real implementation. Mirrors the runtime
# classifier in kernel/subsystems/win32/thunks.cpp.
_NOOP_OFFSETS = {"kOffReturnZero", "kOffReturnOne", "kOffCritSecNop", "kOffGetProcessHeap"}


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


_SYSCALL_PATH = "kernel/syscall/syscall.cpp"


def synth_syscall_patch(num: int, seq: int, repo_root: Path) -> str | None:
    """Generate a unified diff that adds an explicit case to the
    syscall switch returning -ENOSYS, with a TODO marker.

    Inserted just before the `default:` arm of the main dispatcher
    so the new case is reachable. Returns None if we can't find the
    insertion point.
    """
    path = repo_root / _SYSCALL_PATH
    if not path.exists():
        return None
    lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
    # Find the LAST `default:` line indented with 4 spaces — that's
    # the catch-all of the main syscall switch that fires
    # ReportUnknownSyscall + records UnknownSyscall.
    insert_at = None
    for i in range(len(lines) - 1, -1, -1):
        if lines[i].rstrip("\n") == "    default:":
            insert_at = i
            break
    if insert_at is None:
        return None

    new_block = (
        f"    case 0x{num:x}: // STUB: scaffolded from fix journal seq={seq} — implement\n"
        f"    {{\n"
        f"        // TODO: implement syscall #0x{num:x}. The fix journal observed at\n"
        f"        //       least one caller hit this number. Returning -ENOSYS keeps\n"
        f"        //       the call observable in the journal as a STUB hit until a\n"
        f"        //       real implementation lands.\n"
        f"        FIX_NOTE_STUB(syscall_unimpl_0x{num:x});\n"
        f"        frame->rax = static_cast<u64>(-38); // -ENOSYS\n"
        f"        return;\n"
        f"    }}\n\n"
    )

    ctx_start = max(0, insert_at - 3)
    ctx_lines = lines[ctx_start:insert_at]
    after_lines = lines[insert_at : insert_at + 3]
    new_block_lines = new_block.splitlines(keepends=True)

    old_count = len(ctx_lines) + len(after_lines)
    new_count = old_count + len(new_block_lines)

    diff_lines: list[str] = []
    diff_lines.append(f"--- a/{_SYSCALL_PATH}\n")
    diff_lines.append(f"+++ b/{_SYSCALL_PATH}\n")
    diff_lines.append(
        f"@@ -{ctx_start + 1},{old_count} +{ctx_start + 1},{new_count} @@\n"
    )
    for ln in ctx_lines:
        diff_lines.append(" " + ln)
    for ln in new_block_lines:
        diff_lines.append("+" + ln)
    for ln in after_lines:
        diff_lines.append(" " + ln)
    return "".join(diff_lines)


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
                actions.append(
                    Action(
                        kind="note",
                        title=f"`{dll}!{fn}` resolves to noop `{existing}`",
                        body=(
                            f"The thunk table already has an entry for `{dll}!{fn}` "
                            f"pointing at the generic noop `{existing}`. The fix journal "
                            f"recorded the call because the caller likely needs real "
                            f"semantics. Either:\n\n"
                            f"  1. Add a real implementation: write bytecode in "
                            f"`thunks_bytecode.inc`, declare a `kOff<Name>` constant in "
                            f"`thunks.cpp`, and update the row in `thunks_table.inc`.\n"
                            f"  2. Accept the noop as intentional: replace the generic "
                            f"`{existing}` with a distinct named offset (the loader's noop "
                            f"classifier ignores any offset whose name isn't in the noop "
                            f"set, so the journal stops re-recording it).\n"
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
            diff = synth_syscall_patch(num, r.seq, repo_root)
            if diff:
                actions.append(
                    Action(
                        kind="patch",
                        title=f"Scaffold syscall #0x{num:x}",
                        body=diff,
                        filename=f"syscall-0x{num:x}.patch",
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
    if not all_records:
        print("# no readable fix-journal files", file=sys.stderr)
        return 1

    actions = plan_actions(all_records, thunks_index, repo_root)
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
