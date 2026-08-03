#!/usr/bin/env python3
"""Parse, validate, mutate, and lock the parallel-work coordinator."""

from __future__ import annotations

import argparse
import ctypes
import datetime as dt
import fnmatch
import json
import os
import re
import shutil
import socket
import sys
import tempfile
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


HEADER_RE = re.compile(r"^### \[(ACTIVE|DONE)] (\S.*)$")
FIELD_RE = re.compile(r"^- \*\*(Session|Branch|Files|Description|Claimed|Status)\*\*: (.*)$")
COMPLETED_RE = re.compile(r"^COMPLETED @ \S.*$")
MAGIC_RE = re.compile(r"[*?\[]")
NON_FATAL_LEGACY_ISSUES = {"duplicate-id", "header-status-mismatch"}
LOCK_NAME = "duetos-parallel-coordinator.lock"


class GuardError(RuntimeError):
    pass


@dataclass(frozen=True)
class Issue:
    kind: str
    message: str


@dataclass(frozen=True)
class Claim:
    subsystem: str
    header_state: str
    fields: dict[str, str]
    scopes: tuple[str, ...]
    header_line: int
    status_line: int | None

    @property
    def status(self) -> str:
        return self.fields.get("Status", "")

    @property
    def conservatively_active(self) -> bool:
        return self.header_state == "ACTIVE" or self.status == "IN PROGRESS"

    @property
    def consistently_active(self) -> bool:
        return self.header_state == "ACTIVE" and self.status == "IN PROGRESS"

    @property
    def consistently_done(self) -> bool:
        return self.header_state == "DONE" and bool(COMPLETED_RE.fullmatch(self.status))


@dataclass(frozen=True)
class Document:
    text: str
    lines: tuple[str, ...]
    claims: tuple[Claim, ...]
    issues: tuple[Issue, ...]


def _field_value(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value.startswith("`") and value.endswith("`"):
        return value[1:-1]
    return value


def normalize_scopes(raw: str) -> tuple[str, ...]:
    if "\n" in raw or "\r" in raw or "`" in raw:
        raise GuardError("scope list contains a forbidden newline or backtick")

    normalized: list[str] = []
    seen: set[str] = set()
    for token in re.split(r"[\s,]+", raw.strip()):
        if not token:
            continue
        token = token.replace("\\", "/")
        while "//" in token:
            token = token.replace("//", "/")
        if token.startswith("./"):
            token = token[2:]
        token = token.rstrip("/")
        parts = token.split("/")
        if (
            not token
            or token.startswith("/")
            or re.match(r"^[A-Za-z]:", token)
            or any(part in {"", ".", ".."} for part in parts)
        ):
            raise GuardError(f"invalid repository-relative scope: {token!r}")
        if token not in seen:
            seen.add(token)
            normalized.append(token)

    if not normalized:
        raise GuardError("scope list is empty")
    return tuple(normalized)


def canonical_scopes(scopes: Iterable[str]) -> str:
    return ",".join(scopes)


def _path_prefix(parent: str, child: str) -> bool:
    return child == parent or child.startswith(parent.rstrip("/") + "/")


def _has_magic(scope: str) -> bool:
    return MAGIC_RE.search(scope) is not None


def _glob_root(scope: str) -> str:
    match = MAGIC_RE.search(scope)
    if not match:
        return scope
    prefix = scope[: match.start()]
    if "/" not in prefix:
        return ""
    return prefix.rsplit("/", 1)[0]


def scopes_intersect(left: str, right: str) -> bool:
    """Conservatively decide whether two repository-relative scopes overlap."""

    if left == right or _path_prefix(left, right) or _path_prefix(right, left):
        return True

    left_magic = _has_magic(left)
    right_magic = _has_magic(right)
    if not left_magic and not right_magic:
        return False

    if fnmatch.fnmatchcase(left, right) or fnmatch.fnmatchcase(right, left):
        return True

    if left_magic and not right_magic:
        root = _glob_root(left)
        return not root or _path_prefix(right, root) or _path_prefix(root, right)
    if right_magic and not left_magic:
        root = _glob_root(right)
        return not root or _path_prefix(left, root) or _path_prefix(root, left)

    left_root = _glob_root(left)
    right_root = _glob_root(right)
    if not left_root or not right_root:
        return True
    return _path_prefix(left_root, right_root) or _path_prefix(right_root, left_root)


def intersecting_pairs(
    left: Iterable[str], right: Iterable[str]
) -> tuple[tuple[str, str], ...]:
    return tuple(
        (left_scope, right_scope)
        for left_scope in left
        for right_scope in right
        if scopes_intersect(left_scope, right_scope)
    )


def parse_document(text: str) -> Document:
    lines = text.splitlines()
    starts = [index for index, line in enumerate(lines) if line.startswith("### ")]
    claims: list[Claim] = []
    issues: list[Issue] = []

    for position, start in enumerate(starts):
        match = HEADER_RE.fullmatch(lines[start])
        if not match:
            issues.append(Issue("malformed-header", f"line {start + 1}: malformed claim header"))
            continue
        end = starts[position + 1] if position + 1 < len(starts) else len(lines)
        fields: dict[str, str] = {}
        status_line: int | None = None
        for index in range(start + 1, end):
            field_match = FIELD_RE.fullmatch(lines[index])
            if not field_match:
                continue
            name, value = field_match.groups()
            if name in fields:
                issues.append(
                    Issue(
                        "duplicate-field",
                        f"line {index + 1}: duplicate {name} field in {match.group(2)!r}",
                    )
                )
            fields[name] = _field_value(value)
            if name == "Status":
                status_line = index

        subsystem = match.group(2).strip()
        missing = sorted({"Session", "Branch", "Files", "Description", "Claimed", "Status"} - fields.keys())
        if missing:
            issues.append(
                Issue(
                    "missing-field",
                    f"claim {subsystem!r} is missing fields: {', '.join(missing)}",
                )
            )
        try:
            scopes = normalize_scopes(fields.get("Files", ""))
        except GuardError as error:
            scopes = ()
            issues.append(Issue("invalid-scopes", f"claim {subsystem!r}: {error}"))

        status = fields.get("Status", "")
        status_in_progress = status == "IN PROGRESS"
        status_completed = COMPLETED_RE.fullmatch(status) is not None
        if not status_in_progress and not status_completed:
            issues.append(Issue("invalid-status", f"claim {subsystem!r} has invalid status {status!r}"))
        elif (match.group(1) == "ACTIVE") != status_in_progress:
            issues.append(
                Issue(
                    "header-status-mismatch",
                    f"claim {subsystem!r} has [{match.group(1)}] header with {status!r}",
                )
            )

        claims.append(
            Claim(
                subsystem=subsystem,
                header_state=match.group(1),
                fields=fields,
                scopes=scopes,
                header_line=start,
                status_line=status_line,
            )
        )

    by_id: dict[str, list[Claim]] = {}
    for claim in claims:
        by_id.setdefault(claim.subsystem, []).append(claim)
    for subsystem, duplicates in sorted(by_id.items()):
        if len(duplicates) > 1:
            line_list = ", ".join(str(claim.header_line + 1) for claim in duplicates)
            issues.append(
                Issue(
                    "duplicate-id",
                    f"duplicate subsystem id {subsystem!r} at lines {line_list}",
                )
            )

    return Document(text, tuple(lines), tuple(claims), tuple(issues))


def read_document(path: Path) -> Document:
    if not path.exists():
        return parse_document("")
    return parse_document(path.read_text(encoding="utf-8"))


def _fatal_issues(document: Document) -> tuple[Issue, ...]:
    return tuple(issue for issue in document.issues if issue.kind not in NON_FATAL_LEGACY_ISSUES)


def validate_new_claim(document: Document, subsystem: str, scopes: tuple[str, ...]) -> None:
    fatal = _fatal_issues(document)
    if fatal:
        raise GuardError("coordinator is malformed: " + "; ".join(issue.message for issue in fatal))
    if any(claim.subsystem == subsystem for claim in document.claims):
        raise GuardError(f"subsystem id {subsystem!r} already exists in the coordinator")

    conflicts: list[str] = []
    for claim in document.claims:
        if not claim.conservatively_active:
            continue
        overlap = intersecting_pairs(scopes, claim.scopes)
        if overlap:
            details = ", ".join(f"{left} <-> {right}" for left, right in overlap)
            conflicts.append(f"{claim.subsystem}: {details}")
    if conflicts:
        raise GuardError("scope conflict with active claim(s): " + "; ".join(conflicts))


def _safe_field(name: str, value: str) -> str:
    if not value or "\n" in value or "\r" in value:
        raise GuardError(f"{name} must be a non-empty single line")
    if name in {"subsystem", "session", "branch"} and "`" in value:
        raise GuardError(f"{name} cannot contain backticks")
    return value


def atomic_write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def append_claim(args: argparse.Namespace) -> None:
    path = Path(args.file)
    document = read_document(path)
    subsystem = _safe_field("subsystem", args.subsystem)
    scopes = normalize_scopes(args.scopes)
    validate_new_claim(document, subsystem, scopes)
    session = _safe_field("session", args.session)
    branch = _safe_field("branch", args.branch)
    description = _safe_field("description", args.description)
    timestamp = _safe_field("timestamp", args.timestamp)

    prefix = document.text.rstrip()
    if not prefix:
        prefix = (
            "# Parallel Work Coordinator\n\n"
            "Auto-managed by tools/parallel/claim.sh and release.sh — do not edit by hand.\n\n"
            "## Active Sessions"
        )
    block = (
        f"### [ACTIVE] {subsystem}\n"
        f"- **Session**: `{session}`\n"
        f"- **Branch**: `{branch}`\n"
        f"- **Files**: `{canonical_scopes(scopes)}`\n"
        f"- **Description**: {description}\n"
        f"- **Claimed**: {timestamp}\n"
        "- **Status**: IN PROGRESS\n"
    )
    atomic_write(path, prefix + "\n\n" + block)


def complete_claim(args: argparse.Namespace) -> None:
    path = Path(args.file)
    document = read_document(path)
    fatal = _fatal_issues(document)
    if fatal:
        raise GuardError("coordinator is malformed: " + "; ".join(issue.message for issue in fatal))
    matches = [claim for claim in document.claims if claim.subsystem == args.subsystem]
    if len(matches) != 1:
        raise GuardError(
            f"subsystem {args.subsystem!r} is ambiguous or absent ({len(matches)} entries)"
        )
    claim = matches[0]
    if not claim.consistently_active or claim.status_line is None:
        raise GuardError(
            f"subsystem {args.subsystem!r} is not one unambiguous active claim"
        )
    if args.branch and claim.fields.get("Branch") != args.branch:
        raise GuardError(
            f"subsystem {args.subsystem!r} belongs to branch "
            f"{claim.fields.get('Branch')!r}, not {args.branch!r}"
        )

    lines = list(document.lines)
    lines[claim.header_line] = f"### [DONE] {claim.subsystem}"
    lines[claim.status_line] = f"- **Status**: COMPLETED @ {_safe_field('timestamp', args.timestamp)}"
    atomic_write(path, "\n".join(lines) + "\n")


def status_command(args: argparse.Namespace) -> int:
    path = Path(args.file)
    if not path.exists():
        print("No active parallel work. PARALLEL_WORK.md not found.")
        return 0
    document = read_document(path)
    active = [claim for claim in document.claims if claim.conservatively_active]
    done = [claim for claim in document.claims if claim.consistently_done]
    print("\n=======================================")
    print("  Parallel Session Status")
    print("=======================================\n")
    print(f"  Active: {len(active)}  |  Completed: {len(done)}\n")
    for claim in document.claims:
        print(f"### [{claim.header_state}] {claim.subsystem}")
        for field in ("Session", "Branch", "Files", "Description", "Claimed", "Status"):
            print(f"- **{field}**: {claim.fields.get(field, '<missing>')}")
        print()

    overlaps: list[str] = []
    for index, left in enumerate(active):
        for right in active[index + 1 :]:
            pairs = intersecting_pairs(left.scopes, right.scopes)
            if pairs:
                detail = ", ".join(f"{a} <-> {b}" for a, b in pairs)
                overlaps.append(f"{left.subsystem} vs {right.subsystem}: {detail}")

    print("Integrity check:")
    if document.issues:
        for issue in document.issues:
            print(f"  ERROR [{issue.kind}] {issue.message}")
    else:
        print("  OK: coordinator entries are structurally consistent")
    print("Conflict check:")
    if overlaps:
        for overlap in overlaps:
            print(f"  ERROR {overlap}")
    else:
        print("  OK: no active scope intersections detected")
    return 1 if document.issues or overlaps else 0


def _pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    if os.name == "nt":
        from ctypes import wintypes

        process_query_limited_information = 0x1000
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
        kernel32.OpenProcess.restype = wintypes.HANDLE
        kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
        kernel32.CloseHandle.restype = wintypes.BOOL
        handle = kernel32.OpenProcess(process_query_limited_information, False, pid)
        if not handle:
            return ctypes.get_last_error() == 5  # Access denied still proves existence.
        kernel32.CloseHandle(handle)
        return True
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _read_lock_metadata(lock_dir: Path) -> dict[str, object] | None:
    try:
        value = json.loads((lock_dir / "owner.json").read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return None
    return value if isinstance(value, dict) else None


def _lock_is_stale(lock_dir: Path, metadata: dict[str, object] | None, stale_after: float) -> bool:
    now = time.time()
    try:
        created = float(metadata.get("created_unix", 0)) if metadata else lock_dir.stat().st_mtime
    except (OSError, TypeError, ValueError):
        created = now
    if now - created < stale_after:
        return False
    if not metadata:
        return True
    host = str(metadata.get("hostname", "")).casefold()
    try:
        pid = int(metadata.get("pid", 0))
    except (TypeError, ValueError):
        pid = 0
    return host != socket.gethostname().casefold() or not _pid_alive(pid)


def _recover_stale_lock(lock_dir: Path) -> bool:
    quarantine = lock_dir.with_name(lock_dir.name + ".stale-" + uuid.uuid4().hex)
    try:
        lock_dir.rename(quarantine)
    except (FileNotFoundError, FileExistsError, PermissionError, OSError):
        return False
    shutil.rmtree(quarantine, ignore_errors=True)
    return True


def acquire_lock(args: argparse.Namespace) -> str:
    common_dir = Path(args.common_dir).resolve()
    common_dir.mkdir(parents=True, exist_ok=True)
    lock_dir = common_dir / LOCK_NAME
    deadline = time.monotonic() + args.timeout
    token = uuid.uuid4().hex

    while True:
        try:
            lock_dir.mkdir()
        except FileExistsError:
            metadata = _read_lock_metadata(lock_dir)
            if _lock_is_stale(lock_dir, metadata, args.stale_after) and _recover_stale_lock(lock_dir):
                print("recovered stale parallel coordinator lock", file=sys.stderr)
                continue
            if time.monotonic() >= deadline:
                owner = json.dumps(metadata, sort_keys=True) if metadata else "unreadable metadata"
                raise GuardError(f"parallel coordinator lock is busy: {owner}")
            time.sleep(min(0.1, max(0.0, deadline - time.monotonic())))
            continue

        metadata = {
            "version": 1,
            "token": token,
            "pid": args.holder_pid if args.holder_pid is not None else os.getpid(),
            "hostname": args.holder_host or socket.gethostname(),
            "created_unix": time.time(),
            "created_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
            "operation": args.operation,
            "cwd": str(Path.cwd()),
        }
        try:
            (lock_dir / "owner.json").write_text(
                json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )
        except OSError:
            shutil.rmtree(lock_dir, ignore_errors=True)
            raise
        return token


def release_lock(args: argparse.Namespace) -> None:
    lock_dir = Path(args.common_dir).resolve() / LOCK_NAME
    metadata = _read_lock_metadata(lock_dir)
    if not metadata or metadata.get("token") != args.token:
        raise GuardError("lock token does not match the current coordinator lock")
    quarantine = lock_dir.with_name(lock_dir.name + ".release-" + args.token)
    try:
        lock_dir.rename(quarantine)
    except OSError as error:
        raise GuardError(f"could not release coordinator lock: {error}") from error
    shutil.rmtree(quarantine)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    normalize = subparsers.add_parser("normalize")
    normalize.add_argument("--scopes", required=True)

    check = subparsers.add_parser("check-claim")
    check.add_argument("--file", required=True)
    check.add_argument("--subsystem", required=True)
    check.add_argument("--scopes", required=True)

    append = subparsers.add_parser("append-claim")
    append.add_argument("--file", required=True)
    append.add_argument("--subsystem", required=True)
    append.add_argument("--scopes", required=True)
    append.add_argument("--session", required=True)
    append.add_argument("--branch", required=True)
    append.add_argument("--description", required=True)
    append.add_argument("--timestamp", required=True)

    complete = subparsers.add_parser("complete-claim")
    complete.add_argument("--file", required=True)
    complete.add_argument("--subsystem", required=True)
    complete.add_argument("--timestamp", required=True)
    complete.add_argument("--branch")

    status = subparsers.add_parser("status")
    status.add_argument("--file", required=True)

    lock_acquire = subparsers.add_parser("lock-acquire")
    lock_acquire.add_argument("--common-dir", required=True)
    lock_acquire.add_argument("--operation", required=True)
    lock_acquire.add_argument("--timeout", type=float, default=15.0)
    lock_acquire.add_argument("--stale-after", type=float, default=600.0)
    lock_acquire.add_argument("--holder-pid", type=int)
    lock_acquire.add_argument("--holder-host")

    lock_release = subparsers.add_parser("lock-release")
    lock_release.add_argument("--common-dir", required=True)
    lock_release.add_argument("--token", required=True)
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        if args.command == "normalize":
            print(canonical_scopes(normalize_scopes(args.scopes)))
        elif args.command == "check-claim":
            scopes = normalize_scopes(args.scopes)
            validate_new_claim(read_document(Path(args.file)), args.subsystem, scopes)
            print(canonical_scopes(scopes))
        elif args.command == "append-claim":
            append_claim(args)
        elif args.command == "complete-claim":
            complete_claim(args)
        elif args.command == "status":
            return status_command(args)
        elif args.command == "lock-acquire":
            if args.timeout < 0 or args.stale_after < 0:
                raise GuardError("lock timeouts must be non-negative")
            print(acquire_lock(args))
        elif args.command == "lock-release":
            release_lock(args)
        else:
            parser.error(f"unsupported command: {args.command}")
    except (GuardError, OSError) as error:
        print(f"claims_guard: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
