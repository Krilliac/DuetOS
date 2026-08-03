#!/usr/bin/env python3
"""Hostile functional tests for the parallel claim/release protocol."""

from __future__ import annotations

import importlib.util
import json
import os
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SOURCE_PARALLEL = ROOT / "tools" / "parallel"


def load_guard():
    spec = importlib.util.spec_from_file_location(
        "duetos_claims_guard", SOURCE_PARALLEL / "claims_guard.py"
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load claims_guard.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


GUARD = load_guard()


def find_bash() -> str:
    configured = os.environ.get("DUETOS_GIT_BASH")
    candidates = [configured] if configured else []
    if os.name == "nt":
        candidates.extend(
            [
                str(Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Git" / "bin" / "bash.exe"),
                str(Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Git" / "usr" / "bin" / "bash.exe"),
            ]
        )
    candidates.append(shutil.which("bash"))
    for candidate in candidates:
        if candidate and Path(candidate).is_file():
            return candidate
    raise unittest.SkipTest("Git Bash/bash is unavailable")


BASH = find_bash()


def claim_block(
    subsystem: str,
    scopes: str,
    *,
    header: str = "ACTIVE",
    status: str = "IN PROGRESS",
) -> str:
    return textwrap.dedent(
        f"""
        ### [{header}] {subsystem}
        - **Session**: `test-session`
        - **Branch**: `claude/test`
        - **Files**: `{scopes}`
        - **Description**: hostile test fixture
        - **Claimed**: 2026-08-02T00:00:00Z
        - **Status**: {status}
        """
    ).strip()


BASE_COORDINATOR = textwrap.dedent(
    """
    # Parallel Work Coordinator

    Auto-managed by tools/parallel/claim.sh and release.sh — do not edit by hand.

    ## Active Sessions
    """
).lstrip()


class RepoHarness:
    def __init__(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="duetos-claims-")
        self.root = Path(self.temporary.name)
        self.remote = self.root / "remote.git"
        self.repo = self.root / "repo"
        self._run(["git", "init", "--bare", str(self.remote)])
        self._run(["git", "init", "-b", "claude/test", str(self.repo)])
        self.git("config", "user.name", "Parallel Safety Test")
        self.git("config", "user.email", "parallel-safety@example.invalid")
        self.git("config", "commit.gpgsign", "false")
        self.git("config", "core.autocrlf", "false")

        parallel = self.repo / "tools" / "parallel"
        parallel.mkdir(parents=True)
        for name in ("claim.sh", "status.sh", "release.sh", "claims_guard.py"):
            shutil.copy2(SOURCE_PARALLEL / name, parallel / name)
        (self.repo / "PARALLEL_WORK.md").write_text(BASE_COORDINATOR, encoding="utf-8")
        (self.repo / "implementation.txt").write_text("clean\n", encoding="utf-8")
        self.git("add", ".")
        self.git("commit", "-s", "-m", "test: initialize hostile repository")
        self.git("branch", "main")
        self.git("remote", "add", "origin", str(self.remote))
        self.git("push", "-u", "origin", "HEAD:refs/heads/claude/test")
        self.git("push", "origin", "refs/heads/main:refs/heads/main")

    def close(self) -> None:
        self.temporary.cleanup()

    def _run(
        self,
        command: list[str],
        *,
        cwd: Path | None = None,
        env: dict[str, str] | None = None,
        check: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        completed = subprocess.run(
            command,
            cwd=cwd,
            env=env,
            text=True,
            encoding="utf-8",
            errors="replace",
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=30,
            check=False,
        )
        if check and completed.returncode != 0:
            raise AssertionError(
                f"command failed ({completed.returncode}): {' '.join(command)}\n{completed.stdout}"
            )
        return completed

    def git(self, *arguments: str, check: bool = True) -> subprocess.CompletedProcess[str]:
        return self._run(["git", *arguments], cwd=self.repo, check=check)

    def script(
        self, name: str, *arguments: str, extra_env: dict[str, str] | None = None
    ) -> subprocess.CompletedProcess[str]:
        env = os.environ.copy()
        env.update(
            {
                "CLAUDE_SESSION_ID": "hostile-test-session",
                "DUETOS_PARALLEL_LOCK_TIMEOUT": "2",
                "DUETOS_PARALLEL_LOCK_STALE_AFTER": "600",
                "GIT_TERMINAL_PROMPT": "0",
            }
        )
        if extra_env:
            env.update(extra_env)
        return self._run(
            [BASH, f"tools/parallel/{name}", *arguments],
            cwd=self.repo,
            env=env,
            check=False,
        )

    def guard(self, *arguments: str, check: bool = True) -> subprocess.CompletedProcess[str]:
        return self._run(
            [sys.executable, str(self.repo / "tools" / "parallel" / "claims_guard.py"), *arguments],
            cwd=self.repo,
            check=check,
        )

    def coordinator(self) -> Path:
        return self.repo / "PARALLEL_WORK.md"

    def commit_coordinator(self, message: str = "test: coordinator fixture") -> None:
        self.git("add", "PARALLEL_WORK.md")
        self.git("commit", "-s", "-m", message)
        self.git("push", "origin", "HEAD:refs/heads/claude/test")

    def replace_coordinator(self, *blocks: str) -> None:
        suffix = "\n\n".join(blocks)
        text = BASE_COORDINATOR.rstrip() + ("\n\n" + suffix if suffix else "") + "\n"
        self.coordinator().write_text(text, encoding="utf-8")
        self.commit_coordinator()

    def common_dir(self) -> str:
        return self.git("rev-parse", "--path-format=absolute", "--git-common-dir").stdout.strip()

    def remote_oid(self, branch: str = "claude/test") -> str:
        line = self._run(
            ["git", "ls-remote", "--heads", str(self.remote), f"refs/heads/{branch}"]
        ).stdout.strip()
        return line.split()[0]

    def reject_pushes(self) -> None:
        hook = self.remote / "hooks" / "pre-receive"
        hook.write_text("#!/bin/sh\necho rejected-for-test >&2\nexit 1\n", encoding="utf-8", newline="\n")
        hook.chmod(hook.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


class ScopeEngineTests(unittest.TestCase):
    def test_tokenization_normalizes_commas_whitespace_and_slashes(self) -> None:
        self.assertEqual(
            GUARD.normalize_scopes(r"kernel\net\* , kernel/net/socket.cpp  tests/host"),
            ("kernel/net/*", "kernel/net/socket.cpp", "tests/host"),
        )

    def test_glob_file_and_directory_child_intersect(self) -> None:
        self.assertTrue(GUARD.scopes_intersect("kernel/net/*", "kernel/net/socket.cpp"))
        self.assertTrue(GUARD.scopes_intersect("kernel/net", "kernel/net/socket.cpp"))
        self.assertTrue(GUARD.scopes_intersect("kernel/*/socket.cpp", "kernel/net"))
        self.assertFalse(GUARD.scopes_intersect("kernel/net/a.cpp", "kernel/net/b.cpp"))
        self.assertFalse(GUARD.scopes_intersect("kernel/net/*", "kernel/fs/file.cpp"))

    def test_duplicate_and_contradictory_entries_are_reported(self) -> None:
        text = BASE_COORDINATOR + "\n" + claim_block("dup", "a") + "\n\n"
        text += claim_block("dup", "b", header="DONE", status="COMPLETED @ now") + "\n\n"
        text += claim_block("contradiction", "c", status="COMPLETED @ now") + "\n"
        document = GUARD.parse_document(text)
        kinds = {issue.kind for issue in document.issues}
        self.assertIn("duplicate-id", kinds)
        self.assertIn("header-status-mismatch", kinds)
        contradiction = next(c for c in document.claims if c.subsystem == "contradiction")
        self.assertTrue(contradiction.conservatively_active)


class ParallelScriptTests(unittest.TestCase):
    def setUp(self) -> None:
        self.harness = RepoHarness()

    def tearDown(self) -> None:
        self.harness.close()

    def test_claim_allows_unrelated_dirty_file_and_publishes_exact_signed_commit(self) -> None:
        implementation = self.harness.repo / "implementation.txt"
        implementation.write_text("dirty implementation\n", encoding="utf-8")
        self.harness.git("add", "implementation.txt")
        result = self.harness.script(
            "claim.sh", "safe-claim", "kernel/net/a.cpp, kernel/net/b.cpp", "test claim"
        )
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("Claimed and published: safe-claim", result.stdout)
        local_oid = self.harness.git("rev-parse", "HEAD").stdout.strip()
        self.assertEqual(self.harness.remote_oid(), local_oid)
        self.assertEqual(
            self.harness.git("diff-tree", "--no-commit-id", "--name-only", "-r", "HEAD").stdout.strip(),
            "PARALLEL_WORK.md",
        )
        self.assertIn("Signed-off-by:", self.harness.git("log", "-1", "--format=%B").stdout)
        self.assertIn("M  implementation.txt", self.harness.git("status", "--short").stdout)
        self.assertIn(
            "`kernel/net/a.cpp,kernel/net/b.cpp`",
            self.harness.coordinator().read_text(encoding="utf-8"),
        )

    def test_glob_conflict_is_noninteractive_and_fails(self) -> None:
        self.harness.replace_coordinator(claim_block("owner", "kernel/net/*"))
        before = self.harness.git("rev-parse", "HEAD").stdout.strip()
        result = self.harness.script("claim.sh", "contender", "kernel/net/socket.cpp", "conflict")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("scope conflict", result.stdout)
        self.assertNotIn("Claimed and published", result.stdout)
        self.assertEqual(self.harness.git("rev-parse", "HEAD").stdout.strip(), before)

    def test_dirty_coordinator_fails_before_commit(self) -> None:
        with self.harness.coordinator().open("a", encoding="utf-8") as stream:
            stream.write("\n")
        before = self.harness.git("rev-parse", "HEAD").stdout.strip()
        result = self.harness.script("claim.sh", "dirty", "kernel/dirty.cpp", "dirty")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("must be clean", result.stdout)
        self.assertNotIn("Claimed and published", result.stdout)
        self.assertEqual(self.harness.git("rev-parse", "HEAD").stdout.strip(), before)

    def test_lock_contention_fails_and_stale_dead_owner_recovers(self) -> None:
        common_dir = self.harness.common_dir()
        acquired = self.harness.guard(
            "lock-acquire",
            "--common-dir",
            common_dir,
            "--operation",
            "test-holder",
            "--timeout",
            "0",
            "--stale-after",
            "600",
        ).stdout.strip()
        blocked = self.harness.script(
            "claim.sh",
            "blocked",
            "kernel/blocked.cpp",
            "blocked",
            extra_env={"DUETOS_PARALLEL_LOCK_TIMEOUT": "0.2"},
        )
        self.assertNotEqual(blocked.returncode, 0)
        self.assertIn("lock is busy", blocked.stdout)
        self.assertNotIn("Claimed and published", blocked.stdout)
        self.harness.guard("lock-release", "--common-dir", common_dir, "--token", acquired)

        lock_dir = Path(common_dir) / GUARD.LOCK_NAME
        lock_dir.mkdir()
        (lock_dir / "owner.json").write_text(
            json.dumps(
                {
                    "token": "dead",
                    "pid": 2_147_483_647,
                    "hostname": socket.gethostname(),
                    "created_unix": time.time() - 3600,
                }
            ),
            encoding="utf-8",
        )
        recovered = self.harness.script(
            "claim.sh",
            "recovered",
            "kernel/recovered.cpp",
            "stale recovery",
            extra_env={
                "DUETOS_PARALLEL_LOCK_TIMEOUT": "1",
                "DUETOS_PARALLEL_LOCK_STALE_AFTER": "1",
            },
        )
        self.assertEqual(recovered.returncode, 0, recovered.stdout)
        self.assertIn("recovered stale parallel coordinator lock", recovered.stdout)
        self.assertFalse(lock_dir.exists())

    def test_remote_ahead_is_fetched_and_rejected_without_false_success(self) -> None:
        rival = self.harness.root / "rival"
        self.harness._run(["git", "clone", str(self.harness.remote), str(rival)])
        self.harness._run(["git", "config", "user.name", "Rival"], cwd=rival)
        self.harness._run(["git", "config", "user.email", "rival@example.invalid"], cwd=rival)
        self.harness._run(
            ["git", "switch", "-c", "claude/test", "origin/claude/test"], cwd=rival
        )
        (rival / "rival.txt").write_text("remote ahead\n", encoding="utf-8")
        self.harness._run(["git", "add", "rival.txt"], cwd=rival)
        self.harness._run(["git", "commit", "-s", "-m", "test: remote ahead"], cwd=rival)
        self.harness._run(["git", "push", "origin", "HEAD:refs/heads/claude/test"], cwd=rival)

        before = self.harness.git("rev-parse", "HEAD").stdout.strip()
        result = self.harness.script("claim.sh", "behind", "kernel/behind.cpp", "behind")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("not an ancestor of HEAD", result.stdout)
        self.assertNotIn("Claimed and published", result.stdout)
        self.assertEqual(self.harness.git("rev-parse", "HEAD").stdout.strip(), before)

    def test_claim_push_failure_never_prints_success(self) -> None:
        remote_before = self.harness.remote_oid()
        local_before = self.harness.git("rev-parse", "HEAD").stdout.strip()
        self.harness.reject_pushes()
        result = self.harness.script("claim.sh", "push-fail", "kernel/push.cpp", "push fail")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("normal claim push failed", result.stdout)
        self.assertNotIn("Claimed and published", result.stdout)
        self.assertEqual(self.harness.remote_oid(), remote_before)
        self.assertNotEqual(self.harness.git("rev-parse", "HEAD").stdout.strip(), local_before)
        self.assertFalse((Path(self.harness.common_dir()) / GUARD.LOCK_NAME).exists())

    def test_commit_failure_never_prints_success(self) -> None:
        hook = self.harness.repo / ".git" / "hooks" / "commit-msg"
        hook.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8", newline="\n")
        hook.chmod(hook.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        before = self.harness.git("rev-parse", "HEAD").stdout.strip()
        result = self.harness.script("claim.sh", "commit-fail", "kernel/commit.cpp", "fail")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("signed coordinator commit failed", result.stdout)
        self.assertNotIn("Claimed and published", result.stdout)
        self.assertEqual(self.harness.git("rev-parse", "HEAD").stdout.strip(), before)

    def test_release_rejects_duplicate_or_contradictory_target(self) -> None:
        fixtures = (
            (
                "duplicate",
                (claim_block("target", "a"), claim_block("target", "b")),
                "ambiguous or absent",
            ),
            (
                "contradictory",
                (claim_block("target", "a", status="COMPLETED @ now"),),
                "not one unambiguous active claim",
            ),
        )
        for label, blocks, expected in fixtures:
            with self.subTest(label=label):
                if label != "duplicate":
                    self.harness.close()
                    self.harness = RepoHarness()
                self.harness.replace_coordinator(*blocks)
                before = self.harness.git("rev-parse", "HEAD").stdout.strip()
                result = self.harness.script("release.sh", "target")
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(expected, result.stdout)
                self.assertNotIn("Released and published", result.stdout)
                self.assertEqual(self.harness.git("rev-parse", "HEAD").stdout.strip(), before)

    def test_release_push_failure_leaves_remote_active_and_reports_failure(self) -> None:
        claimed = self.harness.script("claim.sh", "release-fail", "kernel/release.cpp", "claim")
        self.assertEqual(claimed.returncode, 0, claimed.stdout)
        remote_before = self.harness.remote_oid()
        self.harness.reject_pushes()
        released = self.harness.script("release.sh", "release-fail")
        self.assertNotEqual(released.returncode, 0)
        self.assertIn("normal release push failed", released.stdout)
        self.assertNotIn("Released and published", released.stdout)
        self.assertEqual(self.harness.remote_oid(), remote_before)
        remote_text = self.harness._run(
            ["git", "--git-dir", str(self.harness.remote), "show", "claude/test:PARALLEL_WORK.md"]
        ).stdout
        self.assertIn("### [ACTIVE] release-fail", remote_text)

    def test_release_rejects_dirty_coordinator_before_commit(self) -> None:
        claimed = self.harness.script("claim.sh", "release-dirty", "kernel/release-dirty.cpp", "claim")
        self.assertEqual(claimed.returncode, 0, claimed.stdout)
        with self.harness.coordinator().open("a", encoding="utf-8") as stream:
            stream.write("\n")
        before = self.harness.git("rev-parse", "HEAD").stdout.strip()
        released = self.harness.script("release.sh", "release-dirty")
        self.assertNotEqual(released.returncode, 0)
        self.assertIn("must be clean", released.stdout)
        self.assertNotIn("Released and published", released.stdout)
        self.assertEqual(self.harness.git("rev-parse", "HEAD").stdout.strip(), before)

    def test_release_commit_failure_never_prints_success(self) -> None:
        claimed = self.harness.script("claim.sh", "release-commit-fail", "kernel/release-commit.cpp", "claim")
        self.assertEqual(claimed.returncode, 0, claimed.stdout)
        hook = self.harness.repo / ".git" / "hooks" / "commit-msg"
        hook.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8", newline="\n")
        hook.chmod(hook.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        before = self.harness.git("rev-parse", "HEAD").stdout.strip()
        released = self.harness.script("release.sh", "release-commit-fail")
        self.assertNotEqual(released.returncode, 0)
        self.assertIn("signed coordinator release commit failed", released.stdout)
        self.assertNotIn("Released and published", released.stdout)
        self.assertEqual(self.harness.git("rev-parse", "HEAD").stdout.strip(), before)

    def test_release_success_publishes_exact_signed_coordinator_commit(self) -> None:
        claimed = self.harness.script("claim.sh", "release-ok", "kernel/release-ok.cpp", "claim")
        self.assertEqual(claimed.returncode, 0, claimed.stdout)
        released = self.harness.script("release.sh", "release-ok")
        self.assertEqual(released.returncode, 0, released.stdout)
        self.assertIn("Released and published: release-ok", released.stdout)
        local_oid = self.harness.git("rev-parse", "HEAD").stdout.strip()
        self.assertEqual(self.harness.remote_oid(), local_oid)
        self.assertEqual(
            self.harness.git("diff-tree", "--no-commit-id", "--name-only", "-r", "HEAD").stdout.strip(),
            "PARALLEL_WORK.md",
        )
        self.assertIn("Signed-off-by:", self.harness.git("log", "-1", "--format=%B").stdout)
        self.assertIn("### [DONE] release-ok", self.harness.coordinator().read_text(encoding="utf-8"))

    def test_merge_refuses_dirty_worktree_before_release(self) -> None:
        claimed = self.harness.script("claim.sh", "merge-dirty", "kernel/merge.cpp", "claim")
        self.assertEqual(claimed.returncode, 0, claimed.stdout)
        (self.harness.repo / "implementation.txt").write_text("dirty\n", encoding="utf-8")
        released = self.harness.script("release.sh", "merge-dirty", "--merge")
        self.assertNotEqual(released.returncode, 0)
        self.assertIn("completely clean worktree", released.stdout)
        self.assertIn("### [ACTIVE] merge-dirty", self.harness.coordinator().read_text(encoding="utf-8"))

    def test_merge_refuses_stale_local_main_without_success(self) -> None:
        claimed = self.harness.script("claim.sh", "merge-stale", "kernel/merge-stale.cpp", "claim")
        self.assertEqual(claimed.returncode, 0, claimed.stdout)

        rival = self.harness.root / "main-rival"
        self.harness._run(["git", "clone", str(self.harness.remote), str(rival)])
        self.harness._run(["git", "config", "user.name", "Main Rival"], cwd=rival)
        self.harness._run(["git", "config", "user.email", "main-rival@example.invalid"], cwd=rival)
        self.harness._run(["git", "switch", "-c", "main", "origin/main"], cwd=rival)
        (rival / "main-ahead.txt").write_text("main ahead\n", encoding="utf-8")
        self.harness._run(["git", "add", "main-ahead.txt"], cwd=rival)
        self.harness._run(["git", "commit", "-s", "-m", "test: advance main"], cwd=rival)
        self.harness._run(["git", "push", "origin", "HEAD:refs/heads/main"], cwd=rival)

        released = self.harness.script("release.sh", "merge-stale", "--merge")
        self.assertNotEqual(released.returncode, 0)
        self.assertIn("local main is stale", released.stdout)
        self.assertNotIn("Released and published", released.stdout)
        self.assertEqual(
            self.harness.git("rev-parse", "refs/heads/main").stdout.strip(),
            self.harness.git("rev-parse", "HEAD~2").stdout.strip(),
        )

    def test_merge_refuses_branch_that_cannot_fast_forward_current_main(self) -> None:
        claimed = self.harness.script("claim.sh", "merge-non-ff", "kernel/merge-non-ff.cpp", "claim")
        self.assertEqual(claimed.returncode, 0, claimed.stdout)

        rival = self.harness.root / "non-ff-rival"
        self.harness._run(["git", "clone", str(self.harness.remote), str(rival)])
        self.harness._run(["git", "config", "user.name", "Non-FF Rival"], cwd=rival)
        self.harness._run(["git", "config", "user.email", "non-ff@example.invalid"], cwd=rival)
        self.harness._run(["git", "switch", "-c", "main", "origin/main"], cwd=rival)
        (rival / "non-ff-main.txt").write_text("diverge main\n", encoding="utf-8")
        self.harness._run(["git", "add", "non-ff-main.txt"], cwd=rival)
        self.harness._run(["git", "commit", "-s", "-m", "test: diverge main"], cwd=rival)
        self.harness._run(["git", "push", "origin", "HEAD:refs/heads/main"], cwd=rival)
        self.harness.git("fetch", "origin", "refs/heads/main:refs/remotes/origin/main")
        self.harness.git("branch", "-f", "main", "refs/remotes/origin/main")

        released = self.harness.script("release.sh", "merge-non-ff", "--merge")
        self.assertNotEqual(released.returncode, 0)
        self.assertIn("cannot fast-forward main", released.stdout)
        self.assertNotIn("Released and published", released.stdout)

    def test_status_uses_shared_parser_and_fails_on_integrity_or_overlap(self) -> None:
        self.harness.replace_coordinator(
            claim_block("first", "kernel/net/*"),
            claim_block("second", "kernel/net/socket.cpp"),
            claim_block("second", "kernel/fs/a.cpp", header="DONE", status="COMPLETED @ now"),
        )
        status = self.harness.script("status.sh")
        self.assertNotEqual(status.returncode, 0)
        self.assertIn("duplicate-id", status.stdout)
        self.assertIn("first vs second", status.stdout)
        self.assertIn("kernel/net/* <-> kernel/net/socket.cpp", status.stdout)

    def test_scripts_forbid_force_push_rebase_and_swallowed_git_errors(self) -> None:
        claim_source = (SOURCE_PARALLEL / "claim.sh").read_text(encoding="utf-8")
        release_source = (SOURCE_PARALLEL / "release.sh").read_text(encoding="utf-8")
        status_source = (SOURCE_PARALLEL / "status.sh").read_text(encoding="utf-8")
        for source in (claim_source, release_source):
            self.assertNotIn("git rebase", source)
            self.assertNotIn("--force-with-lease", source)
            self.assertNotIn("|| true", source)
            self.assertIn("git push -u origin", source)
            self.assertIn("git ls-remote", source)
            self.assertIn("lock-acquire", source)
            self.assertIn('--holder-pid "$HOLDER_PID"', source)
            self.assertIn("NATIVE_PID=", source)
        self.assertIn("claims_guard.py", status_source)
        self.assertIn("lock-acquire", status_source)
        protocol = (ROOT / "CLAUDE_PARALLEL.md").read_text(encoding="utf-8")
        self.assertIn("signed coordinator-only commit", protocol)
        self.assertIn("normal pushes only", protocol)
        self.assertIn("different session branches", protocol)


if __name__ == "__main__":
    unittest.main(verbosity=2)
