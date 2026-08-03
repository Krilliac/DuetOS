#!/usr/bin/env python3
"""Structural guards for scheduler-atomic service publication and rollback."""

from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
PROCESS_H = ROOT / "kernel" / "proc" / "process.h"
PROCESS_CPP = ROOT / "kernel" / "proc" / "process.cpp"
SCHED_CPP = ROOT / "kernel" / "sched" / "sched.cpp"
SERVICE_CPP = ROOT / "kernel" / "core" / "service.cpp"


def braced_body(source: str, opening: int) -> str:
    depth = 0
    for index in range(opening, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[opening + 1 : index]
    raise AssertionError("unterminated braced region")


def function_body(source: str, signature: str) -> str:
    match = re.search(signature + r"\s*\([^;{}]*\)\s*(?:const\s*)?\{", source)
    if match is None:
        raise AssertionError(f"missing function: {signature}")
    return braced_body(source, source.find("{", match.start()))


def require(source: str, pattern: str, message: str) -> re.Match[str]:
    match = re.search(pattern, source, re.DOTALL)
    if match is None:
        raise AssertionError(message)
    return match


def require_order(source: str, *tokens: str) -> None:
    cursor = 0
    for token in tokens:
        found = source.find(token, cursor)
        if found < 0:
            raise AssertionError(f"missing ordered token: {token}")
        cursor = found + len(token)


class ServicePublicationGateContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.process_h = PROCESS_H.read_text(encoding="utf-8")
        cls.process_cpp = PROCESS_CPP.read_text(encoding="utf-8")
        cls.sched_cpp = SCHED_CPP.read_text(encoding="utf-8")
        cls.service_cpp = SERVICE_CPP.read_text(encoding="utf-8")

    def test_process_key_and_one_shot_gate_are_explicit(self) -> None:
        key = require(
            self.process_h,
            r"struct\s+ProcessKey\s*\{(?P<body>[^}]*)\}",
            "missing exact ProcessKey type",
        ).group("body")
        self.assertRegex(key, r"\bu64\s+identity\s*;")
        self.assertRegex(key, r"\bu64\s+pid\s*;")
        self.assertRegex(
            self.process_h,
            r"using\s+ProcessPublicationGate\s*=\s*bool\s*\(\*\)\s*\(\s*ProcessKey\s*,\s*void\s*\*\s*\)",
        )
        self.assertIn("ProcessInstallPublicationGateBeforePublish", self.process_h)
        self.assertIn("ProcessRunPublicationGateAtSchedulerPublication", self.process_h)

    def test_pid_identity_mint_is_nonwrapping(self) -> None:
        create = function_body(self.process_cpp, r"Process\*\s+ProcessCreate")
        self.assertNotRegex(create, r"__atomic_fetch_add\s*\(\s*&g_next_pid")
        self.assertIn("MintProcessKey", create)
        mint = function_body(self.process_cpp, r"u64\s+MintProcessKey")
        self.assertRegex(mint, r"observed\s*==\s*~u64")
        self.assertRegex(mint, r"__atomic_compare_exchange_n")
        self.assertRegex(create, r"if\s*\(\s*process_identity\s*==\s*0\s*\)")

    def test_gate_installation_is_private_and_run_consumes_before_callback(self) -> None:
        install = function_body(self.process_cpp, r"bool\s+ProcessInstallPublicationGateBeforePublish")
        require_order(
            install,
            "ProcessLifecycleLoad(process)",
            "ProcessLifecycleState::Private",
            "process->publication_gate = gate",
            "process->publication_gate_context = context",
        )

        run = function_body(self.process_cpp, r"bool\s+ProcessRunPublicationGateAtSchedulerPublication")
        require_order(
            run,
            "ProcessKeySnapshot(process)",
            "ProcessPublicationGate gate = process->publication_gate",
            "process->publication_gate = nullptr",
            "process->publication_gate_context = nullptr",
            "return gate(key, context)",
        )
        self.assertNotIn("return gate(process", run)

    def test_scheduler_gate_precedes_lifecycle_and_runqueue_publication(self) -> None:
        publish = function_body(self.sched_cpp, r"bool\s+PublishCreatedTask")
        require_order(
            publish,
            "ProcessLifecycleState::Private",
            "ProcessRunPublicationGateAtSchedulerPublication(task->process)",
            "ProcessLifecycleTransition(task->process, ProcessLifecycleState::Private",
            "task->published = true",
            "RunqueuePush(task)",
            "AllTasksLink(task)",
        )

    def test_rejected_publication_destroys_every_private_task_resource(self) -> None:
        destroy = function_body(self.sched_cpp, r"void\s+DestroyUnpublishedTask")
        require_order(
            destroy,
            "!task->published",
            "UserStackReleaseOwnedMappings",
            "FreeKernelStack",
            "KFree(task)",
        )
        self.assertNotIn("ProcessRelease", destroy)

        create = function_body(self.sched_cpp, r"TaskCreateResult\s+SchedCreateInternal")
        rejected = require(
            create,
            r"if\s*\(\s*!published\s*\)\s*\{(?P<body>.*?)\}",
            "publication rejection has no rollback branch",
        ).group("body")
        # The non-greedy branch matcher stops at the closing brace of the
        # braced return initializer, so assert the complete ordered prefix.
        require_order(rejected, "DestroyUnpublishedTask(t)", "return TaskCreateResult{false, 0")
        self.assertNotIn("KASSERT(published", create)

    def test_legacy_service_commits_inside_scheduler_gate(self) -> None:
        runtime = require(
            self.service_cpp,
            r"struct\s+ServiceRuntime\s*\{(?P<body>.*?)\};",
            "legacy runtime row is missing",
        ).group("body")
        self.assertRegex(runtime, r"\bProcessKey\s+process\s*;")
        self.assertNotRegex(runtime, r"\bu64\s+pid\s*;")

        prepare = function_body(self.service_cpp, r"bool\s+PrepareServiceProcess")
        require_order(
            prepare,
            "ProcessReplaceResourceDomainBeforePublish",
            "ProcessInstallPublicationGateBeforePublish",
            "CommitServiceAtSchedulerPublication",
        )

        commit = function_body(self.service_cpp, r"bool\s+CommitServiceAtSchedulerPublication")
        require_order(
            commit,
            "ProcessKeyIsValid(process)",
            "publication_attempted = true",
            "NowNs()",
            "SpinLockGuard guard(g_service_lock)",
            "CommitStartLocked(context->reservation, process",
            "StartCommitResult::Published",
        )

        tick = function_body(self.service_cpp, r"void\s+ServiceManagerTick")
        self.assertIn("!(runtime.process == process)", tick)

        execute = function_body(self.service_cpp, r"bool\s+ExecuteStart")
        self.assertNotIn("SchedKillProcessByPid", execute)
        self.assertRegex(execute, r"cancelled service escaped scheduler publication rollback")


if __name__ == "__main__":
    unittest.main()
