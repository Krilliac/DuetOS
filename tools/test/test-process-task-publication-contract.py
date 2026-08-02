#!/usr/bin/env python3
"""Red-first structural contract for Process/Task publication lifetime."""

from __future__ import annotations

import re
import unittest
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
PROCESS_H = ROOT / "kernel" / "proc" / "process.h"
PROCESS_CPP = ROOT / "kernel" / "proc" / "process.cpp"
SCHED_H = ROOT / "kernel" / "sched" / "sched.h"
SCHED_CPP = ROOT / "kernel" / "sched" / "sched.cpp"

FIRST_PUBLICATION_TRANSITION = (
    r"ProcessLifecycleTransition\s*\(\s*task->process\s*,\s*"
    r"ProcessLifecycleState::Private\s*,\s*ProcessLifecycleState::Published\s*\)"
)
LAST_UNLINK_TRANSITION = (
    r"ProcessLifecycleTransition\s*\(\s*dead_process\s*,\s*"
    r"ProcessLifecycleState::Published\s*,\s*ProcessLifecycleState::Exiting\s*\)"
)
EXIT_COMPLETE_TRANSITION = (
    r"ProcessLifecycleTransition\s*\(\s*process\s*,\s*"
    r"ProcessLifecycleState::Exiting\s*,\s*ProcessLifecycleState::Exited\s*\)"
)


def code_only(source: str) -> str:
    """Blank C/C++ comments and literals while preserving offsets/newlines."""
    masked = list(source)

    def blank(begin: int, end: int) -> None:
        for offset in range(begin, end):
            if masked[offset] not in "\r\n":
                masked[offset] = " "

    index = 0
    while index < len(source):
        if source.startswith("//", index):
            end = source.find("\n", index + 2)
            if end < 0:
                end = len(source)
            blank(index, end)
            index = end
            continue

        if source.startswith("/*", index):
            end = source.find("*/", index + 2)
            if end < 0:
                raise AssertionError("unterminated block comment")
            end += 2
            blank(index, end)
            index = end
            continue

        raw_prefix = next(
            (prefix for prefix in ("u8R\"", "uR\"", "UR\"", "LR\"", "R\"") if source.startswith(prefix, index)),
            None,
        )
        if raw_prefix is not None:
            delimiter_begin = index + len(raw_prefix)
            open_paren = source.find("(", delimiter_begin, delimiter_begin + 17)
            if open_paren >= 0:
                delimiter = source[delimiter_begin:open_paren]
                if not re.search(r"[\s\\()]", delimiter):
                    terminator = ")" + delimiter + '"'
                    end = source.find(terminator, open_paren + 1)
                    if end < 0:
                        raise AssertionError("unterminated raw string literal")
                    end += len(terminator)
                    blank(index, end)
                    index = end
                    continue

        if source[index] in "\"'":
            quote = source[index]
            end = index + 1
            while end < len(source):
                if source[end] == "\\":
                    end += 2
                    continue
                if source[end] == quote:
                    end += 1
                    break
                end += 1
            else:
                raise AssertionError("unterminated quoted literal")
            blank(index, end)
            index = end
            continue

        index += 1

    return "".join(masked)


def matching_delimiter(source: str, opening: int, left: str, right: str) -> int:
    if opening < 0 or source[opening] != left:
        raise AssertionError(f"missing opening {left!r}")
    depth = 0
    for index in range(opening, len(source)):
        if source[index] == left:
            depth += 1
        elif source[index] == right:
            depth -= 1
            if depth == 0:
                return index
    raise AssertionError(f"unterminated {left}{right} region")


def function_body(source: str, signature: str) -> str:
    code = code_only(source)
    found_signature = False
    for match in re.finditer(signature + r"\s*\(", code):
        found_signature = True
        opening_paren = code.find("(", match.start())
        closing_paren = matching_delimiter(code, opening_paren, "(", ")")
        opening_brace = code.find("{", closing_paren + 1)
        declaration_end = code.find(";", closing_paren + 1)
        if declaration_end >= 0 and (opening_brace < 0 or declaration_end < opening_brace):
            continue
        if opening_brace >= 0:
            closing_brace = matching_delimiter(code, opening_brace, "{", "}")
            return code[opening_brace + 1 : closing_brace]
    qualifier = "definition" if found_signature else "signature"
    raise AssertionError(f"missing function {qualifier}: {signature}")


def type_body(source: str, declaration: str) -> str:
    code = code_only(source)
    match = re.search(declaration + r"[^;{]*\{", code)
    if match is None:
        raise AssertionError(f"missing type definition: {declaration}")
    opening = code.find("{", match.start())
    closing = matching_delimiter(code, opening, "{", "}")
    return code[opening + 1 : closing]


def statement_span(source: str, start: int) -> tuple[int, int, int]:
    while start < len(source) and source[start].isspace():
        start += 1
    if start >= len(source):
        raise AssertionError("missing statement")
    if source[start] == "{":
        closing = matching_delimiter(source, start, "{", "}")
        return start + 1, closing, closing + 1
    end = source.find(";", start)
    if end < 0:
        raise AssertionError("unterminated statement")
    return start, end + 1, end + 1


@dataclass(frozen=True)
class IfStatement:
    start: int
    condition: str
    then_body: str
    else_body: str | None


def if_statements(source: str) -> list[IfStatement]:
    statements: list[IfStatement] = []
    for match in re.finditer(r"\bif\b", source):
        opening = match.end()
        while opening < len(source) and source[opening].isspace():
            opening += 1
        if opening >= len(source) or source[opening] != "(":
            continue
        closing = matching_delimiter(source, opening, "(", ")")
        then_begin, then_end, cursor = statement_span(source, closing + 1)
        while cursor < len(source) and source[cursor].isspace():
            cursor += 1
        else_body = None
        if re.match(r"else\b", source[cursor:]):
            cursor += len("else")
            else_begin, else_end, _ = statement_span(source, cursor)
            else_body = source[else_begin:else_end]
        statements.append(
            IfStatement(
                start=match.start(),
                condition=source[opening + 1 : closing],
                then_body=source[then_begin:then_end],
                else_body=else_body,
            )
        )
    return statements


def lock_span_containing(source: str, target: int) -> tuple[int, int]:
    acquire_pattern = re.compile(r"(?:sync::)?SpinLockAcquire\s*\(\s*g_sched_lock\s*\)")
    release_pattern = re.compile(r"(?:sync::)?SpinLockRelease\s*\(\s*g_sched_lock\b")
    for acquire in reversed([match for match in acquire_pattern.finditer(source) if match.start() < target]):
        release = release_pattern.search(source, acquire.end())
        if release is not None and target < release.start():
            return acquire.start(), release.start()

    guard_pattern = re.compile(
        r"(?:sync::)?SpinLockGuard\s+[A-Za-z_]\w*\s*(?:\(\s*g_sched_lock\s*\)|\{\s*g_sched_lock\s*\})"
    )
    brace_pairs: list[tuple[int, int]] = []
    stack: list[int] = []
    for index, char in enumerate(source):
        if char == "{":
            stack.append(index)
        elif char == "}":
            brace_pairs.append((stack.pop(), index))
    for guard in reversed([match for match in guard_pattern.finditer(source) if match.start() < target]):
        enclosing = [(begin, end) for begin, end in brace_pairs if begin < guard.start() < end]
        scope_end = min((end for _, end in enclosing), default=len(source))
        if target < scope_end:
            return guard.start(), scope_end
    raise AssertionError("target is not within a g_sched_lock critical section")


def require_pattern(source: str, pattern: str, message: str) -> re.Match[str]:
    match = re.search(pattern, source, re.DOTALL)
    if match is None:
        raise AssertionError(message)
    return match


def branch_rejects_non_published(source: str) -> bool:
    for statement in if_statements(source):
        condition = statement.condition
        if (
            re.search(r"ProcessLifecycleLoad\s*\(\s*task->process\s*\)", condition)
            and re.search(r"!=\s*ProcessLifecycleState::Published\b", condition)
            and re.search(r"\breturn\s+false\s*;", statement.then_body)
        ):
            return True
    return False


def branch_rejects_failed_first_transition(source: str) -> bool:
    if any(
        re.search(r"!\s*" + FIRST_PUBLICATION_TRANSITION, statement.condition)
        and re.search(r"\breturn\s+false\s*;", statement.then_body)
        for statement in if_statements(source)
    ):
        return True
    # Once a one-shot external publication gate has accepted, losing the
    # Private -> Published CAS is an impossible invariant violation rather
    # than an ordinary rejection path. A checked fatal transition is equally
    # strong and must not be mistaken for an unchecked state write.
    return transition_failure_is_fatal(source, FIRST_PUBLICATION_TRANSITION)


def transition_failure_is_fatal(source: str, transition_pattern: str) -> bool:
    asserted = re.search(r"\bKASSERT(?:_WITH_VALUE)?\s*\(\s*(?:core::)?" + transition_pattern, source)
    if asserted:
        return True
    for statement in if_statements(source):
        if re.search(r"!\s*(?:core::)?" + transition_pattern, statement.condition) and re.search(
            r"\b(?:Panic\w*|KASSERT)\b", statement.then_body
        ):
            return True
    return False


class StructuralParserHostileTests(unittest.TestCase):
    def test_comments_and_all_literal_forms_cannot_supply_contract_tokens(self) -> None:
        hostile = r'''
// ProcessLifecycleState::Private { }
/* ProcessLifecycleTransition(p, Private, Published); */
const char* normal = "TaskCreateResult { bool created; u64 tid; }";
const char brace = '}';
const char* raw = u8R"tag(ProcessLifecycleState::Exited { } // still literal)tag";
int live_token = 1;
'''
        visible = code_only(hostile)
        self.assertNotIn("ProcessLifecycleState", visible)
        self.assertNotIn("TaskCreateResult", visible)
        self.assertNotIn("still literal", visible)
        self.assertIn("int live_token = 1;", visible)

    def test_function_slicing_ignores_prototypes_decoys_and_hostile_braces(self) -> None:
        hostile = r'''
bool PublishCreatedTask(Task*);
const char* decoy = "bool PublishCreatedTask(Task*) { return false; }";
bool PublishCreatedTask(Task* task)
{
    const char* braces = R"raw( } { /* )raw";
    if (task != nullptr) { return true; }
    return false;
}
bool After() { return false; }
'''
        body = function_body(hostile, r"bool\s+PublishCreatedTask")
        self.assertIn("if (task != nullptr) { return true; }", body)
        self.assertNotIn("bool After", body)

    def test_lock_slicing_rejects_tokens_after_manual_or_raii_unlock(self) -> None:
        manual = "SpinLockAcquire(g_sched_lock); inside(); SpinLockRelease(g_sched_lock, flags); outside();"
        self.assertEqual(manual[slice(*lock_span_containing(manual, manual.index("inside")))].count("inside"), 1)
        with self.assertRaisesRegex(AssertionError, "not within"):
            lock_span_containing(manual, manual.index("outside"))

        raii = "{ SpinLockGuard guard(g_sched_lock); inside(); } outside();"
        self.assertIn("inside", raii[slice(*lock_span_containing(raii, raii.index("inside")))])
        with self.assertRaisesRegex(AssertionError, "not within"):
            lock_span_containing(raii, raii.index("outside"))

    def test_policy_matching_rejects_superficial_or_unchecked_state_mentions(self) -> None:
        canonical = """
if (has_existing_process_task)
{
    if (ProcessLifecycleLoad(task->process) != ProcessLifecycleState::Published)
        return false;
}
else
{
    if (!ProcessLifecycleTransition(task->process, ProcessLifecycleState::Private,
                                    ProcessLifecycleState::Published))
        return false;
}
"""
        outer = next(statement for statement in if_statements(canonical) if statement.else_body is not None)
        self.assertTrue(branch_rejects_non_published(outer.then_body))
        self.assertTrue(branch_rejects_failed_first_transition(outer.else_body or ""))

        superficial = """
if (has_existing_process_task)
{
    auto state = ProcessLifecycleLoad(task->process);
    auto expected = ProcessLifecycleState::Published;
    return unrelated_failure ? false : true;
}
else
{
    ProcessLifecycleTransition(task->process, ProcessLifecycleState::Private,
                               ProcessLifecycleState::Published);
}
"""
        outer = next(statement for statement in if_statements(superficial) if statement.else_body is not None)
        self.assertFalse(branch_rejects_non_published(outer.then_body))
        self.assertFalse(branch_rejects_failed_first_transition(outer.else_body or ""))


class ProcessTaskPublicationContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.process_h = PROCESS_H.read_text(encoding="utf-8")
        cls.process_cpp = PROCESS_CPP.read_text(encoding="utf-8")
        cls.sched_h = SCHED_H.read_text(encoding="utf-8")
        cls.sched_cpp = SCHED_CPP.read_text(encoding="utf-8")
        cls.process_h_code = code_only(cls.process_h)
        cls.sched_h_code = code_only(cls.sched_h)
        cls.sched_cpp_code = code_only(cls.sched_cpp)

    def test_process_declares_the_explicit_lifecycle(self) -> None:
        lifecycle = type_body(self.process_h, r"enum\s+class\s+ProcessLifecycleState")
        for state in ("Private", "Published", "Exiting", "Exited"):
            with self.subTest(state=state):
                self.assertRegex(lifecycle, rf"\b{state}\b")

        process = type_body(self.process_h, r"struct\s+Process\b")
        self.assertRegex(process, r"\bProcessLifecycleState\s+lifecycle_state\s*;")

        create = function_body(self.process_cpp, r"Process\s*\*\s*ProcessCreate")
        initialized = require_pattern(
            create,
            r"(?:p->lifecycle_state\s*=|__atomic_store_n\s*\(\s*&p->lifecycle_state\s*,)\s*"
            r"ProcessLifecycleState::Private",
            "ProcessCreate does not explicitly initialize the private state",
        )
        self.assertLess(initialized.start(), create.rfind("return p;"))

    def test_lifecycle_observation_and_transition_are_atomic(self) -> None:
        require_pattern(
            self.process_h_code,
            r"\bProcessLifecycleState\s+ProcessLifecycleLoad\s*\(\s*const\s+Process\s*\*\s*\w+\s*\)\s*;",
            "missing ProcessLifecycleLoad declaration",
        )
        require_pattern(
            self.process_h_code,
            r"\bbool\s+ProcessLifecycleTransition\s*\(\s*Process\s*\*\s*\w+\s*,\s*"
            r"ProcessLifecycleState\s+\w+\s*,\s*ProcessLifecycleState\s+\w+\s*\)\s*;",
            "missing ProcessLifecycleTransition declaration",
        )

        load = function_body(self.process_cpp, r"ProcessLifecycleState\s+ProcessLifecycleLoad")
        require_pattern(
            load,
            r"__atomic_load(?:_n)?\s*\([\s\S]*?&\w+->lifecycle_state\b",
            "lifecycle load is not atomic",
        )
        self.assertIn("__ATOMIC_ACQUIRE", load)
        self.assertNotIn("reinterpret_cast", load)

        transition = function_body(self.process_cpp, r"bool\s+ProcessLifecycleTransition")
        require_pattern(
            transition,
            r"__atomic_compare_exchange(?:_n)?\s*\([\s\S]*?&\w+->lifecycle_state\b",
            "lifecycle transition is not a checked atomic state change",
        )
        self.assertIn("__ATOMIC_ACQ_REL", transition)
        self.assertIn("__ATOMIC_ACQUIRE", transition)
        self.assertNotIn("reinterpret_cast", transition)

    def test_process_termination_tombstone_is_distinct_atomic_and_monotonic(self) -> None:
        termination = type_body(self.process_h, r"enum\s+class\s+ProcessTerminationState")
        self.assertRegex(termination, r"\bOpen\b")
        self.assertRegex(termination, r"\bClosed\b")
        process = type_body(self.process_h, r"struct\s+Process\b")
        self.assertRegex(process, r"\bProcessTerminationState\s+termination_state\s*;")

        require_pattern(
            self.process_h_code,
            r"\bProcessTerminationState\s+ProcessTerminationLoad\s*\(",
            "missing Process termination snapshot API",
        )
        require_pattern(
            self.process_h_code,
            r"\bbool\s+ProcessTerminationClose\s*\(",
            "missing Process termination close API",
        )

        process_cpp_code = code_only(self.process_cpp)
        self.assertEqual(
            len(
                re.findall(
                    r"\btermination_state\s*=\s*ProcessTerminationState::Open\s*;",
                    process_cpp_code,
                )
            ),
            1,
            "Process termination can be reopened or is not initialized exactly once",
        )
        create = function_body(self.process_cpp, r"Process\s*\*\s*ProcessCreate")
        initialized = require_pattern(
            create,
            r"p->termination_state\s*=\s*ProcessTerminationState::Open\s*;",
            "ProcessCreate does not explicitly open Task publication",
        )
        self.assertLess(initialized.start(), create.rfind("return p;"))

        load = function_body(self.process_cpp, r"ProcessTerminationState\s+ProcessTerminationLoad")
        require_pattern(load, r"__atomic_load\s*\([^;]*&process->termination_state", "termination load is not atomic")
        self.assertIn("__ATOMIC_ACQUIRE", load)
        self.assertNotIn("ProcessLifecycle", load)

        close = function_body(self.process_cpp, r"bool\s+ProcessTerminationClose")
        require_pattern(
            close,
            r"__atomic_compare_exchange\s*\([^;]*&process->termination_state",
            "termination close is not a checked atomic transition",
        )
        self.assertIn("ProcessTerminationState::Open", close)
        self.assertIn("ProcessTerminationState::Closed", close)
        self.assertIn("__ATOMIC_ACQ_REL", close)
        self.assertIn("__ATOMIC_ACQUIRE", close)
        self.assertNotIn("ProcessLifecycle", close)

    def test_process_wide_kill_closes_publication_before_its_exact_scan(self) -> None:
        publish = function_body(self.sched_cpp, r"bool\s+PublishCreatedTask")
        publish_store = require_pattern(publish, r"task->published\s*=\s*true\s*;", "Task publication disappeared")
        lock_begin, lock_end = lock_span_containing(publish, publish_store.start())
        locked_publish = publish[lock_begin:lock_end]
        tombstone_guards = [
            statement
            for statement in if_statements(locked_publish)
            if "ProcessTerminationLoad(task->process)" in statement.condition
            and "ProcessTerminationState::Open" in statement.condition
        ]
        self.assertEqual(len(tombstone_guards), 1, "publication lacks one real closed-Process rejection")
        self.assertRegex(tombstone_guards[0].condition, r"!=\s*ProcessTerminationState::Open")
        self.assertRegex(tombstone_guards[0].then_body, r"return\s+false\s*;")
        self.assertLess(tombstone_guards[0].start, locked_publish.index("task->published = true"))
        self.assertLess(
            tombstone_guards[0].start,
            locked_publish.index("ProcessRunPublicationGateAtSchedulerPublication"),
            "closed first-Task publication consumes its one-shot policy gate",
        )

        for name, signature in (
            ("PID kill", r"u64\s+SchedKillProcessByPid"),
            ("retained-Process kill", r"u64\s+SchedKillByProcess"),
        ):
            with self.subTest(kill_path=name):
                body = function_body(self.sched_cpp, signature)
                close = require_pattern(
                    body,
                    r"ProcessTerminationClose\s*\(\s*target\s*,\s*exit_code\s*\)",
                    f"{name} does not close Task publication",
                )
                scan = require_pattern(
                    body[close.end() :],
                    r"for\s*\(\s*Task\s*\*\s*task\s*=\s*g_all_tasks_head\b",
                    f"{name} has no exact post-close task scan",
                )
                scan_position = close.end() + scan.start()
                signal = require_pattern(
                    body[scan_position:],
                    r"SignalTaskLocked\s*\(",
                    f"{name} scan does not signal matching Tasks",
                )
                signal_position = scan_position + signal.start()
                lock_start, lock_finish = lock_span_containing(body, close.start())
                self.assertTrue(
                    lock_start <= close.start() < scan_position < signal_position < lock_finish,
                    f"{name} does not close-before-scan in one scheduler-lock transaction",
                )
                self.assertNotIn(
                    "ProcessLifecycleTransition",
                    body,
                    f"{name} advances lifecycle before last-Task reap",
                )

        individual = function_body(self.sched_cpp, r"KillResult\s+SchedKillByPid")
        self.assertNotIn("ProcessTerminationClose", individual, "individual TID kill closes its whole Process")

    def test_closed_task_publication_preserves_full_private_rollback(self) -> None:
        rollback = function_body(self.sched_cpp, r"void\s+DestroyUnpublishedTask")
        for operation in (
            "UserStackReleaseOwnedMappings",
            "FreeKernelStack",
            "task->process = nullptr",
            "task->as = nullptr",
            "KFree(task)",
        ):
            with self.subTest(rollback_operation=operation):
                self.assertIn(operation, rollback)

        create = function_body(self.sched_cpp, r"TaskCreateResult\s+SchedCreateInternal")
        publish = require_pattern(create, r"PublishCreatedTask\s*\(\s*t\s*\)", "Task creation bypasses publication")
        destroy = require_pattern(
            create,
            r"DestroyUnpublishedTask\s*\(\s*t\s*\)",
            "rejected publication leaks its private Task",
        )
        self.assertLess(publish.start(), destroy.start())
        failed_publish = [
            statement
            for statement in if_statements(create)
            if "!published" in statement.condition and "DestroyUnpublishedTask(t)" in statement.then_body
        ]
        self.assertEqual(len(failed_publish), 1, "private rollback is not controlled by the publication receipt")

        create_user = function_body(self.sched_cpp, r"TaskCreateResult\s+CreateUserTask")
        failed_user = [statement for statement in if_statements(create_user) if "!result.created" in statement.condition]
        self.assertEqual(len(failed_user), 1, "CreateUserTask lost failed-publication handling")
        unwind = failed_user[0].then_body
        unlock = unwind.find("vm_transaction.Unlock()")
        release = unwind.find("ProcessRelease(process)")
        returned = unwind.find("return TaskCreateResult{false, 0}")
        self.assertTrue(0 <= unlock < release < returned, "failed publication releases Process ownership unsafely")

    def test_first_and_additional_task_publication_are_state_gated_under_lock(self) -> None:
        publish = function_body(self.sched_cpp, r"bool\s+PublishCreatedTask")
        publish_store = require_pattern(
            publish,
            r"\btask->published\s*=\s*true\s*;",
            "Task publication sentinel is missing",
        )
        lock_begin, lock_end = lock_span_containing(publish, publish_store.start())
        locked = publish[lock_begin:lock_end]

        membership = require_pattern(
            locked,
            r"\bg_all_tasks_head\b[\s\S]*?\b[A-Za-z_]\w*->process\s*==\s*task->process\b",
            "publication does not distinguish first from additional Process membership",
        )

        paired_policy = False
        for statement in if_statements(locked):
            if statement.else_body is None or statement.start <= membership.start():
                continue
            then = statement.then_body
            otherwise = statement.else_body
            branches = ((then, otherwise), (otherwise, then))
            for additional, first in branches:
                if branch_rejects_non_published(additional) and branch_rejects_failed_first_transition(first):
                    paired_policy = True
        self.assertTrue(
            paired_policy,
            "first/additional branches must reject non-Private/non-Published Process states",
        )

        first_transition = require_pattern(
            locked,
            FIRST_PUBLICATION_TRANSITION,
            "missing Private-to-Published transition",
        )
        self.assertLess(membership.start(), first_transition.start())
        self.assertLess(first_transition.start(), locked.index("task->published = true"))
        self.assertLess(locked.index("task->published = true"), locked.index("RunqueuePush(task)"))
        self.assertLess(locked.index("RunqueuePush(task)"), locked.index("AllTasksLink(task)"))
        self.assertRegex(locked[locked.index("AllTasksLink(task)") :], r"return\s+true\s*;")

    def test_last_unlink_enters_exiting_under_the_same_scheduler_lock(self) -> None:
        reaper = function_body(self.sched_cpp, r"\[\[noreturn\]\]\s+void\s+ReaperMain")
        unlink = require_pattern(reaper, r"\bAllTasksUnlink\s*\(\s*dead\s*\)", "reaper does not unlink the dead Task")
        lock_begin, lock_end = lock_span_containing(reaper, unlink.start())
        locked = reaper[lock_begin:lock_end]

        transition = require_pattern(
            locked,
            LAST_UNLINK_TRANSITION,
            "last Task unlink does not transition Published to Exiting while g_sched_lock is held",
        )
        self.assertLess(locked.index("AllTasksUnlink(dead)"), transition.start())
        self.assertTrue(
            any(
                "dead_was_last_process_task" in statement.condition
                and re.search(LAST_UNLINK_TRANSITION, statement.then_body)
                for statement in if_statements(locked)
            ),
            "Published-to-Exiting transition is not conditional on the exact last-Task result",
        )
        self.assertTrue(
            transition_failure_is_fatal(locked, LAST_UNLINK_TRANSITION),
            "failed Published-to-Exiting transition is ignored",
        )

    def test_exit_hooks_finish_the_lifecycle_before_releasing_the_process(self) -> None:
        reaper = function_body(self.sched_cpp, r"\[\[noreturn\]\]\s+void\s+ReaperMain")
        completion_call = require_pattern(
            reaper,
            r"ProcessCompleteExitFromReaper\s*\(\s*dead_process\s*\)",
            "last-task exit does not delegate the one-shot Process teardown",
        )
        release = reaper.rfind("ProcessRelease(dead_process)")
        self.assertGreater(release, completion_call.end(), "Process reference drops before exit completion")
        self.assertTrue(
            any(
                "dead_was_last_process_task" in statement.condition
                and "ProcessCompleteExitFromReaper(dead_process)" in statement.then_body
                for statement in if_statements(reaper)
            ),
            "Process exit completion is not conditional on the exact last-task result",
        )

        completion = function_body(self.process_cpp, r"void\s+ProcessCompleteExitFromReaper")
        transition = require_pattern(
            completion,
            EXIT_COMPLETE_TRANSITION,
            "last-task exit never completes Exiting to Exited",
        )
        teardown_call = completion.find("TeardownProcessRuntimeResources(process, true)")
        self.assertGreaterEqual(teardown_call, 0)
        self.assertLess(teardown_call, transition.start(), "runtime teardown runs after Exited publication")

        teardown = function_body(self.process_cpp, r"void\s+TeardownProcessRuntimeResources")
        hooks = (
            "ProcessDropOwnedProcessHandles(p)",
            "JobDrainOwned(process_key)",
        )
        for hook in hooks:
            with self.subTest(hook=hook):
                hook_position = teardown.find(hook)
                self.assertGreaterEqual(hook_position, 0)
                self.assertLess(hook_position, teardown.index("AddressSpaceRelease(p->as)"))

        lock_begin, lock_end = lock_span_containing(reaper, reaper.index("AllTasksUnlink(dead)"))
        locked_unlink = reaper[lock_begin:lock_end]
        membership_exit = locked_unlink.find("JobOnProcessExit(core::ProcessKeySnapshot(dead_process))")
        lifecycle_exit = locked_unlink.find("ProcessLifecycleTransition(dead_process")
        self.assertTrue(
            0 <= lifecycle_exit < membership_exit,
            "exact Job membership is not removed at the scheduler-linearized last-Task boundary",
        )
        self.assertNotIn("JobOnProcessExit", teardown, "unlocked teardown reintroduced the assignment/exit race")

        self.assertTrue(
            transition_failure_is_fatal(completion, EXIT_COMPLETE_TRANSITION),
            "failed Exiting-to-Exited transition is ignored",
        )

        self.assertGreaterEqual(completion_call.start(), lock_end, "exit completion runs while g_sched_lock is held")

    def test_process_release_zero_transition_is_state_gated(self) -> None:
        release = function_body(self.process_cpp, r"void\s+ProcessRelease")
        zero_boundary = release.index("if (new_count != 0)")
        destruction = release.rindex("mm::KFree(p)")
        gate_region = release[zero_boundary:destruction]

        load = require_pattern(
            gate_region,
            r"ProcessLifecycleLoad\s*\(\s*p\s*\)",
            "zero-reference ProcessRelease does not inspect lifecycle state",
        )
        self.assertIn("lifecycle == ProcessLifecycleState::Private", gate_region)
        self.assertIn("TeardownProcessRuntimeResources(p, false)", gate_region)
        self.assertIn("lifecycle == ProcessLifecycleState::Exited", gate_region)
        self.assertRegex(gate_region, r"else\s*\{[\s\S]*?PanicWithValue")
        self.assertLess(load.start(), gate_region.index("ProcessLifecycleState::Private"))

    def test_public_create_api_returns_only_an_immutable_value_receipt(self) -> None:
        receipt = type_body(self.sched_h, r"struct\s+TaskCreateResult")
        self.assertRegex(receipt, r"\bbool\s+created\s*;")
        self.assertRegex(receipt, r"\bu64\s+tid\s*;")
        self.assertNotRegex(receipt, r"\bTask\s*[*&]")

        public_names = ("SchedCreate", "SchedCreatePrepared", "SchedCreateUser", "SchedCreateUserPrepared")
        for name in public_names:
            with self.subTest(api=name):
                signature = rf"\bTaskCreateResult\s+{name}\s*\("
                require_pattern(self.sched_h_code, signature, f"{name} declaration does not return TaskCreateResult")
                require_pattern(self.sched_cpp_code, signature, f"{name} definition does not return TaskCreateResult")
                self.assertNotRegex(self.sched_h_code, rf"\bTask\s*\*\s*{name}\s*\(")

    def test_creation_receipt_is_captured_before_publication_and_never_dereferences_after(self) -> None:
        create = function_body(self.sched_cpp, r"TaskCreateResult\s+SchedCreateInternal")
        receipt = require_pattern(
            create,
            r"(?:const\s+)?TaskCreateResult\s+([A-Za-z_]\w*)\s*(?:=\s*)?\{\s*true\s*,\s*t->id\s*\}\s*;",
            "creation does not snapshot {created, tid} while Task is still private",
        )
        receipt_name = receipt.group(1)
        publish = require_pattern(create, r"\bPublishCreatedTask\s*\(\s*t\s*\)", "Task is never published")
        self.assertLess(receipt.start(), publish.start())
        after_publish = create[publish.end() :]
        self.assertNotRegex(after_publish, r"\bt\s*->", "published Task is dereferenced after it may have been reaped")
        self.assertRegex(after_publish, rf"\breturn\s+{re.escape(receipt_name)}\s*;")

if __name__ == "__main__":
    unittest.main()
