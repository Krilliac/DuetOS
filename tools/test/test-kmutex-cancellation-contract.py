#!/usr/bin/env python3
"""Red-first structural contract for cancellable, abandonable KMutex waits."""

from __future__ import annotations

import re
import unittest
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
KMUTEX_H = ROOT / "kernel" / "ipc" / "kmutex.h"
KMUTEX_CPP = ROOT / "kernel" / "ipc" / "kmutex.cpp"
SCHED_H = ROOT / "kernel" / "sched" / "sched.h"
SCHED_CPP = ROOT / "kernel" / "sched" / "sched.cpp"
MUTEX_SYSCALL_CPP = ROOT / "kernel" / "subsystems" / "win32" / "mutex_syscall.cpp"
FILE_SYSCALL_CPP = ROOT / "kernel" / "subsystems" / "win32" / "file_syscall.cpp"


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
            (prefix for prefix in ('u8R"', 'uR"', 'UR"', 'LR"', 'R"') if source.startswith(prefix, index)),
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


def require_pattern(source: str, pattern: str, message: str) -> re.Match[str]:
    match = re.search(pattern, source, re.DOTALL)
    if match is None:
        raise AssertionError(message)
    return match


def reject_pattern(source: str, pattern: str, message: str) -> None:
    if re.search(pattern, source, re.DOTALL) is not None:
        raise AssertionError(message)


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
        elif char == "}" and stack:
            brace_pairs.append((stack.pop(), index))
    for guard in reversed([match for match in guard_pattern.finditer(source) if match.start() < target]):
        enclosing = [(begin, end) for begin, end in brace_pairs if begin < guard.start() < end]
        scope_end = min((end for _, end in enclosing), default=len(source))
        if target < scope_end:
            return guard.start(), scope_end
    raise AssertionError("target is not within a g_sched_lock critical section")


def enum_has_members(source: str, declaration: str, required: set[str]) -> bool:
    try:
        body = type_body(source, declaration)
    except AssertionError:
        return False
    members = set(re.findall(r"\b([A-Za-z_]\w*)\s*(?:=\s*[^,}]+)?\s*(?:,|$)", body))
    return required <= members


def result_function_region(source: str, entry_signatures: tuple[str, ...]) -> str:
    """Collect result-bearing entry bodies and local KMutex helpers they call."""
    pending = list(entry_signatures)
    visited: set[str] = set()
    bodies: list[str] = []
    while pending:
        signature = pending.pop()
        if signature in visited:
            continue
        visited.add(signature)
        body = function_body(source, signature)
        bodies.append(body)
        for call in re.findall(r"\b(KMutex[A-Za-z_]\w*)\s*\(", body):
            helper_signature = rf"KMutexWaitResult\s+{re.escape(call)}"
            if helper_signature in visited:
                continue
            try:
                function_body(source, helper_signature)
            except AssertionError:
                continue
            pending.append(helper_signature)
    return "\n".join(bodies)


@dataclass(frozen=True)
class CancellationDetachPolicy:
    marker: str
    detach_call: str


def cancellation_detach_policy(source: str) -> CancellationDetachPolicy | None:
    """Recognize prompt detach + runnable publication in SignalTaskLocked."""
    try:
        signal = function_body(source, r"KillResult\s+SignalTaskLocked")
    except AssertionError:
        return None

    marker_match = re.search(
        r"target->(?P<marker>(?:wait_[A-Za-z_]*cancell[A-Za-z_]*|cancellable_wait[A-Za-z_]*|"
        r"wait_interrupt[A-Za-z_]*))",
        signal,
    )
    if marker_match is None:
        return None

    tail = signal[marker_match.start() :]
    direct_detach = re.search(
        r"\b(?P<detach>WaitQueue(?:Remove|Detach)[A-Za-z_]*Locked)\s*\([^;]*target",
        tail,
    )
    policy_region = signal
    detach_name = ""
    if direct_detach is not None:
        detach_name = direct_detach.group("detach")
    else:
        helper_call = re.search(
            r"\b(?P<helper>[A-Za-z_]\w*(?:Cancel|Detach)[A-Za-z_]*Wait[A-Za-z_]*Locked)\s*\(\s*target\b",
            tail,
        )
        if helper_call is None:
            return None
        detach_name = helper_call.group("helper")
        try:
            helper = function_body(source, rf"[A-Za-z_:<>*&\s]+\b{re.escape(detach_name)}")
        except AssertionError:
            return None
        if "SpinLockAssertHeld(g_sched_lock)" not in re.sub(r"\s+", "", helper):
            return None
        if not re.search(r"WaitQueue(?:Remove|Detach)[A-Za-z_]*Locked\s*\([^;]*target", helper):
            return None
        policy_region = helper

    compact = re.sub(r"\s+", "", policy_region)
    if "target->state=TaskState::Ready" not in compact or "RunqueuePush(target)" not in compact:
        return None
    if "SpinLockAssertHeld(g_sched_lock)" not in compact:
        return None
    return CancellationDetachPolicy(marker=marker_match.group("marker"), detach_call=detach_name)


class StructuralParserHostileTests(unittest.TestCase):
    def test_comments_and_literal_forms_cannot_supply_contract_tokens(self) -> None:
        hostile = r'''
// enum class KMutexWaitResult { Acquired, Abandoned, TimedOut, Cancelled, Failed };
/* target->wait_cancellable; WaitQueueDetachTaskLocked(queue, target); */
const char* normal = "AbandonableOwnershipNode { Task* owner; }";
const char* raw = u8R"tag(KMutexRelease(m); } // still literal)tag";
int live_token = 1;
'''
        visible = code_only(hostile)
        self.assertNotIn("KMutexWaitResult", visible)
        self.assertNotIn("KMutexRelease", visible)
        self.assertIn("int live_token = 1;", visible)

    def test_function_and_type_slicing_ignore_declarations_and_decoys(self) -> None:
        hostile = r'''
bool KMutexRelease(KMutex*);
const char* decoy = "bool KMutexRelease(KMutex*) { return false; }";
struct Other { int value; };
bool KMutexRelease(KMutex* mutex)
{
    const char* braces = R"raw( } { /* )raw";
    return mutex != nullptr;
}
'''
        body = function_body(hostile, r"bool\s+KMutexRelease")
        self.assertIn("return mutex != nullptr;", body)
        self.assertNotIn("struct Other", body)
        self.assertRegex(type_body(hostile, r"struct\s+Other"), r"\bint\s+value\s*;")

    def test_lock_slicing_distinguishes_inside_from_after_release(self) -> None:
        manual = "SpinLockAcquire(g_sched_lock); inside(); SpinLockRelease(g_sched_lock, flags); outside();"
        self.assertIn("inside", manual[slice(*lock_span_containing(manual, manual.index("inside")))])
        with self.assertRaisesRegex(AssertionError, "not within"):
            lock_span_containing(manual, manual.index("outside"))

        raii = "{ SpinLockGuard guard(g_sched_lock); inside(); } outside();"
        self.assertIn("inside", raii[slice(*lock_span_containing(raii, raii.index("inside")))])
        with self.assertRaisesRegex(AssertionError, "not within"):
            lock_span_containing(raii, raii.index("outside"))

    def test_cancellation_policy_requires_real_detach_and_runnable_publication(self) -> None:
        canonical = r'''
KillResult SignalTaskLocked(Task* target)
{
    SpinLockAssertHeld(g_sched_lock);
    if (target->wait_cancellable && target->waiting_on != nullptr)
    {
        WaitQueueDetachTaskLocked(target->waiting_on, target);
        target->state = TaskState::Ready;
        RunqueuePush(target);
        return KillResult::Signaled;
    }
    return KillResult::Blocked;
}
'''
        policy = cancellation_detach_policy(canonical)
        self.assertIsNotNone(policy)
        self.assertEqual(policy.marker, "wait_cancellable")

        superficial = r'''
KillResult SignalTaskLocked(Task* target)
{
    SpinLockAssertHeld(g_sched_lock);
    // target->wait_cancellable; WaitQueueDetachTaskLocked(q, target);
    target->state = TaskState::Ready;
    return KillResult::Blocked;
}
'''
        self.assertIsNone(cancellation_detach_policy(superficial))


class KMutexCancellationContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.kmutex_h = KMUTEX_H.read_text(encoding="utf-8")
        cls.kmutex_cpp = KMUTEX_CPP.read_text(encoding="utf-8")
        cls.sched_h = SCHED_H.read_text(encoding="utf-8")
        cls.sched_cpp = SCHED_CPP.read_text(encoding="utf-8")
        cls.mutex_syscall_cpp = MUTEX_SYSCALL_CPP.read_text(encoding="utf-8")
        cls.file_syscall_cpp = FILE_SYSCALL_CPP.read_text(encoding="utf-8")
        cls.kmutex_h_code = code_only(cls.kmutex_h)
        cls.kmutex_cpp_code = code_only(cls.kmutex_cpp)
        cls.sched_h_code = code_only(cls.sched_h)
        cls.sched_cpp_code = code_only(cls.sched_cpp)

    def test_scheduler_and_kmutex_expose_explicit_wait_results(self) -> None:
        self.assertTrue(
            enum_has_members(
                self.sched_h,
                r"enum\s+class\s+MutexAcquireResult",
                {"Acquired", "TimedOut", "Cancelled"},
            ),
            "MutexAcquireResult must distinguish acquisition, timeout, and cancellation",
        )
        self.assertTrue(
            enum_has_members(
                self.kmutex_h,
                r"enum\s+class\s+KMutexWaitResult",
                {"Acquired", "Abandoned", "TimedOut", "Cancelled", "Failed"},
            ),
            "KMutexWaitResult must preserve every Win32-visible wait outcome",
        )

    def test_scheduler_declares_intrusive_abandonable_ownership(self) -> None:
        node = type_body(self.sched_h, r"struct\s+AbandonableOwnershipNode")
        for link in ("prev", "next"):
            with self.subTest(link=link):
                self.assertRegex(node, rf"\bAbandonableOwnershipNode\s*\*\s*{link}\s*;")
        self.assertRegex(node, r"\bTask\s*\*\s*owner\s*;")
        callback_is_direct = re.search(
            r"\bvoid\s*\(\s*\*\s*abandon\s*\)\s*\(\s*AbandonableOwnershipNode\s*\*[^)]*\)\s*;",
            node,
        )
        callback_alias = re.search(r"\b(?P<alias>[A-Za-z_]\w*)\s+abandon\s*;", node)
        callback_is_alias = False
        if callback_alias is not None:
            alias = re.escape(callback_alias.group("alias"))
            callback_is_alias = re.search(
                rf"\busing\s+{alias}\s*=\s*void\s*\(\s*\*\s*\)\s*\(\s*AbandonableOwnershipNode\s*\*[^)]*\)",
                self.sched_h_code,
            ) is not None
        self.assertTrue(callback_is_direct or callback_is_alias, "ownership node lacks a node-aware abandon callback")

        task = type_body(self.sched_cpp, r"struct\s+Task")
        self.assertRegex(task, r"\bAbandonableOwnershipNode\s*\*\s*owned_abandonable_head\s*;")

    def test_tracking_and_untracking_serialize_the_intrusive_owner_identity(self) -> None:
        require_pattern(
            self.sched_h_code,
            r"\b(?:bool|void)\s+SchedTrackCurrentAbandonableOwnership\s*\(\s*AbandonableOwnershipNode\s*\*",
            "missing current-Task ownership tracking API",
        )
        require_pattern(
            self.sched_h_code,
            r"\bbool\s+SchedUntrackCurrentAbandonableOwnership\s*\(\s*AbandonableOwnershipNode\s*\*",
            "untrack must report whether the current Task atomically owned the node",
        )

        track = function_body(
            self.sched_cpp,
            r"(?:bool|void)\s+SchedTrackCurrentAbandonableOwnership",
        )
        owner_install = require_pattern(track, r"\b\w+->owner\s*=\s*\w+\s*;", "track never installs the owner")
        lock_span_containing(track, owner_install.start())
        self.assertIn("owned_abandonable_head", track)
        self.assertRegex(track, r"\b\w+->(?:prev|next)\s*=")

        untrack = function_body(self.sched_cpp, r"bool\s+SchedUntrackCurrentAbandonableOwnership")
        require_pattern(untrack, r"\bCurrentTask\s*\(\s*\)", "untrack does not obtain current Task identity")
        owner_check = require_pattern(
            untrack,
            r"\b\w+->owner\s*!=\s*\w+",
            "untrack does not reject a non-owner under the scheduler lock",
        )
        lock_span_containing(untrack, owner_check.start())
        self.assertRegex(untrack, r"\breturn\s+false\s*;")
        self.assertIn("owned_abandonable_head", untrack)
        owner_clear = require_pattern(untrack, r"\b\w+->owner\s*=\s*nullptr\s*;", "untrack leaves a stale owner")
        lock_span_containing(untrack, owner_clear.start())

    def test_reaper_detaches_ownership_then_invokes_callbacks_without_sched_lock(self) -> None:
        reaper = function_body(self.sched_cpp, r"\[\[noreturn\]\]\s+void\s+ReaperMain")
        unlink = require_pattern(reaper, r"\bAllTasksUnlink\s*\(\s*dead\s*\)", "reaper no longer unlinks Task")
        lock_begin, lock_end = lock_span_containing(reaper, unlink.start())
        locked = reaper[lock_begin:lock_end]
        require_pattern(
            locked,
            r"(?:owned_abandonable_head|[A-Za-z_]\w*Detach[A-Za-z_]*Abandon[A-Za-z_]*Locked\s*\(\s*dead)",
            "Task ownership ledger is not detached in the unlink transaction",
        )
        reject_pattern(locked, r"->abandon\s*\(", "abandon callback runs while g_sched_lock is held")

        tail = reaper[lock_end:]
        direct = re.search(r"(?:\(\s*\w+->abandon\s*\)|\w+->abandon)\s*\(", tail)
        helper_call = re.search(
            r"\b(?P<helper>(?:Run|Invoke|Abandon)[A-Za-z_]*Abandon[A-Za-z_]*(?:Callbacks?)?)\s*\(",
            tail,
        )
        self.assertTrue(direct or helper_call, "detached ownership callbacks are never invoked")
        if direct is not None:
            with self.assertRaisesRegex(AssertionError, "not within"):
                lock_span_containing(reaper, lock_end + direct.start())
        else:
            helper_name = helper_call.group("helper")
            helper = function_body(self.sched_cpp, rf"[A-Za-z_:<>*&\s]+\b{re.escape(helper_name)}")
            callback = require_pattern(helper, r"(?:\(\s*\w+->abandon\s*\)|\w+->abandon)\s*\(", "helper omits callback")
            with self.assertRaisesRegex(AssertionError, "not within"):
                lock_span_containing(helper, callback.start())

    def test_kmutex_state_is_tid_based_and_marks_the_inner_waitable_abandonable(self) -> None:
        mutex = type_body(self.kmutex_h, r"struct\s+KMutex")
        reject_pattern(mutex, r"\b(?:sched::)?Task\s*[*&]", "KMutex retains a raw Task owner")
        reject_pattern(
            self.kmutex_h_code,
            r"\b(?:sched::)?Task\s*\*\s*KMutexOwner\w*\s*\(",
            "KMutex exposes a raw Task owner API",
        )
        self.assertRegex(mutex, r"\bbool\s+held\s*;")
        self.assertRegex(mutex, r"\bu64\s+owner_tid\s*;")
        self.assertRegex(mutex, r"\bu32\s+recursion\s*;")
        self.assertRegex(mutex, r"\bbool\s+abandoned_pending\s*;")
        self.assertRegex(mutex, r"\b(?:sched::)?AbandonableOwnershipNode\s+ownership_node\s*;")

        create = function_body(self.kmutex_cpp, r"Result<KMutex\s*\*>\s+KMutexCreate")
        require_pattern(
            create,
            r"\bm->inner\.ownership_class\s*=\s*(?:sched::)?Mutex::OwnershipClass::AbandonableUserWaitable\s*;",
            "KMutexCreate leaves the scheduler mutex classified as Internal",
        )
        require_pattern(
            create,
            r"\bm->ownership_node\.abandon\s*=\s*&?[A-Za-z_]\w*\s*;",
            "KMutexCreate does not install its abandonment callback",
        )

    def test_cancellable_mutex_wait_is_promptly_detached_and_relinquishes_racy_handoff(self) -> None:
        require_pattern(
            self.sched_h_code,
            r"\bMutexAcquireResult\s+MutexLockCancellable\s*\(\s*Mutex\s*\*",
            "missing infinite cancellable mutex acquisition API",
        )
        require_pattern(
            self.sched_h_code,
            r"\bMutexAcquireResult\s+MutexLockTimedCancellable\s*\(\s*Mutex\s*\*[^,]*,\s*u64\b",
            "missing timed cancellable mutex acquisition API",
        )
        policy = cancellation_detach_policy(self.sched_cpp)
        self.assertIsNotNone(
            policy,
            "SignalTaskLocked must detach a marked cancellable waiter and make it runnable under g_sched_lock",
        )

        timed = function_body(self.sched_cpp, r"MutexAcquireResult\s+MutexLockTimedCancellable")
        self.assertIn(f"->{policy.marker}", timed, "cancellable wait never publishes its detach policy")
        killed = require_pattern(timed, r"\bKillPending\s*\(\s*self\s*\)", "resumed wait ignores stable kill intent")
        cancelled = require_pattern(
            timed[killed.start() :],
            r"\bMutexAcquireResult::Cancelled\b",
            "kill intent does not become a Cancelled result",
        )
        race_region = timed[killed.start() : killed.start() + cancelled.end()]
        require_pattern(race_region, r"\bm->owner\s*==\s*self\b", "cancel path ignores a direct FIFO handoff race")
        relinquish = re.search(
            r"\b(?:MutexOwnerDropLocked\s*\(\s*m\s*,\s*self\s*\)|"
            r"Mutex[A-Za-z_]*(?:Relinquish|Abandon|Handoff)[A-Za-z_]*Locked\s*\(\s*m\s*,\s*self)",
            race_region,
        )
        self.assertIsNotNone(relinquish, "cancelled handoff owner is not relinquished/re-handed-off")
        lock_span_containing(timed, killed.start())

    def test_kmutex_wait_ref_covers_block_and_only_success_becomes_holder_ref(self) -> None:
        missing_apis: list[str] = []
        api_arguments = (
            ("KMutexAcquire", r"KMutex\s*\*"),
            ("KMutexAcquireTimed", r"KMutex\s*\*[^,]*,\s*u64\b"),
        )
        for name, arguments in api_arguments:
            declaration = rf"\bKMutexWaitResult\s+{name}\s*\(\s*{arguments}"
            if re.search(declaration, self.kmutex_h_code) is None:
                missing_apis.append(f"{name} declaration")
            if re.search(declaration, self.kmutex_cpp_code) is None:
                missing_apis.append(f"{name} definition")
        self.assertFalse(
            missing_apis,
            "result-bearing KMutex API is incomplete: " + ", ".join(missing_apis),
        )

        region = result_function_region(
            self.kmutex_cpp,
            (r"KMutexWaitResult\s+KMutexAcquire", r"KMutexWaitResult\s+KMutexAcquireTimed"),
        )
        wait_ref = require_pattern(region, r"\bKObjectAcquire\s*\(\s*&m->base\s*\)", "wait does not retain KMutex")
        block = require_pattern(
            region,
            r"\b(?:sched::)?MutexLock(?:Timed)?Cancellable\s*\(\s*&m->inner",
            "KMutex bypasses cancellable scheduler acquisition",
        )
        self.assertLess(wait_ref.start(), block.start(), "wait reference is taken after blocking begins")

        for outcome in ("TimedOut", "Cancelled"):
            with self.subTest(outcome=outcome):
                label = require_pattern(region, rf"\bMutexAcquireResult::{outcome}\b", f"missing {outcome} mapping")
                cleanup_tail = region[label.end() : label.end() + 500]
                self.assertRegex(cleanup_tail, r"\bKObjectRelease\s*\(\s*&m->base\s*\)")
                self.assertRegex(cleanup_tail, rf"\bKMutexWaitResult::{outcome}\b")
        self.assertRegex(region, r"\bKMutexWaitResult::Failed\b")
        self.assertRegex(region, r"\bKMutexWaitResult::Acquired\b")

    def test_abandonment_is_published_before_handoff_and_consumed_once(self) -> None:
        create = function_body(self.kmutex_cpp, r"Result<KMutex\s*\*>\s+KMutexCreate")
        callback_assignment = require_pattern(
            create,
            r"\bm->ownership_node\.abandon\s*=\s*&?(?P<callback>[A-Za-z_]\w*)\s*;",
            "KMutexCreate omits abandonment callback",
        )
        callback = function_body(
            self.kmutex_cpp,
            rf"void\s+{re.escape(callback_assignment.group('callback'))}",
        )
        publish = require_pattern(
            callback,
            r"__atomic_store_n\s*\(\s*&\w+->abandoned_pending\s*,\s*true\s*,\s*__ATOMIC_RELEASE\s*\)",
            "abandonment is not release-published",
        )
        handoff = require_pattern(
            callback,
            r"\b(?:sched::)?Mutex[A-Za-z_]*(?:Abandon|Unlock|Relinquish)[A-Za-z_]*\s*\(",
            "abandonment callback never releases/hands off the inner mutex",
        )
        self.assertLess(publish.start(), handoff.start(), "waiter can run before abandonment becomes visible")
        compact_before_handoff = re.sub(r"\s+", "", callback[: handoff.start()])
        self.assertIn("&m->held,false,", compact_before_handoff)
        self.assertIn("&m->owner_tid,0", compact_before_handoff)
        self.assertIn("&m->recursion,0", compact_before_handoff)
        self.assertRegex(callback, r"\bKObjectRelease\s*\(\s*&\w+->base\s*\)")

        exchange = require_pattern(
            self.kmutex_cpp_code,
            r"__atomic_exchange_n\s*\(\s*&\w+->abandoned_pending\s*,\s*false\s*,\s*__ATOMIC_ACQ_REL\s*\)",
            "abandoned_pending is not consumed by a one-shot atomic exchange",
        )
        tail = self.kmutex_cpp_code[exchange.start() : exchange.start() + 500]
        self.assertRegex(tail, r"\bKMutexWaitResult::Abandoned\b")

    def test_closing_a_mutex_handle_never_releases_thread_ownership(self) -> None:
        close = function_body(self.file_syscall_cpp, r"void\s+DoFileClose")
        reject_pattern(close, r"\bKMutexRelease\s*\(", "CloseHandle force-releases a thread-owned mutex")
        reject_pattern(close, r"\bKMutexOwner\w*\s*\(", "CloseHandle inspects thread ownership to drain recursion")
        self.assertIn("HandleTableDetach", close)
        self.assertIn("KObjectRelease", close)

    def test_win32_wait_maps_abandoned_to_wait_abandoned_zero(self) -> None:
        wait = function_body(self.mutex_syscall_cpp, r"void\s+DoMutexWait")
        abandoned = require_pattern(wait, r"\bKMutexWaitResult::Abandoned\b", "Win32 wait ignores abandonment")
        mapping_tail = wait[abandoned.end() : abandoned.end() + 400]
        mapping = require_pattern(
            mapping_tail,
            r"\bframe->rax\s*=\s*(?:kWaitAbandoned0|0x0*80(?:ULL?|ull?)?)\s*;",
            "Abandoned is not translated to WAIT_ABANDONED_0 (0x80)",
        )
        if "kWaitAbandoned0" in mapping.group(0):
            require_pattern(
                code_only(self.mutex_syscall_cpp),
                r"\bkWaitAbandoned0\s*=\s*0x0*80(?:ULL?|ull?)?\s*;",
                "kWaitAbandoned0 has the wrong ABI value",
            )

    def test_release_returns_failure_after_atomic_owner_verification(self) -> None:
        require_pattern(
            self.kmutex_h_code,
            r"\bbool\s+KMutexRelease\s*\(\s*KMutex\s*\*",
            "KMutexRelease cannot report non-owner failure",
        )
        release = function_body(self.kmutex_cpp, r"bool\s+KMutexRelease")
        owner_check = require_pattern(
            release,
            r"(?:__atomic_load_n\s*\(\s*&)?m->owner_tid(?:\s*,\s*__ATOMIC_\w+\s*\))?\s*!=\s*(?:sched::)?CurrentTaskId\s*\(\s*\)",
            "release does not reject the wrong immutable Task identity",
        )
        self.assertRegex(release[owner_check.end() : owner_check.end() + 300], r"\breturn\s+false\s*;")
        verified = require_pattern(
            release,
            r"if\s*\(\s*!\s*(?:sched::)?SchedUntrackCurrentAbandonableOwnership\s*\(\s*&m->ownership_node\s*\)\s*\)",
            "outer release does not atomically verify/untrack the current owner",
        )
        failure = require_pattern(
            release[verified.end() : verified.end() + 300],
            r"\breturn\s+false\s*;",
            "owner mismatch succeeds",
        )
        outer_clear = require_pattern(
            release,
            r"(?:__atomic_store_n\s*\(\s*&m->(?:held|owner_tid)\s*,|m->(?:held|owner_tid)\s*=)",
            "outer release never clears KMutex ownership state",
        )
        self.assertGreater(outer_clear.start(), verified.start() + failure.end())
        unlock = require_pattern(
            release,
            r"\b(?:sched::)?MutexUnlock\s*\(\s*&m->inner\s*\)",
            "outer release never unlocks",
        )
        self.assertGreater(unlock.start(), verified.start() + failure.end())
        self.assertRegex(release, r"\breturn\s+true\s*;")


if __name__ == "__main__":
    unittest.main()
