#!/usr/bin/env python3
"""Structural guards for the allocation-free thread-group metadata service.

These checks pin the isolation, exact-generation, lock, and terminal-lifetime
rules that are easy to weaken during later scheduler integration. They
complement the hosted behavioural and sanitizer test; they do not replace it.
"""

from __future__ import annotations

import pathlib
import re
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
HEADER = (ROOT / "kernel/proc/thread_group.h").read_text(encoding="utf-8")
SOURCE = (ROOT / "kernel/proc/thread_group.cpp").read_text(encoding="utf-8")
HOST_TEST = (ROOT / "tests/host/test_thread_group.cpp").read_text(encoding="utf-8")
HOST_CMAKE = (ROOT / "tests/host/CMakeLists.txt").read_text(encoding="utf-8")


def body(begin: str, end: str) -> str:
    start = SOURCE.index(begin)
    return SOURCE[start : SOURCE.index(end, start)]


def strip_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
    return re.sub(r"//[^\n]*", "", text)


class ThreadGroupContract(unittest.TestCase):
    def test_public_contract_is_bounded_and_opaque(self) -> None:
        for declaration in (
            "constexpr u32 kThreadGroupCapacity = 64;",
            "constexpr u32 kThreadGroupMemberCapacity = 64;",
            "constexpr u64 kThreadGroupGenerationMaximum = (1ULL << 51) - 1;",
            "struct ThreadGroupKey",
            "struct ThreadGroupMemberIdentity",
            "ThreadGroupMemberIdentity members[kThreadGroupMemberCapacity];",
        ):
            self.assertIn(declaration, HEADER)
        self.assertIn("identity.opaque != 0", HEADER)
        self.assertIn("key.generation != 0", HEADER)
        self.assertIn("key.generation <= kThreadGroupGenerationMaximum", HEADER)

    def test_module_remains_isolated_allocation_free_and_nonblocking(self) -> None:
        code = strip_comments(HEADER + "\n" + SOURCE)
        for forbidden in (
            '#include "proc/process.h"',
            '#include "sched/sched.h"',
            '#include "proc/job.h"',
            "Task*",
            "Process*",
            "new ",
            "delete ",
            "malloc",
            "KMalloc",
            "KFree",
            "std::vector",
            "WaitQueue",
            "SchedYield",
            "Sleep(",
            "Log(",
            "printf(",
        ):
            self.assertNotIn(forbidden, code)
        self.assertEqual(SOURCE.count("constinit sync::SpinLock g_thread_group_lock{};"), 1)
        self.assertEqual(SOURCE.count("sync::SpinLockGuard guard(g_thread_group_lock);"), 7)

    def test_exact_generation_resolution_and_nonwrapping_reuse(self) -> None:
        resolve = body("ThreadGroupRow* ResolveExactLocked(", "ThreadGroupKey AllocateLocked(")
        self.assertIn("ThreadGroupKeyIsValid(key)", resolve)
        self.assertIn("row.generation == key.generation ? &row : nullptr", resolve)

        allocate = body("ThreadGroupKey AllocateLocked(", "u32 MemberLowerBound(")
        self.assertIn("row.state != ThreadGroupState::Retired", allocate)
        self.assertIn("row.generation >= kThreadGroupGenerationMaximum", allocate)
        self.assertLess(allocate.index("++row.generation"), allocate.index("row.state = ThreadGroupState::Open"))
        self.assertNotIn("row.generation = 0", allocate)

    def test_state_transitions_and_final_release_are_fail_closed(self) -> None:
        state = HEADER[HEADER.index("enum class ThreadGroupState") :]
        state = state[: state.index("};")]
        positions = [state.index(name) for name in ("Retired", "Open", "Exiting")]
        self.assertEqual(positions, sorted(positions))

        release = body("bool ThreadGroupRelease(", "bool ThreadGroupAuthorityAttachMember(")
        final_gate = "row->owner_references == 1 && (row->state != ThreadGroupState::Exiting || row->member_count != 0)"
        self.assertIn(final_gate, release)
        self.assertLess(release.index(final_gate), release.index("--row->owner_references"))
        self.assertIn("row->state = ThreadGroupState::Retired", release)
        self.assertLess(release.index("row->state = ThreadGroupState::Retired"), release.index("*key = kInvalidThreadGroupKey"))

        attach = body(
            "bool ThreadGroupAuthorityAttachMember(",
            "ThreadGroupMutationResult ThreadGroupAuthorityDetachMember(",
        )
        self.assertIn("row->state != ThreadGroupState::Open", attach)
        self.assertIn("row->member_count >= kThreadGroupMemberCapacity", attach)

        begin_exit = body("ThreadGroupMutationResult ThreadGroupBeginExit(", "bool ThreadGroupInspectExact(")
        self.assertIn("ThreadGroupState::Exiting", begin_exit)
        self.assertIn("ThreadGroupMutationResult::AlreadySatisfied", begin_exit)
        self.assertIn("row->state = ThreadGroupState::Exiting", begin_exit)

    def test_owner_reference_saturation_precedes_increment(self) -> None:
        retain = body("bool ThreadGroupRetain(", "bool ThreadGroupRelease(")
        saturation = "row->owner_references == static_cast<u32>(~0U)"
        self.assertIn(saturation, retain)
        self.assertLess(retain.index(saturation), retain.index("++row->owner_references"))
        self.assertIn("HostSetActiveThreadGroupOwnerReferences", HOST_TEST)
        self.assertIn("kOwnerReferenceMaximum - 1U", HOST_TEST)
        self.assertIn("EXPECT_FALSE(ThreadGroupRetain(saturated))", HOST_TEST)

    def test_detach_is_exact_idempotent_and_canonical(self) -> None:
        detach = body(
            "ThreadGroupMutationResult ThreadGroupAuthorityDetachMember(",
            "ThreadGroupMutationResult ThreadGroupBeginExit(",
        )
        self.assertIn("MemberLowerBound(*row, member)", detach)
        self.assertIn("ThreadGroupMutationResult::AlreadySatisfied", detach)
        self.assertIn("--row->member_count", detach)
        self.assertIn("row->members[row->member_count] = kInvalidThreadGroupMemberIdentity", detach)

    def test_snapshot_copies_storage_and_clears_failures(self) -> None:
        inspect = SOURCE[SOURCE.index("bool ThreadGroupInspectExact(") :]
        self.assertIn("*out_snapshot = {};", inspect)
        self.assertIn("snapshot.members[index] = row->members[index]", inspect)
        self.assertIn("*out_snapshot = snapshot", inspect)
        self.assertNotIn("ThreadGroupRow*", HEADER)

    def test_hosted_test_exercises_lifetime_aba_exit_and_concurrency(self) -> None:
        for scenario in (
            "kLifecycleCycles = 10000",
            "kThreadGroupGenerationMaximum - 1U",
            "replacement.generation > stale.generation",
            "kConcurrentIterations = 2000",
            "kExitRaceCycles = 256",
            "kReleaseRetainRaceCycles = 512",
            "ThreadGroupRelease(&releasing_owner)",
            "ThreadGroupRetain(exact)",
            "std::barrier",
            "std::thread",
        ):
            self.assertIn(scenario, HOST_TEST)

    def test_host_target_is_registered_with_thread_support(self) -> None:
        self.assertIn("add_host_test(thread_group)", HOST_CMAKE)
        self.assertIn("target_link_libraries(test_thread_group PRIVATE Threads::Threads)", HOST_CMAKE)


if __name__ == "__main__":
    unittest.main()
