#!/usr/bin/env python3
"""Structural contract for Process runtime teardown and exit admission."""

from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
PROCESS_H = ROOT / "kernel" / "proc" / "process.h"
PROCESS_CPP = ROOT / "kernel" / "proc" / "process.cpp"
SCHED_CPP = ROOT / "kernel" / "sched" / "sched.cpp"
SYSCALL_CPP = ROOT / "kernel" / "syscall" / "syscall.cpp"
PIDFD_CPP = ROOT / "kernel" / "subsystems" / "linux" / "pidfd_splice.cpp"
DBG_CORE_CPP = ROOT / "kernel" / "apps" / "dbg_core.cpp"
LEAK_DETECTOR_CPP = ROOT / "kernel" / "diag" / "leak_detector.cpp"
GDB_MONITOR_H = ROOT / "kernel" / "diag" / "gdb_monitor.h"
GDB_MONITOR_CPP = ROOT / "kernel" / "diag" / "gdb_monitor.cpp"
GDB_MONITOR_READ_CPP = ROOT / "kernel" / "diag" / "gdb_monitor_read.cpp"
GDB_SERVER_CPP = ROOT / "kernel" / "diag" / "gdb_server.cpp"
SMP_CPP = ROOT / "kernel" / "arch" / "x86_64" / "smp.cpp"
LINUX_PROC_CPP = ROOT / "kernel" / "subsystems" / "linux" / "syscall_proc.cpp"
SHELL_EXEC_CPP = ROOT / "kernel" / "shell" / "shell_exec.cpp"


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

        # C++ digit separators (for example 100'000ULL) are not character
        # literals. Treat an apostrophe between identifier/number characters
        # as code so it cannot blank an arbitrary later source region.
        if (
            source[index] == "'"
            and index > 0
            and index + 1 < len(source)
            and source[index - 1].isalnum()
            and source[index + 1].isalnum()
        ):
            index += 1
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


def matching_brace(source: str, opening: int) -> int:
    if opening < 0 or source[opening] != "{":
        raise AssertionError("missing opening brace")
    depth = 0
    for index in range(opening, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return index
    raise AssertionError("unterminated brace region")


def function_body(source: str, signature: str) -> str:
    code = code_only(source)
    for match in re.finditer(signature + r"\s*\(", code):
        opening = code.find("{", match.end())
        semicolon = code.find(";", match.end(), opening if opening >= 0 else None)
        if opening >= 0 and semicolon < 0:
            return code[opening + 1 : matching_brace(code, opening)]
    raise AssertionError(f"missing function definition: {signature}")


def type_body(source: str, signature: str) -> str:
    code = code_only(source)
    match = re.search(signature, code)
    if match is None:
        raise AssertionError(f"missing type definition: {signature}")
    opening = code.find("{", match.end())
    return code[opening + 1 : matching_brace(code, opening)]


def case_body(source: str, label: str) -> str:
    code = code_only(source)
    match = re.search(rf"\bcase\s+{re.escape(label)}\s*:", code)
    if match is None:
        raise AssertionError(f"missing switch case: {label}")
    opening = code.find("{", match.end())
    if opening < 0:
        raise AssertionError(f"missing body for switch case: {label}")
    return code[opening + 1 : matching_brace(code, opening)]


def require_order(body: str, *needles: str) -> None:
    cursor = -1
    for needle in needles:
        position = body.find(needle, cursor + 1)
        if position < 0:
            raise AssertionError(f"missing ordered token: {needle}")
        if position <= cursor:
            raise AssertionError(f"token is out of order: {needle}")
        cursor = position


class ProcessRuntimeAccessContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.process_h = PROCESS_H.read_text(encoding="utf-8")
        cls.process_cpp = PROCESS_CPP.read_text(encoding="utf-8")
        cls.sched_cpp = SCHED_CPP.read_text(encoding="utf-8")
        cls.syscall_cpp = SYSCALL_CPP.read_text(encoding="utf-8")
        cls.pidfd_cpp = PIDFD_CPP.read_text(encoding="utf-8")
        cls.dbg_core_cpp = DBG_CORE_CPP.read_text(encoding="utf-8")
        cls.leak_detector_cpp = LEAK_DETECTOR_CPP.read_text(encoding="utf-8")
        cls.gdb_monitor_h = GDB_MONITOR_H.read_text(encoding="utf-8")
        cls.gdb_monitor_cpp = GDB_MONITOR_CPP.read_text(encoding="utf-8")
        cls.gdb_monitor_read_cpp = GDB_MONITOR_READ_CPP.read_text(encoding="utf-8")
        cls.gdb_server_cpp = GDB_SERVER_CPP.read_text(encoding="utf-8")
        cls.smp_cpp = SMP_CPP.read_text(encoding="utf-8")
        cls.linux_proc_cpp = LINUX_PROC_CPP.read_text(encoding="utf-8")
        cls.shell_exec_cpp = SHELL_EXEC_CPP.read_text(encoding="utf-8")

    def test_parser_rejects_comment_string_and_raw_string_spoofs(self) -> None:
        hostile = r'''
// ScopedProcessRuntimeAccess target_runtime(target);
const char* a = "ProcessCompleteExitFromReaper(dead_process)";
const char* b = R"tag(case SYS_VM_FREE: { AddressSpaceUnmapUserPage(target->as, va); })tag";
const char* c = "FindStoppedProc(pid, &p, &vm_quiescent)";
case SYS_VM_FREE: { return; }
'''
        visible = code_only(hostile)
        self.assertNotIn("ScopedProcessRuntimeAccess", visible)
        self.assertNotIn("ProcessCompleteExitFromReaper", visible)
        self.assertNotIn("FindStoppedProc", visible)
        body = case_body(hostile, "SYS_VM_FREE")
        self.assertNotIn("AddressSpaceUnmapUserPage", body)

    def test_runtime_admission_is_lifecycle_checked_under_vm_mutex(self) -> None:
        declaration = type_body(self.process_h, r"class\s+ScopedProcessRuntimeAccess\s+final")
        self.assertIn("explicit operator bool() const", declaration)
        self.assertIn("void Unlock()", declaration)

        constructor = function_body(
            self.process_cpp,
            r"ScopedProcessRuntimeAccess::ScopedProcessRuntimeAccess",
        )
        require_order(
            constructor,
            "MutexLock(&m_process->vm_transaction_lock)",
            "ProcessLifecycleLoad(m_process)",
            "ProcessLifecycleState::Published",
            "m_process->as == nullptr",
            "MutexUnlock(&m_process->vm_transaction_lock)",
            "m_process = nullptr",
        )

    def test_reaper_delegates_only_after_exiting_publication(self) -> None:
        reaper = function_body(self.sched_cpp, r"\[\[noreturn\]\]\s+void\s+ReaperMain")
        require_order(
            reaper,
            "ProcessLifecycleTransition(dead_process, ProcessLifecycleState::Published",
            "ProcessLifecycleState::Exiting",
            "JobOnProcessExit(core::ProcessKeySnapshot(dead_process))",
            "ProcessCompleteExitFromReaper(dead_process)",
            "ProcessRelease(dead_process)",
        )

    def test_runtime_teardown_precedes_exited_and_observer_wakes(self) -> None:
        teardown = function_body(self.process_cpp, r"void\s+TeardownProcessRuntimeResources")
        require_order(
            teardown,
            "const ProcessKey process_key = ProcessKeySnapshot(p)",
            "ProcessDropOwnedProcessHandles(p)",
            "JobDrainOwned(process_key)",
            "DetachAllWin32SectionRows(p, &section_drain)",
            "AddressSpaceRelease(p->as)",
            "p->as = nullptr",
            "HandleTableDrain(p->kobj_handles)",
            "StdinFocusClearIf(p)",
            "ReleaseProcessSecurityOwners(p",
            "ReleaseProcessResourceDomainOwner(p",
        )
        self.assertNotIn("JobOnProcessExit", teardown)
        self.assertNotIn("KFree(p)", teardown)

        resource_release = function_body(self.process_cpp, r"void\s+ReleaseProcessResourceDomainOwner")
        require_order(
            resource_release,
            "const ResourceDomainKey doomed = process->resource_domain",
            "process->resource_domain = kInvalidResourceDomainKey",
            "ResourceDomainRelease(doomed)",
        )

        completion = function_body(self.process_cpp, r"void\s+ProcessCompleteExitFromReaper")
        require_order(
            completion,
            "TeardownProcessRuntimeResources(process, true)",
            "ProcessLifecycleTransition(process, ProcessLifecycleState::Exiting, ProcessLifecycleState::Exited)",
            "__atomic_sub_fetch(&g_live_processes",
            "QueueLinuxParentExit(process)",
            # Exact-pid waiters share this queue, so one exit must wake every
            # selector to prevent the wrong waiter from consuming the wake.
            "WaitQueueWakeAll(&parent_to_wake->linux_wait_wq)",
            "LinuxPidfdExitWake()",
        )

    def test_private_abort_cleans_without_published_exit_callbacks(self) -> None:
        release = function_body(self.process_cpp, r"void\s+ProcessRelease")
        private = release.index("lifecycle == ProcessLifecycleState::Private")
        exited = release.index("lifecycle == ProcessLifecycleState::Exited")
        private_branch = release[private:exited]
        self.assertIn("TeardownProcessRuntimeResources(p, false)", private_branch)
        self.assertNotIn("JobOnProcessExit", private_branch)
        self.assertNotIn("QueueLinuxParentExit", private_branch)
        self.assertNotIn("LinuxPidfdExitWake", private_branch)

        exited_branch = release[exited:]
        self.assertNotIn("TeardownProcessRuntimeResources", exited_branch)
        self.assertNotIn("AddressSpaceRelease", release)
        self.assertNotIn("HandleTableDrain", release)
        self.assertEqual(release.count("mm::KFree(p)"), 1)

        teardown = function_body(self.process_cpp, r"void\s+TeardownProcessRuntimeResources")
        for callback in (
            "CompositorLock()",
            "TrackPopupCancelByOwner(p->pid)",
            "GdiReapByOwner(p->pid)",
            "SocketReleaseByOwner(p->pid)",
            "StdinFocusClearIf(p)",
        ):
            with self.subTest(private_guarded_callback=callback):
                callback_at = teardown.index(callback)
                guarded_prefix = teardown[:callback_at]
                self.assertRegex(guarded_prefix[-2500:], r"if\s*\(\s*observable_exit\s*\)")

        drop_handles = function_body(self.process_cpp, r"void\s+ProcessDropOwnedProcessHandles")
        require_order(
            drop_handles,
            "targets[i] == p",
            "__atomic_load_n(&p->refcount",
            "PanicWithValue(",
            "ProcessRelease(targets[i])",
        )

    def test_external_runtime_syscalls_admit_before_first_target_access(self) -> None:
        cases = {
            "SYS_PROCESS_VM_READ": "CrossAsTransfer(target",
            "SYS_PROCESS_VM_QUERY": "AddressSpaceProbePteRaw(target->as",
            "SYS_VM_ALLOCATE": "AddressSpaceReserveUserRange(target->as",
            "SYS_VM_FREE": "AddressSpaceUnmapUserPage(target->as",
            "SYS_VM_PROTECT": "AddressSpaceProtectUserPage(target->as",
            "SYS_SECTION_MAP": "SectionMapAndRetainView(section_ref.Get(), target->as",
            "SYS_SECTION_UNMAP": "SectionUnmapAndReleaseView(claim.key, target->as",
            "kProcessHandleCount": "HandleTableLiveCount(target->kobj_handles)",
        }
        for label, first_access in cases.items():
            with self.subTest(case=label):
                body = case_body(self.syscall_cpp, label)
                require_order(
                    body,
                    "ScopedProcessRuntimeAccess target_runtime(target)",
                    "if (!target_runtime)",
                    "kStatusProcessIsTerminating",
                    first_access,
                )

    def test_pidfd_operations_admit_before_scheduler_or_fd_access(self) -> None:
        getfd = function_body(self.pidfd_cpp, r"i64\s+DoPidfdGetfd")
        require_order(
            getfd,
            "ScopedProcessRuntimeAccess target_runtime(target.Get())",
            "SchedProcessAlive(target_pid)",
            "target_fd = util::MaskedIndex(target_fd, kLinuxFdCap)",
            "LinuxFdExport(target.Get()",
            "LinuxFdImportLowest(caller",
            "LinuxFdTransferRelease(&transfer)",
        )
        self.assertNotIn("target->linux_fds", getfd)

        send_signal = function_body(self.pidfd_cpp, r"i64\s+DoPidfdSendSignal")
        require_order(
            send_signal,
            "ScopedProcessRuntimeAccess target_runtime(target.Get())",
            "SchedProcessAlive(target_pid)",
            "LinuxSignalDeliver(target.Get()",
        )

    def test_debug_core_admits_before_address_space_access(self) -> None:
        functions = {
            r"usize\s+EnumerateProcesses": "AddressSpaceUserPageCount(p->as)",
            r"bool\s+LookupProcess": "AddressSpaceUserPageCount(p->as)",
            r"u64\s+ReadMem": "AddressSpaceReadUserMemory(p->as",
            r"u64\s+WriteMem": "AddressSpaceWriteUserMemory(p->as",
            r"usize\s+ScanBytes": "mm::AddressSpace* as = p->as",
        }
        for signature, first_access in functions.items():
            with self.subTest(function=signature):
                body = function_body(self.dbg_core_cpp, signature)
                require_order(
                    body,
                    "ScopedProcessRuntimeAccess runtime_access(p)",
                    "if (!runtime_access)",
                    first_access,
                )

    def test_blocking_diagnostics_admit_before_drained_table_or_vm_access(self) -> None:
        leak_functions = {
            r"void\s+ResolveTaskAgg": "HandleTableLiveCount(p->kobj_handles)",
            r"bool\s+LeakDetectorSnapshotPid": "HandleTableLiveCount(p->kobj_handles)",
        }
        for signature, first_access in leak_functions.items():
            with self.subTest(leak_function=signature):
                body = function_body(self.leak_detector_cpp, signature)
                require_order(
                    body,
                    "ScopedProcessRuntimeAccess runtime_access(p)",
                    "if (!runtime_access)",
                    first_access,
                )

    def test_gdb_stop_context_is_complete_for_the_exact_acknowledged_generation(self) -> None:
        stop_context = type_body(self.gdb_monitor_h, r"struct\s+GdbMonitorStopContext")
        for field in ("generation", "expected_mask", "acknowledged_mask", "complete"):
            with self.subTest(stop_context_field=field):
                self.assertRegex(stop_context, rf"\b{field}\b")

        acknowledged = function_body(self.smp_cpp, r"u64\s+GdbAcknowledgedPeerMask")
        self.assertIn("__atomic_load_n(&peer->gdb_frozen_generation, __ATOMIC_ACQUIRE) == generation", acknowledged)

        rendezvous = function_body(self.smp_cpp, r"GdbStopRendezvous\s+SmpStopBroadcastNmiAndWait")
        require_order(
            rendezvous,
            "result.generation = NextGdbStopGeneration()",
            "GdbAcknowledgedPeerMask(result.expected_mask, result.generation)",
            "result.missing_mask = result.expected_mask & ~result.acknowledged_mask",
            "result.complete = result.missing_mask == 0",
        )

        enter = function_body(self.gdb_server_cpp, r"void\s+GdbServerEnterAndWait")
        require_order(
            enter,
            "SmpStopBroadcastNmiAndWait(kGdbStopRendezvousSpinBudget)",
            "SmpGdbStopGeneration() != rendezvous.generation",
            "g_stop_rendezvous = rendezvous",
            "SendStop(reason)",
            "SmpStopReleaseNmi(g_stop_rendezvous.generation)",
        )

        peer_check = function_body(self.gdb_server_cpp, r"bool\s+PeerAcknowledgedForCurrentStop")
        self.assertIn("g_stop_rendezvous.acknowledged_mask & bit", peer_check)
        self.assertIn("SmpGdbStopGeneration() != g_stop_rendezvous.generation", peer_check)
        self.assertIn(
            "__atomic_load_n(&peer->gdb_frozen_generation, __ATOMIC_ACQUIRE) != g_stop_rendezvous.generation",
            peer_check,
        )

        packet = function_body(self.gdb_server_cpp, r"void\s+HandlePacket")
        require_order(
            packet,
            "GdbMonitorStopContext stop_context",
            ".generation = g_stop_rendezvous.generation",
            ".expected_mask = g_stop_rendezvous.expected_mask",
            ".acknowledged_mask = g_stop_rendezvous.acknowledged_mask",
            ".complete = g_stop_rendezvous.complete",
            "GdbMonitorDispatch(mon_cmd, dn, w, &stop_context)",
        )

        dispatch = function_body(self.gdb_monitor_cpp, r"bool\s+GdbMonitorDispatch")
        require_order(dispatch, "!stop_context->complete", "mon_internal::CmdPs(out)")

    def test_gdb_readers_use_stopped_borrows_and_no_wait_runtime_access(self) -> None:
        clean_read = code_only(self.gdb_monitor_read_cpp)
        for forbidden in (
            "ScopedProcessRuntimeAccess",
            "SchedFindProcessByPidRetained",
            "ProcessRetain(",
            "ProcessRelease(",
            "SpinLockGuard",
            "MutexLock(",
            "MutexTryLock(",
        ):
            with self.subTest(forbidden_blocking_or_owning_api=forbidden):
                self.assertNotIn(forbidden, clean_read)

        stopped_lookup = function_body(self.gdb_monitor_read_cpp, r"core::ErrorCode\s+FindStoppedProc")
        require_order(
            stopped_lookup,
            "SchedFindProcessByPidStopped(pid, process_out, vm_quiescent_out)",
            "ProcessLifecycleLoad(*process_out)",
            "ProcessLifecycleState::Published",
        )

        scheduler_lookup = function_body(self.sched_cpp, r"core::ErrorCode\s+SchedFindProcessByPidStopped")
        require_order(
            scheduler_lookup,
            "SpinLockTryGuard guard(g_sched_lock)",
            "if (!guard)",
            "*process_out = process",
            "process->vm_transaction_lock.owner == nullptr",
            "process->vm_transaction_lock.waiters.head == nullptr",
            "process->vm_transaction_lock.waiters.tail == nullptr",
        )
        self.assertNotIn("ProcessRetain(", scheduler_lookup)
        self.assertNotIn("ScopedProcessRuntimeAccess", scheduler_lookup)

        readers = {
            r"void\s+CmdCaps": ("ProcessCapsTrySnapshotNoExpire(p, &caps)", False),
            r"void\s+CmdHandles": ("SpinLockTryGuard handle_guard(p->kobj_handles.lock)", False),
            r"void\s+CmdVm": ("const mm::AddressSpace* as = p->as", True),
            r"void\s+CmdMods": ("p->dll_image_count", True),
            r"void\s+CmdWin32": ("custom::GetState(p)", True),
        }
        for signature, (first_access, needs_vm_quiescence) in readers.items():
            with self.subTest(gdb_reader=signature):
                body = function_body(self.gdb_monitor_read_cpp, signature)
                require_order(
                    body,
                    "FindStoppedProc(pid, &p, &vm_quiescent)",
                    "lookup != core::ErrorCode::Ok",
                    first_access,
                )
                if needs_vm_quiescence:
                    require_order(body, "FindStoppedProc(pid, &p, &vm_quiescent)", "if (!vm_quiescent)", first_access)

    def test_signal_and_shell_callers_admit_before_runtime_use(self) -> None:
        tgkill = function_body(self.linux_proc_cpp, r"i64\s+DoTgkill")
        require_order(
            tgkill,
            "ScopedProcessRuntimeAccess target_runtime(target.Get())",
            "if (!target_runtime)",
            "if (sig == 0)",
            "SchedProcessAlive(target->pid)",
            "LinuxSignalDeliver(target.Get()",
        )
        kill = function_body(self.linux_proc_cpp, r"i64\s+DoKill")
        require_order(
            kill,
            "ScopedProcessRuntimeAccess target_runtime(target)",
            "if (!target_runtime)",
            "SchedProcessAlive(target->pid)",
            "LinuxSignalDeliver(target",
        )

        tkill = function_body(self.linux_proc_cpp, r"i64\s+DoTkill")
        self.assertNotIn("DoTgkill", tkill)
        require_order(
            tkill,
            "SchedFindProcessByTidRetained(tid)",
            "ScopedProcessRuntimeAccess target_runtime(target.Get())",
            "if (!target_runtime)",
            "if (sig == 0)",
            "SchedProcessAlive(target->pid)",
            "LinuxSignalDeliver(target.Get()",
        )
        rt_sigqueue = function_body(self.linux_proc_cpp, r"i64\s+DoRtSigqueueinfo")
        self.assertIn("DoKill(tgid, sig)", rt_sigqueue)
        self.assertNotIn("DoTgkill", rt_sigqueue)

        triage = function_body(self.shell_exec_cpp, r"void\s+CmdPeTriage")
        self.assertGreaterEqual(triage.count("ScopedProcessRuntimeAccess runtime_access(p)"), 2)
        first_print = triage.index("PrintProcessTriage(p, pid)")
        self.assertLess(triage.index("ScopedProcessRuntimeAccess runtime_access(p)"), first_print)
        last_guard = triage.rfind("ScopedProcessRuntimeAccess runtime_access(p)")
        last_count_read = triage.rfind("p->win32_iat_miss_count")
        self.assertLess(last_guard, last_count_read)

    def test_stdin_focus_owns_and_pins_process_across_cpus(self) -> None:
        header_code = code_only(self.process_h)
        self.assertNotIn("ProcessFeedStdinChar", header_code)
        self.assertNotIn("StdinFocusGet", header_code)
        self.assertNotIn("StdinFocusSet", header_code)

        claim = function_body(self.process_cpp, r"void\s+StdinFocusClaimIfEmpty")
        require_order(
            claim,
            "ProcessRetain(process)",
            "ScopedProcessRef candidate(process)",
            "ScopedProcessRuntimeAccess runtime_access(process)",
            "if (!runtime_access)",
            "SpinLockGuard focus_guard(g_stdin_focus_lock)",
            "g_stdin_focus == nullptr",
            "g_stdin_focus = candidate.Detach()",
        )

        clear = function_body(self.process_cpp, r"void\s+StdinFocusClearIf")
        require_order(
            clear,
            "SpinLockGuard focus_guard(g_stdin_focus_lock)",
            "detached = g_stdin_focus",
            "g_stdin_focus = nullptr",
            "ProcessRelease(detached)",
        )

        feed = function_body(self.process_cpp, r"void\s+ProcessFeedStdinFocusChar")
        require_order(
            feed,
            "SpinLockGuard focus_guard(g_stdin_focus_lock)",
            "ProcessRetain(g_stdin_focus)",
            "process = g_stdin_focus",
            "ScopedProcessRef focus_pin(process)",
            "ScopedProcessRuntimeAccess runtime_access(process)",
            "if (!runtime_access)",
            "Process::StdinRing& r = process->stdin_ring",
            "WaitQueueWakeOne(&r.waiters)",
        )

        read = function_body(self.process_cpp, r"i64\s+ProcessReadStdinBlocking")
        require_order(read, "StdinFocusClaimIfEmpty(proc)", "Process::StdinRing& r = proc->stdin_ring")


if __name__ == "__main__":
    unittest.main()
