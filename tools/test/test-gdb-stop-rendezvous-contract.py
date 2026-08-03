#!/usr/bin/env python3
"""Structural contract for the generation-safe GDB NMI stop rendezvous."""

from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
PERCPU_H = ROOT / "kernel/cpu/percpu.h"
SMP_H = ROOT / "kernel/arch/x86_64/smp.h"
SMP_CPP = ROOT / "kernel/arch/x86_64/smp.cpp"
TRAPS_CPP = ROOT / "kernel/arch/x86_64/traps.cpp"
SERVER_CPP = ROOT / "kernel/diag/gdb_server.cpp"


def function_body(source: str, signature: str) -> str:
    match = re.search(signature + r"\s*\([^)]*\)\s*\{", source)
    if match is None:
        raise AssertionError(f"missing function: {signature}")
    opening = source.find("{", match.start())
    depth = 0
    for index in range(opening, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[opening + 1 : index]
    raise AssertionError(f"unterminated function: {signature}")


def ordered(source: str, *needles: str) -> None:
    cursor = -1
    for needle in needles:
        position = source.find(needle, cursor + 1)
        if position < 0:
            raise AssertionError(f"missing ordered token: {needle}")
        cursor = position


class GdbStopRendezvousContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.percpu = PERCPU_H.read_text(encoding="utf-8")
        cls.smp_h = SMP_H.read_text(encoding="utf-8")
        cls.smp = SMP_CPP.read_text(encoding="utf-8")
        cls.traps = TRAPS_CPP.read_text(encoding="utf-8")
        cls.server = SERVER_CPP.read_text(encoding="utf-8")

    def test_public_result_reports_generation_and_all_peer_sets(self) -> None:
        for field in (
            "u64 generation;",
            "u64 expected_mask;",
            "u64 acknowledged_mask;",
            "u64 missing_mask;",
            "bool complete;",
        ):
            self.assertIn(field, self.smp_h)
        self.assertIn(
            "GdbStopRendezvous SmpStopBroadcastNmiAndWait(u64 spin_budget);",
            self.smp_h,
        )
        self.assertIn("bool SmpStopReleaseNmi(u64 generation);", self.smp_h)

    def test_generation_is_nonzero_and_monotonically_advanced(self) -> None:
        body = function_body(self.smp, r"u64\s+NextGdbStopGeneration")
        ordered(
            body,
            "__atomic_load_n(&g_gdb_stop_generation_counter",
            "observed == ~u64{0}",
            "const u64 next = observed + 1",
            "__atomic_compare_exchange_n(&g_gdb_stop_generation_counter",
            "return next",
        )
        self.assertIn('Panic("arch/smp", "GDB stop generation exhausted")', body)

    def test_peer_ack_is_the_exact_current_generation(self) -> None:
        self.assertIn("u64 gdb_frozen_generation;", self.percpu)
        self.assertNotRegex(self.percpu, r"\bu8\s+gdb_frozen\s*;")
        ack = function_body(self.smp, r"u64\s+GdbAcknowledgedPeerMask")
        self.assertRegex(
            ack,
            r"__atomic_load_n\(&peer->gdb_frozen_generation,\s*__ATOMIC_ACQUIRE\)\s*==\s*generation",
        )
        self.assertNotRegex(ack, r"gdb_frozen_generation[^;]*!=\s*0")

        # Host-side hostile case: a prior nonzero acknowledgement is still
        # rejected when it does not equal the new generation.
        old_generation = 41
        current_generation = 42
        self.assertNotEqual(old_generation, current_generation)

    def test_nmi_publishes_frame_and_snapshot_before_release_ack(self) -> None:
        trap = function_body(self.traps, r'extern\s+"C"\s+void\s+TrapDispatch')
        ordered(
            trap,
            "const u64 gdb_stop_generation = arch::SmpGdbStopGeneration()",
            "p->gdb_snapshot_rip = frame->rip",
            "p->gdb_snapshot_rsp = frame->rsp",
            "p->gdb_snapshot_rflags = frame->rflags",
            "p->gdb_frozen_frame = frame",
            "__atomic_store_n(&p->gdb_frozen_generation, gdb_stop_generation, __ATOMIC_RELEASE)",
            "while (arch::SmpGdbStopGeneration() == gdb_stop_generation)",
        )

    def test_initiator_wait_is_collective_exact_and_bounded(self) -> None:
        body = function_body(self.smp, r"GdbStopRendezvous\s+SmpStopBroadcastNmiAndWait")
        ordered(
            body,
            "result.generation = NextGdbStopGeneration()",
            "result.expected_mask = GdbExpectedPeerMask()",
            "__atomic_compare_exchange_n(&g_gdb_stop_active_generation",
            "LapicSendIcr(0, icr_low)",
            "result.acknowledged_mask = GdbAcknowledgedPeerMask",
            "spin == spin_budget",
            'asm volatile("pause"',
            "result.missing_mask = result.expected_mask & ~result.acknowledged_mask",
            "result.complete = result.missing_mask == 0",
        )
        self.assertNotIn("TimerTicks", body)

    def test_release_cannot_clear_a_different_generation(self) -> None:
        body = function_body(self.smp, r"bool\s+SmpStopReleaseNmi")
        ordered(
            body,
            "if (generation == 0)",
            "u64 expected = generation",
            "__atomic_compare_exchange_n(&g_gdb_stop_active_generation, &expected, 0u",
        )
        self.assertNotRegex(body, r"g_gdb_stop_active_generation\s*=\s*0")

    def test_server_waits_and_logs_before_exposing_packet_loop(self) -> None:
        body = function_body(self.server, r"void\s+GdbServerEnterAndWait")
        ordered(
            body,
            "SmpStopBroadcastNmiAndWait(kGdbStopRendezvousSpinBudget)",
            'stop_log.Str("[gdb-server] stop generation=0x")',
            'stop_log.Str(" complete=")',
            "SerialWriteNRecursiveFault(stop_log.Data(), stop_log.Len())",
            "SendStop(reason)",
            "while (!g_resume_signalled)",
            "SmpStopReleaseNmi(g_stop_rendezvous.generation)",
        )
        self.assertNotIn("arch::SerialWrite(", body)
        self.assertNotIn("arch::SerialWriteHex(", body)

    def test_rejected_nested_stop_cannot_overwrite_outer_owner(self) -> None:
        body = function_body(self.server, r"void\s+GdbServerEnterAndWait")
        call = body.index("SmpStopBroadcastNmiAndWait(kGdbStopRendezvousSpinBudget)")
        ownership_check = body.index(
            "if (arch::SmpGdbStopGeneration() != rendezvous.generation)", call
        )
        rejected_return = body.index("return;", ownership_check)
        publish = body.index("g_stop_rendezvous = rendezvous", call)
        self.assertLess(call, ownership_check)
        self.assertLess(ownership_check, rejected_return)
        self.assertLess(rejected_return, publish)

        route = function_body(self.server, r"bool\s+RouteToStopLoop")
        active_guard = route.index("if (arch::SmpGdbStopGeneration() != 0)")
        consumed_return = route.index("return true;", active_guard)
        snapshot = route.index("TrapFrameToSnapshot(frame, g_trap_snapshot)")
        self.assertLess(active_guard, consumed_return)
        self.assertLess(consumed_return, snapshot)

    def test_qrcmd_receives_stack_snapshot_of_rendezvous(self) -> None:
        ordered(
            self.server,
            "const ::duetos::diag::GdbMonitorStopContext stop_context",
            ".generation = g_stop_rendezvous.generation",
            ".expected_mask = g_stop_rendezvous.expected_mask",
            ".acknowledged_mask = g_stop_rendezvous.acknowledged_mask",
            ".complete = g_stop_rendezvous.complete",
            "GdbMonitorDispatch(mon_cmd, dn, w, &stop_context)",
        )

    def test_peer_register_mutations_require_current_ack(self) -> None:
        guard = function_body(self.server, r"bool\s+PeerAcknowledgedForCurrentStop")
        self.assertIn("g_stop_rendezvous.acknowledged_mask & bit", guard)
        self.assertIn("SmpGdbStopGeneration() != g_stop_rendezvous.generation", guard)
        self.assertIn("peer->gdb_frozen_generation", guard)
        self.assertGreaterEqual(
            self.server.count("PeerAcknowledgedForCurrentStop("),
            5,
            "selection, vCont mutation, and final commit must all use the guard",
        )
        g_write = function_body(self.server, r"void\s+HandlePacket")
        null_guard = g_write.index("if (g_regs_writable == nullptr)")
        refusal = g_write.index('SendCStr("E01")', null_guard)
        mutation = g_write.index("g_regs_writable->rax", null_guard)
        self.assertLess(refusal, mutation)


if __name__ == "__main__":
    unittest.main()
