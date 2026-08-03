#!/usr/bin/env python3
"""Structural contract checks for kernel-stack TLB-safe reclamation."""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
PAGING_CPP = ROOT / "kernel" / "mm" / "paging.cpp"
PAGING_H = ROOT / "kernel" / "mm" / "paging.h"
KSTACK_CPP = ROOT / "kernel" / "mm" / "kstack.cpp"
SCHED_CPP = ROOT / "kernel" / "sched" / "sched.cpp"
CONTEXT_SWITCH_S = ROOT / "kernel" / "sched" / "context_switch.S"


def source_between(source: str, begin: str, end: str) -> str:
    start = source.index(begin)
    finish = source.index(end, start)
    return source[start:finish]


class TlbShootdownContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.paging_cpp = PAGING_CPP.read_text(encoding="utf-8")
        cls.paging_h = PAGING_H.read_text(encoding="utf-8")
        cls.kstack_cpp = KSTACK_CPP.read_text(encoding="utf-8")
        cls.sched_cpp = SCHED_CPP.read_text(encoding="utf-8")
        cls.context_switch_s = CONTEXT_SWITCH_S.read_text(encoding="utf-8")

    def test_stack_frames_are_not_freed_before_confirmed_barrier(self) -> None:
        body = source_between(
            self.kstack_cpp,
            "void TearDownStackPages(u32 slot_index)",
            "bool FreelistPop(u32* out_slot)",
        )

        snapshot = body.index("PhysAddr frames[kKernelStackPages]")
        unmap = body.index("UnmapPage(base + i * kPageSize)")
        barrier = body.index(
            "KernelTlbReclaimBarrier(base, kKernelStackPages * kPageSize)"
        )
        free = body.index("FreeFrame(frames[i])")
        clear = body.index("g_slot_frames[slot_index][i] = kNullFrame")

        self.assertLess(snapshot, unmap)
        self.assertLess(unmap, barrier)
        self.assertLess(barrier, free)
        self.assertLess(free, clear)
        self.assertNotIn("FreeFrame(", body[:barrier])
        self.assertNotIn("SmpTlbShootdownRange", body)

    def test_barrier_uses_ready_confirmed_per_cpu_delivery(self) -> None:
        body = source_between(
            self.paging_cpp,
            "void KernelTlbReclaimBarrier(uptr virt, u64 len)",
            "void* MapMmio(PhysAddr phys, u64 bytes)",
        )

        pin = body.index("cpu::CriticalGuard critical_guard")
        ready = body.index("peer->tlb_ipi_ready")
        irq_gate = body.index("arch::ReadRflags() & kRflagsIf")
        delivery = body.index(
            "while (!cpu::IpiCallOne(id, &InvalidateKernelTlbRange, &range, "
            "/*wait=*/true))"
        )

        self.assertLess(pin, ready)
        self.assertLess(ready, irq_gate)
        self.assertLess(irq_gate, delivery)
        self.assertNotIn("kSpinLimit", body)
        self.assertNotIn("SmpTlbShootdown", body)

    def test_ipi_callback_invalidates_the_entire_range(self) -> None:
        callback = source_between(
            self.paging_cpp,
            "void InvalidateKernelTlbRange(void* opaque)",
            "inline u64 ReadMsr(u32 msr)",
        )
        self.assertIn(
            "for (uptr virt = range->start; virt < range->end; virt += kPageSize)",
            callback,
        )
        self.assertIn("Invlpg(virt)", callback)

    def test_public_contract_requires_barrier_before_reclamation(self) -> None:
        self.assertIn(
            "void KernelTlbReclaimBarrier(uptr virt, u64 len);", self.paging_h
        )
        declaration = source_between(
            self.paging_h,
            "/// Complete a reclamation barrier",
            "/// Map a contiguous physical region",
        )
        self.assertIn("must not free or reuse any backing frame", declaration)
        self.assertIn("delayed peers are waited out", declaration)

    def test_reaper_enables_interrupts_before_stack_reclamation(self) -> None:
        body = source_between(
            self.sched_cpp,
            "[[noreturn]] void ReaperMain(void*)",
            "void SchedStartReaper()",
        )

        loop = body.index("for (;;)")
        loop_body = body.index("{", loop)
        enable = body.index("arch::Sti();", loop_body)
        acquire = body.index("sync::SpinLockAcquire(g_sched_lock)", loop_body)
        stack_free = body.index("mm::FreeKernelStack(")
        reclaim_scope = body[body.rindex("if (dead->stack_base", 0, stack_free) : stack_free]

        self.assertGreater(enable, loop_body)
        self.assertLess(enable, acquire)
        self.assertLess(enable, stack_free)
        self.assertIn("cpu::CriticalNesting() == 0", reclaim_scope)
        self.assertIn("arch::ReadRflags()", reclaim_scope)
        self.assertIn("kernel-stack reclaim lost resumed-task IF", reclaim_scope)
        self.assertIn("arch::Sti();", reclaim_scope)

    def test_lock_handoff_restores_the_resumed_tasks_interrupt_state(self) -> None:
        finish = source_between(
            self.sched_cpp,
            'extern "C" void SchedFinishTaskSwitch(u64 resumed_lock_rflags)',
            "void SchedInit()",
        )
        handoff_tail = source_between(
            self.sched_cpp,
            "ContextSwitch(&prev->rsp, next->rsp);",
            "void SchedYield()",
        )

        self.assertIn("sync::IrqFlags flags{.rflags = resumed_lock_rflags}", finish)
        self.assertNotIn("flags{.rflags = pcpu->ctxsw_lock_flags}", finish)
        self.assertIn("SchedFinishTaskSwitch(lock_flags.rflags);", handoff_tail)

        trampoline = source_between(
            self.context_switch_s,
            "SchedTaskTrampoline:",
            ".size SchedTaskTrampoline",
        )
        zero = trampoline.index("xor     edi, edi")
        call = trampoline.index("call    SchedFinishTaskSwitch")
        enable = trampoline.index("sti", call)
        self.assertLess(zero, call)
        self.assertLess(call, enable)


if __name__ == "__main__":
    unittest.main()
