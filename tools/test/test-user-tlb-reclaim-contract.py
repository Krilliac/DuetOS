#!/usr/bin/env python3
"""Structural contract checks for confirmed user-address-space reclamation."""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
ADDRESS_SPACE_CPP = ROOT / "kernel" / "mm" / "address_space.cpp"
ADDRESS_SPACE_H = ROOT / "kernel" / "mm" / "address_space.h"


def source_between(source: str, begin: str, end: str) -> str:
    start = source.index(begin)
    finish = source.index(end, start)
    return source[start:finish]


class UserTlbReclaimContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = ADDRESS_SPACE_CPP.read_text(encoding="utf-8")
        cls.header = ADDRESS_SPACE_H.read_text(encoding="utf-8")

    def test_barrier_uses_sparse_ready_confirmed_delivery(self) -> None:
        body = source_between(
            self.source,
            "void ConfirmedUserTlbShootdown(AddressSpace* as, u64 start, u64 end)",
            "// Allocate a fresh page-table frame",
        )

        pin = body.index("cpu::CriticalGuard critical_guard")
        mask = body.index("as->active_cpu_mask")
        sparse = body.index("arch::SmpGetPercpu(id)")
        ready = body.index("peer->tlb_ipi_ready")
        irq_gate = body.index("arch::ReadRflags() & kRflagsIf")
        delivery = body.index(
            "while (!cpu::IpiCallOne(id, &InvalidateUserTlbRange, &range, "
            "/*wait=*/true))"
        )

        self.assertLess(pin, mask)
        self.assertLess(mask, sparse)
        self.assertLess(sparse, ready)
        self.assertLess(ready, irq_gate)
        self.assertLess(irq_gate, delivery)
        self.assertNotIn("kSpinLimit", body)
        self.assertNotIn("SmpTlbShootdown", body)

    def test_callback_invalidates_every_page(self) -> None:
        callback = source_between(
            self.source,
            "void InvalidateUserTlbRange(void* opaque)",
            "void ConfirmedUserTlbShootdown",
        )
        self.assertIn(
            "for (u64 virt = range->start; virt < range->end; virt += kPageSize)",
            callback,
        )
        self.assertIn("Invlpg(virt)", callback)

    def test_cr3_reload_precedes_old_active_bit_retirement(self) -> None:
        activate = source_between(
            self.source,
            "void AddressSpaceActivate(AddressSpace* as)",
            "AddressSpace* AddressSpaceCurrent()",
        )

        publish_new = activate.index("__atomic_fetch_or(&as->active_cpu_mask")
        reload_cr3 = activate.index("arch::WriteCr3(cr3)")
        retire_old = activate.index("__atomic_fetch_and(&old_as->active_cpu_mask")
        self.assertLess(publish_new, reload_cr3)
        self.assertLess(reload_cr3, retire_old)

    def test_owned_frames_are_freed_only_after_confirmed_shootdown(self) -> None:
        unmap = source_between(
            self.source,
            "bool AddressSpaceUnmapUserPage(AddressSpace* as, u64 virt)",
            "bool AddressSpaceReleaseUserReservation",
        )
        shootdown = unmap.index("TlbShootdownAddr(as, retired.virt)")
        free_leaf = unmap.index("FreeFrame(retired.frame)")
        free_tables = unmap.index("ReleaseRetiredPageTables(retired.page_tables)")
        self.assertLess(shootdown, free_leaf)
        self.assertLess(shootdown, free_tables)

        helper = source_between(
            self.source,
            "void TlbShootdownAddr(AddressSpace* as, u64 virt)",
            "void TlbShootdownRange",
        )
        self.assertIn("ConfirmedUserTlbShootdown", helper)
        self.assertNotIn("arch::SmpTlbShootdown", helper)

    def test_public_contract_forbids_timeout_based_reuse(self) -> None:
        declaration = source_between(
            self.header,
            "/// Flush a single virtual address",
            "/// Boot-time self-test",
        )
        self.assertIn("does not return", declaration)
        self.assertIn("only after it returns", declaration)
        self.assertIn("requires IF=1", declaration)
        self.assertIn("full TLB flush before joining", declaration)


if __name__ == "__main__":
    unittest.main()
