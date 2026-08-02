#!/usr/bin/env python3
"""Structural guard for failure-atomic unpublished HandleTable publication."""

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[2]
HEADER = (ROOT / "kernel/ipc/handle_table.h").read_text(encoding="utf-8")
SOURCE = (ROOT / "kernel/ipc/handle_table.cpp").read_text(encoding="utf-8")
SELFTEST = (ROOT / "kernel/ipc/handle_table_selftest.cpp").read_text(encoding="utf-8")
BOOT = (ROOT / "kernel/core/boot_bringup.cpp").read_text(encoding="utf-8")
KERNEL_CMAKE = (ROOT / "kernel/CMakeLists.txt").read_text(encoding="utf-8")


class HandlePublicationReservationContract(unittest.TestCase):
    def test_reserved_is_a_distinct_invisible_slot_state(self) -> None:
        self.assertRegex(HEADER, r"enum class HandleSlotState[\s\S]*\bReserved\s*=\s*4")
        self.assertIn("u64 reservation_nonce;", HEADER)
        self.assertIn("KObjectType reserved_type;", HEADER)
        self.assertRegex(SOURCE, r"SlotMatches\([^)]*\)[\s\S]*HandleSlotState::Live")
        self.assertNotRegex(
            SOURCE,
            r"SlotMatches\([^)]*\)[\s\S]{0,220}HandleSlotState::Reserved",
        )

    def test_ticket_is_nonce_bound_and_publication_adopts_only_on_success(self) -> None:
        for token in (
            "struct HandleTableReservation",
            "HandleTableReserve(HandleTable& table",
            "HandleTablePublish(HandleTable& table",
            "HandleTableAbort(HandleTable& table",
            "MintHandleReservationNonce",
            "ReservationMatches",
        ):
            self.assertIn(token, HEADER + SOURCE)
        publish = SOURCE.split("HandleTablePublish(HandleTable& table", 1)[1].split(
            "HandleTableAbort(HandleTable& table", 1
        )[0]
        self.assertIn("KObjectRefcount(obj) == 0", publish)
        self.assertIn("slot.reserved_type != obj->type", publish)
        self.assertIn("slot.obj = obj;", publish)
        self.assertIn("slot.state = HandleSlotState::Live;", publish)
        self.assertNotIn("KObjectAcquire", publish)
        self.assertNotIn("KObjectRelease", publish)

    def test_service_endpoint_has_an_append_only_object_tag_and_channel_rights(self) -> None:
        kobject_header = (ROOT / "kernel/ipc/kobject.h").read_text(encoding="utf-8")
        kobject_source = (ROOT / "kernel/ipc/kobject.cpp").read_text(encoding="utf-8")
        self.assertIn("ServiceEndpoint = 9", kobject_header)
        self.assertIn('return "service-endpoint";', kobject_source)
        self.assertRegex(
            SOURCE,
            r"case KObjectType::ServiceEndpoint:[\s\S]{0,180}kHandleRightRead\s*\|\s*"
            r"kHandleRightWrite\s*\|\s*kHandleRightWait",
        )

    def test_abort_and_drain_consume_no_object_reference(self) -> None:
        abort = SOURCE.split("HandleTableAbort(HandleTable& table", 1)[1].split(
            "HandleTableLookupRef", 1
        )[0]
        self.assertIn("slot.state = ClosedStateFor(slot);", abort)
        self.assertNotIn("KObjectAcquire", abort)
        self.assertNotIn("KObjectRelease", abort)
        drain = SOURCE.split("void HandleTableDrain", 1)[1]
        self.assertIn("slot.state == HandleSlotState::Reserved", drain)
        self.assertIn("slot.reservation_nonce = 0;", drain)
        self.assertIn("slot.reserved_type = KObjectType::Invalid;", drain)

    def test_drain_waits_for_release_callbacks_before_publishing_closed(self) -> None:
        drain = SOURCE.split("void HandleTableDrain", 1)[1]
        release = drain.index("KObjectRelease(victims[i]);")
        publish_closed = drain.index("table.state = HandleTableState::Closed;")
        self.assertLess(release, publish_closed)
        self.assertIn("concurrent drain returned before destroy callback completed", SELFTEST)

    def test_boot_selftest_covers_hostile_and_terminal_paths(self) -> None:
        for phrase in (
            "unpublished reservation became observable",
            "wrong reservation nonce published",
            "cross-table reservation published",
            "wrong-type publication consumed caller ownership",
            "consumed publication ticket replayed",
            "terminal reservation generation did not retire",
            "drain consumed unpublished caller ownership",
        ):
            self.assertIn(phrase, SELFTEST)

    def test_selftests_are_extracted_built_and_registered_atomically(self) -> None:
        for function in (
            "HandleTableSelfTest",
            "HandleRightsSelfTest",
            "HandleTableContentionSelfTest",
        ):
            self.assertNotRegex(SOURCE, rf"void\s+{function}\s*\(")
            self.assertRegex(SELFTEST, rf"void\s+{function}\s*\(")
        self.assertRegex(
            BOOT,
            r'InitcallRegisterOrPanic\(duetos::core::Phase::Sched,\s*"handle-table-contention-selftest",'
            r"[\s\S]{0,400}HandleTableContentionSelfTest\(\)",
        )
        self.assertIn("DUETOS_BOOT_SELFTEST(duetos::ipc::HandleTableSelfTest());", BOOT)
        self.assertIn("duetos::ipc::HandleRightsSelfTest();", BOOT)
        self.assertIn("file(GLOB_RECURSE DUETOS_KERNEL_SHARED_SOURCES", KERNEL_CMAKE)
        self.assertIn('"${CMAKE_CURRENT_SOURCE_DIR}/*.cpp"', KERNEL_CMAKE)


if __name__ == "__main__":
    unittest.main(verbosity=2)
