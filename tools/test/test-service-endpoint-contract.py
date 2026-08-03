#!/usr/bin/env python3
"""Structural guards for dormant authenticated service endpoint publication."""

from __future__ import annotations

import pathlib
import re
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
ENDPOINT_HEADER = (ROOT / "kernel/core/service_endpoint.h").read_text(encoding="utf-8")
ENDPOINT_SOURCE = (ROOT / "kernel/core/service_endpoint.cpp").read_text(encoding="utf-8")
DIRECTORY_HEADER = (ROOT / "kernel/core/service_directory.h").read_text(encoding="utf-8")
DIRECTORY_SOURCE = (ROOT / "kernel/core/service_directory.cpp").read_text(encoding="utf-8")
ENDPOINT_TEST = (ROOT / "tests/host/test_service_endpoint.cpp").read_text(encoding="utf-8")
DIRECTORY_TEST = (ROOT / "tests/host/test_service_directory.cpp").read_text(encoding="utf-8")
HOST_CMAKE = (ROOT / "tests/host/CMakeLists.txt").read_text(encoding="utf-8")
WIKI = (ROOT / "wiki/kernel/Service-Bootstrap.md").read_text(encoding="utf-8")


def body_between(source: str, start: str, end: str) -> str:
    return source[source.index(start) : source.index(end, source.index(start))]


def assert_order(test: unittest.TestCase, source: str, *tokens: str) -> None:
    cursor = 0
    for token in tokens:
        found = source.find(token, cursor)
        test.assertGreaterEqual(found, 0, token)
        cursor = found + len(token)


def cpp_code_only(source: str) -> str:
    """Remove comments and literals before searching for C++ allocation syntax."""
    return re.sub(
        r'//[^\n]*|/\*.*?\*/|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'',
        "",
        source,
        flags=re.DOTALL,
    )


class ServiceEndpointContract(unittest.TestCase):
    def test_owner_is_fixed_storage_with_exact_nonwrapping_identity(self) -> None:
        for token in (
            "kServiceEndpointOwnerCapacity = 32",
            "kServiceEndpointGenerationMaximum = (1ULL << 51) - 1",
            "u32 slot;",
            "u64 generation;",
            "ipc::ChannelEpoch channel_epoch;",
            "ServiceEndpointRole role;",
            "ipc::ChannelCore core;",
            "ServiceEndpointObject endpoints[ipc::kChannelCoreDirectionCount]",
            "ServiceEndpointOwnerSlot slots[kServiceEndpointOwnerCapacity]",
            "g_last_endpoint_generations[kServiceEndpointOwnerCapacity]",
        ):
            self.assertIn(token, ENDPOINT_HEADER + ENDPOINT_SOURCE)
        self.assertNotRegex(cpp_code_only(ENDPOINT_SOURCE), r"\bnew\b")
        self.assertNotIn("KHeap", ENDPOINT_SOURCE)

    def test_protocol_and_exact_peer_credentials_are_stored_by_value(self) -> None:
        endpoint_object = body_between(
            ENDPOINT_HEADER, "struct ServiceEndpointObject", "struct ServiceEndpointOwnerReceipt"
        )
        self.assertIn("ServiceEndpointProtocolAuthority protocol;", endpoint_object)
        self.assertIn("ServiceEndpointPeerSnapshot peer;", endpoint_object)
        self.assertIn("ProcessKey process;", ENDPOINT_HEADER)
        self.assertIn("ServiceEndpointCredentialSnapshot credential;", ENDPOINT_HEADER)
        create = body_between(ENDPOINT_SOURCE, "ServiceEndpointCreatePair(", "ServiceEndpointActivate(")
        for token in (
            "protocol_snapshot = *protocol",
            "initiator_snapshot = *initiator",
            "acceptor_snapshot = *acceptor",
            "selected.endpoints[0].peer = acceptor_snapshot",
            "selected.endpoints[1].peer = initiator_snapshot",
        ):
            self.assertIn(token, create)

    def test_protocol_authority_freezes_wire_route_and_method_mapping(self) -> None:
        for token in (
            "u32 wire_service_id;",
            "u32 reserved32;",
            "sizeof(ServiceEndpointProtocolAuthority) == 48",
            "wire_service_id) == 40",
            "reserved32) == 44",
            "kServiceEndpointProtocolVersionMaximum = 0xFFFFU",
            "authority.protocol_version <= kServiceEndpointProtocolVersionMaximum",
            "method_id > 64",
            "u64{1} << (method_id - 1U)",
        ):
            self.assertIn(token, ENDPOINT_HEADER + ENDPOINT_SOURCE)
        self.assertNotIn("u64 reserved;", body_between(
            ENDPOINT_HEADER, "struct ServiceEndpointProtocolAuthority", "bool ServiceEndpointProtocolAuthorityIsCanonical"
        ))

    def test_direction_borrow_requires_both_object_and_exact_core_pins(self) -> None:
        acquire = body_between(
            ENDPOINT_SOURCE, "ServiceEndpointAcquireOperation(", "ServiceEndpointBorrowDirection("
        )
        assert_order(self, acquire, "KObjectAcquire(retained_object)", "ChannelCoreAcquireOperation")
        self.assertIn("ServiceEndpointOperation{endpoint, identity, pinned.pin}", acquire)

        borrow = body_between(
            ENDPOINT_SOURCE, "ServiceEndpointBorrowDirection(", "ServiceEndpointReserveRequest("
        )
        self.assertIn("ServiceEndpointOperationIsValid", borrow)
        self.assertIn("ChannelCoreBorrowDirection", borrow)
        self.assertIn("operation->core_pin", borrow)

        release = body_between(
            ENDPOINT_SOURCE, "ServiceEndpointReleaseOperation(", "ServiceEndpointInspectObject("
        )
        assert_order(self, release, "ChannelCoreReleaseOperation", "drive_drain", "KObjectRelease")
        self.assertIn("slot->state == ServiceEndpointSlotState::Draining", release)

    def test_one_shared_drain_and_recycle_gate_cover_every_owner(self) -> None:
        recycle = body_between(ENDPOINT_SOURCE, "bool TryRecycleLocked", "ipc::ChannelCoreDirection")
        for token in (
            "ServiceEndpointSlotState::Drained",
            "slot.outer_owner_live",
            "slot.drain_driver_active",
            "slot.endpoint_reference_live[0]",
            "slot.endpoint_reference_live[1]",
            "ChannelCoreDetachedCleanupIsEmpty",
        ):
            self.assertIn(token, recycle)

        drain = body_between(ENDPOINT_SOURCE, "ServiceEndpointStatus DriveDrain", "void DestroyEndpointObject")
        assert_order(
            self,
            drain,
            "slot->drain_driver_active = true",
            "ChannelCoreDrainExpected",
            "DeliverRequestCleanup",
            "ChannelCoreReleaseDetachedCleanup",
            "ServiceEndpointSlotState::Drained",
            "slot->drain_driver_active = false",
            "TryRecycleLocked",
        )
        cleanup = body_between(ENDPOINT_SOURCE, "ServiceEndpointStatus DeliverRequestCleanup", "ServiceEndpointStatus MapDrainStatus")
        self.assertLess(cleanup.index("EndpointRequestKeyIsValid"), cleanup.index("sink.consume"))

    def test_connect_publication_is_invisible_private_and_failure_atomic(self) -> None:
        connect = body_between(DIRECTORY_SOURCE, "ServiceDirectoryConnect(", "ServiceDirectoryAccept(")
        assert_order(
            self,
            connect,
            "HandleTableReserve",
            "ServiceEndpointCreatePair",
            "PendingClientPublish",
            "EnqueueTailLocked",
            "InvokePublicationHook",
            "HandleTablePublish",
            "ServiceEndpointActivate",
            "ServiceDirectoryQueuedChannelState::Ready",
        )
        for token in (
            "HandleTableAbort",
            "HandleTableDetach",
            "ServiceDirectoryDrainOwnedChannel",
            "ServiceDirectoryStatus::QueueFull",
            "ServiceDirectoryStatus::Closing",
        ):
            self.assertIn(token, DIRECTORY_SOURCE)

    def test_accept_has_exact_tracker_and_explicit_release_hook(self) -> None:
        accept = body_between(
            DIRECTORY_SOURCE, "ServiceDirectoryAccept(", "ServiceDirectoryReleaseAcceptedChannel("
        )
        assert_order(
            self,
            accept,
            "HandleTableReserve",
            "DequeueLocked",
            "AllocateAcceptedLocked",
            "InvokePublicationHook",
            "HandleTablePublish",
            "ServiceDirectoryAcceptedChannelState::Published",
        )
        for token in (
            "ServiceDirectoryAcceptedChannelKey",
            "Publishing",
            "Published",
            "Releasing",
            "release_driver_active",
            "ServiceDirectoryReleaseAcceptedChannel",
            "ServiceDirectoryReleaseAcceptedHandle",
        ):
            self.assertIn(token, DIRECTORY_HEADER + DIRECTORY_SOURCE)
        close_adapter = body_between(
            DIRECTORY_SOURCE,
            "ServiceDirectoryReleaseAcceptedResult ServiceDirectoryReleaseAcceptedHandle(",
            "ServiceEndpointStatus ServiceDirectoryDrainOwnedChannel(",
        )
        assert_order(
            self,
            close_adapter,
            "DirectoryGuard guard",
            "accepted.server_process == server_process",
            "accepted.server_handle != server_handle",
            "ServiceDirectoryReleaseAcceptedChannel(directory, &accepted_key)",
        )
        self.assertIn("generation-bearing handle", DIRECTORY_TEST)

    def test_owner_crash_detaches_queued_and_accepted_before_external_cleanup(self) -> None:
        close = body_between(DIRECTORY_SOURCE, "ServiceDirectoryCloseResult CloseEntry", "} // namespace")
        assert_order(
            self,
            close,
            "DirectoryGuard guard",
            "DequeueLocked",
            "ClearAcceptedLocked",
            "ServiceDirectoryDrainOwnedChannel",
        )
        self.assertIn("ServiceDirectoryOwnerCrashed", DIRECTORY_HEADER)
        self.assertIn("kServiceDirectoryCloseBatchCapacity", DIRECTORY_HEADER)
        self.assertIn("external_publishers", DIRECTORY_HEADER)

    def test_hostile_tests_build_and_dormant_boundary_are_registered(self) -> None:
        for token in (
            "add_host_test(service_endpoint)",
            "kernel/core/service_endpoint.cpp",
            "add_host_test(service_directory)",
            "kernel/core/service_directory.cpp",
            "kernel/ipc/handle_table.cpp",
        ):
            self.assertIn(token, HOST_CMAKE)
        for token in (
            "normal operation only drops",
            "close-vs-acquire stress",
            "full client table",
            "listener queue",
            "close-vs-connect",
            "owner-crash-vs-accept",
        ):
            self.assertIn(token, ENDPOINT_TEST + DIRECTORY_TEST)
        self.assertIn("COMPILED/DORMANT, AUTHENTICATED DIRECTORY-PUBLICATION SEAM", WIKI)
        self.assertIn("not a send/receive/wait syscall implementation", WIKI)
        self.assertIn(
            "No live boot path publishes an endpoint today",
            " ".join(WIKI.split()),
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
