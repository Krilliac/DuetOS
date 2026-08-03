#!/usr/bin/env python3
"""Structural guards for authenticated native ServiceEndpoint ingress."""

from __future__ import annotations

import json
import pathlib
import re
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
ABI = json.loads((ROOT / "abi/native_syscalls.json").read_text(encoding="utf-8"))
PUBLIC = (ROOT / "userland/libc/include/duet/service_endpoint.h").read_text(encoding="utf-8")
LIBC = (ROOT / "userland/libc/src/syscall.c").read_text(encoding="utf-8")
INGRESS_HEADER = (ROOT / "kernel/syscall/service_endpoint_ingress.h").read_text(encoding="utf-8")
INGRESS_SOURCE = (ROOT / "kernel/syscall/service_endpoint_ingress.cpp").read_text(encoding="utf-8")
SYSCALL_HEADER = (ROOT / "kernel/syscall/syscall.h").read_text(encoding="utf-8")
SYSCALL_SOURCE = (ROOT / "kernel/syscall/syscall.cpp").read_text(encoding="utf-8")
SYSCALL_NAMES = (ROOT / "kernel/syscall/syscall_names.def").read_text(encoding="utf-8")
GENERATED_IDL = (ROOT / "kernel/syscall/syscall_idl_generated.def").read_text(encoding="utf-8")
GENERATED_LIBC = (ROOT / "userland/libc/include/duet/syscall_numbers_generated.h").read_text(encoding="utf-8")
PROCESS_SOURCE = (ROOT / "kernel/proc/process.cpp").read_text(encoding="utf-8")
HOST_TEST = (ROOT / "tests/host/test_service_endpoint_ingress.cpp").read_text(encoding="utf-8")


def body_between(source: str, start: str, end: str) -> str:
    begin = source.index(start)
    return source[begin : source.index(end, begin + len(start))]


def braced_block(source: str, marker: str) -> str:
    begin = source.index(marker)
    opening = source.index("{", begin)
    depth = 0
    for cursor in range(opening, len(source)):
        if source[cursor] == "{":
            depth += 1
        elif source[cursor] == "}":
            depth -= 1
            if depth == 0:
                return source[begin : cursor + 1]
    raise AssertionError(f"unterminated block after {marker!r}")


def assert_order(test: unittest.TestCase, source: str, *tokens: str) -> None:
    cursor = 0
    for token in tokens:
        found = source.find(token, cursor)
        test.assertGreaterEqual(found, 0, token)
        cursor = found + len(token)


class ServiceEndpointIngressContract(unittest.TestCase):
    def test_syscall_idl_and_generated_surfaces_are_exact(self) -> None:
        row = next(item for item in ABI["syscalls"] if item["name"] == "SYS_SERVICE_ENDPOINT_OP")
        self.assertEqual(227, row["number"])
        self.assertEqual("implemented", row["status"])
        self.assertEqual("dynamic", row["authorization"]["mode"])
        self.assertEqual("dynamic", row["object_rights"]["mode"])
        self.assertTrue(row["trace"]["sensitive"])
        self.assertEqual("ipc", row["trace"]["category"])
        self.assertEqual("mixed", row["fuzz"]["profile"])
        self.assertEqual(
            [("rdi", "user_buffer"), ("rsi", "size"), ("rdx", "user_buffer"), ("r10", "size")],
            [(arg["register"], arg["kind"]) for arg in row["arguments"]],
        )
        self.assertIn("SYS_SERVICE_ENDPOINT_OP = 227", SYSCALL_HEADER)
        self.assertIn("X(SYS_SERVICE_ENDPOINT_OP, 227)", SYSCALL_NAMES)
        self.assertIn(
            "DUETOS_NATIVE_SYSCALL(SYS_SERVICE_ENDPOINT_OP, 227, Dynamic, 0ULL, Dynamic, Ipc, Mixed)",
            GENERATED_IDL,
        )
        self.assertIn("DUET_SYS_SERVICE_ENDPOINT_OP = 227", GENERATED_LIBC)

    def test_public_request_is_versioned_pointer_free_and_authority_free(self) -> None:
        request = body_between(
            PUBLIC,
            "typedef struct duet_service_endpoint_request_v1",
            "typedef struct duet_service_endpoint_channel_identity_v1",
        )
        self.assertNotIn("*", request)
        for caller_claim in ("pid", "process", "credential", "task_identity", "authority_identity",
                             "protocol_identity", "allowed_methods"):
            self.assertNotIn(caller_claim, request)
        self.assertIn("uint64_t target_service_identity", request)
        self.assertIn("never protocol authority", request)
        for token in (
            "uint32_t struct_size",
            "uint16_t version",
            "uint16_t operation",
            "uint32_t frame_bytes",
            "uint64_t endpoint_handle",
            "uint64_t completion_receipt",
            "uint32_t transfer_reference",
            "uint16_t object_type",
            "sizeof(duet_service_endpoint_request_v1) == 72",
            "DUET_SERVICE_ENDPOINT_MAX_FRAME_BYTES 4096U",
        ):
            self.assertIn(token, PUBLIC)

    def test_connect_send_and_route_authority_layout_are_frozen(self) -> None:
        for token in (
            "DUET_SERVICE_ENDPOINT_OP_CONNECT = 8",
            "DUET_SERVICE_ENDPOINT_OP_SEND_REQUEST = 9",
            "uint64_t target_service_identity",
            "uint64_t reserved64",
            "uint32_t wire_service_id",
            "uint32_t reserved32",
            "offsetof(duet_service_endpoint_protocol_authority_v1, wire_service_id) == 40",
            "offsetof(duet_service_endpoint_protocol_authority_v1, reserved32) == 44",
            "sizeof(duet_service_endpoint_protocol_authority_v1) == 48",
            "sizeof(duet_service_endpoint_result_v1) == 456",
        ):
            self.assertIn(token, PUBLIC)
        request_check = braced_block(INGRESS_SOURCE, "bool RequestIsCanonical(")
        self.assertIn("request.operation != DUET_SERVICE_ENDPOINT_OP_CONNECT", request_check)
        self.assertIn("request.target_service_identity != 0", request_check)
        self.assertIn("case DUET_SERVICE_ENDPOINT_OP_CONNECT:", request_check)
        self.assertIn("case DUET_SERVICE_ENDPOINT_OP_SEND_REQUEST:", request_check)
        self.assertIn("request.frame_bytes >= ipc::kMessageAbiHeaderV1Bytes", request_check)

    def test_non_cancel_frames_require_exact_route_and_payload_version(self) -> None:
        validation = braced_block(INGRESS_SOURCE, "AuthorizedFrameValidation ValidateAuthorizedFrame(")
        assert_order(
            self,
            validation,
            "MessageValidate",
            "view.kind == ipc::MessageKind::Cancel",
            "ServiceEndpointProtocolAuthorityAllowsRoute",
            "view.payload_size == 0",
            "static_cast<u16>(authority.protocol_version)",
            "PayloadValidate",
        )
        self.assertNotIn("kOpaquePayloadV1Rule", INGRESS_SOURCE)

    def test_peer_identity_is_snapshot_only_and_task_absence_is_explicit(self) -> None:
        for token in (
            "duet_service_endpoint_process_key_v1 peer_process",
            "duet_service_endpoint_credential_v1 peer_credential",
            "DUET_SERVICE_ENDPOINT_RESULT_PEER_TASK_UNAVAILABLE",
            "Always zero in v1",
        ):
            self.assertIn(token, PUBLIC)
        fill = braced_block(INGRESS_SOURCE, "void FillEndpointInfo(")
        self.assertIn("peer.process.identity", fill)
        self.assertIn("peer.process.pid", fill)
        self.assertIn("result->peer_task_identity = 0", fill)
        self.assertIn("DUET_SERVICE_ENDPOINT_RESULT_PEER_TASK_UNAVAILABLE", fill)

    def test_receipts_hold_scalars_and_bind_process_plus_endpoint(self) -> None:
        receipt = body_between(
            INGRESS_HEADER,
            "struct ServiceEndpointIngressReceiptRow",
            "struct ServiceEndpointIngressCursorRow",
        )
        self.assertIn("ProcessKey owner", receipt)
        self.assertIn("ServiceEndpointIdentity endpoint", receipt)
        self.assertIn("EndpointRequestCompletionAuthority completion", receipt)
        self.assertNotIn("KObject*", receipt)
        self.assertNotIn("ServiceEndpointOperation", receipt)

        claim = braced_block(INGRESS_SOURCE, "AbiStatus ClaimReceipt(")
        assert_order(
            self,
            claim,
            "DecodeReceipt",
            "ProcessMatches(row.owner, owner)",
            "EndpointMatches(row.endpoint, endpoint)",
            "row.generation != generation",
            "row.state != ServiceEndpointIngressReceiptState::Live",
        )

    def test_ingress_lock_regions_make_no_external_subsystem_calls(self) -> None:
        regions = (
            braced_block(INGRESS_SOURCE, "PendingReceipt ReservePendingReceipt("),
            braced_block(INGRESS_SOURCE, "void AbandonReceipt("),
            braced_block(INGRESS_SOURCE, "bool PublishReceipt("),
            braced_block(INGRESS_SOURCE, "AbiStatus ClaimReceipt("),
            braced_block(INGRESS_SOURCE, "void FinishReceipt("),
            braced_block(INGRESS_SOURCE, "void CancelEndpointState("),
            braced_block(INGRESS_SOURCE, "u64 MintObjectIdentity("),
            braced_block(INGRESS_SOURCE, "u64 MintProtocolAuthorityIdentity("),
            braced_block(INGRESS_SOURCE, "void ServiceEndpointIngressCancelProcess("),
        )
        forbidden_calls = (
            "HandleTableLookupRef(",
            "HandleTableDetach(",
            "KObjectAcquire(",
            "KObjectRelease(",
            "KMessagePort",
            "ObjectTransfer",
            "ServiceDirectory",
            "ServiceEndpointAcquireOperation(",
            "ServiceEndpointReleaseOperation(",
            "ServiceEndpointBorrowDirection(",
        )
        for region in regions:
            self.assertIn("StateGuard guard", region)
            for forbidden in forbidden_calls:
                self.assertNotIn(forbidden, region)

    def test_wrapper_pins_bounded_output_before_acting_and_derives_current_authority(self) -> None:
        wrapper = body_between(INGRESS_SOURCE, "void DoServiceEndpointOp(", "#endif")
        assert_order(
            self,
            wrapper,
            "request_bytes > sizeof(duet_service_endpoint_request_v1) + DUET_SERVICE_ENDPOINT_MAX_FRAME_BYTES",
            "CopyFromUser(&request",
            "request_bytes != sizeof(request) + request.frame_bytes",
            "frame->rdi > ~u64{0}",
            "CopyFromUser(bounce.frame",
            "CurrentProcess()",
            "ProcessInspectCredentials",
            "ProcessKeySnapshot(process)",
            "ProcessCredentialKeySnapshot(process)",
            "ProcessCapsSnapshot(process)",
            "process->resource_domain",
            "AddressSpaceAcquireWriteLease",
            "DUETOS_DEFER",
            "ServiceEndpointIngressExecute",
            "AddressSpaceCopyToWriteLease",
        )
        self.assertIn("u8 frame[DUET_SERVICE_ENDPOINT_MAX_FRAME_BYTES]", wrapper)
        self.assertNotIn("ProbeUserWriteRange", wrapper)
        self.assertNotIn("CopyToUser", wrapper)
        self.assertNotIn(
            "request.version != DUET_SERVICE_ENDPOINT_ABI_VERSION",
            wrapper,
            "a safely snapshotted unknown version must receive structured BAD_VERSION",
        )
        self.assertNotIn("request.pid", wrapper)
        self.assertNotIn("request.process", wrapper)
        self.assertNotIn("request.service", wrapper)

    def test_foreign_receipt_probe_cannot_disclose_ledger_occupancy(self) -> None:
        claim = braced_block(INGRESS_SOURCE, "AbiStatus ClaimReceipt(")
        foreign = body_between(
            claim,
            "if (!ProcessMatches(row.owner, owner))",
            "if (!EndpointMatches(row.endpoint, endpoint))",
        )
        self.assertIn("DUET_SERVICE_ENDPOINT_STATUS_REPLAY_REJECTED", foreign)
        self.assertNotIn("row.state", foreign)
        self.assertNotIn("DUET_SERVICE_ENDPOINT_STATUS_ACCESS_DENIED", foreign)

    def test_operation_rights_and_transfer_policy_are_fail_closed(self) -> None:
        receive = braced_block(INGRESS_SOURCE, "void ExecuteReceive(")
        reply = braced_block(INGRESS_SOURCE, "void ExecuteReply(")
        export = braced_block(INGRESS_SOURCE, "void ExecuteExport(")
        import_ = braced_block(INGRESS_SOURCE, "void ExecuteImport(")
        close = braced_block(INGRESS_SOURCE, "AbiStatus CloseEndpointHandle(")
        self.assertIn("ipc::kHandleRightRead | ipc::kHandleRightWait", receive)
        self.assertIn("ipc::kHandleRightWrite", reply)
        self.assertIn("ipc::kHandleRightWrite", export)
        self.assertIn("ipc::kHandleRightRead", import_)
        self.assertIn("ipc::kHandleRightDestroy", close)
        for region in (export, import_):
            self.assertIn("HandleRightsForProcess", region)
            self.assertIn("request.requested_rights & ~ceiling", region)
        transfer_types = braced_block(INGRESS_SOURCE, "bool TransferTypeAllowed(")
        self.assertIn("KObjectType::ServiceEndpoint", transfer_types)
        self.assertIn("return false", transfer_types)

    def test_receive_reserves_before_consume_and_never_strands_pending_receipt(self) -> None:
        receive = braced_block(INGRESS_SOURCE, "void ExecuteReceive(")
        assert_order(
            self,
            receive,
            "ReservePendingReceipt",
            "KMessagePortTryReceive",
            "ServiceEndpointCommitReceivedRequest",
            "PublishReceipt",
            "AbandonReceipt",
            "DUET_SERVICE_ENDPOINT_STATUS_CANCELLED",
        )
        self.assertGreaterEqual(receive.count("AbandonReceipt"), 5)
        assert_order(
            self,
            receive,
            "ValidateAuthorizedFrame",
            "ServiceEndpointRejectReceivedRequest",
            "result->frame_bytes = received.copied_bytes",
            "ServiceEndpointCommitReceivedRequest",
            "PublishReceipt",
        )
        rejection = body_between(receive, "if (validation.status", "result->frame_bytes")
        self.assertIn("ServiceEndpointRejectReceivedRequest", rejection)
        self.assertNotIn("DUET_SERVICE_ENDPOINT_RESULT_HAS_FRAME", rejection)
        self.assertNotIn("PublishReceipt", rejection)

    def test_reply_sends_under_pin_then_completes_and_retires_receipt(self) -> None:
        reply = braced_block(INGRESS_SOURCE, "void ExecuteReply(")
        assert_order(
            self,
            reply,
            "AcquireEndpoint",
            "ValidateAuthorizedFrame",
            "ClaimReceipt",
            "completion.request_key().request_id != view.request_id",
            "ServiceEndpointBorrowDirection",
            "KMessagePortSend",
            "ServiceEndpointCompleteReceivedRequest",
            "FinishReceipt(state, caller.process, request.completion_receipt, true)",
        )
        self.assertIn("retire the receipt", reply)

    def test_send_request_is_validate_reserve_send_exact_rollback(self) -> None:
        send = braced_block(INGRESS_SOURCE, "void ExecuteSendRequest(")
        assert_order(
            self,
            send,
            "AcquireEndpoint",
            "ValidateAuthorizedFrame",
            "validation.view.kind != ipc::MessageKind::Request",
            "ServiceEndpointBorrowDirection",
            "ServiceEndpointReserveRequest",
            "KMessagePortSend",
            "ServiceEndpointCancelSentRequest",
            "EndpointRequestKeyIsValid(rollback)",
        )
        self.assertNotRegex(send, r"for\s*\([^)]*(retry|attempt)")

    def test_connect_derives_authority_and_retains_exact_busy_rollback(self) -> None:
        resolve = braced_block(INGRESS_SOURCE, "AbiStatus ResolveTargetService(")
        assert_order(
            self,
            resolve,
            "ServiceRuntimeBindActivationAuthorityV1",
            "target_service_identity",
            "ServiceProtocolPolicyResolveV1",
            "ServiceDirectoryNameIsCanonical",
        )
        connect = braced_block(INGRESS_SOURCE, "void ExecuteConnect(")
        assert_order(
            self,
            connect,
            "ResolveTargetService",
            "ReserveConnectRollbackSlot",
            "ServiceDirectoryLookup",
            "ServiceDirectoryInspectExact",
            "request.target_service_identity",
            "MintProtocolAuthorityIdentity",
            "ServiceProtocolPolicyBindV1",
            "ServiceDirectoryConnect",
            "ServiceDirectoryReleaseOperation",
            "RetainConnectRollback",
            "DriveConnectRollbackSlot",
        )
        self.assertNotIn("request.protocol", connect)
        self.assertNotIn("request.allowed_methods", connect)
        self.assertNotIn("request.wire_service_id", connect)

        rollback = body_between(
            INGRESS_HEADER,
            "struct ServiceEndpointIngressConnectRollbackRow",
            "struct ServiceEndpointIngressState",
        )
        self.assertIn("ServiceDirectory* directory", rollback)
        self.assertIn("ServiceDirectoryOwnedChannel channel", rollback)
        self.assertIn("ServiceEndpointIngressConnectRollbackState state", rollback)
        driver = braced_block(INGRESS_SOURCE, "ServiceEndpointStatus DriveConnectRollbackSlot(")
        assert_order(self, driver, "Driving", "ServiceDirectoryDrainOwnedChannel", "StateGuard guard")
        self.assertIn("row.state = ServiceEndpointIngressConnectRollbackState::Live", driver)
        self.assertIn("row = {}", driver)

    def test_process_teardown_cancels_before_handle_drain(self) -> None:
        teardown = braced_block(PROCESS_SOURCE, "void TeardownProcessRuntimeResources(")
        assert_order(
            self,
            teardown,
            "ServiceEndpointIngressCancelProcessKernel(process_key)",
            "TransferAcceptedServiceEndpointOwners(process_key)",
            "HandleTableDrain(p->kobj_handles)",
        )

    def test_dispatch_initialization_and_libc_r10_wiring_are_present(self) -> None:
        self.assertIn("ServiceEndpointIngressInitializeKernel()", SYSCALL_SOURCE)
        dispatch = body_between(SYSCALL_SOURCE, "case SYS_SERVICE_ENDPOINT_OP:", "case SYS_GFX_D3D_STUB:")
        self.assertIn("DoServiceEndpointOp(frame)", dispatch)
        wrapper = braced_block(LIBC, "long duet_service_endpoint_op(")
        self.assertIn("DUET_SYS_SERVICE_ENDPOINT_OP", wrapper)
        self.assertIn('"mov %5, %%r10', wrapper)
        self.assertIn('"r"((long)result_capacity)', wrapper)

    def test_hostile_host_fixture_covers_authority_and_replay_boundaries(self) -> None:
        for token in (
            "DUET_SERVICE_ENDPOINT_STATUS_BUFFER_TOO_SMALL",
            "ProcessKey{fixture.server_process.identity + 1U",
            "DUET_SERVICE_ENDPOINT_STATUS_REPLAY_REJECTED",
            "DUET_SERVICE_ENDPOINT_RESULT_PEER_TASK_UNAVAILABLE",
            "DUET_KOBJECT_SERVICE_ENDPOINT",
            "DUET_SERVICE_ENDPOINT_STATUS_UNSUPPORTED",
            "DUET_SERVICE_ENDPOINT_STATUS_RIGHTS_DENIED",
            "ServiceEndpointIngressCancelProcess",
            "last_committed_request_sequence, 1ULL",
            "next_protocol_authority_identity, 1ULL",
            "ConnectRollbacksAreFree",
            "g_directory_lookup_calls, 0U",
            "g_last_connect_protocol.allowed_methods, 0x3ULL",
            "ServiceEndpointIngressConnectRollbackState::Live",
            "drains_before_settlement + 1U",
            "wrong_route_request",
            "wrong_version_request",
            "wrong_route_reply",
            "wrong_version_reply",
            "rejected_route.frame_bytes, 0U",
            "rejected_version.frame_bytes, 0U",
        ):
            self.assertIn(token, HOST_TEST)


if __name__ == "__main__":
    unittest.main(verbosity=2)
