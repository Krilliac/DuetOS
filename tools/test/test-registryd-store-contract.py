#!/usr/bin/env python3
"""Structural guards for registryd's allocation-free durable store core."""

from __future__ import annotations

import pathlib
import re
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
BASE = ROOT / "userland/native-apps/registryd"
HEADER = (BASE / "registry_store.h").read_text(encoding="utf-8")
INTERNAL = (BASE / "registry_store_internal.h").read_text(encoding="utf-8")
STORE = (BASE / "registry_store.c").read_text(encoding="utf-8")
VALIDATE = (BASE / "registry_validate.c").read_text(encoding="utf-8")
PERSISTENCE = (BASE / "registry_persistence.c").read_text(encoding="utf-8")
RECOVERY = (BASE / "registry_recovery.c").read_text(encoding="utf-8")
SOURCE = "\n".join((STORE, VALIDATE, PERSISTENCE, RECOVERY))
HOST_TEST = (ROOT / "tests/host/test_registryd_store.cpp").read_text(encoding="utf-8")


class RegistrydStoreContract(unittest.TestCase):
    def test_boundary_is_bounded_freestanding_and_authority_free(self) -> None:
        for token in (
            "REGISTRYD_STORE_MAX_ENTRIES 64U",
            "REGISTRYD_STORE_MAX_CLIENTS 16U",
            "REGISTRYD_STORE_MAX_KEY_BYTES 127U",
            "REGISTRYD_STORE_MAX_VALUE_BYTES 256U",
            "uint8_t bytes[REGISTRYD_STORE_STORAGE_BYTES]",
            "RegistrydSnapshotEntry entries[REGISTRYD_STORE_MAX_ENTRIES]",
            "RegistrydSnapshotClient clients[REGISTRYD_STORE_MAX_CLIENTS]",
        ):
            self.assertIn(token, HEADER + INTERNAL + SOURCE)
        self.assertNotRegex(SOURCE, r"\b(?:malloc|calloc|realloc|free|new|delete)\s*\(")
        self.assertNotRegex(SOURCE, r"\b(?:memcpy|memmove|memset|strlen|strcmp)\s*\(")
        for forbidden in ("kernel/", "Process", "Task", "Capability", "KObject", "Vfs", "KFile"):
            self.assertNotIn(forbidden, HEADER + INTERNAL + SOURCE)

    def test_mutation_is_wal_before_publish(self) -> None:
        prepare = STORE[STORE.index("RegistrydStorePrepareMutation") : STORE.index("static int PreparedMatches")]
        order = (
            "RegistrydStoreInternalCanonicalize",
            "CheckRequest",
            "CheckExpectedVersion",
            "state->commit_sequence == UINT64_MAX",
            "RegistrydStoreInternalEncodeWal",
            "state->pending.active = 1U",
        )
        cursor = 0
        for token in order:
            found = prepare.find(token, cursor)
            self.assertGreaterEqual(found, 0, token)
            cursor = found + len(token)
        commit = STORE[STORE.index("RegistrydStoreCommitMutation") : STORE.index("RegistrydStoreAbortMutation")]
        self.assertLess(commit.index("ApplyMutation"), commit.index("BytesZero(&state->pending"))

    def test_versions_requests_and_generations_fail_closed(self) -> None:
        for token in (
            "mutation->request_id < prior->mutation.request_id",
            "RegistrydStoreInternalMutationIsExact(mutation, &prior->mutation)",
            "REGISTRYD_STORE_REQUEST_ID_CONFLICT",
            "REGISTRYD_STORE_REPLAYED_REQUEST",
            "entry_generation != state->last_entry_generation + 1U",
            "sequence != state->commit_sequence + 1U",
            "REGISTRYD_STORE_GENERATION_EXHAUSTED",
            "expected_entry_generation",
        ):
            self.assertIn(token, SOURCE)

    def test_persistence_is_canonical_checksummed_and_bounded(self) -> None:
        for token in (
            "REGISTRYD_STORE_MAX_WAL_RECORD_BYTES",
            "REGISTRYD_STORE_MAX_SNAPSHOT_BYTES",
            "Crc32ZeroField",
            "CompareEntries",
            "client.mutation.client_identity < best_client.mutation.client_identity",
            "ReadLe32(record + 88U)",
            "ReadLe32(record + 92U)",
            "ReadLe32(snapshot + 40U)",
            "ReadLe32(snapshot + 44U)",
        ):
            self.assertIn(token, PERSISTENCE)

    def test_recovery_never_exposes_corrupt_partial_state(self) -> None:
        for token in (
            "RegistrydStoreInternalFailClosed(store)",
            "REGISTRYD_STORE_CORRUPT_SNAPSHOT",
            "REGISTRYD_STORE_CORRUPT_WAL",
            "WalPrefixCanBeTorn",
            "REGISTRYD_STORE_RECOVERED_TORN_WAL",
            "wal_bytes_ignored",
        ):
            self.assertIn(token, PERSISTENCE)
        self.assertGreaterEqual(PERSISTENCE.count("RegistrydStoreInternalFailClosed(store)"), 6)

    def test_torn_wal_tail_generation_continuity_checked_early(self) -> None:
        # A torn tail with only the 12-byte magic/version/header-size prefix
        # intact must still have its sequence/previous_sequence/
        # entry_generation triplet validated against recovered state as
        # soon as those bytes (offsets 16..39) are physically present --
        # not only once the full 96-byte header survived truncation.
        # Otherwise a corrupted (not genuinely truncated) tail that merely
        # matches the 12-byte prefix is silently accepted as benign.
        for token in (
            "REGISTRYD_WAL_TORN_SEQUENCE_BYTES 40U",
            "PersistZero(header, sizeof(*header))",
        ):
            self.assertIn(token, PERSISTENCE)
        self.assertNotIn("wal_size - cursor >= REGISTRYD_WAL_HEADER_SIZE", PERSISTENCE)
        recover = PERSISTENCE[PERSISTENCE.index("RegistrydStoreStatus RegistrydStoreRecover(") :]
        self.assertIn("wal_size - cursor >= REGISTRYD_WAL_TORN_SEQUENCE_BYTES", recover)

    def test_commit_mutation_fails_closed_on_apply_or_sanity_failure(self) -> None:
        # Both post-ApplyMutation failure exits of RegistrydStoreCommitMutation
        # must zero the store rather than leave a flagged-but-live state,
        # matching the fail-closed convention used throughout recovery.
        commit = STORE[STORE.index("RegistrydStoreCommitMutation") : STORE.index("RegistrydStoreAbortMutation")]
        self.assertEqual(commit.count("RegistrydStoreInternalFailClosed(store)"), 2)

    def test_hostile_host_test_covers_required_failures(self) -> None:
        for token in (
            "TestValidationVersionsAndDedup",
            "TestPrepareAbortDeleteAndDeterminism",
            "TestBoundsAndCapacity",
            "TestSnapshotWalRecoveryAndCorruption",
            "TestGenerationExhaustion",
            "TestConcurrentIndependentStores",
            "REGISTRYD_STORE_VERSION_CONFLICT",
            "REGISTRYD_STORE_DUPLICATE_REQUEST",
            "REGISTRYD_STORE_REQUEST_ID_CONFLICT",
            "REGISTRYD_STORE_RECOVERED_TORN_WAL",
            "REGISTRYD_STORE_CORRUPT_WAL",
            "REGISTRYD_STORE_CORRUPT_SNAPSHOT",
            "std::thread",
        ):
            self.assertIn(token, HOST_TEST)


if __name__ == "__main__":
    unittest.main()
