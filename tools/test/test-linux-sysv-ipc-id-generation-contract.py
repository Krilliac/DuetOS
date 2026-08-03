#!/usr/bin/env python3
"""Hostile contract for stale-safe generation-bearing Linux SysV IPC IDs."""

from __future__ import annotations

import re
import unittest
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
HEADER = (ROOT / "kernel/subsystems/linux/syscall_internal.h").read_text(encoding="utf-8")
MSG_SOURCE = (ROOT / "kernel/subsystems/linux/msg_queues.cpp").read_text(encoding="utf-8")
SYSV_SOURCE = (ROOT / "kernel/subsystems/linux/sysv_ipc.cpp").read_text(encoding="utf-8")

INDEX_BITS = 3
FAMILY_BITS = 2
GENERATION_SHIFT = INDEX_BITS + FAMILY_BITS
POOL_CAPACITY = 1 << INDEX_BITS
GENERATION_MAX = (1 << (31 - GENERATION_SHIFT)) - 1
ID_MAX = (1 << 31) - 1
SHARED_MEMORY = 1
SEMAPHORE = 2
MESSAGE_QUEUE = 3


def encode(family: int, index: int, generation: int) -> int:
    if not 0 < family < (1 << FAMILY_BITS):
        return 0
    if not 0 <= index < POOL_CAPACITY:
        return 0
    if not 0 < generation <= GENERATION_MAX:
        return 0
    return (generation << GENERATION_SHIFT) | (family << INDEX_BITS) | index


def decode(raw_id: int, expected_family: int) -> tuple[int, int] | None:
    if raw_id <= 0 or raw_id > ID_MAX:
        return None
    family = (raw_id >> INDEX_BITS) & ((1 << FAMILY_BITS) - 1)
    generation = raw_id >> GENERATION_SHIFT
    if family != expected_family or generation == 0:
        return None
    return raw_id & (POOL_CAPACITY - 1), generation


@dataclass
class ModelSlot:
    generation: int = 0
    in_use: bool = False
    key: int = 0


class ModelPool:
    """Small executable lifecycle oracle for the fixed-pool ID contract."""

    def __init__(self, family: int) -> None:
        self.family = family
        self.slots = [ModelSlot() for _ in range(POOL_CAPACITY)]

    def get(self, key: int, *, publish: bool = True) -> int | None:
        if key != 0:
            for index, slot in enumerate(self.slots):
                if slot.in_use and slot.key == key:
                    return encode(self.family, index, slot.generation)
        for index, slot in enumerate(self.slots):
            if slot.in_use or slot.generation >= GENERATION_MAX:
                continue
            # Reservation consumes the generation even when publication fails.
            slot.generation += 1
            if not publish:
                return None
            slot.in_use = True
            slot.key = key
            return encode(self.family, index, slot.generation)
        return None

    def rmid(self, public_id: int) -> bool:
        decoded = decode(public_id, self.family)
        if decoded is None:
            return False
        index, generation = decoded
        slot = self.slots[index]
        if not slot.in_use or slot.generation != generation:
            return False
        slot.in_use = False
        slot.key = 0
        return True

    def initial_lookup(self, public_id: int) -> str:
        decoded = decode(public_id, self.family)
        if decoded is None:
            return "EINVAL"
        index, generation = decoded
        slot = self.slots[index]
        return "OK" if slot.in_use and slot.generation == generation else "EINVAL"

    def blocked_recheck(self, public_id: int) -> str:
        return "OK" if self.initial_lookup(public_id) == "OK" else "EIDRM"


def code_only(source: str) -> str:
    """Blank comments and quoted literals while preserving offsets and braces."""
    masked = list(source)

    def blank(begin: int, end: int) -> None:
        for offset in range(begin, end):
            if masked[offset] not in "\r\n":
                masked[offset] = " "

    index = 0
    while index < len(source):
        if source.startswith("//", index):
            end = source.find("\n", index + 2)
            end = len(source) if end < 0 else end
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
        if source[index] == "'" and index > 0 and index + 1 < len(source):
            if source[index - 1].isdigit() and source[index + 1].isdigit():
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


def matching(source: str, opening: int, left: str, right: str) -> int:
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
    for match in re.finditer(signature + r"\s*\(", code):
        opening_paren = code.find("(", match.start())
        closing_paren = matching(code, opening_paren, "(", ")")
        opening_brace = code.find("{", closing_paren + 1)
        declaration_end = code.find(";", closing_paren + 1)
        if declaration_end >= 0 and (opening_brace < 0 or declaration_end < opening_brace):
            continue
        if opening_brace >= 0:
            return code[opening_brace + 1 : matching(code, opening_brace, "{", "}")]
    raise AssertionError(f"missing function definition: {signature}")


def struct_body(source: str, name: str) -> str:
    code = code_only(source)
    match = re.search(rf"struct\s+{name}\s*\{{(?P<body>.*?)\}}\s*;", code, re.S)
    if match is None:
        raise AssertionError(f"missing struct: {name}")
    return match.group("body")


def require_order(body: str, *needles: str) -> None:
    positions = [body.find(needle) for needle in needles]
    if any(position < 0 for position in positions) or positions != sorted(positions):
        raise AssertionError(f"required order absent: {needles!r}; positions={positions!r}")


class LinuxSysvIpcIdGenerationContract(unittest.TestCase):
    def test_layout_is_positive_roundtrippable_and_family_separated(self) -> None:
        self.assertIn("SharedMemory = 1", HEADER)
        self.assertIn("Semaphore = 2", HEADER)
        self.assertIn("MessageQueue = 3", HEADER)
        self.assertIn("kSysvIpcIdGenerationShift", HEADER)
        self.assertIn("kSysvIpcIdMax = 0x7FFFFFFFu", HEADER)
        self.assertIn("generation == 0", function_body(HEADER, r"inline\s+constexpr\s+u32\s+SysvIpcEncodeId"))
        decoder = function_body(HEADER, r"inline\s+constexpr\s+bool\s+SysvIpcDecodeId")
        self.assertIn("raw_id > kSysvIpcIdMax", decoder)
        self.assertIn("family != static_cast<u32>(expected_family)", decoder)
        self.assertIn("generation == 0", decoder)

        for family in (SHARED_MEMORY, SEMAPHORE, MESSAGE_QUEUE):
            for index in (0, POOL_CAPACITY - 1):
                for generation in (1, GENERATION_MAX):
                    public_id = encode(family, index, generation)
                    self.assertGreater(public_id, 0)
                    self.assertLessEqual(public_id, ID_MAX)
                    self.assertEqual(decode(public_id, family), (index, generation))
                    for other in (SHARED_MEMORY, SEMAPHORE, MESSAGE_QUEUE):
                        if other != family:
                            self.assertIsNone(decode(public_id, other))
        self.assertEqual(encode(MESSAGE_QUEUE, 7, GENERATION_MAX), ID_MAX)

    def test_malformed_and_cross_family_ids_fail_before_pool_access(self) -> None:
        malformed = (0, -1, ID_MAX + 1, 1 << 63, SHARED_MEMORY << INDEX_BITS)
        for raw_id in malformed:
            for family in (SHARED_MEMORY, SEMAPHORE, MESSAGE_QUEUE):
                self.assertIsNone(decode(raw_id, family))

        cases = (
            (MSG_SOURCE, r"i64\s+DoMsgsnd", "msqid", "MessageQueue", "g_sysv_pool[idx]"),
            (MSG_SOURCE, r"i64\s+DoMsgrcv", "msqid", "MessageQueue", "g_sysv_pool[idx]"),
            (MSG_SOURCE, r"i64\s+DoMsgctl", "msqid", "MessageQueue", "g_sysv_pool[idx]"),
            (SYSV_SOURCE, r"i64\s+DoShmat", "shmid", "SharedMemory", "g_shm_pool[idx]"),
            (SYSV_SOURCE, r"i64\s+DoShmctl", "shmid", "SharedMemory", "g_shm_pool[idx]"),
            (SYSV_SOURCE, r"i64\s+DoSemop", "semid", "Semaphore", "SemValidateIngress"),
            (SYSV_SOURCE, r"i64\s+DoSemtimedop", "semid", "Semaphore", "SemValidateIngress"),
            (SYSV_SOURCE, r"i64\s+DoSemctl", "semid", "Semaphore", "g_sem_pool[idx]"),
        )
        for source, signature, argument, family, first_access in cases:
            body = function_body(source, signature)
            require_order(body, f"SysvIpcDecodeId({argument}, SysvIpcIdFamily::{family}", first_access)

        combined = code_only(MSG_SOURCE + SYSV_SOURCE)
        self.assertNotRegex(combined, r"\b(?:msqid|semid|shmid)\s*-\s*1\b")

    def test_stale_reuse_never_aliases_and_errno_depends_on_operation_state(self) -> None:
        for family in (SHARED_MEMORY, SEMAPHORE, MESSAGE_QUEUE):
            pool = ModelPool(family)
            old_id = pool.get(0)
            self.assertIsNotNone(old_id)
            assert old_id is not None
            self.assertEqual(pool.initial_lookup(old_id), "OK")
            self.assertTrue(pool.rmid(old_id))
            replacement = pool.get(0)
            self.assertIsNotNone(replacement)
            self.assertNotEqual(old_id, replacement)
            self.assertEqual(pool.initial_lookup(old_id), "EINVAL")
            self.assertEqual(pool.blocked_recheck(old_id), "EIDRM")
            self.assertEqual(pool.initial_lookup(replacement or 0), "OK")

        for source, signature in (
            (MSG_SOURCE, r"i64\s+DoMsgsnd"),
            (MSG_SOURCE, r"i64\s+DoMsgrcv"),
        ):
            body = function_body(source, signature)
            self.assertIn("const u64 expected_incarnation = decoded.generation", body)
            self.assertIn("q.incarnation != expected_incarnation", body)
            self.assertIn("return -22", body)
            self.assertIn("return kEIDRM", body)
            self.assertIn("removed ? kEIDRM : kEINTR", body)

        validate = function_body(SYSV_SOURCE, r"i64\s+SemValidateIngress")
        self.assertIn("return kEINVAL", validate)
        operate = function_body(SYSV_SOURCE, r"i64\s+SemOperate")
        self.assertIn("s.incarnation != expected_incarnation", operate)
        self.assertIn("return kEIDRM", operate)

        shmctl = function_body(SYSV_SOURCE, r"i64\s+DoShmctl")
        self.assertIn("seg.marked_destroy", shmctl)
        self.assertIn("seg.incarnation != decoded.generation", shmctl)

        shmat = function_body(SYSV_SOURCE, r"i64\s+DoShmat")
        require_order(shmat, "ShmValidateAttachIngress", "ShmAttachReserve")
        self.assertIn("ref_saturated = exact_identity &&", shmat)
        require_order(
            shmat,
            "if (!exact_identity)",
            "pin_error = kEIDRM",
            "else if (denied_private)",
            "else if (ref_saturated)",
            "return pin_error",
        )
        attach_ingress = function_body(SYSV_SOURCE, r"i64\s+ShmValidateAttachIngress")
        self.assertIn("segment.marked_destroy", attach_ingress)
        self.assertIn("segment.incarnation != expected_incarnation", attach_ingress)

    def test_rmid_during_copy_or_wait_cannot_redirect_to_reused_slot(self) -> None:
        send = function_body(MSG_SOURCE, r"i64\s+DoMsgsnd")
        require_order(
            send,
            "SysvIpcDecodeId(msqid",
            "expected_incarnation = decoded.generation",
            "q.incarnation != expected_incarnation",
            "CopyFromUser",
            "while (true)",
            "return kEIDRM",
        )
        for signature in (r"i64\s+DoSemop", r"i64\s+DoSemtimedop"):
            body = function_body(SYSV_SOURCE, signature)
            require_order(
                body,
                "SysvIpcDecodeId(semid",
                "expected_incarnation = decoded.generation",
                "SemValidateIngress",
                "CopyFromUser",
                "SemOperate",
            )
        operate = function_body(SYSV_SOURCE, r"i64\s+SemOperate")
        require_order(operate, "s.incarnation != expected_incarnation", "return kEIDRM")
        self.assertIn("removed ? kEIDRM : kEINTR", send)
        self.assertIn("if (removed)", operate)
        self.assertIn("return kEIDRM", operate[operate.find("if (wait_result != 0)") :])

    def test_generation_is_persistent_failed_reservations_burn_and_max_retires(self) -> None:
        for source, name in (
            (MSG_SOURCE, "SysvMq"),
            (SYSV_SOURCE, "SemSet"),
            (SYSV_SOURCE, "ShmSegment"),
        ):
            self.assertIn("u64 incarnation", struct_body(source, name))

        mq_alloc = function_body(MSG_SOURCE, r"i64\s+SysvMqAlloc")
        shm_alloc = function_body(SYSV_SOURCE, r"i64\s+ShmAlloc")
        sem_alloc = function_body(SYSV_SOURCE, r"i32\s+SemAllocLocked")
        for body, increment in (
            (mq_alloc, "++q.incarnation"),
            (shm_alloc, "++segment.incarnation"),
            (sem_alloc, "++s.incarnation"),
        ):
            require_order(body, "incarnation >= kSysvIpcIdGenerationMax", increment)
        self.assertIn("const u64 incarnation = segment.incarnation", function_body(SYSV_SOURCE, r"void\s+ShmClearSlotLocked"))
        self.assertNotRegex(code_only(MSG_SOURCE), r"\bq\.incarnation\s*=\s*0\b")
        self.assertNotRegex(code_only(SYSV_SOURCE), r"\b(?:s|segment)\.incarnation\s*=\s*0\b")

        for family in (SHARED_MEMORY, MESSAGE_QUEUE):
            pool = ModelPool(family)
            self.assertIsNone(pool.get(0, publish=False))
            second = pool.get(0)
            self.assertEqual(decode(second or 0, family), (0, 2))
            self.assertEqual(pool.slots[0].generation, 2)

        saturated = ModelPool(MESSAGE_QUEUE)
        saturated.slots[0].generation = GENERATION_MAX - 1
        maximum_id = saturated.get(0)
        self.assertEqual(decode(maximum_id or 0, MESSAGE_QUEUE), (0, GENERATION_MAX))
        self.assertTrue(saturated.rmid(maximum_id or 0))
        successor = saturated.get(0)
        self.assertEqual(decode(successor or 0, MESSAGE_QUEUE), (1, 1))
        saturated.rmid(successor or 0)
        for slot in saturated.slots:
            slot.in_use = False
            slot.generation = GENERATION_MAX
        self.assertIsNone(saturated.get(0))

    def test_key_lookup_private_creation_and_concurrent_creator_contracts(self) -> None:
        for family in (SHARED_MEMORY, SEMAPHORE, MESSAGE_QUEUE):
            pool = ModelPool(family)
            keyed = pool.get(77)
            self.assertEqual(pool.get(77), keyed)
            self.assertTrue(pool.rmid(keyed or 0))
            recreated = pool.get(77)
            self.assertNotEqual(recreated, keyed)
            private_one = pool.get(0)
            private_two = pool.get(0)
            self.assertNotEqual(private_one, private_two)

        allocator = function_body(MSG_SOURCE, r"i64\s+SysvMqAlloc")
        require_order(
            allocator,
            "SpinLockAcquire(g_sysv_lock)",
            "q.in_use && !q.marked_destroy && q.key == key",
            "return kSysvMqAllocBusy",
            "++q.incarnation",
        )
        msgget = function_body(MSG_SOURCE, r"i64\s+DoMsgget")
        self.assertIn("while (true)", msgget)
        self.assertNotIn("kCreateRetryLimit", msgget)
        self.assertIn("id == kSysvMqAllocBusy", msgget)
        self.assertIn("existing == kSysvMqAllocBusy", msgget)
        self.assertIn("SchedYield", msgget)
        require_order(msgget, "SysvMqFindByKey", "SysvMqAlloc")

        shmget = function_body(SYSV_SOURCE, r"i64\s+DoShmget")
        self.assertIn("while (true)", shmget)
        self.assertNotIn("kCreateRetryLimit", shmget)

    def test_all_getters_publish_current_encoded_identity_under_family_lock(self) -> None:
        msg_find = function_body(MSG_SOURCE, r"i64\s+SysvMqFindByKey")
        require_order(msg_find, "SpinLockGuard guard(g_sysv_lock)", "SysvIpcEncodeId(SysvIpcIdFamily::MessageQueue")
        msg_alloc = function_body(MSG_SOURCE, r"i64\s+SysvMqAlloc")
        require_order(msg_alloc, "SpinLockAcquire(g_sysv_lock)", "++q.incarnation", "SysvIpcEncodeId")

        shmget = function_body(SYSV_SOURCE, r"i64\s+DoShmget")
        require_order(shmget, "SpinLockAcquire(g_shm_lock)", "SysvIpcEncodeId(SysvIpcIdFamily::SharedMemory")
        require_order(shmget, "size > segment.size_bytes", "SysvIpcEncodeId(SysvIpcIdFamily::SharedMemory")
        require_order(shmget, "size == 0 || size >", "ShmAlloc")
        shm_alloc = function_body(SYSV_SOURCE, r"i64\s+ShmAlloc")
        self.assertIn("segment.size_bytes = size", shm_alloc)
        semget = function_body(SYSV_SOURCE, r"i64\s+DoSemget")
        require_order(semget, "SpinLockAcquire(g_sem_lock)", "SysvIpcEncodeId(SysvIpcIdFamily::Semaphore")
        require_order(semget, "nsems > set.nsems", "SysvIpcEncodeId(SysvIpcIdFamily::Semaphore")
        require_order(semget, "nsems == 0 || nsems > kSemPerSet", "static_cast<u32>(nsems)")

        semctl = function_body(SYSV_SOURCE, r"i64\s+DoSemctl")
        require_order(semctl, "ProcessHasCap", "SpinLockAcquire(g_sem_lock)")

        shmctl = function_body(SYSV_SOURCE, r"i64\s+DoShmctl")
        require_order(shmctl, "if (cmd == kIpcInfo)", "SysvIpcDecodeId(shmid")
        info_path = shmctl[shmctl.find("if (cmd == kIpcInfo)") : shmctl.find("SysvIpcDecodedId decoded")]
        self.assertIn("segment.in_use && !segment.initializing", info_path)
        self.assertIn("return highest_index", info_path)

    def test_shm_attachment_ledger_retains_and_revalidates_complete_id(self) -> None:
        shmat = function_body(SYSV_SOURCE, r"i64\s+DoShmat")
        self.assertIn("ShmAttachPublish(p, reservation, static_cast<u32>(shmid)", shmat)
        shmdt = function_body(SYSV_SOURCE, r"i64\s+DoShmdt")
        require_order(
            shmdt,
            "SysvIpcDecodeId(claim.published.shmid, SysvIpcIdFamily::SharedMemory",
            "seg.incarnation == decoded.generation",
            "ShmDropReference(idx, decoded.generation)",
        )
        drain = function_body(SYSV_SOURCE, r"void\s+LinuxShmDrainProcess")
        require_order(
            drain,
            "SysvIpcDecodeId(att.shmid, SysvIpcIdFamily::SharedMemory",
            "segment.incarnation == decoded.generation",
            "ShmDropReference(idx, decoded.generation)",
        )
        drop = function_body(SYSV_SOURCE, r"bool\s+ShmDropReference")
        self.assertIn("segment.incarnation == expected_incarnation", drop)


if __name__ == "__main__":
    unittest.main()
