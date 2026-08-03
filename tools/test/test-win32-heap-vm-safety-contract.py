#!/usr/bin/env python3
"""Hostile structural contract for Win32 heap metadata and VM access."""

from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def code_only(source: str) -> str:
    """Blank C/C++ comments and literals while preserving source offsets."""
    masked = list(source)
    index = 0
    state = "code"
    quote = ""
    while index < len(source):
        current = source[index]
        following = source[index + 1] if index + 1 < len(source) else ""
        if state == "code":
            if current == "/" and following == "/":
                masked[index] = masked[index + 1] = " "
                index += 2
                state = "line"
                continue
            if current == "/" and following == "*":
                masked[index] = masked[index + 1] = " "
                index += 2
                state = "block"
                continue
            if current in ('"', "'"):
                quote = current
                masked[index] = " "
                index += 1
                state = "literal"
                continue
        elif state == "line":
            if current == "\n":
                state = "code"
            else:
                masked[index] = " "
            index += 1
            continue
        elif state == "block":
            if current == "*" and following == "/":
                masked[index] = masked[index + 1] = " "
                index += 2
                state = "code"
                continue
            if current != "\n":
                masked[index] = " "
            index += 1
            continue
        elif state == "literal":
            if current == "\\":
                masked[index] = " "
                if index + 1 < len(source):
                    masked[index + 1] = " "
                index += 2
                continue
            masked[index] = " "
            index += 1
            if current == quote:
                state = "code"
            continue
        index += 1
    return "".join(masked)


def function_body(source: str, name: str) -> str:
    clean = code_only(source)
    for match in re.finditer(rf"\b{re.escape(name)}\s*\(", clean):
        opening = clean.find("{", match.end())
        semicolon = clean.find(";", match.end())
        if opening < 0 or (semicolon >= 0 and semicolon < opening):
            continue
        depth = 0
        for position in range(opening, len(clean)):
            if clean[position] == "{":
                depth += 1
            elif clean[position] == "}":
                depth -= 1
                if depth == 0:
                    return source[opening : position + 1]
    raise AssertionError(f"definition not found: {name}")


class ParserHostileTests(unittest.TestCase):
    def test_comment_literal_and_declaration_cannot_spoof_body(self) -> None:
        hostile = r'''
        // Target() { PhysToVirt(fake); }
        const char* text = "Target() { PhysToVirt(fake); }";
        void Target();
        void Target() { int real = 1; }
        '''
        body = function_body(hostile, "Target")
        self.assertIn("real", body)
        self.assertNotIn("PhysToVirt", code_only(body))


class Win32HeapVmSafetyContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.heap = read("kernel/subsystems/win32/heap.cpp")
        cls.heap_header = read("kernel/subsystems/win32/heap.h")
        cls.process_header = read("kernel/proc/process.h")
        cls.process = read("kernel/proc/process.cpp")

    def test_no_unpinned_frame_or_direct_map_access_remains(self) -> None:
        source = code_only(self.heap)
        for forbidden in ("AddressSpaceLookupUserFrame", "PhysToVirt"):
            self.assertNotIn(forbidden, source)
        self.assertIn("AddressSpaceReadUserMemory", source)
        self.assertIn("AddressSpaceWriteUserMemory", source)

    def test_metadata_helpers_propagate_bounded_vm_failures(self) -> None:
        read_body = code_only(function_body(self.heap, "ReadHeapU64"))
        write_body = code_only(function_body(self.heap, "WriteHeapU64"))
        copy_body = code_only(function_body(self.heap, "CopyHeapPayloadLocked"))
        self.assertIn("AddressSpaceReadUserMemory", read_body)
        self.assertIn("AddressSpaceWriteUserMemory", write_body)
        self.assertIn("AddressSpaceReadUserMemory", copy_body)
        self.assertIn("AddressSpaceWriteUserMemory", copy_body)
        self.assertIn("kReallocCopyChunk", self.heap)
        self.assertRegex(copy_body, r"chunk\s*>\s*source_room")
        self.assertRegex(copy_body, r"chunk\s*>\s*destination_room")

    def test_process_owned_sleeping_mutex_covers_all_heap_state(self) -> None:
        self.assertRegex(self.process_header, r"mutable\s+sched::Mutex\s+win32_heap_lock\s*;")
        self.assertIn("win32_heap_lock -> AddressSpace::mutation_lock -> regions_lock", self.process_header)
        create = code_only(function_body(self.process, "ProcessCreate"))
        for initialization in (
            "p->win32_heap_lock.owner = nullptr",
            "p->win32_heap_lock.waiters.head = nullptr",
            "p->win32_heap_lock.waiters.tail = nullptr",
            "p->win32_heap_lock.class_id = sync::kLockClassUnclassified",
        ):
            self.assertIn(initialization, create)
        self.assertNotIn("SpinLock", code_only(self.heap))

    def test_every_public_heap_entry_serializes_metadata(self) -> None:
        entries = (
            "Win32HeapInit",
            "Win32HeapAllocOnBinding",
            "Win32HeapAlloc",
            "Win32HeapFreeOnBinding",
            "Win32HeapFree",
            "Win32HeapSizeOnBinding",
            "Win32HeapSize",
            "Win32HeapReallocOnBinding",
            "Win32HeapRealloc",
            "Win32HeapResolveHandle",
            "Win32HeapExCreate",
            "Win32HeapExDestroy",
        )
        for entry in entries:
            with self.subTest(entry=entry):
                self.assertIn("HeapLockGuard guard(*proc)", code_only(function_body(self.heap, entry)))

    def test_public_binding_is_a_value_receipt_and_is_revalidated(self) -> None:
        binding = re.search(r"struct\s+Win32HeapBinding\s*\{(?P<body>.*?)\};", self.heap_header, re.S)
        self.assertIsNotNone(binding)
        body = code_only(binding.group("body"))
        self.assertNotIn("*", body)
        for field in ("base_va", "pages", "generation", "slot"):
            self.assertRegex(body, rf"\b{field}\b")
        resolve = code_only(function_body(self.heap, "ResolveBindingLocked"))
        self.assertIn("binding.slot", resolve)
        self.assertIn("row.in_use", resolve)
        self.assertIn("row.base_va != binding.base_va", resolve)
        self.assertIn("row.pages != binding.pages", resolve)
        self.assertIn("row.generation != binding.generation", resolve)

    def test_hostile_size_links_overflow_and_cycles_fail_closed(self) -> None:
        rounding = code_only(function_body(self.heap, "RoundRequestToBlockSize"))
        allocation = code_only(function_body(self.heap, "HeapAllocLocked"))
        freeing = code_only(function_body(self.heap, "HeapFreeLocked"))
        sizing = code_only(function_body(self.heap, "HeapSizeLocked"))
        self.assertGreaterEqual(rounding.count("~u64{0}"), 2)
        self.assertIn("max_hops", allocation)
        self.assertRegex(allocation, r"hop\s*<\s*max_hops")
        for body in (allocation, freeing, sizing):
            self.assertRegex(body, r"block_size\s*>\s*heap_end\s*-\s*(?:cur|block_header)")
            self.assertIn("block_size & 7", body)
        self.assertIn("IsFreeLinkInHeap", allocation)
        self.assertIn("IsFreeLinkInHeap", freeing)

    def test_seed_is_committed_before_kernel_metadata_publication(self) -> None:
        init = code_only(function_body(self.heap, "Win32HeapInit"))
        write = init.index("WriteHeapU64(proc, kWin32HeapVa")
        self.assertLess(write, init.index("proc->heap_base = kWin32HeapVa"))
        self.assertLess(write, init.index("proc->heap_free_head = kWin32HeapVa"))
        create = code_only(function_body(self.heap, "Win32HeapExCreate"))
        self.assertLess(create.index("WriteHeapU64(proc, base_va"), create.index("row.in_use = true"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
