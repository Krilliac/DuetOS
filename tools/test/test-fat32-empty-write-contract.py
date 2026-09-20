#!/usr/bin/env python3
"""Contract for growing clusterless FAT32 files through write/truncate APIs."""

from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SOURCE = (ROOT / "kernel" / "fs" / "fat32_write.cpp").read_text(encoding="utf-8")
SELFTEST_SOURCE = (ROOT / "kernel" / "fs" / "fat32_selftest.cpp").read_text(encoding="utf-8")


def between(start: str, end: str) -> str:
    begin = SOURCE.index(start)
    finish = SOURCE.index(end, begin)
    return SOURCE[begin:finish]


class Fat32EmptyWriteContract(unittest.TestCase):
    def test_empty_write_delegates_after_sparse_write_rejection(self) -> None:
        body = between("i64 WriteInDir(", "i64 Fat32AppendInRoot(")
        sparse_reject = body.index("if (offset > old_size)")
        empty = re.search(
            r"if\s*\(e->first_cluster\s*<\s*2\)\s*\{(?P<body>.*?)\n\s*\}",
            body,
            re.DOTALL,
        )
        self.assertIsNotNone(empty, "WriteInDir lacks an explicit clusterless-file branch")
        assert empty is not None
        self.assertLess(sparse_reject, empty.start(), "clusterless files bypass sparse-write rejection")
        self.assertIn("old_size != 0", empty.group("body"))
        self.assertIn("offset != 0", empty.group("body"))
        self.assertIn("return AppendInDir(v, dir_cluster, name, buf, len)", empty.group("body"))

    def test_empty_truncate_growth_reuses_append_allocation(self) -> None:
        body = between("i64 TruncateInDir(", "i64 WriteInDir(")
        grow = body[body.index("if (new_size > old_size)") : body.index("// Shrink:")]
        self.assertIn("AppendInDir(v, dir_cluster, name, zeros, chunk)", grow)
        self.assertNotRegex(
            grow,
            r"if\s*\(e->first_cluster\s*<\s*2\)\s*return\s+-1",
            "truncate still rejects the clusterless empty-file state before append can allocate it",
        )

    def test_native_handle_route_uses_the_ram_fixture_before_it_is_forgotten(self) -> None:
        begin = SELFTEST_SOURCE.index("void ExerciseEmptyFileRoute(")
        finish = SELFTEST_SOURCE.index("} // namespace", begin)
        body = SELFTEST_SOURCE[begin:finish]
        self.assertIn("[fs/route-selftest] empty-create-write PASS (RAM FAT32)", body)
        for operation in (
            "routing::CreateForProcess(&process, path, nullptr, 0)",
            "routing::WriteForProcess(&process, handle, kPayload, kPayloadLen)",
            "routing::FstatForProcess(&process, handle, &size)",
            "routing::SeekForProcess(&process, handle, 0",
            "routing::ReadForProcess(&process, handle, readback",
            "routing::CloseForProcess(&process, handle)",
            'Fat32DeleteAtPath(volume, "/RTEMPTY.TXT")',
            "VfsUmount(mount_id)",
        ):
            self.assertIn(operation, body)

        ownership = SELFTEST_SOURCE[SELFTEST_SOURCE.index("void Fat32OwnershipSelfTest()") :]
        self.assertLess(
            ownership.index("ExerciseEmptyFileRoute(fmt_v, fmt_idx)"),
            ownership.index("Fat32ForgetVolume(fmt_h)"),
            "native route proof runs after the RAM FAT32 fixture leaves the volume registry",
        )


if __name__ == "__main__":
    unittest.main()
