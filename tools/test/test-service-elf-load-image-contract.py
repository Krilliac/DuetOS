#!/usr/bin/env python3
"""Hostile structural contract for the service ELF -> LoadImage adapter."""

from __future__ import annotations

import pathlib
import re
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
HEADER = (ROOT / "kernel/loader/elf_load_image.h").read_text(encoding="utf-8")
SOURCE = (ROOT / "kernel/loader/elf_load_image.cpp").read_text(encoding="utf-8")
HOST_CMAKE = (ROOT / "tests/host/CMakeLists.txt").read_text(encoding="utf-8")
WIKI = (ROOT / "wiki/kernel/Loader.md").read_text(encoding="utf-8")


class ServiceElfLoadImageContract(unittest.TestCase):
    def test_production_parser_is_the_only_elf_byte_authority(self) -> None:
        self.assertIn("core::ElfValidate(request.bytes, request.byte_count)", SOURCE)
        self.assertEqual(SOURCE.count("core::ElfForEachPtLoad("), 2)
        self.assertNotRegex(SOURCE, r"\bLeU(?:16|32|64)\b|e_phoff|e_phnum")

    def test_exact_external_source_hash_is_verified_before_staging(self) -> None:
        digest = SOURCE.index("crypto::Sha256Hash")
        comparison = SOURCE.index("HashEqual(observed_hash, request.expected_source_hash)")
        initialize = SOURCE.index("LoadImageInitialize(")
        self.assertLess(digest, comparison)
        self.assertLess(comparison, initialize)
        self.assertIn("separately authenticated", HEADER)

    def test_bounds_wx_and_executable_entry_are_preflighted(self) -> None:
        initialize = SOURCE.index("LoadImageInitialize(")
        for needle in (
            "segment.filesz > segment.memsz",
            "kElfLoadImageMaximumSegmentSpanBytes",
            "kLoadPlanUserMax",
            "ElfLoadImageStatus::WritableExecutable",
            "bounds.entry_executable",
        ):
            self.assertLess(SOURCE.index(needle), initialize, needle)

        # A zero-memory PT_LOAD is ignorable only after proving it does not
        # claim file bytes. Keep this adapter-level defense even though the
        # production Rust parser currently enforces p_filesz <= p_memsz.
        self.assertLess(
            SOURCE.index("segment.filesz > segment.memsz"),
            SOURCE.index("if (segment.memsz == 0)"),
        )

    def test_failure_after_initialization_releases_owned_frames(self) -> None:
        stage_failure = re.search(
            r"if \(stage\.failure != LoadImageStatus::Ok\)\s*\{(?P<body>.*?)\n\s*\}",
            SOURCE,
            re.DOTALL,
        )
        self.assertIsNotNone(stage_failure)
        self.assertIn("LoadImageRelease(image)", stage_failure.group("body"))
        seal_failure = re.search(
            r"if \(image_status != LoadImageStatus::Ok\)\s*\{(?P<body>.*?)\n\s*\}",
            SOURCE[SOURCE.index("image_status = LoadImageSeal(image)") :],
            re.DOTALL,
        )
        self.assertIsNotNone(seal_failure)
        self.assertIn("LoadImageRelease(image)", seal_failure.group("body"))

    def test_adapter_stops_before_admission_mapping_and_publication(self) -> None:
        body = SOURCE[SOURCE.index("ElfLoadImageResult ElfLoadImagePrepare") :]
        for forbidden in ("ExecAdmissionPrepare", "LoadImageMapInto", "SchedCreate", "PublishCreatedTask"):
            self.assertNotIn(forbidden, body)
        self.assertIn("does not map a target AddressSpace", HEADER)

    def test_host_contract_and_documentation_are_registered(self) -> None:
        self.assertIn("add_host_test(elf_load_image)", HOST_CMAKE)
        self.assertIn("kernel/loader/elf_load_image.cpp", HOST_CMAKE)
        self.assertIn("Service package ELF staging", WIKI)
        self.assertIn("Activation readiness remains false", WIKI)


if __name__ == "__main__":
    unittest.main()
