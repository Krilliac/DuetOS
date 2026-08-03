#!/usr/bin/env python3
"""Structural regression contract for bounded Rust/C ingress."""

from __future__ import annotations

import importlib.util
import re
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
FFI = ROOT / "kernel" / "fs" / "duetfs" / "src" / "ffi.rs"
COMPRESS = ROOT / "kernel" / "fs" / "duetfs" / "src" / "compress.rs"
CRYPTO = ROOT / "kernel" / "fs" / "duetfs" / "src" / "crypto.rs"
ALLOCATOR = ROOT / "kernel" / "fs" / "duetfs" / "src" / "kheap_alloc.rs"
FS = ROOT / "kernel" / "fs" / "duetfs" / "src" / "fs.rs"
FORMAT = ROOT / "kernel" / "fs" / "duetfs" / "src" / "format.rs"
HEADER = ROOT / "kernel" / "fs" / "duetfs" / "include" / "duetfs.h"
CHECKER = ROOT / "tools" / "test" / "check-rust-ffi.py"

KNOWN_UNCALLED = {
    "duetfs_mkfs_encrypted",
    "duetfs_read_encryption_meta",
    "duetos_acpi_parse_hpet",
    "duetos_acpi_parse_madt_entry_header",
    "duetos_acpi_parse_mcfg_entry",
    "duetos_acpi_parse_srat_memory_affinity",
    "duetos_acpi_parse_table_header",
    "duetos_exec_meta_pe_validate_prefix",
    "duetos_exfat_fat_chain_next",
    "duetos_hci_parse_command_complete",
    "duetos_hci_parse_command_status",
    "duetos_hci_parse_disconnection_complete",
    "duetos_hci_parse_event_packet",
    "duetos_hci_parse_le_meta",
    "duetos_parsers_tcp_walk_options",
    "duetos_pci_caps_find_extended",
    "duetos_pci_caps_parse_extended_at",
    "duetos_pci_caps_parse_standard_at",
    "duetos_wifi80211_parse_eapol_key",
}


def code_only(source: str) -> str:
    """Blank comments and ordinary literals, preserving newlines."""
    token = re.compile(
        r"//[^\r\n]*|/\*.*?\*/|\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\\r\n])'",
        re.DOTALL,
    )

    def blank(match: re.Match[str]) -> str:
        value = match.group(0)
        return "".join("\n" if char == "\n" else " " for char in value)

    return token.sub(blank, source)


def function_body(source: str, name: str) -> str:
    code = code_only(source)
    match = re.search(rf"\bfn\s+{re.escape(name)}(?:\s*<[^>{{}}]*>)?\s*\(", code)
    if match is None:
        raise AssertionError(f"missing function: {name}")
    opening = code.find("{", match.end())
    if opening < 0:
        raise AssertionError(f"missing function body: {name}")
    depth = 0
    for index in range(opening, len(code)):
        if code[index] == "{":
            depth += 1
        elif code[index] == "}":
            depth -= 1
            if depth == 0:
                return code[opening + 1 : index]
    raise AssertionError(f"unterminated function body: {name}")


def assert_order(test: unittest.TestCase, source: str, *needles: str) -> None:
    positions = [source.find(needle) for needle in needles]
    test.assertNotIn(-1, positions, f"missing ordered marker from {needles!r}")
    test.assertEqual(positions, sorted(positions), f"wrong ordering for {needles!r}")


def load_checker():
    spec = importlib.util.spec_from_file_location("duetos_rust_ffi_checker", CHECKER)
    if spec is None or spec.loader is None:
        raise AssertionError("could not load Rust FFI checker")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class RustIngressHardeningContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.ffi = FFI.read_text(encoding="utf-8")
        cls.compress = COMPRESS.read_text(encoding="utf-8")
        cls.crypto = CRYPTO.read_text(encoding="utf-8")
        cls.allocator = ALLOCATOR.read_text(encoding="utf-8")
        cls.fs = FS.read_text(encoding="utf-8")
        cls.format = FORMAT.read_text(encoding="utf-8")
        cls.header = HEADER.read_text(encoding="utf-8")

    def test_raw_ffi_slices_are_funnelled_through_checked_helpers(self) -> None:
        code = code_only(self.ffi)
        self.assertEqual(len(re.findall(r"core::slice::from_raw_parts\s*\(", code)), 1)
        self.assertEqual(len(re.findall(r"core::slice::from_raw_parts_mut\s*\(", code)), 1)
        gate = function_body(self.ffi, "ffi_range")
        for marker in ("align_of::<T>()", "checked_mul", "isize::MAX", "checked_add"):
            self.assertIn(marker, gate)
        pure_output = function_body(self.ffi, "ffi_output_bytes")
        assert_order(self, pure_output, "ffi_range(ptr, len)", "write_bytes", "ffi_inout_slice_mut")
        for name in (
            "duetfs_read_file",
            "duetfs_readlink",
            "duetfs_block_read",
            "duetfs_kdf_argon2id",
            "duetfs_lz4_compress",
            "duetfs_lz4_decompress",
            "duetfs_xattr_get",
            "duetfs_xattr_list",
            "duetfs_read_encryption_meta",
        ):
            self.assertIn("ffi_output_bytes", function_body(self.ffi, name), name)
        for name in ("duetfs_xts_encrypt_block", "duetfs_xts_decrypt_block"):
            self.assertIn("ffi_inout_slice_mut", function_body(self.ffi, name), name)
        readdir = function_body(self.ffi, "duetfs_readdir")
        self.assertIn("core::ptr::write(out.add(written), entry)", readdir)
        self.assertNotIn("ffi_inout_slice_mut", readdir)

    def test_output_ranges_are_validated_and_pairwise_disjoint(self) -> None:
        helper = function_body(self.ffi, "ffi_output_ranges_disjoint")
        for marker in ("ranges.iter().enumerate()", "right_start != right_end", "left_start < right_end"):
            self.assertIn(marker, helper)
        for name in (
            "duetfs_lookup",
            "duetfs_read_file",
            "duetfs_readdir",
            "duetfs_write_at",
            "duetfs_create_path",
            "duetfs_fsck",
            "duetfs_create_symlink",
            "duetfs_readlink",
            "duetfs_xattr_get",
            "duetfs_xattr_list",
            "duetfs_read_encryption_meta",
            "duetfs_block_read",
        ):
            self.assertIn("ffi_output_ranges_disjoint", function_body(self.ffi, name), name)
        for name in (
            "duetfs_kdf_argon2id",
            "duetfs_xts_encrypt_block",
            "duetfs_xts_decrypt_block",
            "duetfs_lz4_compress",
            "duetfs_lz4_decompress",
        ):
            self.assertIn("ffi_ranges_overlap", function_body(self.ffi, name), name)

    def test_lz4_is_allocation_free_and_prefix_bounded(self) -> None:
        production = self.compress.split("#[cfg(test)]", 1)[0]
        self.assertNotIn("alloc::vec::Vec", production)
        self.assertNotIn("lz4_flex::block::compress_prepend_size", production)
        self.assertNotIn("lz4_flex::block::decompress_size_prepended", production)
        self.assertIn("lz4_flex::block::compress_into", production)
        self.assertIn("lz4_flex::block::decompress_into", production)
        decompress = function_body(self.compress, "decompress_size_prepended")
        assert_order(self, decompress, "expected > MAX_INPUT_BYTES", "decompress_into")
        bound = function_body(self.compress, "compress_bound")
        for marker in ("checked_mul", "checked_div", "checked_add", "unwrap_or(0)"):
            self.assertIn(marker, bound)

        compress_ffi = function_body(self.ffi, "duetfs_lz4_compress")
        for marker in ("compress::MAX_INPUT_BYTES", "ffi_ranges_overlap", "dst_extent"):
            self.assertIn(marker, compress_ffi)
        decompress_ffi = function_body(self.ffi, "duetfs_lz4_decompress")
        assert_order(
            self,
            decompress_ffi,
            "u32::from_le_bytes",
            "expected > compress::MAX_INPUT_BYTES",
            "ffi_output_bytes",
        )

    def test_argon2_costs_are_validated_before_work_or_format(self) -> None:
        production = self.crypto.split("#[cfg(test)]", 1)[0]
        self.assertIn("Vec::<Block>::new()", production)
        self.assertIn("try_reserve_exact(block_count)", production)
        self.assertIn("hash_password_into_with_memory", production)
        self.assertNotIn(".hash_password_into(password", production)
        self.assertIn("compare_exchange(false, true", production)
        policy = function_body(self.crypto, "argon2id_params_valid")
        assert_order(self, policy, "ARGON2_MAX_MEMORY_KIB", "Params::new")
        kdf = function_body(self.ffi, "duetfs_kdf_argon2id")
        assert_order(self, kdf, "ARGON2_MAX_PASSWORD_BYTES", "ffi_slice(password")
        self.assertIn("ffi_ranges_overlap", kdf)
        mkfs = function_body(self.ffi, "duetfs_mkfs_encrypted")
        assert_order(self, mkfs, "argon2id_params_valid", "make_dev", "format_encrypted")

    def test_native_lengths_have_explicit_work_caps(self) -> None:
        cstr = function_body(self.ffi, "cstr_to_slice")
        self.assertIn("max > FFI_PATH_CSTRING_MAX", cstr)
        read_file = function_body(self.ffi, "duetfs_read_file")
        self.assertIn("min(dst_max, FFI_MAX_IO_BYTES)", read_file)
        write_at = function_body(self.ffi, "duetfs_write_at")
        for marker in ("checked_add(src_max)", "src_max > FFI_MAX_IO_BYTES", "write_end > FFI_MAX_IO_BYTES"):
            self.assertIn(marker, write_at)
        readdir = function_body(self.ffi, "duetfs_readdir")
        self.assertIn("ffi_range(out, produce)", readdir)
        self.assertIn("core::ptr::write(out.add(written), entry)", readdir)
        self.assertNotIn("start_index + out_max as u32", readdir)

    def test_on_disk_nodes_are_validated_before_normal_use(self) -> None:
        validator = function_body(self.fs, "node_semantics_are_valid")
        for marker in (
            "node.child_count > DIR_MAX_CHILDREN",
            "node.extent_count as usize > MAX_INLINE_EXTENTS",
            "node.name_len as usize > NAME_MAX",
            "extent_is_valid",
        ):
            self.assertIn(marker, validator)
        read_node = function_body(self.fs, "read_node")
        assert_order(self, read_node, "read_node_raw(id)", "node_semantics_are_valid", "FsError::Corrupt")
        self.assertIn("crafted_directory_child_count_is_rejected_before_indexing", self.fs)
        self.assertIn("pub const DIR_MAX_CHILDREN", self.format)

    def test_callback_reachable_storage_contract_is_explicit(self) -> None:
        for marker in (
            "Storage reachable through `Device::cookie`",
            "stable and disjoint",
            "No other thread may mutate",
            "never retain those pointers",
        ):
            self.assertIn(marker, self.header)

    def test_overaligned_allocator_fails_closed_on_arithmetic_overflow(self) -> None:
        allocate = function_body(self.allocator, "alloc")
        assert_order(self, allocate, "checked_add(align)", "duetos_rust_alloc(total)")
        self.assertGreaterEqual(allocate.count("checked_add"), 3)
        self.assertRegex(allocate, r"duetos_rust_free\s*\(\s*raw\s*\)")

    def test_duetfs_layout_and_resource_constants_are_paired(self) -> None:
        pairs = {
            "DuetFsDevice": ("Device", 32, 8),
            "DuetFsLookupResult": ("LookupResult", 16, 4),
            "DuetFsDirEntry": ("DirEntry", 80, 4),
            "DuetFsFsckReport": ("FsckReport", 32, 4),
        }
        for rust_name, (cpp_name, size, alignment) in pairs.items():
            self.assertIn(f"size_of::<{rust_name}>() == {size}", self.ffi)
            self.assertIn(f"align_of::<{rust_name}>() == {alignment}", self.ffi)
            self.assertIn(f"sizeof({cpp_name}) == {size}", self.header)
            self.assertIn(f"alignof({cpp_name}) == {alignment}", self.header)
        for marker in (
            "kPathMax = 4096",
            "kMaxIoBytes = 1024 * kBlockSize",
            "kArgon2MaxMemoryKiB = 8 * 1024",
            "kLz4MaxInputBytes = 64 * 1024 * 1024",
        ):
            self.assertIn(marker, self.header)

    def test_every_function_export_is_declared_and_every_crate_has_a_caller(self) -> None:
        checker = load_checker()
        inventory = checker.build_inventory(ROOT, ROOT / "kernel" / "rust" / "Cargo.toml")
        self.assertFalse(inventory.issues, inventory.issues)
        exports = [item for item in inventory.exports if item.kind == "function"]
        header_names = set().union(*inventory.header_names.values())
        missing_headers = {item.name for item in exports} - header_names
        self.assertFalse(missing_headers, f"function exports without header declarations: {sorted(missing_headers)}")

        names = {item.name: item.crate.member for item in exports}
        call = re.compile(r"\b(" + "|".join(map(re.escape, sorted(names, key=len, reverse=True))) + r")\s*\(")
        hits = {name: set() for name in names}
        scanned_files = 0
        scanned_bytes = 0
        for path in sorted((ROOT / "kernel").rglob("*")):
            if path.suffix.lower() not in {".c", ".cc", ".cpp"}:
                continue
            scanned_files += 1
            scanned_bytes += path.stat().st_size
            self.assertLessEqual(scanned_files, 1024, "caller inventory exceeded its file budget")
            self.assertLessEqual(scanned_bytes, 32 * 1024 * 1024, "caller inventory exceeded its byte budget")
            source = code_only(path.read_text(encoding="utf-8", errors="replace"))
            for match in call.finditer(source):
                hits[match.group(1)].add(path.relative_to(ROOT).as_posix())

        uncalled = {name for name, paths in hits.items() if not paths}
        self.assertFalse(uncalled - KNOWN_UNCALLED, f"new function exports have no native caller: {sorted(uncalled)}")
        export_crates = set(names.values())
        called_crates = {names[name] for name, paths in hits.items() if paths}
        self.assertEqual(export_crates, called_crates, "one or more Rust crates have no native caller")


if __name__ == "__main__":
    unittest.main()
