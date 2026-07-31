#!/usr/bin/env python3
"""Hostile parser fixtures for check-rust-ffi-signatures.py."""

from __future__ import annotations

import importlib.util
import sys
import tempfile
from pathlib import Path


SCRIPT = Path(__file__).with_name("check-rust-ffi-signatures.py")
SPEC = importlib.util.spec_from_file_location("check_rust_ffi_signatures", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot import {SCRIPT}")
GATE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = GATE
SPEC.loader.exec_module(GATE)


def expect_failure(callable_object, message: str) -> None:
    try:
        callable_object()
    except GATE.ParseFailure:
        return
    raise AssertionError(message)


def rust_signature(source: str, member: str = "kernel/demo"):
    parsed = GATE.parse_rust_exports_text(member, Path("demo.rs"), source)
    assert len(parsed) == 1, parsed
    return parsed[0]


def header_signature(source: str, member: str = "kernel/demo"):
    parsed = GATE.parse_header_declarations_text(member, Path("demo.h"), source)
    assert len(parsed) == 1, parsed
    return parsed[0]


def test_scalar_alias_and_const_pointer_match() -> None:
    rust = rust_signature(
        '#[no_mangle]\npub unsafe extern "C" fn duetos_demo_read(p: *const u8, n: u32) -> i32 { 0 }'
    )
    header = header_signature('int32_t duetos_demo_read(const uint8_t* p, uint32_t n);')
    assert GATE.compare_signatures(rust, header) == []


def test_mutability_mismatch() -> None:
    rust = rust_signature(
        '#[no_mangle]\npub unsafe extern "C" fn duetos_demo_read(p: *const u8) -> bool { true }'
    )
    header = header_signature('bool duetos_demo_read(uint8_t* p);')
    mismatch = GATE.compare_signatures(rust, header)
    assert mismatch == ["parameter 1 Rust=*const u8 C=*mut u8"], mismatch


def test_pointer_depth_mismatch() -> None:
    rust = rust_signature(
        '#[no_mangle]\npub unsafe extern "C" fn duetos_demo_read(p: *mut *const u8) { }'
    )
    header = header_signature('void duetos_demo_read(const uint8_t* p);')
    mismatch = GATE.compare_signatures(rust, header)
    assert mismatch == ["parameter 1 Rust=*mut *const u8 C=*const u8"], mismatch


def test_pointer_to_pointer_constness_match() -> None:
    rust = rust_signature(
        '#[no_mangle]\npub unsafe extern "C" fn duetos_demo_read(p: *mut *const u8) { }'
    )
    header = header_signature('void duetos_demo_read(const uint8_t** p);')
    assert GATE.compare_signatures(rust, header) == []


def test_array_parameter_adjustment() -> None:
    rust = rust_signature(
        '#[no_mangle]\npub unsafe extern "C" fn duetos_demo_fill(p: *mut u8) { }'
    )
    header = header_signature('void duetos_demo_fill(uint8_t p[32]);')
    assert GATE.compare_signatures(rust, header) == []


def test_arity_mismatch() -> None:
    rust = rust_signature('#[no_mangle]\npub extern "C" fn duetos_demo_ping(v: u32) -> u32 { v }')
    header = header_signature('uint32_t duetos_demo_ping(uint32_t v, bool strict);')
    mismatch = GATE.compare_signatures(rust, header)
    assert mismatch == ["arity Rust=1 C=2"], mismatch


def test_non_c_abi_is_rejected() -> None:
    rust = rust_signature(
        '#[no_mangle]\npub unsafe extern "C-unwind" fn duetos_demo_ping(v: u32) -> u32 { v }'
    )
    header = header_signature('u32 duetos_demo_ping(u32 v);')
    assert GATE.compare_signatures(rust, header) == ["unsupported Rust ABI 'C-unwind'"]


def test_export_name() -> None:
    rust = rust_signature(
        '#[export_name = "duetos_demo_named"]\npub extern "C" fn internal(v: c_uint) -> c_uint { v }'
    )
    header = header_signature('u32 duetos_demo_named(u32 v);')
    assert rust.name == "duetos_demo_named"
    assert GATE.compare_signatures(rust, header) == []


def test_duetfs_named_alias_is_scoped() -> None:
    source = '#[no_mangle]\npub unsafe extern "C" fn duetfs_probe(p: *const DuetFsDevice) -> c_uint { 0 }'
    header_source = 'u32 duetfs_probe(const Device* p);'
    rust = rust_signature(source, "kernel/fs/duetfs")
    header = header_signature(header_source, "kernel/fs/duetfs")
    assert GATE.compare_signatures(rust, header) == []
    unscoped_rust = rust_signature(source)
    unscoped_header = header_signature(header_source)
    assert GATE.compare_signatures(unscoped_rust, unscoped_header)


def test_unsupported_declarators_fail_closed() -> None:
    expect_failure(
        lambda: header_signature('void duetos_demo_cb(void (*callback)(uint32_t));'),
        "inline callback declarator was accepted",
    )
    expect_failure(
        lambda: rust_signature(
            '#[no_mangle]\npub extern "C" fn duetos_demo_ref(value: &u32) -> u32 { *value }'
        ),
        "Rust reference was accepted at the FFI wall",
    )
    expect_failure(
        lambda: header_signature('void duetos_demo_grid(uint8_t grid[4][8]);'),
        "multidimensional array was accepted",
    )


def test_unbalanced_signature_fails_closed() -> None:
    expect_failure(
        lambda: rust_signature('#[no_mangle]\npub extern "C" fn duetos_demo_bad(v: Option<u32) { }'),
        "unbalanced Rust signature was accepted",
    )


def write_fixture(root: Path, rust_body: str, header_body: str) -> None:
    (root / "kernel" / "demo" / "src").mkdir(parents=True)
    (root / "kernel" / "demo" / "include").mkdir(parents=True)
    (root / "Cargo.toml").write_text('[workspace]\nmembers = ["kernel/demo"]\n', encoding="utf-8")
    (root / "kernel" / "demo" / "Cargo.toml").write_text(
        '[package]\nname="demo"\nversion="0.0.0"\nedition="2021"\n', encoding="utf-8"
    )
    (root / "kernel" / "demo" / "src" / "lib.rs").write_text(rust_body, encoding="utf-8")
    (root / "kernel" / "demo" / "include" / "demo.h").write_text(header_body, encoding="utf-8")


def test_inventory_missing_and_duplicate_diagnostics() -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        write_fixture(
            root,
            '#[no_mangle]\npub extern "C" fn duetos_demo_one(v: u32) -> u32 { v }\n',
            'u32 duetos_demo_two(u32 v);\nu32 duetos_demo_two(u32 v);\n',
        )
        findings, summary = GATE.audit(root)
        assert {finding.code for finding in findings} == {"RFS003", "RFS004", "RFS005"}, findings
        assert summary["findings"] == 3


def test_inventory_happy_path() -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        write_fixture(
            root,
            '#[no_mangle]\npub unsafe extern "C" fn '
            "duetos_demo_one(p: *const u8, n: usize) -> bool { !p.is_null() && n > 0 }\n",
            'bool duetos_demo_one(const uint8_t* p, size_t n);\n',
        )
        findings, summary = GATE.audit(root)
        assert findings == []
        assert summary == {
            "workspace_members": 1,
            "rust_functions": 1,
            "header_functions": 1,
            "matched_functions": 1,
            "findings": 0,
        }


def main() -> int:
    tests = [
        (name, value)
        for name, value in globals().items()
        if name.startswith("test_") and callable(value)
    ]
    tests.sort(key=lambda item: item[0])
    for _, test in tests:
        test()
    print(f"test-rust-ffi-signatures: PASS ({len(tests)} hostile/static cases)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
