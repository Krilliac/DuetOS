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


def expect_failure_containing(callable_object, expected: str) -> None:
    try:
        callable_object()
    except GATE.ParseFailure as error:
        assert expected in str(error), error
        return
    raise AssertionError(f"expected ParseFailure containing {expected!r}")


def rust_signature(source: str, member: str = "kernel/demo"):
    parsed = GATE.parse_rust_exports_text(member, Path("demo.rs"), source)
    assert len(parsed) == 1, parsed
    return parsed[0]


def header_signature(source: str, member: str = "kernel/demo"):
    linked = f'extern "C" {{\n{source}\n}}\n'
    parsed = GATE.parse_header_declarations_text(member, Path("demo.h"), linked)
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
    (root / ".cargo").mkdir()
    (root / ".cargo" / "config.toml").write_text(
        '[build]\ntarget="x86_64-unknown-none"\n'
        '[unstable]\nbuild-std=["core","alloc"]\n'
        'build-std-features=["compiler-builtins-mem"]\n',
        encoding="utf-8",
    )
    (root / "rust-toolchain.toml").write_text(
        '[toolchain]\nchannel="nightly-2026-01-15"\ncomponents=["rust-src"]\n'
        'targets=["x86_64-unknown-none"]\nprofile="minimal"\n',
        encoding="utf-8",
    )
    (root / "kernel" / "demo" / "Cargo.toml").write_text(
        '[package]\nname="demo"\nversion="0.0.0"\nedition="2021"\n', encoding="utf-8"
    )
    (root / "kernel" / "demo" / "src" / "lib.rs").write_text(rust_body, encoding="utf-8")
    (root / "kernel" / "demo" / "include" / "demo.h").write_text(
        f'extern "C" {{\n{header_body}\n}}\n', encoding="utf-8"
    )


def test_header_declaration_requires_lexical_c_linkage() -> None:
    expect_failure_containing(
        lambda: GATE.parse_header_declarations_text(
            "kernel/demo", Path("demo.h"), "u32 duetos_demo_ping(u32 value);"
        ),
        'lacks lexical extern "C" linkage',
    )
    direct = GATE.parse_header_declarations_text(
        "kernel/demo", Path("demo.h"), 'extern "C" u32 duetos_demo_ping(u32 value);'
    )
    assert len(direct) == 1


def test_header_linkage_masks_literal_comment_and_preprocessor_decoys() -> None:
    linked = '''extern "C" {
constexpr const char* ordinary_noise = "}";
constexpr int character_noise = '}}';
constexpr const char* raw_noise = R"tag(} extern "C++" {)tag";
/* } extern "C++" { */
u32 duetos_demo_ping(u32 value);
}
'''
    parsed = GATE.parse_header_declarations_text("kernel/demo", Path("demo.h"), linked)
    assert len(parsed) == 1
    assert parsed[0].line == 6

    canonical_wrapper = '''#ifdef __cplusplus
extern "C" {
#endif
u32 duetos_demo_ping(u32 value);
#ifdef __cplusplus
}
#endif
'''
    assert len(GATE.parse_header_declarations_text("kernel/demo", Path("demo.h"), canonical_wrapper)) == 1

    raw_string_decoy = '''namespace demo {
constexpr const char* decoy = R"(extern "C" {)";
u32 duetos_demo_ping(u32 value);
}
'''
    expect_failure_containing(
        lambda: GATE.parse_header_declarations_text("kernel/demo", Path("demo.h"), raw_string_decoy),
        'lacks lexical extern "C" linkage',
    )

    preprocessor_decoy = '''#if 0
extern "C" {
#endif
u32 duetos_demo_ping(u32 value);
#if 0
}
#endif
'''
    expect_failure_containing(
        lambda: GATE.parse_header_declarations_text("kernel/demo", Path("demo.h"), preprocessor_decoy),
        'lacks lexical extern "C" linkage',
    )

    nested_cpp_linkage = '''extern "C" {
extern "C++" {
u32 duetos_demo_ping(u32 value);
}
}
'''
    expect_failure_containing(
        lambda: GATE.parse_header_declarations_text("kernel/demo", Path("demo.h"), nested_cpp_linkage),
        'lacks lexical extern "C" linkage',
    )


def test_duetfs_callback_prototypes_are_compared() -> None:
    rust_source = '''
#[repr(C)]
pub struct DuetFsDevice {
    pub read: Option<unsafe extern "C" fn(cookie: *mut c_void, lba: u32, dst: *mut u8) -> i32>,
}
'''
    header_source = '''
extern "C" {
using BlockReadFn = i32 (*)(void* cookie, u32 lba, u8* dst);
}
struct Device {
    BlockReadFn read;
};
'''
    rust = GATE.parse_rust_callbacks_text("kernel/fs/duetfs", Path("ffi.rs"), rust_source)
    header = GATE.parse_header_callbacks_text("kernel/fs/duetfs", Path("duetfs.h"), header_source)
    assert len(rust) == len(header) == 1
    assert GATE.compare_callbacks(rust[0], header[0]) == []

    mismatched = header_source.replace("u8* dst", "const u8* dst")
    header = GATE.parse_header_callbacks_text("kernel/fs/duetfs", Path("duetfs.h"), mismatched)
    assert GATE.compare_callbacks(rust[0], header[0]) == ["parameter 3 Rust=*mut u8 C=*const u8"]


def test_duetfs_callback_linkage_rejects_literal_and_preprocessor_decoys() -> None:
    linked = '''extern "C" {
constexpr const char* ordinary_noise = "}";
constexpr int character_noise = '}}';
constexpr const char* raw_noise = R"tag(} extern "C++" {)tag";
using BlockReadFn = i32 (*)(void* cookie, u32 lba, u8* dst);
}
struct Device {
    BlockReadFn read;
};
'''
    parsed = GATE.parse_header_callbacks_text("kernel/fs/duetfs", Path("duetfs.h"), linked)
    assert len(parsed) == 1
    assert parsed[0].field == "read"

    raw_string_decoy = '''namespace duetos::fs::duetfs {
constexpr const char* decoy = R"(extern "C" {)";
using BlockReadFn = i32 (*)(void* cookie, u32 lba, u8* dst);
struct Device { BlockReadFn read; };
}
'''
    expect_failure_containing(
        lambda: GATE.parse_header_callbacks_text(
            "kernel/fs/duetfs", Path("duetfs.h"), raw_string_decoy
        ),
        'callback alias BlockReadFn lacks lexical extern "C" linkage',
    )

    preprocessor_decoy = '''#if 0
extern "C" {
#endif
using BlockReadFn = i32 (*)(void* cookie, u32 lba, u8* dst);
struct Device { BlockReadFn read; };
#if 0
}
#endif
'''
    expect_failure_containing(
        lambda: GATE.parse_header_callbacks_text(
            "kernel/fs/duetfs", Path("duetfs.h"), preprocessor_decoy
        ),
        'callback alias BlockReadFn lacks lexical extern "C" linkage',
    )

    nested_cpp_linkage = '''extern "C" {
extern "C++" {
using BlockReadFn = i32 (*)(void* cookie, u32 lba, u8* dst);
struct Device { BlockReadFn read; };
}
}
'''
    expect_failure_containing(
        lambda: GATE.parse_header_callbacks_text(
            "kernel/fs/duetfs", Path("duetfs.h"), nested_cpp_linkage
        ),
        'callback alias BlockReadFn lacks lexical extern "C" linkage',
    )


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


def test_inventory_real_signature_mismatch_path() -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        write_fixture(
            root,
            '#[no_mangle]\npub unsafe extern "C" fn duetos_demo_read(p: *const u8) { }\n',
            'void duetos_demo_read(uint8_t* p);\n',
        )
        findings, summary = GATE.audit(root)
        assert [finding.code for finding in findings] == ["RFS006"], findings
        assert "parameter 1 Rust=*const u8 C=*mut u8" in findings[0].message
        assert summary["matched_functions"] == 1


def test_inventory_rejects_nested_directory_symlink_or_reparse() -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        write_fixture(
            root,
            '#[no_mangle]\npub extern "C" fn duetos_demo_one(v: u32) -> u32 { v }\n',
            'u32 duetos_demo_one(u32 v);\n',
        )
        hidden = root / "hidden-source"
        hidden.mkdir()
        (hidden / "hidden.rs").write_text(
            '#[no_mangle]\npub extern "C" fn duetos_demo_hidden(v: u32) -> u32 { v }\n',
            encoding="utf-8",
        )
        link = root / "kernel" / "demo" / "src" / "linked"
        try:
            link.symlink_to(hidden, target_is_directory=True)
        except (NotImplementedError, OSError):
            # Windows without Developer Mode cannot create this hostile fixture.
            return

        findings, summary = GATE.audit(root)
        assert [finding.code for finding in findings] == ["RFS001"], findings
        assert findings[0].path == "kernel/demo/src/linked"
        assert summary["rust_functions"] == 1


def test_inventory_rejects_symlink_file() -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        write_fixture(
            root,
            '#[no_mangle]\npub extern "C" fn duetos_demo_one(v: u32) -> u32 { v }\n',
            'u32 duetos_demo_one(u32 v);\n',
        )
        hidden = root / "hidden.rs"
        hidden.write_text(
            '#[no_mangle]\npub extern "C" fn duetos_demo_hidden(v: u32) -> u32 { v }\n',
            encoding="utf-8",
        )
        link = root / "kernel" / "demo" / "src" / "linked.rs"
        try:
            link.symlink_to(hidden)
        except (NotImplementedError, OSError):
            return

        findings, summary = GATE.audit(root)
        assert [finding.code for finding in findings] == ["RFS001"], findings
        assert findings[0].path == "kernel/demo/src/linked.rs"
        assert summary["rust_functions"] == 1


def test_inventory_limit_counts_ignored_entries_before_retaining() -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        write_fixture(
            root,
            '#[no_mangle]\npub extern "C" fn duetos_demo_one(v: u32) -> u32 { v }\n',
            'u32 duetos_demo_one(u32 v);\n',
        )
        (root / "kernel" / "demo" / "ignored.txt").write_text("ignored\n", encoding="utf-8")
        expect_failure_containing(
            lambda: GATE.audit(root, max_inventory_entries=5),
            "source inventory exceeds 5 visited entries",
        )


def test_inventory_prunes_target_before_descent() -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        write_fixture(
            root,
            '#[no_mangle]\npub extern "C" fn duetos_demo_one(v: u32) -> u32 { v }\n',
            'u32 duetos_demo_one(u32 v);\n',
        )
        generated = root / "kernel" / "demo" / "target" / "debug" / "generated"
        generated.mkdir(parents=True)
        for index in range(32):
            (generated / f"generated_{index}.rs").write_text("not an input\n", encoding="utf-8")

        findings, summary = GATE.audit(root, max_inventory_entries=6)
        assert findings == []
        assert summary["matched_functions"] == 1


def test_inventory_audits_nested_target_module() -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        write_fixture(
            root,
            'mod target;\n#[no_mangle]\npub extern "C" fn duetos_demo_one(v: u32) -> u32 { v }\n',
            'u32 duetos_demo_one(u32 v);\n',
        )
        nested = root / "kernel" / "demo" / "src" / "target"
        nested.mkdir()
        (nested / "mod.rs").write_text(
            '#[no_mangle]\npub extern "C" fn duetos_demo_nested(v: u32) -> u32 { v }\n', encoding="utf-8"
        )
        findings, summary = GATE.audit(root)
        assert [finding.code for finding in findings] == ["RFS004"], findings
        assert findings[0].path == "kernel/demo/src/target/mod.rs"
        assert summary["rust_functions"] == 2


def test_inventory_scandir_error_fails_closed() -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        write_fixture(
            root,
            '#[no_mangle]\npub extern "C" fn duetos_demo_one(v: u32) -> u32 { v }\n',
            'u32 duetos_demo_one(u32 v);\n',
        )
        original_scandir = GATE.os.scandir

        def failing_scandir(path):
            if Path(path).name == "src":
                raise OSError("hostile fixture denied directory enumeration")
            return original_scandir(path)

        GATE.os.scandir = failing_scandir
        try:
            expect_failure_containing(lambda: GATE.audit(root), "cannot scan workspace directory")
        finally:
            GATE.os.scandir = original_scandir


def test_inventory_rejects_custom_target_and_unlisted_local_dependency() -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        write_fixture(
            root,
            '#[no_mangle]\npub extern "C" fn duetos_demo_one(v: u32) -> u32 { v }\n',
            'u32 duetos_demo_one(u32 v);\n',
        )
        manifest = root / "kernel" / "demo" / "Cargo.toml"
        manifest.write_text(
            manifest.read_text(encoding="utf-8") + '[lib]\npath="../outside.rs"\n', encoding="utf-8"
        )
        expect_failure_containing(lambda: GATE.audit(root), "custom [lib] path")

    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        write_fixture(
            root,
            '#[no_mangle]\npub extern "C" fn duetos_demo_one(v: u32) -> u32 { v }\n',
            'u32 duetos_demo_one(u32 v);\n',
        )
        outsider = root / "kernel" / "outsider"
        outsider.mkdir()
        (outsider / "Cargo.toml").write_text(
            '[package]\nname="outsider"\nversion="0.0.0"\nedition="2021"\n', encoding="utf-8"
        )
        manifest = root / "kernel" / "demo" / "Cargo.toml"
        manifest.write_text(
            manifest.read_text(encoding="utf-8")
            + '[dependencies]\noutsider={path="../outsider"}\n',
            encoding="utf-8",
        )
        expect_failure_containing(lambda: GATE.audit(root), "not an explicit audited workspace member")


def test_inventory_rejects_path_attributes_and_code_include() -> None:
    for hostile_source, expected in (
        ('#[path = "other.rs"]\nmod other;\n', "#[path]"),
        ('include!("other.rs");\n', "include! code"),
        ('include /* gap */ ! { "other.rs" };\n', "include! code"),
        ('include\n! [ "other.rs" ];\n', "include! code"),
    ):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_fixture(root, hostile_source, "")
            (root / "kernel" / "demo" / "src" / "other.rs").write_text("", encoding="utf-8")
            findings, _ = GATE.audit(root)
            assert [finding.code for finding in findings] == ["RFS002"], findings
            assert expected in findings[0].message


def test_inventory_aggregate_byte_and_signature_budgets() -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        write_fixture(
            root,
            '#[no_mangle]\npub extern "C" fn duetos_demo_one(v: u32) -> u32 { v }\n',
            'u32 duetos_demo_one(u32 v);\n',
        )
        expect_failure_containing(lambda: GATE.audit(root, max_input_bytes=8), "aggregate bytes")
        expect_failure_containing(lambda: GATE.audit(root, max_signature_records=1), "signature inventory")

    repeated = "\n".join(
        f'#[no_mangle]\npub extern "C" fn duetos_demo_{index}(v: u32) -> u32 {{ v }}'
        for index in range(32)
    )
    budget = GATE.TraversalBudget(limit=100, signature_limit=3)
    expect_failure_containing(
        lambda: GATE.parse_rust_exports_text("kernel/demo", Path("single.rs"), repeated, budget),
        "signature inventory exceeds 3 records",
    )
    assert budget.signatures == 4


def test_inventory_rejects_cargo_config_escape_hatches() -> None:
    for hostile_config, expected in (
        ('[build]\ntarget="x86_64-unknown-none"\nrustc-wrapper="outside"\n', "canonical target"),
        ('paths=["../outside"]\n', "canonical target"),
    ):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_fixture(
                root,
                '#[no_mangle]\npub extern "C" fn duetos_demo_one(v: u32) -> u32 { v }\n',
                'u32 duetos_demo_one(u32 v);\n',
            )
            (root / ".cargo" / "config.toml").write_text(hostile_config, encoding="utf-8")
            expect_failure_containing(lambda: GATE.audit(root), expected)

    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        write_fixture(
            root,
            '#[no_mangle]\npub extern "C" fn duetos_demo_one(v: u32) -> u32 { v }\n',
            'u32 duetos_demo_one(u32 v);\n',
        )
        nested = root / "kernel" / "demo" / ".cargo"
        nested.mkdir()
        (nested / "config.toml").write_text('[build]\nrustc="outside"\n', encoding="utf-8")
        expect_failure_containing(lambda: GATE.audit(root), "only repository-root")


def test_inventory_rejects_floating_toolchain() -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        write_fixture(
            root,
            '#[no_mangle]\npub extern "C" fn duetos_demo_one(v: u32) -> u32 { v }\n',
            'u32 duetos_demo_one(u32 v);\n',
        )
        (root / "rust-toolchain.toml").write_text(
            '[toolchain]\nchannel="nightly"\ncomponents=["rust-src"]\n'
            'targets=["x86_64-unknown-none"]\nprofile="minimal"\n',
            encoding="utf-8",
        )
        expect_failure_containing(lambda: GATE.audit(root), "canonical dated channel")


def test_finding_budget_stops_many_parameter_mismatches() -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        rust_parameters = ", ".join(f"p{index}: u32" for index in range(8))
        c_parameters = ", ".join(f"uint64_t p{index}" for index in range(8))
        write_fixture(
            root,
            f'#[no_mangle]\npub extern "C" fn duetos_demo_many({rust_parameters}) {{ }}\n',
            f'void duetos_demo_many({c_parameters});\n',
        )
        original_limit = GATE.MAX_FINDINGS
        try:
            GATE.MAX_FINDINGS = 3
            expect_failure_containing(lambda: GATE.audit(root), "finding inventory exceeds 3 records")
        finally:
            GATE.MAX_FINDINGS = original_limit


def test_reparse_tag_classification_allows_cloud_filter_only() -> None:
    reparse = GATE.WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT
    assert not GATE.windows_reparse_is_unsafe(0, None)
    assert GATE.windows_reparse_is_unsafe(reparse, None)
    assert GATE.windows_reparse_is_unsafe(reparse, 0)
    assert GATE.windows_reparse_is_unsafe(reparse, 0xA000000C)
    assert not GATE.windows_reparse_is_unsafe(reparse, 0x9000001A)


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
