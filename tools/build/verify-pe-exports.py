#!/usr/bin/env python3
"""Verify that an AMD64 PE32+ DLL has callable exports from a manifest."""

from __future__ import annotations

import argparse
import re
import struct
import sys
from dataclasses import dataclass
from pathlib import Path


MAX_IMAGE_SIZE = 512 * 1024 * 1024
MAX_EXPORTS = 65536
AMD64_MACHINE = 0x8664
PE32_PLUS_MAGIC = 0x20B
IMAGE_FILE_DLL = 0x2000
IMAGE_SCN_MEM_EXECUTE = 0x20000000
PAGE_ALIGNMENT = 4096
SUPPORTED_FILE_ALIGNMENTS = frozenset((512, 1024, 2048, 4096))
MAX_USER_VA = 0x00007FFFFFFFFFFF
EXPECTED_DLL_NAME = "kernel32.dll"
MANIFEST_RE = re.compile(r'DUETOS_RETIRED_KERNEL32_IMPORT\("([^"]+)"\)')


class PeError(ValueError):
    """A bounded PE structure is malformed or violates the contract."""


@dataclass(frozen=True)
class Section:
    virtual_address: int
    virtual_size: int
    raw_offset: int
    raw_size: int
    characteristics: int


def read_u16(data: bytes, offset: int) -> int:
    if offset < 0 or offset + 2 > len(data):
        raise PeError(f"u16 outside file at 0x{offset:x}")
    return struct.unpack_from("<H", data, offset)[0]


def read_u32(data: bytes, offset: int) -> int:
    if offset < 0 or offset + 4 > len(data):
        raise PeError(f"u32 outside file at 0x{offset:x}")
    return struct.unpack_from("<I", data, offset)[0]


def read_u64(data: bytes, offset: int) -> int:
    if offset < 0 or offset + 8 > len(data):
        raise PeError(f"u64 outside file at 0x{offset:x}")
    return struct.unpack_from("<Q", data, offset)[0]


def rva_to_offset(
    data: bytes,
    sections: list[Section],
    size_of_headers: int,
    rva: int,
    size: int = 1,
) -> int:
    if rva < 0 or size < 0 or rva + size > 0x100000000:
        raise PeError(f"invalid RVA span 0x{rva:x}+0x{size:x}")
    if rva < size_of_headers:
        if rva + size > min(size_of_headers, len(data)):
            raise PeError(f"header RVA span outside file: 0x{rva:x}+0x{size:x}")
        return rva
    for section in sections:
        span = max(section.virtual_size, section.raw_size)
        if rva < section.virtual_address:
            continue
        delta = rva - section.virtual_address
        if delta >= span:
            continue
        if delta + size > section.raw_size:
            raise PeError(f"RVA span reaches virtual-only bytes: 0x{rva:x}+0x{size:x}")
        offset = section.raw_offset + delta
        if offset + size > len(data):
            raise PeError(f"RVA span outside file: 0x{rva:x}+0x{size:x}")
        return offset
    raise PeError(f"unmapped RVA 0x{rva:x}")


def section_for_rva(sections: list[Section], rva: int) -> Section | None:
    for section in sections:
        if rva < section.virtual_address:
            continue
        delta = rva - section.virtual_address
        if delta < section.raw_size:
            return section
    return None


def read_c_string(data: bytes, offset: int, cap: int = 1024) -> str:
    if offset < 0 or offset >= len(data):
        raise PeError(f"string offset outside file: 0x{offset:x}")
    end = data.find(b"\0", offset, min(len(data), offset + cap))
    if end < 0:
        raise PeError(f"unterminated string at 0x{offset:x}")
    try:
        return data[offset:end].decode("ascii")
    except UnicodeDecodeError as exc:
        raise PeError(f"non-ASCII export name at 0x{offset:x}") from exc


def parse_manifest(path: Path) -> list[str]:
    names: list[str] = []
    seen: set[str] = set()
    for line_number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("//"):
            continue
        match = MANIFEST_RE.fullmatch(line)
        if match is None:
            raise ValueError(f"{path}:{line_number}: malformed retirement macro")
        name = match.group(1)
        if not name or any(ch.isspace() for ch in name):
            raise ValueError(f"{path}:{line_number}: invalid export name")
        if name in seen:
            raise ValueError(f"{path}:{line_number}: duplicate export {name!r}")
        seen.add(name)
        names.append(name)
    if not names:
        raise ValueError(f"{path}: manifest contains no required exports")
    return names


def parse_exports(path: Path, required: set[str]) -> set[str]:
    # A single bounded read avoids the stat/open race where a file can
    # grow or be replaced after the size check and force an unbounded
    # allocation before len(data) is inspected.
    with path.open("rb") as image:
        data = image.read(MAX_IMAGE_SIZE + 1)
    if len(data) > MAX_IMAGE_SIZE:
        raise PeError(f"image is too large (cap is {MAX_IMAGE_SIZE} bytes)")
    if len(data) < 0x40 or data[:2] != b"MZ":
        raise PeError("missing DOS header")

    pe_offset = read_u32(data, 0x3C)
    if pe_offset + 24 > len(data) or data[pe_offset : pe_offset + 4] != b"PE\0\0":
        raise PeError("missing PE signature")
    coff = pe_offset + 4
    machine = read_u16(data, coff)
    if machine != AMD64_MACHINE:
        raise PeError(f"expected AMD64 machine 0x{AMD64_MACHINE:x}, got 0x{machine:x}")
    section_count = read_u16(data, coff + 2)
    optional_size = read_u16(data, coff + 16)
    characteristics = read_u16(data, coff + 18)
    if section_count == 0 or section_count > 96:
        raise PeError(f"invalid section count {section_count}")
    if (characteristics & IMAGE_FILE_DLL) == 0:
        raise PeError("PE image is not marked IMAGE_FILE_DLL")

    optional = coff + 20
    optional_end = optional + optional_size
    if optional_end > len(data):
        raise PeError("optional header outside file")
    magic = read_u16(data, optional)
    if magic != PE32_PLUS_MAGIC:
        raise PeError(f"expected PE32+ magic 0x{PE32_PLUS_MAGIC:x}, got 0x{magic:x}")
    if optional_size < 120:
        raise PeError("optional header is too short for export directory")
    image_base = read_u64(data, optional + 24)
    section_alignment = read_u32(data, optional + 32)
    file_alignment = read_u32(data, optional + 36)
    size_of_image = read_u32(data, optional + 56)
    size_of_headers = read_u32(data, optional + 60)
    if image_base > MAX_USER_VA or (image_base & (PAGE_ALIGNMENT - 1)) != 0:
        raise PeError("DLL ImageBase is not a page-aligned user address")
    if section_alignment != PAGE_ALIGNMENT:
        raise PeError(f"unsupported section alignment {section_alignment}")
    if file_alignment not in SUPPORTED_FILE_ALIGNMENTS:
        raise PeError(f"unsupported file alignment {file_alignment}")
    if size_of_image == 0:
        raise PeError("DLL SizeOfImage is zero")
    if image_base + size_of_image - 1 > MAX_USER_VA:
        raise PeError("DLL image extends outside the canonical user range")
    if size_of_headers == 0 or size_of_headers > len(data):
        raise PeError("DLL SizeOfHeaders is outside the file")
    directory_count = read_u32(data, optional + 108)
    if directory_count < 1:
        raise PeError("PE declares no export data directory")
    export_rva = read_u32(data, optional + 112)
    export_size = read_u32(data, optional + 116)
    if export_rva == 0 or export_size < 40 or export_rva + export_size > 0x100000000:
        raise PeError("missing or malformed export data directory")

    section_table = optional_end
    if section_table + section_count * 40 > len(data):
        raise PeError("section table outside file")
    sections: list[Section] = []
    for index in range(section_count):
        header = section_table + index * 40
        section = Section(
            virtual_address=read_u32(data, header + 12),
            virtual_size=read_u32(data, header + 8),
            raw_offset=read_u32(data, header + 20),
            raw_size=read_u32(data, header + 16),
            characteristics=read_u32(data, header + 36),
        )
        if section.raw_offset + section.raw_size > len(data):
            raise PeError(f"section {index} raw range is outside the file")
        mapped_size = max(section.virtual_size, section.raw_size)
        if mapped_size > 0 and (
            section.virtual_address >= size_of_image
            or mapped_size > size_of_image - section.virtual_address
        ):
            raise PeError(f"section {index} extends outside SizeOfImage")
        sections.append(section)
    spans = sorted(
        (section.virtual_address, section.virtual_address + max(section.virtual_size, section.raw_size))
        for section in sections
        if max(section.virtual_size, section.raw_size) > 0
    )
    for previous, current in zip(spans, spans[1:]):
        if current[0] < previous[1]:
            raise PeError("overlapping section RVA ranges are ambiguous")

    export_offset = rva_to_offset(data, sections, size_of_headers, export_rva, export_size)
    dll_name_rva = read_u32(data, export_offset + 12)
    dll_name_offset = rva_to_offset(data, sections, size_of_headers, dll_name_rva)
    dll_name = read_c_string(data, dll_name_offset)
    if dll_name.lower() != EXPECTED_DLL_NAME:
        raise PeError(
            f"export directory names {dll_name!r}, expected {EXPECTED_DLL_NAME!r}"
        )
    function_count = read_u32(data, export_offset + 20)
    name_count = read_u32(data, export_offset + 24)
    functions_rva = read_u32(data, export_offset + 28)
    names_rva = read_u32(data, export_offset + 32)
    ordinals_rva = read_u32(data, export_offset + 36)
    if function_count > MAX_EXPORTS or name_count > MAX_EXPORTS:
        raise PeError("unreasonable export count")
    if name_count > function_count:
        raise PeError("export-name count exceeds function count")
    if name_count == 0:
        return set()

    functions_offset = rva_to_offset(
        data, sections, size_of_headers, functions_rva, function_count * 4
    )
    names_offset = rva_to_offset(data, sections, size_of_headers, names_rva, name_count * 4)
    ordinals_offset = rva_to_offset(
        data, sections, size_of_headers, ordinals_rva, name_count * 2
    )

    exports: set[str] = set()
    previous_name: str | None = None
    for index in range(name_count):
        ordinal = read_u16(data, ordinals_offset + index * 2)
        if ordinal >= function_count:
            raise PeError(f"export name index {index} has out-of-range ordinal")
        function_rva = read_u32(data, functions_offset + ordinal * 4)
        if function_rva == 0:
            raise PeError(f"export name index {index} resolves to a null function RVA")

        name_rva = read_u32(data, names_offset + index * 4)
        name_offset = rva_to_offset(data, sections, size_of_headers, name_rva)
        name = read_c_string(data, name_offset)
        if previous_name is not None and name <= previous_name:
            raise PeError("export name table is not strictly ASCII-sorted")
        previous_name = name
        if name in exports:
            raise PeError(f"duplicate export name {name!r}")
        exports.add(name)

        if name not in required:
            continue
        if export_rva <= function_rva < export_rva + export_size:
            raise PeError(f"required export {name!r} resolves to a forwarder")
        rva_to_offset(data, sections, size_of_headers, function_rva)
        section = section_for_rva(sections, function_rva)
        if section is None or (section.characteristics & IMAGE_SCN_MEM_EXECUTE) == 0:
            raise PeError(f"required export {name!r} resolves outside executable code")
    return exports


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", type=Path)
    parser.add_argument("manifest", type=Path)
    args = parser.parse_args()
    try:
        required = parse_manifest(args.manifest)
        exports = parse_exports(args.image, set(required))
    except (OSError, PeError, ValueError) as exc:
        print(f"verify-pe-exports: error: {exc}", file=sys.stderr)
        return 2
    missing = [name for name in required if name not in exports]
    if missing:
        print(
            f"verify-pe-exports: {args.image}: missing {len(missing)} required export(s): "
            + ", ".join(missing),
            file=sys.stderr,
        )
        return 1
    print(
        f"verify-pe-exports: {args.image.name}: PASS "
        f"({len(required)} required, {len(exports)} total exports)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
