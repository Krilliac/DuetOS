#!/usr/bin/env python3
# DuetOS AML bytecode fuzz seed generator.
#
# WHAT  Emits DSDT tables (36-byte ACPI header + hand-encoded AML
#       body) whose body exercises the deep arms of the namespace
#       walker (kernel/acpi/aml.cpp) from cycle 1: Scope, Device,
#       Method, Name with Word/Byte/Package data, OperationRegion +
#       Field, and the \_S5 sleep package the AmlReadS5 decoder
#       parses. fuzz_aml serves each file as the DSDT.
#
# WHY   AmlNamespaceBuild only walks bytes past the 36-byte header,
#       and the recursive TermList decoder needs a valid PkgLength +
#       NameString prefix to reach HandleContainer / HandleMethod /
#       IndexFieldList. A random mutator almost never lands a valid
#       opcode+PkgLength+NameSeg run, so without seeds the walker
#       bails at the first byte. These seeds put the mutator on the
#       container recursion and the field-list / package decoders —
#       where the PkgLength-underflow class (fixed via this harness)
#       lived.
#
# NOTE  The walker does NOT validate the ACPI header checksum, so the
#       header here is plausible but not checksummed — only the body
#       matters.
#
# USAGE  python3 gen_aml_seeds.py <out_dir>

import os
import struct
import sys


def header(total_len: int) -> bytearray:
    h = bytearray(36)
    h[0:4] = b"DSDT"
    struct.pack_into("<I", h, 4, total_len)
    h[8] = 2  # revision (2 => 64-bit integers)
    h[10:16] = b"DUETOS"
    h[16:24] = b"DUETDSDT"
    struct.pack_into("<I", h, 24, 1)
    h[28:32] = b"DUET"
    struct.pack_into("<I", h, 32, 1)
    return h


def nameseg(s: str) -> bytes:
    # 4-char NameSeg, '_'-padded, leading char A-Z or '_'.
    s = (s + "____")[:4]
    return s.encode("ascii")


def pkg(body: bytes) -> bytes:
    # 1-byte PkgLength (covers itself + body); valid while < 63.
    n = len(body) + 1
    assert n < 0x40, "seed body too long for 1-byte PkgLength"
    return bytes([n]) + body


def name_byte(seg: str, value: int) -> bytes:
    # NameOp NameSeg BytePrefix data
    return bytes([0x08]) + nameseg(seg) + bytes([0x0A, value & 0xFF])


def name_word(seg: str, value: int) -> bytes:
    # NameOp NameSeg WordPrefix data(2)
    return bytes([0x08]) + nameseg(seg) + bytes([0x0B]) + struct.pack("<H", value & 0xFFFF)


def method(seg: str, args: int, body: bytes = b"") -> bytes:
    # MethodOp PkgLength NameSeg MethodFlags TermList
    return bytes([0x14]) + pkg(nameseg(seg) + bytes([args & 0x07]) + body)


def scope(name: bytes, body: bytes) -> bytes:
    # ScopeOp PkgLength NameString TermList
    return bytes([0x10]) + pkg(name + body)


def device(seg: str, body: bytes = b"") -> bytes:
    # ExtOpPrefix DeviceOp PkgLength NameSeg TermList
    return bytes([0x5B, 0x82]) + pkg(nameseg(seg) + body)


def opregion(seg: str, space: int, offset: int, length: int) -> bytes:
    # ExtOpPrefix OpRegionOp NameSeg RegionSpace RegionOffset RegionLen
    return (bytes([0x5B, 0x80]) + nameseg(seg) + bytes([space & 0xFF, 0x0A, offset & 0xFF, 0x0A, length & 0xFF]))


def field(region: str, flags: int, units: bytes) -> bytes:
    # ExtOpPrefix FieldOp PkgLength NameSeg(region) FieldFlags FieldList
    return bytes([0x5B, 0x81]) + pkg(nameseg(region) + bytes([flags & 0xFF]) + units)


def s5_package() -> bytes:
    # Name(\_S5_, Package(){0,0,0,0}) — the soft-off sleep values.
    pkg_body = bytes([0x04, 0x00, 0x00, 0x00, 0x00])  # numelem + 4×ZeroOp
    return bytes([0x08, 0x5C]) + nameseg("_S5") + bytes([0x12]) + pkg(pkg_body)


def build(body: bytes) -> bytes:
    total = 36 + len(body)
    return bytes(header(total)) + body


def main() -> None:
    out = sys.argv[1] if len(sys.argv) > 1 else "corpus/aml"
    os.makedirs(out, exist_ok=True)

    seeds = {}

    # Minimal: a single Name(WORD, 0x1234).
    seeds["name_word.bin"] = build(name_word("WORD", 0x1234))

    # Scope(\_SB_) { Method(TEST,0), Name(BYTE,0x42) }.
    sb = scope(bytes([0x5C]) + nameseg("_SB"), method("TEST", 0) + name_byte("BYTE", 0x42))
    seeds["scope_method.bin"] = build(sb)

    # _S5 sleep package — drives the AmlReadS5 decoder.
    seeds["s5.bin"] = build(s5_package())

    # OperationRegion + Field: NamedField unit indexing.
    reg = opregion("GPE0", 0x01, 0x00, 0x08)  # SystemIO, 8 bytes
    units = nameseg("BIT0") + bytes([0x01])   # one 1-bit NamedField
    fld = field("GPE0", 0x01, units)
    seeds["opregion_field.bin"] = build(reg + fld)

    # Rich: a device tree mixing every construct, nested one level.
    inner = (
        device("PCI0", name_byte("ADR_", 0x00) + method("_STA", 0))
        + opregion("DBG0", 0x00, 0x10, 0x04)
        + field("DBG0", 0x00, nameseg("DBGB") + bytes([0x20]))
    )
    rich = scope(bytes([0x5C]) + nameseg("_SB"), inner) + s5_package()
    seeds["rich_tree.bin"] = build(rich)

    for name, data in seeds.items():
        open(os.path.join(out, name), "wb").write(data)
    print(f"seeded {out}: {len(os.listdir(out))} files")


if __name__ == "__main__":
    main()
