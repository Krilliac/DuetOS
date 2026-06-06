#!/usr/bin/env python3
# DuetOS ACPI firmware-table fuzz seed generator.
#
# WHAT  Emits well-formed ACPI tables that clear the parsers'
#       signature + length + 8-bit-additive-checksum gates so the
#       fuzzer (fuzz_acpi) starts INSIDE the per-table body walkers
#       instead of bouncing off byte 0. One seed per table the
#       duetos_acpi crate decodes: RSDP (v1 + v2), a generic table
#       header, MADT (with LAPIC + IOAPIC subtables at the chained-
#       walk offset), FADT, MCFG (one ECAM entry), HPET, and SRAT
#       (one Memory-Affinity subtable).
#
# WHY   The whole-table additive checksum eliminates 255 of every
#       256 random inputs at the header gate, and the per-table
#       signature/length fields are hard for blind mutation to hit.
#       A seed that clears both puts the mutator on the MADT/SRAT
#       subtable length-walk and the FADT/MCFG/HPET field math from
#       cycle 1 — exactly where a malformed length underflows.
#
# USAGE  python3 gen_acpi_seeds.py <out_dir>

import os
import struct
import sys


def fix_table_checksum(b: bytearray) -> bytearray:
    # ACPI: the 8-bit sum of every byte in the table is 0. The
    # checksum byte lives at offset 9. Zero it, sum, then set it so
    # the total wraps to 0.
    b[9] = 0
    b[9] = (256 - (sum(b) & 0xFF)) & 0xFF
    return b


def table_header(sig: bytes, total_len: int, revision: int = 1) -> bytearray:
    h = bytearray(36)
    h[0:4] = sig
    struct.pack_into("<I", h, 4, total_len)  # length (whole table)
    h[8] = revision
    # h[9] checksum — filled by fix_table_checksum once the body lands
    h[10:16] = b"DUETOS"          # oem_id
    h[16:24] = b"DUETTBL_"        # oem_table_id
    struct.pack_into("<I", h, 24, 1)  # oem_revision
    h[28:32] = b"DUET"            # creator_id
    struct.pack_into("<I", h, 32, 1)  # creator_revision
    return h


def build_rsdp_v1() -> bytes:
    # 20-byte RSDP: "RSD PTR " + checksum(8) + oem(6) + rev(1) +
    # rsdt_addr(4). The 8-bit sum of all 20 bytes must be 0.
    b = bytearray(20)
    b[0:8] = b"RSD PTR "
    b[9:15] = b"DUETOS"
    b[15] = 0  # revision 0 (ACPI 1.0)
    struct.pack_into("<I", b, 16, 0x000E0000)  # rsdt_address
    b[8] = 0
    b[8] = (256 - (sum(b) & 0xFF)) & 0xFF
    return bytes(b)


def build_rsdp_v2() -> bytes:
    # 36-byte RSDP: the v1 fields + length(4) + xsdt_addr(8) +
    # ext_checksum(1) + reserved(3). Both checksums must be 0.
    b = bytearray(36)
    b[0:8] = b"RSD PTR "
    b[9:15] = b"DUETOS"
    b[15] = 2  # revision 2 (ACPI 2.0+)
    struct.pack_into("<I", b, 16, 0x000E0000)  # rsdt_address
    struct.pack_into("<I", b, 20, 36)          # length
    struct.pack_into("<Q", b, 24, 0x000F0000)  # xsdt_address
    # v1 checksum (first 20 bytes) at offset 8.
    b[8] = 0
    b[8] = (256 - (sum(b[:20]) & 0xFF)) & 0xFF
    # extended checksum (all 36 bytes) at offset 32.
    b[32] = 0
    b[32] = (256 - (sum(b) & 0xFF)) & 0xFF
    return bytes(b)


def build_madt() -> bytes:
    # header(36) + local_apic_address(4) + flags(4) + subtables.
    # Subtable walk starts at offset 44 (matches fuzz_acpi WalkMadt).
    body = bytearray()
    body += struct.pack("<I", 0xFEE00000)  # local APIC address
    body += struct.pack("<I", 1)           # flags (PCAT_COMPAT)
    # LAPIC entry: type 0, len 8, acpi_id, apic_id, flags(4).
    body += bytes([0, 8, 0, 0]) + struct.pack("<I", 1)
    # IOAPIC entry: type 1, len 12.
    body += bytes([1, 12, 0, 0]) + struct.pack("<I", 0xFEC00000) + struct.pack("<I", 0)
    # Interrupt source override: type 2, len 10.
    body += bytes([2, 10, 0, 0]) + struct.pack("<I", 0) + struct.pack("<H", 0)
    total = 36 + len(body)
    t = table_header(b"APIC", total) + body
    return bytes(fix_table_checksum(t))


def build_fadt() -> bytes:
    # FADT through the reset-register block — 116 bytes is the floor
    # the crate accepts. Lay down the few fields it decodes.
    total = 116
    t = table_header(b"FACP", total)
    t += bytearray(total - 36)
    struct.pack_into("<I", t, 40, 0x000E0000)  # DSDT pointer
    struct.pack_into("<H", t, 46, 9)           # SCI_INT
    struct.pack_into("<I", t, 64, 0x404)       # PM1a_CNT_BLK
    t[89] = 2                                  # PM1_CNT_LEN
    struct.pack_into("<I", t, 112, 1 << 10)    # FLAGS: RESET_REG_SUP
    return bytes(fix_table_checksum(t))


def build_mcfg() -> bytes:
    # header(36) + reserved(8) + one 16-byte allocation entry.
    body = bytearray(8)  # reserved
    body += struct.pack("<Q", 0xE0000000)  # ECAM base
    body += struct.pack("<H", 0)           # segment group
    body += bytes([0, 255])                # start/end bus
    body += bytes([0, 0, 0, 0])            # reserved
    total = 36 + len(body)
    t = table_header(b"MCFG", total) + body
    return bytes(fix_table_checksum(t))


def build_hpet() -> bytes:
    # header(36) + event_timer_block_id(4) + GAS(12) + hpet_number(1)
    # + min_clock_tick(2) + page_protection(1).
    body = struct.pack("<I", 0x8086A201)  # event timer block id
    body += bytes([0, 8, 0, 0]) + struct.pack("<Q", 0xFED00000)  # GAS: base addr
    body += bytes([0])                    # hpet number
    body += struct.pack("<H", 0x80)       # min clock tick
    body += bytes([0])                    # page protection / oem
    total = 36 + len(body)
    t = table_header(b"HPET", total) + body
    return bytes(fix_table_checksum(t))


def build_srat() -> bytes:
    # header(36) + reserved(4)=1 + reserved(8) + Memory-Affinity
    # subtable. Subtable walk starts at offset 48 (matches WalkSrat).
    body = struct.pack("<I", 1) + bytearray(8)
    # Memory Affinity: type 1, len 40.
    ma = bytearray(40)
    ma[0] = 1   # type
    ma[1] = 40  # length
    struct.pack_into("<I", ma, 2, 0)            # proximity domain
    struct.pack_into("<Q", ma, 8, 0x00000000)   # base address
    struct.pack_into("<Q", ma, 16, 0x40000000)  # length (1 GiB)
    struct.pack_into("<I", ma, 28, 1)           # flags: enabled
    body += ma
    total = 36 + len(body)
    t = table_header(b"SRAT", total) + body
    return bytes(fix_table_checksum(t))


def main() -> None:
    out = sys.argv[1] if len(sys.argv) > 1 else "corpus/acpi"
    os.makedirs(out, exist_ok=True)
    seeds = {
        "rsdp_v1.bin": build_rsdp_v1(),
        "rsdp_v2.bin": build_rsdp_v2(),
        "madt.bin": build_madt(),
        "fadt.bin": build_fadt(),
        "mcfg.bin": build_mcfg(),
        "hpet.bin": build_hpet(),
        "srat.bin": build_srat(),
    }
    for name, data in seeds.items():
        open(os.path.join(out, name), "wb").write(data)
    print(f"seeded {out}: {len(os.listdir(out))} files")


if __name__ == "__main__":
    main()
