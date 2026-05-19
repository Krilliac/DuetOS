#!/usr/bin/env python3
# DuetOS ELF fuzz seed generator.
#
# WHAT  Emits structurally-valid ELF64 (x86_64, LSB) images so the
#       fuzz_elf harness starts past the e_ident/machine gate and
#       exercises the program-header walker (ElfForEachPtLoad) and
#       the duetos_exec_meta Rust validator's PT_LOAD bounds logic
#       instead of dying at BadMagic on every random input.
#
# WHY   With no seed ~all inputs fail the 4-byte \x7fELF magic and
#       the interesting walker code (raw pointer arithmetic over
#       e_phoff + i*e_phentsize) is never reached.
#
# USAGE  python3 gen_elf_seeds.py <out_dir>
#        (the Makefile's run-elf target calls this automatically)

import os
import struct
import sys

EM_X86_64 = 62
ET_EXEC = 2
PT_LOAD = 1
PT_NOTE = 4
EHDR_SZ = 64
PHDR_SZ = 56


def ehdr(e_phoff, e_phnum, e_entry=0x401000, e_phentsize=PHDR_SZ):
    e = bytearray(EHDR_SZ)
    e[0:4] = b"\x7fELF"
    e[4] = 2  # ELFCLASS64
    e[5] = 1  # ELFDATA2LSB
    e[6] = 1  # EV_CURRENT
    struct.pack_into("<H", e, 16, ET_EXEC)
    struct.pack_into("<H", e, 18, EM_X86_64)
    struct.pack_into("<I", e, 20, 1)  # e_version
    struct.pack_into("<Q", e, 24, e_entry)  # e_entry
    struct.pack_into("<Q", e, 32, e_phoff)  # e_phoff
    struct.pack_into("<Q", e, 40, 0)  # e_shoff
    struct.pack_into("<H", e, 52, EHDR_SZ)  # e_ehsize
    struct.pack_into("<H", e, 54, e_phentsize)  # e_phentsize
    struct.pack_into("<H", e, 56, e_phnum)  # e_phnum
    return e


def phdr(p_type, off, vaddr, filesz, memsz, flags=5, align=0x1000):
    p = bytearray(PHDR_SZ)
    struct.pack_into("<I", p, 0, p_type)  # p_type
    struct.pack_into("<I", p, 4, flags)  # p_flags
    struct.pack_into("<Q", p, 8, off)  # p_offset
    struct.pack_into("<Q", p, 16, vaddr)  # p_vaddr
    struct.pack_into("<Q", p, 24, vaddr)  # p_paddr
    struct.pack_into("<Q", p, 32, filesz)  # p_filesz
    struct.pack_into("<Q", p, 40, memsz)  # p_memsz
    struct.pack_into("<Q", p, 48, align)  # p_align
    return p


def min_elf(nphdr=1, extra_note=False):
    phoff = EHDR_SZ
    phs = []
    # One PT_LOAD covering the headers themselves (offset 0,
    # file/mem size = whole file region) — keeps p_offset+p_filesz
    # in-bounds for the Rust validator.
    n = nphdr + (1 if extra_note else 0)
    body_off = phoff + n * PHDR_SZ
    phs.append(phdr(PT_LOAD, 0, 0x400000, body_off + 16, body_off + 16))
    for _ in range(nphdr - 1):
        phs.append(phdr(PT_LOAD, 0, 0x400000, body_off, body_off))
    if extra_note:
        phs.append(phdr(PT_NOTE, body_off, 0, 8, 8, flags=4))
    buf = bytearray()
    buf += ehdr(phoff, n)
    for p in phs:
        buf += p
    buf += b"\x00" * 16  # tiny segment body
    return bytes(buf)


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "corpus/elf"
    os.makedirs(out, exist_ok=True)
    seeds = {
        "min_x86_64.elf": min_elf(),
        "min_2pt.elf": min_elf(nphdr=2),
        "min_note.elf": min_elf(nphdr=1, extra_note=True),
    }
    for name, data in seeds.items():
        with open(os.path.join(out, name), "wb") as fh:
            fh.write(data)
    print(f"seeded {out}: {len(os.listdir(out))} files")


if __name__ == "__main__":
    main()
