#!/usr/bin/env python3
# DuetOS PE fuzz seed generator.
#
# WHAT  Emits a handful of structurally-valid PE32+ images into an
#       output directory so libFuzzer's PE harness (fuzz_pe) starts
#       past the DOS/COFF prefix gate and actually exercises the
#       deep C++ directory walkers (ParseHeaders, PeReport's
#       import/reloc/TLS/load-config walks) instead of just the
#       "random bytes are not 'MZ'" rejection path.
#
# WHY   With no seed, ~all fuzz inputs die at BadDosMagic and the
#       interesting pe_loader.cpp code (the part with raw pointer
#       arithmetic over attacker offsets) is never reached. The
#       minimal PE mirrors the Rust crate's make_min_pe_image()
#       fixture; the real shipped windows-kill.exe (if present)
#       is the high-fidelity seed that has real imports/sections.
#
# USAGE  python3 gen_pe_seeds.py <out_dir>
#        (the Makefile's run-pe target calls this automatically)

import os
import struct
import sys

DOS_MAGIC = 0x5A4D
PE_SIG = 0x00004550
MACHINE_AMD64 = 0x8664
MACHINE_I386 = 0x014C
OPT_MAGIC_PE32PLUS = 0x020B
OPT_MAGIC_PE32 = 0x010B
PAGE_ALIGN = 0x1000


def min_pe(machine=MACHINE_AMD64, opt_magic=OPT_MAGIC_PE32PLUS, nsec=1):
    nt_base = 0x40
    opt_size = 112
    buf = bytearray(0x40)
    struct.pack_into("<H", buf, 0, DOS_MAGIC)
    struct.pack_into("<I", buf, 0x3C, nt_base)
    buf += struct.pack("<I", PE_SIG)
    # FileHeader: Machine, NumSections, TimeDateStamp, PtrToSym,
    # NumSyms, SizeOfOptionalHeader, Characteristics.
    buf += struct.pack("<H", machine)
    buf += struct.pack("<H", nsec)
    buf += struct.pack("<I", 0)
    buf += struct.pack("<I", 0)
    buf += struct.pack("<I", 0)
    buf += struct.pack("<H", opt_size)
    buf += struct.pack("<H", 0)
    opt = bytearray(opt_size)
    struct.pack_into("<H", opt, 0, opt_magic)
    struct.pack_into("<I", opt, 16, 0x1000)  # AddressOfEntryPoint
    struct.pack_into("<Q", opt, 24, 0x0040_0000)  # ImageBase
    struct.pack_into("<I", opt, 32, PAGE_ALIGN)  # SectionAlignment
    struct.pack_into("<I", opt, 36, 512)  # FileAlignment
    struct.pack_into("<I", opt, 56, 0x1000)  # SizeOfImage
    struct.pack_into("<I", opt, 108, 0)  # NumberOfRvaAndSizes
    buf += opt
    buf += bytearray(40 * nsec)  # zero-extent section header(s)
    return bytes(buf)


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "corpus/pe"
    os.makedirs(out, exist_ok=True)

    seeds = {
        "min_amd64.pe": min_pe(),
        "min_amd64_2sec.pe": min_pe(nsec=2),
        "min_i386.pe": min_pe(machine=MACHINE_I386, opt_magic=OPT_MAGIC_PE32),
    }
    for name, data in seeds.items():
        with open(os.path.join(out, name), "wb") as fh:
            fh.write(data)

    # The shipped real PE is the richest seed (real imports,
    # sections, data directories). Symlink-free copy keeps the
    # corpus self-contained.
    real = os.path.join(
        os.path.dirname(__file__),
        "..", "..", "..",
        "userland", "apps", "windows_kill", "windows-kill.exe",
    )
    if os.path.isfile(real):
        with open(real, "rb") as src:
            with open(os.path.join(out, "windows-kill.exe"), "wb") as dst:
                dst.write(src.read())

    print(f"seeded {out}: {len(os.listdir(out))} files")


if __name__ == "__main__":
    main()
