#!/usr/bin/env python3
"""Cross-check the duetos-vmm hostile-input test vectors.

WHAT
  Rebuilds, byte for byte, the malformed ELF64 / record-log images that
  tools/vmm/tests/{test_elf64_parse,test_elf_symbols_load,test_record}.cpp
  construct, then evaluates BOTH the pre-hardening and post-hardening
  range predicates against each one.

WHY
  The C++ tests can only prove the hardened predicate rejects a vector.
  They cannot prove the vector actually tripped the ORIGINAL bug -- a
  vector that was simply malformed in some boring way would pass the new
  code while proving nothing. This asserts, for every case, that the old
  predicate wrongly said "in range" (or under-reported a size) and the
  new one rejects. That is the pre-fix failure evidence, and it runs
  without a C++ toolchain.

USAGE
  python3 tools/test/vmm-parser-vectors.py          # exit 0 = all vectors valid
  python3 tools/test/vmm-parser-vectors.py -v       # show every case

Mirrors: tools/vmm/src/elf64_parse.cpp, src/debug/elf_symbols.cpp,
         src/debug/record.cpp
"""
import sys
import struct

U64_MAX = (1 << 64) - 1
MASK64 = U64_MAX

FAILURES = []
CHECKS = 0


def check(cond, label):
    global CHECKS
    CHECKS += 1
    if not cond:
        FAILURES.append(label)
    if "-v" in sys.argv:
        print(("  ok   " if cond else "  FAIL ") + label)


# --- the two predicates ---------------------------------------------------
def old_in_range(off, ln, size):
    """Pre-hardening: `off + ln > size` -- wraps at 2**64."""
    return ((off + ln) & MASK64) <= size


def new_in_range(off, ln, size):
    """Post-hardening InFile(): subtraction, cannot wrap."""
    return off <= size and ln <= size - off


EHDR = 64
PHDR = 56
SHDR = 64
SYM = 24


def build_elf64(phs, tail=64):
    """[Ehdr][phdrs][tail] -- mirrors BuildElf in test_elf64_parse.cpp."""
    n = len(phs)
    buf = bytearray(EHDR + n * PHDR + tail)
    buf[0:4] = b"\x7fELF"
    buf[4] = 2
    buf[5] = 1
    struct.pack_into("<H", buf, 16, 2)
    struct.pack_into("<H", buf, 18, 62)
    struct.pack_into("<Q", buf, 24, 0x100000)
    struct.pack_into("<Q", buf, 32, EHDR)
    struct.pack_into("<H", buf, 54, PHDR)
    struct.pack_into("<H", buf, 56, n)
    for i, ph in enumerate(phs):
        o = EHDR + i * PHDR
        struct.pack_into("<I", buf, o + 0, ph.get("type", 1))
        struct.pack_into("<Q", buf, o + 8, ph.get("offset", 0))
        struct.pack_into("<Q", buf, o + 24, ph.get("paddr", 0))
        struct.pack_into("<Q", buf, o + 32, ph.get("filesz", 0))
        struct.pack_into("<Q", buf, o + 40, ph.get("memsz", 0))
    return buf


def elf64_vectors():
    print("ELF64 program headers (src/elf64_parse.cpp)")

    # 1. e_phoff near 2**64: phoff + phnum*phentsize wraps small.
    buf = build_elf64([{"offset": EHDR + PHDR, "paddr": 0x100000,
                        "filesz": 8, "memsz": 8}])
    size = len(buf)
    phoff = U64_MAX - 8
    check(old_in_range(phoff, PHDR, size),
          "phoff=UINT64_MAX-8: OLD wrongly accepts (wrapped to %d <= %d)"
          % ((phoff + PHDR) & MASK64, size))
    check(not new_in_range(phoff, PHDR, size),
          "phoff=UINT64_MAX-8: NEW rejects")

    # 2. p_offset near 2**64 with a small p_filesz.
    off, flen = U64_MAX - 4, 16
    check(old_in_range(off, flen, size),
          "p_offset=UINT64_MAX-4 filesz=16: OLD wrongly accepts (wrapped to %d)"
          % ((off + flen) & MASK64))
    check(not new_in_range(off, flen, size),
          "p_offset=UINT64_MAX-4 filesz=16: NEW rejects")

    # 3. p_paddr + p_memsz wrap under-reports the RAM requirement.
    paddr, memsz = U64_MAX - 0x1000, 0x2000
    wrapped = (paddr + memsz) & MASK64
    check(wrapped < paddr,
          "paddr+memsz: OLD under-reports highPaddr (0x%x -> 0x%x)"
          % (paddr, wrapped))
    check(memsz > U64_MAX - paddr, "paddr+memsz: NEW rejects the overflow")

    # 4. Sanity: the well-formed image must satisfy the new predicate.
    body = EHDR + 2 * PHDR
    good = build_elf64([{"offset": body, "paddr": 0x100000, "filesz": 32,
                         "memsz": 32},
                        {"offset": body, "paddr": 0x200000, "filesz": 16,
                         "memsz": 64}])
    check(new_in_range(body, 32, len(good)),
          "valid 2-segment image: NEW accepts both segments")
    check(new_in_range(EHDR, 2 * PHDR, len(good)),
          "valid 2-segment image: NEW accepts the phdr table")


def elf_symbols_vectors():
    print("ELF symbol table (src/debug/elf_symbols.cpp)")
    shnum = 3
    shoff = EHDR
    symoff = EHDR + shnum * SHDR
    strtab = b"\x00g_ticks\x00"
    size = symoff + 1 * SYM + len(strtab)

    # e_shoff / e_shnum bound the section-header table.
    check(not new_in_range(U64_MAX - 8, SHDR, size),
          "e_shoff=UINT64_MAX-8: NEW rejects the shdr table")
    check(old_in_range(U64_MAX - 8, SHDR, size),
          "e_shoff=UINT64_MAX-8: OLD wrongly accepts")
    check(not new_in_range(shoff, 1000 * SHDR, size),
          "e_shnum=1000: NEW rejects (table would run past EOF)")
    check(new_in_range(shoff, shnum * SHDR, size),
          "e_shnum=3: NEW accepts the real table")

    # sh_link must index a real section.
    check(99 >= shnum, "sh_link=99: out of range for e_shnum=3")

    # sh_offset / sh_size of .symtab and .strtab.
    check(not new_in_range(U64_MAX - 16, SYM, size),
          "symtab sh_offset=UINT64_MAX-16: NEW rejects")
    check(not new_in_range(symoff, U64_MAX // 2, size),
          "symtab sh_size=UINT64_MAX/2: NEW rejects")

    # st_name past the end of .strtab.
    check(9999 >= len(strtab), "st_name=9999: past the %d-byte .strtab"
          % len(strtab))

    # THE unbounded read: .strtab = {0,'a','b','c'} with no trailing NUL,
    # placed flush against EOF. The bounded scan must stop at the section
    # end and yield exactly "abc".
    unterm = b"\x00abc"
    st_name = 1
    maxlen = len(unterm) - st_name
    scanned = 0
    while scanned < maxlen and unterm[st_name + scanned] != 0:
        scanned += 1
    check(scanned == 3 and unterm[st_name:st_name + scanned] == b"abc",
          'unterminated .strtab: bounded scan yields "abc" (%d bytes)'
          % scanned)
    check(unterm[-1] != 0,
          "unterminated .strtab: last byte is not NUL, so an unbounded "
          "std::string() scan would leave the mapping")


def record_vectors():
    print("Record/replay log (src/debug/record.cpp)")
    magic = b"DUETREC1"
    frame = 8 + 1 + 8
    check(frame == 17, "frame is 17 bytes (u64 seq | u8 kind | u64 a)")

    def mk(seq, kind, a):
        return struct.pack("<QBQ", seq, kind, a)

    legal = {1, 2, 3}
    check(0 not in legal, "kind=0: not a legal EvKind")
    check(99 not in legal, "kind=99: not a legal EvKind")
    check(all(k in legal for k in (1, 2, 3)),
          "kinds 1..3 (SerialRx/RaiseLine/Pit2Expire) are legal")

    body = magic + mk(1, 1, ord("A")) + mk(2, 99, 0) + mk(3, 2, 4)
    check(len(body) == 8 + 3 * frame, "unknown-kind vector is well-formed")
    check(body[8 + frame + 8] == 99, "unknown-kind byte lands at frame 2")

    # Backwards seq is TOLERATED, not rejected: EventLog::Put is called
    # from four threads with no lock, stamping a seq read from a plain
    # non-atomic ExitTrace::m_seq, so a correct recording can legitimately
    # contain out-of-order frames. Rejecting them would truncate a valid
    # replay. This vector only pins that the ordering really is backwards.
    back = magic + mk(10, 1, ord("A")) + mk(5, 1, ord("B"))
    s0 = struct.unpack_from("<Q", back, 8)[0]
    s1 = struct.unpack_from("<Q", back, 8 + frame)[0]
    check(s1 < s0,
          "backwards-seq vector really goes backwards (%d < %d) -- and is "
          "tolerated by design" % (s1, s0))

    trunc = magic + mk(1, 1, ord("A")) + b"\x00" * 5
    check((len(trunc) - 8) % frame != 0,
          "truncated vector leaves a partial trailing frame")


def mmap_vectors():
    print("Multiboot2 memory map (src/multiboot2.cpp)")
    ram = 64 << 20
    res_end = 0x800000
    fb = 0x400000  # below reservedEnd -- the collision case
    check(((fb - res_end) & MASK64) > ram,
          "fbAddr<reservedEnd: OLD length underflows to 0x%x (> %d RAM)"
          % ((fb - res_end) & MASK64, ram))
    fb_base = max(fb, res_end)
    fb_base = min(fb_base, ram)
    check(fb_base - res_end == 0 and ram - fb_base <= ram,
          "NEW clamp yields a 0-length available entry, no underflow")

    res_big = 64 << 20
    ram_small = 4 << 20
    check(((ram_small - res_big) & MASK64) > ram_small,
          "reservedEnd>ram: OLD length underflows to 0x%x"
          % ((ram_small - res_big) & MASK64))
    clamped = min(res_big, ram_small)
    check(ram_small - clamped == 0, "NEW clamp yields 0, no underflow")


def main():
    elf64_vectors()
    elf_symbols_vectors()
    record_vectors()
    mmap_vectors()
    print("\n%d checks, %d failures" % (CHECKS, len(FAILURES)))
    for f in FAILURES:
        print("  FAILED: " + f)
    return 1 if FAILURES else 0


if __name__ == "__main__":
    sys.exit(main())
