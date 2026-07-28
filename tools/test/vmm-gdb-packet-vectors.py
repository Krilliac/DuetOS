#!/usr/bin/env python3
"""Compiler-free model + static contract check for the VMM GDB packet decoders.

The VMM's GDB stub (`tools/vmm/src/debug/gdb_server.cpp`) listens on
loopback whenever `--gdb` is passed, so every packet operand is
untrusted input. The decoders live in `tools/vmm/src/debug/gdb_packet.cpp`
and the host unit test is `tools/vmm/tests/test_gdb_packet.cpp` — but
that needs MSVC. This script needs nothing but python3:

  1. It re-implements the SAME length rules in Python and runs the same
     vector table the C++ test uses, so the rules can be exercised on a
     host with no toolchain.
  2. It statically asserts that gdb_server.cpp routes through the
     parsers instead of indexing the received std::string — the exact
     shape of the original heap-OOB read (`hex[off]` for off up to 271
     on a 2-char body, `pkt.c_str() + 3` on a 2-char "Z0").

Usage:  python3 tools/test/vmm-gdb-packet-vectors.py
Exit:   0 = all vectors + contracts hold, 1 = something drifted.
"""

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]

# Mirrors of the constants in tools/vmm/src/debug/gdb_packet.h.
REG_BLOCK_REGS = 17
REG_BLOCK_HEX_LEN = REG_BLOCK_REGS * 16  # 272
MAX_MEM_BYTES = 0x4000 // 2
MAX_PACKET_BODY = 64 * 1024

HEX_DIGITS = set("0123456789abcdefABCDEF")


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


# --------------------------------------------------------------------
# Model of gdb_packet.cpp
# --------------------------------------------------------------------


def scan_hex(s: str, i: int):
    """Returns (count_consumed, value). Saturates at 2**64-1."""
    start, v = i, 0
    while i < len(s) and s[i] in HEX_DIGITS:
        v = 0xFFFFFFFFFFFFFFFF if v > (0xFFFFFFFFFFFFFFFF >> 4) else (v << 4) | int(s[i], 16)
        i += 1
    return i - start, v


def parse_reg_block(hexstr: str):
    """'G' operand -> list of 17 u64, or None when short / non-hex."""
    if len(hexstr) < REG_BLOCK_HEX_LEN:
        return None
    if any(c not in HEX_DIGITS for c in hexstr[:REG_BLOCK_HEX_LEN]):
        return None
    out = []
    for r in range(REG_BLOCK_REGS):
        chunk = hexstr[r * 16 : r * 16 + 16]
        # little-endian byte order
        out.append(int.from_bytes(bytes.fromhex(chunk), "little"))
    return out


def parse_mem_spec(pkt: str):
    """'m'/'M' operand -> (addr, len, data_off) or None."""
    i = 1  # skip the command char
    na, addr = scan_hex(pkt, i)
    if na == 0:
        return None
    i += na
    if i >= len(pkt) or pkt[i] != ",":
        return None
    i += 1
    nl, length = scan_hex(pkt, i)
    if nl == 0:
        return None
    i += nl
    length = min(length, MAX_MEM_BYTES)
    data_off = i + 1 if i < len(pkt) and pkt[i] == ":" else 0
    return addr, length, data_off


def parse_bp_spec(pkt: str):
    """'Z0'/'z0' operand -> addr or None."""
    if len(pkt) < 4 or pkt[2] != ",":
        return None
    n, addr = scan_hex(pkt, 3)
    return addr if n else None


# --------------------------------------------------------------------
# Vectors (kept 1:1 with tools/vmm/tests/test_gdb_packet.cpp)
# --------------------------------------------------------------------


def reg_block(base: int) -> str:
    return "".join(((base + r) & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little").hex() for r in range(REG_BLOCK_REGS))


def check_vectors() -> None:
    # 'G' — the heap-OOB vector and its neighbours.
    require(parse_reg_block("00") is None, "G: 2-char block must be rejected")
    require(parse_reg_block("") is None, "G: empty block must be rejected")
    require(parse_reg_block(reg_block(0)[:-1]) is None, "G: one char short must be rejected")
    bad = list(reg_block(0))
    bad[100] = "z"
    require(parse_reg_block("".join(bad)) is None, "G: non-hex digit must be rejected")

    regs = parse_reg_block(reg_block(0x1000))
    require(regs is not None, "G: full block must decode")
    require(regs[0] == 0x1000, "G: rax must decode little-endian")
    require(regs[15] == 0x100F, "G: r15 must decode little-endian")
    require(regs[16] == 0x1010, "G: rip must decode little-endian")
    longer = parse_reg_block(reg_block(7) + "0246000000000000")
    require(longer is not None and longer[16] == 0x17, "G: trailing eflags/segs must be ignored")

    # 'm' / 'M' — the unbounded-length and missing-separator vectors.
    require(parse_mem_spec("m1000,40") == (0x1000, 0x40, 0), "m: addr,len must decode")
    huge = parse_mem_spec("mffffffff,ffffffffffffffff")
    require(huge is not None and huge[1] == MAX_MEM_BYTES, "m: u64 length must clamp to PacketSize")
    require(parse_mem_spec("m1000") is None, "m: missing comma must be rejected")
    require(parse_mem_spec("m") is None, "m: bare command must be rejected")
    require(parse_mem_spec("m1000,") is None, "m: empty length must be rejected")
    require(parse_mem_spec("M2000,2:9090") == (0x2000, 2, 8), "M: payload offset must be reported")
    mspec = parse_mem_spec("M2000,2")
    require(mspec is not None and mspec[2] == 0, "M: no ':' means no payload")

    # 'Z0' / 'z0' — the `c_str() + 3` vector.
    require(parse_bp_spec("Z0,ffff800000201000,1") == 0xFFFF800000201000, "Z0: address must decode")
    require(parse_bp_spec("Z0") is None, "Z0: bare command must be rejected")
    require(parse_bp_spec("z0") is None, "z0: bare command must be rejected")
    require(parse_bp_spec("Z0,") is None, "Z0: empty address must be rejected")
    require(parse_bp_spec("Z01000") is None, "Z0: missing comma must be rejected")


# --------------------------------------------------------------------
# Static contracts on the C++ side
# --------------------------------------------------------------------


def check_sources() -> None:
    hdr = read("tools/vmm/src/debug/gdb_packet.h")
    require("kRegBlockRegs * 16" in hdr, "gdb_packet.h: register-block length must stay derived")
    require("kMaxMemBytes = 0x4000 / 2" in hdr, "gdb_packet.h: mem cap must track the advertised PacketSize")
    require("kMaxPacketBody = 64 * 1024" in hdr, "gdb_packet.h: packet-body cap missing")

    srv = read("tools/vmm/src/debug/gdb_server.cpp")
    require("gdb::ParseRegBlock" in srv, "gdb_server.cpp: 'G' must go through ParseRegBlock")
    require("gdb::ParseMemSpec" in srv, "gdb_server.cpp: 'm'/'M' must go through ParseMemSpec")
    require("gdb::ParseBpSpec" in srv, "gdb_server.cpp: 'Z0'/'z0' must go through ParseBpSpec")
    require("gdb::kMaxPacketBody" in srv, "gdb_server.cpp: RecvPacket must cap the body")
    require("c_str() + 3" not in srv, "gdb_server.cpp: the past-the-end 'Z0' pointer is back")
    require("std::sscanf" not in srv, "gdb_server.cpp: sscanf on packet text is back")
    require("PacketSize=4000" in srv, "gdb_server.cpp: advertised PacketSize changed — retune kMaxMemBytes")

    cml = read("tools/vmm/tests/CMakeLists.txt")
    require("test_gdb_packet.cpp" in cml, "vmm-tests: the gdb packet test is not wired in")
    require("../src/debug/gdb_packet.cpp" in cml, "vmm-tests: gdb_packet.cpp is not in the test build")


def main() -> int:
    try:
        check_vectors()
        check_sources()
    except AssertionError as exc:
        print(f"FAIL: {exc}")
        return 1
    except FileNotFoundError as exc:
        print(f"FAIL: missing source: {exc}")
        return 1
    print("PASS: gdb packet vectors + gdb_server contracts hold")
    return 0


if __name__ == "__main__":
    sys.exit(main())
