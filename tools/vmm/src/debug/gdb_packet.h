// Pure, length-checked decoders for the GDB remote-serial-protocol
// operands the host stub accepts. Split out of gdb_server.cpp for the
// same reason mmio_decode was: the stub's socket is an UNTRUSTED
// input — anything on the host that can reach loopback speaks to it —
// so the parsing has to be unit-testable without a WHP partition.
//
// The rule every entry point enforces: never index a std::string past
// its size. Only `s[s.size()]` is defined ([string.access]); the old
// hand-rolled decode read `hex[off]` for off up to 271 regardless of
// what arrived, so a 2-char `$G00#xx` sprayed ~270 bytes of adjacent
// heap straight into the guest's RAX..RIP. Each function below returns
// false on anything short or malformed and gdb_server.cpp turns that
// into an RSP error reply. Protocol semantics are unchanged: a
// well-formed packet decodes exactly as it did before.
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

namespace duetos::vmm::gdb
{

// Longest packet body RecvPacket will buffer. A conforming client
// never exceeds the PacketSize we advertise; this only bounds a peer
// that never sends the terminating '#'.
constexpr size_t kMaxPacketBody = 64 * 1024;

// The 'G' write covers 16 GPRs + RIP, 8 bytes each, hex-encoded two
// chars per byte. eflags and the segment selectors that follow in the
// 164-byte 'g' block are read-only for us, so this prefix — not the
// full block — is the length bar a 'G' packet has to clear.
constexpr size_t kRegBlockRegs   = 17;
constexpr size_t kRegBlockHexLen = kRegBlockRegs * 16; // 272

// Largest 'm' read we service, derived from the PacketSize=4000 we
// advertise in qSupported. RSP counts that field in HEX (0x4000 =
// 16384 reply chars) and a byte costs two hex chars, so 8192 bytes is
// the most one reply can carry. Over-long requests are clamped rather
// than refused — a short read is explicitly legal in RSP, and gdb
// re-requests the remainder.
constexpr uint64_t kMaxMemBytes = 0x4000 / 2;

bool    IsHex(char c);
uint8_t Unhex(char c);

// 'G' — decodes the leading 17 little-endian 8-byte registers (RAX..
// R15 then RIP) of `hex` into `out`. False if `hex` is shorter than
// kRegBlockHexLen or holds a non-hex digit inside that prefix.
bool ParseRegBlock(const std::string& hex, uint64_t out[kRegBlockRegs]);

// 'm'/'M' — decodes the `<addr>,<len>` operand starting at index 1 of
// `pkt`. Requires at least one hex digit on each side of a literal
// ','; `len` is clamped to kMaxMemBytes. For 'M', `dataOff` receives
// the index of the first payload hex char (just past the ':') and
// stays 0 when the packet carries no ':'.
bool ParseMemSpec(const std::string& pkt, uint64_t& addr, uint64_t& len,
                  size_t* dataOff = nullptr);

// 'Z0'/'z0' — decodes the address from `<Z|z>0,<addr>[,<kind>]`. The
// address field starts at index 3, so a bare "Z0" (size 2) has to be
// rejected before `c_str() + 3` is even formed.
bool ParseBpSpec(const std::string& pkt, uint64_t& addr);

} // namespace duetos::vmm::gdb
