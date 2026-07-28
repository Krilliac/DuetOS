// TDD for the GDB remote-serial-protocol operand decoders.
//
// Regression origin: the stub parsed every variable-length operand by
// indexing the received std::string directly. `$G00#xx` gave a 2-char
// body and WriteRegisters read hex[0..271] — ~270 bytes of adjacent
// heap written straight into the guest's RAX..RIP — while "Z0" (size
// 2) formed `pkt.c_str() + 3`, past one-past-the-end, and handed it to
// sscanf. These tests pin the length rules, not the happy path alone:
// every short/malformed vector must be REJECTED, and a well-formed
// packet must still decode exactly as it used to.
#include <cstdint>
#include <string>

#include "debug/gdb_packet.h"
#include "test_main.h"

using duetos::vmm::gdb::kMaxMemBytes;
using duetos::vmm::gdb::kRegBlockHexLen;
using duetos::vmm::gdb::kRegBlockRegs;
using duetos::vmm::gdb::ParseBpSpec;
using duetos::vmm::gdb::ParseMemSpec;
using duetos::vmm::gdb::ParseRegBlock;

namespace
{
// Builds a valid 'G' payload: 17 little-endian 8-byte registers where
// register i holds `base + i`.
std::string RegBlock(uint64_t base)
{
    static const char* kNyb = "0123456789abcdef";
    std::string        s;
    for (size_t r = 0; r < kRegBlockRegs; ++r)
    {
        const uint64_t v = base + r;
        for (size_t b = 0; b < 8; ++b)
        {
            const uint8_t byte = static_cast<uint8_t>(v >> (8 * b));
            s += kNyb[byte >> 4];
            s += kNyb[byte & 0xF];
        }
    }
    return s;
}
} // namespace

// The exact packet that used to spray heap into the guest: `G` plus a
// single hex byte. 2 chars < 272 -> reject, no indexing.
TEST(gdb_G_short_block_rejected)
{
    uint64_t r[kRegBlockRegs] = {};
    CHECK(!ParseRegBlock("00", r));
}

// `$G#xx` — empty payload after the command char.
TEST(gdb_G_empty_block_rejected)
{
    uint64_t r[kRegBlockRegs] = {};
    CHECK(!ParseRegBlock("", r));
}

// One char short of the RIP slot is still short.
TEST(gdb_G_one_char_short_rejected)
{
    uint64_t r[kRegBlockRegs] = {};
    std::string hex = RegBlock(0).substr(0, kRegBlockHexLen - 1);
    CHECK(!ParseRegBlock(hex, r));
}

// Right length, but a non-hex digit inside it — Unhex used to map
// anything unknown to 0 and write it to the guest silently.
TEST(gdb_G_non_hex_rejected)
{
    uint64_t    r[kRegBlockRegs] = {};
    std::string hex              = RegBlock(0);
    hex[100]                     = 'z';
    CHECK(!ParseRegBlock(hex, r));
}

// Happy path: little-endian, RAX..R15 then RIP, unchanged semantics.
TEST(gdb_G_full_block_decodes_le)
{
    uint64_t r[kRegBlockRegs] = {};
    CHECK(ParseRegBlock(RegBlock(0x1000), r));
    CHECK_EQ(r[0], 0x1000ull);  // rax
    CHECK_EQ(r[15], 0x100Full); // r15
    CHECK_EQ(r[16], 0x1010ull); // rip
}

// A longer block (the full 328-char 'g' reply echoed back) is fine —
// we only consume the 17-register prefix.
TEST(gdb_G_trailing_flags_ignored)
{
    uint64_t r[kRegBlockRegs] = {};
    CHECK(ParseRegBlock(RegBlock(7) + "0246000000000000", r));
    CHECK_EQ(r[16], 0x17ull);
}

// `m<addr>,<len>` happy path.
TEST(gdb_m_addr_len_decodes)
{
    uint64_t a = 0, l = 0;
    CHECK(ParseMemSpec("m1000,40", a, l));
    CHECK_EQ(a, 0x1000ull);
    CHECK_EQ(l, 0x40ull);
}

// The unbounded-length hole: ReadMem looped `for (i = 0; i < len; ++i)`
// appending 2 chars per byte, so this asked for a 32 EiB reply string.
// Clamped to what one PacketSize-bounded reply can carry.
TEST(gdb_m_huge_len_clamped)
{
    uint64_t a = 0, l = 0;
    CHECK(ParseMemSpec("mffffffff,ffffffffffffffff", a, l));
    CHECK_EQ(l, kMaxMemBytes);
}

// No comma -> no length field. sscanf left `l` at 0 and read 0 bytes;
// now it is an explicit reject so the client sees E22.
TEST(gdb_m_missing_comma_rejected)
{
    uint64_t a = 0, l = 0;
    CHECK(!ParseMemSpec("m1000", a, l));
}

// Bare "m": no address digits at all.
TEST(gdb_m_bare_rejected)
{
    uint64_t a = 0, l = 0;
    CHECK(!ParseMemSpec("m", a, l));
}

// Comma present but nothing after it.
TEST(gdb_m_empty_len_rejected)
{
    uint64_t a = 0, l = 0;
    CHECK(!ParseMemSpec("m1000,", a, l));
}

// `M<addr>,<len>:<data>` reports where the payload starts.
TEST(gdb_M_reports_data_offset)
{
    uint64_t a = 0, l = 0;
    size_t   off = 0;
    CHECK(ParseMemSpec("M2000,2:9090", a, l, &off));
    CHECK_EQ(a, 0x2000ull);
    CHECK_EQ(l, 2ull);
    CHECK_EQ(off, 8u); // index of the first payload char
}

// An 'M' with no ':' has no payload — offset stays 0 and the caller
// rejects rather than writing whatever followed the length.
TEST(gdb_M_missing_colon_has_no_payload)
{
    uint64_t a = 0, l = 0;
    size_t   off = 7;
    CHECK(ParseMemSpec("M2000,2", a, l, &off));
    CHECK_EQ(off, 0u);
}

// `Z0,<addr>,<kind>` happy path.
TEST(gdb_Z0_addr_decodes)
{
    uint64_t a = 0;
    CHECK(ParseBpSpec("Z0,ffff800000201000,1", a));
    CHECK_EQ(a, 0xffff800000201000ull);
}

// The `c_str() + 3` hole: "Z0" is size 2, so index 3 is past
// one-past-the-end. Must be rejected before the pointer is formed.
TEST(gdb_Z0_no_address_rejected)
{
    uint64_t a = 0;
    CHECK(!ParseBpSpec("Z0", a));
}

// Same for the remove form.
TEST(gdb_z0_no_address_rejected)
{
    uint64_t a = 0;
    CHECK(!ParseBpSpec("z0", a));
}

// Comma but no address digits.
TEST(gdb_Z0_empty_address_rejected)
{
    uint64_t a = 0;
    CHECK(!ParseBpSpec("Z0,", a));
}

// Missing the separator entirely.
TEST(gdb_Z0_missing_comma_rejected)
{
    uint64_t a = 0;
    CHECK(!ParseBpSpec("Z01000", a));
}
