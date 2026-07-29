// test_smbios_type17.cpp — hosted unit test for the freestanding
// SMBIOS Type 17 (Memory Device) field decoders.
//
// Covers kernel/arch/x86_64/smbios_decode.h:
//   DecodeMemorySizeBytes  — the five-case Size encoding, incl. the
//                            KB-vs-MB unit bit and Extended Size
//   DecodeMemorySpeedMts   — configured-speed-preferred-over-rated
//   MemorySlotIsEmpty      — empty slot vs unknown size
//   MemoryTypeName / MemoryFormFactorName
//
// Offsets and sentinel semantics are pinned to SMBIOS DSP0134 §7.18.
// These run against synthetic records rather than live firmware,
// because the decode is exactly the part that a boot on one machine
// would not exercise: a single desktop reports one size encoding, and
// the KB-unit and Extended-Size paths only appear on modules that this
// dev host does not have.

#include "host_test_helper.h"

#include "arch/x86_64/smbios_decode.h"

using namespace duetos_host_test;
namespace dec = duetos::arch::smbios_decode;

using duetos::u16;
using duetos::u32;
using duetos::u64;
using duetos::u8;

namespace
{

// A Type 17 record long enough to carry every field we decode
// (through Configured Memory Speed at 0x20..0x21 => length 0x22).
constexpr u8 kFullLength = 0x22;

// Build a zeroed record of `length` bytes with the type/length header
// filled in. Callers poke the fields they care about.
struct Record
{
    u8 bytes[64];

    explicit Record(u8 length)
    {
        for (u32 i = 0; i < sizeof(bytes); ++i)
            bytes[i] = 0;
        bytes[0] = 17;     // Type
        bytes[1] = length; // Length
    }

    void PutU16(u32 off, u16 v)
    {
        bytes[off] = static_cast<u8>(v & 0xFF);
        bytes[off + 1] = static_cast<u8>((v >> 8) & 0xFF);
    }

    void PutU32(u32 off, u32 v)
    {
        bytes[off] = static_cast<u8>(v & 0xFF);
        bytes[off + 1] = static_cast<u8>((v >> 8) & 0xFF);
        bytes[off + 2] = static_cast<u8>((v >> 16) & 0xFF);
        bytes[off + 3] = static_cast<u8>((v >> 24) & 0xFF);
    }

    const u8* fmt() const { return bytes; }
};

constexpr u64 kMiB = 1024ULL * 1024ULL;

} // namespace

int main()
{
    // --- Size: plain megabyte encoding (bit 15 clear) -----------------
    // The common case: an 8 GiB DDR4 module reports 8192 MB.
    {
        Record r(kFullLength);
        r.PutU16(dec::kType17OffsetSize, 8192);
        EXPECT_EQ(dec::DecodeMemorySizeBytes(r.fmt(), kFullLength), 8192ULL * kMiB);
        EXPECT_FALSE(dec::MemorySlotIsEmpty(r.fmt(), kFullLength));
    }

    // A 32 GiB module — still comfortably under the 0x7FFF escape.
    {
        Record r(kFullLength);
        r.PutU16(dec::kType17OffsetSize, 32768);
        EXPECT_EQ(dec::DecodeMemorySizeBytes(r.fmt(), kFullLength), 32768ULL * kMiB);
    }

    // --- Size: kilobyte encoding (bit 15 set) -------------------------
    // Bit 15 flips the unit to KB. 0x8100 => 0x0100 == 256 KB, NOT
    // 33024 MB — getting this backwards would overstate a small module
    // by ~4000x, which is precisely the bug this case exists to catch.
    {
        Record r(kFullLength);
        r.PutU16(dec::kType17OffsetSize, static_cast<u16>(0x8000U | 256U));
        EXPECT_EQ(dec::DecodeMemorySizeBytes(r.fmt(), kFullLength), 256ULL * 1024ULL);
    }

    // --- Size: 0x7FFF escape to Extended Size -------------------------
    // Modules >= 32 GiB - 1 MB use the DWORD at 0x1C, in megabytes.
    // 65536 MB == 64 GiB.
    {
        Record r(kFullLength);
        r.PutU16(dec::kType17OffsetSize, dec::kSizeUseExtended);
        r.PutU32(dec::kType17OffsetExtendedSize, 65536);
        EXPECT_EQ(dec::DecodeMemorySizeBytes(r.fmt(), kFullLength), 65536ULL * kMiB);
    }

    // Bit 31 of Extended Size is reserved and must be masked off, not
    // folded into the magnitude.
    {
        Record r(kFullLength);
        r.PutU16(dec::kType17OffsetSize, dec::kSizeUseExtended);
        r.PutU32(dec::kType17OffsetExtendedSize, 0x80000000U | 16384U);
        EXPECT_EQ(dec::DecodeMemorySizeBytes(r.fmt(), kFullLength), 16384ULL * kMiB);
    }

    // A record that escapes to Extended Size but is too short to hold
    // it must report unknown rather than read past its own length.
    {
        Record r(0x1C);
        r.PutU16(dec::kType17OffsetSize, dec::kSizeUseExtended);
        r.PutU32(dec::kType17OffsetExtendedSize, 65536); // present in buffer, past Length
        EXPECT_EQ(dec::DecodeMemorySizeBytes(r.fmt(), 0x1C), 0ULL);
    }

    // --- Size: empty slot vs unknown ----------------------------------
    // Both decode to 0 bytes, but they mean different things and a UI
    // renders them differently ("empty" vs "unavailable").
    {
        Record empty(kFullLength);
        empty.PutU16(dec::kType17OffsetSize, dec::kSizeEmptySlot);
        EXPECT_EQ(dec::DecodeMemorySizeBytes(empty.fmt(), kFullLength), 0ULL);
        EXPECT_TRUE(dec::MemorySlotIsEmpty(empty.fmt(), kFullLength));

        Record unknown(kFullLength);
        unknown.PutU16(dec::kType17OffsetSize, dec::kSizeUnknown);
        EXPECT_EQ(dec::DecodeMemorySizeBytes(unknown.fmt(), kFullLength), 0ULL);
        EXPECT_FALSE(dec::MemorySlotIsEmpty(unknown.fmt(), kFullLength));
    }

    // --- Speed: configured wins over rated ----------------------------
    // A DDR4-3200 kit left at stock JEDEC reports rated 3200 but
    // configured 2133. The configured rate is the true clock.
    {
        Record r(kFullLength);
        r.PutU16(dec::kType17OffsetSpeed, 3200);
        r.PutU16(dec::kType17OffsetConfiguredSpeed, 2133);
        EXPECT_EQ(dec::DecodeMemorySpeedMts(r.fmt(), kFullLength), 2133U);
    }

    // Configured absent (0) => fall back to the rated speed.
    {
        Record r(kFullLength);
        r.PutU16(dec::kType17OffsetSpeed, 3200);
        r.PutU16(dec::kType17OffsetConfiguredSpeed, 0);
        EXPECT_EQ(dec::DecodeMemorySpeedMts(r.fmt(), kFullLength), 3200U);
    }

    // Configured explicitly "unknown" (0xFFFF) => also fall back.
    {
        Record r(kFullLength);
        r.PutU16(dec::kType17OffsetSpeed, 2666);
        r.PutU16(dec::kType17OffsetConfiguredSpeed, dec::kSpeedUnknown);
        EXPECT_EQ(dec::DecodeMemorySpeedMts(r.fmt(), kFullLength), 2666U);
    }

    // A short (SMBIOS 2.3-era) record has no configured-speed field at
    // all; the rated speed must still decode without over-reading.
    {
        Record r(0x17);
        r.PutU16(dec::kType17OffsetSpeed, 1333);
        r.PutU16(dec::kType17OffsetConfiguredSpeed, 9999); // past Length — must be ignored
        EXPECT_EQ(dec::DecodeMemorySpeedMts(r.fmt(), 0x17), 1333U);
    }

    // Both unknown => 0, never a fabricated number.
    {
        Record r(kFullLength);
        r.PutU16(dec::kType17OffsetSpeed, 0);
        r.PutU16(dec::kType17OffsetConfiguredSpeed, 0);
        EXPECT_EQ(dec::DecodeMemorySpeedMts(r.fmt(), kFullLength), 0U);
    }

    // A record too short even for the rated-speed field.
    {
        Record r(0x15);
        EXPECT_EQ(dec::DecodeMemorySpeedMts(r.fmt(), 0x15), 0U);
    }

    // --- Truncated record guards --------------------------------------
    // A record that doesn't even reach the Size field reports unknown
    // and is not mistaken for an empty slot.
    {
        Record r(0x0C);
        EXPECT_EQ(dec::DecodeMemorySizeBytes(r.fmt(), 0x0C), 0ULL);
        EXPECT_FALSE(dec::MemorySlotIsEmpty(r.fmt(), 0x0C));
    }

    // --- Name tables ---------------------------------------------------
    EXPECT_STREQ(dec::MemoryTypeName(0x1A), "DDR4");
    EXPECT_STREQ(dec::MemoryTypeName(0x22), "DDR5");
    EXPECT_STREQ(dec::MemoryTypeName(0x18), "DDR3");
    // An unassigned code must degrade to "unknown", not to a neighbour.
    EXPECT_STREQ(dec::MemoryTypeName(0x77), "unknown");
    EXPECT_STREQ(dec::MemoryFormFactorName(0x09), "DIMM");
    EXPECT_STREQ(dec::MemoryFormFactorName(0x0D), "SODIMM");
    EXPECT_STREQ(dec::MemoryFormFactorName(0x00), "unknown");

    // --- Endianness sanity ---------------------------------------------
    // SMBIOS is little-endian; a byte-swapped read of 0x0102 would give
    // 0x0201 == 513. Pin the correct value so a future "optimisation"
    // to an unaligned u16 load on a big-endian port fails loudly.
    {
        Record r(kFullLength);
        r.bytes[dec::kType17OffsetSize] = 0x02;
        r.bytes[dec::kType17OffsetSize + 1] = 0x01;
        EXPECT_EQ(dec::ReadU16(r.fmt(), dec::kType17OffsetSize), static_cast<u16>(0x0102));
        EXPECT_EQ(dec::DecodeMemorySizeBytes(r.fmt(), kFullLength), 258ULL * kMiB);
    }

    std::printf("[smbios-type17-host] PASS\n");
    return 0;
}
