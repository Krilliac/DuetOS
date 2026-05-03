#include "util/crc32.h"

#include "core/panic.h"

namespace duetos::util
{

namespace
{

constinit u32 g_crc_table[256] = {};
constinit bool g_crc_table_ready = false;

void Crc32TableInit()
{
    if (g_crc_table_ready)
        return;
    for (u32 i = 0; i < 256; ++i)
    {
        u32 c = i;
        for (int j = 0; j < 8; ++j)
            c = (c & 1) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
        g_crc_table[i] = c;
    }
    g_crc_table_ready = true;
}

} // namespace

u32 Crc32(const u8* data, u64 len)
{
    Crc32TableInit();
    u32 c = 0xFFFFFFFFu;
    for (u64 i = 0; i < len; ++i)
        c = g_crc_table[(c ^ data[i]) & 0xFFu] ^ (c >> 8);
    return c ^ 0xFFFFFFFFu;
}

void Crc32SelfTest()
{
    // Standard ASCII "123456789" → 0xCBF43926. Every CRC-32
    // (IEEE 802.3, reflected) reference uses this.
    {
        const u8 msg[9] = {'1', '2', '3', '4', '5', '6', '7', '8', '9'};
        const u32 got = Crc32(msg, 9);
        KASSERT(got == 0xCBF43926u, "util/crc32", "CRC32(\"123456789\") mismatch (expected 0xCBF43926)");
    }
    // Empty input → 0 by convention. Some libraries return ~0
    // pre-XOR; the reflected form with the 0xFFFFFFFF final XOR
    // collapses to 0 for the empty buffer.
    {
        const u32 got = Crc32(nullptr, 0);
        KASSERT(got == 0u, "util/crc32", "CRC32(empty) mismatch (expected 0)");
    }
    // Single 0x00 byte → 0xD202EF8D (well-known reference).
    {
        const u8 msg[1] = {0x00};
        const u32 got = Crc32(msg, 1);
        KASSERT(got == 0xD202EF8Du, "util/crc32", "CRC32(0x00) mismatch (expected 0xD202EF8D)");
    }
    // Single 0xFF byte → 0xFF000000.
    {
        const u8 msg[1] = {0xFF};
        const u32 got = Crc32(msg, 1);
        KASSERT(got == 0xFF000000u, "util/crc32", "CRC32(0xFF) mismatch (expected 0xFF000000)");
    }
}

} // namespace duetos::util
