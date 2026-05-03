#include "util/adler32.h"

#include "core/panic.h"

namespace duetos::util
{

u32 Adler32Update(u32 prev, const u8* data, u32 len)
{
    u32 a = prev & 0xFFFFu;
    u32 b = (prev >> 16) & 0xFFFFu;
    while (len > 0)
    {
        const u32 take = (len < kAdler32MaxRunBytes) ? len : kAdler32MaxRunBytes;
        for (u32 i = 0; i < take; ++i)
        {
            a += data[i];
            b += a;
        }
        a %= kAdler32Base;
        b %= kAdler32Base;
        data += take;
        len -= take;
    }
    return (b << 16) | a;
}

u32 Adler32(const u8* data, u32 len)
{
    return Adler32Update(1, data, len);
}

void Adler32SelfTest()
{
    // ----- Reference: Adler-32("Wikipedia") = 0x11E60398.
    {
        const char* s = "Wikipedia";
        u32 n = 0;
        while (s[n] != '\0')
            ++n;
        const u32 c = Adler32(reinterpret_cast<const u8*>(s), n);
        KASSERT(c == 0x11E60398u, "util/adler32", "Wikipedia vector mismatch");
    }

    // ----- Empty input → seed value 1.
    {
        const u32 c = Adler32(nullptr, 0);
        KASSERT(c == 1u, "util/adler32", "empty input should be 1");
    }

    // ----- Single-byte 'a' (0x61). a = 1+0x61 = 0x62; b = 0+0x62 = 0x62.
    // Result = (0x62 << 16) | 0x62 = 0x00620062.
    {
        const u8 one[1] = {'a'};
        const u32 c = Adler32(one, 1);
        KASSERT(c == 0x00620062u, "util/adler32", "single-byte 'a' wrong");
    }

    // ----- Streaming: split "Wikipedia" at offset 4 and ensure the
    // continued checksum equals the one-shot.
    {
        const char* s = "Wikipedia";
        u32 a = Adler32(reinterpret_cast<const u8*>(s), 4);
        a = Adler32Update(a, reinterpret_cast<const u8*>(s + 4), 5);
        KASSERT(a == 0x11E60398u, "util/adler32", "split-stream mismatch");
    }

    // ----- Boundary: a 6000-byte zero buffer (forces the
    // amortized-modulo block to roll over once).
    {
        u8 zeros[6000];
        for (u32 i = 0; i < sizeof(zeros); ++i)
            zeros[i] = 0;
        // a stays at 1; b accumulates 1 per byte → 6000 mod 65521 = 6000.
        // Result = (6000 << 16) | 1 = 0x17700001.
        const u32 c = Adler32(zeros, sizeof(zeros));
        KASSERT(c == 0x17700001u, "util/adler32", "6KB-zeros boundary wrong");
    }
}

} // namespace duetos::util
