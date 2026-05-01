#include "net/wireless/crypto/pbkdf2.h"

#include "core/panic.h"
#include "net/wireless/crypto/hmac.h"
#include "net/wireless/crypto/sha1.h"

namespace duetos::net::wireless::crypto
{

namespace
{

void XorInto(u8* dst, const u8* src, u32 len)
{
    for (u32 i = 0; i < len; ++i)
        dst[i] ^= src[i];
}

u32 StringLen(const char* s)
{
    u32 n = 0;
    if (s == nullptr)
        return 0;
    while (s[n] != '\0')
        ++n;
    return n;
}

} // namespace

void Pbkdf2HmacSha1(const u8* password, u32 password_len, const u8* salt, u32 salt_len, u32 iterations, u8* out,
                    u32 out_len)
{
    if (out == nullptr || out_len == 0)
        return;

    // PBKDF2 produces ceil(out_len/20) blocks of 20 bytes. Each
    // block T_i = U_1 ⊕ U_2 ⊕ ... ⊕ U_iterations, where U_1 =
    // HMAC-SHA1(password, salt || INT(i)) and U_j = HMAC-SHA1(password, U_{j-1}).
    const u32 block_size = kSha1DigestBytes;
    const u32 num_blocks = (out_len + block_size - 1u) / block_size;

    for (u32 block = 1; block <= num_blocks; ++block)
    {
        // Build salt || INT(block).
        u8 work[256]; // bounded — WPA2 salts are SSIDs, ≤ 32 bytes.
        // Salts longer than 252 bytes aren't a real-world concern
        // here; bail safely if so.
        if (salt_len > 252)
            return;
        for (u32 i = 0; i < salt_len; ++i)
            work[i] = salt[i];
        work[salt_len] = static_cast<u8>((block >> 24) & 0xFFu);
        work[salt_len + 1] = static_cast<u8>((block >> 16) & 0xFFu);
        work[salt_len + 2] = static_cast<u8>((block >> 8) & 0xFFu);
        work[salt_len + 3] = static_cast<u8>(block & 0xFFu);

        u8 u[kSha1DigestBytes];
        u8 t[kSha1DigestBytes];
        HmacSha1(password, password_len, work, salt_len + 4, u);
        for (u32 i = 0; i < block_size; ++i)
            t[i] = u[i];

        for (u32 j = 1; j < iterations; ++j)
        {
            u8 u_next[kSha1DigestBytes];
            HmacSha1(password, password_len, u, kSha1DigestBytes, u_next);
            for (u32 i = 0; i < block_size; ++i)
                u[i] = u_next[i];
            XorInto(t, u, block_size);
        }

        // Copy out into final buffer.
        const u32 base = (block - 1u) * block_size;
        const u32 to_copy = (out_len - base < block_size) ? (out_len - base) : block_size;
        for (u32 i = 0; i < to_copy; ++i)
            out[base + i] = t[i];
    }
}

void WpaPmkDerive(const char* passphrase, const char* ssid, u32 ssid_len, u8 out[kPmkBytes])
{
    Pbkdf2HmacSha1(reinterpret_cast<const u8*>(passphrase), StringLen(passphrase), reinterpret_cast<const u8*>(ssid),
                   ssid_len, kPbkdf2WpaIterations, out, kPmkBytes);
}

void Pbkdf2SelfTest()
{
    // IEEE 802.11i Annex H.4 / RFC 7616 cross-vector:
    //   passphrase = "password", SSID = "IEEE", 4096 iter, 32 bytes:
    //   F4 2C 6F C5 2D F0 EB EF 9E BB 4B 90 B3 8A 5F 90
    //   2E 83 FE 1B 13 5A 70 E2 3A AB 11 E4 D2 80 18 70
    {
        u8 pmk[32];
        WpaPmkDerive("password", "IEEE", 4u, pmk);
        const u8 want[32] = {0xF4, 0x2C, 0x6F, 0xC5, 0x2D, 0xF0, 0xEB, 0xEF, 0x9E, 0xBB, 0x4B,
                             0x90, 0xB3, 0x8A, 0x5F, 0x90, 0x2E, 0x83, 0xFE, 0x1B, 0x13, 0x5A,
                             0x70, 0xE2, 0x3A, 0xAB, 0x11, 0xE4, 0xD2, 0x80, 0x18, 0x70};
        for (u32 i = 0; i < 32; ++i)
            KASSERT(pmk[i] == want[i], "net/wireless/crypto/pbkdf2", "PBKDF2-WPA \"password\"/IEEE KAT mismatch");
    }
    // Second IEEE 802.11i vector:
    //   passphrase = "ThisIsAPassword", SSID = "ThisIsASSID", 4096 iter:
    //   0D C0 D6 EB 90 55 5E D6 41 97 56 B9 A1 5E C3 E3
    //   20 9B 63 DF 70 7D D5 08 D1 45 81 F8 98 27 21 AF
    {
        u8 pmk[32];
        WpaPmkDerive("ThisIsAPassword", "ThisIsASSID", 11u, pmk);
        const u8 want[32] = {0x0D, 0xC0, 0xD6, 0xEB, 0x90, 0x55, 0x5E, 0xD6, 0x41, 0x97, 0x56,
                             0xB9, 0xA1, 0x5E, 0xC3, 0xE3, 0x20, 0x9B, 0x63, 0xDF, 0x70, 0x7D,
                             0xD5, 0x08, 0xD1, 0x45, 0x81, 0xF8, 0x98, 0x27, 0x21, 0xAF};
        for (u32 i = 0; i < 32; ++i)
            KASSERT(pmk[i] == want[i], "net/wireless/crypto/pbkdf2",
                    "PBKDF2-WPA \"ThisIsAPassword\"/SSID KAT mismatch");
    }
}

} // namespace duetos::net::wireless::crypto
