#include "crypto/pbkdf2.h"

#include "core/panic.h"
#include "crypto/hmac.h"
#include "crypto/sha1.h"
#include "crypto/sha256.h"

namespace duetos::crypto
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

void Pbkdf2HmacSha256(const u8* password, u32 password_len, const u8* salt, u32 salt_len, u32 iterations, u8* out,
                      u32 out_len)
{
    if (out == nullptr || out_len == 0)
        return;

    const u32 block_size = kSha256DigestBytes;
    const u32 num_blocks = (out_len + block_size - 1u) / block_size;

    for (u32 block = 1; block <= num_blocks; ++block)
    {
        u8 work[256];
        if (salt_len > 252)
            return;
        for (u32 i = 0; i < salt_len; ++i)
            work[i] = salt[i];
        work[salt_len] = static_cast<u8>((block >> 24) & 0xFFu);
        work[salt_len + 1] = static_cast<u8>((block >> 16) & 0xFFu);
        work[salt_len + 2] = static_cast<u8>((block >> 8) & 0xFFu);
        work[salt_len + 3] = static_cast<u8>(block & 0xFFu);

        u8 u[kSha256DigestBytes];
        u8 t[kSha256DigestBytes];
        HmacSha256(password, password_len, work, salt_len + 4, u);
        for (u32 i = 0; i < block_size; ++i)
            t[i] = u[i];

        for (u32 j = 1; j < iterations; ++j)
        {
            u8 u_next[kSha256DigestBytes];
            HmacSha256(password, password_len, u, kSha256DigestBytes, u_next);
            for (u32 i = 0; i < block_size; ++i)
                u[i] = u_next[i];
            XorInto(t, u, block_size);
        }

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
    // RFC 6070 vector 1 — easiest first because c=1 means only
    // one HMAC call per output block.
    //   P = "password", S = "salt", c = 1, dkLen = 20:
    //   0c60c80f961f0e71f3a9b524af6012062fe037a6
    {
        u8 dk[20];
        Pbkdf2HmacSha1(reinterpret_cast<const u8*>("password"), 8, reinterpret_cast<const u8*>("salt"), 4, 1, dk, 20);
        const u8 want[20] = {0x0C, 0x60, 0xC8, 0x0F, 0x96, 0x1F, 0x0E, 0x71, 0xF3, 0xA9,
                             0xB5, 0x24, 0xAF, 0x60, 0x12, 0x06, 0x2F, 0xE0, 0x37, 0xA6};
        for (u32 i = 0; i < 20; ++i)
            KASSERT_WITH_VALUE(dk[i] == want[i], "crypto/pbkdf2", "RFC 6070 #1 mismatch", dk[i]);
    }
    // RFC 6070 vector 2 — c=2, exercises the iteration loop.
    //   P = "password", S = "salt", c = 2, dkLen = 20:
    //   ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957
    {
        u8 dk[20];
        Pbkdf2HmacSha1(reinterpret_cast<const u8*>("password"), 8, reinterpret_cast<const u8*>("salt"), 4, 2, dk, 20);
        const u8 want[20] = {0xEA, 0x6C, 0x01, 0x4D, 0xC7, 0x2D, 0x6F, 0x8C, 0xCD, 0x1E,
                             0xD9, 0x2A, 0xCE, 0x1D, 0x41, 0xF0, 0xD8, 0xDE, 0x89, 0x57};
        for (u32 i = 0; i < 20; ++i)
            KASSERT_WITH_VALUE(dk[i] == want[i], "crypto/pbkdf2", "RFC 6070 #2 mismatch", dk[i]);
    }
    // RFC 6070 vector 4 — c=4096, single-block. Isolates
    // iteration-count correctness from multi-block correctness.
    //   P = "password", S = "salt", c = 4096, dkLen = 20:
    //   4b007901b765489abead49d926f721d065a429c1
    {
        u8 dk[20];
        Pbkdf2HmacSha1(reinterpret_cast<const u8*>("password"), 8, reinterpret_cast<const u8*>("salt"), 4, 4096, dk,
                       20);
        const u8 want[20] = {0x4B, 0x00, 0x79, 0x01, 0xB7, 0x65, 0x48, 0x9A, 0xBE, 0xAD,
                             0x49, 0xD9, 0x26, 0xF7, 0x21, 0xD0, 0x65, 0xA4, 0x29, 0xC1};
        for (u32 i = 0; i < 20; ++i)
            KASSERT_WITH_VALUE(dk[i] == want[i], "crypto/pbkdf2", "RFC 6070 #4 mismatch", dk[i]);
    }
    // PBKDF2-HMAC-SHA1("password", "IEEE", 4096, 32) — verified
    // against Python's hashlib.pbkdf2_hmac (independent reference):
    //   f42c6fc52df0ebef9ebb4b90b38a5f902e83fe1b135a70e23aed762e9710a12e
    {
        u8 pmk[32];
        WpaPmkDerive("password", "IEEE", 4u, pmk);
        const u8 want[32] = {0xF4, 0x2C, 0x6F, 0xC5, 0x2D, 0xF0, 0xEB, 0xEF, 0x9E, 0xBB, 0x4B,
                             0x90, 0xB3, 0x8A, 0x5F, 0x90, 0x2E, 0x83, 0xFE, 0x1B, 0x13, 0x5A,
                             0x70, 0xE2, 0x3A, 0xED, 0x76, 0x2E, 0x97, 0x10, 0xA1, 0x2E};
        for (u32 i = 0; i < 32; ++i)
            KASSERT_WITH_VALUE(pmk[i] == want[i], "crypto/pbkdf2", "PBKDF2-WPA \"password\"/IEEE KAT mismatch", pmk[i]);
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
            KASSERT(pmk[i] == want[i], "crypto/pbkdf2", "PBKDF2-WPA \"ThisIsAPassword\"/SSID KAT mismatch");
    }

    // ---------- PBKDF2-HMAC-SHA256 vectors ----------
    // RFC 7914 §11 — PBKDF2-HMAC-SHA256 with P="passwd", S="salt",
    // c=1, dkLen=64.
    //   55 ac 04 6e 56 e3 08 9f ec 16 91 c2 25 44 b6 05
    //   f9 41 85 21 6d de 04 65 e6 8b 9d 57 c2 0d ac bc
    //   49 ca 9c cc f1 79 b6 45 99 16 64 b3 9d 77 ef 31
    //   7c 71 b8 45 b1 e3 0b d5 09 11 20 41 d3 a1 97 83
    {
        u8 dk[64];
        Pbkdf2HmacSha256(reinterpret_cast<const u8*>("passwd"), 6, reinterpret_cast<const u8*>("salt"), 4, 1, dk, 64);
        const u8 want[64] = {0x55, 0xAC, 0x04, 0x6E, 0x56, 0xE3, 0x08, 0x9F, 0xEC, 0x16, 0x91, 0xC2, 0x25,
                             0x44, 0xB6, 0x05, 0xF9, 0x41, 0x85, 0x21, 0x6D, 0xDE, 0x04, 0x65, 0xE6, 0x8B,
                             0x9D, 0x57, 0xC2, 0x0D, 0xAC, 0xBC, 0x49, 0xCA, 0x9C, 0xCC, 0xF1, 0x79, 0xB6,
                             0x45, 0x99, 0x16, 0x64, 0xB3, 0x9D, 0x77, 0xEF, 0x31, 0x7C, 0x71, 0xB8, 0x45,
                             0xB1, 0xE3, 0x0B, 0xD5, 0x09, 0x11, 0x20, 0x41, 0xD3, 0xA1, 0x97, 0x83};
        for (u32 i = 0; i < 64; ++i)
            KASSERT(dk[i] == want[i], "crypto/pbkdf2", "PBKDF2-HMAC-SHA256 RFC 7914 #1 mismatch");
    }
    // RFC 7914 §11 vector 2 (P="Password", S="NaCl", c=80000, dkLen=64)
    // is intentionally omitted — 80k HMAC-SHA256 iterations spin a
    // QEMU-TCG boot for ~40s, and the iteration loop is already
    // covered by the c=4096 PBKDF2-HMAC-SHA1 vectors above (same
    // logic, different inner hash). The single-iter SHA-256 vector
    // covers the SHA-256 inner path. Skipping it loses no unique
    // correctness coverage; it would only stress-test throughput.
}

} // namespace duetos::crypto
