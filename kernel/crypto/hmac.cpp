#include "crypto/hmac.h"

#include "core/panic.h"

namespace duetos::crypto
{

namespace
{

constexpr u32 kHmacBlockBytes = 64;
constexpr u8 kHmacIPad = 0x36;
constexpr u8 kHmacOPad = 0x5C;

// Generic HMAC over a hash whose block size is 64 bytes (true for
// SHA-1, SHA-256, and MD5). The `digest_bytes` parameter selects
// which digest to use; the implementation just dispatches to the
// matching primitives.
void HmacInner(const u8* key, u32 key_len, const u8* data, u32 data_len, u8* out, u32 digest_bytes)
{
    u8 ipad_key[kHmacBlockBytes];
    u8 opad_key[kHmacBlockBytes];
    u8 hashed_key[kSha256DigestBytes]; // big enough for any of the three

    const u8* effective_key = key;
    u32 effective_key_len = key_len;
    if (key_len > kHmacBlockBytes)
    {
        if (digest_bytes == kSha1DigestBytes)
            Sha1Hash(key, key_len, hashed_key);
        else if (digest_bytes == kSha256DigestBytes)
            Sha256Hash(key, key_len, hashed_key);
        else
            Md5Hash(key, key_len, hashed_key);
        effective_key = hashed_key;
        effective_key_len = digest_bytes;
    }

    for (u32 i = 0; i < kHmacBlockBytes; ++i)
    {
        const u8 kb = (i < effective_key_len) ? effective_key[i] : 0u;
        ipad_key[i] = kb ^ kHmacIPad;
        opad_key[i] = kb ^ kHmacOPad;
    }

    if (digest_bytes == kSha1DigestBytes)
    {
        Sha1Ctx ctx;
        Sha1Init(ctx);
        Sha1Update(ctx, ipad_key, kHmacBlockBytes);
        Sha1Update(ctx, data, data_len);
        u8 inner[kSha1DigestBytes];
        Sha1Final(ctx, inner);

        Sha1Init(ctx);
        Sha1Update(ctx, opad_key, kHmacBlockBytes);
        Sha1Update(ctx, inner, kSha1DigestBytes);
        Sha1Final(ctx, out);
    }
    else if (digest_bytes == kSha256DigestBytes)
    {
        Sha256Ctx ctx;
        Sha256Init(ctx);
        Sha256Update(ctx, ipad_key, kHmacBlockBytes);
        Sha256Update(ctx, data, data_len);
        u8 inner[kSha256DigestBytes];
        Sha256Final(ctx, inner);

        Sha256Init(ctx);
        Sha256Update(ctx, opad_key, kHmacBlockBytes);
        Sha256Update(ctx, inner, kSha256DigestBytes);
        Sha256Final(ctx, out);
    }
    else
    {
        Md5Ctx ctx;
        Md5Init(ctx);
        Md5Update(ctx, ipad_key, kHmacBlockBytes);
        Md5Update(ctx, data, data_len);
        u8 inner[kMd5DigestBytes];
        Md5Final(ctx, inner);

        Md5Init(ctx);
        Md5Update(ctx, opad_key, kHmacBlockBytes);
        Md5Update(ctx, inner, kMd5DigestBytes);
        Md5Final(ctx, out);
    }
}

} // namespace

void HmacSha1(const u8* key, u32 key_len, const u8* data, u32 data_len, u8 out[kSha1DigestBytes])
{
    HmacInner(key, key_len, data, data_len, out, kSha1DigestBytes);
}

void HmacSha256(const u8* key, u32 key_len, const u8* data, u32 data_len, u8 out[kSha256DigestBytes])
{
    HmacInner(key, key_len, data, data_len, out, kSha256DigestBytes);
}

void HmacMd5(const u8* key, u32 key_len, const u8* data, u32 data_len, u8 out[kMd5DigestBytes])
{
    HmacInner(key, key_len, data, data_len, out, kMd5DigestBytes);
}

void HmacSelfTest()
{
    // RFC 2202 test vector 1: HMAC-SHA1 with key 20 × 0x0B and data
    // "Hi There" → 0xB617318655057264E28BC0B6FB378C8EF146BE00
    {
        u8 key[20];
        for (u32 i = 0; i < 20; ++i)
            key[i] = 0x0B;
        const u8 msg[8] = {'H', 'i', ' ', 'T', 'h', 'e', 'r', 'e'};
        u8 mac[20];
        HmacSha1(key, 20, msg, 8, mac);
        const u8 want[20] = {0xB6, 0x17, 0x31, 0x86, 0x55, 0x05, 0x72, 0x64, 0xE2, 0x8B,
                             0xC0, 0xB6, 0xFB, 0x37, 0x8C, 0x8E, 0xF1, 0x46, 0xBE, 0x00};
        for (u32 i = 0; i < 20; ++i)
            KASSERT(mac[i] == want[i], "crypto/hmac", "HMAC-SHA1 RFC 2202 vector 1 mismatch");
    }
    // RFC 4231 test vector 1: HMAC-SHA256 with key 20 × 0x0B and
    // data "Hi There" → 0xB0344C61D8DB38535CA8AFCEAF0BF12B881DC200C9833DA726E9376C2E32CFF7
    {
        u8 key[20];
        for (u32 i = 0; i < 20; ++i)
            key[i] = 0x0B;
        const u8 msg[8] = {'H', 'i', ' ', 'T', 'h', 'e', 'r', 'e'};
        u8 mac[32];
        HmacSha256(key, 20, msg, 8, mac);
        const u8 want[32] = {0xB0, 0x34, 0x4C, 0x61, 0xD8, 0xDB, 0x38, 0x53, 0x5C, 0xA8, 0xAF,
                             0xCE, 0xAF, 0x0B, 0xF1, 0x2B, 0x88, 0x1D, 0xC2, 0x00, 0xC9, 0x83,
                             0x3D, 0xA7, 0x26, 0xE9, 0x37, 0x6C, 0x2E, 0x32, 0xCF, 0xF7};
        for (u32 i = 0; i < 32; ++i)
            KASSERT(mac[i] == want[i], "crypto/hmac", "HMAC-SHA256 RFC 4231 vector 1 mismatch");
    }
    // RFC 2202 test vector 1 for HMAC-MD5: key 16 × 0x0B, data
    // "Hi There" → 0x9294727A3638BB1C13F48EF8158BFC9D
    {
        u8 key[16];
        for (u32 i = 0; i < 16; ++i)
            key[i] = 0x0B;
        const u8 msg[8] = {'H', 'i', ' ', 'T', 'h', 'e', 'r', 'e'};
        u8 mac[16];
        HmacMd5(key, 16, msg, 8, mac);
        const u8 want[16] = {0x92, 0x94, 0x72, 0x7A, 0x36, 0x38, 0xBB, 0x1C,
                             0x13, 0xF4, 0x8E, 0xF8, 0x15, 0x8B, 0xFC, 0x9D};
        for (u32 i = 0; i < 16; ++i)
            KASSERT(mac[i] == want[i], "crypto/hmac", "HMAC-MD5 RFC 2202 vector 1 mismatch");
    }
    // RFC 2202 test vector 2 for HMAC-MD5: key "Jefe", data
    // "what do ya want for nothing?" → 0x750C783E6AB0B503EAA86E310A5DB738
    {
        const u8 key[4] = {'J', 'e', 'f', 'e'};
        const u8 msg[28] = {'w', 'h', 'a', 't', ' ', 'd', 'o', ' ', 'y', 'a', ' ', 'w', 'a', 'n',
                            't', ' ', 'f', 'o', 'r', ' ', 'n', 'o', 't', 'h', 'i', 'n', 'g', '?'};
        u8 mac[16];
        HmacMd5(key, 4, msg, 28, mac);
        const u8 want[16] = {0x75, 0x0C, 0x78, 0x3E, 0x6A, 0xB0, 0xB5, 0x03,
                             0xEA, 0xA8, 0x6E, 0x31, 0x0A, 0x5D, 0xB7, 0x38};
        for (u32 i = 0; i < 16; ++i)
            KASSERT(mac[i] == want[i], "crypto/hmac", "HMAC-MD5 RFC 2202 vector 2 mismatch");
    }
    // RFC 2202 test vector 6 for HMAC-MD5: key 80 × 0xAA (> 64-byte
    // block, exercises the key-shrink branch), data "Test Using
    // Larger Than Block-Size Key - Hash Key First"
    // → 0x6B1AB7FE4BD7BF8F0B62E6CE61B9D0CD
    {
        u8 key[80];
        for (u32 i = 0; i < 80; ++i)
            key[i] = 0xAA;
        const char* text = "Test Using Larger Than Block-Size Key - Hash Key First";
        u32 text_len = 0;
        while (text[text_len] != '\0')
            ++text_len;
        u8 mac[16];
        HmacMd5(key, 80, reinterpret_cast<const u8*>(text), text_len, mac);
        const u8 want[16] = {0x6B, 0x1A, 0xB7, 0xFE, 0x4B, 0xD7, 0xBF, 0x8F,
                             0x0B, 0x62, 0xE6, 0xCE, 0x61, 0xB9, 0xD0, 0xCD};
        for (u32 i = 0; i < 16; ++i)
            KASSERT(mac[i] == want[i], "crypto/hmac", "HMAC-MD5 RFC 2202 vector 6 mismatch");
    }
}

} // namespace duetos::crypto
