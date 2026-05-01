#include "net/wireless/crypto/hmac.h"

#include "core/panic.h"

namespace duetos::net::wireless::crypto
{

namespace
{

constexpr u32 kHmacBlockBytes = 64;
constexpr u8 kHmacIPad = 0x36;
constexpr u8 kHmacOPad = 0x5C;

// Generic HMAC over a hash whose block size is 64 bytes (true for
// both SHA-1 and SHA-256). The `digest_bytes` parameter selects
// which digest to use; the implementation just dispatches to the
// matching primitives. v0 keeps two specializations for
// readability; common code shape stays in a static helper.
void HmacInner(const u8* key, u32 key_len, const u8* data, u32 data_len, u8* out, u32 digest_bytes)
{
    u8 ipad_key[kHmacBlockBytes];
    u8 opad_key[kHmacBlockBytes];
    u8 hashed_key[kSha256DigestBytes]; // big enough for either

    const u8* effective_key = key;
    u32 effective_key_len = key_len;
    if (key_len > kHmacBlockBytes)
    {
        if (digest_bytes == kSha1DigestBytes)
            Sha1Hash(key, key_len, hashed_key);
        else
            Sha256Hash(key, key_len, hashed_key);
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
    else
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
            KASSERT(mac[i] == want[i], "net/wireless/crypto/hmac", "HMAC-SHA1 RFC 2202 vector 1 mismatch");
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
            KASSERT(mac[i] == want[i], "net/wireless/crypto/hmac", "HMAC-SHA256 RFC 4231 vector 1 mismatch");
    }
}

} // namespace duetos::net::wireless::crypto
