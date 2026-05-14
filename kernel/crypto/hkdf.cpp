#include "crypto/hkdf.h"

#include "arch/x86_64/serial.h"
#include "crypto/hmac.h"

namespace duetos::crypto
{

void HkdfSha256Extract(const u8* salt, u32 salt_len, const u8* ikm, u32 ikm_len, u8 prk[kSha256DigestBytes])
{
    // RFC 5869 §2.2: PRK = HMAC(salt, IKM). Empty salt is
    // treated as a zero-filled HashLen block.
    u8 zero_salt[kSha256DigestBytes];
    if (salt == nullptr || salt_len == 0)
    {
        for (u32 i = 0; i < kSha256DigestBytes; ++i)
            zero_salt[i] = 0;
        salt = zero_salt;
        salt_len = kSha256DigestBytes;
    }
    HmacSha256(salt, salt_len, ikm == nullptr ? reinterpret_cast<const u8*>("") : ikm, ikm_len, prk);
}

bool HkdfSha256Expand(const u8 prk[kSha256DigestBytes], const u8* info, u32 info_len, u8* out, u32 len)
{
    if (len > kHkdfSha256MaxOkm)
        return false;
    if (out == nullptr)
        return false;
    if (info == nullptr)
        info_len = 0;
    // RFC 5869 §2.3: T(0) = empty, T(i) = HMAC(PRK, T(i-1) ||
    // info || octet(i)). OKM = T(1) || T(2) || ... truncated
    // to `len` bytes.
    u8 t[kSha256DigestBytes];
    u32 t_len = 0; // first iteration: empty T(0)
    u32 written = 0;
    u8 counter = 0;
    constexpr u32 kHmacInputCap = kSha256DigestBytes + 256 + 1;
    u8 hmac_input[kHmacInputCap];
    if (info_len > 256)
        return false; // safety net; TLS labels are << 256
    while (written < len)
    {
        ++counter;
        if (counter == 0)
            return false; // > 255 iterations — protected by cap above
        u32 in_off = 0;
        for (u32 i = 0; i < t_len; ++i)
            hmac_input[in_off++] = t[i];
        for (u32 i = 0; i < info_len; ++i)
            hmac_input[in_off++] = info[i];
        hmac_input[in_off++] = counter;
        HmacSha256(prk, kSha256DigestBytes, hmac_input, in_off, t);
        t_len = kSha256DigestBytes;
        const u32 take = (len - written < kSha256DigestBytes) ? (len - written) : kSha256DigestBytes;
        for (u32 i = 0; i < take; ++i)
            out[written + i] = t[i];
        written += take;
    }
    return true;
}

bool HkdfSha256(const u8* salt, u32 salt_len, const u8* ikm, u32 ikm_len, const u8* info, u32 info_len, u8* out,
                u32 len)
{
    u8 prk[kSha256DigestBytes];
    HkdfSha256Extract(salt, salt_len, ikm, ikm_len, prk);
    return HkdfSha256Expand(prk, info, info_len, out, len);
}

// ---------------------------------------------------------------------------
// Self-test: RFC 5869 Appendix A.1 (Test Case 1, SHA-256).
// ---------------------------------------------------------------------------

void HkdfSelfTest()
{
    using arch::SerialWrite;

    // RFC 5869 §A.1
    const u8 ikm[22] = {0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
                        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b};
    const u8 salt[13] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c};
    const u8 info[10] = {0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9};
    constexpr u32 kOkmLen = 42;
    const u8 want_prk[32] = {0x07, 0x77, 0x09, 0x36, 0x2c, 0x2e, 0x32, 0xdf, 0x0d, 0xdc, 0x3f,
                             0x0d, 0xc4, 0x7b, 0xba, 0x63, 0x90, 0xb6, 0xc7, 0x3b, 0xb5, 0x0f,
                             0x9c, 0x31, 0x22, 0xec, 0x84, 0x4a, 0xd7, 0xc2, 0xb3, 0xe5};
    const u8 want_okm[42] = {0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36,
                             0x2f, 0x2a, 0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56,
                             0xec, 0xc4, 0xc5, 0xbf, 0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65};

    u8 prk[32];
    HkdfSha256Extract(salt, sizeof(salt), ikm, sizeof(ikm), prk);
    for (u32 i = 0; i < 32; ++i)
    {
        if (prk[i] != want_prk[i])
        {
            SerialWrite("[hkdf] FAIL extract\n");
            return;
        }
    }

    u8 okm[kOkmLen];
    if (!HkdfSha256Expand(prk, info, sizeof(info), okm, kOkmLen))
    {
        SerialWrite("[hkdf] FAIL expand-call\n");
        return;
    }
    for (u32 i = 0; i < kOkmLen; ++i)
    {
        if (okm[i] != want_okm[i])
        {
            SerialWrite("[hkdf] FAIL expand-bytes\n");
            return;
        }
    }

    // Combined helper produces the same OKM.
    u8 combined[kOkmLen];
    if (!HkdfSha256(salt, sizeof(salt), ikm, sizeof(ikm), info, sizeof(info), combined, kOkmLen))
    {
        SerialWrite("[hkdf] FAIL combined-call\n");
        return;
    }
    for (u32 i = 0; i < kOkmLen; ++i)
    {
        if (combined[i] != want_okm[i])
        {
            SerialWrite("[hkdf] FAIL combined-bytes\n");
            return;
        }
    }

    SerialWrite("[hkdf] PASS (RFC 5869 A.1 extract + expand + combined)\n");
}

} // namespace duetos::crypto
