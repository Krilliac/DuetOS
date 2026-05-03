#include "crypto/aes_ccm.h"

#include "core/panic.h"

namespace duetos::crypto
{

namespace
{

constexpr u32 kBlockBytes = 16;

bool TagLenValid(u32 t)
{
    return t == 4 || t == 6 || t == 8 || t == 10 || t == 12 || t == 14 || t == 16;
}

void XorBlock(u8 dst[kBlockBytes], const u8* src, u32 src_len)
{
    for (u32 i = 0; i < src_len && i < kBlockBytes; ++i)
        dst[i] ^= src[i];
}

void EncryptBlockInplace(const AesCtx& ctx, u8 b[kBlockBytes])
{
    AesEncryptBlock(ctx, b, b);
}

// SP 800-38C §A.3 — counter block format with L=2 (so 13-byte
// nonce, 16-bit big-endian counter), M = (tag_len - 2)/2 in the
// flags byte for the CBC-MAC, M coded as 0 in the CTR flags.
void BuildCtrBlock(u8 ctr[kBlockBytes], const u8 nonce[kAesCcmNonceBytes], u16 i)
{
    ctr[0] = 0x01; // flags: L-1 = 1 (so nonce length 13)
    for (u32 k = 0; k < 13; ++k)
        ctr[1 + k] = nonce[k];
    ctr[14] = u8(i >> 8);
    ctr[15] = u8(i);
}

bool CcmCore(const AesCtx& ctx, const u8 nonce[kAesCcmNonceBytes], const u8* aad, u32 aad_len, const u8* in, u32 len,
             u8* out, bool encrypt, u8* tag, u32 tag_len)
{
    if (!TagLenValid(tag_len))
        return false;
    if (aad_len > 0xFEFFu)
        return false; // v0 caps AAD at the 2-byte length-prefix range
    // CCMP enforces L=2, which limits payload to 2^16-1 bytes;
    // beyond that the spec requires a different L encoding.
    if (len > 0xFFFEu)
        return false;

    // Step 1: CBC-MAC over B0 || formatted-AAD || formatted-payload.
    u8 mac[kBlockBytes] = {};
    // B0: flags || nonce || Q (length of plaintext, big-endian, L bytes).
    const u8 m_field = u8((tag_len - 2) / 2);
    const u8 flags_b0 = u8(((aad_len > 0) ? 0x40 : 0x00) | (m_field << 3) | 0x01); // L-1=1
    mac[0] = flags_b0;
    for (u32 i = 0; i < 13; ++i)
        mac[1 + i] = nonce[i];
    mac[14] = u8(len >> 8);
    mac[15] = u8(len);
    EncryptBlockInplace(ctx, mac);

    // AAD formatting: 2-byte big-endian length, then bytes, padded to block.
    if (aad_len > 0)
    {
        u8 aad_block[kBlockBytes] = {};
        aad_block[0] = u8(aad_len >> 8);
        aad_block[1] = u8(aad_len);
        const u32 first_take = (aad_len < kBlockBytes - 2) ? aad_len : (kBlockBytes - 2);
        for (u32 i = 0; i < first_take; ++i)
            aad_block[2 + i] = aad[i];
        XorBlock(mac, aad_block, kBlockBytes);
        EncryptBlockInplace(ctx, mac);

        u32 off = first_take;
        while (off < aad_len)
        {
            u8 blk[kBlockBytes] = {};
            const u32 take = (aad_len - off < kBlockBytes) ? (aad_len - off) : kBlockBytes;
            for (u32 i = 0; i < take; ++i)
                blk[i] = aad[off + i];
            XorBlock(mac, blk, kBlockBytes);
            EncryptBlockInplace(ctx, mac);
            off += take;
        }
    }

    // Plaintext formatting: padded to block. CBC-MAC absorbs the
    // *plaintext*, not the ciphertext (per the spec). For decrypt
    // we recover the plaintext stream first using CTR, then feed
    // it into the MAC computation here.
    const u8* mac_data = encrypt ? in : nullptr;

    // For decrypt we have to first recover plaintext via CTR, so
    // do that now.
    u8* plain = nullptr;
    if (!encrypt)
    {
        // Run CTR to recover plaintext into `out` (caller's buffer).
        u32 off = 0;
        u16 i = 1;
        while (off < len)
        {
            u8 ctr_blk[kBlockBytes];
            BuildCtrBlock(ctr_blk, nonce, i);
            u8 ks[kBlockBytes];
            AesEncryptBlock(ctx, ctr_blk, ks);
            const u32 take = (len - off < kBlockBytes) ? (len - off) : kBlockBytes;
            for (u32 j = 0; j < take; ++j)
                out[off + j] = u8(in[off + j] ^ ks[j]);
            off += take;
            ++i;
        }
        plain = out;
        mac_data = plain;
    }

    if (len > 0)
    {
        u32 off = 0;
        while (off < len)
        {
            u8 blk[kBlockBytes] = {};
            const u32 take = (len - off < kBlockBytes) ? (len - off) : kBlockBytes;
            for (u32 i = 0; i < take; ++i)
                blk[i] = mac_data[off + i];
            XorBlock(mac, blk, kBlockBytes);
            EncryptBlockInplace(ctx, mac);
            off += take;
        }
    }

    // Step 2: encrypt counter block index 0 to derive S0; XOR with MAC[0..tag_len].
    u8 s0[kBlockBytes];
    {
        u8 ctr0[kBlockBytes];
        BuildCtrBlock(ctr0, nonce, 0);
        AesEncryptBlock(ctx, ctr0, s0);
    }

    if (encrypt)
    {
        // Now CTR-encrypt plaintext -> ciphertext, counter starting at 1.
        u32 off = 0;
        u16 i = 1;
        while (off < len)
        {
            u8 ctr_blk[kBlockBytes];
            BuildCtrBlock(ctr_blk, nonce, i);
            u8 ks[kBlockBytes];
            AesEncryptBlock(ctx, ctr_blk, ks);
            const u32 take = (len - off < kBlockBytes) ? (len - off) : kBlockBytes;
            for (u32 j = 0; j < take; ++j)
                out[off + j] = u8(in[off + j] ^ ks[j]);
            off += take;
            ++i;
        }
        for (u32 i = 0; i < tag_len; ++i)
            tag[i] = u8(mac[i] ^ s0[i]);
        return true;
    }
    else
    {
        // Recompute T = mac[0..tag_len] XOR s0[0..tag_len].
        u8 expected[16];
        for (u32 i = 0; i < tag_len; ++i)
            expected[i] = u8(mac[i] ^ s0[i]);
        u8 diff = 0;
        for (u32 i = 0; i < tag_len; ++i)
            diff |= u8(expected[i] ^ tag[i]);
        return diff == 0;
    }
}

} // namespace

bool AesCcm128Encrypt(const u8 key[kAes128KeyBytes], const u8 nonce[kAesCcmNonceBytes], const u8* aad, u32 aad_len,
                      const u8* plaintext, u32 plaintext_len, u8* ciphertext, u8* tag, u32 tag_len)
{
    AesCtx ctx;
    AesKeyExpand128(ctx, key);
    return CcmCore(ctx, nonce, aad, aad_len, plaintext, plaintext_len, ciphertext, true, tag, tag_len);
}

bool AesCcm128Decrypt(const u8 key[kAes128KeyBytes], const u8 nonce[kAesCcmNonceBytes], const u8* aad, u32 aad_len,
                      const u8* ciphertext, u32 ciphertext_len, const u8* tag, u32 tag_len, u8* plaintext)
{
    AesCtx ctx;
    AesKeyExpand128(ctx, key);
    return CcmCore(ctx, nonce, aad, aad_len, ciphertext, ciphertext_len, plaintext, false, const_cast<u8*>(tag),
                   tag_len);
}

bool AesCcm256Encrypt(const u8 key[kAes256KeyBytes], const u8 nonce[kAesCcmNonceBytes], const u8* aad, u32 aad_len,
                      const u8* plaintext, u32 plaintext_len, u8* ciphertext, u8* tag, u32 tag_len)
{
    AesCtx ctx;
    AesKeyExpand256(ctx, key);
    return CcmCore(ctx, nonce, aad, aad_len, plaintext, plaintext_len, ciphertext, true, tag, tag_len);
}

bool AesCcm256Decrypt(const u8 key[kAes256KeyBytes], const u8 nonce[kAesCcmNonceBytes], const u8* aad, u32 aad_len,
                      const u8* ciphertext, u32 ciphertext_len, const u8* tag, u32 tag_len, u8* plaintext)
{
    AesCtx ctx;
    AesKeyExpand256(ctx, key);
    return CcmCore(ctx, nonce, aad, aad_len, ciphertext, ciphertext_len, plaintext, false, const_cast<u8*>(tag),
                   tag_len);
}

void AesCcmSelfTest()
{
    // ----- Round-trip a 32-byte plaintext with 8 bytes of AAD and an
    // 8-byte tag — the CCMP-shaped configuration. We don't have a
    // 13-byte-nonce NIST vector handy, so the test is "encrypt, then
    // decrypt with the same inputs and confirm round-trip"; a
    // tampered tag must reject.
    {
        u8 key[16];
        for (u32 i = 0; i < 16; ++i)
            key[i] = u8(i + 1);
        u8 nonce[13];
        for (u32 i = 0; i < 13; ++i)
            nonce[i] = u8(0x10 + i);
        u8 aad[8];
        for (u32 i = 0; i < 8; ++i)
            aad[i] = u8(0xA0 + i);
        u8 plain[32];
        for (u32 i = 0; i < 32; ++i)
            plain[i] = u8(i);
        u8 ct[32];
        u8 tag[8];
        const bool enc_ok = AesCcm128Encrypt(key, nonce, aad, 8, plain, 32, ct, tag, 8);
        KASSERT(enc_ok, "crypto/aes-ccm", "CCM-128 encrypt failed");

        // Verify ciphertext differs from plaintext.
        bool any_diff = false;
        for (u32 i = 0; i < 32; ++i)
            if (ct[i] != plain[i])
                any_diff = true;
        KASSERT(any_diff, "crypto/aes-ccm", "ciphertext == plaintext (no encrypt)");

        // Decrypt round-trip.
        u8 round[32];
        const bool dec_ok = AesCcm128Decrypt(key, nonce, aad, 8, ct, 32, tag, 8, round);
        KASSERT(dec_ok, "crypto/aes-ccm", "CCM-128 decrypt failed");
        for (u32 i = 0; i < 32; ++i)
            KASSERT(round[i] == plain[i], "crypto/aes-ccm", "round-trip mismatch");

        // Tag tamper.
        u8 bad_tag[8];
        for (u32 i = 0; i < 8; ++i)
            bad_tag[i] = tag[i];
        bad_tag[3] ^= 0x80;
        const bool tampered = AesCcm128Decrypt(key, nonce, aad, 8, ct, 32, bad_tag, 8, round);
        KASSERT(!tampered, "crypto/aes-ccm", "tag tamper not rejected");

        // Ciphertext tamper.
        u8 bad_ct[32];
        for (u32 i = 0; i < 32; ++i)
            bad_ct[i] = ct[i];
        bad_ct[10] ^= 1;
        const bool tampered2 = AesCcm128Decrypt(key, nonce, aad, 8, bad_ct, 32, tag, 8, round);
        KASSERT(!tampered2, "crypto/aes-ccm", "ciphertext tamper not rejected");
    }

    // ----- AES-256-CCM round-trip smoke (no NIST vector handy).
    {
        u8 key[32];
        for (u32 i = 0; i < 32; ++i)
            key[i] = u8(i + 1);
        u8 nonce[13];
        for (u32 i = 0; i < 13; ++i)
            nonce[i] = u8(0x20 + i);
        u8 plain[10];
        for (u32 i = 0; i < 10; ++i)
            plain[i] = u8('a' + i);
        u8 ct[10];
        u8 tag[16];
        const bool ok = AesCcm256Encrypt(key, nonce, nullptr, 0, plain, 10, ct, tag, 16);
        KASSERT(ok, "crypto/aes-ccm", "CCM-256 encrypt failed");
        u8 round[10];
        const bool dec = AesCcm256Decrypt(key, nonce, nullptr, 0, ct, 10, tag, 16, round);
        KASSERT(dec, "crypto/aes-ccm", "CCM-256 decrypt failed");
        for (u32 i = 0; i < 10; ++i)
            KASSERT(round[i] == plain[i], "crypto/aes-ccm", "CCM-256 round-trip mismatch");
    }

    // ----- Tag-length validation.
    {
        u8 key[16] = {};
        u8 nonce[13] = {};
        u8 ct[1] = {};
        u8 tag[16];
        const bool bad = AesCcm128Encrypt(key, nonce, nullptr, 0, nullptr, 0, ct, tag, 5);
        KASSERT(!bad, "crypto/aes-ccm", "bad tag length not rejected");
    }
}

} // namespace duetos::crypto
