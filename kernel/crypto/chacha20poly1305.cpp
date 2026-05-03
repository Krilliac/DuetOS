#include "crypto/chacha20poly1305.h"

#include "core/panic.h"

namespace duetos::crypto
{

namespace
{

inline u32 LoadU32Le(const u8* p)
{
    return u32(p[0]) | (u32(p[1]) << 8) | (u32(p[2]) << 16) | (u32(p[3]) << 24);
}

inline void StoreU32Le(u8* p, u32 v)
{
    p[0] = u8(v);
    p[1] = u8(v >> 8);
    p[2] = u8(v >> 16);
    p[3] = u8(v >> 24);
}

inline u32 RotL32(u32 x, u32 n)
{
    return (x << n) | (x >> (32 - n));
}

// ChaCha20 quarter round per RFC 8439 §2.1.
inline void QuarterRound(u32& a, u32& b, u32& c, u32& d)
{
    a += b;
    d ^= a;
    d = RotL32(d, 16);
    c += d;
    b ^= c;
    b = RotL32(b, 12);
    a += b;
    d ^= a;
    d = RotL32(d, 8);
    c += d;
    b ^= c;
    b = RotL32(b, 7);
}

// RFC 8439 §2.3 — produce one 64-byte keystream block.
void ChaCha20Block(const u8 key[kChaCha20KeyBytes], const u8 nonce[kChaCha20NonceBytes], u32 counter,
                   u8 out[kChaCha20BlockBytes])
{
    // The state is 16 × u32:
    //   [0..3]   constants "expand 32-byte k"
    //   [4..11]  256-bit key
    //   [12]     32-bit block counter
    //   [13..15] 96-bit nonce
    u32 state[16];
    state[0] = 0x61707865;
    state[1] = 0x3320646e;
    state[2] = 0x79622d32;
    state[3] = 0x6b206574;
    for (u32 i = 0; i < 8; ++i)
        state[4 + i] = LoadU32Le(key + i * 4);
    state[12] = counter;
    state[13] = LoadU32Le(nonce + 0);
    state[14] = LoadU32Le(nonce + 4);
    state[15] = LoadU32Le(nonce + 8);

    u32 w[16];
    for (u32 i = 0; i < 16; ++i)
        w[i] = state[i];
    for (u32 i = 0; i < 10; ++i)
    {
        // Column rounds.
        QuarterRound(w[0], w[4], w[8], w[12]);
        QuarterRound(w[1], w[5], w[9], w[13]);
        QuarterRound(w[2], w[6], w[10], w[14]);
        QuarterRound(w[3], w[7], w[11], w[15]);
        // Diagonal rounds.
        QuarterRound(w[0], w[5], w[10], w[15]);
        QuarterRound(w[1], w[6], w[11], w[12]);
        QuarterRound(w[2], w[7], w[8], w[13]);
        QuarterRound(w[3], w[4], w[9], w[14]);
    }
    for (u32 i = 0; i < 16; ++i)
        StoreU32Le(out + i * 4, w[i] + state[i]);
}

} // namespace

void ChaCha20Xor(const u8 key[kChaCha20KeyBytes], const u8 nonce[kChaCha20NonceBytes], u32 counter, const u8* in,
                 u8* out, u32 len)
{
    u8 ks[kChaCha20BlockBytes];
    u32 off = 0;
    while (off < len)
    {
        ChaCha20Block(key, nonce, counter, ks);
        const u32 take = (len - off < kChaCha20BlockBytes) ? (len - off) : kChaCha20BlockBytes;
        for (u32 i = 0; i < take; ++i)
            out[off + i] = in[off + i] ^ ks[i];
        off += take;
        ++counter;
    }
}

namespace
{

// Poly1305 (RFC 8439 §2.5) implemented as 5 × 26-bit limbs, the
// donna-style layout. Each multiply produces a u64 product; the
// 130-bit-mod-(2^130-5) reduction folds via the identity
// 2^130 ≡ 5 (mod 2^130 - 5).
struct Poly1305State
{
    u32 r[5];    // clamped 16-byte multiplier as 5×26-bit limbs
    u32 s[4];    // 16-byte addend
    u32 h[5];    // 130-bit accumulator
    u8 buf[16];  // pending partial block
    u32 buf_len; // 0..15
};

void Poly1305Init(Poly1305State& st, const u8 key[kPoly1305KeyBytes])
{
    // Clamp r per RFC 8439 §2.5.1.
    u8 rb[16];
    for (u32 i = 0; i < 16; ++i)
        rb[i] = key[i];
    rb[3] &= 15;
    rb[7] &= 15;
    rb[11] &= 15;
    rb[15] &= 15;
    rb[4] &= 252;
    rb[8] &= 252;
    rb[12] &= 252;

    const u32 t0 = LoadU32Le(rb + 0);
    const u32 t1 = LoadU32Le(rb + 4);
    const u32 t2 = LoadU32Le(rb + 8);
    const u32 t3 = LoadU32Le(rb + 12);
    st.r[0] = (t0) & 0x03ffffffu;
    st.r[1] = ((t0 >> 26) | (t1 << 6)) & 0x03ffffffu;
    st.r[2] = ((t1 >> 20) | (t2 << 12)) & 0x03ffffffu;
    st.r[3] = ((t2 >> 14) | (t3 << 18)) & 0x03ffffffu;
    st.r[4] = (t3 >> 8) & 0x03ffffffu;

    st.s[0] = LoadU32Le(key + 16);
    st.s[1] = LoadU32Le(key + 20);
    st.s[2] = LoadU32Le(key + 24);
    st.s[3] = LoadU32Le(key + 28);

    for (u32 i = 0; i < 5; ++i)
        st.h[i] = 0;
    st.buf_len = 0;
}

// Process exactly one 16-byte block. `final_block_partial` is true
// for a partial last block; the high "1" bit is then placed inside
// the limb at the byte position of the last data byte.
void Poly1305ProcessBlock(Poly1305State& st, const u8 b[16], bool last_full)
{
    const u32 t0 = LoadU32Le(b + 0);
    const u32 t1 = LoadU32Le(b + 4);
    const u32 t2 = LoadU32Le(b + 8);
    const u32 t3 = LoadU32Le(b + 12);

    // Add block to h, including the high "1" bit at byte 16 for
    // full blocks. For partial blocks the caller has already laid
    // down the 1-bit in the source buffer at the byte after the
    // last data byte (and zeros after that), so the high limb
    // gets +0 here.
    st.h[0] += (t0) & 0x03ffffffu;
    st.h[1] += ((t0 >> 26) | (t1 << 6)) & 0x03ffffffu;
    st.h[2] += ((t1 >> 20) | (t2 << 12)) & 0x03ffffffu;
    st.h[3] += ((t2 >> 14) | (t3 << 18)) & 0x03ffffffu;
    st.h[4] += (t3 >> 8) | (last_full ? (1u << 24) : 0u);

    // Multiply h by r modulo 2^130 - 5.
    const u64 r0 = st.r[0];
    const u64 r1 = st.r[1];
    const u64 r2 = st.r[2];
    const u64 r3 = st.r[3];
    const u64 r4 = st.r[4];
    const u64 s1 = st.r[1] * 5;
    const u64 s2 = st.r[2] * 5;
    const u64 s3 = st.r[3] * 5;
    const u64 s4 = st.r[4] * 5;
    const u64 h0 = st.h[0];
    const u64 h1 = st.h[1];
    const u64 h2 = st.h[2];
    const u64 h3 = st.h[3];
    const u64 h4 = st.h[4];

    u64 d0 = h0 * r0 + h1 * s4 + h2 * s3 + h3 * s2 + h4 * s1;
    u64 d1 = h0 * r1 + h1 * r0 + h2 * s4 + h3 * s3 + h4 * s2;
    u64 d2 = h0 * r2 + h1 * r1 + h2 * r0 + h3 * s4 + h4 * s3;
    u64 d3 = h0 * r3 + h1 * r2 + h2 * r1 + h3 * r0 + h4 * s4;
    u64 d4 = h0 * r4 + h1 * r3 + h2 * r2 + h3 * r1 + h4 * r0;

    u32 c;
    c = u32(d0 >> 26);
    st.h[0] = u32(d0) & 0x03ffffffu;
    d1 += c;
    c = u32(d1 >> 26);
    st.h[1] = u32(d1) & 0x03ffffffu;
    d2 += c;
    c = u32(d2 >> 26);
    st.h[2] = u32(d2) & 0x03ffffffu;
    d3 += c;
    c = u32(d3 >> 26);
    st.h[3] = u32(d3) & 0x03ffffffu;
    d4 += c;
    c = u32(d4 >> 26);
    st.h[4] = u32(d4) & 0x03ffffffu;
    st.h[0] += c * 5;
    c = st.h[0] >> 26;
    st.h[0] &= 0x03ffffffu;
    st.h[1] += c;
}

void Poly1305Update(Poly1305State& st, const u8* data, u32 len)
{
    if (st.buf_len > 0)
    {
        const u32 want = 16 - st.buf_len;
        const u32 take = (len < want) ? len : want;
        for (u32 i = 0; i < take; ++i)
            st.buf[st.buf_len + i] = data[i];
        st.buf_len += take;
        data += take;
        len -= take;
        if (st.buf_len == 16)
        {
            Poly1305ProcessBlock(st, st.buf, /*last_full=*/true);
            st.buf_len = 0;
        }
    }
    while (len >= 16)
    {
        Poly1305ProcessBlock(st, data, /*last_full=*/true);
        data += 16;
        len -= 16;
    }
    if (len > 0)
    {
        for (u32 i = 0; i < len; ++i)
            st.buf[i] = data[i];
        st.buf_len = len;
    }
}

void Poly1305Final(Poly1305State& st, u8 tag[kPoly1305TagBytes])
{
    if (st.buf_len > 0)
    {
        st.buf[st.buf_len] = 1;
        for (u32 i = st.buf_len + 1; i < 16; ++i)
            st.buf[i] = 0;
        Poly1305ProcessBlock(st, st.buf, /*last_full=*/false);
    }

    // Final carry chain.
    u32 c;
    c = st.h[1] >> 26;
    st.h[1] &= 0x03ffffffu;
    st.h[2] += c;
    c = st.h[2] >> 26;
    st.h[2] &= 0x03ffffffu;
    st.h[3] += c;
    c = st.h[3] >> 26;
    st.h[3] &= 0x03ffffffu;
    st.h[4] += c;
    c = st.h[4] >> 26;
    st.h[4] &= 0x03ffffffu;
    st.h[0] += c * 5;
    c = st.h[0] >> 26;
    st.h[0] &= 0x03ffffffu;
    st.h[1] += c;

    // Compute h + (-p) = h + (5 - 2^130) and select if h >= p.
    u32 g0 = st.h[0] + 5;
    c = g0 >> 26;
    g0 &= 0x03ffffffu;
    u32 g1 = st.h[1] + c;
    c = g1 >> 26;
    g1 &= 0x03ffffffu;
    u32 g2 = st.h[2] + c;
    c = g2 >> 26;
    g2 &= 0x03ffffffu;
    u32 g3 = st.h[3] + c;
    c = g3 >> 26;
    g3 &= 0x03ffffffu;
    const u32 g4 = st.h[4] + c - (1u << 26);

    // mask = 0xffffffff iff h >= p (g4 high bit clear), else 0.
    const u32 mask = ~((g4 >> 31) - 1u);
    const u32 nmask = ~mask;
    st.h[0] = (st.h[0] & nmask) | (g0 & mask);
    st.h[1] = (st.h[1] & nmask) | (g1 & mask);
    st.h[2] = (st.h[2] & nmask) | (g2 & mask);
    st.h[3] = (st.h[3] & nmask) | (g3 & mask);
    st.h[4] = (st.h[4] & nmask) | (g4 & mask);

    // Reassemble h to 4 × 32-bit little-endian.
    const u32 h0 = st.h[0] | (st.h[1] << 26);
    const u32 h1 = (st.h[1] >> 6) | (st.h[2] << 20);
    const u32 h2 = (st.h[2] >> 12) | (st.h[3] << 14);
    const u32 h3 = (st.h[3] >> 18) | (st.h[4] << 8);

    // tag = (h + s) mod 2^128.
    u64 sum0 = u64(h0) + u64(st.s[0]);
    u64 sum1 = u64(h1) + u64(st.s[1]) + (sum0 >> 32);
    u64 sum2 = u64(h2) + u64(st.s[2]) + (sum1 >> 32);
    u64 sum3 = u64(h3) + u64(st.s[3]) + (sum2 >> 32);
    StoreU32Le(tag + 0, u32(sum0));
    StoreU32Le(tag + 4, u32(sum1));
    StoreU32Le(tag + 8, u32(sum2));
    StoreU32Le(tag + 12, u32(sum3));
}

} // namespace

void Poly1305Mac(const u8 key[kPoly1305KeyBytes], const u8* msg, u32 msg_len, u8 tag[kPoly1305TagBytes])
{
    Poly1305State st;
    Poly1305Init(st, key);
    Poly1305Update(st, msg, msg_len);
    Poly1305Final(st, tag);
}

namespace
{

// AEAD MAC layout per RFC 8439 §2.8: AAD || pad16(AAD) ||
// ciphertext || pad16(ciphertext) || u64le(aad_len) || u64le(ct_len).
void AeadMacFeed(Poly1305State& st, const u8* data, u32 len)
{
    Poly1305Update(st, data, len);
    const u32 pad = (16 - (len & 15)) & 15;
    if (pad > 0)
    {
        u8 zeros[16] = {};
        Poly1305Update(st, zeros, pad);
    }
}

void DeriveOneTimeKey(const u8 key[kChaCha20KeyBytes], const u8 nonce[kChaCha20NonceBytes], u8 out[kPoly1305KeyBytes])
{
    // RFC 8439 §2.6 — Poly1305 key is the first 32 bytes of the
    // ChaCha20(key, nonce, counter=0) keystream.
    u8 block[kChaCha20BlockBytes];
    u8 zeroes[kChaCha20BlockBytes] = {};
    ChaCha20Xor(key, nonce, 0, zeroes, block, kChaCha20BlockBytes);
    for (u32 i = 0; i < kPoly1305KeyBytes; ++i)
        out[i] = block[i];
}

} // namespace

void ChaCha20Poly1305Encrypt(const u8 key[kChaCha20KeyBytes], const u8 nonce[kChaCha20NonceBytes], const u8* aad,
                             u32 aad_len, const u8* plaintext, u32 plaintext_len, u8* ciphertext,
                             u8 tag[kChaCha20Poly1305TagBytes])
{
    u8 mac_key[kPoly1305KeyBytes];
    DeriveOneTimeKey(key, nonce, mac_key);
    ChaCha20Xor(key, nonce, /*counter=*/1, plaintext, ciphertext, plaintext_len);

    Poly1305State st;
    Poly1305Init(st, mac_key);
    AeadMacFeed(st, aad, aad_len);
    AeadMacFeed(st, ciphertext, plaintext_len);
    u8 lengths[16];
    for (u32 i = 0; i < 8; ++i)
        lengths[i] = u8((u64(aad_len) >> (8 * i)) & 0xFFu);
    for (u32 i = 0; i < 8; ++i)
        lengths[8 + i] = u8((u64(plaintext_len) >> (8 * i)) & 0xFFu);
    Poly1305Update(st, lengths, 16);
    Poly1305Final(st, tag);
}

bool ChaCha20Poly1305Decrypt(const u8 key[kChaCha20KeyBytes], const u8 nonce[kChaCha20NonceBytes], const u8* aad,
                             u32 aad_len, const u8* ciphertext, u32 ciphertext_len,
                             const u8 tag[kChaCha20Poly1305TagBytes], u8* plaintext)
{
    u8 mac_key[kPoly1305KeyBytes];
    DeriveOneTimeKey(key, nonce, mac_key);

    Poly1305State st;
    Poly1305Init(st, mac_key);
    AeadMacFeed(st, aad, aad_len);
    AeadMacFeed(st, ciphertext, ciphertext_len);
    u8 lengths[16];
    for (u32 i = 0; i < 8; ++i)
        lengths[i] = u8((u64(aad_len) >> (8 * i)) & 0xFFu);
    for (u32 i = 0; i < 8; ++i)
        lengths[8 + i] = u8((u64(ciphertext_len) >> (8 * i)) & 0xFFu);
    Poly1305Update(st, lengths, 16);
    u8 expected[kChaCha20Poly1305TagBytes];
    Poly1305Final(st, expected);

    // Constant-time tag compare.
    u8 diff = 0;
    for (u32 i = 0; i < kChaCha20Poly1305TagBytes; ++i)
        diff |= u8(expected[i] ^ tag[i]);
    if (diff != 0)
        return false;

    ChaCha20Xor(key, nonce, /*counter=*/1, ciphertext, plaintext, ciphertext_len);
    return true;
}

void ChaCha20Poly1305SelfTest()
{
    // ----- RFC 8439 §2.4.2: ChaCha20 single-block keystream.
    {
        u8 key[32];
        for (u32 i = 0; i < 32; ++i)
            key[i] = u8(i);
        const u8 nonce[12] = {0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00};
        u8 zeros[64] = {};
        u8 ks[64];
        ChaCha20Xor(key, nonce, /*counter=*/1, zeros, ks, 64);
        const u8 want[64] = {0x10, 0xf1, 0xe7, 0xe4, 0xd1, 0x3b, 0x59, 0x15, 0x50, 0x0f, 0xdd, 0x1f, 0xa3,
                             0x20, 0x71, 0xc4, 0xc7, 0xd1, 0xf4, 0xc7, 0x33, 0xc0, 0x68, 0x03, 0x04, 0x22,
                             0xaa, 0x9a, 0xc3, 0xd4, 0x6c, 0x4e, 0xd2, 0x82, 0x64, 0x46, 0x07, 0x9f, 0xaa,
                             0x09, 0x14, 0xc2, 0xd7, 0x05, 0xd9, 0x8b, 0x02, 0xa2, 0xb5, 0x12, 0x9c, 0xd1,
                             0xde, 0x16, 0x4e, 0xb9, 0xcb, 0xd0, 0x83, 0xe8, 0xa2, 0x50, 0x3c, 0x4e};
        for (u32 i = 0; i < 64; ++i)
            KASSERT(ks[i] == want[i], "crypto/chacha20", "RFC 8439 §2.4.2 keystream mismatch");
    }

    // ----- RFC 8439 §2.5.2: Poly1305 over "Cryptographic Forum Research Group".
    {
        const u8 key[32] = {0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33, 0x7f, 0x44, 0x52,
                            0xfe, 0x42, 0xd5, 0x06, 0xa8, 0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d,
                            0xb2, 0xfd, 0x4a, 0xbf, 0xf6, 0xaf, 0x41, 0x49, 0xf5, 0x1b};
        const char* msg_text = "Cryptographic Forum Research Group";
        u32 msg_len = 0;
        while (msg_text[msg_len] != '\0')
            ++msg_len;
        u8 tag[16];
        Poly1305Mac(key, reinterpret_cast<const u8*>(msg_text), msg_len, tag);
        const u8 want[16] = {0xa8, 0x06, 0x1d, 0xc1, 0x30, 0x51, 0x36, 0xc6,
                             0xc2, 0x2b, 0x8b, 0xaf, 0x0c, 0x01, 0x27, 0xa9};
        for (u32 i = 0; i < 16; ++i)
            KASSERT(tag[i] == want[i], "crypto/poly1305", "RFC 8439 §2.5.2 tag mismatch");
    }

    // ----- RFC 8439 §2.8.2: ChaCha20-Poly1305 AEAD encrypt round-trip.
    {
        u8 key[32];
        for (u32 i = 0; i < 32; ++i)
            key[i] = u8(0x80 + i);
        const u8 nonce[12] = {0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47};
        const u8 aad[12] = {0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7};
        const char* pt = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, "
                         "sunscreen would be it.";
        u32 pt_len = 0;
        while (pt[pt_len] != '\0')
            ++pt_len;
        KASSERT(pt_len == 114, "crypto/aead", "fixture length wrong");

        u8 ct[114];
        u8 tag[16];
        ChaCha20Poly1305Encrypt(key, nonce, aad, 12, reinterpret_cast<const u8*>(pt), pt_len, ct, tag);

        const u8 want_tag[16] = {0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a,
                                 0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60, 0x06, 0x91};
        for (u32 i = 0; i < 16; ++i)
            KASSERT(tag[i] == want_tag[i], "crypto/aead", "RFC 8439 §2.8.2 tag mismatch");

        // First 16 bytes of expected ciphertext from RFC 8439 §2.8.2.
        const u8 want_ct_prefix[16] = {0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb,
                                       0x7b, 0x86, 0xaf, 0xbc, 0x53, 0xef, 0x7e, 0xc2};
        for (u32 i = 0; i < 16; ++i)
            KASSERT(ct[i] == want_ct_prefix[i], "crypto/aead", "RFC 8439 §2.8.2 ciphertext mismatch");

        // Decrypt round-trip.
        u8 round[114];
        const bool ok = ChaCha20Poly1305Decrypt(key, nonce, aad, 12, ct, pt_len, tag, round);
        KASSERT(ok, "crypto/aead", "decrypt failed");
        for (u32 i = 0; i < pt_len; ++i)
            KASSERT(round[i] == u8(pt[i]), "crypto/aead", "decrypt round-trip mismatch");

        // Tamper detection: flipping any tag byte must reject.
        u8 bad_tag[16];
        for (u32 i = 0; i < 16; ++i)
            bad_tag[i] = tag[i];
        bad_tag[5] ^= 0x80;
        const bool tampered = ChaCha20Poly1305Decrypt(key, nonce, aad, 12, ct, pt_len, bad_tag, round);
        KASSERT(!tampered, "crypto/aead", "tampered tag not rejected");

        // Tamper detection: flipping a ciphertext byte must reject.
        u8 bad_ct[114];
        for (u32 i = 0; i < 114; ++i)
            bad_ct[i] = ct[i];
        bad_ct[20] ^= 0x01;
        const bool tampered2 = ChaCha20Poly1305Decrypt(key, nonce, aad, 12, bad_ct, pt_len, tag, round);
        KASSERT(!tampered2, "crypto/aead", "tampered ciphertext not rejected");
    }
}

} // namespace duetos::crypto
