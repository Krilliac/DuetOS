/*
 * DuetOS — ChaCha20-Poly1305 (RFC 8439) reference-style implementation.
 *
 * See chacha20_poly1305.h for the public contract. The code follows
 * RFC 8439 line-by-line; comments quote section numbers so a
 * reviewer can cross-check.
 */

#include "security/chacha20_poly1305.h"

#include "arch/x86_64/serial.h"
#include "core/panic.h"
#include "util/types.h"

namespace duetos::security
{

namespace
{

inline u32 LoadLE32(const u8* p)
{
    return static_cast<u32>(p[0]) | (static_cast<u32>(p[1]) << 8) | (static_cast<u32>(p[2]) << 16) |
           (static_cast<u32>(p[3]) << 24);
}

inline void StoreLE32(u8* p, u32 v)
{
    p[0] = static_cast<u8>(v);
    p[1] = static_cast<u8>(v >> 8);
    p[2] = static_cast<u8>(v >> 16);
    p[3] = static_cast<u8>(v >> 24);
}

inline void StoreLE64(u8* p, u64 v)
{
    for (u32 i = 0; i < 8; ++i)
        p[i] = static_cast<u8>(v >> (8u * i));
}

inline u32 RotL32(u32 x, u32 n)
{
    return (x << n) | (x >> (32u - n));
}

// RFC 8439 §2.1 — quarter round.
inline void QR(u32& a, u32& b, u32& c, u32& d)
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

// RFC 8439 §2.3 — ChaCha20 block function.
//   state = "expa" || "nd 3" || "2-by" || "te k"  (LE32 constants)
//        || key (8 LE32 words)
//        || counter (1 LE32)
//        || nonce (3 LE32)
// 20 rounds = 10 (column-round + diagonal-round) iterations.
void ChaChaBlock(const u8 key[kChaCha20KeyBytes], u32 counter, const u8 nonce[kChaCha20NonceBytes], u8 out[64])
{
    u32 state[16];
    state[0] = 0x61707865;
    state[1] = 0x3320646e;
    state[2] = 0x79622d32;
    state[3] = 0x6b206574;
    for (u32 i = 0; i < 8; ++i)
        state[4 + i] = LoadLE32(key + i * 4);
    state[12] = counter;
    state[13] = LoadLE32(nonce + 0);
    state[14] = LoadLE32(nonce + 4);
    state[15] = LoadLE32(nonce + 8);

    u32 working[16];
    for (u32 i = 0; i < 16; ++i)
        working[i] = state[i];

    for (u32 r = 0; r < 10; ++r)
    {
        // Column rounds.
        QR(working[0], working[4], working[8], working[12]);
        QR(working[1], working[5], working[9], working[13]);
        QR(working[2], working[6], working[10], working[14]);
        QR(working[3], working[7], working[11], working[15]);
        // Diagonal rounds.
        QR(working[0], working[5], working[10], working[15]);
        QR(working[1], working[6], working[11], working[12]);
        QR(working[2], working[7], working[8], working[13]);
        QR(working[3], working[4], working[9], working[14]);
    }

    for (u32 i = 0; i < 16; ++i)
        working[i] += state[i];

    for (u32 i = 0; i < 16; ++i)
        StoreLE32(out + i * 4, working[i]);
}

// XOR-keystream encryption (RFC 8439 §2.4). Starts at the
// supplied initial block counter (the AEAD uses counter=1 for the
// payload after the Poly1305 key derivation at counter=0).
void ChaCha20Xor(const u8 key[kChaCha20KeyBytes], u32 initial_counter, const u8 nonce[kChaCha20NonceBytes],
                 const u8* in, u32 len, u8* out)
{
    u8 ks[64];
    u32 counter = initial_counter;
    u32 done = 0;
    while (done < len)
    {
        ChaChaBlock(key, counter, nonce, ks);
        const u32 chunk = (len - done) > 64u ? 64u : (len - done);
        for (u32 i = 0; i < chunk; ++i)
            out[done + i] = in[done + i] ^ ks[i];
        done += chunk;
        ++counter;
    }
}

// -----------------------------------------------------------------
// Poly1305 — RFC 8439 §2.5. A degree-N polynomial MAC evaluated
// modulo (2^130 - 5), with the key split as (r, s). r is clamped
// per §2.5.1.
//
// Internal arithmetic uses a 5-limb representation in base 2^26
// (130 bits = 5 * 26), which lets each multiplication stay within
// 64-bit unsigned without spilling. The implementation below is
// the textbook RFC version, optimised for correctness and
// reviewability rather than throughput.
// -----------------------------------------------------------------

struct Poly1305Ctx
{
    u32 r[5];    // clamped key (low 130 bits)
    u32 s_le[4]; // upper 16 bytes of poly key (final add)
    u32 acc[5];  // accumulator
    u8 buf[16];  // partial-block buffer
    u32 buf_len; // bytes in buf
    bool finalised;
};

inline void Clamp(u32 r[5], const u8 key16[16])
{
    // Per §2.5.1: clamp r before use.
    // r &= 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF (little-endian),
    // i.e. zero the top 4 bits of bytes 3/7/11/15 and the bottom 2
    // bits of bytes 4/8/12.
    u8 k[16];
    for (u32 i = 0; i < 16; ++i)
        k[i] = key16[i];
    k[3] &= 0x0F;
    k[7] &= 0x0F;
    k[11] &= 0x0F;
    k[15] &= 0x0F;
    k[4] &= 0xFC;
    k[8] &= 0xFC;
    k[12] &= 0xFC;
    // Pack into 5 26-bit limbs little-endian.
    const u32 t0 = LoadLE32(k + 0);
    const u32 t1 = LoadLE32(k + 4);
    const u32 t2 = LoadLE32(k + 8);
    const u32 t3 = LoadLE32(k + 12);
    r[0] = t0 & 0x3FFFFFFu;
    r[1] = ((t0 >> 26) | (t1 << 6)) & 0x3FFFFFFu;
    r[2] = ((t1 >> 20) | (t2 << 12)) & 0x3FFFFFFu;
    r[3] = ((t2 >> 14) | (t3 << 18)) & 0x3FFFFFFu;
    r[4] = (t3 >> 8) & 0x3FFFFFFu;
}

void Poly1305Init(Poly1305Ctx& c, const u8 key[32])
{
    Clamp(c.r, key);
    c.s_le[0] = LoadLE32(key + 16);
    c.s_le[1] = LoadLE32(key + 20);
    c.s_le[2] = LoadLE32(key + 24);
    c.s_le[3] = LoadLE32(key + 28);
    for (u32 i = 0; i < 5; ++i)
        c.acc[i] = 0;
    c.buf_len = 0;
    c.finalised = false;
}

void Poly1305AbsorbBlock(Poly1305Ctx& c, const u8 block[16], u32 block_len, bool is_full)
{
    // Compose 5-limb representation of (block || 0x01 for full, or
    // block padded to len then 0x01 byte appended at position
    // block_len). RFC §2.5.2: append a 1 byte (the "tag bit") to
    // each block. For a full 16-byte block this is bit 128.
    u8 b[17] = {0};
    for (u32 i = 0; i < block_len; ++i)
        b[i] = block[i];
    if (is_full)
        b[16] = 1;
    else
        b[block_len] = 1;
    const u32 t0 = LoadLE32(b + 0);
    const u32 t1 = LoadLE32(b + 4);
    const u32 t2 = LoadLE32(b + 8);
    const u32 t3 = LoadLE32(b + 12);
    const u32 t4 = b[16];
    u32 h0 = c.acc[0] + (t0 & 0x3FFFFFFu);
    u32 h1 = c.acc[1] + (((t0 >> 26) | (t1 << 6)) & 0x3FFFFFFu);
    u32 h2 = c.acc[2] + (((t1 >> 20) | (t2 << 12)) & 0x3FFFFFFu);
    u32 h3 = c.acc[3] + (((t2 >> 14) | (t3 << 18)) & 0x3FFFFFFu);
    u32 h4 = c.acc[4] + ((t3 >> 8) | (t4 << 24));

    // h = h * r mod (2^130 - 5).
    const u32 r0 = c.r[0];
    const u32 r1 = c.r[1];
    const u32 r2 = c.r[2];
    const u32 r3 = c.r[3];
    const u32 r4 = c.r[4];
    const u32 s1 = r1 * 5u;
    const u32 s2 = r2 * 5u;
    const u32 s3 = r3 * 5u;
    const u32 s4 = r4 * 5u;

    u64 d0 = static_cast<u64>(h0) * r0 + static_cast<u64>(h1) * s4 + static_cast<u64>(h2) * s3 +
             static_cast<u64>(h3) * s2 + static_cast<u64>(h4) * s1;
    u64 d1 = static_cast<u64>(h0) * r1 + static_cast<u64>(h1) * r0 + static_cast<u64>(h2) * s4 +
             static_cast<u64>(h3) * s3 + static_cast<u64>(h4) * s2;
    u64 d2 = static_cast<u64>(h0) * r2 + static_cast<u64>(h1) * r1 + static_cast<u64>(h2) * r0 +
             static_cast<u64>(h3) * s4 + static_cast<u64>(h4) * s3;
    u64 d3 = static_cast<u64>(h0) * r3 + static_cast<u64>(h1) * r2 + static_cast<u64>(h2) * r1 +
             static_cast<u64>(h3) * r0 + static_cast<u64>(h4) * s4;
    u64 d4 = static_cast<u64>(h0) * r4 + static_cast<u64>(h1) * r3 + static_cast<u64>(h2) * r2 +
             static_cast<u64>(h3) * r1 + static_cast<u64>(h4) * r0;

    // Reduce carries.
    u32 carry = static_cast<u32>(d0 >> 26);
    h0 = static_cast<u32>(d0) & 0x3FFFFFFu;
    d1 += carry;
    carry = static_cast<u32>(d1 >> 26);
    h1 = static_cast<u32>(d1) & 0x3FFFFFFu;
    d2 += carry;
    carry = static_cast<u32>(d2 >> 26);
    h2 = static_cast<u32>(d2) & 0x3FFFFFFu;
    d3 += carry;
    carry = static_cast<u32>(d3 >> 26);
    h3 = static_cast<u32>(d3) & 0x3FFFFFFu;
    d4 += carry;
    carry = static_cast<u32>(d4 >> 26);
    h4 = static_cast<u32>(d4) & 0x3FFFFFFu;
    h0 += carry * 5u;
    carry = h0 >> 26;
    h0 &= 0x3FFFFFFu;
    h1 += carry;

    c.acc[0] = h0;
    c.acc[1] = h1;
    c.acc[2] = h2;
    c.acc[3] = h3;
    c.acc[4] = h4;
}

void Poly1305Update(Poly1305Ctx& c, const u8* in, u32 len)
{
    if (c.buf_len > 0)
    {
        const u32 need = 16u - c.buf_len;
        const u32 take = (len < need) ? len : need;
        for (u32 i = 0; i < take; ++i)
            c.buf[c.buf_len + i] = in[i];
        c.buf_len += take;
        in += take;
        len -= take;
        if (c.buf_len == 16)
        {
            Poly1305AbsorbBlock(c, c.buf, 16, true);
            c.buf_len = 0;
        }
    }
    while (len >= 16)
    {
        Poly1305AbsorbBlock(c, in, 16, true);
        in += 16;
        len -= 16;
    }
    if (len > 0)
    {
        for (u32 i = 0; i < len; ++i)
            c.buf[i] = in[i];
        c.buf_len = len;
    }
}

void Poly1305Finish(Poly1305Ctx& c, u8 tag[kPoly1305TagBytes])
{
    if (c.buf_len > 0)
    {
        Poly1305AbsorbBlock(c, c.buf, c.buf_len, false);
        c.buf_len = 0;
    }

    // Fully reduce h modulo p = 2^130 - 5.
    u32 h0 = c.acc[0];
    u32 h1 = c.acc[1];
    u32 h2 = c.acc[2];
    u32 h3 = c.acc[3];
    u32 h4 = c.acc[4];
    u32 carry = h1 >> 26;
    h1 &= 0x3FFFFFFu;
    h2 += carry;
    carry = h2 >> 26;
    h2 &= 0x3FFFFFFu;
    h3 += carry;
    carry = h3 >> 26;
    h3 &= 0x3FFFFFFu;
    h4 += carry;
    carry = h4 >> 26;
    h4 &= 0x3FFFFFFu;
    h0 += carry * 5u;
    carry = h0 >> 26;
    h0 &= 0x3FFFFFFu;
    h1 += carry;

    // Compute h + (-p) and condition-select.
    u32 g0 = h0 + 5u;
    u32 g_c = g0 >> 26;
    g0 &= 0x3FFFFFFu;
    u32 g1 = h1 + g_c;
    g_c = g1 >> 26;
    g1 &= 0x3FFFFFFu;
    u32 g2 = h2 + g_c;
    g_c = g2 >> 26;
    g2 &= 0x3FFFFFFu;
    u32 g3 = h3 + g_c;
    g_c = g3 >> 26;
    g3 &= 0x3FFFFFFu;
    u32 g4 = h4 + g_c - (1u << 26);

    // mask = (g4 >> 31) ? 0 : 0xffffffff (i.e. select g if g4
    // didn't underflow).
    const u32 mask_g = (g4 >> 31) - 1u;
    const u32 mask_h = ~mask_g;
    h0 = (h0 & mask_h) | (g0 & mask_g);
    h1 = (h1 & mask_h) | (g1 & mask_g);
    h2 = (h2 & mask_h) | (g2 & mask_g);
    h3 = (h3 & mask_h) | (g3 & mask_g);
    h4 = (h4 & mask_h) | (g4 & mask_g);

    // Repack to 4 u32s LE.
    u32 t0 = h0 | (h1 << 26);
    u32 t1 = (h1 >> 6) | (h2 << 20);
    u32 t2 = (h2 >> 12) | (h3 << 14);
    u32 t3 = (h3 >> 18) | (h4 << 8);

    // Add the second half of the key (s).
    u64 sum = static_cast<u64>(t0) + c.s_le[0];
    t0 = static_cast<u32>(sum);
    sum = static_cast<u64>(t1) + c.s_le[1] + (sum >> 32);
    t1 = static_cast<u32>(sum);
    sum = static_cast<u64>(t2) + c.s_le[2] + (sum >> 32);
    t2 = static_cast<u32>(sum);
    sum = static_cast<u64>(t3) + c.s_le[3] + (sum >> 32);
    t3 = static_cast<u32>(sum);

    StoreLE32(tag + 0, t0);
    StoreLE32(tag + 4, t1);
    StoreLE32(tag + 8, t2);
    StoreLE32(tag + 12, t3);
    c.finalised = true;
}

// Derive the Poly1305 one-time key from the ChaCha20 keystream at
// counter=0 (RFC 8439 §2.6). The first 32 bytes of the block
// become the (r, s) MAC key for this (key, nonce) pair.
void DerivePolyKey(const u8 key[kChaCha20KeyBytes], const u8 nonce[kChaCha20NonceBytes], u8 poly_key[32])
{
    u8 block[64];
    ChaChaBlock(key, 0, nonce, block);
    for (u32 i = 0; i < 32; ++i)
        poly_key[i] = block[i];
}

// MAC over: pad16(ad) || pad16(ct) || LE64(ad_len) || LE64(ct_len).
void Poly1305AeadMac(const u8 poly_key[32], const u8* ad, u32 ad_len, const u8* ct, u32 ct_len,
                     u8 tag[kPoly1305TagBytes])
{
    Poly1305Ctx p;
    Poly1305Init(p, poly_key);
    if (ad_len > 0)
        Poly1305Update(p, ad, ad_len);
    if (ad_len % 16u != 0u)
    {
        u8 pad[16] = {0};
        Poly1305Update(p, pad, 16u - (ad_len % 16u));
    }
    if (ct_len > 0)
        Poly1305Update(p, ct, ct_len);
    if (ct_len % 16u != 0u)
    {
        u8 pad[16] = {0};
        Poly1305Update(p, pad, 16u - (ct_len % 16u));
    }
    u8 lengths[16];
    StoreLE64(lengths + 0, static_cast<u64>(ad_len));
    StoreLE64(lengths + 8, static_cast<u64>(ct_len));
    Poly1305Update(p, lengths, 16);
    Poly1305Finish(p, tag);
}

inline bool ConstantTimeEq(const u8* a, const u8* b, u32 n)
{
    u32 diff = 0;
    for (u32 i = 0; i < n; ++i)
        diff |= static_cast<u32>(a[i] ^ b[i]);
    return diff == 0;
}

} // namespace

void ChaCha20Poly1305Encrypt(const u8 key[kChaCha20KeyBytes], const u8 nonce[kChaCha20NonceBytes], const u8* ad,
                             u32 ad_len, const u8* pt, u32 pt_len, u8* ct, u8 tag[kPoly1305TagBytes])
{
    u8 poly_key[32];
    DerivePolyKey(key, nonce, poly_key);
    // Encrypt at counter=1 (counter=0 produces the Poly1305 key).
    if (pt_len > 0)
        ChaCha20Xor(key, 1, nonce, pt, pt_len, ct);
    Poly1305AeadMac(poly_key, ad, ad_len, ct, pt_len, tag);
}

bool ChaCha20Poly1305Decrypt(const u8 key[kChaCha20KeyBytes], const u8 nonce[kChaCha20NonceBytes], const u8* ad,
                             u32 ad_len, const u8* ct, u32 ct_len, const u8 tag[kPoly1305TagBytes], u8* pt)
{
    u8 poly_key[32];
    DerivePolyKey(key, nonce, poly_key);
    u8 computed_tag[kPoly1305TagBytes];
    Poly1305AeadMac(poly_key, ad, ad_len, ct, ct_len, computed_tag);
    if (!ConstantTimeEq(computed_tag, tag, kPoly1305TagBytes))
        return false;
    if (ct_len > 0)
        ChaCha20Xor(key, 1, nonce, ct, ct_len, pt);
    return true;
}

namespace
{

bool BytesEq(const u8* a, const u8* b, u32 n)
{
    for (u32 i = 0; i < n; ++i)
        if (a[i] != b[i])
            return false;
    return true;
}

} // namespace

void ChaCha20Poly1305SelfTest()
{
    arch::SerialWrite("[chacha20poly1305] self-test: RFC 8439 vectors\n");

    // RFC 8439 §2.8.2 — AEAD test vector.
    static const u8 kKey[32] = {0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a,
                                0x8b, 0x8c, 0x8d, 0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95,
                                0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f};
    static const u8 kNonce[12] = {0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47};
    static const u8 kAd[12] = {0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7};
    static const char kPlaintext[] = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for "
                                     "the future, sunscreen would be it.";
    const u32 pt_len = static_cast<u32>(sizeof(kPlaintext) - 1);

    static const u8 kExpectedCt[114] = {
        0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb, 0x7b, 0x86, 0xaf, 0xbc, 0x53, 0xef, 0x7e, 0xc2, 0xa4,
        0xad, 0xed, 0x51, 0x29, 0x6e, 0x08, 0xfe, 0xa9, 0xe2, 0xb5, 0xa7, 0x36, 0xee, 0x62, 0xd6, 0x3d, 0xbe,
        0xa4, 0x5e, 0x8c, 0xa9, 0x67, 0x12, 0x82, 0xfa, 0xfb, 0x69, 0xda, 0x92, 0x72, 0x8b, 0x1a, 0x71, 0xde,
        0x0a, 0x9e, 0x06, 0x0b, 0x29, 0x05, 0xd6, 0xa5, 0xb6, 0x7e, 0xcd, 0x3b, 0x36, 0x92, 0xdd, 0xbd, 0x7f,
        0x2d, 0x77, 0x8b, 0x8c, 0x98, 0x03, 0xae, 0xe3, 0x28, 0x09, 0x1b, 0x58, 0xfa, 0xb3, 0x24, 0xe4, 0xfa,
        0xd6, 0x75, 0x94, 0x55, 0x85, 0x80, 0x8b, 0x48, 0x31, 0xd7, 0xbc, 0x3f, 0xf4, 0xde, 0xf0, 0x8e, 0x4b,
        0x7a, 0x9d, 0xe5, 0x76, 0xd2, 0x65, 0x86, 0xce, 0xc6, 0x4b, 0x61, 0x16};
    static const u8 kExpectedTag[16] = {0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a,
                                        0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60, 0x06, 0x91};

    u8 ct[114];
    u8 tag[16];
    ChaCha20Poly1305Encrypt(kKey, kNonce, kAd, 12, reinterpret_cast<const u8*>(kPlaintext), pt_len, ct, tag);
    if (!BytesEq(ct, kExpectedCt, pt_len))
        duetos::core::Panic("chacha20poly1305", "self-test: ciphertext mismatch");
    if (!BytesEq(tag, kExpectedTag, 16))
        duetos::core::Panic("chacha20poly1305", "self-test: tag mismatch");

    // Round-trip decrypt: must succeed and reproduce plaintext.
    u8 pt2[114];
    if (!ChaCha20Poly1305Decrypt(kKey, kNonce, kAd, 12, ct, pt_len, tag, pt2))
        duetos::core::Panic("chacha20poly1305", "self-test: decrypt rejected its own output");
    if (!BytesEq(pt2, reinterpret_cast<const u8*>(kPlaintext), pt_len))
        duetos::core::Panic("chacha20poly1305", "self-test: decrypted plaintext mismatch");

    // Tampered tag — single bit flip — must reject.
    u8 bad_tag[16];
    for (u32 i = 0; i < 16; ++i)
        bad_tag[i] = tag[i];
    bad_tag[0] ^= 0x01;
    if (ChaCha20Poly1305Decrypt(kKey, kNonce, kAd, 12, ct, pt_len, bad_tag, pt2))
        duetos::core::Panic("chacha20poly1305", "self-test: tampered tag accepted");

    // Tampered ciphertext — single bit flip — must reject.
    u8 bad_ct[114];
    for (u32 i = 0; i < pt_len; ++i)
        bad_ct[i] = ct[i];
    bad_ct[0] ^= 0x01;
    if (ChaCha20Poly1305Decrypt(kKey, kNonce, kAd, 12, bad_ct, pt_len, tag, pt2))
        duetos::core::Panic("chacha20poly1305", "self-test: tampered ciphertext accepted");

    // Tampered AD — single bit flip — must reject.
    u8 bad_ad[12];
    for (u32 i = 0; i < 12; ++i)
        bad_ad[i] = kAd[i];
    bad_ad[0] ^= 0x01;
    if (ChaCha20Poly1305Decrypt(kKey, kNonce, bad_ad, 12, ct, pt_len, tag, pt2))
        duetos::core::Panic("chacha20poly1305", "self-test: tampered AD accepted");

    arch::SerialWrite("[chacha20poly1305] self-test: PASS\n");
}

} // namespace duetos::security
