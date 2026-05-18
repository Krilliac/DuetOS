/*
 * DuetOS — Argon2id (RFC 9106) reference-style implementation.
 *
 * See argon2id.h for the public contract. The code below follows
 * the RFC §3 algorithm description line-by-line; comments quote
 * section numbers so a reviewer can cross-check.
 *
 * Notation lifted from the RFC: `H` is Blake2b, `H'` is the
 * variable-length-output construction in §3.3, `G` is the 1024-byte
 * block compression in §3.6, `P` is the Blake2b-derived permutation
 * over 16 u64s in §3.7.
 */

#include "security/argon2id.h"

#include "arch/x86_64/serial.h"
#include "core/panic.h"
#include "log/klog.h"
#include "mm/kheap.h"
#include "security/blake2b.h"
#include "util/types.h"

namespace duetos::security
{

namespace
{

// ---------------------------------------------------------------------
// Little-endian encoders. Argon2 uses LE32 + LE64 throughout.
// ---------------------------------------------------------------------

inline void StoreLE32(u8* p, u32 v)
{
    p[0] = static_cast<u8>(v);
    p[1] = static_cast<u8>(v >> 8);
    p[2] = static_cast<u8>(v >> 16);
    p[3] = static_cast<u8>(v >> 24);
}

inline u64 LoadLE64(const u8* p)
{
    u64 r = 0;
    for (u32 i = 0; i < 8; ++i)
        r |= static_cast<u64>(p[i]) << (8u * i);
    return r;
}

inline void StoreLE64(u8* p, u64 v)
{
    for (u32 i = 0; i < 8; ++i)
        p[i] = static_cast<u8>(v >> (8u * i));
}

// 1024-byte block = 128 u64s.
constexpr u32 kQWordsPerBlock = kArgon2idBlockBytes / 8;

struct Block
{
    u64 v[kQWordsPerBlock];
};

inline void BlockZero(Block& b)
{
    for (u32 i = 0; i < kQWordsPerBlock; ++i)
        b.v[i] = 0;
}

inline void BlockCopy(Block& dst, const Block& src)
{
    for (u32 i = 0; i < kQWordsPerBlock; ++i)
        dst.v[i] = src.v[i];
}

inline void BlockXor(Block& dst, const Block& a)
{
    for (u32 i = 0; i < kQWordsPerBlock; ++i)
        dst.v[i] ^= a.v[i];
}

inline void BytesToBlock(const u8* in, Block& b)
{
    for (u32 i = 0; i < kQWordsPerBlock; ++i)
        b.v[i] = LoadLE64(in + i * 8);
}

inline void BlockToBytes(const Block& b, u8* out)
{
    for (u32 i = 0; i < kQWordsPerBlock; ++i)
        StoreLE64(out + i * 8, b.v[i]);
}

// ---------------------------------------------------------------------
// H' — variable-length Blake2b (RFC 9106 §3.3).
// ---------------------------------------------------------------------
//
// For tag_len <= 64: H'(X) = Blake2b(LE32(tag_len) || X, tag_len).
// For tag_len  > 64: chain 32-byte partial digests, last chunk
// trimmed. See RFC for exact construction.
void VarHash(const u8* in, u32 in_len, u8* out, u32 out_len)
{
    u8 lenle[4];
    StoreLE32(lenle, out_len);

    if (out_len <= kArgon2idMaxTagBytes)
    {
        Blake2bState s;
        Blake2bInit(s, out_len);
        Blake2bUpdate(s, lenle, 4);
        Blake2bUpdate(s, in, in_len);
        Blake2bFinal(s, out);
        return;
    }

    // out_len > 64. Chain 64-byte digests, take first 32 bytes of
    // each, then a final partial digest of size (out_len - 32*r).
    //
    // Care: the final partial is Blake2b(V_n, tail) where V_n is the
    // LAST V_i whose 32-byte prefix was written — i.e. we must NOT
    // advance V past that final-prefix V before computing the partial.
    Blake2bState s;
    u8 v[kArgon2idMaxTagBytes];
    Blake2bInit(s, kArgon2idMaxTagBytes);
    Blake2bUpdate(s, lenle, 4);
    Blake2bUpdate(s, in, in_len);
    Blake2bFinal(s, v);

    // First chunk: write V_1[0..31].
    for (u32 i = 0; i < 32; ++i)
        out[i] = v[i];
    u32 written = 32;
    // Each loop iteration advances V to the next one, then writes
    // its 32-byte prefix. Loop continues while there will STILL be
    // more than 64 unwritten bytes after the next write — so on exit
    // `v` holds the last V whose prefix was emitted, ready to feed
    // the final partial.
    while (out_len - written > kArgon2idMaxTagBytes)
    {
        Blake2bHash(v, kArgon2idMaxTagBytes, v, kArgon2idMaxTagBytes);
        for (u32 i = 0; i < 32; ++i)
            out[written + i] = v[i];
        written += 32;
    }
    // Final partial — (out_len - written) bytes, in [1, 64].
    const u32 tail = out_len - written;
    u8 last[kArgon2idMaxTagBytes];
    Blake2bHash(v, kArgon2idMaxTagBytes, last, tail);
    for (u32 i = 0; i < tail; ++i)
        out[written + i] = last[i];
}

// ---------------------------------------------------------------------
// P — permutation function (RFC 9106 §3.7).
//
// Argon2's "round" is Blake2b's round with the addition step replaced
// by `a = a + b + 2 * trunc(a) * trunc(b)`, where trunc() is the low
// 32 bits. The eight calls per round match Blake2b's layout.
// ---------------------------------------------------------------------

inline u64 Trunc32(u64 x)
{
    return x & 0xFFFFFFFFull;
}

inline u64 RotR64(u64 x, u32 n)
{
    return (x >> n) | (x << (64u - n));
}

inline void GB(u64& a, u64& b, u64& c, u64& d)
{
    a = a + b + 2ull * Trunc32(a) * Trunc32(b);
    d = RotR64(d ^ a, 32);
    c = c + d + 2ull * Trunc32(c) * Trunc32(d);
    b = RotR64(b ^ c, 24);
    a = a + b + 2ull * Trunc32(a) * Trunc32(b);
    d = RotR64(d ^ a, 16);
    c = c + d + 2ull * Trunc32(c) * Trunc32(d);
    b = RotR64(b ^ c, 63);
}

inline void Round(u64 v[16])
{
    GB(v[0], v[4], v[8], v[12]);
    GB(v[1], v[5], v[9], v[13]);
    GB(v[2], v[6], v[10], v[14]);
    GB(v[3], v[7], v[11], v[15]);
    GB(v[0], v[5], v[10], v[15]);
    GB(v[1], v[6], v[11], v[12]);
    GB(v[2], v[7], v[8], v[13]);
    GB(v[3], v[4], v[9], v[14]);
}

// ---------------------------------------------------------------------
// Compression G (RFC 9106 §3.6).
//
// Input: 1024-byte blocks X, Y.  Output: 1024-byte block.
// R := X XOR Y;  Q := P(R) by rows;  Z := P(Q) by columns;
// out := Z XOR R.
//
// "Rows" / "columns" treat the 1024-byte block as 8x8 16-byte cells
// (i.e. 8 rows of 16 u64s = 128 bytes per row).
// ---------------------------------------------------------------------

void Compress(Block& dst, const Block& x, const Block& y)
{
    Block r;
    for (u32 i = 0; i < kQWordsPerBlock; ++i)
        r.v[i] = x.v[i] ^ y.v[i];

    Block q;
    BlockCopy(q, r);

    // Rows of 16 u64s each — 8 of them.
    for (u32 row = 0; row < 8; ++row)
    {
        u64* base = &q.v[row * 16];
        Round(base);
    }

    // Columns: gather 16 u64s as (col, col+8) pairs across rows.
    // Treat layout as 8 rows × 8 columns of pairs.
    for (u32 col = 0; col < 8; ++col)
    {
        u64 v[16];
        for (u32 row = 0; row < 8; ++row)
        {
            v[row * 2 + 0] = q.v[row * 16 + col * 2 + 0];
            v[row * 2 + 1] = q.v[row * 16 + col * 2 + 1];
        }
        Round(v);
        for (u32 row = 0; row < 8; ++row)
        {
            q.v[row * 16 + col * 2 + 0] = v[row * 2 + 0];
            q.v[row * 16 + col * 2 + 1] = v[row * 2 + 1];
        }
    }

    for (u32 i = 0; i < kQWordsPerBlock; ++i)
        dst.v[i] = q.v[i] ^ r.v[i];
}

// XOR-into-dst variant for pass>0 mixing: dst ^= G(x, y).
void CompressXor(Block& dst, const Block& x, const Block& y)
{
    Block tmp;
    Compress(tmp, x, y);
    BlockXor(dst, tmp);
}

// ---------------------------------------------------------------------
// H_0 — initial 64-byte digest (RFC 9106 §3.2).
//
// H_0 = Blake2b(
//   LE32(p) || LE32(tag_len) || LE32(mem_kib) || LE32(iterations)
//   || LE32(version) || LE32(type) || LE32(pwd_len) || pwd
//   || LE32(salt_len) || salt || LE32(secret_len) || secret
//   || LE32(ad_len) || ad,
//   64
// )
// ---------------------------------------------------------------------

void ComputeH0(const u8* password, u32 password_len, const u8* salt, u32 salt_len, const u8* secret, u32 secret_len,
               const u8* ad, u32 ad_len, const Argon2idParamsRuntime& params, u8 h0[kArgon2idMaxTagBytes])
{
    Blake2bState s;
    Blake2bInit(s, kArgon2idMaxTagBytes);

    u8 le[4];
    StoreLE32(le, params.parallelism);
    Blake2bUpdate(s, le, 4);
    StoreLE32(le, params.tag_len);
    Blake2bUpdate(s, le, 4);
    StoreLE32(le, params.memory_kib);
    Blake2bUpdate(s, le, 4);
    StoreLE32(le, params.time_cost);
    Blake2bUpdate(s, le, 4);
    StoreLE32(le, kArgon2idVersion);
    Blake2bUpdate(s, le, 4);
    StoreLE32(le, kArgon2idTypeId);
    Blake2bUpdate(s, le, 4);

    StoreLE32(le, password_len);
    Blake2bUpdate(s, le, 4);
    if (password_len > 0)
        Blake2bUpdate(s, password, password_len);

    StoreLE32(le, salt_len);
    Blake2bUpdate(s, le, 4);
    if (salt_len > 0)
        Blake2bUpdate(s, salt, salt_len);

    StoreLE32(le, secret_len);
    Blake2bUpdate(s, le, 4);
    if (secret_len > 0)
        Blake2bUpdate(s, secret, secret_len);

    StoreLE32(le, ad_len);
    Blake2bUpdate(s, le, 4);
    if (ad_len > 0)
        Blake2bUpdate(s, ad, ad_len);

    Blake2bFinal(s, h0);
}

// ---------------------------------------------------------------------
// Indexing — pseudo-random reference block selection.
//
// For Argon2id: data-independent (Argon2i) when pass==0 AND slice<2;
// data-dependent (Argon2d) otherwise. The "data-independent" path
// generates J1/J2 by running G on a counter block (RFC §3.4.1.1);
// the "data-dependent" path uses the first u64 of the previous block.
//
// Per-segment state. `addresses` holds 128 (J1, J2) pairs = one
// 1024-byte block of pseudo-random offsets. `input` is the seed
// block that feeds the generator; `input.v[6]` is the counter field
// the RFC refreshes before each address-block production.
// ---------------------------------------------------------------------

struct IdxState
{
    bool data_independent;
    Block addresses;
    Block input; // pre-populated input block for address generator
};

void NextAddresses(IdxState& s)
{
    // RFC §3.4.1.1: increment input.v[6], then:
    //   tmp = G(0, input)
    //   addresses = G(0, tmp)
    // The "0" operand is a constant all-zero block. Sharing one
    // read-only static (Compress takes it by const ref and never
    // writes it) keeps a 1 KiB Block off this frame, which sits
    // directly above two Compress frames in the deepest Argon2
    // call chain — margin for the 64 KiB kernel task stack.
    static const Block kZeroBlock = {};
    s.input.v[6] += 1;
    Block tmp;
    Compress(tmp, kZeroBlock, s.input);
    Compress(s.addresses, kZeroBlock, tmp);
}

void InitIdxState(IdxState& s, bool data_independent, u64 pass, u64 lane, u64 slice, u64 mem_blocks, u64 total_passes)
{
    s.data_independent = data_independent;
    BlockZero(s.input);
    s.input.v[0] = pass;
    s.input.v[1] = lane;
    s.input.v[2] = slice;
    s.input.v[3] = mem_blocks;
    s.input.v[4] = total_passes;
    s.input.v[5] = kArgon2idTypeId;
    s.input.v[6] = 0;
    BlockZero(s.addresses);
}

// Compute (ref_lane, ref_index) for the new block at
// (pass, lane, slice, j_in_segment). Returns by reference.
//
// RFC §3.4 reference-set construction:
//
//   pass == 0:
//     - if slice == 0:               ref_lane = cur_lane, |R| = j - 1
//     - if ref_lane == cur_lane:     |R| = slice*L + j - 1
//     - else:                        |R| = slice*L (- 1 if j == 0)
//
//   pass > 0:
//     - if ref_lane == cur_lane:     |R| = 3*L + j - 1
//     - else:                        |R| = 3*L     (- 1 if j == 0)
//
// J1 maps to a position within R via the RFC's "non-uniform" rule:
//   x = (J1*J1) >> 32
//   y = (|R| * x) >> 32
//   z = |R| - 1 - y
// Then the absolute index in the lane is `(start + z) mod lane_length`
// where `start` is 0 for pass 0 and `(slice+1 mod 4)*segment_length`
// for pass > 0 (i.e. the oldest still-live block).
void ComputeReference(u32 j1, u32 j2, u32 pass, u32 cur_lane, u32 slice, u32 j_in_segment, u32 segment_length,
                      u32 lane_length, u32 parallelism, u32& ref_lane_out, u32& ref_index_out)
{
    if (pass == 0 && slice == 0)
        ref_lane_out = cur_lane;
    else
        ref_lane_out = static_cast<u32>(j2 % parallelism);

    u32 ref_area_size = 0;
    if (pass == 0)
    {
        if (slice == 0)
        {
            ref_area_size = j_in_segment - 1u;
        }
        else if (ref_lane_out == cur_lane)
        {
            ref_area_size = slice * segment_length + j_in_segment - 1u;
        }
        else
        {
            ref_area_size = slice * segment_length;
            if (j_in_segment == 0 && ref_area_size > 0)
                ref_area_size -= 1u;
        }
    }
    else
    {
        if (ref_lane_out == cur_lane)
        {
            ref_area_size = 3u * segment_length + j_in_segment - 1u;
        }
        else
        {
            ref_area_size = 3u * segment_length;
            if (j_in_segment == 0)
                ref_area_size -= 1u;
        }
    }

    const u64 j1_sq = static_cast<u64>(j1) * static_cast<u64>(j1);
    const u64 x = j1_sq >> 32;
    const u64 y = (static_cast<u64>(ref_area_size) * x) >> 32;
    const u64 z = static_cast<u64>(ref_area_size) - 1u - y;

    u32 start = 0;
    if (pass != 0)
        start = ((slice + 1u) % 4u) * segment_length;

    ref_index_out = static_cast<u32>((static_cast<u64>(start) + z) % static_cast<u64>(lane_length));
}

} // namespace

bool Argon2idDerive(const u8* password, u32 password_len, const u8* salt, u32 salt_len, const u8* secret,
                    u32 secret_len, const u8* ad, u32 ad_len, const Argon2idParamsRuntime& params, u8* out)
{
    // -------------- Parameter validation (RFC §3.1) --------------
    if (out == nullptr)
        return false;
    if (params.parallelism == 0)
        return false;
    if (params.time_cost == 0)
        return false;
    if (params.tag_len < 4 || params.tag_len > kArgon2idMaxTagBytes)
        return false;
    if (salt_len < 8) // RFC floor; persistence layer always uses 16
        return false;
    if (params.memory_kib < kArgon2idMinMemKib * params.parallelism)
        return false;
    if (params.memory_kib > kArgon2idMaxMemKib)
        return false;

    const u32 parallelism = params.parallelism;

    // m_prime: largest multiple of (4*parallelism) <= memory_kib.
    const u32 m_prime = (params.memory_kib / (4u * parallelism)) * (4u * parallelism);
    if (m_prime < 8u * parallelism)
        return false;
    const u32 lane_length = m_prime / parallelism;
    const u32 segment_length = lane_length / 4u;

    // -------------- Allocate the memory matrix --------------
    // Single contiguous Block array of m_prime entries.
    const u64 alloc_bytes = static_cast<u64>(m_prime) * sizeof(Block);
    Block* memory = static_cast<Block*>(duetos::mm::KMalloc(alloc_bytes));
    if (memory == nullptr)
    {
        KLOG_WARN("argon2id", "KMalloc failed for memory matrix");
        return false;
    }

    // -------------- H_0 and initial two blocks per lane --------------
    u8 h0[kArgon2idMaxTagBytes];
    ComputeH0(password, password_len, salt, salt_len, secret, secret_len, ad, ad_len, params, h0);

    // B[i][0] = H'(H_0 || LE32(0) || LE32(i), 1024)
    // B[i][1] = H'(H_0 || LE32(1) || LE32(i), 1024)
    u8 seed[kArgon2idMaxTagBytes + 8];
    for (u32 i = 0; i < kArgon2idMaxTagBytes; ++i)
        seed[i] = h0[i];
    u8 block_bytes[kArgon2idBlockBytes];
    for (u32 lane = 0; lane < parallelism; ++lane)
    {
        // ord = 0
        StoreLE32(seed + kArgon2idMaxTagBytes + 0, 0);
        StoreLE32(seed + kArgon2idMaxTagBytes + 4, lane);
        VarHash(seed, sizeof(seed), block_bytes, kArgon2idBlockBytes);
        BytesToBlock(block_bytes, memory[lane * lane_length + 0]);
        // ord = 1
        StoreLE32(seed + kArgon2idMaxTagBytes + 0, 1);
        VarHash(seed, sizeof(seed), block_bytes, kArgon2idBlockBytes);
        BytesToBlock(block_bytes, memory[lane * lane_length + 1]);
    }

    // -------------- Main mixing loop --------------
    // Sync points are slice boundaries; within a slice, lanes are
    // independent. We run them sequentially (no kernel threads
    // wired into this path yet). Argon2 correctness only requires
    // the slice barrier, not in-slice parallelism.
    for (u32 pass = 0; pass < params.time_cost; ++pass)
    {
        for (u32 slice = 0; slice < 4u; ++slice)
        {
            const bool data_independent = (pass == 0) && (slice < 2u);
            for (u32 lane = 0; lane < parallelism; ++lane)
            {
                IdxState idx;
                InitIdxState(idx, data_independent, pass, lane, slice, m_prime, params.time_cost);

                const u32 starting_index = (pass == 0 && slice == 0) ? 2u : 0u;
                if (data_independent && pass == 0 && slice == 0)
                {
                    // Per phc-winner-argon2 reference: for slice 0
                    // of pass 0, pre-generate the address block
                    // BEFORE the loop because the i % 128 == 0
                    // refresh condition wouldn't fire at i=2.
                    NextAddresses(idx);
                }

                for (u32 j = starting_index; j < segment_length; ++j)
                {
                    const u32 cur_index = slice * segment_length + j;
                    const u32 prev_lane_pos = (cur_index == 0) ? (lane_length - 1u) : (cur_index - 1u);
                    const Block& prev = memory[lane * lane_length + prev_lane_pos];

                    u32 j1 = 0, j2 = 0;
                    if (data_independent)
                    {
                        const u32 addr_in_block = j % 128u;
                        // Refresh on a 128-block boundary (but not at
                        // i=2 of slice 0 pass 0; we pre-fetched).
                        if (addr_in_block == 0 && !(pass == 0 && slice == 0 && j == 0))
                        {
                            NextAddresses(idx);
                        }
                        // For slice 0 pass 0 we use addr indices 2..
                        // since j starts at 2 (matches reference).
                        const u64 addr_word = idx.addresses.v[addr_in_block];
                        j1 = static_cast<u32>(addr_word);
                        j2 = static_cast<u32>(addr_word >> 32);
                    }
                    else
                    {
                        const u64 pv = prev.v[0];
                        j1 = static_cast<u32>(pv);
                        j2 = static_cast<u32>(pv >> 32);
                    }

                    u32 ref_lane = 0, ref_index = 0;
                    ComputeReference(j1, j2, pass, lane, slice, j, segment_length, lane_length, parallelism, ref_lane,
                                     ref_index);

                    const Block& ref = memory[ref_lane * lane_length + ref_index];
                    Block& cur = memory[lane * lane_length + cur_index];
                    if (pass == 0)
                    {
                        Compress(cur, prev, ref);
                    }
                    else
                    {
                        // pass>0: cur = cur XOR G(prev, ref)
                        CompressXor(cur, prev, ref);
                    }
                }
            }
        }
    }

    // -------------- Final tag --------------
    // C = XOR of last blocks of every lane.
    Block c;
    BlockCopy(c, memory[0 * lane_length + (lane_length - 1u)]);
    for (u32 lane = 1; lane < parallelism; ++lane)
    {
        BlockXor(c, memory[lane * lane_length + (lane_length - 1u)]);
    }

    BlockToBytes(c, block_bytes);
    VarHash(block_bytes, kArgon2idBlockBytes, out, params.tag_len);

    // Wipe and free.
    for (u32 i = 0; i < m_prime; ++i)
        BlockZero(memory[i]);
    duetos::mm::KFree(memory);
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

void Argon2idSelfTest()
{
    arch::SerialWrite("[argon2id] self-test: RFC 9106 vector\n");

    // RFC 9106 §5.3 Argon2id test vector.
    //   p = 4, t = 3, m = 32 KiB, tag = 32 bytes
    //   password = 32 * 0x01
    //   salt     = 16 * 0x02
    //   secret   =  8 * 0x03
    //   ad       = 12 * 0x04
    u8 password[32];
    for (u32 i = 0; i < 32; ++i)
        password[i] = 0x01;
    u8 salt[16];
    for (u32 i = 0; i < 16; ++i)
        salt[i] = 0x02;
    u8 secret[8];
    for (u32 i = 0; i < 8; ++i)
        secret[i] = 0x03;
    u8 ad[12];
    for (u32 i = 0; i < 12; ++i)
        ad[i] = 0x04;

    Argon2idParamsRuntime p{};
    p.memory_kib = 32;
    p.time_cost = 3;
    p.parallelism = 4;
    p.tag_len = 32;

    static const u8 kExpected[32] = {0x0D, 0x64, 0x0D, 0xF5, 0x8D, 0x78, 0x76, 0x6C, 0x08, 0xC0, 0x37,
                                     0xA3, 0x4A, 0x8B, 0x53, 0xC9, 0xD0, 0x1E, 0xF0, 0x45, 0x2D, 0x75,
                                     0xB6, 0x5E, 0xB5, 0x25, 0x20, 0xE9, 0x6B, 0x01, 0xE6, 0x59};

    u8 got[32];
    const bool ok = Argon2idDerive(password, 32, salt, 16, secret, 8, ad, 12, p, got);
    if (!ok)
        duetos::core::Panic("argon2id", "self-test: Argon2idDerive returned false");
    if (!BytesEq(got, kExpected, 32))
        duetos::core::Panic("argon2id", "self-test: RFC 9106 §5.3 tag mismatch");

    // Smoke: small derivation with p=1 (the password-hashing common
    // case). Just exercises the single-lane path and confirms the
    // tag is non-zero. No fixed vector — single-lane Argon2id has
    // no canonical RFC vector at small parameters.
    Argon2idParamsRuntime q{};
    q.memory_kib = 16;
    q.time_cost = 2;
    q.parallelism = 1;
    q.tag_len = 32;
    u8 tag2[32] = {0};
    const u8 pw2[5] = {'p', 'a', 's', 's', '!'};
    const u8 sa2[16] = {'S', 'A', 'L', 'T', '_', 'S', 'A', 'L', 'T', '_', 'S', 'A', 'L', 'T', '!', '?'};
    if (!Argon2idDerive(pw2, 5, sa2, 16, nullptr, 0, nullptr, 0, q, tag2))
        duetos::core::Panic("argon2id", "self-test: p=1 derive failed");
    bool any_nonzero = false;
    for (u32 i = 0; i < 32; ++i)
        if (tag2[i] != 0)
            any_nonzero = true;
    if (!any_nonzero)
        duetos::core::Panic("argon2id", "self-test: p=1 derive produced all-zero tag");

    // Determinism — same inputs give same tag.
    u8 tag3[32] = {0};
    if (!Argon2idDerive(pw2, 5, sa2, 16, nullptr, 0, nullptr, 0, q, tag3))
        duetos::core::Panic("argon2id", "self-test: p=1 second derive failed");
    if (!BytesEq(tag2, tag3, 32))
        duetos::core::Panic("argon2id", "self-test: p=1 not deterministic");

    arch::SerialWrite("[argon2id] self-test: PASS\n");
}

} // namespace duetos::security
