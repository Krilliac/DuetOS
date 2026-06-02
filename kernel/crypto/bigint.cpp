#include "crypto/bigint.h"

#include "arch/x86_64/serial.h"
#include "core/panic.h"
#include "util/compiler.h"

namespace duetos::crypto
{

namespace
{

// Recompute `used` after a mutation by trimming trailing zero
// limbs. Cheap because most of our values are small relative to
// the fixed limb count.
inline void TrimUsed(BigInt* a)
{
    u32 u = kBigIntLimbs;
    while (u > 0 && a->limbs[u - 1] == 0)
        --u;
    a->used = u;
}

// Bit length of `a`. Used by ModExp to walk only the populated
// high bits of the exponent.
u32 BitLength(const BigInt& a)
{
    if (a.used == 0)
        return 0;
    u32 v = a.limbs[a.used - 1];
    u32 bits = (a.used - 1) * 32;
    while (v != 0)
    {
        ++bits;
        v >>= 1;
    }
    return bits;
}

// Test bit `idx` of `a`. Returns 0 or 1.
u32 GetBit(const BigInt& a, u32 idx)
{
    const u32 limb = idx / 32;
    if (limb >= kBigIntLimbs)
        return 0;
    return (a.limbs[limb] >> (idx % 32)) & 1u;
}

} // namespace

// ---------------------------------------------------------------------------

void BigIntZero(BigInt* a)
{
    if (a == nullptr)
        return;
    for (u32 i = 0; i < kBigIntLimbs; ++i)
        a->limbs[i] = 0;
    a->used = 0;
}

void BigIntCopy(BigInt* dst, const BigInt& src)
{
    if (dst == nullptr)
        return;
    for (u32 i = 0; i < kBigIntLimbs; ++i)
        dst->limbs[i] = src.limbs[i];
    dst->used = src.used;
}

bool BigIntFromBytesBE(BigInt* out, const u8* be, u32 len)
{
    if (out == nullptr)
        return false;
    BigIntZero(out);
    if (be == nullptr || len == 0)
        return true;
    if (len > kBigIntBits / 8)
        return false;
    // Walk big-endian input: the most-significant byte is at
    // be[0], so the least-significant byte (which lands in
    // limbs[0]) is at be[len-1].
    for (u32 i = 0; i < len; ++i)
    {
        const u32 byte = be[len - 1 - i];
        const u32 limb_idx = i / 4;
        const u32 shift = (i % 4) * 8;
        out->limbs[limb_idx] |= byte << shift;
    }
    TrimUsed(out);
    return true;
}

u32 BigIntToBytesBE(const BigInt& a, u8* dst, u32 cap)
{
    if (dst == nullptr || cap == 0)
        return 0;
    // Zero-fill the destination so leading bytes are zero
    // for values narrower than cap.
    for (u32 i = 0; i < cap; ++i)
        dst[i] = 0;
    for (u32 i = 0; i < cap; ++i)
    {
        const u32 limb_idx = i / 4;
        const u32 shift = (i % 4) * 8;
        if (limb_idx >= kBigIntLimbs)
            break;
        const u8 byte = static_cast<u8>((a.limbs[limb_idx] >> shift) & 0xFF);
        dst[cap - 1 - i] = byte;
    }
    return cap;
}

DUETOS_NO_SANITIZE_WRAP int BigIntCompare(const BigInt& a, const BigInt& b)
{
    if (a.used != b.used)
        return a.used < b.used ? -1 : 1;
    for (u32 i = a.used; i-- > 0;)
    {
        if (a.limbs[i] != b.limbs[i])
            return a.limbs[i] < b.limbs[i] ? -1 : 1;
    }
    return 0;
}

void BigIntAdd(BigInt* out, const BigInt& a, const BigInt& b)
{
    u64 carry = 0;
    for (u32 i = 0; i < kBigIntLimbs; ++i)
    {
        const u64 sum = u64(a.limbs[i]) + u64(b.limbs[i]) + carry;
        out->limbs[i] = static_cast<u32>(sum & 0xFFFFFFFFu);
        carry = sum >> 32;
    }
    KASSERT(carry == 0, "bigint", "Add overflow past kBigIntBits");
    TrimUsed(out);
}

void BigIntSub(BigInt* out, const BigInt& a, const BigInt& b)
{
    KASSERT(BigIntCompare(a, b) >= 0, "bigint", "Sub underflow");
    i64 borrow = 0;
    for (u32 i = 0; i < kBigIntLimbs; ++i)
    {
        const i64 diff = i64(a.limbs[i]) - i64(b.limbs[i]) - borrow;
        if (diff < 0)
        {
            out->limbs[i] = static_cast<u32>(diff + (i64(1) << 32));
            borrow = 1;
        }
        else
        {
            out->limbs[i] = static_cast<u32>(diff);
            borrow = 0;
        }
    }
    KASSERT(borrow == 0, "bigint", "Sub final borrow nonzero");
    TrimUsed(out);
}

void BigIntMul(BigInt* out, const BigInt& a, const BigInt& b)
{
    // Schoolbook O(n^2). Walks the smaller operand on the
    // outer loop so the inner-loop carry stays in register.
    u32 product[kBigIntLimbs];
    for (u32 i = 0; i < kBigIntLimbs; ++i)
        product[i] = 0;
    const u32 a_used = a.used;
    const u32 b_used = b.used;
    for (u32 i = 0; i < a_used; ++i)
    {
        if (a.limbs[i] == 0)
            continue;
        u64 carry = 0;
        for (u32 j = 0; j < b_used; ++j)
        {
            const u32 idx = i + j;
            KASSERT(idx < kBigIntLimbs, "bigint", "Mul overflow past kBigIntBits");
            const u64 acc = u64(product[idx]) + u64(a.limbs[i]) * u64(b.limbs[j]) + carry;
            product[idx] = static_cast<u32>(acc & 0xFFFFFFFFu);
            carry = acc >> 32;
        }
        // Propagate the final carry into the next column.
        u32 k = i + b_used;
        while (carry != 0 && k < kBigIntLimbs)
        {
            const u64 acc = u64(product[k]) + carry;
            product[k] = static_cast<u32>(acc & 0xFFFFFFFFu);
            carry = acc >> 32;
            ++k;
        }
        KASSERT(carry == 0, "bigint", "Mul carry overflow");
    }
    for (u32 i = 0; i < kBigIntLimbs; ++i)
        out->limbs[i] = product[i];
    TrimUsed(out);
}

DUETOS_NO_SANITIZE_WRAP void BigIntMod(BigInt* out, const BigInt& a, const BigInt& m)
{
    KASSERT(!BigIntIsZero(m), "bigint", "Mod by zero");
    // a < m: result is a.
    if (BigIntCompare(a, m) < 0)
    {
        BigIntCopy(out, a);
        return;
    }

    // Bit-by-bit MSB-first long division: the running remainder `r` is
    // shifted left by one each step, the next bit of `a` is OR-ed in, and
    // `m` is subtracted once when r >= m. `r` is always < m by the end of
    // each step, so it never needs more limbs than `m` has plus the one
    // carry bit the shift can produce. The full BigInt is 128 limbs wide
    // (sized for the RSA-4096 squared-modulus product), but a P-384 field
    // or group modulus is only ~12 limbs — touching all 128 limbs per
    // shift/subtract turned an ECDSA P-384 verify into a multi-minute
    // grind under TCG and froze the boot self-test. So we bound every
    // inner operation to the active window `rl` = (limbs in m) + 1, which
    // is the fast narrow path. `rl` is clamped to the full width, so a
    // modulus that fills the whole BigInt still divides correctly (just at
    // the original full-width cost) — there is no separate slow branch.
    const u32 abits = BitLength(a);
    const u32 mlimbs = m.used; // m != 0 here, so >= 1
    const u32 rl = (mlimbs + 1 <= kBigIntLimbs) ? (mlimbs + 1) : kBigIntLimbs;

    BigInt r{};
    BigIntZero(&r);
    for (u32 i = abits; i-- > 0;)
    {
        // r <<= 1 over just the active window.
        u32 carry = 0;
        for (u32 j = 0; j < rl; ++j)
        {
            const u32 v = r.limbs[j];
            r.limbs[j] = (v << 1) | carry;
            carry = (v >> 31) & 1u;
        }
        // OR in the next bit of a.
        r.limbs[0] |= GetBit(a, i);

        // Compare r >= m over the window (MSB-first), then subtract m if so.
        // rl <= kBigIntLimbs, so r.limbs[j] / m.limbs[j] are always in range.
        bool ge = true; // all-limbs-equal falls through to true (r == m -> r >= m)
        for (u32 j = rl; j-- > 0;)
        {
            const u32 rv = r.limbs[j];
            const u32 mv = m.limbs[j];
            if (rv != mv)
            {
                ge = (rv > mv);
                break;
            }
        }
        if (ge)
        {
            i64 borrow = 0;
            for (u32 j = 0; j < rl; ++j)
            {
                const i64 diff = i64(r.limbs[j]) - i64(m.limbs[j]) - borrow;
                if (diff < 0)
                {
                    r.limbs[j] = static_cast<u32>(diff + (i64(1) << 32));
                    borrow = 1;
                }
                else
                {
                    r.limbs[j] = static_cast<u32>(diff);
                    borrow = 0;
                }
            }
        }
    }
    TrimUsed(&r);
    BigIntCopy(out, r);
}

DUETOS_NO_SANITIZE_WRAP void BigIntModExp(BigInt* out, const BigInt& base, const BigInt& exp, const BigInt& m)
{
    KASSERT(!BigIntIsZero(m), "bigint", "ModExp m=0");
    // result = 1
    BigInt result{};
    BigIntZero(&result);
    result.limbs[0] = 1;
    result.used = 1;
    // running = base mod m
    BigInt running{};
    BigIntMod(&running, base, m);
    const u32 ebits = BitLength(exp);
    // Walk exp MSB-first; on each bit, square-mod the result
    // unconditionally and multiply-mod by `running` if the bit
    // is 1. Walking MSB-first means the first nonzero bit just
    // copies `running` into `result`, then every subsequent bit
    // squares it. Square-mod and mul-mod both go through Mul +
    // Mod so the working values stay bounded.
    for (u32 i = ebits; i-- > 0;)
    {
        // result = result^2 mod m
        BigInt sq{};
        BigIntMul(&sq, result, result);
        BigIntMod(&result, sq, m);
        if (GetBit(exp, i))
        {
            BigInt prod{};
            BigIntMul(&prod, result, running);
            BigIntMod(&result, prod, m);
        }
    }
    BigIntCopy(out, result);
}

// ---------------------------------------------------------------------------
// Self-test
// ---------------------------------------------------------------------------

namespace
{

bool SmallEq(const BigInt& a, u32 expected_low_limb)
{
    if (a.used == 0)
        return expected_low_limb == 0;
    if (a.used != 1)
        return false;
    return a.limbs[0] == expected_low_limb;
}

} // namespace

void BigIntSelfTest()
{
    using arch::SerialWrite;

    // Construct small values via BigIntZero + limb poke.
    BigInt one{};
    BigIntZero(&one);
    one.limbs[0] = 1;
    one.used = 1;

    BigInt two{};
    BigIntZero(&two);
    two.limbs[0] = 2;
    two.used = 1;

    BigInt three{};
    BigIntZero(&three);
    three.limbs[0] = 3;
    three.used = 1;

    BigInt ten{};
    BigIntZero(&ten);
    ten.limbs[0] = 10;
    ten.used = 1;

    BigInt thousand{};
    BigIntZero(&thousand);
    thousand.limbs[0] = 1000;
    thousand.used = 1;

    BigInt sixfivek{};
    BigIntZero(&sixfivek);
    sixfivek.limbs[0] = 65537;
    sixfivek.used = 1;

    // Add: 1 + 2 = 3.
    BigInt s{};
    BigIntAdd(&s, one, two);
    if (!SmallEq(s, 3))
    {
        SerialWrite("[bigint] FAIL add\n");
        return;
    }

    // Sub: 3 - 1 = 2.
    BigInt d{};
    BigIntSub(&d, three, one);
    if (!SmallEq(d, 2))
    {
        SerialWrite("[bigint] FAIL sub\n");
        return;
    }

    // Mul: 3 * 10 = 30.
    BigInt p{};
    BigIntMul(&p, three, ten);
    if (!SmallEq(p, 30))
    {
        SerialWrite("[bigint] FAIL mul\n");
        return;
    }

    // Mod: 1000 mod 65537 = 1000.
    BigInt r{};
    BigIntMod(&r, thousand, sixfivek);
    if (!SmallEq(r, 1000))
    {
        SerialWrite("[bigint] FAIL mod-small\n");
        return;
    }

    // ModExp: 2^10 mod 1000 = 24.
    BigInt ex{};
    BigIntZero(&ex);
    ex.limbs[0] = 10;
    ex.used = 1;
    BigInt got{};
    BigIntModExp(&got, two, ex, thousand);
    if (!SmallEq(got, 24))
    {
        SerialWrite("[bigint] FAIL modexp-2^10\n");
        return;
    }

    // Fermat little theorem spot check: for prime p=65537,
    // 3^p mod p = 3 (i.e. a^p == a mod p when gcd(a,p) = 1).
    BigIntModExp(&got, three, sixfivek, sixfivek);
    if (!SmallEq(got, 3))
    {
        SerialWrite("[bigint] FAIL modexp-fermat\n");
        return;
    }

    // BE round-trip: a 4-byte signature value goes in, comes out
    // identical at fixed width.
    const u8 in_be[4] = {0x12, 0x34, 0x56, 0x78};
    BigInt v{};
    if (!BigIntFromBytesBE(&v, in_be, 4))
    {
        SerialWrite("[bigint] FAIL bytes-in\n");
        return;
    }
    u8 out_be[8] = {0};
    BigIntToBytesBE(v, out_be, 8);
    // 8-byte fixed width: 4 leading zeros, then the original bytes.
    const u8 want[8] = {0, 0, 0, 0, 0x12, 0x34, 0x56, 0x78};
    for (u32 i = 0; i < 8; ++i)
    {
        if (out_be[i] != want[i])
        {
            SerialWrite("[bigint] FAIL bytes-rt\n");
            return;
        }
    }

    SerialWrite("[bigint] PASS (add/sub/mul/mod/modexp/be-rt)\n");
}

} // namespace duetos::crypto
