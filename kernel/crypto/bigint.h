#pragma once

#include "util/types.h"

/*
 * DuetOS — fixed-size big-integer arithmetic for asymmetric crypto.
 *
 * Backs RSA verify (PKCS#1 v1.5) and is the substrate for the
 * future ECDH + ECDSA paths in `crypto/ecp.{h,cpp}` (TLS Tier 2).
 * Scope is deliberately narrow:
 *
 *   - Fixed maximum operand width (kBigIntLimbs * 32 bits = 4096
 *     bits). Holds an RSA-4096 modulus directly; the 8192-bit
 *     squared-modulus product used inside modular exponentiation
 *     lives in a file-local double-width accumulator (bigint.cpp),
 *     not in a `BigInt`, so the public type stays 512 bytes.
 *   - Unsigned only — RSA / DH / ECP all live in non-negative
 *     modular rings. The Sub family clamps to zero / asserts on
 *     wrap.
 *   - No allocation. Every value is a `BigInt` by value on the
 *     caller's stack. Caller pays the 512-byte stack cost per
 *     scratch variable; for RSA verify the working set is ~4 KB.
 *   - No constant-time guarantees in v0 — this is a verify-only
 *     path. Signing / DH-private-side / secret-data operations
 *     will need a constant-time rework in a follow-on slice.
 *
 * The eventual TLS handshake calls into this layer for:
 *   - RSA-2048 signature verify on the server's certificate.
 *   - (later) RSA encrypt for the pre-master secret (TLS 1.2
 *     `TLS_RSA_*`).
 *   - (later) Modular arithmetic for ECDH P-256 (TLS 1.3).
 *
 * Threading: every routine is pure — operates on caller-supplied
 * BigInt values, no global state, safe from any context.
 */

namespace duetos::crypto
{

// 128 u32 limbs * 32 bits = 4096 bits. This is the maximum OPERAND
// width — it holds an RSA-4096 modulus (and 2048/3072) directly. The
// unreduced a*b / a^2 product inside modular exponentiation is up to
// twice this (8192 bits for RSA-4096); it does NOT live in a `BigInt`.
// ModExp computes it in a file-local double-width accumulator
// (`BigIntWide`, bigint.cpp) and reduces it modulo `m` straight back
// into a `BigInt`, so the public type stays 512 bytes and only ModExp
// pays the wide cost on its own stack frame.
inline constexpr u32 kBigIntLimbs = 128;
inline constexpr u32 kBigIntBits = kBigIntLimbs * 32;

// Little-endian limb order: `limbs[0]` is the least-significant
// 32 bits. `used` is the count of "active" limbs — the high
// limbs from `used` to `kBigIntLimbs - 1` are guaranteed zero.
// Callers can read past `used` without bounds-checking; the
// constructors zero the trailing limbs.
struct BigInt
{
    u32 limbs[kBigIntLimbs];
    u32 used;
};

// ---- construction / IO -----------------------------------------

/// Zero `a` (used = 0, every limb cleared).
void BigIntZero(BigInt* a);

/// Copy `src` into `dst` (full struct, including the
/// zero-padded high limbs).
void BigIntCopy(BigInt* dst, const BigInt& src);

/// Construct from a big-endian byte buffer (most-significant
/// byte first — the on-wire encoding for RSA modulus, signature,
/// and certificate INTEGER fields). `len` is in bytes; values
/// longer than `kBigIntBits / 8` are rejected (returns false and
/// leaves `*out` zeroed).
bool BigIntFromBytesBE(BigInt* out, const u8* be, u32 len);

/// Reverse of `BigIntFromBytesBE`: emit big-endian bytes into
/// `dst[0..cap)`. Returns the number of bytes written; pads
/// leading zeros up to `cap` so the output is a fixed-width
/// representation (RSA signatures are always modulus-width).
u32 BigIntToBytesBE(const BigInt& a, u8* dst, u32 cap);

// ---- comparison ------------------------------------------------

/// Returns -1 / 0 / +1 for a < b / a == b / a > b.
int BigIntCompare(const BigInt& a, const BigInt& b);

inline bool BigIntIsZero(const BigInt& a)
{
    return a.used == 0;
}

// ---- additive operations ---------------------------------------

/// `out = a + b`. Asserts on overflow past `kBigIntBits` — RSA
/// callers always operate on values bounded by the modulus, which
/// is at most kBigIntBits / 2, so overflow indicates a logic bug.
void BigIntAdd(BigInt* out, const BigInt& a, const BigInt& b);

/// `out = a - b`. Asserts on underflow (a < b). Used internally
/// by mod-reduce; external callers should guard with
/// `BigIntCompare`.
void BigIntSub(BigInt* out, const BigInt& a, const BigInt& b);

// ---- multiplicative operations ---------------------------------

/// `out = a * b`. The result fits in `kBigIntBits` only if
/// `bits(a) + bits(b) <= kBigIntBits`. Inside ModExp we
/// arrange callers so squaring an N-bit value stays within 2N
/// bits, and 2N <= kBigIntBits.
void BigIntMul(BigInt* out, const BigInt& a, const BigInt& b);

/// `out = a mod m`. Implemented as repeated shift-and-subtract;
/// O(bits(a) * limbs(m)). Sufficient for v0 verify but slow —
/// Barrett or Montgomery reduction is a follow-on.
void BigIntMod(BigInt* out, const BigInt& a, const BigInt& m);

/// `out = base^exp mod m`. Square-and-multiply, MSB-first. The
/// exponent's bits are walked top-to-bottom; each iteration
/// squares and conditionally multiplies, then reduces modulo `m`.
void BigIntModExp(BigInt* out, const BigInt& base, const BigInt& exp, const BigInt& m);

// ---- self-test --------------------------------------------------

/// Boot-time round-trip test:
///   - Add / Sub commutativity.
///   - Mul matches a known small product.
///   - Mod matches a known small remainder.
///   - ModExp computes 2^10 mod 1000 = 24 and 3^65537 mod 65537 = 3
///     (Fermat for prime 65537).
///   - RSA-4096 known-answer vector: sig^e mod n reproduces the
///     EMSA-PKCS1-v1_5 encoded message (host-OpenSSL provenance, see
///     bigint_rsa4096_vector.h), plus a full-width (n-1)^2 == 1 (mod n)
///     carry-stress check. Both exercise the 8192-bit intermediate
///     product handled by the file-local double-width accumulator.
/// Emits `[bigint] PASS (... incl 4096)` / `[bigint] FAIL <step>` on serial.
void BigIntSelfTest();

} // namespace duetos::crypto
