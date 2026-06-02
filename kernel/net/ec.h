#pragma once

#include "crypto/bigint.h"
#include "util/types.h"

/*
 * DuetOS — elliptic-curve math for ECDSA certificate verification.
 *
 * Scope (deliberately narrow — this exists ONLY to validate ECDSA
 * certificate chains on the HTTPS path):
 *
 *   - Two short-Weierstrass curves over a prime field, y^2 = x^3 + ax + b:
 *       * NIST P-256 (secp256r1) — the dominant ECDSA leaf/intermediate
 *         curve on the public web.
 *       * NIST P-384 (secp384r1) — used by the ECDSA web ROOTS we embed
 *         (DigiCert Global Root G3, ISRG Root X2, the GTS R* ECC roots).
 *   - Prime-field arithmetic (add/sub/mul/inverse mod p) on the kernel
 *     bigint (`crypto::BigInt`). A 384-bit operand's product is 768 bits,
 *     well inside the 4096-bit bigint width — no overflow risk.
 *   - Point add / double in Jacobian projective coordinates, and
 *     double-and-add scalar multiplication.
 *   - ECDSA-Verify(curve, Q, hash, r, s) per FIPS 186-4 / SEC1 §4.1.4.
 *
 * NOT constant-time: this path only ever touches PUBLIC data (the
 * server's certificate, its public key, the signature, the message
 * hash). There is no secret to leak via timing, so the simpler
 * variable-time double-and-add and Fermat inverse are correct here.
 * (A signing / ECDH-private path would need a constant-time rework —
 * that is out of scope.)
 *
 * HOSTILE-INPUT SAFE: every public input is range-checked. r,s outside
 * [1, n-1] are rejected; a public-key point that is not on the curve is
 * rejected; the identity / point-at-infinity is rejected. The contract
 * is the same as the X.509 verifier above it: a function that returns
 * "valid" when it should not is strictly worse than one that always
 * fails, so every ambiguous shape fails closed.
 *
 * GAP (out of scope — fail closed): P-521, brainpool, Ed25519/Ed448
 * (those are not short-Weierstrass), and compressed point encodings
 * (the SPKI parser in x509_verify only accepts the 0x04 uncompressed
 * form).
 */

namespace duetos::net::ec
{

/// The two curves this module supports.
enum class CurveId : u8
{
    P256 = 0,
    P384 = 1,
};

/// An affine point. `infinity == true` marks the identity element (the
/// point at infinity); x/y are then meaningless.
struct Point
{
    duetos::crypto::BigInt x;
    duetos::crypto::BigInt y;
    bool infinity;
};

/// Curve domain parameters, resolved from a CurveId. All values are
/// big-integers over the kernel bigint. Field byte width is the number
/// of bytes in the coordinate encoding (32 for P-256, 48 for P-384).
struct Curve
{
    duetos::crypto::BigInt p; // field prime
    duetos::crypto::BigInt a; // curve coefficient a (== p-3 for both)
    duetos::crypto::BigInt b; // curve coefficient b
    duetos::crypto::BigInt n; // group order
    Point g;                  // base point G
    u32 field_bytes;          // 32 (P-256) or 48 (P-384)
};

/// Resolve a CurveId to its domain parameters. Returns false for an
/// unknown id (never happens for the two enum values, but keeps the
/// caller honest).
bool GetCurve(CurveId id, Curve* out);

/// Parse an uncompressed EC point (SEC1 0x04 || X || Y) of the curve's
/// field width into an affine Point AND verify it lies on the curve and
/// is not the identity. Returns false on a bad length, a non-0x04
/// prefix, an out-of-range coordinate, or a point not on the curve.
/// `len` is the full length including the 0x04 prefix byte.
bool ParsePublicKey(const Curve& curve, const u8* point, u32 len, Point* out);

/// ECDSA signature verification (FIPS 186-4 §4.1.4 / SEC1 §4.1.4).
///
///   curve     Domain parameters (must match the public key's curve).
///   pubkey    The signer's public key Q, already validated by
///             ParsePublicKey (on-curve, not identity).
///   hash/hlen The message hash (SHA-256 digest for P-256 web certs,
///             SHA-384 for P-384). Leftmost min(hlen, ceil(log2 n / 8))
///             bytes are taken as the integer e, per SEC1.
///   r, s      Signature integers, big-endian bytes (the two INTEGERs
///             from the ECDSA-Sig-Value SEQUENCE). Each must lie in
///             [1, n-1] or the verify fails closed.
///
/// Returns true IFF the signature is valid for (hash, pubkey) on this
/// curve. Returns false on any out-of-range input, a point-at-infinity
/// intermediate, or a final r-comparison mismatch. Never asserts on
/// attacker-controlled bytes.
bool EcdsaVerify(const Curve& curve, const Point& pubkey, const u8* hash, u32 hlen, const u8* r, u32 r_len, const u8* s,
                 u32 s_len);

/// Boot self-test: a P-256 and a P-384 known-answer ECDSA verification
/// (valid signature => true), plus negatives (tampered r, out-of-range
/// s, off-curve point) => false. Emits `[ec-selftest] PASS (...)`; on
/// failure fires KBP_PROBE_V(kBootSelftestFail, ...) and a FAIL line.
void EcSelfTest();

} // namespace duetos::net::ec
