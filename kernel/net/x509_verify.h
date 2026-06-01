#pragma once

#include "util/types.h"

/*
 * DuetOS — X.509 certificate-chain verification for the TLS / HTTPS path.
 *
 * Sits ABOVE the structural parser in `crypto/x509.{h,cpp}` and the
 * primitive RSA verify in `crypto/rsa.{h,cpp}`. Where `crypto::x509`
 * answers "what does this DER say?", this layer answers the
 * security-critical question the TLS client actually needs:
 *
 *   "Is the certificate this server presented trustworthy for the
 *    hostname I dialed, right now?"
 *
 * That is the conjunction of four independent checks, ALL of which
 * must hold for Verify() to return true:
 *
 *   1. Signature(s): every certificate in the path is signed by the
 *      public key of the next cert up — RSA-PKCS#1 v1.5 + SHA-256, OR
 *      ECDSA + SHA-256 (P-256) / SHA-384 (P-384) — terminating at a key
 *      we trust a priori.
 *   2. Chain-to-anchor: the path terminates at a certificate whose
 *      public key is in our embedded trust store (a small set of
 *      self-signed roots). Depth is bounded at 2 (leaf, optional
 *      single intermediate, root).
 *   3. Hostname: the leaf's subjectAltName dNSName list (with a
 *      leftmost "*." wildcard) matches the dialed hostname, falling
 *      back to the subject CN when no SAN is present. ASCII
 *      case-insensitive.
 *   4. Validity window: `now_unix` lies within [notBefore, notAfter]
 *      for every certificate in the path.
 *
 * SECURITY POSTURE: a verifier that returns true when it should
 * return false is strictly worse than no verifier at all, because it
 * launders an attacker's certificate as trusted. Every parse step
 * over attacker-controlled DER is bounds-checked, every ambiguous or
 * unsupported shape fails CLOSED (returns false / "not trusted"), and
 * no path returns true without all four checks passing.
 *
 * Supported signature primitives: RSA-PKCS#1 v1.5 + SHA-256, and ECDSA
 * over NIST P-256 (ecdsa-with-SHA256) and P-384 (ecdsa-with-SHA384). The
 * EC math lives in net/ec.{h,cpp}; SHA-384 in crypto/sha384.{h,cpp}.
 *
 * GAP (deliberately unimplemented — fail closed on each):
 *   - Other signature schemes: RSA-PSS, Ed25519/Ed448, ECDSA over P-521 /
 *     brainpool, ecdsa-with-SHA1 / SHA-512, compressed EC points (only the
 *     0x04 uncompressed SEC1 form is accepted). A cert signed any other
 *     way fails verification.
 *   - Name constraints, EKU / KU policy enforcement, basicConstraints
 *     pathLen beyond the hard depth-2 cap.
 *   - CRL / OCSP revocation. A revoked-but-unexpired cert still
 *     verifies. Revisit when the network stack can fetch OCSP.
 *   - The full Mozilla / CCADB root program. The embedded store carries
 *     synthetic test roots PLUS a small hand-picked set of real,
 *     widely-trusted roots: RSA-2048 sha256WithRSA roots (DigiCert Global
 *     Root G2, Amazon Root CA 1, GlobalSign Root CA - R3, Go Daddy Root
 *     CA - G2, AffirmTrust Commercial) and P-384 ecdsa-with-SHA384 roots
 *     (DigiCert Global Root G3, ISRG Root X2). Sites whose chains
 *     terminate at any OTHER root fail closed until that root lands.
 *   - RSA-4096 moduli. The kernel bigint is 4096 bits wide, which holds a
 *     2048-bit modulus's squared intermediate but overflows on a 4096-bit
 *     one. RSA-4096 roots/leaves fail closed until the bigint widens.
 *     (EC operands are far smaller — P-384's 768-bit product fits easily.)
 *   - Cross-signed / multi-path chains, chains deeper than one
 *     intermediate.
 */

namespace duetos::net::x509
{

/// Maximum certificate DER we will look at. A real-world RSA-4096
/// leaf with a fat SAN list is well under this; anything larger is
/// rejected as malformed rather than chewing unbounded CPU.
inline constexpr u32 kMaxCertDer = 16 * 1024;

/// Maximum chain certs the caller may supply (intermediates). The
/// effective trust path is leaf + at most one intermediate + root,
/// so we only ever consult the first usable intermediate, but we
/// accept a small array for forward compatibility.
inline constexpr u32 kMaxChainCerts = 8;

/// Verify a presented certificate against the embedded trust store.
///
///   leaf_der / leaf_len   The server's leaf certificate, DER.
///   chain_ders / chain_lens / chain_count
///                         Intermediate certificates the server sent
///                         (DER each). May be empty when the leaf is
///                         issued directly by a trusted root. Order
///                         is not assumed — the builder searches.
///   hostname              NUL-terminated dialed hostname (the SNI /
///                         URL host). Must be non-empty.
///   now_unix              Current wall-clock time, Unix epoch
///                         seconds, used for the validity window.
///
/// Returns true IFF the leaf chains (depth <= 2) to a trusted root
/// with every signature valid, the hostname matches the leaf's
/// SAN/CN, and every cert in the path is within its validity window
/// at `now_unix`. Returns false on ANY parse error, unsupported
/// algorithm, missing link, hostname mismatch, or time-window
/// violation. Never throws; safe on fully attacker-controlled input.
bool Verify(const u8* leaf_der, u32 leaf_len, const u8* const* chain_ders, const u32* chain_lens, u32 chain_count,
            const char* hostname, u64 now_unix);

/// Function-pointer shape a TLS socket layer can install as its
/// certificate-verification callback. `Verify` already matches this
/// shape; the typedef pins the contract so a thin adapter in the
/// socket layer can take `CertVerifyFn` without depending on this
/// header's full surface.
using CertVerifyFn = bool (*)(const u8* leaf_der, u32 leaf_len, const u8* const* chain_ders, const u32* chain_lens,
                              u32 chain_count, const char* hostname, u64 now_unix);

/// Boot self-test. First runs the SHA-384 and EC/ECDSA primitive KATs
/// (crypto::Sha384SelfTest, ec::EcSelfTest), then embeds real
/// OpenSSL-generated DER fixtures — an RSA self-signed root + leaf +
/// intermediate + depth-2 leaf, AND a P-256 ECDSA self-signed root + leaf
/// for "ec.test.duetos.local" — and asserts:
///   - the valid RSA leaf->root and leaf->intermediate->root paths TRUE,
///   - the valid ECDSA leaf->root path (+ SAN wildcard) TRUE,
///   - a tampered signature byte (RSA and ECDSA) verifies FALSE,
///   - a wrong hostname verifies FALSE,
///   - an out-of-window `now_unix` verifies FALSE,
///   - a leaf with no trusted issuer verifies FALSE,
///   - every embedded REAL root parses and its own self-signature
///     verifies (RSA+SHA-256 for the 5 RSA roots, ECDSA+SHA-384 for the
///     2 P-384 roots), proving the chain-verify code works on real-world
///     DER, not just the synthetic fixtures.
/// Real leaves are deliberately NOT embedded: they expire, so a
/// hardcoded live leaf is not a durable self-test — only the roots'
/// long-lived self-signatures are asserted.
/// Emits `[x509-verify-selftest] PASS (...)`; on any failure fires
/// KBP_PROBE_V(kBootSelftestFail, ...) and emits a FAIL line.
void X509VerifySelfTest();

} // namespace duetos::net::x509
