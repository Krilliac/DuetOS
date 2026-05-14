#pragma once

#include "crypto/rsa.h"
#include "util/types.h"

/*
 * DuetOS — minimal X.509 v3 certificate parser.
 *
 * Surfaces only the fields the TLS Tier 1 stack needs to
 * authenticate a server certificate:
 *
 *   - The raw TBSCertificate bytes (to hash + RSA-verify
 *     against the issuer's public key).
 *   - The signature algorithm OID (so the verifier picks the
 *     right hash + PKCS1 variant).
 *   - The signature BIT STRING (RSA signature bytes).
 *   - The subject's RSA public key, ready to be handed to
 *     RsaPkcs1V15Verify on the leaf cert's own data.
 *
 * Not surfaced (yet):
 *   - Issuer / subject DN parsing (we don't do CN matching
 *     in v0; SNI happens at the TLS layer).
 *   - Validity dates beyond raw UTCTime / GeneralizedTime
 *     slices.
 *   - X.509 v3 extensions (BasicConstraints, KeyUsage,
 *     SAN). v0 punts on path-length / usage enforcement.
 *
 * Built on crypto/asn1.{h,cpp} for the DER walk and
 * crypto/rsa.{h,cpp} for the public-key marshalling.
 */

namespace duetos::crypto::x509
{

enum class Status : u8
{
    Ok = 0,
    BadCertStructure,      // outer SEQUENCE doesn't parse
    BadTbsStructure,       // TBSCertificate's children don't match
    BadSpkiStructure,      // SubjectPublicKeyInfo malformed
    UnsupportedAlgorithm,  // SPKI algorithm OID is not rsaEncryption
    BadRsaPublicKey,       // RSAPublicKey INTEGERS don't parse
    BadSignatureAlgorithm, // outer signatureAlgorithm malformed
    BadSignatureBitString, // signature BIT STRING malformed
};

const char* StatusName(Status s);

/// Algorithm OIDs we recognise. Stored as the OID body bytes
/// (the value following the universal OID tag + length).
inline constexpr u8 kOidRsaEncryption[] = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01};
inline constexpr u8 kOidSha256WithRsa[] = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B};
inline constexpr u8 kOidSha1WithRsa[] = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x05};

enum class SignatureAlgo : u8
{
    Unknown = 0,
    Sha256WithRsa,
    Sha1WithRsa,
};

/// Parsed view over an X.509 v3 certificate. All byte slices
/// borrow into the caller's input buffer; the certificate
/// bytes must outlive every Certificate produced from them.
struct Certificate
{
    // The bytes that get hashed for the outer signature:
    // exactly the TBSCertificate TLV (header + value), with
    // ASN.1 framing intact.
    const u8* tbs;
    u32 tbs_len;

    // The signatureAlgorithm OID body, as a byte slice.
    SignatureAlgo sig_algo;

    // RSA signature bytes (the BIT STRING value, minus the
    // leading "unused-bits" byte that ASN.1 BIT STRING
    // requires).
    const u8* signature;
    u32 signature_len;

    // Subject's RSA public key, populated when the SPKI
    // algorithm OID is rsaEncryption.
    RsaPublicKey subject_rsa;
    bool subject_rsa_present;

    // Slices into TBSCertificate for callers that want them
    // (validity check, subject DN match). Empty (nullptr,0)
    // if not present.
    const u8* validity_not_before; // UTCTime / GeneralizedTime value bytes
    u32 validity_not_before_len;
    const u8* validity_not_after;
    u32 validity_not_after_len;
};

/// Parse an X.509 v3 cert from a DER buffer.
Status Parse(const u8* der, u32 der_len, Certificate* out);

/// Boot self-test. Builds a minimal hand-crafted certificate
/// in a stack buffer (just enough to exercise the parser:
/// TBS with a fake serial / signature OID / dummy issuer /
/// validity / subject / RSA SPKI; outer signature OID + BIT
/// STRING) and walks it back.
void X509SelfTest();

} // namespace duetos::crypto::x509
