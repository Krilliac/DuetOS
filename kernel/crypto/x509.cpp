#include "crypto/x509.h"

#include "arch/x86_64/serial.h"
#include "crypto/asn1.h"

namespace duetos::crypto::x509
{

const char* StatusName(Status s)
{
    switch (s)
    {
    case Status::Ok:
        return "Ok";
    case Status::BadCertStructure:
        return "BadCertStructure";
    case Status::BadTbsStructure:
        return "BadTbsStructure";
    case Status::BadSpkiStructure:
        return "BadSpkiStructure";
    case Status::UnsupportedAlgorithm:
        return "UnsupportedAlgorithm";
    case Status::BadRsaPublicKey:
        return "BadRsaPublicKey";
    case Status::BadSignatureAlgorithm:
        return "BadSignatureAlgorithm";
    case Status::BadSignatureBitString:
        return "BadSignatureBitString";
    }
    return "?";
}

namespace
{

bool ParseAlgorithmId(const asn1::Element& algo, SignatureAlgo* out)
{
    *out = SignatureAlgo::Unknown;
    if (algo.tag != asn1::kTagSequence)
        return false;
    asn1::Element oid{};
    if (asn1::Read(algo.value, algo.len, &oid) != asn1::Status::Ok)
        return false;
    if (oid.tag != asn1::kTagOid)
        return false;
    if (asn1::OidEquals(oid, kOidSha256WithRsa, sizeof(kOidSha256WithRsa)))
        *out = SignatureAlgo::Sha256WithRsa;
    else if (asn1::OidEquals(oid, kOidSha1WithRsa, sizeof(kOidSha1WithRsa)))
        *out = SignatureAlgo::Sha1WithRsa;
    return true;
}

// Decode SubjectPublicKeyInfo:
//   SubjectPublicKeyInfo ::= SEQUENCE {
//       algorithm        AlgorithmIdentifier,
//       subjectPublicKey BIT STRING
//   }
// For rsaEncryption, the BIT STRING wraps:
//   RSAPublicKey ::= SEQUENCE {
//       modulus         INTEGER,
//       publicExponent  INTEGER
//   }
bool ParseSpki(const asn1::Element& spki, RsaPublicKey* rsa, bool* rsa_present)
{
    *rsa_present = false;
    if (spki.tag != asn1::kTagSequence)
        return false;
    asn1::Element algo{};
    if (asn1::Read(spki.value, spki.len, &algo) != asn1::Status::Ok)
        return false;
    if (algo.tag != asn1::kTagSequence)
        return false;
    asn1::Element algo_oid{};
    if (asn1::Read(algo.value, algo.len, &algo_oid) != asn1::Status::Ok)
        return false;
    if (algo_oid.tag != asn1::kTagOid)
        return false;
    // Only RSA in v0. Non-RSA algorithms parse OK but rsa_present stays false.
    const bool is_rsa = asn1::OidEquals(algo_oid, kOidRsaEncryption, sizeof(kOidRsaEncryption));
    // BIT STRING after algorithm.
    const u32 algo_step = algo.header_len + algo.len;
    if (algo_step > spki.len)
        return false;
    asn1::Element bitstr{};
    if (asn1::Read(spki.value + algo_step, spki.len - algo_step, &bitstr) != asn1::Status::Ok)
        return false;
    if (bitstr.tag != asn1::kTagBitString || bitstr.len < 1)
        return false;
    // BIT STRING value starts with a one-byte "unused bits"
    // count, then the actual bit-string contents. For RSA SPKI
    // this contents is an ASN.1 SEQUENCE of (modulus, exponent).
    const u8 unused_bits = bitstr.value[0];
    if (unused_bits != 0)
        return false; // RSA SPKI never has trailing unused bits
    if (!is_rsa)
        return true;
    asn1::Element rsa_seq{};
    if (asn1::Read(bitstr.value + 1, bitstr.len - 1, &rsa_seq) != asn1::Status::Ok)
        return false;
    if (rsa_seq.tag != asn1::kTagSequence)
        return false;
    asn1::Element mod_int{};
    if (asn1::Read(rsa_seq.value, rsa_seq.len, &mod_int) != asn1::Status::Ok)
        return false;
    if (mod_int.tag != asn1::kTagInteger)
        return false;
    const u32 mod_step = mod_int.header_len + mod_int.len;
    if (mod_step > rsa_seq.len)
        return false;
    asn1::Element exp_int{};
    if (asn1::Read(rsa_seq.value + mod_step, rsa_seq.len - mod_step, &exp_int) != asn1::Status::Ok)
        return false;
    if (exp_int.tag != asn1::kTagInteger)
        return false;
    // Decode the INTEGER bytes (strip the DER leading-zero
    // disambiguation if present) and hand to RsaPublicKeyFromBE.
    u8 mod_buf[kBigIntBits / 8];
    u8 exp_buf[16];
    // ML-07: IntegerToBytesBE clamps an over-long INTEGER to the
    // buffer capacity (its contract — the exponent path relies on
    // it). For the modulus that clamp would silently TRUNCATE a
    // >4096-bit RSA key from an untrusted cert into a different,
    // shorter key, feeding key-confusion into real verification.
    // Reject the over-long modulus here instead of accepting the
    // clamp. Mirror IntegerToBytesBE's de-padding so the comparison
    // is against the natural unsigned big-endian length.
    u32 mod_natural_len = mod_int.len;
    if (mod_int.len >= 2 && mod_int.value[0] == 0x00 && (mod_int.value[1] & 0x80) != 0)
        mod_natural_len -= 1;
    if (mod_natural_len > sizeof(mod_buf))
        return false;
    const u32 mod_bytes = asn1::IntegerToBytesBE(mod_int, mod_buf, sizeof(mod_buf));
    const u32 exp_bytes = asn1::IntegerToBytesBE(exp_int, exp_buf, sizeof(exp_buf));
    if (mod_bytes == 0 || exp_bytes == 0)
        return false;
    if (!RsaPublicKeyFromBE(rsa, mod_buf, mod_bytes, exp_buf, exp_bytes))
        return false;
    *rsa_present = true;
    return true;
}

// Walk TBSCertificate. The first child is either the [0]
// EXPLICIT version tag (context-specific tag 0xA0) or, in v1
// certs, the serial INTEGER directly. v3 certs we care about
// always carry the version, but parse defensively.
//
//   TBSCertificate ::= SEQUENCE {
//       [0] EXPLICIT Version (optional),
//       serialNumber,
//       signature AlgorithmIdentifier,
//       issuer Name,
//       validity Validity { notBefore Time, notAfter Time },
//       subject Name,
//       subjectPublicKeyInfo SubjectPublicKeyInfo,
//       [...] OPTIONAL extensions
//   }
//
// We extract validity bytes and the SPKI; everything else is
// skipped past.
bool ParseTbs(const asn1::Element& tbs, Certificate* out)
{
    if (tbs.tag != asn1::kTagSequence)
        return false;
    u32 off = 0;
    auto step_next = [&]() -> bool
    {
        asn1::Element e{};
        if (asn1::Read(tbs.value + off, tbs.len - off, &e) != asn1::Status::Ok)
            return false;
        off += e.header_len + e.len;
        return true;
    };

    asn1::Element first{};
    if (asn1::Read(tbs.value, tbs.len, &first) != asn1::Status::Ok)
        return false;
    // Skip [0] EXPLICIT Version if present (tag 0xA0).
    if (first.tag == 0xA0)
    {
        off = first.header_len + first.len;
    }
    // serialNumber
    if (!step_next())
        return false;
    // signature AlgorithmIdentifier (inside TBS — separate
    // from the outer signatureAlgorithm; spec requires they
    // match)
    if (!step_next())
        return false;
    // issuer Name
    if (!step_next())
        return false;
    // validity SEQUENCE { notBefore Time, notAfter Time }
    asn1::Element validity{};
    if (asn1::Read(tbs.value + off, tbs.len - off, &validity) != asn1::Status::Ok)
        return false;
    if (validity.tag == asn1::kTagSequence)
    {
        asn1::Element nb{};
        if (asn1::Read(validity.value, validity.len, &nb) == asn1::Status::Ok)
        {
            out->validity_not_before = nb.value;
            out->validity_not_before_len = nb.len;
            const u32 nb_step = nb.header_len + nb.len;
            if (nb_step <= validity.len)
            {
                asn1::Element na{};
                if (asn1::Read(validity.value + nb_step, validity.len - nb_step, &na) == asn1::Status::Ok)
                {
                    out->validity_not_after = na.value;
                    out->validity_not_after_len = na.len;
                }
            }
        }
    }
    off += validity.header_len + validity.len;
    // subject Name — RDN sequence; walk it looking for the
    // commonName attribute (OID 2.5.4.3 = body bytes 55 04 03).
    asn1::Element subject{};
    if (asn1::Read(tbs.value + off, tbs.len - off, &subject) != asn1::Status::Ok)
        return false;
    if (subject.tag == asn1::kTagSequence)
    {
        // Walk RDNSequence -> SET -> SEQUENCE { OID, value }
        u32 sub_off = 0;
        while (sub_off < subject.len)
        {
            asn1::Element rdn{};
            if (asn1::Read(subject.value + sub_off, subject.len - sub_off, &rdn) != asn1::Status::Ok)
                break;
            if (rdn.tag == asn1::kTagSet)
            {
                u32 set_off = 0;
                while (set_off < rdn.len)
                {
                    asn1::Element atv{};
                    if (asn1::Read(rdn.value + set_off, rdn.len - set_off, &atv) != asn1::Status::Ok)
                        break;
                    if (atv.tag == asn1::kTagSequence)
                    {
                        asn1::Element oid{};
                        if (asn1::Read(atv.value, atv.len, &oid) == asn1::Status::Ok && oid.tag == asn1::kTagOid)
                        {
                            // commonName OID body = 0x55 0x04 0x03
                            static constexpr u8 kCnOid[] = {0x55, 0x04, 0x03};
                            if (asn1::OidEquals(oid, kCnOid, sizeof(kCnOid)))
                            {
                                const u32 oid_step = oid.header_len + oid.len;
                                if (oid_step < atv.len)
                                {
                                    asn1::Element val{};
                                    if (asn1::Read(atv.value + oid_step, atv.len - oid_step, &val) == asn1::Status::Ok)
                                    {
                                        // Accept any string-shaped tag
                                        // (PrintableString / UTF8String /
                                        // IA5String). Other tags are
                                        // legal-but-rare; ignore for v0.
                                        if (val.tag == asn1::kTagPrintableString || val.tag == asn1::kTagUtf8String ||
                                            val.tag == asn1::kTagIa5String)
                                        {
                                            out->subject_cn = val.value;
                                            out->subject_cn_len = val.len;
                                        }
                                    }
                                }
                            }
                        }
                    }
                    set_off += atv.header_len + atv.len;
                }
            }
            sub_off += rdn.header_len + rdn.len;
        }
    }
    off += subject.header_len + subject.len;
    // SPKI
    asn1::Element spki{};
    if (asn1::Read(tbs.value + off, tbs.len - off, &spki) != asn1::Status::Ok)
        return false;
    if (!ParseSpki(spki, &out->subject_rsa, &out->subject_rsa_present))
        return false;
    return true;
}

} // namespace

bool CnMatchesHostname(const u8* cn, u32 cn_len, const char* hostname)
{
    if (cn == nullptr || hostname == nullptr)
        return false;
    u32 host_len = 0;
    while (hostname[host_len] != '\0')
        ++host_len;
    if (cn_len != host_len)
        return false;
    for (u32 i = 0; i < cn_len; ++i)
    {
        u8 a = cn[i];
        u8 b = static_cast<u8>(hostname[i]);
        if (a >= 'A' && a <= 'Z')
            a = static_cast<u8>(a + 32);
        if (b >= 'A' && b <= 'Z')
            b = static_cast<u8>(b + 32);
        if (a != b)
            return false;
    }
    return true;
}

Status Parse(const u8* der, u32 der_len, Certificate* out)
{
    if (der == nullptr || out == nullptr)
        return Status::BadCertStructure;
    *out = Certificate{};
    asn1::Element outer{};
    if (asn1::Read(der, der_len, &outer) != asn1::Status::Ok)
        return Status::BadCertStructure;
    if (outer.tag != asn1::kTagSequence)
        return Status::BadCertStructure;
    // The outer SEQUENCE has three children:
    //   TBSCertificate, signatureAlgorithm, signature(BIT STRING).
    asn1::Element tbs{};
    if (asn1::Read(outer.value, outer.len, &tbs) != asn1::Status::Ok)
        return Status::BadTbsStructure;
    out->tbs = outer.value;
    out->tbs_len = tbs.header_len + tbs.len;
    if (!ParseTbs(tbs, out))
        return Status::BadTbsStructure;
    // signatureAlgorithm
    const u32 algo_off = tbs.header_len + tbs.len;
    asn1::Element sig_algo{};
    if (asn1::Read(outer.value + algo_off, outer.len - algo_off, &sig_algo) != asn1::Status::Ok)
        return Status::BadSignatureAlgorithm;
    if (!ParseAlgorithmId(sig_algo, &out->sig_algo))
        return Status::BadSignatureAlgorithm;
    // signature BIT STRING
    const u32 sig_off = algo_off + sig_algo.header_len + sig_algo.len;
    asn1::Element sig_bs{};
    if (asn1::Read(outer.value + sig_off, outer.len - sig_off, &sig_bs) != asn1::Status::Ok)
        return Status::BadSignatureBitString;
    if (sig_bs.tag != asn1::kTagBitString || sig_bs.len < 1 || sig_bs.value[0] != 0)
        return Status::BadSignatureBitString;
    out->signature = sig_bs.value + 1;
    out->signature_len = sig_bs.len - 1;
    return Status::Ok;
}

// ---------------------------------------------------------------------------
// Self-test
//
// Builds the minimum X.509-shaped TLV tree the parser walks:
//   SEQUENCE {                      <-- outer cert
//     SEQUENCE {                    <-- TBSCertificate
//       INTEGER 0x42                <-- serialNumber
//       SEQUENCE { OID(sha256RSA) } <-- inner signature algo
//       SEQUENCE {}                 <-- issuer (empty Name)
//       SEQUENCE {                  <-- validity
//         UTCTime "0",              <-- notBefore (placeholder)
//         UTCTime "0"               <-- notAfter
//       },
//       SEQUENCE {}                 <-- subject (empty Name)
//       SEQUENCE {                  <-- SPKI
//         SEQUENCE { OID(rsaEnc), NULL }
//         BIT STRING (unused=0) {
//           SEQUENCE {
//             INTEGER modulus = 0x C0FFEE...01 (small but >256 bytes worth not needed)
//             INTEGER exponent = 0x010001 (65537)
//           }
//         }
//       }
//     },
//     SEQUENCE { OID(sha256RSA) },  <-- outer signatureAlgorithm
//     BIT STRING (unused=0) { 0x42 0x42 ... } <-- signature
//   }
//
// The point is to round-trip the parser, not to produce a
// cryptographically valid cert. The version tag is omitted on
// purpose to verify the parser's "first child is INTEGER" v1
// path also works.
// ---------------------------------------------------------------------------

namespace
{

// Helpers to emit DER into a stack buffer at *cur. Each
// returns false on overflow so the test fails loudly instead
// of running off the end.
struct Emitter
{
    u8* buf;
    u32 cap;
    u32 cur;
};

bool EmitByte(Emitter& e, u8 b)
{
    if (e.cur >= e.cap)
        return false;
    e.buf[e.cur++] = b;
    return true;
}

bool EmitBytes(Emitter& e, const u8* src, u32 n)
{
    if (n > e.cap - e.cur)
        return false;
    for (u32 i = 0; i < n; ++i)
        e.buf[e.cur + i] = src[i];
    e.cur += n;
    return true;
}

bool EmitTlvShort(Emitter& e, u8 tag, const u8* val, u32 len)
{
    // Use short form (< 128 bytes) for the self-test fixtures.
    if (len >= 128)
        return false;
    return EmitByte(e, tag) && EmitByte(e, static_cast<u8>(len)) && EmitBytes(e, val, len);
}

bool EmitTlvLong(Emitter& e, u8 tag, const u8* val, u32 len)
{
    // Force long-form (1-byte length count) when len >= 128.
    if (!EmitByte(e, tag))
        return false;
    if (len < 128)
        return EmitByte(e, static_cast<u8>(len)) && EmitBytes(e, val, len);
    if (len <= 0xFF)
        return EmitByte(e, 0x81) && EmitByte(e, static_cast<u8>(len)) && EmitBytes(e, val, len);
    return EmitByte(e, 0x82) && EmitByte(e, static_cast<u8>((len >> 8) & 0xFF)) &&
           EmitByte(e, static_cast<u8>(len & 0xFF)) && EmitBytes(e, val, len);
}

} // namespace

void X509SelfTest()
{
    using arch::SerialWrite;

    // Step 1: build the RSA SPKI value bytes.
    // BIT STRING content = SEQUENCE { INTEGER mod, INTEGER exp }.
    // We use a 4-byte modulus (0x0100000001) so it has the
    // high-bit-set disambiguation prefix, plus the canonical
    // 3-byte exponent 0x010001 (65537).
    u8 rsa_seq_buf[64];
    Emitter rsa_seq{rsa_seq_buf, sizeof(rsa_seq_buf), 0};
    // INTEGER 0x00 01 00 00 00 01 (forced leading zero because
    // the next byte is 0x01 which has bit 7 clear — DER would
    // omit it. Use a high-bit value so the disambiguation is
    // exercised). Pick modulus 0xC1 0x00 0x00 0x01 — top byte has
    // bit 7 set, so DER must prepend 0x00.
    const u8 mod_be[] = {0xC1, 0x00, 0x00, 0x01};
    const u8 mod_int_val[] = {0x00, 0xC1, 0x00, 0x00, 0x01}; // 5 bytes incl leading zero
    if (!EmitTlvShort(rsa_seq, asn1::kTagInteger, mod_int_val, sizeof(mod_int_val)))
    {
        SerialWrite("[x509] FAIL build-mod\n");
        return;
    }
    const u8 exp_int_val[] = {0x01, 0x00, 0x01};
    if (!EmitTlvShort(rsa_seq, asn1::kTagInteger, exp_int_val, sizeof(exp_int_val)))
    {
        SerialWrite("[x509] FAIL build-exp\n");
        return;
    }
    u8 rsa_seq_wrapped[64];
    Emitter rsa_outer{rsa_seq_wrapped, sizeof(rsa_seq_wrapped), 0};
    if (!EmitTlvShort(rsa_outer, asn1::kTagSequence, rsa_seq.buf, rsa_seq.cur))
    {
        SerialWrite("[x509] FAIL build-rsa-seq\n");
        return;
    }
    // BIT STRING for SPKI: 0x00 unused-bits byte + the SEQUENCE.
    u8 spki_bitstr_val[64];
    Emitter sbv{spki_bitstr_val, sizeof(spki_bitstr_val), 0};
    if (!EmitByte(sbv, 0x00) || !EmitBytes(sbv, rsa_outer.buf, rsa_outer.cur))
    {
        SerialWrite("[x509] FAIL build-bitstr-val\n");
        return;
    }
    // SPKI SEQUENCE { SEQUENCE { OID(rsaEnc), NULL }, BIT STRING }.
    u8 algo_id_buf[32];
    Emitter algo{algo_id_buf, sizeof(algo_id_buf), 0};
    if (!EmitTlvShort(algo, asn1::kTagOid, kOidRsaEncryption, sizeof(kOidRsaEncryption)))
    {
        SerialWrite("[x509] FAIL build-oid\n");
        return;
    }
    if (!EmitTlvShort(algo, asn1::kTagNull, nullptr, 0))
    {
        SerialWrite("[x509] FAIL build-null\n");
        return;
    }
    u8 spki_buf[128];
    Emitter spki{spki_buf, sizeof(spki_buf), 0};
    if (!EmitTlvShort(spki, asn1::kTagSequence, algo.buf, algo.cur))
    {
        SerialWrite("[x509] FAIL build-spki-algo\n");
        return;
    }
    if (!EmitTlvShort(spki, asn1::kTagBitString, sbv.buf, sbv.cur))
    {
        SerialWrite("[x509] FAIL build-spki-bs\n");
        return;
    }
    // Wrap SPKI in its outer SEQUENCE.
    u8 spki_wrapped[160];
    Emitter spki_wrap{spki_wrapped, sizeof(spki_wrapped), 0};
    if (!EmitTlvShort(spki_wrap, asn1::kTagSequence, spki.buf, spki.cur))
    {
        SerialWrite("[x509] FAIL build-spki-outer\n");
        return;
    }

    // Step 2: build TBSCertificate.
    u8 tbs_buf[256];
    Emitter tbs{tbs_buf, sizeof(tbs_buf), 0};
    const u8 serial_val[] = {0x42};
    if (!EmitTlvShort(tbs, asn1::kTagInteger, serial_val, sizeof(serial_val)))
        goto fail_tbs;
    // inner signature algo (SEQUENCE { OID(sha256RSA), NULL })
    {
        u8 inner_algo_buf[32];
        Emitter ia{inner_algo_buf, sizeof(inner_algo_buf), 0};
        if (!EmitTlvShort(ia, asn1::kTagOid, kOidSha256WithRsa, sizeof(kOidSha256WithRsa)))
            goto fail_tbs;
        if (!EmitTlvShort(ia, asn1::kTagNull, nullptr, 0))
            goto fail_tbs;
        if (!EmitTlvShort(tbs, asn1::kTagSequence, ia.buf, ia.cur))
            goto fail_tbs;
    }
    // issuer Name (empty SEQUENCE)
    if (!EmitTlvShort(tbs, asn1::kTagSequence, nullptr, 0))
        goto fail_tbs;
    // validity SEQUENCE { UTCTime, UTCTime }
    {
        u8 val_buf[64];
        Emitter v{val_buf, sizeof(val_buf), 0};
        const u8 nb[] = "260101000000Z";
        const u8 na[] = "270101000000Z";
        if (!EmitTlvShort(v, asn1::kTagUtcTime, nb, sizeof(nb) - 1))
            goto fail_tbs;
        if (!EmitTlvShort(v, asn1::kTagUtcTime, na, sizeof(na) - 1))
            goto fail_tbs;
        if (!EmitTlvShort(tbs, asn1::kTagSequence, v.buf, v.cur))
            goto fail_tbs;
    }
    // subject Name (empty SEQUENCE)
    if (!EmitTlvShort(tbs, asn1::kTagSequence, nullptr, 0))
        goto fail_tbs;
    // SPKI — copy what we built
    if (!EmitBytes(tbs, spki_wrap.buf, spki_wrap.cur))
        goto fail_tbs;

    // Step 3: wrap TBS in a SEQUENCE, append outer
    // signatureAlgorithm + signature BIT STRING.
    {
        u8 cert_buf[512];
        Emitter cert{cert_buf, sizeof(cert_buf), 0};
        if (!EmitTlvLong(cert, asn1::kTagSequence, tbs.buf, tbs.cur))
        {
            SerialWrite("[x509] FAIL wrap-tbs\n");
            return;
        }
        {
            u8 outer_algo_buf[32];
            Emitter oa{outer_algo_buf, sizeof(outer_algo_buf), 0};
            if (!EmitTlvShort(oa, asn1::kTagOid, kOidSha256WithRsa, sizeof(kOidSha256WithRsa)))
            {
                SerialWrite("[x509] FAIL outer-algo\n");
                return;
            }
            if (!EmitTlvShort(oa, asn1::kTagNull, nullptr, 0))
            {
                SerialWrite("[x509] FAIL outer-algo-null\n");
                return;
            }
            if (!EmitTlvShort(cert, asn1::kTagSequence, oa.buf, oa.cur))
            {
                SerialWrite("[x509] FAIL outer-algo-seq\n");
                return;
            }
        }
        const u8 sig_bs_val[] = {0x00, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42}; // unused=0, then 8 bytes
        if (!EmitTlvShort(cert, asn1::kTagBitString, sig_bs_val, sizeof(sig_bs_val)))
        {
            SerialWrite("[x509] FAIL sig-bs\n");
            return;
        }

        // Wrap the whole thing in the outer Certificate SEQUENCE.
        u8 outer_buf[768];
        Emitter outer{outer_buf, sizeof(outer_buf), 0};
        if (!EmitTlvLong(outer, asn1::kTagSequence, cert.buf, cert.cur))
        {
            SerialWrite("[x509] FAIL outer-cert\n");
            return;
        }

        // Step 4: parse it back.
        Certificate parsed{};
        Status rc = Parse(outer.buf, outer.cur, &parsed);
        if (rc != Status::Ok)
        {
            SerialWrite("[x509] FAIL parse status=");
            SerialWrite(StatusName(rc));
            SerialWrite("\n");
            return;
        }
        if (parsed.sig_algo != SignatureAlgo::Sha256WithRsa)
        {
            SerialWrite("[x509] FAIL sig-algo\n");
            return;
        }
        if (parsed.signature_len != 8)
        {
            SerialWrite("[x509] FAIL sig-len\n");
            return;
        }
        if (!parsed.subject_rsa_present)
        {
            SerialWrite("[x509] FAIL subject-rsa-missing\n");
            return;
        }
        // Modulus bytes round-trip: should be {0xC1,0,0,0x01}
        u8 mod_check[8] = {0};
        const u32 mod_n = BigIntToBytesBE(parsed.subject_rsa.n, mod_check, sizeof(mod_check));
        // The BigInt is fixed-width; the actual modulus bytes
        // are the trailing 4 of the 8-byte output. parsed.subject_rsa.n_bytes
        // is `mod_bytes` passed to RsaPublicKeyFromBE = 4.
        if (parsed.subject_rsa.n_bytes != 4 || mod_n != sizeof(mod_check))
        {
            SerialWrite("[x509] FAIL mod-bytes-len\n");
            return;
        }
        for (u32 i = 0; i < 4; ++i)
        {
            if (mod_check[4 + i] != mod_be[i])
            {
                SerialWrite("[x509] FAIL mod-bytes-mismatch\n");
                return;
            }
        }
        if (parsed.validity_not_before_len != 13 || parsed.validity_not_after_len != 13)
        {
            SerialWrite("[x509] FAIL validity-len\n");
            return;
        }
        SerialWrite("[x509] PASS (parse + sig-algo + rsa-spki + validity)\n");
        return;
    }

fail_tbs:
    SerialWrite("[x509] FAIL build-tbs\n");
}

} // namespace duetos::crypto::x509
