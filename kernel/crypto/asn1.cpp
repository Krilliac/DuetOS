#include "crypto/asn1.h"

#include "arch/x86_64/serial.h"

namespace duetos::crypto::asn1
{

const char* StatusName(Status s)
{
    switch (s)
    {
    case Status::Ok:
        return "Ok";
    case Status::BufferTooShort:
        return "BufferTooShort";
    case Status::BadLengthForm:
        return "BadLengthForm";
    case Status::LengthOverflow:
        return "LengthOverflow";
    case Status::TagMismatch:
        return "TagMismatch";
    case Status::IntegerMalformed:
        return "IntegerMalformed";
    case Status::OidMalformed:
        return "OidMalformed";
    }
    return "?";
}

Status Read(const u8* buf, u32 cap, Element* out)
{
    if (out == nullptr || buf == nullptr)
        return Status::BufferTooShort;
    *out = Element{};
    if (cap < 2)
        return Status::BufferTooShort;
    const u8 tag = buf[0];
    const u8 len0 = buf[1];
    u32 len = 0;
    u32 header = 2;
    if ((len0 & 0x80) == 0)
    {
        // Short form: length is the byte's low 7 bits.
        len = len0 & 0x7F;
    }
    else
    {
        // Long form: low 7 bits are the number of subsequent
        // length bytes (1..4 for everything we accept). 0
        // would be indefinite-length form, which DER forbids.
        const u8 nbytes = len0 & 0x7F;
        if (nbytes == 0)
            return Status::BadLengthForm;
        if (nbytes > 4)
            return Status::LengthOverflow;
        if (u32(2) + nbytes > cap)
            return Status::BufferTooShort;
        for (u8 i = 0; i < nbytes; ++i)
        {
            len = (len << 8) | buf[2 + i];
        }
        header = u32(2) + nbytes;
    }
    if (header > cap || len > cap - header)
        return Status::BufferTooShort;
    out->tag = tag;
    out->len = len;
    out->header_len = header;
    out->value = buf + header;
    return Status::Ok;
}

Status ReadExpect(const u8* buf, u32 cap, u8 expected, Element* out)
{
    Status rc = Read(buf, cap, out);
    if (rc != Status::Ok)
        return rc;
    if (out->tag != expected)
        return Status::TagMismatch;
    return Status::Ok;
}

Status ForEachInSequence(const Element& seq, SequenceVisitor visit, void* ctx)
{
    if (visit == nullptr)
        return Status::Ok;
    u32 off = 0;
    while (off < seq.len)
    {
        Element child{};
        const Status rc = Read(seq.value + off, seq.len - off, &child);
        if (rc != Status::Ok)
            return rc;
        if (!visit(child, ctx))
            return Status::Ok;
        const u32 step = child.header_len + child.len;
        if (step == 0 || step > seq.len - off)
            return Status::BufferTooShort;
        off += step;
    }
    return Status::Ok;
}

u32 IntegerToBytesBE(const Element& integer, u8* dst, u32 cap)
{
    if (integer.value == nullptr || integer.len == 0 || dst == nullptr || cap == 0)
        return 0;
    // DER signed-integer encoding: if the top bit of the most-
    // significant byte would be set and the value is non-negative,
    // a leading 0x00 byte is prepended. We strip exactly one such
    // padding byte if present so an unsigned RSA modulus / sig /
    // public exponent comes out as the natural big-endian value.
    u32 start = 0;
    u32 len = integer.len;
    if (len >= 2 && integer.value[0] == 0x00 && (integer.value[1] & 0x80) != 0)
    {
        start = 1;
        len -= 1;
    }
    if (len > cap)
        len = cap;
    for (u32 i = 0; i < len; ++i)
        dst[i] = integer.value[start + i];
    return len;
}

bool OidEquals(const Element& oid, const u8* pattern, u32 pattern_len)
{
    if (oid.tag != kTagOid)
        return false;
    if (oid.len != pattern_len)
        return false;
    for (u32 i = 0; i < pattern_len; ++i)
    {
        if (oid.value[i] != pattern[i])
            return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// Self-test
// ---------------------------------------------------------------------------

namespace
{

// A SEQUENCE { INTEGER 0x1234, OCTET STRING "abc" }.
// Encoded:
//   30 09                      SEQUENCE, len 9
//      02 02 12 34             INTEGER, 0x1234
//      04 03 61 62 63          OCTET STRING, "abc"
constexpr u8 kFixture[] = {0x30, 0x09, 0x02, 0x02, 0x12, 0x34, 0x04, 0x03, 0x61, 0x62, 0x63};

// rsaEncryption OID body: 1.2.840.113549.1.1.1 -> 9 bytes
//   2a 86 48 86 f7 0d 01 01 01
constexpr u8 kOidRsaEncryption[] = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01};

// INTEGER with the disambiguation prefix: 0x00 0xFF -> unsigned 0xFF.
constexpr u8 kIntegerPad[] = {0x02, 0x02, 0x00, 0xFF};

// INTEGER without prefix: 0x7F -> unsigned 0x7F.
constexpr u8 kIntegerPlain[] = {0x02, 0x01, 0x7F};

// OID TLV: tag 0x06 + len 0x09 + the rsaEncryption body.
constexpr u8 kOidRsaTlv[] = {0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01};

struct VisitCtx
{
    int count;
    int integer_ok;
    int octet_ok;
};

bool Visit(const Element& child, void* ctx)
{
    auto* c = static_cast<VisitCtx*>(ctx);
    ++c->count;
    if (c->count == 1)
    {
        if (child.tag == kTagInteger && child.len == 2 && child.value[0] == 0x12 && child.value[1] == 0x34)
            c->integer_ok = 1;
    }
    if (c->count == 2)
    {
        if (child.tag == kTagOctetString && child.len == 3 && child.value[0] == 'a' && child.value[1] == 'b' &&
            child.value[2] == 'c')
            c->octet_ok = 1;
    }
    return true;
}

} // namespace

void Asn1SelfTest()
{
    using arch::SerialWrite;

    // Step 1: outer SEQUENCE parses, length 9.
    Element seq{};
    if (Read(kFixture, sizeof(kFixture), &seq) != Status::Ok || seq.tag != kTagSequence || seq.len != 9)
    {
        SerialWrite("[asn1] FAIL outer-sequence\n");
        return;
    }

    // Step 2: walk the children. Expect one INTEGER (0x1234)
    // followed by one OCTET STRING "abc".
    VisitCtx vc{0, 0, 0};
    if (ForEachInSequence(seq, &Visit, &vc) != Status::Ok || vc.count != 2 || !vc.integer_ok || !vc.octet_ok)
    {
        SerialWrite("[asn1] FAIL sequence-walk\n");
        return;
    }

    // Step 3: INTEGER with leading-zero padding decodes to a
    // single byte 0xFF (unsigned interpretation).
    Element ipad{};
    if (Read(kIntegerPad, sizeof(kIntegerPad), &ipad) != Status::Ok || ipad.tag != kTagInteger)
    {
        SerialWrite("[asn1] FAIL integer-pad-parse\n");
        return;
    }
    u8 ibuf[4] = {0};
    const u32 n = IntegerToBytesBE(ipad, ibuf, sizeof(ibuf));
    if (n != 1 || ibuf[0] != 0xFF)
    {
        SerialWrite("[asn1] FAIL integer-pad-decode\n");
        return;
    }

    // Step 4: INTEGER without padding passes through unchanged.
    Element iplain{};
    if (Read(kIntegerPlain, sizeof(kIntegerPlain), &iplain) != Status::Ok || iplain.tag != kTagInteger)
    {
        SerialWrite("[asn1] FAIL integer-plain-parse\n");
        return;
    }
    const u32 m = IntegerToBytesBE(iplain, ibuf, sizeof(ibuf));
    if (m != 1 || ibuf[0] != 0x7F)
    {
        SerialWrite("[asn1] FAIL integer-plain-decode\n");
        return;
    }

    // Step 5: OID equality. Match the rsaEncryption OID against
    // its canonical body.
    Element oid{};
    if (Read(kOidRsaTlv, sizeof(kOidRsaTlv), &oid) != Status::Ok || oid.tag != kTagOid)
    {
        SerialWrite("[asn1] FAIL oid-parse\n");
        return;
    }
    if (!OidEquals(oid, kOidRsaEncryption, sizeof(kOidRsaEncryption)))
    {
        SerialWrite("[asn1] FAIL oid-match\n");
        return;
    }

    SerialWrite("[asn1] PASS (sequence + integer + oid)\n");
}

} // namespace duetos::crypto::asn1
