// DuetOS — ASN.1 DER reader fuzz harness.
//
// asn1::Read decodes one TLV (tag + DER length form + value
// slice) out of a buffer; ForEachInSequence recurses children.
// The bytes are DER from a TLS certificate or an RSA key blob —
// attacker-controlled. The harness reads the top-level element,
// then, if it is constructed, walks it as a SEQUENCE so the
// long-form-length decode, the child-overruns-parent check, and
// the OID/INTEGER helpers all see hostile input. ASan catches
// any slice that escapes the input buffer.

#include "crypto/asn1.h"

#include <cstddef>
#include <cstdint>

namespace
{
bool VisitChild(const duetos::crypto::asn1::Element& child, void* ctx)
{
    auto* depth = static_cast<int*>(ctx);
    // INTEGER / OID helpers are the other byte-walkers worth
    // hitting; drive them on every child.
    duetos::u8 tmp[512];
    (void)duetos::crypto::asn1::IntegerToBytesBE(child, tmp, sizeof(tmp));
    static const duetos::u8 kRsaOid[] = {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01};
    (void)duetos::crypto::asn1::OidEquals(child, kRsaOid, sizeof(kRsaOid));

    // One level of recursion into nested constructed elements.
    if (*depth < 1 && (child.tag & 0x20u) != 0)
    {
        int next = *depth + 1;
        (void)duetos::crypto::asn1::ForEachInSequence(child, &VisitChild, &next);
    }
    return true;
}
} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size == 0 || size > (1u << 16))
        return 0;

    duetos::crypto::asn1::Element top{};
    if (duetos::crypto::asn1::Read(reinterpret_cast<const duetos::u8*>(data), static_cast<duetos::u32>(size), &top) !=
        duetos::crypto::asn1::Status::Ok)
        return 0;

    if ((top.tag & 0x20u) != 0)
    {
        int depth = 0;
        (void)duetos::crypto::asn1::ForEachInSequence(top, &VisitChild, &depth);
    }
    return 0;
}
