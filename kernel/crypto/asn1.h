#pragma once

#include "util/types.h"

/*
 * DuetOS — ASN.1 DER reader (Distinguished Encoding Rules).
 *
 * Parses the minimal subset of ASN.1 needed for X.509 certificate
 * walks + PKCS#1 RSA blobs:
 *   - Universal-class primitive types: INTEGER, OCTET STRING,
 *     BIT STRING, NULL, OBJECT IDENTIFIER, PrintableString,
 *     UTF8String, UTCTime, GeneralizedTime.
 *   - Universal-class constructed types: SEQUENCE, SET.
 *   - Context-specific tags (used by EXPLICIT extensions in
 *     X.509 v3 cert TBSCertificate.extensions) — reported by
 *     the raw tag byte so callers can match the specific
 *     [0], [3], etc. extensions they care about.
 *
 * Out of scope (deliberate):
 *   - BER (indefinite-length / constructed strings) — DER is a
 *     stricter subset; X.509 certs are always DER-encoded.
 *   - Multi-byte tags (tag-number 31 and above). Every X.509
 *     v3 tag we touch fits in one byte.
 *   - Per-type encoding rules (e.g. INTEGER's minimal
 *     two's-complement representation). The reader returns the
 *     raw value bytes; the caller (BigInt, OID matcher) does
 *     the higher-level decode.
 *
 * No allocation. Everything is a slice into the caller's input
 * buffer. Caller owns the bytes for the lifetime of every
 * derived `Asn1Element`.
 */

namespace duetos::crypto::asn1
{

// Universal class tags we recognise. Class bits + P/C bit
// combined into the literal tag byte you see in a DER stream:
//   0x02 INTEGER (primitive, universal, tag 2)
//   0x30 SEQUENCE (constructed, universal, tag 16)
//   etc.
inline constexpr u8 kTagInteger = 0x02;
inline constexpr u8 kTagBitString = 0x03;
inline constexpr u8 kTagOctetString = 0x04;
inline constexpr u8 kTagNull = 0x05;
inline constexpr u8 kTagOid = 0x06;
inline constexpr u8 kTagUtf8String = 0x0C;
inline constexpr u8 kTagPrintableString = 0x13;
inline constexpr u8 kTagIa5String = 0x16;
inline constexpr u8 kTagUtcTime = 0x17;
inline constexpr u8 kTagGeneralizedTime = 0x18;
inline constexpr u8 kTagSequence = 0x30;
inline constexpr u8 kTagSet = 0x31;

enum class Status : u8
{
    Ok = 0,
    BufferTooShort,   // input ran out mid-header / mid-value
    BadLengthForm,    // long-form length with too many length bytes
    LengthOverflow,   // length doesn't fit in u32
    TagMismatch,      // ReadTag asked for X, found Y
    IntegerMalformed, // value bytes are not a valid DER INTEGER
    OidMalformed,     // OID bytes break the base-128 rules
};

const char* StatusName(Status s);

/// One parsed TLV (tag-length-value). `value` points into the
/// caller's input buffer; `len` is the number of value bytes.
/// `header_len` is the byte count of tag+length so callers can
/// re-slice the next sibling: `next = elem.value + elem.len`.
struct Element
{
    u8 tag;
    u32 len;
    u32 header_len;
    const u8* value;
};

/// Parse one TLV starting at `buf` (limit `cap` bytes). Writes
/// the parsed shape into `out`. Returns Ok on success and
/// updates `out->value` / `out->len` to slice into the input.
Status Read(const u8* buf, u32 cap, Element* out);

/// Same as `Read`, but also requires the parsed tag to equal
/// `expected`. Returns `TagMismatch` if not.
Status ReadExpect(const u8* buf, u32 cap, u8 expected, Element* out);

/// Walk a SEQUENCE's children in declaration order. The caller
/// supplies a callback that gets one `Element` per child;
/// returning false from the callback stops the walk early.
/// `ctx` is forwarded. Returns Ok on a fully-consumed sequence,
/// `BufferTooShort` if a child's TLV overruns the parent.
using SequenceVisitor = bool (*)(const Element& child, void* ctx);
Status ForEachInSequence(const Element& seq, SequenceVisitor visit, void* ctx);

/// Decode an INTEGER's value bytes as a big-endian unsigned
/// integer into a caller buffer. DER encodes signed integers
/// in two's-complement minimal form; an unsigned RSA modulus
/// or signature is always non-negative, but DER may prefix a
/// 0x00 byte to disambiguate from a negative value. This
/// helper strips that leading 0 when present. Returns the
/// number of bytes written.
u32 IntegerToBytesBE(const Element& integer, u8* dst, u32 cap);

/// Compare an OID's value bytes to a known OID pattern (in
/// DER body form — the first two arcs are still packed). Returns
/// true on exact match.
bool OidEquals(const Element& oid, const u8* pattern, u32 pattern_len);

// ---- self-test --------------------------------------------------

/// Round-trips:
///   - SEQUENCE { INTEGER 0x1234, OCTET STRING "abc" } parse.
///   - INTEGER value extraction with and without leading-zero
///     disambiguation.
///   - OID equality against the rsaEncryption OID
///     (1.2.840.113549.1.1.1 = 0x2a 0x86 0x48 ... 0x01 0x01 0x01).
/// Emits `[asn1] PASS` on serial.
void Asn1SelfTest();

} // namespace duetos::crypto::asn1
