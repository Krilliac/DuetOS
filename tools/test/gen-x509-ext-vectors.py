#!/usr/bin/env python3
"""Generate the X.509 extension-policy test vectors for the x509_verify
self-test.

Why this exists
---------------
kernel/net/x509_verify.cpp decides, from a certificate's v3 extension
block, whether that certificate may SIGN another certificate. Getting
that wrong is a total defeat of the HTTPS trust decision, and the
dangerous inputs are all *shapes* rather than *values*: a duplicate
basicConstraints whose first copy is malformed, an extnValue with
trailing bytes, a truncated inner SEQUENCE, a critical extension the
verifier does not implement.

Those shapes need no signing key — they live entirely inside the
`Extensions ::= SEQUENCE OF Extension` blob. So instead of minting a
certificate per case, this script emits the extension blobs directly,
together with the verdict the verifier must reach for each. The
self-test feeds them to DecodeExtensionSeq() and asserts the verdict.

    tools/test/gen-x509-ext-vectors.py > kernel/net/x509_ext_vectors.h
    clang-format -i kernel/net/x509_ext_vectors.h

Self-checking
-------------
Every vector's expectation is re-derived here by the independent mirror
decoder in tools/test/x509-embedded-extensions.py before it is emitted.
If a vector's bytes and its stated verdict disagree, this script fails
with a non-zero exit instead of writing a header that would encode a
wrong expectation into the test.
"""

import importlib.util
import sys
from pathlib import Path

TOOLS = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location(
    "x509_embedded_extensions", TOOLS / "x509-embedded-extensions.py")
mirror = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mirror)


# --- DER builders -----------------------------------------------------------
def tlv(tag, body):
    """One TLV with a MINIMAL DER length (short form below 128)."""
    n = len(body)
    if n < 128:
        return bytes([tag, n]) + body
    width = (n.bit_length() + 7) // 8
    return bytes([tag, 0x80 | width]) + n.to_bytes(width, "big") + body


def seq(*parts):
    return tlv(0x30, b"".join(parts))


def octets(body):
    return tlv(0x04, body)


def octets_longform(body):
    """An OCTET STRING whose length uses the long form when the short form
    would do — legal BER, forbidden by DER (X.690 10.1)."""
    assert len(body) < 128
    return bytes([0x04, 0x81, len(body)]) + body


def oid(*body):
    return tlv(0x06, bytes(body))


BOOL_TRUE = tlv(0x01, b"\xff")

OID_BC = oid(0x55, 0x1D, 0x13)   # 2.5.29.19 basicConstraints
OID_KU = oid(0x55, 0x1D, 0x0F)   # 2.5.29.15 keyUsage
OID_SAN = oid(0x55, 0x1D, 0x11)  # 2.5.29.17 subjectAltName
OID_NC = oid(0x55, 0x1D, 0x1E)   # 2.5.29.30 nameConstraints — recognised by
#                                  name only; the verifier does NOT implement
#                                  it, so critical => reject
OID_SKI = oid(0x55, 0x1D, 0x0E)  # 2.5.29.14 subjectKeyIdentifier — unknown to
#                                  the verifier and always non-critical
OID_AKI = oid(0x55, 0x1D, 0x23)  # 2.5.29.35 authorityKeyIdentifier
# 2.5.29.19 with the final arc spelled `80 13` instead of `13`: the same
# OID, non-canonically encoded. Must be refused, or one extension could
# wear two byte strings and slip past a bytewise duplicate check.
OID_BC_NONMINIMAL = oid(0x55, 0x1D, 0x80, 0x13)

# extnValue payloads: an OCTET STRING wrapping exactly one inner element.
BC_CA_TRUE = octets(seq(BOOL_TRUE))
BC_CA_TRUE_PATH0 = octets(seq(BOOL_TRUE, tlv(0x02, b"\x00")))
BC_EMPTY = octets(seq())                                    # cA DEFAULT FALSE
BC_BAD_TAG = octets(tlv(0x05, b""))                         # NULL, not SEQUENCE
BC_TRAILING = octets(seq(BOOL_TRUE) + tlv(0x05, b""))       # SEQUENCE + NULL
BC_TRUNCATED = octets(b"\x30\x05")                          # claims 5, has 0
BC_BER_BOOL = octets(seq(tlv(0x01, b"\x01")))               # BER TRUE, not 0xFF
BC_NONMINIMAL = octets(seq(BOOL_TRUE, tlv(0x02, b"\x00\x05")))

KU_CERT_SIGN = octets(tlv(0x03, b"\x02\x04"))     # unused=2, keyCertSign set
KU_DIGSIG_ONLY = octets(tlv(0x03, b"\x07\x80"))   # unused=7, digitalSignature
KU_TRAILING = octets(tlv(0x03, b"\x02\x04") + tlv(0x05, b""))
KU_BAD_UNUSED = octets(tlv(0x03, b"\x09\x04"))    # unused-bit count 9 > 7
# KeyUsage is a NAMED BIT STRING: X.690 11.2.2 forbids encoding trailing
# zero bits, so keyCertSign has exactly one spelling (02 04). These two
# name the same bit non-canonically and must be refused.
KU_NONMINIMAL_UNUSED = octets(tlv(0x03, b"\x00\x04"))       # unused=0, tz=2
KU_TRAILING_ZERO_OCTET = octets(tlv(0x03, b"\x00\x04\x00"))  # final octet 0x00
SKI_VALUE = octets(tlv(0x04, b"\xaa\xbb\xcc\xdd"))
SAN_ONE_DNS = octets(seq(tlv(0x82, b"a.duetos.local")))
# A SAN that is PRESENT but names no DNS host. Must still suppress the CN
# fallback — the extension's presence is the signal, not its dNSName count.
SAN_NO_DNS = octets(seq(tlv(0x81, b"ops@duetos.local")))
SAN_BAD_TAG = octets(seq(tlv(0x89, b"\x01\x02")))     # [9] — outside the CHOICE
SAN_EMPTY_DNS = octets(seq(tlv(0x82, b"")))           # zero-length dNSName
SAN_BAD_IP = octets(seq(tlv(0x87, b"\x0a\x00\x01")))  # iPAddress, 3 bytes
SAN_NON_IA5_DNS = octets(seq(tlv(0x82, b"caf\xe9.local")))   # 0xE9 > 0x7F
SAN_NON_IA5_URI = octets(seq(tlv(0x86, b"https://\xff/")))   # 0xFF > 0x7F
SAN_EMPTY_RFC822 = octets(seq(tlv(0x81, b"")))               # empty rfc822Name
SAN_EMPTY_URI = octets(seq(tlv(0x86, b"")))                  # empty URI
SAN_BAD_REGID = octets(seq(tlv(0x88, b"\x55\x1d\x80\x13")))  # non-minimal arc
SAN_EMPTY_REGID = octets(seq(tlv(0x88, b"")))                # empty OID
SAN_DIRECTORY_NAME = octets(seq(tlv(0xA4, seq())))    # [4] structured, unvalidated
SAN_OTHER_NAME = octets(seq(tlv(0xA0, seq())))        # [0] structured, unvalidated
BC_EXPLICIT_FALSE = octets(seq(tlv(0x01, b"\x00")))   # cA DEFAULT written out


def ext(oid_bytes, value, critical=False):
    parts = [oid_bytes]
    if critical:
        parts.append(BOOL_TRUE)
    parts.append(value)
    return seq(*parts)


# name, bytes, accept, issuer@0, issuer@1, comment
VECTORS = [
    ("kExtNormalCa",
     seq(ext(OID_BC, BC_CA_TRUE, True), ext(OID_KU, KU_CERT_SIGN, True),
         ext(OID_SKI, SKI_VALUE)),
     True, True, True,
     "the ordinary CA shape: cA TRUE + keyCertSign, no pathLen"),
    ("kExtCaPathLen0",
     seq(ext(OID_BC, BC_CA_TRUE_PATH0, True), ext(OID_KU, KU_CERT_SIGN, True)),
     True, True, False,
     "pathLenConstraint 0 -> may issue the leaf, may not anchor deeper"),
    ("kExtLeafNotCa",
     seq(ext(OID_BC, BC_EMPTY, True), ext(OID_KU, KU_DIGSIG_ONLY, True),
         ext(OID_SAN, SAN_ONE_DNS)),
     True, False, False,
     "end-entity shape: empty BasicConstraints == cA FALSE"),
    ("kExtCaNoKeyCertSign",
     seq(ext(OID_BC, BC_CA_TRUE, True), ext(OID_KU, KU_DIGSIG_ONLY, True)),
     True, False, False,
     "cA TRUE but keyUsage omits keyCertSign -> not an issuer"),
    ("kExtUnknownNonCritical",
     seq(ext(OID_SKI, SKI_VALUE), ext(OID_BC, BC_CA_TRUE, True),
         ext(OID_KU, KU_CERT_SIGN, True)),
     True, True, True,
     "an unknown NON-critical extension is ignored, not fatal"),
    ("kExtUnknownCritical",
     seq(ext(OID_BC, BC_CA_TRUE, True), ext(OID_KU, KU_CERT_SIGN, True),
         ext(OID_NC, octets(seq()), True)),
     False, False, False,
     "RFC 5280 6.1.4(k): unrecognised CRITICAL extension -> reject"),
    ("kExtDupBcMalformedFirst",
     seq(ext(OID_BC, BC_BAD_TAG, True), ext(OID_BC, BC_CA_TRUE, True),
         ext(OID_KU, KU_CERT_SIGN, True)),
     False, False, False,
     "duplicate basicConstraints, FIRST copy malformed -> reject, and the"
     " second copy must not be mistaken for a first occurrence"),
    ("kExtDupBcValidFirst",
     seq(ext(OID_BC, BC_CA_TRUE, True), ext(OID_BC, BC_BAD_TAG, True),
         ext(OID_KU, KU_CERT_SIGN, True)),
     False, False, False,
     "duplicate basicConstraints, first copy valid -> still reject"),
    ("kExtDupKuMalformedFirst",
     seq(ext(OID_BC, BC_CA_TRUE, True), ext(OID_KU, KU_BAD_UNUSED, True),
         ext(OID_KU, KU_CERT_SIGN, True)),
     False, False, False,
     "same rule on keyUsage: malformed first copy, valid second -> reject"),
    ("kExtBcTrailingBytes",
     seq(ext(OID_BC, BC_TRAILING, True), ext(OID_KU, KU_CERT_SIGN, True)),
     False, False, False,
     "trailing bytes after the BasicConstraints SEQUENCE inside extnValue"),
    ("kExtKuTrailingBytes",
     seq(ext(OID_BC, BC_CA_TRUE, True), ext(OID_KU, KU_TRAILING, True)),
     False, False, False,
     "trailing bytes after the keyUsage BIT STRING inside extnValue"),
    ("kExtTrailingAfterExtnValue",
     seq(seq(OID_BC, BOOL_TRUE, BC_CA_TRUE, tlv(0x05, b"")),
         ext(OID_KU, KU_CERT_SIGN, True)),
     False, False, False,
     "a fourth field after extnValue in the Extension SEQUENCE"),
    ("kExtBcTruncated",
     seq(ext(OID_BC, BC_TRUNCATED, True), ext(OID_KU, KU_CERT_SIGN, True)),
     False, False, False,
     "BasicConstraints SEQUENCE length runs past the end of extnValue"),
    ("kExtBcBerBoolean",
     seq(ext(OID_BC, BC_BER_BOOL, True), ext(OID_KU, KU_CERT_SIGN, True)),
     False, False, False,
     "cA encoded BER-style as 0x01; DER requires 0xFF for TRUE"),
    ("kExtBcNonMinimalPathLen",
     seq(ext(OID_BC, BC_NONMINIMAL, True), ext(OID_KU, KU_CERT_SIGN, True)),
     False, False, False,
     "pathLenConstraint INTEGER carries a redundant leading 0x00"),
    ("kExtDupUnknownNonCritical",
     seq(ext(OID_BC, BC_CA_TRUE, True), ext(OID_KU, KU_CERT_SIGN, True),
         ext(OID_SKI, SKI_VALUE), ext(OID_SKI, SKI_VALUE)),
     False, False, False,
     "a duplicate UNKNOWN non-critical extnID is still a duplicate"),
    ("kExtNonMinimalLength",
     seq(ext(OID_BC, octets_longform(seq(BOOL_TRUE)), True),
         ext(OID_KU, KU_CERT_SIGN, True)),
     False, False, False,
     "a 3-byte extnValue spelled with a long-form length (0x81 0x03)"),
    ("kExtNonMinimalOidArc",
     seq(ext(OID_BC_NONMINIMAL, BC_CA_TRUE, True),
         ext(OID_KU, KU_CERT_SIGN, True)),
     False, False, False,
     "extnID 2.5.29.19 with a non-minimal final arc (0x80 0x13)"),
    ("kExtSanPresentNoDns",
     seq(ext(OID_BC, BC_EMPTY, True), ext(OID_SAN, SAN_NO_DNS)),
     True, False, False,
     "SAN present but naming no DNS host — accepted, and it must still"
     " suppress the CN fallback (see SanSuppressionChecks)"),
    ("kExtSanWithDns",
     seq(ext(OID_BC, BC_EMPTY, True), ext(OID_SAN, SAN_ONE_DNS)),
     True, False, False,
     "the ordinary leaf SAN, one dNSName — the positive control for"
     " SanSuppressionChecks"),
    ("kExtSanBadGeneralNameTag",
     seq(ext(OID_BC, BC_EMPTY, True), ext(OID_SAN, SAN_BAD_TAG)),
     False, False, False,
     "a GeneralName tagged [9], outside the CHOICE"),
    ("kExtSanEmptyDnsName",
     seq(ext(OID_BC, BC_EMPTY, True), ext(OID_SAN, SAN_EMPTY_DNS)),
     False, False, False,
     "a zero-length dNSName matches nothing and is malformed"),
    ("kExtSanBadIpAddress",
     seq(ext(OID_BC, BC_EMPTY, True), ext(OID_SAN, SAN_BAD_IP)),
     False, False, False,
     "iPAddress must be exactly 4 or 16 octets"),
    ("kExtSanNonIa5DnsName",
     seq(ext(OID_BC, BC_EMPTY, True), ext(OID_SAN, SAN_NON_IA5_DNS)),
     False, False, False,
     "dNSName is IMPLICIT IA5String — a byte above 0x7F is some other"
     " encoding smuggled in under an IA5 tag"),
    ("kExtSanNonIa5Uri",
     seq(ext(OID_BC, BC_EMPTY, True), ext(OID_SAN, SAN_NON_IA5_URI)),
     False, False, False,
     "same rule on uniformResourceIdentifier"),
    ("kExtSanEmptyRfc822Name",
     seq(ext(OID_BC, BC_EMPTY, True), ext(OID_SAN, SAN_EMPTY_RFC822)),
     False, False, False,
     "an empty rfc822Name names nothing"),
    ("kExtSanEmptyUri",
     seq(ext(OID_BC, BC_EMPTY, True), ext(OID_SAN, SAN_EMPTY_URI)),
     False, False, False,
     "an empty URI names nothing"),
    ("kExtSanNonCanonicalRegisteredId",
     seq(ext(OID_BC, BC_EMPTY, True), ext(OID_SAN, SAN_BAD_REGID)),
     False, False, False,
     "registeredID carries OID content under an IMPLICIT [8] tag; it"
     " must still be canonical"),
    ("kExtSanEmptyRegisteredId",
     seq(ext(OID_BC, BC_EMPTY, True), ext(OID_SAN, SAN_EMPTY_REGID)),
     False, False, False,
     "an empty registeredID is not an OID"),
    ("kExtSanDirectoryName",
     seq(ext(OID_BC, BC_EMPTY, True), ext(OID_SAN, SAN_DIRECTORY_NAME)),
     False, False, False,
     "directoryName [4] carries a nested schema this layer does not"
     " implement — refused rather than skipped unvalidated"),
    ("kExtSanOtherName",
     seq(ext(OID_BC, BC_EMPTY, True), ext(OID_SAN, SAN_OTHER_NAME)),
     False, False, False,
     "otherName [0] — same rule"),
    ("kExtKuNonMinimalUnused",
     seq(ext(OID_BC, BC_CA_TRUE, True), ext(OID_KU, KU_NONMINIMAL_UNUSED, True)),
     False, False, False,
     "keyUsage 03 02 00 04: names keyCertSign, but a NAMED BIT STRING"
     " must not encode the 2 trailing zero bits (canonical is 02 04)"),
    ("kExtKuTrailingZeroOctet",
     seq(ext(OID_BC, BC_CA_TRUE, True), ext(OID_KU, KU_TRAILING_ZERO_OCTET, True)),
     False, False, False,
     "keyUsage 03 03 00 04 00: a wholly-zero trailing octet that should"
     " have been dropped — a third spelling of keyCertSign"),
    ("kExtBcExplicitCaFalse",
     seq(ext(OID_BC, BC_EXPLICIT_FALSE, True), ext(OID_KU, KU_CERT_SIGN, True)),
     False, False, False,
     "cA DEFAULT FALSE written out longhand (X.690 11.5 says omit it)"),
    ("kExtCriticalFalseExplicit",
     seq(seq(OID_BC, tlv(0x01, b"\x00"), BC_CA_TRUE),
         ext(OID_KU, KU_CERT_SIGN, True)),
     False, False, False,
     "critical DEFAULT FALSE written out longhand"),
    ("kExtEmptyExtensions", seq(),
     False, False, False,
     "Extensions ::= SEQUENCE SIZE (1..MAX) — an empty one is a second"
     " spelling of 'no [3] block at all'"),
]

# TBS-level vectors: these exercise ParseExtensionsFromTbs(), which has to
# decide how many [3] blocks a TBSCertificate may carry and where. Each is
# a whole (synthetic, unsigned) TBSCertificate — the prefix fields are
# empty placeholders, since only the walk to [3] is under test.
TBS_BODY = (
    tlv(0x02, b"\x01"),             # serialNumber
    seq(),                          # signature AlgorithmIdentifier
    seq(),                          # issuer
    seq(),                          # validity
    seq(),                          # subject
    seq(),                          # subjectPublicKeyInfo
)
VERSION_V3 = tlv(0xA0, tlv(0x02, b"\x02"))
VERSION_V2 = tlv(0xA0, tlv(0x02, b"\x01"))
VERSION_V1_EXPLICIT = tlv(0xA0, tlv(0x02, b"\x00"))
TBS_PREFIX = (VERSION_V3,) + TBS_BODY

GOOD_EXTS = seq(ext(OID_BC, BC_CA_TRUE, True), ext(OID_KU, KU_CERT_SIGN, True))
OTHER_EXTS = seq(ext(OID_AKI, SKI_VALUE))


def tbs(*tail):
    return seq(*(TBS_PREFIX + tail))


# name, bytes, accept, issuer@0, comment
TBS_VECTORS = [
    ("kTbsOneTerminalExts", tbs(tlv(0xA3, GOOD_EXTS)), True, True,
     "the ordinary shape: exactly one [3], last field in the TBS"),
    ("kTbsNoExts", tbs(), True, False,
     "no [3] at all — legal (v1/v2), but nothing seen, so not an issuer"),
    ("kTbsSecondExtsBlock",
     tbs(tlv(0xA3, GOOD_EXTS), tlv(0xA3, OTHER_EXTS)), False, False,
     "a SECOND [3] block: stopping at the first would decode a different"
     " certificate than a parser that reads the last"),
    ("kTbsExtsNotTerminal",
     tbs(tlv(0xA3, GOOD_EXTS), seq()), False, False,
     "[3] followed by a trailing field — extensions must close the TBS"),
    ("kTbsV1WithExts",
     seq(*(TBS_BODY + (tlv(0xA3, GOOD_EXTS),))), False, False,
     "version ABSENT (v1 by DEFAULT) but carrying extensions — RFC 5280"
     " 4.1.2.9 puts extensions in v3 only"),
    ("kTbsV2WithExts",
     seq(*((VERSION_V2,) + TBS_BODY + (tlv(0xA3, GOOD_EXTS),))), False, False,
     "version v2 carrying extensions — same rule"),
    ("kTbsV1ExplicitVersion",
     seq(*((VERSION_V1_EXPLICIT,) + TBS_BODY)), False, False,
     "version v1 written out longhand; DEFAULT v1 must be omitted"),
    ("kTbsEmptyExtensions",
     tbs(tlv(0xA3, seq())), False, False,
     "a [3] block holding an empty Extensions SEQUENCE"),
    ("kTbsPrimitiveA3",
     tbs(tlv(0x83, GOOD_EXTS)), False, False,
     "a PRIMITIVE 0x83 where [3] must be constructed. Skipping it made"
     " the certificate parse as having no extensions — hence no SAN,"
     " hence the CN fallback re-enabled"),
    ("kTbsUniqueIdsInOrder",
     seq(*((VERSION_V3,) + TBS_BODY +
           (tlv(0x81, b"\x00\xaa"), tlv(0x82, b"\x00\xbb"),
            tlv(0xA3, GOOD_EXTS)))), True, True,
     "the full legal tail: issuerUniqueID, subjectUniqueID, extensions"),
    ("kTbsUniqueIdsOutOfOrder",
     seq(*((VERSION_V3,) + TBS_BODY +
           (tlv(0x82, b"\x00\xbb"), tlv(0x81, b"\x00\xaa"),
            tlv(0xA3, GOOD_EXTS)))), False, False,
     "subjectUniqueID before issuerUniqueID — out of declared order"),
    ("kTbsDuplicateIssuerUniqueId",
     seq(*((VERSION_V3,) + TBS_BODY +
           (tlv(0x81, b"\x00\xaa"), tlv(0x81, b"\x00\xcc"),
            tlv(0xA3, GOOD_EXTS)))), False, False,
     "issuerUniqueID twice"),
    ("kTbsUniqueIdInV1",
     seq(*(TBS_BODY + (tlv(0x81, b"\x00\xaa"),))), False, False,
     "issuerUniqueID in a v1 certificate — RFC 5280 4.1.2.8 needs v2/v3"),
    ("kTbsArbitraryTailField",
     seq(*((VERSION_V3,) + TBS_BODY + (tlv(0x84, b"\x01"),))), False, False,
     "a [4] field that does not exist in TBSCertificate"),
    ("kTbsConstructedUniqueId",
     seq(*((VERSION_V3,) + TBS_BODY + (tlv(0xA1, tlv(0x03, b"\x00\xaa")),))),
     False, False,
     "issuerUniqueID as constructed 0xA1; IMPLICIT tagging makes it"
     " primitive 0x81"),
    ("kTbsUniqueIdEmptyContent",
     seq(*((VERSION_V3,) + TBS_BODY +
           (tlv(0x81, b""), tlv(0xA3, GOOD_EXTS)))), False, False,
     "issuerUniqueID with NO content: a BIT STRING needs at least the"
     " unused-bit count octet"),
    ("kTbsUniqueIdUnusedTooBig",
     seq(*((VERSION_V3,) + TBS_BODY +
           (tlv(0x81, b"\x08\xaa"), tlv(0xA3, GOOD_EXTS)))), False, False,
     "issuerUniqueID unused-bit count of 8 (max is 7)"),
    ("kTbsUniqueIdNonZeroPadding",
     seq(*((VERSION_V3,) + TBS_BODY +
           (tlv(0x81, b"\x04\xaf"), tlv(0xA3, GOOD_EXTS)))), False, False,
     "issuerUniqueID whose 4 unused trailing bits are not zero (0xAF)"),
    ("kTbsUniqueIdNoDataUnusedNonZero",
     seq(*((VERSION_V3,) + TBS_BODY +
           (tlv(0x82, b"\x03"), tlv(0xA3, GOOD_EXTS)))), False, False,
     "subjectUniqueID with no data octets but a nonzero unused count"),
]


def many_extension_blob(n):
    """An Extensions blob with `n` DISTINCT extnIDs (BC + KU + fillers).

    Exercises the bounded duplicate table: the cap is 32 entries, so 32
    must be accepted and 33 refused rather than parsed with an incomplete
    duplicate check.
    """
    exts = [ext(OID_BC, BC_CA_TRUE, True), ext(OID_KU, KU_CERT_SIGN, True)]
    # 1.3.6.1.4.1.99999.i — distinct, unknown, non-critical.
    for i in range(n - 2):
        body = bytes([0x2B, 0x06, 0x01, 0x04, 0x01, 0x86, 0x8D, 0x1F, i])
        exts.append(ext(tlv(0x06, body), SKI_VALUE))
    return seq(*exts)


VECTORS.extend([
    ("kExtMaxExtensions", many_extension_blob(32), True, True, True,
     "exactly 32 distinct extensions — the duplicate table's capacity"),
    ("kExtTooManyExtensions", many_extension_blob(33), False, False, False,
     "33 distinct extensions: refused rather than deduped incompletely"),
])


def mirror_verdict(blob):
    """Independently decide accept/issuer for one Extensions blob."""
    end = len(blob)
    try:
        stag, sstart, send, nxt = mirror.read_tlv(blob, 0, end)
        if stag != 0x30 or nxt != end:
            return False, False, False
        if send == sstart:
            return False, False, False  # Extensions SIZE (1..MAX)
        seen, bc, ku = set(), None, None
        xo = sstart
        while xo < send:
            etag, estart, eend, xnxt = mirror.read_tlv(blob, xo, send)
            if etag != 0x30:
                return False, False, False
            otag, os_, oe, after_oid = mirror.read_tlv(blob, estart, eend)
            if otag != 0x06 or oe == os_:
                return False, False, False
            mirror.check_canonical_oid(blob, os_, oe)
            o = mirror.decode_oid(blob, os_, oe)
            critical, cur = False, after_oid
            if cur >= eend:
                return False, False, False
            t, cs, ce, nb = mirror.read_tlv(blob, cur, eend)
            if t == 0x01:
                # DEFAULT FALSE: present means TRUE, explicit FALSE is
                # refused (X.690 11.5), BER nonzero is refused (11.1).
                if ce - cs != 1 or blob[cs] != 0xFF:
                    return False, False, False
                critical = True
                cur = nb
                if cur >= eend:
                    return False, False, False
                t, cs, ce, nb = mirror.read_tlv(blob, cur, eend)
            if t != 0x04 or nb != eend:
                return False, False, False
            # Generic duplicate rule: every extnID, recognised or not.
            if o in seen or len(seen) >= 32:
                return False, False, False
            seen.add(o)
            if o == "2.5.29.19":
                bc = mirror.decode_basic_constraints(blob, cs, ce)
            elif o == "2.5.29.15":
                ku = mirror.decode_key_usage(blob, cs, ce)
            elif o == "2.5.29.17":
                if mirror.decode_subject_alt_name(blob, cs, ce) is None:
                    return False, False, False
            elif critical:
                return False, False, False
            xo = xnxt
        if xo != send:
            return False, False, False
    except mirror.DerError:
        return False, False, False

    def issuer(certs_below):
        if bc is None or not bc[0]:
            return False
        if ku is not None and not ku:
            return False
        if bc[1] is not None and certs_below > bc[1]:
            return False
        return True

    return True, issuer(0), issuer(1)


def mirror_tbs_verdict(blob):
    """Independently decide accept/issuer for one whole TBSCertificate."""
    end = len(blob)
    try:
        ttag, tstart, tend, nxt = mirror.read_tlv(blob, 0, end)
        if ttag != 0x30 or nxt != end:
            return False, False
        off = tstart
        tag, vs0, ve0, after = mirror.read_tlv(blob, off, tend)
        version = 1
        if tag == 0xA0:
            vt, ivs, ive, ivn = mirror.read_tlv(blob, vs0, ve0)
            if vt != 0x02 or ivn != ve0 or ive - ivs != 1 or blob[ivs] > 2:
                return False, False
            if blob[ivs] == 0:
                return False, False  # explicit DEFAULT v1
            version = blob[ivs] + 1
            off = after
        for _ in range(6):
            if off >= tend:
                return False, False
            _, _, _, off = mirror.read_tlv(blob, off, tend)
        # Legal tail: [1] issuerUniqueID, [2] subjectUniqueID (both
        # IMPLICIT, hence primitive), [3] extensions (EXPLICIT, hence
        # constructed) — in order, each at most once.
        ranks = {0x81: 1, 0x82: 2, 0xA3: 3}
        last_rank, accept, i0 = 0, True, False
        while off < tend:
            tag, vs, ve, after = mirror.read_tlv(blob, off, tend)
            rank = ranks.get(tag)
            if rank is None or rank <= last_rank:
                return False, False
            last_rank = rank
            if rank <= 2:
                if version < 2:
                    return False, False
                # IMPLICIT BIT STRING content rules still apply.
                try:
                    mirror.check_bit_string_content(blob, vs, ve)
                except mirror.DerError:
                    return False, False
            if rank == 3:
                if version != 3 or after != tend:
                    return False, False
                stag, ss, se, snxt = mirror.read_tlv(blob, vs, ve)
                if stag != 0x30 or snxt != ve:
                    return False, False
                accept, i0, _ = mirror_verdict(blob[vs:ve])
                if not accept:
                    return False, False
            off = after
        return accept, i0
    except mirror.DerError:
        return False, False


def cfmt(name, data):
    out = [f"inline constexpr u8 {name}[] = {{"]
    line = "   "
    for b in data:
        piece = f" 0x{b:02X},"
        if len(line) + len(piece) > 116:
            out.append(line)
            line = "   "
        line += piece
    if line.strip():
        out.append(line)
    out.append("};")
    return "\n".join(out)


def main():
    problems = []
    for name, blob, accept, i0, i1, _ in VECTORS:
        got = mirror_verdict(blob)
        if got != (accept, i0, i1):
            problems.append(f"{name}: stated {(accept, i0, i1)}, mirror says {got}")
    for name, blob, accept, i0, _ in TBS_VECTORS:
        got = mirror_tbs_verdict(blob)
        if got != (accept, i0):
            problems.append(f"{name}: stated {(accept, i0)}, mirror says {got}")
    if problems:
        sys.stderr.write("vector self-check FAILED:\n  " + "\n  ".join(problems) + "\n")
        return 1

    # DuetOS is LF-everywhere and UTF-8-everywhere. On Windows the default
    # stdout is CRLF + cp1252, which silently turned the em dash in the
    # banner below into a lone 0x97 — a byte that is not valid UTF-8 at
    # all, in a header the kernel compiles. Pin both.
    sys.stdout.reconfigure(encoding="utf-8", newline="\n")
    w = sys.stdout.write
    w("#pragma once\n\n")
    w("// AUTO-GENERATED by tools/test/gen-x509-ext-vectors.py — do not hand-edit.\n")
    w("//\n")
    w("// X.509 v3 extension-policy vectors for the x509_verify self-test. Each\n")
    w("// blob is a bare `Extensions ::= SEQUENCE OF Extension` — the exact\n")
    w("// element DecodeExtensionSeq() consumes — so the dangerous SHAPES\n")
    w("// (duplicate extension, trailing bytes, truncated inner SEQUENCE,\n")
    w("// unrecognised critical extension) can be tested without minting a\n")
    w("// signed certificate for each one.\n")
    w("//\n")
    w("// `accept` is what DecodeExtensionSeq() must return; `issuer_at_0` /\n")
    w("// `issuer_at_1` are what IsUsableIssuer() must return for a path\n")
    w("// carrying 0 / 1 certificates below this one. A rejected blob must\n")
    w("// never be a usable issuer, which is the property that stops a\n")
    w("// malformed-duplicate or unknown-critical certificate from being\n")
    w("// promoted to a CA.\n\n")
    w('#include "util/types.h"\n\n')
    w("namespace duetos::net::x509\n{\n\n")

    for name, blob, _, _, _, comment in VECTORS:
        w(f"// {comment}\n")
        w(cfmt(name, blob) + "\n\n")

    w("// One row per vector above. `name` is only used to label a self-test\n")
    w("// failure; the numeric code carries the row index.\n")
    w("struct ExtPolicyVector\n{\n")
    w("    const char* name;\n")
    w("    const u8* der;\n")
    w("    u32 len;\n")
    w("    bool accept;\n")
    w("    bool issuer_at_0;\n")
    w("    bool issuer_at_1;\n")
    w("};\n\n")
    w("inline constexpr ExtPolicyVector kExtPolicyVectors[] = {\n")
    for name, blob, accept, i0, i1, _ in VECTORS:
        w(f'    {{"{name}", {name}, static_cast<u32>(sizeof({name})), '
          f'{str(accept).lower()}, {str(i0).lower()}, {str(i1).lower()}}},\n')
    w("};\n\n")

    w("// Whole (synthetic, unsigned) TBSCertificates for the [3] block\n")
    w("// policy: how many extensions blocks a TBS may carry, and where.\n")
    w("// `accept` is what ParseExtensionsFromTbs() must return.\n\n")
    for name, blob, _, _, comment in TBS_VECTORS:
        w(f"// {comment}\n")
        w(cfmt(name, blob) + "\n\n")
    w("struct TbsPolicyVector\n{\n")
    w("    const char* name;\n")
    w("    const u8* der;\n")
    w("    u32 len;\n")
    w("    bool accept;\n")
    w("    bool issuer_at_0;\n")
    w("};\n\n")
    w("inline constexpr TbsPolicyVector kTbsPolicyVectors[] = {\n")
    for name, blob, accept, i0, _ in TBS_VECTORS:
        w(f'    {{"{name}", {name}, static_cast<u32>(sizeof({name})), '
          f'{str(accept).lower()}, {str(i0).lower()}}},\n')
    w("};\n\n")
    w("} // namespace duetos::net::x509\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
