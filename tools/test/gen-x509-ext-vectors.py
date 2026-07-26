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
    assert len(body) < 128, "vectors deliberately stay in short-form length"
    return bytes([tag, len(body)]) + body


def seq(*parts):
    return tlv(0x30, b"".join(parts))


def octets(body):
    return tlv(0x04, body)


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
SKI_VALUE = octets(tlv(0x04, b"\xaa\xbb\xcc\xdd"))
SAN_ONE_DNS = octets(seq(tlv(0x82, b"a.duetos.local")))


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
]


def mirror_verdict(blob):
    """Independently decide accept/issuer for one Extensions blob."""
    end = len(blob)
    try:
        stag, sstart, send, nxt = mirror.read_tlv(blob, 0, end)
        if stag != 0x30 or nxt != end:
            return False, False, False
        seen, bc, ku = set(), None, None
        xo = sstart
        while xo < send:
            etag, estart, eend, xnxt = mirror.read_tlv(blob, xo, send)
            if etag != 0x30:
                return False, False, False
            otag, os_, oe, after_oid = mirror.read_tlv(blob, estart, eend)
            if otag != 0x06 or oe == os_:
                return False, False, False
            o = mirror.decode_oid(blob, os_, oe)
            critical, cur = False, after_oid
            if cur >= eend:
                return False, False, False
            t, cs, ce, nb = mirror.read_tlv(blob, cur, eend)
            if t == 0x01:
                if ce - cs != 1 or blob[cs] not in (0x00, 0xFF):
                    return False, False, False
                critical = blob[cs] == 0xFF
                cur = nb
                if cur >= eend:
                    return False, False, False
                t, cs, ce, nb = mirror.read_tlv(blob, cur, eend)
            if t != 0x04 or nb != eend:
                return False, False, False
            # Duplicates are rejected only for the extensions the verifier
            # decodes — matching DecodeExtensionSeq(), which does not
            # dedupe extensions nothing reads.
            if o in ("2.5.29.19", "2.5.29.15", "2.5.29.17"):
                if o in seen:
                    return False, False, False
                seen.add(o)
            if o == "2.5.29.19":
                bc = mirror.decode_basic_constraints(blob, cs, ce)
            elif o == "2.5.29.15":
                ku = mirror.decode_key_usage(blob, cs, ce)
            elif o == "2.5.29.17":
                mirror.decode_subject_alt_name(blob, cs, ce)
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
    if problems:
        sys.stderr.write("vector self-check FAILED:\n  " + "\n  ".join(problems) + "\n")
        return 1

    # DuetOS is LF-everywhere; on Windows the default stdout translation
    # would emit CRLF and git would normalise it back on every add.
    sys.stdout.reconfigure(newline="\n")
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
    w("} // namespace duetos::net::x509\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
