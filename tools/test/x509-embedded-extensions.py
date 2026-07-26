#!/usr/bin/env python3
"""
x509-embedded-extensions.py — inventory the X.509 v3 extensions of every
DER certificate embedded as a C++ byte array in a source file.

WHY THIS EXISTS
    kernel/net/x509_verify.cpp enforces RFC 5280 §6.1.4(k): a certificate
    carrying a CRITICAL extension the verifier does not recognise is
    REJECTED. That rule is only safe if every certificate we embed —
    the synthetic fixtures AND the real trust-store roots — is known not
    to carry a critical extension outside the recognised set. Adding a
    new root without checking is how you turn a hardening fix into a
    boot self-test failure (or, worse, a silently unusable anchor).

    Run this whenever you add a trust anchor or a DER fixture, and
    whenever you change the recognised-critical set in x509_verify.cpp.
    It needs no toolchain: it reads the source text and does its own
    bounded DER walk, so it is safe to run while a kernel build is in
    flight.

    The decoders below deliberately MIRROR the strict rules in
    ParseExtension / DecodeBasicConstraints / DecodeKeyUsage /
    DecodeSubjectAltName: exact-DER (one TLV that exactly fills its
    container, no trailing and no truncated bytes), duplicate extensions
    rejected, DER BOOLEAN restricted to 0x00/0xFF, minimal INTEGER. So
    the `issuer=` verdict it prints is what IsUsableIssuer will decide.
    If you change the C++ rules, change these to match — that is the
    point of the file.

USAGE
    python3 tools/test/x509-embedded-extensions.py [source.cpp ...]
    python3 tools/test/x509-embedded-extensions.py --der cert.der [more.pem ...]
    python3 tools/test/x509-embedded-extensions.py --recognised 2.5.29.19,2.5.29.15,2.5.29.17

    Default source is kernel/net/x509_verify.cpp; default recognised set
    is basicConstraints + keyUsage + subjectAltName, matching the
    extensions DecodeExtensionSeq() actually decodes.

    `--der` reads real certificates (raw DER, or PEM with BEGIN
    CERTIFICATE armour, one or more per file) instead of C++ sources.
    That is the mode to reach for when a live site fails to verify: grab
    its chain with `openssl s_client -showcerts -connect host:443` and
    run it through here to see which extension the verifier is rejecting.

EXIT STATUS
    0  every embedded certificate parsed under the strict rules and every
       critical extension in it is in the recognised set (the verifier
       will accept them all).
    1  at least one certificate would be REJECTED by the verifier — an
       unrecognised critical extension, a duplicate, a non-exact DER
       value, or a parse failure. Details on stdout.

QUICK ANALYSIS
    # just the critical extensions, deduped
    python3 tools/test/x509-embedded-extensions.py | grep CRITICAL | sort -u
    # which embedded certs are usable as issuers
    python3 tools/test/x509-embedded-extensions.py | grep -E "^(k|  issuer)"
"""

import argparse
import re
import sys
from pathlib import Path

# id-ce arcs we care to name. Anything unnamed prints as a raw dotted OID.
OID_NAMES = {
    "2.5.29.14": "subjectKeyIdentifier",
    "2.5.29.15": "keyUsage",
    "2.5.29.16": "privateKeyUsagePeriod",
    "2.5.29.17": "subjectAltName",
    "2.5.29.18": "issuerAltName",
    "2.5.29.19": "basicConstraints",
    "2.5.29.30": "nameConstraints",
    "2.5.29.31": "cRLDistributionPoints",
    "2.5.29.32": "certificatePolicies",
    "2.5.29.33": "policyMappings",
    "2.5.29.35": "authorityKeyIdentifier",
    "2.5.29.36": "policyConstraints",
    "2.5.29.37": "extKeyUsage",
    "2.5.29.54": "inhibitAnyPolicy",
    "1.3.6.1.5.5.7.1.1": "authorityInfoAccess",
    "2.16.840.1.113730.1.1": "netscapeCertType",
}

DEFAULT_RECOGNISED = ["2.5.29.19", "2.5.29.15", "2.5.29.17"]

ARRAY_RE = re.compile(
    r"constexpr\s+u8\s+(k[A-Za-z0-9_]*Der)\s*\[\s*\]\s*=\s*\{(.*?)\}\s*;",
    re.DOTALL,
)
BYTE_RE = re.compile(r"0[xX]([0-9a-fA-F]{1,2})")


class DerError(Exception):
    pass


def read_tlv(buf, off, end):
    """Strict DER TLV read. Mirrors ReadStrict().

    Returns (tag, vstart, vend, next_off).
    """
    if off + 2 > end:
        raise DerError("truncated header")
    tag = buf[off]
    if tag & 0x1F == 0x1F:
        raise DerError("high-tag-number form not accepted")
    len0 = buf[off + 1]
    if len0 & 0x80:
        n = len0 & 0x7F
        if n == 0:
            raise DerError("indefinite length (BER, not DER)")
        if n > 4:
            raise DerError("length > 4 bytes")
        if off + 2 + n > end:
            raise DerError("truncated long-form length")
        length = int.from_bytes(buf[off + 2 : off + 2 + n], "big")
        # DER admits exactly one spelling: short form below 128, and long
        # form with no leading zero octets.
        if length < 128:
            raise DerError(f"length {length} must use short form, not long")
        need = 1
        if length > 0xFFFFFF:
            need = 4
        elif length > 0xFFFF:
            need = 3
        elif length > 0xFF:
            need = 2
        if n != need:
            raise DerError(f"non-minimal long-form length ({n} octets, need {need})")
        hdr = 2 + n
    else:
        length = len0
        hdr = 2
    vstart = off + hdr
    if vstart + length > end:
        raise DerError("value overruns parent")
    return tag, vstart, vstart + length, vstart + length


def check_canonical_oid(buf, start, end):
    """Mirrors IsCanonicalOidBody(): minimal base-128 subidentifiers."""
    if start >= end:
        raise DerError("empty OID")
    if buf[end - 1] & 0x80:
        raise DerError("OID ends mid-subidentifier")
    at_start = True
    for i in range(start, end):
        if at_start and buf[i] == 0x80:
            raise DerError("non-minimal OID arc (leading 0x80)")
        at_start = not buf[i] & 0x80


def check_bit_string_content(buf, start, end):
    """Mirrors ValidBitStringContent(): [unused-count][data...]."""
    n = end - start
    if n < 1:
        raise DerError("BIT STRING has no unused-bit count octet")
    unused = buf[start]
    if unused > 7:
        raise DerError(f"unused-bit count {unused} > 7")
    if n == 1:
        if unused != 0:
            raise DerError("no data octets but a nonzero unused-bit count")
        return
    if buf[end - 1] & ((1 << unused) - 1):
        raise DerError("unused trailing bits are not zero")


def decode_oid(buf, start, end):
    if start >= end:
        raise DerError("empty OID")
    first = buf[start]
    arcs = [str(first // 40), str(first % 40)]
    acc = 0
    for i in range(start + 1, end):
        b = buf[i]
        acc = (acc << 7) | (b & 0x7F)
        if not b & 0x80:
            arcs.append(str(acc))
            acc = 0
    return ".".join(arcs)


def read_exact(buf, start, end, expect_tag):
    """One TLV that must EXACTLY fill [start, end). Mirrors ReadExact()."""
    tag, vs, ve, nxt = read_tlv(buf, start, end)
    if tag != expect_tag:
        raise DerError(f"expected tag 0x{expect_tag:02x}, found 0x{tag:02x}")
    if nxt != end:
        raise DerError("value does not exactly fill its container")
    return vs, ve


def decode_basic_constraints(buf, start, end):
    """Mirrors DecodeBasicConstraints(). Returns (is_ca, path_len | None)."""
    vs, ve = read_exact(buf, start, end, 0x30)
    off = vs
    is_ca = False
    path_len = None
    if off < ve:
        tag, cs, ce, nxt = read_tlv(buf, off, ve)
        if tag == 0x01:
            # DEFAULT FALSE: present means TRUE. An explicit FALSE should
            # have been omitted (X.690 11.5); BER nonzero is refused too.
            if ce - cs != 1 or buf[cs] != 0xFF:
                raise DerError("cA must be the DER BOOLEAN 0xFF (omit DEFAULT FALSE)")
            is_ca = True
            off = nxt
    if off < ve:
        tag, ps, pe, nxt = read_tlv(buf, off, ve)
        if tag != 0x02:
            raise DerError("unexpected field in BasicConstraints")
        n = pe - ps
        if n < 1 or n > 4 or buf[ps] & 0x80:
            raise DerError("pathLenConstraint negative or too wide")
        if n > 1 and buf[ps] == 0x00 and not buf[ps + 1] & 0x80:
            raise DerError("pathLenConstraint INTEGER not DER-minimal")
        path_len = int.from_bytes(buf[ps:pe], "big")
        off = nxt
    if off != ve:
        raise DerError("trailing field in BasicConstraints")
    return is_ca, path_len


def decode_key_usage(buf, start, end):
    """Mirrors DecodeKeyUsage() + ValidNamedBitStringContent().

    KeyUsage is a NAMED BIT STRING, so X.690 11.2.2 additionally forbids
    encoding trailing zero bits: `03 02 02 04` is the only spelling of
    keyCertSign, not `03 02 00 04` or `03 03 00 04 00`.
    """
    vs, ve = read_exact(buf, start, end, 0x03)
    check_bit_string_content(buf, vs, ve)
    n = ve - vs
    unused = buf[vs]
    if n == 1:
        return False  # canonical empty bit list
    last = buf[ve - 1]
    if last == 0:
        raise DerError("trailing all-zero octet must not be encoded")
    trailing_zeros = 0
    while not (last >> trailing_zeros) & 1:
        trailing_zeros += 1
    if unused != trailing_zeros:
        raise DerError(
            f"non-minimal NAMED BIT STRING: unused={unused}, "
            f"final octet 0x{last:02X} has {trailing_zeros} trailing zero bits")
    significant = (n - 1) * 8 - unused
    return significant > 5 and bool(buf[vs + 1] & 0x04)


def decode_subject_alt_name(buf, start, end):
    """Mirrors DecodeSubjectAltName(). Returns the dNSName list."""
    vs, ve = read_exact(buf, start, end, 0x30)
    names = []
    off = vs
    count = 0
    while off < ve:
        tag, ns, ne, nxt = read_tlv(buf, off, ve)
        if tag in (0x81, 0x82, 0x86):  # rfc822Name / dNSName / URI
            if ne == ns:
                raise DerError(f"empty IA5String GeneralName [0x{tag:02X}]")
            for i in range(ns, ne):
                if buf[i] > 0x7F:
                    raise DerError(
                        f"non-IA5 byte 0x{buf[i]:02X} in GeneralName [0x{tag:02X}]")
        elif tag == 0x87:  # iPAddress
            if ne - ns not in (4, 16):
                raise DerError(f"iPAddress is {ne - ns} octets, must be 4 or 16")
        elif tag == 0x88:  # registeredID
            check_canonical_oid(buf, ns, ne)
        else:
            # otherName [0], x400Address [3], directoryName [4],
            # ediPartyName [5] carry nested schemas the verifier does not
            # implement, so it refuses them rather than skip them.
            raise DerError(f"GeneralName tag 0x{tag:02X} not schema-validated")
        count += 1
        if tag == 0x82:
            names.append(bytes(buf[ns:ne]).decode("ascii", "replace"))
        off = nxt
    if off != ve:
        raise DerError("GeneralNames does not exactly fill extnValue")
    if count == 0:
        raise DerError("empty GeneralNames")
    return names


def extensions_of(der):
    """Yield (oid, critical, value_len, note) for a v3 certificate."""
    end = len(der)
    _, ostart, oend, _ = read_tlv(der, 0, end)  # Certificate SEQUENCE
    tag, tstart, tend, _ = read_tlv(der, ostart, oend)  # TBSCertificate
    if tag != 0x30:
        raise DerError("TBSCertificate is not a SEQUENCE")

    off = tstart
    tag, vs, ve, nxt = read_tlv(der, off, tend)
    version = 1
    if tag == 0xA0:  # [0] EXPLICIT version
        vt, ivs, ive, ivn = read_tlv(der, vs, ve)
        if vt != 0x02 or ivn != ve:
            raise DerError("version is not exactly one INTEGER")
        if ive - ivs != 1 or der[ivs] > 2:
            raise DerError("version out of range / not DER-minimal")
        if der[ivs] == 0:
            raise DerError("version v1 written out; DEFAULT must be omitted")
        version = der[ivs] + 1
        off = nxt
    for _ in range(6):  # serial, sigAlg, issuer, validity, subject, SPKI
        if off >= tend:
            return
        _, _, _, off = read_tlv(der, off, tend)

    # Legal tail: [1] issuerUniqueID, [2] subjectUniqueID (IMPLICIT, so
    # primitive), [3] extensions (EXPLICIT, so constructed) — in order,
    # each at most once, with the version constraints of RFC 5280
    # 4.1.2.8 / 4.1.2.9.
    ranks = {0x81: 1, 0x82: 2, 0xA3: 3}
    last_rank = 0
    while off < tend:
        tag, vs, ve, nxt = read_tlv(der, off, tend)
        rank = ranks.get(tag)
        if rank is None:
            raise DerError(f"tag 0x{tag:02X} is not a legal TBS tail field")
        if rank <= last_rank:
            raise DerError(f"tail field 0x{tag:02X} duplicated or out of order")
        last_rank = rank
        if rank <= 2:
            if version < 2:
                raise DerError("issuer/subjectUniqueID requires v2 or v3")
            # IMPLICIT BIT STRING: the tag is [1]/[2] but the content
            # rules are still the BIT STRING's.
            check_bit_string_content(der, vs, ve)
        if rank == 3:  # [3] EXPLICIT extensions
            if version != 3:
                raise DerError(f"extensions present in a v{version} certificate")
            if nxt != tend:
                raise DerError("[3] extensions is not the final TBS field")
            stag, sstart, send, snxt = read_tlv(der, vs, ve)
            if stag != 0x30:
                raise DerError("extensions wrapper is not a SEQUENCE")
            if snxt != ve:
                raise DerError("[3] wrapper not exactly consumed by Extensions")
            if send == sstart:
                raise DerError("empty Extensions SEQUENCE (SIZE 1..MAX)")
            xo = sstart
            while xo < send:
                etag, estart, eend, xnxt = read_tlv(der, xo, send)
                if etag != 0x30:
                    raise DerError("Extension is not a SEQUENCE")
                otag, ostart2, oend2, after_oid = read_tlv(der, estart, eend)
                if otag != 0x06:
                    raise DerError("extnID is not an OID")
                check_canonical_oid(der, ostart2, oend2)
                oid = decode_oid(der, ostart2, oend2)
                critical = False
                cur = after_oid
                if cur < eend:
                    ctag, cstart, cend, after_bool = read_tlv(der, cur, eend)
                    note = ""
                    if ctag == 0x01:
                        # DEFAULT FALSE: present means TRUE. Explicit
                        # FALSE (X.690 11.5) and BER nonzero (11.1) are
                        # both refused.
                        if cend - cstart != 1 or der[cstart] != 0xFF:
                            raise DerError("critical must be the DER BOOLEAN 0xFF (omit DEFAULT FALSE)")
                        critical = True
                        cur = after_bool
                else:
                    note = ""
                vtag, vstart2, vend2, after_val = read_tlv(der, cur, eend)
                if vtag != 0x04:
                    raise DerError("extnValue is not an OCTET STRING")
                if after_val != eend:
                    raise DerError("trailing bytes after extnValue")
                yield oid, critical, vstart2, vend2, note
                xo = xnxt
            if xo != send:
                raise DerError("Extensions SEQUENCE not exactly consumed")
            return
        off = nxt


def report(name, der, recognised):
    """Print one certificate's extension inventory + issuer verdict.

    Returns the number of problems (0 = the verifier will accept it).
    """
    print(f"\n{name}  ({len(der)} bytes)")
    problems = 0
    seen = set()
    bc = None  # (is_ca, path_len)
    ku = None  # key_cert_sign
    try:
        exts = list(extensions_of(der))
    except DerError as e:
        print(f"  !! REJECTED — DER parse failed: {e}")
        return 1

    if not exts:
        print("  (no v3 extensions -> not a CA, cannot be an issuer)")
        return 0

    for oid, critical, vs, ve, note in exts:
        label = OID_NAMES.get(oid, "?")
        flag = "CRITICAL" if critical else "        "
        detail = ""
        # Duplicate detection is generic — every extnID, recognised or
        # not (RFC 5280 §4.2 allows at most one instance of each).
        if oid in seen:
            print(f"  !! REJECTED — duplicate extension {oid} ({label})")
            return problems + 1
        seen.add(oid)
        if len(seen) > 32:
            print("  !! REJECTED — more than 32 extensions")
            return problems + 1
        try:
            if oid == "2.5.29.19":
                bc = decode_basic_constraints(der, vs, ve)
                detail = f"  cA={bc[0]} pathLen={bc[1]}"
            elif oid == "2.5.29.15":
                ku = decode_key_usage(der, vs, ve)
                detail = f"  keyCertSign={ku}"
            elif oid == "2.5.29.17":
                names = decode_subject_alt_name(der, vs, ve)
                detail = "  dNSName=" + ",".join(names) if names else "  (no dNSName)"
            elif critical:
                print(f"  {flag} {oid:<24} {label:<24} value={ve - vs}B")
                print(f"  !! REJECTED — unrecognised CRITICAL extension {oid} ({label})")
                return problems + 1
        except DerError as e:
            print(f"  {flag} {oid:<24} {label:<24} value={ve - vs}B")
            print(f"  !! REJECTED — {label} value is not exact DER: {e}")
            return problems + 1
        extra = f"  <-- {note}" if note else ""
        print(f"  {flag} {oid:<24} {label:<24} value={ve - vs}B{detail}{extra}")
        if note:
            problems += 1

    # IsUsableIssuer(certs_below = 0) — the leaf's direct issuer.
    if bc is None or not bc[0]:
        verdict = "no (basicConstraints absent or cA FALSE)"
    elif ku is not None and not ku:
        verdict = "no (keyUsage omits keyCertSign)"
    elif bc[1] is not None and bc[1] < 1:
        verdict = f"YES at depth 0 only (pathLen={bc[1]})"
    else:
        verdict = f"YES (pathLen={bc[1]})"
    print(f"  issuer= {verdict}")
    return problems


def arrays_in(text):
    for m in ARRAY_RE.finditer(text):
        name, body = m.group(1), m.group(2)
        data = bytes(int(h, 16) for h in BYTE_RE.findall(body))
        if data:
            yield name, data


def certs_in_file(path):
    """Yield (label, der) for a raw-DER or PEM certificate file."""
    raw = Path(path).read_bytes()
    if b"-----BEGIN CERTIFICATE-----" in raw:
        import base64

        text = raw.decode("ascii", "replace")
        blocks = text.split("-----BEGIN CERTIFICATE-----")[1:]
        for i, block in enumerate(blocks):
            b64 = block.split("-----END CERTIFICATE-----")[0]
            yield f"{Path(path).name}#{i}", base64.b64decode(
                "".join(b64.split()))
    else:
        yield Path(path).name, raw


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("sources", nargs="*", default=["kernel/net/x509_verify.cpp"])
    ap.add_argument(
        "--recognised",
        default=",".join(DEFAULT_RECOGNISED),
        help="comma-separated OIDs the verifier recognises as critical",
    )
    ap.add_argument(
        "--der",
        action="store_true",
        help="treat the arguments as DER/PEM certificate files, not C++ sources",
    )
    args = ap.parse_args()
    recognised = {o.strip() for o in args.recognised.split(",") if o.strip()}

    print("recognised-critical set: " + ", ".join(
        f"{o} ({OID_NAMES.get(o, '?')})" for o in sorted(recognised)))
    bad = 0
    total = 0
    for src in args.sources:
        path = Path(src)
        if not path.is_file():
            print(f"!! missing source: {src}")
            bad += 1
            continue
        if args.der:
            for name, der in certs_in_file(path):
                total += 1
                bad += report(name, der, recognised)
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        for name, der in arrays_in(text):
            total += 1
            bad += report(name, der, recognised)

    print(f"\n{total} certificate(s) inspected, {bad} would be REJECTED")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
