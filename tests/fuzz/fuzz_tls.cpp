// DuetOS — TLS 1.2 record + handshake parser fuzz harness.
//
// TlsPeekRecord / TlsPeekHandshake / TlsParseServerHello /
// TlsParseCertificateLeaf / TlsParseServerHelloDone walk byte
// streams arriving from a TLS server — fully attacker-
// controlled when the peer is hostile. The parsers chain into
// crypto::x509::Parse on the certificate path, which feeds the
// ASN.1/X.509 walker that the asn1 + x509 fuzzers already
// cover. This harness adds upstream coverage so a malformed
// TLS record header / handshake length / Certificate-message
// length-prefix encoding gets caught BEFORE it reaches the
// X.509 parser.
//
// The harness selects which parser to drive via the first
// input byte; the rest of the input is the body. That way one
// corpus exercises all five entry points and libFuzzer's
// coverage-guided mutator distributes input among them.

#include "net/tls.h"

#include <cstddef>
#include <cstdint>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size < 1 || size > (1u << 16))
        return 0;

    const uint8_t sel = data[0];
    const duetos::u8* body = reinterpret_cast<const duetos::u8*>(data) + 1;
    const duetos::u32 body_len = static_cast<duetos::u32>(size - 1);

    // Five parsers, dispatched by the low bits of the selector.
    switch (sel & 0x7)
    {
    case 0:
    {
        duetos::net::tls::RecordView v{};
        (void)duetos::net::tls::TlsPeekRecord(body, body_len, &v);
        break;
    }
    case 1:
    {
        duetos::net::tls::HandshakeView v{};
        (void)duetos::net::tls::TlsPeekHandshake(body, body_len, &v);
        break;
    }
    case 2:
    {
        duetos::u8 sr[duetos::net::tls::kServerRandomBytes];
        duetos::u16 cipher = 0;
        (void)duetos::net::tls::TlsParseServerHello(body, body_len, sr, &cipher);
        break;
    }
    case 3:
    {
        const duetos::u8* leaf = nullptr;
        duetos::u32 leaf_len = 0;
        (void)duetos::net::tls::TlsParseCertificateLeaf(body, body_len, &leaf, &leaf_len);
        break;
    }
    case 4:
        (void)duetos::net::tls::TlsParseServerHelloDone(body, body_len);
        break;
    default:
    {
        // Run them all so a chained-record-then-handshake-then-cert
        // input still exercises the full path even if the selector
        // accidentally picks a high bit.
        duetos::net::tls::RecordView rv{};
        (void)duetos::net::tls::TlsPeekRecord(body, body_len, &rv);
        duetos::net::tls::HandshakeView hv{};
        (void)duetos::net::tls::TlsPeekHandshake(body, body_len, &hv);
        break;
    }
    }
    return 0;
}
