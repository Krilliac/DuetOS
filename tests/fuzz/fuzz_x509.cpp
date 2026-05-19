// DuetOS — X.509 v3 certificate parser fuzz harness.
//
// x509::Parse walks a DER-encoded certificate: TBSCertificate,
// validity window, subject CN, and the RSA SubjectPublicKeyInfo
// — every field sliced out of the cert bytes. The cert arrives
// in a TLS handshake or off disk, fully attacker-controlled.
// The parser sits on top of asn1::Read, so this harness also
// exercises the DER reader along the certificate-shaped path.

#include "crypto/x509.h"

#include <cstddef>
#include <cstdint>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size == 0 || size > (1u << 16))
        return 0;

    duetos::crypto::x509::Certificate cert{};
    (void)duetos::crypto::x509::Parse(reinterpret_cast<const duetos::u8*>(data), static_cast<duetos::u32>(size), &cert);
    return 0;
}
