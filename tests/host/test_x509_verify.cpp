// tests/host/test_x509_verify.cpp
//
// Hosted unit test for the kernel X.509 certificate-chain verifier in
// `kernel/net/x509_verify.cpp` — the HTTPS trust path. Compiles the real
// production crypto stack (ASN.1 DER parse, RSA PKCS#1 v1.5 verify incl.
// RSA-4096, ECDSA P-256/P-384, SHA-256/384, X.509 cert parse, big-int
// modexp) and runs its built-in `X509VerifySelfTest()` natively.
//
// That self-test embeds real OpenSSL-signed DER fixtures and proves the
// leaf->root and leaf->intermediate->root paths verify TRUE while a
// tampered signature, wrong hostname, expired window, and untrusted
// issuer all verify FALSE; it also parses 8 real trust-store roots
// (6 RSA incl. one RSA-4096 + 2 ECDSA) and self-verifies one of each.
//
// This is the heaviest of the boot crypto self-tests (~the bulk of the
// ~200 s under-TCG crypto block). Hosted, it runs natively in a few
// seconds and gates every PR, so the in-kernel boot copy can stay gated
// behind the `selftests=full` opt-in (see kernel/core/boot_bringup.cpp).
//
// Kernel-only symbols (arch::SerialWrite, core::Panic*, debug::ProbeFire)
// come from crypto_host_shims.h, which captures SerialWrite into
// g_crypto_serial so we can read back the self-test's verdict line.

#include "host_test_helper.h"

#include "crypto_host_shims.h"
#include "net/x509_verify.h"

#include <string>

int main()
{
    g_crypto_serial.clear();
    duetos::net::x509::X509VerifySelfTest();

    // On success the verifier emits "[x509-verify-selftest] PASS (...)".
    // A failed positive/negative case logs a FAIL line (and the embedded
    // EcSelfTest it calls would log "[ec-selftest] FAIL"); a corrupt
    // fixture would trip a Panic shim (→ abort → test failure).
    EXPECT_TRUE(g_crypto_serial.find("FAIL") == std::string::npos);
    EXPECT_TRUE(g_crypto_serial.find("[x509-verify-selftest] PASS") != std::string::npos);
    return 0;
}
