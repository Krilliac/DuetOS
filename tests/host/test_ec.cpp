// tests/host/test_ec.cpp
//
// Hosted unit test for the kernel ECDSA implementation in
// `kernel/net/ec.cpp` (P-256 + P-384 verify) and the big-integer
// modular arithmetic it leans on (`kernel/crypto/bigint.cpp`).
//
// Unlike test_text_hash.cpp (which reproduces a tiny algorithm
// verbatim), this test compiles the REAL production crypto TUs and
// runs their built-in self-test, `duetos::net::ec::EcSelfTest()`,
// natively. That self-test drives the same P-256/P-384 known-answer
// vectors and 8 negative cases (tampered-r, s-range, off-curve,
// tampered-hash) the kernel runs at boot under `selftests=full`.
//
// Why hosted: the ECDSA + bigint verify is ~pure computation over
// embedded byte vectors, but costs ~200 s as part of the boot crypto
// cluster under QEMU TCG. Running it here is native (milliseconds) and
// gates every PR, so the in-kernel boot copy can stay gated behind the
// `selftests=full` opt-in (see kernel/core/boot_bringup.cpp).
//
// The compiled kernel TUs reference a few kernel-only symbols
// (arch::SerialWrite, core::Panic*, debug::ProbeFire) — provided by
// crypto_host_shims.h, which also captures SerialWrite into
// g_crypto_serial so we can read back the self-test's PASS / FAIL line.

#include "host_test_helper.h"

#include "crypto_host_shims.h"
#include "net/ec.h"

#include <string>

int main()
{
    g_crypto_serial.clear();
    duetos::net::ec::EcSelfTest();

    // EcSelfTest emits "[ec-selftest] PASS (...)" on success, or
    // "[ec-selftest] FAIL (<label>)" + returns early on any failed
    // KAT / negative case. Assert we saw PASS and never FAIL.
    EXPECT_TRUE(g_crypto_serial.find("[ec-selftest] FAIL") == std::string::npos);
    EXPECT_TRUE(g_crypto_serial.find("[ec-selftest] PASS") != std::string::npos);
    return 0;
}
