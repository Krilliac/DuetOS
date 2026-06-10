// test_rsa_pss.cpp — hosted unit test for RSASSA-PSS / SHA-256 verify, the
// signature scheme TLS 1.3 uses for an RSA CertificateVerify.
//
// Covers: kernel/crypto/rsa.cpp  RsaPssSha256Verify()
//
// Vector generated with OpenSSL (2048-bit key, rsa_padding_mode:pss,
// rsa_pss_saltlen:32, SHA-256) and confirmed with `openssl dgst -verify`:
//   msg = "DuetOS TLS 1.3 RSA-PSS test message"

#include "host_test_helper.h"

// Provides the off-target SerialWrite / Panic stubs the kernel crypto TUs
// reference (same as test_x509_verify).
#include "crypto_host_shims.h"

#include "../../kernel/crypto/rsa.h"

#include <cstdint>
#include <cstring>

using namespace duetos_host_test;
using namespace duetos::crypto;

namespace
{
unsigned hexbytes(const char* h, uint8_t* out, unsigned cap)
{
    auto nib = [](char c) -> int
    {
        if (c >= '0' && c <= '9')
            return c - '0';
        if (c >= 'a' && c <= 'f')
            return c - 'a' + 10;
        if (c >= 'A' && c <= 'F')
            return c - 'A' + 10;
        return 0;
    };
    unsigned n = 0;
    for (unsigned i = 0; h[2 * i] && h[2 * i + 1] && n < cap; ++i)
        out[n++] = static_cast<uint8_t>((nib(h[2 * i]) << 4) | nib(h[2 * i + 1]));
    return n;
}

const char* N_HEX =
    "8ced6c24cf499e27ee8efb65af38c9084cf63ba53a70ff29163fa637885c433ed4bd21ba4cf28414016eb54d96d5678e89b11a00"
    "03be4d0f43e38f146e0e06613918420bfd734f0ceaf056e14d8fd30568312a2cd2c05c60583863f4f24877c216b2f8d876062a4c"
    "18c818e0ba2096c56fb4de4b34de151b18c26ee14449cf297a564e4cb627d8321917873266a9d187b9294d0fad9a36a16df22067"
    "248b86dfbf8c9ca59a2bfd478a599eaf1e209c390f9fca425cdb3e589e4fc8c2be3d7f33a0e4be60e69980c0c3273d27cefeffbd0"
    "882c9fe09bdc7aa55b02203e8d9e0dd43a1ecc9abde7cdedac3dcee015cd99d2a94a93c2664d215939570236407e5ed";
const char* SIG_HEX =
    "0dd31f8dc8966abf9667ca7b81e6ce99b0bbb865221164175db9d6bb72df8ab312be3da3b40c38290cf6224e0c8bf00ae4a53240"
    "291f1d6a25381bec0de211f946e5f02d6cf7603ea7b03a03abe41645764c105edc63717eafbfe3426287cc3f639be0d76a84c320"
    "be548c3a7fe9447321244d66ffac362da3989a708c83c6913f589716579cd5bd60637787f783d8283dc2e210a2acc8811c652ee1"
    "485cb2e83cda4f70f834b91934f6c4a9b4ff98ec1f4db0fdbdc850faade1514a37669aaf6cb757546e6a878eff3c5b828e887b46"
    "96622d96586bac40d2e8a9b4ab702540269cb4c03ebd9c3757e19159493391ab52b62acc2eb530d1249e1c36d2c53ed6";
const char* MSG_SHA256 = "99a41669623eaa78c23895676d43e9893d179b3f10b1006b6ab46739a9f65655";
} // namespace

int main()
{
    uint8_t modbuf[256], sigbuf[256], mhash[32];
    uint8_t e[3] = {0x01, 0x00, 0x01};
    unsigned mlen = hexbytes(N_HEX, modbuf, sizeof(modbuf));
    unsigned slen = hexbytes(SIG_HEX, sigbuf, sizeof(sigbuf));
    hexbytes(MSG_SHA256, mhash, sizeof(mhash));

    RsaPublicKey k{};
    ASSERT_TRUE(RsaPublicKeyFromBE(&k, modbuf, mlen, e, sizeof(e)));

    // Positive — the genuine OpenSSL PSS signature verifies.
    EXPECT_TRUE(RsaPssSha256Verify(k, sigbuf, slen, mhash, 32));

    // Negative — a flipped message-hash byte must NOT verify.
    uint8_t bad_hash[32];
    std::memcpy(bad_hash, mhash, 32);
    bad_hash[0] ^= 0x01;
    EXPECT_FALSE(RsaPssSha256Verify(k, sigbuf, slen, bad_hash, 32));

    // Negative — a flipped signature byte must NOT verify.
    uint8_t bad_sig[256];
    std::memcpy(bad_sig, sigbuf, slen);
    bad_sig[100] ^= 0x01;
    EXPECT_FALSE(RsaPssSha256Verify(k, bad_sig, slen, mhash, 32));

    // Negative — wrong mhash length rejected.
    EXPECT_FALSE(RsaPssSha256Verify(k, sigbuf, slen, mhash, 31));

    return finish_main("rsa_pss");
}
