// test_x25519.cpp — hosted unit test for X25519 (Curve25519 ECDH), the
// key-exchange primitive for TLS 1.3.
//
// Covers: kernel/crypto/x25519.h
//   X25519(out, scalar, u)  — Montgomery-ladder scalar mult (RFC 7748)
//   X25519Base(out, scalar) — scalar * base point (u=9)
//
// Vectors are RFC 7748 §5.2 (single scalar-mult) and §6.1 (the full
// Diffie-Hellman exchange: Alice/Bob keypairs + shared secret).

#include "host_test_helper.h"

#include "../../kernel/crypto/x25519.h"

#include <cstdint>
#include <cstring>

using namespace duetos_host_test;
using duetos::crypto::X25519;
using duetos::crypto::X25519Base;

namespace
{
// Parse 64 hex chars -> 32 bytes.
void hex32(const char* h, uint8_t out[32])
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
    for (int i = 0; i < 32; ++i)
        out[i] = static_cast<uint8_t>((nib(h[2 * i]) << 4) | nib(h[2 * i + 1]));
}

bool eq32(const uint8_t a[32], const char* expect_hex)
{
    uint8_t e[32];
    hex32(expect_hex, e);
    return std::memcmp(a, e, 32) == 0;
}
} // namespace

int main()
{
    uint8_t scalar[32], u[32], out[32];

    // ---- RFC 7748 §5.2 vector 1 ----
    hex32("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4", scalar);
    hex32("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c", u);
    X25519(out, scalar, u);
    EXPECT_TRUE(eq32(out, "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"));

    // ---- RFC 7748 §5.2 vector 2 ----
    hex32("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d", scalar);
    hex32("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493", u);
    X25519(out, scalar, u);
    EXPECT_TRUE(eq32(out, "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957"));

    // ---- RFC 7748 §6.1 Diffie-Hellman ----
    uint8_t a_priv[32], b_priv[32], a_pub[32], b_pub[32], shared[32];
    hex32("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a", a_priv);
    hex32("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb", b_priv);

    X25519Base(a_pub, a_priv);
    EXPECT_TRUE(eq32(a_pub, "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"));
    X25519Base(b_pub, b_priv);
    EXPECT_TRUE(eq32(b_pub, "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"));

    // a * B == b * A == shared
    X25519(shared, a_priv, b_pub);
    EXPECT_TRUE(eq32(shared, "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"));
    X25519(shared, b_priv, a_pub);
    EXPECT_TRUE(eq32(shared, "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"));

    return finish_main("x25519");
}
