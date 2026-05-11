// duet-pkg Phase 2 — SHA-256 + Ed25519 + key-loader tests.
//
// Fixture: tests/fixtures/test_ed25519.pub — a real
// Ed25519 PEM produced by:
//   openssl genpkey -algorithm ed25519 -out /tmp/test-key.pem
//   openssl pkey -in /tmp/test-key.pem -pubout -out test_ed25519.pub
// Private key NOT committed; raw + signature constants below
// were captured from the same `openssl pkeyutl -sign` run.
//
// Frameworkless, same EXPECT_* macros as test_manifest_parse.cpp.

#include "crypto/keying.hpp"
#include "crypto/verifier.hpp"

#include <sodium.h>

#include <array>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <random>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace
{

int g_failures = 0;

#define EXPECT_TRUE(cond, msg)                                                                                         \
    do                                                                                                                 \
    {                                                                                                                  \
        if (!(cond))                                                                                                   \
        {                                                                                                              \
            std::fprintf(stderr, "FAIL %s:%d: %s — expected true: %s\n", __FILE__, __LINE__, __func__, msg);           \
            ++g_failures;                                                                                              \
            return;                                                                                                    \
        }                                                                                                              \
    } while (0)

#define EXPECT_FALSE(cond, msg)                                                                                        \
    do                                                                                                                 \
    {                                                                                                                  \
        if ((cond))                                                                                                    \
        {                                                                                                              \
            std::fprintf(stderr, "FAIL %s:%d: %s — expected false: %s\n", __FILE__, __LINE__, __func__, msg);          \
            ++g_failures;                                                                                              \
            return;                                                                                                    \
        }                                                                                                              \
    } while (0)

#define EXPECT_EQ_STR(actual, expected)                                                                                \
    do                                                                                                                 \
    {                                                                                                                  \
        const std::string _a{(actual)};                                                                                \
        const std::string _e{(expected)};                                                                              \
        if (_a != _e)                                                                                                  \
        {                                                                                                              \
            std::fprintf(stderr, "FAIL %s:%d: %s — expected '%s' got '%s'\n", __FILE__, __LINE__, __func__,            \
                         _e.c_str(), _a.c_str());                                                                      \
            ++g_failures;                                                                                              \
            return;                                                                                                    \
        }                                                                                                              \
    } while (0)

[[nodiscard]] std::string FixturePath(const char* leaf)
{
    return std::string{DUET_PKG_FIXTURES_DIR} + "/" + leaf;
}

[[nodiscard]] std::vector<std::uint8_t> HexToBytes(std::string_view hex)
{
    std::vector<std::uint8_t> out;
    out.reserve(hex.size() / 2);
    auto nibble = [](char c) -> int
    {
        if (c >= '0' && c <= '9')
            return c - '0';
        if (c >= 'a' && c <= 'f')
            return 10 + (c - 'a');
        if (c >= 'A' && c <= 'F')
            return 10 + (c - 'A');
        return -1;
    };
    for (std::size_t i = 0; i + 1 < hex.size(); i += 2)
    {
        const int hi = nibble(hex[i]);
        const int lo = nibble(hex[i + 1]);
        if (hi < 0 || lo < 0)
            return {};
        out.push_back(static_cast<std::uint8_t>((hi << 4) | lo));
    }
    return out;
}

// =========================================================
// Captured-once constants. See file header comment.
// =========================================================

// Raw 32-byte Ed25519 public key matching test_ed25519.pub.
constexpr std::string_view kRawPubKeyHex = "7d99d71ade69aaf5f2e3f62af919eacf8e690e0cd4bf8f306a9aa665187b970a";

// Signature for the message "hello duet-pkg" under the private
// key paired with the PEM above.
constexpr std::string_view kSampleMessage = "hello duet-pkg";
constexpr std::string_view kSampleSigHex = "a2f0acd2bd39bbdaec1a200412a94c11cbadc5aa8bad7f91da6a738b726b0c09"
                                           "1780780bfcac019bdd8db8db621e5c895455d0b2ef7210587b0da309d159d209";

// SHA-256 of the raw 32-byte pubkey above.
constexpr std::string_view kFingerprintHex = "43cf8d9054c9be191145a3d95e8dcf71f69330ee07f00fe0ac1a0dc8c34b3923";

// SHA-256 of the empty string (RFC 6234 §8 well-known vector).
constexpr std::string_view kEmptyStringSha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

// SHA-256 of "abc" (RFC 6234 §8 well-known vector).
constexpr std::string_view kAbcSha256 = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

// =========================================================
// SHA-256 tests
// =========================================================

void TestSha256EmptyString()
{
    const std::array<std::uint8_t, 0> empty{};
    EXPECT_EQ_STR(duet::crypto::Sha256HexOfBytes(empty), kEmptyStringSha256);
}

void TestSha256Abc()
{
    constexpr std::string_view abc = "abc";
    EXPECT_EQ_STR(duet::crypto::Sha256HexOfBytes(
                      std::span<const std::uint8_t>{reinterpret_cast<const std::uint8_t*>(abc.data()), abc.size()}),
                  kAbcSha256);
}

void TestVerifySha256BytesMatch()
{
    constexpr std::string_view abc = "abc";
    auto rc = duet::crypto::VerifySha256Bytes(
        std::span<const std::uint8_t>{reinterpret_cast<const std::uint8_t*>(abc.data()), abc.size()}, kAbcSha256);
    EXPECT_TRUE(rc.has_value(), "abc digest should verify");
}

void TestVerifySha256BytesMismatch()
{
    constexpr std::string_view abc = "abc";
    auto rc = duet::crypto::VerifySha256Bytes(
        std::span<const std::uint8_t>{reinterpret_cast<const std::uint8_t*>(abc.data()), abc.size()},
        // Same digest with one nibble flipped at the end.
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ae");
    EXPECT_FALSE(rc.has_value(), "altered digest should fail");
    EXPECT_TRUE(rc.error().code == duet::ErrorCode::HashMismatch, "code = HashMismatch");
}

void TestVerifySha256BytesBadHex()
{
    constexpr std::string_view abc = "abc";
    auto rc = duet::crypto::VerifySha256Bytes(
        std::span<const std::uint8_t>{reinterpret_cast<const std::uint8_t*>(abc.data()), abc.size()},
        "not-a-hex-digest");
    EXPECT_FALSE(rc.has_value(), "non-hex expected value should fail");
}

void TestSha256OfFile()
{
    // Write a 65 KiB file (forces multiple read chunks) full of
    // 'a' bytes, hash it, compare against a known good value
    // computed with openssl dgst -sha256.
    const auto path = std::filesystem::temp_directory_path() / "duet-pkg-sha256-stream.bin";
    {
        std::ofstream out{path, std::ios::binary | std::ios::trunc};
        EXPECT_TRUE(out.is_open(), "tmp file open");
        std::string body(65 * 1024, 'a');
        out.write(body.data(), static_cast<std::streamsize>(body.size()));
    }
    auto hex = duet::crypto::Sha256HexOfFile(path);
    std::filesystem::remove(path);
    EXPECT_TRUE(hex.has_value(), "hash of streamed file");
    // openssl: `printf 'a%.0s' $(seq 1 66560) | openssl dgst -sha256`
    // → cd69d3887c6af9264b100d7b7602331335d9aa7e3bd7c30cdc6d6f4bfbb3c888
    EXPECT_EQ_STR(*hex, "cd69d3887c6af9264b100d7b7602331335d9aa7e3bd7c30cdc6d6f4bfbb3c888");
}

// =========================================================
// Key-loader tests
// =========================================================

void TestPemKeyParse()
{
    auto key = duet::crypto::LoadPublicKeyFromFile(FixturePath("test_ed25519.pub"));
    EXPECT_TRUE(key.has_value(), "PEM should parse");
    const auto raw = HexToBytes(kRawPubKeyHex);
    EXPECT_TRUE(raw.size() == 32, "fixture hex is 32 bytes");
    for (std::size_t i = 0; i < raw.size(); ++i)
    {
        EXPECT_TRUE(key->bytes[i] == raw[i], "raw byte matches");
    }
}

void TestPemKeyRejectsGarbage()
{
    const std::string garbage = "this is not a PEM file\n";
    auto key = duet::crypto::ParsePublicKeyFromPemBytes(garbage);
    EXPECT_FALSE(key.has_value(), "garbage PEM should not parse");
}

void TestPemKeyRejectsWrongLength()
{
    // Valid PEM markers, but base64 body decodes to something
    // shorter than an Ed25519 SPKI.
    const std::string body = "-----BEGIN PUBLIC KEY-----\n"
                             "QUFBQUFBQUFBQUFBQUFBQUFB\n" // 18 bytes
                             "-----END PUBLIC KEY-----\n";
    auto key = duet::crypto::ParsePublicKeyFromPemBytes(body);
    EXPECT_FALSE(key.has_value(), "wrong-length PEM should not parse");
}

void TestFingerprintMatchesSpec()
{
    auto key = duet::crypto::LoadPublicKeyFromFile(FixturePath("test_ed25519.pub"));
    EXPECT_TRUE(key.has_value(), "PEM should parse");
    EXPECT_EQ_STR(duet::crypto::Fingerprint(*key), kFingerprintHex);
}

void TestPublicKeyTomlRoundTrip()
{
    auto key = duet::crypto::LoadPublicKeyFromFile(FixturePath("test_ed25519.pub"));
    EXPECT_TRUE(key.has_value(), "PEM should parse");
    const std::string tom = duet::crypto::PublicKeyToTomlString(*key);
    EXPECT_TRUE(tom.starts_with("ed25519:"), "TOML form has ed25519: prefix");
    auto round = duet::crypto::ParsePublicKeyFromTomlString(tom);
    EXPECT_TRUE(round.has_value(), "TOML form re-parses");
    for (std::size_t i = 0; i < 32; ++i)
    {
        EXPECT_TRUE(round->bytes[i] == key->bytes[i], "round-tripped byte matches");
    }
}

void TestPublicKeyTomlBadPrefix()
{
    auto bad = duet::crypto::ParsePublicKeyFromTomlString("rsa:AAAA");
    EXPECT_FALSE(bad.has_value(), "non-ed25519 prefix must fail");
}

// =========================================================
// Ed25519 signature tests
// =========================================================

void TestEd25519SampleSignature()
{
    const auto pubkey = HexToBytes(kRawPubKeyHex);
    const auto sig = HexToBytes(kSampleSigHex);
    EXPECT_TRUE(pubkey.size() == 32, "pubkey 32 bytes");
    EXPECT_TRUE(sig.size() == 64, "sig 64 bytes");
    auto rc = duet::crypto::VerifySignature(
        std::span<const std::uint8_t>{reinterpret_cast<const std::uint8_t*>(kSampleMessage.data()),
                                      kSampleMessage.size()},
        sig, pubkey);
    EXPECT_TRUE(rc.has_value(), "sample signature should verify");
}

void TestEd25519TamperedMessage()
{
    const auto pubkey = HexToBytes(kRawPubKeyHex);
    const auto sig = HexToBytes(kSampleSigHex);
    constexpr std::string_view tampered = "hello duet-PKG"; // case flip
    auto rc = duet::crypto::VerifySignature(
        std::span<const std::uint8_t>{reinterpret_cast<const std::uint8_t*>(tampered.data()), tampered.size()}, sig,
        pubkey);
    EXPECT_FALSE(rc.has_value(), "tampered message must not verify");
    EXPECT_TRUE(rc.error().code == duet::ErrorCode::SignatureInvalid, "code = SignatureInvalid");
}

void TestEd25519TamperedSignature()
{
    const auto pubkey = HexToBytes(kRawPubKeyHex);
    auto sig = HexToBytes(kSampleSigHex);
    sig[0] ^= 0x01; // flip one bit
    auto rc = duet::crypto::VerifySignature(
        std::span<const std::uint8_t>{reinterpret_cast<const std::uint8_t*>(kSampleMessage.data()),
                                      kSampleMessage.size()},
        sig, pubkey);
    EXPECT_FALSE(rc.has_value(), "tampered signature must not verify");
}

void TestEd25519SignatureBadLength()
{
    const auto pubkey = HexToBytes(kRawPubKeyHex);
    std::array<std::uint8_t, 63> too_short{};
    auto rc = duet::crypto::VerifySignature(
        std::span<const std::uint8_t>{reinterpret_cast<const std::uint8_t*>(kSampleMessage.data()),
                                      kSampleMessage.size()},
        too_short, pubkey);
    EXPECT_FALSE(rc.has_value(), "63-byte sig must be rejected");
}

void TestEd25519PubKeyBadLength()
{
    const auto sig = HexToBytes(kSampleSigHex);
    std::array<std::uint8_t, 31> too_short{};
    auto rc = duet::crypto::VerifySignature(
        std::span<const std::uint8_t>{reinterpret_cast<const std::uint8_t*>(kSampleMessage.data()),
                                      kSampleMessage.size()},
        sig, too_short);
    EXPECT_FALSE(rc.has_value(), "31-byte pubkey must be rejected");
}

void TestRoundTripSignVerify()
{
    // Generate a fresh keypair via libsodium directly, sign,
    // then verify through our wrapper. Catches integration
    // issues that the canned-vector test above can mask.
    EXPECT_TRUE(duet::crypto::EnsureSodiumInit().has_value(), "sodium_init");
    std::array<std::uint8_t, 32> pk{};
    std::array<std::uint8_t, 64> sk{};
    crypto_sign_keypair(pk.data(), sk.data());
    constexpr std::string_view msg = "round trip me";
    std::array<std::uint8_t, 64> sig{};
    crypto_sign_detached(sig.data(), nullptr, reinterpret_cast<const std::uint8_t*>(msg.data()), msg.size(), sk.data());
    auto ok = duet::crypto::VerifySignature(
        std::span<const std::uint8_t>{reinterpret_cast<const std::uint8_t*>(msg.data()), msg.size()}, sig, pk);
    EXPECT_TRUE(ok.has_value(), "fresh keypair sign+verify round trip");
}

} // namespace

int main()
{
    TestSha256EmptyString();
    TestSha256Abc();
    TestVerifySha256BytesMatch();
    TestVerifySha256BytesMismatch();
    TestVerifySha256BytesBadHex();
    TestSha256OfFile();
    TestPemKeyParse();
    TestPemKeyRejectsGarbage();
    TestPemKeyRejectsWrongLength();
    TestFingerprintMatchesSpec();
    TestPublicKeyTomlRoundTrip();
    TestPublicKeyTomlBadPrefix();
    TestEd25519SampleSignature();
    TestEd25519TamperedMessage();
    TestEd25519TamperedSignature();
    TestEd25519SignatureBadLength();
    TestEd25519PubKeyBadLength();
    TestRoundTripSignVerify();
    if (g_failures == 0)
    {
        std::printf("all verifier tests passed\n");
        return 0;
    }
    std::fprintf(stderr, "%d verifier test(s) FAILED\n", g_failures);
    return 1;
}
