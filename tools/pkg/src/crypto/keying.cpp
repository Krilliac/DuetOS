#include "crypto/keying.hpp"

#include <sodium.h>

#include <algorithm>
#include <cstring>
#include <fstream>
#include <sstream>
#include <utility>

namespace duet::crypto
{
namespace
{

constexpr std::string_view kPemBegin = "-----BEGIN PUBLIC KEY-----";
constexpr std::string_view kPemEnd = "-----END PUBLIC KEY-----";
constexpr std::string_view kTomlPrefix = "ed25519:";

// X.509 SubjectPublicKeyInfo header for Ed25519 (RFC 8410):
//   SEQUENCE { SEQUENCE { OID 1.3.101.112 }, BIT STRING { 0x00 || key } }
// The first 12 bytes of the SPKI are constant; bytes 12..43 are
// the raw 32-byte public key.
constexpr std::array<std::uint8_t, 12> kEd25519SpkiHeader = {
    0x30, 0x2A, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x03, 0x21, 0x00,
};

[[nodiscard]] std::string StripWhitespace(std::string_view s)
{
    std::string out;
    out.reserve(s.size());
    for (char c : s)
    {
        if (c != ' ' && c != '\n' && c != '\r' && c != '\t')
            out.push_back(c);
    }
    return out;
}

} // namespace

Expected<std::vector<std::uint8_t>> Base64Decode(std::string_view input)
{
    auto init = EnsureSodiumInit();
    if (!init)
        return std::unexpected(init.error());

    // libsodium's `sodium_base642bin` handles padding + ignores
    // newlines; we still strip whitespace first so the input
    // length used as the output bound is tight.
    const std::string cleaned = StripWhitespace(input);
    std::vector<std::uint8_t> out(cleaned.size()); // upper bound
    std::size_t out_len = 0;
    const char* end = nullptr;
    // Try standard alphabet first; if that fails, try URL-safe.
    int rc = sodium_base642bin(out.data(), out.size(), cleaned.data(), cleaned.size(), nullptr, &out_len, &end,
                               sodium_base64_VARIANT_ORIGINAL);
    if (rc != 0)
    {
        rc = sodium_base642bin(out.data(), out.size(), cleaned.data(), cleaned.size(), nullptr, &out_len, &end,
                               sodium_base64_VARIANT_URLSAFE);
    }
    if (rc != 0)
    {
        return std::unexpected(MakeError(ErrorCode::SignatureInvalid, "base64 decode failed"));
    }
    out.resize(out_len);
    return out;
}

Expected<PublicKey> ParsePublicKeyFromTomlString(std::string_view input)
{
    if (!input.starts_with(kTomlPrefix))
    {
        return std::unexpected(
            MakeError(ErrorCode::SignatureInvalid, "expected `ed25519:<base64>`; got: " + std::string{input}));
    }
    const std::string_view body = input.substr(kTomlPrefix.size());
    auto bytes = Base64Decode(body);
    if (!bytes)
        return std::unexpected(bytes.error());
    if (bytes->size() != kEd25519PublicKeyBytes)
    {
        return std::unexpected(MakeError(ErrorCode::SignatureInvalid, "Ed25519 public key must be 32 bytes; decoded " +
                                                                          std::to_string(bytes->size())));
    }
    PublicKey out{};
    std::memcpy(out.bytes.data(), bytes->data(), kEd25519PublicKeyBytes);
    return out;
}

Expected<PublicKey> ParsePublicKeyFromPemBytes(std::string_view pem)
{
    // Find the BEGIN / END boundaries — order matters because we
    // accept files with leading metadata / comments.
    const auto begin_off = pem.find(kPemBegin);
    if (begin_off == std::string_view::npos)
    {
        return std::unexpected(MakeError(ErrorCode::SignatureInvalid, "PEM: missing BEGIN PUBLIC KEY marker"));
    }
    const auto begin_end = begin_off + kPemBegin.size();
    const auto end_off = pem.find(kPemEnd, begin_end);
    if (end_off == std::string_view::npos)
    {
        return std::unexpected(MakeError(ErrorCode::SignatureInvalid, "PEM: missing END PUBLIC KEY marker"));
    }
    const std::string_view base64 = pem.substr(begin_end, end_off - begin_end);
    auto der = Base64Decode(base64);
    if (!der)
        return std::unexpected(der.error());

    if (der->size() != kEd25519SpkiHeader.size() + kEd25519PublicKeyBytes)
    {
        return std::unexpected(
            MakeError(ErrorCode::SignatureInvalid,
                      "PEM body is not an Ed25519 SubjectPublicKeyInfo (size=" + std::to_string(der->size()) + ")"));
    }
    for (std::size_t i = 0; i < kEd25519SpkiHeader.size(); ++i)
    {
        if ((*der)[i] != kEd25519SpkiHeader[i])
        {
            return std::unexpected(
                MakeError(ErrorCode::SignatureInvalid, "PEM body header is not the Ed25519 SPKI prefix"));
        }
    }
    PublicKey out{};
    std::memcpy(out.bytes.data(), der->data() + kEd25519SpkiHeader.size(), kEd25519PublicKeyBytes);
    return out;
}

Expected<PublicKey> LoadPublicKeyFromFile(const std::filesystem::path& path)
{
    std::ifstream in{path, std::ios::binary};
    if (!in.is_open())
    {
        return std::unexpected(MakeError(ErrorCode::FilesystemError, "cannot open key file: " + path.string()));
    }
    std::ostringstream buf;
    buf << in.rdbuf();
    return ParsePublicKeyFromPemBytes(buf.str());
}

std::string PublicKeyToTomlString(const PublicKey& key)
{
    (void)EnsureSodiumInit();
    // sodium_bin2base64 needs the encoded buffer size up front.
    const std::size_t needed = sodium_base64_encoded_len(kEd25519PublicKeyBytes, sodium_base64_VARIANT_ORIGINAL);
    std::string b64(needed, '\0');
    sodium_bin2base64(b64.data(), b64.size(), key.bytes.data(), kEd25519PublicKeyBytes, sodium_base64_VARIANT_ORIGINAL);
    // sodium_bin2base64 NUL-terminates inside the buffer; strip
    // trailing NUL bytes the C++ string view shouldn't carry.
    while (!b64.empty() && b64.back() == '\0')
    {
        b64.pop_back();
    }
    return std::string{kTomlPrefix} + b64;
}

std::string Fingerprint(const PublicKey& key)
{
    return Sha256HexOfBytes(std::span<const std::uint8_t>{key.bytes.data(), key.bytes.size()});
}

} // namespace duet::crypto
