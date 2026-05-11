#include "crypto/verifier.hpp"

#include <sodium.h>

#include <array>
#include <fstream>
#include <utility>
#include <vector>

namespace duet::crypto
{
namespace
{

constexpr std::size_t kStreamChunkBytes = 64 * 1024;

[[nodiscard]] std::string BytesToLowerHex(std::span<const std::uint8_t> bytes)
{
    static constexpr char kHex[] = "0123456789abcdef";
    std::string out;
    out.resize(bytes.size() * 2);
    for (std::size_t i = 0; i < bytes.size(); ++i)
    {
        out[i * 2] = kHex[(bytes[i] >> 4) & 0xF];
        out[i * 2 + 1] = kHex[bytes[i] & 0xF];
    }
    return out;
}

[[nodiscard]] bool LowerHexEq(std::string_view a, std::string_view b) noexcept
{
    if (a.size() != b.size())
        return false;
    for (std::size_t i = 0; i < a.size(); ++i)
    {
        char ca = a[i];
        char cb = b[i];
        if (ca >= 'A' && ca <= 'F')
            ca = static_cast<char>(ca + ('a' - 'A'));
        if (cb >= 'A' && cb <= 'F')
            cb = static_cast<char>(cb + ('a' - 'A'));
        if (ca != cb)
            return false;
    }
    return true;
}

[[nodiscard]] bool IsValidHexDigest(std::string_view s) noexcept
{
    if (s.size() != kSha256HexLen)
        return false;
    for (char c : s)
    {
        const bool ok = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
        if (!ok)
            return false;
    }
    return true;
}

} // namespace

Expected<void> EnsureSodiumInit() noexcept
{
    static const int initialised = sodium_init();
    if (initialised < 0)
    {
        return std::unexpected(MakeError(ErrorCode::InstallFailed, "libsodium init failed"));
    }
    return {};
}

std::string Sha256HexOfBytes(std::span<const std::uint8_t> bytes)
{
    (void)EnsureSodiumInit();
    std::array<std::uint8_t, kSha256DigestBytes> digest{};
    crypto_hash_sha256(digest.data(), bytes.data(), bytes.size());
    return BytesToLowerHex(digest);
}

Expected<std::string> Sha256HexOfFile(const std::filesystem::path& path)
{
    auto init = EnsureSodiumInit();
    if (!init)
        return std::unexpected(init.error());

    std::ifstream in{path, std::ios::binary};
    if (!in.is_open())
    {
        return std::unexpected(MakeError(ErrorCode::FilesystemError, "cannot open for hashing: " + path.string()));
    }

    crypto_hash_sha256_state state;
    crypto_hash_sha256_init(&state);

    std::vector<std::uint8_t> buf(kStreamChunkBytes);
    while (in)
    {
        in.read(reinterpret_cast<char*>(buf.data()), static_cast<std::streamsize>(buf.size()));
        const auto got = in.gcount();
        if (got > 0)
        {
            crypto_hash_sha256_update(&state, buf.data(), static_cast<std::size_t>(got));
        }
    }
    if (in.bad())
    {
        return std::unexpected(MakeError(ErrorCode::FilesystemError, "read failed while hashing: " + path.string()));
    }

    std::array<std::uint8_t, kSha256DigestBytes> digest{};
    crypto_hash_sha256_final(&state, digest.data());
    return BytesToLowerHex(digest);
}

Expected<void> VerifySha256(const std::filesystem::path& path, std::string_view expected_hex)
{
    if (!IsValidHexDigest(expected_hex))
    {
        return std::unexpected(MakeError(ErrorCode::HashMismatch,
                                         "expected SHA-256 digest is not 64 hex chars: " + std::string{expected_hex}));
    }
    auto actual = Sha256HexOfFile(path);
    if (!actual)
        return std::unexpected(actual.error());
    if (!LowerHexEq(*actual, expected_hex))
    {
        return std::unexpected(MakeError(ErrorCode::HashMismatch, "SHA-256 mismatch for " + path.string(),
                                         "expected=" + std::string{expected_hex} + " actual=" + *actual));
    }
    return {};
}

Expected<void> VerifySha256Bytes(std::span<const std::uint8_t> bytes, std::string_view expected_hex)
{
    if (!IsValidHexDigest(expected_hex))
    {
        return std::unexpected(MakeError(ErrorCode::HashMismatch,
                                         "expected SHA-256 digest is not 64 hex chars: " + std::string{expected_hex}));
    }
    const auto actual = Sha256HexOfBytes(bytes);
    if (!LowerHexEq(actual, expected_hex))
    {
        return std::unexpected(MakeError(ErrorCode::HashMismatch, "SHA-256 mismatch",
                                         "expected=" + std::string{expected_hex} + " actual=" + actual));
    }
    return {};
}

Expected<void> VerifySignature(std::span<const std::uint8_t> data, std::span<const std::uint8_t> signature,
                               std::span<const std::uint8_t> pubkey)
{
    auto init = EnsureSodiumInit();
    if (!init)
        return std::unexpected(init.error());

    if (signature.size() != kEd25519SignatureBytes)
    {
        return std::unexpected(
            MakeError(ErrorCode::SignatureInvalid,
                      "Ed25519 signature length must be 64 bytes; got " + std::to_string(signature.size())));
    }
    if (pubkey.size() != kEd25519PublicKeyBytes)
    {
        return std::unexpected(
            MakeError(ErrorCode::SignatureInvalid,
                      "Ed25519 public key length must be 32 bytes; got " + std::to_string(pubkey.size())));
    }
    const int rc = crypto_sign_verify_detached(signature.data(), data.data(), data.size(), pubkey.data());
    if (rc != 0)
    {
        return std::unexpected(MakeError(ErrorCode::SignatureInvalid, "Ed25519 signature failed verification"));
    }
    return {};
}

Expected<void> VerifySignatureOfFile(const std::filesystem::path& data_path, std::span<const std::uint8_t> signature,
                                     std::span<const std::uint8_t> pubkey)
{
    std::ifstream in{data_path, std::ios::binary};
    if (!in.is_open())
    {
        return std::unexpected(
            MakeError(ErrorCode::FilesystemError, "cannot open for signature verify: " + data_path.string()));
    }
    in.seekg(0, std::ios::end);
    const auto size = in.tellg();
    in.seekg(0, std::ios::beg);
    if (size < 0)
    {
        return std::unexpected(MakeError(ErrorCode::FilesystemError, "tellg failed: " + data_path.string()));
    }
    std::vector<std::uint8_t> buf(static_cast<std::size_t>(size));
    if (size > 0)
    {
        in.read(reinterpret_cast<char*>(buf.data()), static_cast<std::streamsize>(buf.size()));
        if (in.bad())
        {
            return std::unexpected(MakeError(ErrorCode::FilesystemError, "read failed: " + data_path.string()));
        }
    }
    return VerifySignature(buf, signature, pubkey);
}

} // namespace duet::crypto
