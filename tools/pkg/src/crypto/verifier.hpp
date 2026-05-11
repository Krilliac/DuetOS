#pragma once

#include "error.hpp"

#include <array>
#include <cstdint>
#include <filesystem>
#include <span>
#include <string>
#include <string_view>

/*
 * duet-pkg Phase 2 — SHA-256 + Ed25519 verification.
 *
 * `Verifier` wraps libsodium's `crypto_hash_sha256` and
 * `crypto_sign_verify_detached`. Two surfaces:
 *
 *   - VerifySha256(path, expected_hex)         → check a file
 *   - VerifySha256Bytes(bytes, expected_hex)   → check a buffer
 *   - VerifySignature(data, sig, pubkey)       → Ed25519 detached
 *
 * Hex digests are 64 lowercase ASCII chars (no `0x`, no
 * whitespace). Signatures are exactly `kEd25519SignatureBytes`
 * (64). Public keys are exactly `kEd25519PublicKeyBytes` (32).
 * Anything else returns `SignatureInvalid` / `HashMismatch`
 * before a libsodium call.
 */

namespace duet::crypto
{

inline constexpr std::size_t kSha256DigestBytes = 32;
inline constexpr std::size_t kSha256HexLen = kSha256DigestBytes * 2;
inline constexpr std::size_t kEd25519SignatureBytes = 64;
inline constexpr std::size_t kEd25519PublicKeyBytes = 32;

/// Initialise libsodium. Safe to call repeatedly; the underlying
/// `sodium_init()` is idempotent. Returns `InstallFailed` only if
/// libsodium itself reports init failure (unrecoverable).
[[nodiscard]] Expected<void> EnsureSodiumInit() noexcept;

/// Compute the SHA-256 of a file's full contents and return the
/// hex digest. Reads streamed in 64 KiB chunks so a 10 MiB
/// tarball doesn't balloon RAM.
[[nodiscard]] Expected<std::string> Sha256HexOfFile(const std::filesystem::path& path);

/// Same shape over an in-memory buffer.
[[nodiscard]] std::string Sha256HexOfBytes(std::span<const std::uint8_t> bytes);

/// Hash a file and compare against the expected hex digest.
/// `HashMismatch` on disagreement (the actual digest goes into
/// `detail` for `--verbose`); `FilesystemError` if the file
/// can't be read.
[[nodiscard]] Expected<void> VerifySha256(const std::filesystem::path& path, std::string_view expected_hex);

/// Same shape over an in-memory buffer.
[[nodiscard]] Expected<void> VerifySha256Bytes(std::span<const std::uint8_t> bytes, std::string_view expected_hex);

/// Verify an Ed25519 detached signature. `data` is the original
/// message; `signature` is the 64-byte signature emitted by
/// `crypto_sign_detached`; `pubkey` is the 32-byte raw public
/// key. Returns `SignatureInvalid` on any failure (libsodium does
/// not differentiate further by design).
[[nodiscard]] Expected<void> VerifySignature(std::span<const std::uint8_t> data,
                                             std::span<const std::uint8_t> signature,
                                             std::span<const std::uint8_t> pubkey);

/// Verify the signature attached to a file. Reads the file
/// fully, then calls `VerifySignature`. Useful for the install
/// flow where the tarball + sidecar `.sig` pair gets verified
/// together.
[[nodiscard]] Expected<void> VerifySignatureOfFile(const std::filesystem::path& data_path,
                                                   std::span<const std::uint8_t> signature,
                                                   std::span<const std::uint8_t> pubkey);

} // namespace duet::crypto
