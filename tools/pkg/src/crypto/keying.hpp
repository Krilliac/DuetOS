#pragma once

#include "crypto/verifier.hpp"
#include "error.hpp"

#include <array>
#include <cstdint>
#include <filesystem>
#include <span>
#include <string>
#include <string_view>
#include <vector>

/*
 * duet-pkg Phase 2 — public-key loader + trust-DB primitives.
 *
 * Three accepted on-wire forms for an Ed25519 public key:
 *
 *  1. RAW 32 bytes (typical signing-tool output).
 *  2. PEM-wrapped X.509 SubjectPublicKeyInfo
 *     (`openssl pkey -pubout` output). DER body is
 *     12 bytes of header + 32 bytes of key.
 *  3. "ed25519:" prefix followed by URL-safe base64 of the
 *     raw 32 bytes (the format `repo.toml`'s `signing_key`
 *     field uses).
 *
 * Phase 2 implements LoadPublicKeyFromFile (PEM file on disk)
 * and ParsePublicKeyFromTomlString ("ed25519:..." form) for the
 * repo manifest. Phase 4 stitches both into the trust DB at
 * `/etc/duet-pkg/keys/<fingerprint>.pub`.
 */

namespace duet::crypto
{

struct PublicKey
{
    std::array<std::uint8_t, kEd25519PublicKeyBytes> bytes{};
};

/// Decode a base64 string ("standard" alphabet with optional
/// "=" padding, or URL-safe alphabet). Returns the decoded
/// bytes or `SignatureInvalid` if the input isn't well-formed
/// base64.
[[nodiscard]] Expected<std::vector<std::uint8_t>> Base64Decode(std::string_view input);

/// Parse an "ed25519:<base64>" toml-style public-key string
/// (the form `repo.toml`'s `signing_key` field uses). The
/// prefix is mandatory.
[[nodiscard]] Expected<PublicKey> ParsePublicKeyFromTomlString(std::string_view input);

/// Load an Ed25519 public key from a PEM-encoded file
/// (`openssl pkey -pubout`). The PEM body is X.509 SPKI:
/// 12-byte header + 32-byte key. Anything else returns
/// `SignatureInvalid` with the reason in `detail`.
[[nodiscard]] Expected<PublicKey> LoadPublicKeyFromFile(const std::filesystem::path& path);

/// Same shape but starting from in-memory PEM bytes.
[[nodiscard]] Expected<PublicKey> ParsePublicKeyFromPemBytes(std::string_view pem);

/// Render the key as `"ed25519:<base64>"` for round-tripping
/// into a repo manifest. Uses the standard alphabet, no padding.
[[nodiscard]] std::string PublicKeyToTomlString(const PublicKey& key);

/// Compute the canonical fingerprint of a key: the SHA-256 of
/// the raw 32 bytes, rendered as lowercase hex. Trust-DB
/// filenames + the `--trust-key` flag both refer to this.
[[nodiscard]] std::string Fingerprint(const PublicKey& key);

} // namespace duet::crypto
