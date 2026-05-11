#pragma once

#include "crypto/keying.hpp"
#include "error.hpp"
#include "repo/repo_manifest.hpp"

#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

/*
 * duet-pkg Phase 4 — repo manager.
 *
 * Owns the on-disk trust DB + active-repo registry:
 *
 *   $DUET_PKG_CONFIG_DIR (default /etc/duet-pkg)
 *   ├── repos.toml                    ← active repos (this index)
 *   ├── repos/
 *   │   ├── <name>.toml               ← cached body of remote repo.toml
 *   │   └── <name>.toml.sig           ← cached detached signature
 *   └── keys/
 *       └── <fingerprint>.pub         ← trusted key (ed25519:<base64>)
 *
 * Trust model:
 *   - First add: caller passes `--trust-key <fingerprint>`. Manager
 *     fetches repo.toml, parses signing_key, checks the key's
 *     fingerprint matches the caller's expectation, then verifies
 *     the detached signature against the same key.
 *   - Subsequent syncs: re-verify against the cached key in
 *     keys/<fingerprint>.pub. No key on disk == hard reject.
 *
 * `$DUET_PKG_CONFIG_DIR` overrides the default root so tests
 * don't need /etc write access.
 */

namespace duet::repo
{

struct RepoIndexEntry
{
    std::string name;
    std::string url;
    std::string trust_fingerprint;
    std::string last_synced; // ISO 8601 UTC; opaque string
    std::uint64_t package_count = 0;
};

class RepoManager
{
  public:
    explicit RepoManager(std::filesystem::path config_root) noexcept : m_config_root(std::move(config_root)) {}

    [[nodiscard]] const std::filesystem::path& ConfigRoot() const noexcept { return m_config_root; }

    /// Resolve the canonical config root for the current process:
    /// `$DUET_PKG_CONFIG_DIR` if set, else `/etc/duet-pkg`.
    [[nodiscard]] static std::filesystem::path DefaultConfigRoot() noexcept;

    /// Read the on-disk repos.toml. Returns an empty list if the
    /// index file doesn't exist yet (fresh install state).
    [[nodiscard]] Expected<std::vector<RepoIndexEntry>> LoadIndex() const;

    /// Write the in-memory list back to repos.toml. Atomic via
    /// `.tmp` + rename.
    [[nodiscard]] Expected<void> SaveIndex(const std::vector<RepoIndexEntry>& entries) const;

    /// Add a new repo to the trust DB + index.
    ///
    ///   1. Download `<url>/repo.toml` (the URL points at the
    ///      manifest, NOT at a directory).
    ///   2. Download `<url>/repo.toml.sig` (sibling detached sig).
    ///   3. Parse signing_key from the downloaded repo.toml.
    ///   4. Reject unless `crypto::Fingerprint(key) ==
    ///      trust_fingerprint`.
    ///   5. Verify the detached signature against the manifest body.
    ///   6. Reject if a repo with the same name (from `[repo].name`)
    ///      is already registered, unless `force_replace` is true.
    ///   7. Persist the manifest + sig + trusted key to disk.
    ///   8. Append / update the index entry.
    [[nodiscard]] Expected<RepoIndexEntry> Add(std::string_view url, std::string_view trust_fingerprint,
                                               bool allow_insecure = false, bool force_replace = false);

    /// Remove a repo by name. Deletes its cached manifest, sig,
    /// AND its trusted key file (the key is repo-scoped — re-adding
    /// the same repo prompts the operator for a fresh `--trust-key`).
    [[nodiscard]] Expected<void> Remove(std::string_view name);

    /// Re-fetch every repo's repo.toml + .sig, verify against the
    /// cached trusted key, update `last_synced`. If `only_name` is
    /// non-empty, only that single repo is synced.
    ///
    /// Returns a vector of the synced entries (length 1 when
    /// `only_name` is set, else the full list). Failures on
    /// individual repos abort the call — partial sync is a recipe
    /// for a half-fresh, half-stale view.
    [[nodiscard]] Expected<std::vector<RepoIndexEntry>> Sync(std::string_view only_name = {},
                                                             bool allow_insecure = false);

    /// Read the cached body of one repo's manifest. Useful for
    /// `info` / `list --available` / `search` (Phase 7).
    [[nodiscard]] Expected<RepoManifest> LoadCachedManifest(std::string_view name) const;

    // ------------------------------------------------------------
    // Trust-DB primitives. Exposed for the `key list/trust/revoke`
    // subcommands; intentionally narrow so they're easy to audit.
    // ------------------------------------------------------------

    /// Path to a trusted key on disk (does not check existence).
    [[nodiscard]] std::filesystem::path TrustedKeyPath(std::string_view fingerprint) const;

    /// Enumerate every fingerprint in `keys/`. Lexicographic
    /// order so output stays stable.
    [[nodiscard]] Expected<std::vector<std::string>> ListTrustedFingerprints() const;

    /// Read the trusted key by fingerprint.
    [[nodiscard]] Expected<crypto::PublicKey> LoadTrustedKey(std::string_view fingerprint) const;

    /// Persist a public key to the trust DB. Filename is the
    /// fingerprint; body is the `ed25519:<base64>` form.
    [[nodiscard]] Expected<void> SaveTrustedKey(const crypto::PublicKey& key) const;

    /// Delete a trusted key by fingerprint. Returns
    /// `PackageNotFound` (reused) if the file isn't present.
    [[nodiscard]] Expected<void> RemoveTrustedKey(std::string_view fingerprint) const;

  private:
    [[nodiscard]] std::filesystem::path RepoBodyPath(std::string_view name) const;
    [[nodiscard]] std::filesystem::path RepoSigPath(std::string_view name) const;
    [[nodiscard]] std::filesystem::path KeysDir() const { return m_config_root / "keys"; }
    [[nodiscard]] std::filesystem::path ReposDir() const { return m_config_root / "repos"; }
    [[nodiscard]] std::filesystem::path IndexPath() const { return m_config_root / "repos.toml"; }

    std::filesystem::path m_config_root;
};

} // namespace duet::repo
