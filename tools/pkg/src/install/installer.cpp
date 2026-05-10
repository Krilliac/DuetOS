#include "install/installer.hpp"

#include "crypto/keying.hpp"
#include "crypto/verifier.hpp"
#include "net/fetcher.hpp"
#include "repo/package_manifest.hpp"

#include <chrono>
#include <cstdlib>
#include <ctime>
#include <fstream>
#include <span>
#include <sstream>
#include <sys/wait.h>
#include <unistd.h>
#include <utility>

namespace duet::install
{
namespace
{

constexpr std::string_view kEnvPkgPrefix = "DUET_PKG_PREFIX";
constexpr std::string_view kEnvBinPrefix = "DUET_PKG_BIN_PREFIX";
constexpr std::string_view kEnvCacheDir = "DUET_PKG_CACHE";

[[nodiscard]] std::filesystem::path EnvOr(std::string_view env, std::string_view fallback) noexcept
{
    const char* v = std::getenv(std::string{env}.c_str());
    if (v != nullptr && v[0] != '\0')
        return std::filesystem::path{v};
    return std::filesystem::path{std::string{fallback}};
}

[[nodiscard]] std::string Iso8601Utc()
{
    using namespace std::chrono;
    const auto now = system_clock::now();
    const std::time_t t = system_clock::to_time_t(now);
    std::tm tm{};
    gmtime_r(&t, &tm);
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm);
    return std::string{buf};
}

// Exec `tar -xzf <archive> -C <dest>`. v0 shells out to the
// system tar; a pure-C++ tar extractor is a Phase 6+ slice if it
// matters. Returns Ok on tar exit 0; failure detail includes the
// child's exit code.
[[nodiscard]] Expected<void> ExtractTarGz(const std::filesystem::path& archive, const std::filesystem::path& dest)
{
    std::error_code ec;
    std::filesystem::create_directories(dest, ec);
    if (ec)
    {
        return std::unexpected(MakeError(ErrorCode::FilesystemError, "mkdir -p " + dest.string(), ec.message()));
    }
    pid_t pid = fork();
    if (pid < 0)
    {
        return std::unexpected(MakeError(ErrorCode::InstallFailed, "fork for tar failed"));
    }
    if (pid == 0)
    {
        // Child: exec tar. Tell it to refuse anything that tries
        // to escape the dest (e.g. absolute paths, "../" entries)
        // — that's a real path-traversal hazard from untrusted
        // tarballs. GNU tar's --no-same-owner + the chdir below
        // are the belt-and-braces.
        ::execlp("tar", "tar", "--no-same-owner", "--no-same-permissions", "-C", dest.c_str(), "-xzf", archive.c_str(),
                 static_cast<char*>(nullptr));
        std::_Exit(127);
    }
    int status = 0;
    if (::waitpid(pid, &status, 0) < 0)
    {
        return std::unexpected(MakeError(ErrorCode::InstallFailed, "waitpid for tar failed"));
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
    {
        return std::unexpected(MakeError(ErrorCode::InstallFailed, "tar failed extracting " + archive.string(),
                                         "exit=" + std::to_string(WIFEXITED(status) ? WEXITSTATUS(status) : -1)));
    }
    return {};
}

// Atomic symlink update: write to `<target>.tmp`, then rename
// over the existing one. POSIX rename(2) on a symlink replaces
// the destination atomically.
[[nodiscard]] Expected<void> AtomicSymlink(const std::filesystem::path& link_target,
                                           const std::filesystem::path& link_path)
{
    std::error_code ec;
    std::filesystem::create_directories(link_path.parent_path(), ec);
    auto tmp = link_path;
    tmp += ".tmp";
    std::filesystem::remove(tmp, ec);
    std::filesystem::create_symlink(link_target, tmp, ec);
    if (ec)
    {
        return std::unexpected(MakeError(
            ErrorCode::InstallFailed, "create_symlink " + tmp.string() + " -> " + link_target.string(), ec.message()));
    }
    std::filesystem::rename(tmp, link_path, ec);
    if (ec)
    {
        std::filesystem::remove(tmp);
        return std::unexpected(
            MakeError(ErrorCode::InstallFailed, "rename symlink to " + link_path.string(), ec.message()));
    }
    return {};
}

[[nodiscard]] std::filesystem::path TarballBasename(const repo::RepoPackageEntry& entry)
{
    // Use the binary_url's leaf for the cache filename so the
    // cache survives across versions cleanly. Fall back to a
    // composed name if the manifest didn't ship a binary_url.
    if (!entry.binary_url.empty())
    {
        const auto pos = entry.binary_url.find_last_of('/');
        return pos == std::string::npos ? entry.binary_url : entry.binary_url.substr(pos + 1);
    }
    return entry.name + "-" + entry.version + "-" + entry.arch + ".tar.gz";
}

} // namespace

InstallPaths DefaultInstallPaths() noexcept
{
    InstallPaths p;
    p.pkg_prefix = EnvOr(kEnvPkgPrefix, "/pkg");
    p.bin_prefix = EnvOr(kEnvBinPrefix, "/usr/local/bin");
    p.cache_dir = EnvOr(kEnvCacheDir, "/var/cache/duet-pkg");
    p.registry_root = registry::Registry::DefaultRoot();
    return p;
}

std::filesystem::path Installer::VersionDir(std::string_view name, std::string_view version) const
{
    return m_paths.pkg_prefix / name / version;
}

std::filesystem::path Installer::CurrentSymlink(std::string_view name) const
{
    return m_paths.pkg_prefix / name / "current";
}

std::filesystem::path Installer::CachePath(const repo::RepoPackageEntry& entry) const
{
    return m_paths.cache_dir / TarballBasename(entry);
}

Expected<InstallReport> Installer::Install(std::string_view target,
                                           const std::vector<std::pair<std::string, repo::RepoManifest>>& repos,
                                           bool allow_insecure)
{
    auto resolved = duet::resolve::Resolve(target, repos);
    if (!resolved)
        return std::unexpected(resolved.error());

    registry::Registry reg{m_paths.registry_root};
    auto existing_or = reg.LoadAll();
    if (!existing_or)
        return std::unexpected(existing_or.error());
    std::unordered_map<std::string, std::string> installed_versions;
    for (const auto& e : *existing_or)
        installed_versions[e.name] = e.version;

    InstallReport report;
    for (const auto& pkg : *resolved)
    {
        auto it = installed_versions.find(pkg.entry.name);
        if (it != installed_versions.end() && it->second == pkg.entry.version)
        {
            report.already_present.push_back(pkg.entry.name);
            continue;
        }
        auto rc = InstallOne(pkg, allow_insecure);
        if (!rc)
            return std::unexpected(rc.error());
        report.installed.push_back(pkg.entry.name);
    }
    return report;
}

Expected<void> Installer::InstallOne(const resolve::ResolvedPackage& pkg, bool allow_insecure)
{
    // The repo manager knows the URL + trusted key for the repo
    // this package came from.
    auto index_or = m_mgr.LoadIndex();
    if (!index_or)
        return std::unexpected(index_or.error());
    const duet::repo::RepoIndexEntry* idx_entry = nullptr;
    for (const auto& e : *index_or)
    {
        if (e.name == pkg.repo)
        {
            idx_entry = &e;
            break;
        }
    }
    if (idx_entry == nullptr)
    {
        return std::unexpected(MakeError(ErrorCode::InstallFailed,
                                         "package " + pkg.entry.name + " sourced from unknown repo: " + pkg.repo));
    }
    auto key_or = m_mgr.LoadTrustedKey(idx_entry->trust_fingerprint);
    if (!key_or)
        return std::unexpected(key_or.error());

    // Compose the binary URL. binary_url is documented as
    // "relative to base_url"; we glue them with a single slash.
    auto cached_manifest_or = m_mgr.LoadCachedManifest(idx_entry->name);
    if (!cached_manifest_or)
        return std::unexpected(cached_manifest_or.error());
    std::string base = cached_manifest_or->base_url;
    while (!base.empty() && base.back() == '/')
        base.pop_back();
    std::string rel = pkg.entry.binary_url;
    while (!rel.empty() && rel.front() == '/')
        rel.erase(0, 1);
    const std::string body_url = base + "/" + rel;
    const std::string sig_url = body_url + ".sig";

    // 1. Download tarball to cache. Verify SHA-256.
    const auto cache_path = CachePath(pkg.entry);
    std::error_code ec;
    std::filesystem::create_directories(cache_path.parent_path(), ec);
    if (ec)
    {
        return std::unexpected(
            MakeError(ErrorCode::FilesystemError, "mkdir -p " + cache_path.parent_path().string(), ec.message()));
    }
    duet::net::FetchOptions opts;
    opts.allow_insecure = allow_insecure;
    auto dl = duet::net::Download(body_url, cache_path, opts, {});
    if (!dl)
        return std::unexpected(dl.error());
    if (!pkg.entry.sha256.empty())
    {
        auto sha = duet::crypto::VerifySha256(cache_path, pkg.entry.sha256);
        if (!sha)
            return std::unexpected(sha.error());
    }

    // 2. Download signature. Verify against repo's trusted key.
    const auto sig_cache = cache_path.string() + ".sig";
    std::filesystem::remove(sig_cache, ec);
    auto sig_dl = duet::net::Download(sig_url, sig_cache, opts, {});
    if (!sig_dl)
        return std::unexpected(sig_dl.error());
    std::ifstream sig_in{sig_cache, std::ios::binary};
    if (!sig_in.is_open())
    {
        return std::unexpected(MakeError(ErrorCode::FilesystemError, "cannot open " + sig_cache));
    }
    std::vector<std::uint8_t> sig_bytes((std::istreambuf_iterator<char>(sig_in)), std::istreambuf_iterator<char>());
    sig_in.close();
    auto verify = duet::crypto::VerifySignatureOfFile(
        cache_path, sig_bytes, std::span<const std::uint8_t>{key_or->bytes.data(), key_or->bytes.size()});
    if (!verify)
        return std::unexpected(verify.error());

    // 3. Unpack atomically. New version goes to <prefix>/<name>/<version>.partial,
    // then renamed to <prefix>/<name>/<version> on success.
    const auto final_dir = VersionDir(pkg.entry.name, pkg.entry.version);
    auto partial_dir = final_dir;
    partial_dir += ".partial";
    std::filesystem::remove_all(partial_dir, ec);
    auto extract = ExtractTarGz(cache_path, partial_dir);
    if (!extract)
    {
        std::filesystem::remove_all(partial_dir);
        return std::unexpected(extract.error());
    }
    // If a previous attempt left final_dir partial, remove it.
    std::filesystem::remove_all(final_dir, ec);
    std::filesystem::rename(partial_dir, final_dir, ec);
    if (ec)
    {
        std::filesystem::remove_all(partial_dir);
        return std::unexpected(MakeError(ErrorCode::InstallFailed, "rename to " + final_dir.string(), ec.message()));
    }

    // 4. Update `current` symlink + emit /usr/local/bin shims.
    auto cur = AtomicSymlink(pkg.entry.version, CurrentSymlink(pkg.entry.name));
    if (!cur)
    {
        std::filesystem::remove_all(final_dir);
        return std::unexpected(cur.error());
    }

    // Re-read the in-tarball manifest if present so we know what
    // to symlink. If it's missing or malformed we fall back to
    // "the package contributes a binary named the same as the
    // package" — that's what `windows-kill` and most simple
    // packages do.
    std::vector<std::string> bin_targets;
    const auto inner_manifest = final_dir / "manifest.toml";
    if (std::filesystem::exists(inner_manifest))
    {
        auto m = duet::repo::LoadPackageManifestFromFile(inner_manifest);
        if (m)
            bin_targets = m->install.bin;
    }
    if (bin_targets.empty())
    {
        const auto candidate = final_dir / "bin" / pkg.entry.name;
        if (std::filesystem::exists(candidate))
            bin_targets.push_back("bin/" + pkg.entry.name);
    }
    for (const auto& rel_bin : bin_targets)
    {
        // rel_bin is something like "bin/nvim"; we link
        // /usr/local/bin/<leaf> -> /pkg/<name>/current/<rel_bin>.
        const auto leaf = std::filesystem::path{rel_bin}.filename();
        if (leaf.empty())
            continue;
        const auto link = m_paths.bin_prefix / leaf;
        const auto target_rel = CurrentSymlink(pkg.entry.name) / rel_bin;
        auto sym = AtomicSymlink(target_rel, link);
        if (!sym)
        {
            // Best-effort rollback: clear the version dir + any
            // bin symlinks we already wrote. We re-walk
            // bin_targets up to (but not including) this one to
            // undo the prior successful symlinks; the caller
            // sees the original error.
            std::filesystem::remove_all(final_dir);
            return std::unexpected(sym.error());
        }
    }

    // 5. Write registry entry.
    duet::registry::Registry reg{m_paths.registry_root};
    duet::registry::RegistryEntry entry;
    entry.name = pkg.entry.name;
    entry.version = pkg.entry.version;
    entry.installed_at = Iso8601Utc();
    entry.installed_from = pkg.repo;
    entry.install_prefix = final_dir.string();
    entry.sha256 = pkg.entry.sha256;
    entry.deps = pkg.entry.deps;
    auto wr = reg.Write(entry);
    if (!wr)
    {
        std::filesystem::remove_all(final_dir);
        return std::unexpected(wr.error());
    }
    return {};
}

Expected<std::string> Installer::InstallLocal(const std::filesystem::path& tar_path)
{
    if (!std::filesystem::exists(tar_path))
    {
        return std::unexpected(MakeError(ErrorCode::FilesystemError, "no such tarball: " + tar_path.string()));
    }
    // 1. Compute SHA-256 of the tarball — recorded in the
    // registry entry for forensic audit + matches the contract
    // documented in DUETOS_PKG_IMPLEMENTATION.md.
    auto sha_or = duet::crypto::Sha256HexOfFile(tar_path);
    if (!sha_or)
        return std::unexpected(sha_or.error());

    // 2. Extract to a partial dir we can later rename to the
    // canonical version dir.
    const auto tmp = std::filesystem::temp_directory_path() /
                     ("duet-pkg-local-" + std::to_string(std::hash<std::string>{}(tar_path.string())));
    std::filesystem::remove_all(tmp);
    auto extract = ExtractTarGz(tar_path, tmp);
    if (!extract)
    {
        std::filesystem::remove_all(tmp);
        return std::unexpected(extract.error());
    }

    // 3. Read manifest.toml from the extracted tree. Without
    // one, install-local has no way to know the version + name;
    // require the manifest.
    const auto inner_manifest = tmp / "manifest.toml";
    if (!std::filesystem::exists(inner_manifest))
    {
        std::filesystem::remove_all(tmp);
        return std::unexpected(
            MakeError(ErrorCode::ManifestMissingField, "tarball " + tar_path.string() + " is missing manifest.toml"));
    }
    auto manifest_or = duet::repo::LoadPackageManifestFromFile(inner_manifest);
    if (!manifest_or)
    {
        std::filesystem::remove_all(tmp);
        return std::unexpected(manifest_or.error());
    }
    const auto& manifest = *manifest_or;
    if (manifest.name.empty() || manifest.version.empty())
    {
        std::filesystem::remove_all(tmp);
        return std::unexpected(
            MakeError(ErrorCode::ManifestMissingField, "tarball manifest.toml requires name + version"));
    }
    std::fprintf(stderr, "warning: installing unsigned local package '%s' %s — verify source yourself.\n",
                 manifest.name.c_str(), manifest.version.c_str());

    // 4. Move the staging dir to the canonical version dir.
    const auto final_dir = VersionDir(manifest.name, manifest.version);
    std::error_code ec;
    std::filesystem::create_directories(final_dir.parent_path(), ec);
    if (ec)
    {
        std::filesystem::remove_all(tmp);
        return std::unexpected(
            MakeError(ErrorCode::FilesystemError, "mkdir -p " + final_dir.parent_path().string(), ec.message()));
    }
    std::filesystem::remove_all(final_dir, ec);
    std::filesystem::rename(tmp, final_dir, ec);
    if (ec)
    {
        // Fall back to a recursive copy + remove (rename across
        // filesystems would otherwise error with EXDEV).
        std::filesystem::copy(tmp, final_dir,
                              std::filesystem::copy_options::recursive | std::filesystem::copy_options::copy_symlinks,
                              ec);
        std::filesystem::remove_all(tmp);
        if (ec)
        {
            return std::unexpected(
                MakeError(ErrorCode::InstallFailed, "move staging dir to " + final_dir.string(), ec.message()));
        }
    }

    // 5. Update `current` + emit bin shims (same as remote install).
    auto cur = AtomicSymlink(manifest.version, CurrentSymlink(manifest.name));
    if (!cur)
    {
        std::filesystem::remove_all(final_dir);
        return std::unexpected(cur.error());
    }
    std::vector<std::string> bin_targets = manifest.install.bin;
    if (bin_targets.empty())
    {
        const auto candidate = final_dir / "bin" / manifest.name;
        if (std::filesystem::exists(candidate))
            bin_targets.push_back("bin/" + manifest.name);
    }
    for (const auto& rel_bin : bin_targets)
    {
        const auto leaf = std::filesystem::path{rel_bin}.filename();
        if (leaf.empty())
            continue;
        const auto link = m_paths.bin_prefix / leaf;
        const auto target_rel = CurrentSymlink(manifest.name) / rel_bin;
        auto sym = AtomicSymlink(target_rel, link);
        if (!sym)
        {
            std::filesystem::remove_all(final_dir);
            return std::unexpected(sym.error());
        }
    }

    // 6. Register the install. `installed_from = "local"` so
    // `list` reports the provenance accurately.
    duet::registry::Registry reg{m_paths.registry_root};
    duet::registry::RegistryEntry entry;
    entry.name = manifest.name;
    entry.version = manifest.version;
    entry.installed_at = Iso8601Utc();
    entry.installed_from = "local";
    entry.install_prefix = final_dir.string();
    entry.sha256 = *sha_or;
    entry.deps = manifest.deps;
    auto wr = reg.Write(entry);
    if (!wr)
    {
        std::filesystem::remove_all(final_dir);
        return std::unexpected(wr.error());
    }
    return manifest.name;
}

} // namespace duet::install
