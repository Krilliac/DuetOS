#include "repo/repo_manager.hpp"

#include "crypto/verifier.hpp"
#include "net/fetcher.hpp"

#include <toml++/toml.hpp>

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <utility>
#include <vector>

namespace duet::repo
{
namespace
{

constexpr std::string_view kEnvConfigDir = "DUET_PKG_CONFIG_DIR";
constexpr std::string_view kDefaultConfigDir = "/etc/duet-pkg";

// Conservative filename validator. Same shape as the package-name
// check in registry.cpp — keeps `<name>.toml.sig` safe to compose.
[[nodiscard]] bool IsValidRepoName(std::string_view name) noexcept
{
    if (name.empty() || name.size() > 128)
        return false;
    for (char c : name)
    {
        const bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' ||
                        c == '-' || c == '.';
        if (!ok)
            return false;
    }
    return name != "." && name != "..";
}

[[nodiscard]] bool IsValidFingerprint(std::string_view fp) noexcept
{
    if (fp.size() != 64)
        return false;
    for (char c : fp)
    {
        const bool ok = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
        if (!ok)
            return false;
    }
    return true;
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

[[nodiscard]] Expected<std::vector<std::uint8_t>> SlurpFile(const std::filesystem::path& path)
{
    std::ifstream in{path, std::ios::binary};
    if (!in.is_open())
    {
        return std::unexpected(MakeError(ErrorCode::FilesystemError, "cannot open " + path.string()));
    }
    in.seekg(0, std::ios::end);
    const auto sz = in.tellg();
    in.seekg(0, std::ios::beg);
    if (sz < 0)
    {
        return std::unexpected(MakeError(ErrorCode::FilesystemError, "tellg failed " + path.string()));
    }
    std::vector<std::uint8_t> out(static_cast<std::size_t>(sz));
    if (sz > 0)
    {
        in.read(reinterpret_cast<char*>(out.data()), static_cast<std::streamsize>(out.size()));
        if (in.bad())
        {
            return std::unexpected(MakeError(ErrorCode::FilesystemError, "read failed " + path.string()));
        }
    }
    return out;
}

[[nodiscard]] Expected<void> AtomicWrite(const std::filesystem::path& path, std::span<const std::uint8_t> body)
{
    std::error_code ec;
    std::filesystem::create_directories(path.parent_path(), ec);
    if (ec)
    {
        return std::unexpected(
            MakeError(ErrorCode::FilesystemError, "mkdir -p " + path.parent_path().string(), ec.message()));
    }
    auto tmp = path;
    tmp += ".tmp";
    {
        std::ofstream out{tmp, std::ios::binary | std::ios::trunc};
        if (!out.is_open())
        {
            return std::unexpected(MakeError(ErrorCode::FilesystemError, "cannot open " + tmp.string()));
        }
        out.write(reinterpret_cast<const char*>(body.data()), static_cast<std::streamsize>(body.size()));
        if (!out)
        {
            return std::unexpected(MakeError(ErrorCode::FilesystemError, "write failed " + tmp.string()));
        }
    }
    std::filesystem::rename(tmp, path, ec);
    if (ec)
    {
        return std::unexpected(MakeError(ErrorCode::FilesystemError, "rename to " + path.string(), ec.message()));
    }
    return {};
}

[[nodiscard]] Expected<std::vector<std::uint8_t>> DownloadToBytes(std::string_view url, bool allow_insecure)
{
    const auto tmp = std::filesystem::temp_directory_path() /
                     ("duet-pkg-fetch-" + std::to_string(std::hash<std::string>{}(std::string{url})) + ".bin");
    std::filesystem::remove(tmp);
    duet::net::FetchOptions opts;
    opts.allow_insecure = allow_insecure;
    auto rc = duet::net::Download(url, tmp, opts, {});
    if (!rc)
    {
        std::filesystem::remove(tmp);
        return std::unexpected(rc.error());
    }
    auto body = SlurpFile(tmp);
    std::filesystem::remove(tmp);
    return body;
}

[[nodiscard]] std::string SerializeRepoIndex(const std::vector<RepoIndexEntry>& entries)
{
    std::ostringstream out;
    out << "# duet-pkg repo index. Edit via `duet-pkg repo add/remove`.\n";
    for (const auto& e : entries)
    {
        out << "\n[[repo]]\n";
        out << "name               = \"" << e.name << "\"\n";
        out << "url                = \"" << e.url << "\"\n";
        out << "trust_fingerprint  = \"" << e.trust_fingerprint << "\"\n";
        out << "last_synced        = \"" << e.last_synced << "\"\n";
        out << "package_count      = " << e.package_count << "\n";
    }
    return out.str();
}

[[nodiscard]] Expected<std::vector<RepoIndexEntry>> ParseRepoIndex(std::string_view body, std::string_view source_label)
{
    std::vector<RepoIndexEntry> out;
    toml::parse_result result = toml::parse(body, source_label);
    if (!result)
    {
        return std::unexpected(MakeError(ErrorCode::ManifestParseFailed,
                                         std::string{source_label} + ": repos.toml parse failed",
                                         std::string{result.error().description()}));
    }
    const auto* arr = result.table().get_as<toml::array>("repo");
    if (arr == nullptr)
    {
        // Empty / no [[repo]] blocks → no active repos.
        return out;
    }
    out.reserve(arr->size());
    for (std::size_t i = 0; i < arr->size(); ++i)
    {
        const auto* t = (*arr)[i].as_table();
        if (t == nullptr)
        {
            return std::unexpected(MakeError(ErrorCode::ManifestBadType,
                                             std::string{source_label} + ": [[repo]] element must be a table"));
        }
        RepoIndexEntry e;
        auto str = [&](const char* key, std::string& dst) -> Expected<void>
        {
            const auto* node = t->get(key);
            if (node == nullptr)
            {
                dst.clear();
                return {};
            }
            const auto* s = node->as_string();
            if (s == nullptr)
            {
                return std::unexpected(MakeError(ErrorCode::ManifestBadType,
                                                 std::string{source_label} + ": [[repo]]." + key + " must be string"));
            }
            dst = std::string{s->get()};
            return {};
        };
        if (auto r = str("name", e.name); !r)
            return std::unexpected(r.error());
        if (auto r = str("url", e.url); !r)
            return std::unexpected(r.error());
        if (auto r = str("trust_fingerprint", e.trust_fingerprint); !r)
            return std::unexpected(r.error());
        if (auto r = str("last_synced", e.last_synced); !r)
            return std::unexpected(r.error());
        if (const auto* node = t->get("package_count"))
        {
            const auto* in_node = node->as_integer();
            if (in_node == nullptr || in_node->get() < 0)
            {
                return std::unexpected(
                    MakeError(ErrorCode::ManifestBadType,
                              std::string{source_label} + ": package_count must be a non-negative integer"));
            }
            e.package_count = static_cast<std::uint64_t>(in_node->get());
        }
        if (e.name.empty())
        {
            return std::unexpected(
                MakeError(ErrorCode::ManifestMissingField, std::string{source_label} + ": [[repo]] missing name"));
        }
        out.push_back(std::move(e));
    }
    return out;
}

[[nodiscard]] std::string TrimUrl(std::string_view url)
{
    while (!url.empty() && (url.back() == '/' || url.back() == ' '))
        url.remove_suffix(1);
    return std::string{url};
}

} // namespace

std::filesystem::path RepoManager::DefaultConfigRoot() noexcept
{
    const char* env = std::getenv(std::string{kEnvConfigDir}.c_str());
    if (env != nullptr && env[0] != '\0')
        return std::filesystem::path{env};
    return std::filesystem::path{std::string{kDefaultConfigDir}};
}

std::filesystem::path RepoManager::RepoBodyPath(std::string_view name) const
{
    return ReposDir() / (std::string{name} + ".toml");
}

std::filesystem::path RepoManager::RepoSigPath(std::string_view name) const
{
    return ReposDir() / (std::string{name} + ".toml.sig");
}

std::filesystem::path RepoManager::TrustedKeyPath(std::string_view fingerprint) const
{
    return KeysDir() / (std::string{fingerprint} + ".pub");
}

Expected<std::vector<RepoIndexEntry>> RepoManager::LoadIndex() const
{
    std::vector<RepoIndexEntry> empty;
    std::error_code ec;
    if (!std::filesystem::exists(IndexPath(), ec))
        return empty;
    auto body = SlurpFile(IndexPath());
    if (!body)
        return std::unexpected(body.error());
    std::string body_str{reinterpret_cast<const char*>(body->data()), body->size()};
    return ParseRepoIndex(body_str, IndexPath().string());
}

Expected<void> RepoManager::SaveIndex(const std::vector<RepoIndexEntry>& entries) const
{
    const std::string body = SerializeRepoIndex(entries);
    return AtomicWrite(IndexPath(),
                       std::span<const std::uint8_t>{reinterpret_cast<const std::uint8_t*>(body.data()), body.size()});
}

Expected<std::vector<std::string>> RepoManager::ListTrustedFingerprints() const
{
    std::vector<std::string> out;
    std::error_code ec;
    if (!std::filesystem::exists(KeysDir(), ec))
        return out;
    for (const auto& de : std::filesystem::directory_iterator{KeysDir(), ec})
    {
        if (ec)
        {
            return std::unexpected(
                MakeError(ErrorCode::FilesystemError, "directory_iterator " + KeysDir().string(), ec.message()));
        }
        if (!de.is_regular_file())
            continue;
        const auto& p = de.path();
        if (p.extension() != ".pub")
            continue;
        const auto stem = p.stem().string();
        if (IsValidFingerprint(stem))
            out.push_back(stem);
    }
    std::sort(out.begin(), out.end());
    return out;
}

Expected<crypto::PublicKey> RepoManager::LoadTrustedKey(std::string_view fingerprint) const
{
    if (!IsValidFingerprint(fingerprint))
    {
        return std::unexpected(MakeError(ErrorCode::KeyNotTrusted, "bad fingerprint: " + std::string{fingerprint}));
    }
    auto body = SlurpFile(TrustedKeyPath(fingerprint));
    if (!body)
        return std::unexpected(body.error());
    std::string body_str{reinterpret_cast<const char*>(body->data()), body->size()};
    // Trim any trailing whitespace from the file so a "echo
    // ed25519:..." round trip stays canonical.
    while (!body_str.empty() && (body_str.back() == '\n' || body_str.back() == ' '))
        body_str.pop_back();
    return crypto::ParsePublicKeyFromTomlString(body_str);
}

Expected<void> RepoManager::SaveTrustedKey(const crypto::PublicKey& key) const
{
    const std::string fp = crypto::Fingerprint(key);
    const std::string body = crypto::PublicKeyToTomlString(key) + "\n";
    return AtomicWrite(TrustedKeyPath(fp),
                       std::span<const std::uint8_t>{reinterpret_cast<const std::uint8_t*>(body.data()), body.size()});
}

Expected<void> RepoManager::RemoveTrustedKey(std::string_view fingerprint) const
{
    if (!IsValidFingerprint(fingerprint))
    {
        return std::unexpected(MakeError(ErrorCode::KeyNotTrusted, "bad fingerprint: " + std::string{fingerprint}));
    }
    const auto path = TrustedKeyPath(fingerprint);
    std::error_code ec;
    if (!std::filesystem::exists(path, ec))
    {
        return std::unexpected(
            MakeError(ErrorCode::PackageNotFound, "fingerprint not in trust DB: " + std::string{fingerprint}));
    }
    std::filesystem::remove(path, ec);
    if (ec)
    {
        return std::unexpected(MakeError(ErrorCode::FilesystemError, "remove " + path.string(), ec.message()));
    }
    return {};
}

Expected<RepoIndexEntry> RepoManager::Add(std::string_view url, std::string_view trust_fingerprint, bool allow_insecure,
                                          bool force_replace)
{
    if (!IsValidFingerprint(trust_fingerprint))
    {
        return std::unexpected(MakeError(ErrorCode::KeyNotTrusted, "--trust-key must be 64 lowercase hex chars: " +
                                                                       std::string{trust_fingerprint}));
    }
    const std::string base = TrimUrl(url);
    const std::string body_url = base + "/repo.toml";
    const std::string sig_url = base + "/repo.toml.sig";

    auto body = DownloadToBytes(body_url, allow_insecure);
    if (!body)
        return std::unexpected(body.error());
    auto sig = DownloadToBytes(sig_url, allow_insecure);
    if (!sig)
        return std::unexpected(sig.error());

    // Parse the manifest to extract signing_key + name.
    std::string body_str{reinterpret_cast<const char*>(body->data()), body->size()};
    auto manifest_or = LoadRepoManifestFromString(body_str, body_url);
    if (!manifest_or)
        return std::unexpected(manifest_or.error());
    const auto& manifest = *manifest_or;
    if (manifest.name.empty())
    {
        return std::unexpected(MakeError(ErrorCode::ManifestMissingField, body_url + ": [repo].name is empty"));
    }
    if (!IsValidRepoName(manifest.name))
    {
        return std::unexpected(MakeError(ErrorCode::InvalidArgument,
                                         body_url + ": repo name '" + manifest.name + "' contains illegal chars"));
    }
    if (manifest.signing_key.empty())
    {
        return std::unexpected(MakeError(ErrorCode::SignatureInvalid, body_url + ": [repo].signing_key is required"));
    }
    auto key_or = crypto::ParsePublicKeyFromTomlString(manifest.signing_key);
    if (!key_or)
        return std::unexpected(key_or.error());
    const std::string actual_fp = crypto::Fingerprint(*key_or);
    if (actual_fp != trust_fingerprint)
    {
        return std::unexpected(MakeError(ErrorCode::KeyNotTrusted,
                                         "repo signing-key fingerprint does not match --trust-key",
                                         "expected=" + std::string{trust_fingerprint} + " actual=" + actual_fp));
    }
    auto verify =
        crypto::VerifySignature(*body, *sig, std::span<const std::uint8_t>{key_or->bytes.data(), key_or->bytes.size()});
    if (!verify)
        return std::unexpected(verify.error());

    auto index_or = LoadIndex();
    if (!index_or)
        return std::unexpected(index_or.error());
    auto index = *index_or;
    auto existing =
        std::find_if(index.begin(), index.end(), [&](const RepoIndexEntry& e) { return e.name == manifest.name; });
    if (existing != index.end() && !force_replace)
    {
        return std::unexpected(
            MakeError(ErrorCode::AlreadyInstalled,
                      "repo '" + manifest.name + "' is already registered; pass --force to replace"));
    }

    // Persist body, sig, key.
    auto wr_body = AtomicWrite(RepoBodyPath(manifest.name), *body);
    if (!wr_body)
        return std::unexpected(wr_body.error());
    auto wr_sig = AtomicWrite(RepoSigPath(manifest.name), *sig);
    if (!wr_sig)
        return std::unexpected(wr_sig.error());
    auto wr_key = SaveTrustedKey(*key_or);
    if (!wr_key)
        return std::unexpected(wr_key.error());

    RepoIndexEntry entry;
    entry.name = manifest.name;
    entry.url = base;
    entry.trust_fingerprint = actual_fp;
    entry.last_synced = Iso8601Utc();
    entry.package_count = static_cast<std::uint64_t>(manifest.packages.size());
    if (existing != index.end())
        *existing = entry;
    else
        index.push_back(entry);
    auto wr_idx = SaveIndex(index);
    if (!wr_idx)
        return std::unexpected(wr_idx.error());
    return entry;
}

Expected<void> RepoManager::Remove(std::string_view name)
{
    if (!IsValidRepoName(name))
    {
        return std::unexpected(MakeError(ErrorCode::InvalidArgument, "bad repo name: " + std::string{name}));
    }
    auto index_or = LoadIndex();
    if (!index_or)
        return std::unexpected(index_or.error());
    auto index = *index_or;
    auto it = std::find_if(index.begin(), index.end(), [&](const RepoIndexEntry& e) { return e.name == name; });
    if (it == index.end())
    {
        return std::unexpected(MakeError(ErrorCode::PackageNotFound, "repo not registered: " + std::string{name}));
    }
    const std::string fp = it->trust_fingerprint;
    index.erase(it);
    std::error_code ec;
    std::filesystem::remove(RepoBodyPath(name), ec);
    std::filesystem::remove(RepoSigPath(name), ec);
    if (!fp.empty())
    {
        std::filesystem::remove(TrustedKeyPath(fp), ec);
    }
    return SaveIndex(index);
}

Expected<std::vector<RepoIndexEntry>> RepoManager::Sync(std::string_view only_name, bool allow_insecure)
{
    auto index_or = LoadIndex();
    if (!index_or)
        return std::unexpected(index_or.error());
    auto& index = *index_or;
    std::vector<RepoIndexEntry> synced;
    for (auto& entry : index)
    {
        if (!only_name.empty() && entry.name != only_name)
            continue;
        const std::string body_url = entry.url + "/repo.toml";
        const std::string sig_url = entry.url + "/repo.toml.sig";
        auto body = DownloadToBytes(body_url, allow_insecure);
        if (!body)
            return std::unexpected(body.error());
        auto sig = DownloadToBytes(sig_url, allow_insecure);
        if (!sig)
            return std::unexpected(sig.error());
        auto key_or = LoadTrustedKey(entry.trust_fingerprint);
        if (!key_or)
            return std::unexpected(key_or.error());
        auto verify = crypto::VerifySignature(
            *body, *sig, std::span<const std::uint8_t>{key_or->bytes.data(), key_or->bytes.size()});
        if (!verify)
            return std::unexpected(verify.error());
        std::string body_str{reinterpret_cast<const char*>(body->data()), body->size()};
        auto manifest_or = LoadRepoManifestFromString(body_str, body_url);
        if (!manifest_or)
            return std::unexpected(manifest_or.error());
        // Optional: detect a name change between cached + remote.
        if (manifest_or->name != entry.name)
        {
            return std::unexpected(
                MakeError(ErrorCode::SignatureInvalid, "sync: remote repo name '" + manifest_or->name +
                                                           "' differs from cached '" + entry.name + "'"));
        }
        auto wr_body = AtomicWrite(RepoBodyPath(entry.name), *body);
        if (!wr_body)
            return std::unexpected(wr_body.error());
        auto wr_sig = AtomicWrite(RepoSigPath(entry.name), *sig);
        if (!wr_sig)
            return std::unexpected(wr_sig.error());
        entry.last_synced = Iso8601Utc();
        entry.package_count = static_cast<std::uint64_t>(manifest_or->packages.size());
        synced.push_back(entry);
    }
    auto save = SaveIndex(index);
    if (!save)
        return std::unexpected(save.error());
    if (!only_name.empty() && synced.empty())
    {
        return std::unexpected(MakeError(ErrorCode::PackageNotFound, "repo not registered: " + std::string{only_name}));
    }
    return synced;
}

Expected<RepoManifest> RepoManager::LoadCachedManifest(std::string_view name) const
{
    if (!IsValidRepoName(name))
    {
        return std::unexpected(MakeError(ErrorCode::InvalidArgument, "bad repo name: " + std::string{name}));
    }
    return LoadRepoManifestFromFile(RepoBodyPath(name));
}

} // namespace duet::repo
