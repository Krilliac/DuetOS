// duet-pkg-pack — Phase 7 packaging tool for repo maintainers.
//
// Usage:
//   duet-pkg-pack create --name <name> --version <ver>
//                         --bin <path>      (repeatable)
//                         [--lib <path>]    (repeatable)
//                         [--share <path>]  (repeatable)
//                         [--desc <text>]
//                         [--license <id>]
//                         [--source-url <url>]
//                         [--dep <name>]    (repeatable)
//                         [--key <pem-path> | env DUETOS_SIGNING_KEY=<pem-path>]
//                         [--repo-url <prefix>]   default: "" (relative to base_url)
//                         [--out-dir <dir>]       default: cwd
//
// Produces in <out-dir>:
//   <name>-<version>-x86_64.tar.gz
//   <name>-<version>-x86_64.tar.gz.sig
// AND prints to stdout the [[packages]] block to paste into repo.toml.
//
// The signing key is an Ed25519 private key in PEM form
// (`openssl genpkey -algorithm ed25519`). The 32 raw private-key
// bytes live inside the PEM; we extract them via the same SPKI-
// style header walk we use for the public-key loader.

#include "crypto/keying.hpp"
#include "crypto/verifier.hpp"
#include "error.hpp"

#include <sodium.h>

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <random>
#include <span>
#include <sstream>
#include <string>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

namespace
{

constexpr std::string_view kPemBegin = "-----BEGIN PRIVATE KEY-----";
constexpr std::string_view kPemEnd = "-----END PRIVATE KEY-----";

// Ed25519 PKCS#8 v1 PrivateKeyInfo (RFC 8410):
//   SEQUENCE { INTEGER 0, AlgorithmIdentifier ed25519,
//              OCTET STRING { OCTET STRING { key } } }
// The PEM body is a 48-byte DER blob; bytes 16..47 are the
// 32-byte raw seed.
constexpr std::array<std::uint8_t, 16> kEd25519PkInfoHeader = {
    0x30, 0x2E, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
};

struct PrivateKey
{
    // libsodium's ed25519 secret-key form: seed (32 bytes) is
    // expanded into a 64-byte sk used by crypto_sign_detached.
    std::array<std::uint8_t, 32> seed{};
    std::array<std::uint8_t, 32> public_key{};
    std::array<std::uint8_t, 64> sk{};
};

[[nodiscard]] duet::Expected<PrivateKey> LoadPrivateKey(const std::filesystem::path& path)
{
    std::ifstream in{path, std::ios::binary};
    if (!in.is_open())
        return std::unexpected(
            duet::MakeError(duet::ErrorCode::FilesystemError, "cannot open private key: " + path.string()));
    std::ostringstream buf;
    buf << in.rdbuf();
    const std::string body = buf.str();
    const auto bo = body.find(kPemBegin);
    if (bo == std::string::npos)
        return std::unexpected(
            duet::MakeError(duet::ErrorCode::SignatureInvalid, "PEM: missing BEGIN PRIVATE KEY marker"));
    const auto be = bo + kPemBegin.size();
    const auto eo = body.find(kPemEnd, be);
    if (eo == std::string::npos)
        return std::unexpected(
            duet::MakeError(duet::ErrorCode::SignatureInvalid, "PEM: missing END PRIVATE KEY marker"));
    std::string_view b64{body.data() + be, eo - be};
    auto der = duet::crypto::Base64Decode(b64);
    if (!der)
        return std::unexpected(der.error());
    if (der->size() != kEd25519PkInfoHeader.size() + 32)
        return std::unexpected(
            duet::MakeError(duet::ErrorCode::SignatureInvalid, "PEM private-key body not an Ed25519 PKCS#8 v1"));
    for (std::size_t i = 0; i < kEd25519PkInfoHeader.size(); ++i)
    {
        if ((*der)[i] != kEd25519PkInfoHeader[i])
        {
            return std::unexpected(duet::MakeError(duet::ErrorCode::SignatureInvalid,
                                                   "PEM private-key header is not the Ed25519 PKCS#8 prefix"));
        }
    }
    PrivateKey out{};
    std::memcpy(out.seed.data(), der->data() + kEd25519PkInfoHeader.size(), 32);
    crypto_sign_seed_keypair(out.public_key.data(), out.sk.data(), out.seed.data());
    return out;
}

struct CliArgs
{
    std::string name;
    std::string version;
    std::string desc;
    std::string license;
    std::string source_url;
    std::string repo_url; // optional path prefix prepended to binary_url
    std::vector<std::string> bins;
    std::vector<std::string> libs;
    std::vector<std::string> shares;
    std::vector<std::string> deps;
    std::string key_path;
    std::string out_dir;
};

[[nodiscard]] bool ParseArgs(int argc, char** argv, CliArgs& out)
{
    if (argc < 2 || std::string{argv[1]} != "create")
    {
        std::fprintf(stderr, "usage: duet-pkg-pack create --name <n> --version <v> --bin <path> ...\n");
        return false;
    }
    auto take = [&](int& i, const char* /*flag*/) -> const char*
    {
        if (i + 1 >= argc)
            return nullptr;
        return argv[++i];
    };
    for (int i = 2; i < argc; ++i)
    {
        std::string_view a = argv[i];
        if (a == "--name")
        {
            const char* v = take(i, "--name");
            if (!v)
                return false;
            out.name = v;
        }
        else if (a == "--version")
        {
            const char* v = take(i, "--version");
            if (!v)
                return false;
            out.version = v;
        }
        else if (a == "--desc")
        {
            const char* v = take(i, "--desc");
            if (!v)
                return false;
            out.desc = v;
        }
        else if (a == "--license")
        {
            const char* v = take(i, "--license");
            if (!v)
                return false;
            out.license = v;
        }
        else if (a == "--source-url")
        {
            const char* v = take(i, "--source-url");
            if (!v)
                return false;
            out.source_url = v;
        }
        else if (a == "--repo-url")
        {
            const char* v = take(i, "--repo-url");
            if (!v)
                return false;
            out.repo_url = v;
        }
        else if (a == "--bin")
        {
            const char* v = take(i, "--bin");
            if (!v)
                return false;
            out.bins.emplace_back(v);
        }
        else if (a == "--lib")
        {
            const char* v = take(i, "--lib");
            if (!v)
                return false;
            out.libs.emplace_back(v);
        }
        else if (a == "--share")
        {
            const char* v = take(i, "--share");
            if (!v)
                return false;
            out.shares.emplace_back(v);
        }
        else if (a == "--dep")
        {
            const char* v = take(i, "--dep");
            if (!v)
                return false;
            out.deps.emplace_back(v);
        }
        else if (a == "--key")
        {
            const char* v = take(i, "--key");
            if (!v)
                return false;
            out.key_path = v;
        }
        else if (a == "--out-dir")
        {
            const char* v = take(i, "--out-dir");
            if (!v)
                return false;
            out.out_dir = v;
        }
        else
        {
            std::fprintf(stderr, "duet-pkg-pack: unknown flag: %s\n", argv[i]);
            return false;
        }
    }
    if (out.key_path.empty())
    {
        if (const char* env = std::getenv("DUETOS_SIGNING_KEY"))
            out.key_path = env;
    }
    if (out.name.empty() || out.version.empty() || out.bins.empty())
    {
        std::fprintf(stderr, "duet-pkg-pack: --name, --version, and at least one --bin are required\n");
        return false;
    }
    if (out.key_path.empty())
    {
        std::fprintf(stderr, "duet-pkg-pack: --key <pem> or DUETOS_SIGNING_KEY env required\n");
        return false;
    }
    if (out.out_dir.empty())
        out.out_dir = std::filesystem::current_path().string();
    return true;
}

[[nodiscard]] bool CopyExecutable(const std::filesystem::path& src, const std::filesystem::path& dest)
{
    std::error_code ec;
    std::filesystem::create_directories(dest.parent_path(), ec);
    std::filesystem::copy_file(src, dest, std::filesystem::copy_options::overwrite_existing, ec);
    if (ec)
    {
        std::fprintf(stderr, "duet-pkg-pack: copy %s -> %s failed: %s\n", src.c_str(), dest.c_str(),
                     ec.message().c_str());
        return false;
    }
    // Preserve / set exec bit. We don't trust the source's mode
    // (it may have been built into a temp dir with restricted
    // perms); enforce 0755.
    if (::chmod(dest.c_str(), 0755) != 0)
        return false;
    return true;
}

[[nodiscard]] bool RunCmd(const std::vector<std::string>& argv, const std::filesystem::path& cwd)
{
    std::vector<char*> c;
    for (const auto& s : argv)
        c.push_back(const_cast<char*>(s.c_str()));
    c.push_back(nullptr);
    pid_t pid = fork();
    if (pid < 0)
        return false;
    if (pid == 0)
    {
        if (!cwd.empty())
            ::chdir(cwd.c_str());
        ::execvp(c[0], c.data());
        std::_Exit(127);
    }
    int st = 0;
    ::waitpid(pid, &st, 0);
    return WIFEXITED(st) && WEXITSTATUS(st) == 0;
}

int Run(int argc, char** argv)
{
    CliArgs a;
    if (!ParseArgs(argc, argv, a))
        return 2;

    if (sodium_init() < 0)
    {
        std::fprintf(stderr, "duet-pkg-pack: libsodium init failed\n");
        return 1;
    }

    auto pk_or = LoadPrivateKey(a.key_path);
    if (!pk_or)
    {
        std::fprintf(stderr, "duet-pkg-pack: %s\n", pk_or.error().message.c_str());
        return 1;
    }
    const auto& sk = *pk_or;

    // Stage the package layout.
    static std::mt19937_64 rng{std::random_device{}()};
    const auto stage = std::filesystem::temp_directory_path() / ("duet-pkg-pack-" + std::to_string(rng()));
    std::filesystem::create_directories(stage);
    for (const auto& bin : a.bins)
    {
        const std::filesystem::path src{bin};
        if (!CopyExecutable(src, stage / "bin" / src.filename()))
        {
            std::filesystem::remove_all(stage);
            return 1;
        }
    }
    for (const auto& lib : a.libs)
    {
        const std::filesystem::path src{lib};
        std::error_code ec;
        std::filesystem::create_directories(stage / "lib", ec);
        std::filesystem::copy_file(src, stage / "lib" / src.filename(),
                                   std::filesystem::copy_options::overwrite_existing, ec);
        if (ec)
        {
            std::fprintf(stderr, "duet-pkg-pack: copy lib failed: %s\n", ec.message().c_str());
            std::filesystem::remove_all(stage);
            return 1;
        }
    }
    for (const auto& share : a.shares)
    {
        const std::filesystem::path src{share};
        std::error_code ec;
        std::filesystem::create_directories(stage / "share", ec);
        std::filesystem::copy(
            src, stage / "share" / src.filename(),
            std::filesystem::copy_options::recursive | std::filesystem::copy_options::overwrite_existing, ec);
        if (ec)
        {
            std::fprintf(stderr, "duet-pkg-pack: copy share failed: %s\n", ec.message().c_str());
            std::filesystem::remove_all(stage);
            return 1;
        }
    }

    // Write manifest.toml inside the stage.
    {
        std::ofstream m{stage / "manifest.toml"};
        m << "name = \"" << a.name << "\"\n";
        m << "version = \"" << a.version << "\"\n";
        m << "arch = \"x86_64\"\n";
        if (!a.desc.empty())
            m << "description = \"" << a.desc << "\"\n";
        if (!a.license.empty())
            m << "license = \"" << a.license << "\"\n";
        if (!a.source_url.empty())
            m << "source_url = \"" << a.source_url << "\"\n";
        m << "deps = [";
        for (std::size_t i = 0; i < a.deps.size(); ++i)
        {
            if (i)
                m << ", ";
            m << "\"" << a.deps[i] << "\"";
        }
        m << "]\n";
        m << "[install]\n";
        m << "bin = [";
        bool first = true;
        for (const auto& b : a.bins)
        {
            if (!first)
                m << ", ";
            first = false;
            m << "\"bin/" << std::filesystem::path{b}.filename().string() << "\"";
        }
        m << "]\n";
        if (!a.libs.empty())
        {
            m << "lib = [";
            first = true;
            for (const auto& l : a.libs)
            {
                if (!first)
                    m << ", ";
                first = false;
                m << "\"lib/" << std::filesystem::path{l}.filename().string() << "\"";
            }
            m << "]\n";
        }
        if (!a.shares.empty())
        {
            m << "share = [";
            first = true;
            for (const auto& s : a.shares)
            {
                if (!first)
                    m << ", ";
                first = false;
                m << "\"share/" << std::filesystem::path{s}.filename().string() << "\"";
            }
            m << "]\n";
        }
    }

    // Tar the stage.
    std::filesystem::create_directories(a.out_dir);
    const std::filesystem::path tar_path =
        std::filesystem::path{a.out_dir} / (a.name + "-" + a.version + "-x86_64.tar.gz");
    if (!RunCmd({"tar", "-czf", tar_path.string(), "-C", stage.string(), "."}, {}))
    {
        std::fprintf(stderr, "duet-pkg-pack: tar failed\n");
        std::filesystem::remove_all(stage);
        return 1;
    }

    // SHA-256 + sign.
    auto sha = duet::crypto::Sha256HexOfFile(tar_path);
    if (!sha)
    {
        std::fprintf(stderr, "duet-pkg-pack: hash failed\n");
        std::filesystem::remove_all(stage);
        return 1;
    }
    std::ifstream tar_in{tar_path, std::ios::binary};
    std::vector<std::uint8_t> tar_bytes((std::istreambuf_iterator<char>(tar_in)), std::istreambuf_iterator<char>());
    tar_in.close();
    std::array<std::uint8_t, 64> sig{};
    crypto_sign_detached(sig.data(), nullptr, tar_bytes.data(), tar_bytes.size(), sk.sk.data());
    const std::filesystem::path sig_path = tar_path.string() + ".sig";
    {
        std::ofstream so{sig_path, std::ios::binary | std::ios::trunc};
        so.write(reinterpret_cast<const char*>(sig.data()), static_cast<std::streamsize>(sig.size()));
    }

    // Public-key fingerprint (lets the maintainer pin it in
    // their repo's signing_key + downstream --trust-key flags).
    duet::crypto::PublicKey pk{};
    pk.bytes = sk.public_key;
    const std::string pk_toml = duet::crypto::PublicKeyToTomlString(pk);
    const std::string fp = duet::crypto::Fingerprint(pk);

    // Compose the repo.toml [[packages]] block and emit it.
    const std::string binary_url =
        a.repo_url.empty() ? tar_path.filename().string() : a.repo_url + "/" + tar_path.filename().string();
    std::printf("\n# ---------- paste the block below into your repo.toml ----------\n");
    std::printf("[[packages]]\n");
    std::printf("name        = \"%s\"\n", a.name.c_str());
    std::printf("version     = \"%s\"\n", a.version.c_str());
    std::printf("arch        = \"x86_64\"\n");
    if (!a.desc.empty())
        std::printf("description = \"%s\"\n", a.desc.c_str());
    if (!a.license.empty())
        std::printf("license     = \"%s\"\n", a.license.c_str());
    if (!a.source_url.empty())
        std::printf("source_url  = \"%s\"\n", a.source_url.c_str());
    std::printf("deps        = [");
    for (std::size_t i = 0; i < a.deps.size(); ++i)
    {
        if (i)
            std::printf(", ");
        std::printf("\"%s\"", a.deps[i].c_str());
    }
    std::printf("]\n");
    std::printf("binary_url  = \"%s\"\n", binary_url.c_str());
    std::printf("sha256      = \"%s\"\n", sha->c_str());
    std::printf("# ----------------------------------------------------------------\n\n");
    std::printf("# public-key fingerprint for --trust-key:\n");
    std::printf("#   %s\n", fp.c_str());
    std::printf("# repo signing_key value:\n");
    std::printf("#   %s\n", pk_toml.c_str());
    std::printf("\n");
    std::printf("# tarball : %s\n", tar_path.string().c_str());
    std::printf("# sig     : %s\n", sig_path.string().c_str());

    std::filesystem::remove_all(stage);
    return 0;
}

} // namespace

int main(int argc, char** argv)
{
    return Run(argc, argv);
}
