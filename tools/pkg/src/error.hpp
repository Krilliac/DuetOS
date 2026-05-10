#pragma once

#include <expected>
#include <string>
#include <string_view>

/*
 * duet-pkg error-handling primitive.
 *
 * Every fallible function in duet-pkg returns
 * `duet::Expected<T> = std::expected<T, DuetPkgError>`. This mirrors
 * the kernel's `duetos::core::Result<T, E>` discipline, adapted for
 * a hosted binary (we can pay for `std::string` here, the kernel
 * can't).
 *
 * `ErrorCode` is a flat enum class — every error site picks one
 * code plus a human-readable `message` shown to the user, and an
 * optional `detail` shown only under --verbose. Phases beyond 1
 * extend `ErrorCode` rather than rolling a per-subsystem error
 * type.
 */

namespace duet
{

enum class ErrorCode
{
    Ok = 0,
    ManifestParseFailed,
    ManifestMissingField,
    ManifestBadType,
    RegistryReadFailed,
    RegistryWriteFailed,
    PackageNotFound,
    FilesystemError,
    InvalidArgument,
    // Reserved for later phases — listed here so the enum surface
    // stays stable as we grow. Unused codes are inert.
    NetworkError,
    HashMismatch,
    SignatureInvalid,
    KeyNotTrusted,
    DependencyCycle,
    VersionConflict,
    InstallFailed,
    PermissionDenied,
    AlreadyInstalled,
};

[[nodiscard]] std::string_view ErrorCodeName(ErrorCode c) noexcept;

struct DuetPkgError
{
    ErrorCode code = ErrorCode::Ok;
    std::string message;
    std::string detail;
};

inline DuetPkgError MakeError(ErrorCode code, std::string message, std::string detail = {})
{
    return DuetPkgError{code, std::move(message), std::move(detail)};
}

template <class T> using Expected = std::expected<T, DuetPkgError>;

} // namespace duet
