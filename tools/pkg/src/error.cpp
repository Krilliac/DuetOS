#include "error.hpp"

namespace duet
{

std::string_view ErrorCodeName(ErrorCode c) noexcept
{
    switch (c)
    {
    case ErrorCode::Ok:
        return "Ok";
    case ErrorCode::ManifestParseFailed:
        return "ManifestParseFailed";
    case ErrorCode::ManifestMissingField:
        return "ManifestMissingField";
    case ErrorCode::ManifestBadType:
        return "ManifestBadType";
    case ErrorCode::RegistryReadFailed:
        return "RegistryReadFailed";
    case ErrorCode::RegistryWriteFailed:
        return "RegistryWriteFailed";
    case ErrorCode::PackageNotFound:
        return "PackageNotFound";
    case ErrorCode::FilesystemError:
        return "FilesystemError";
    case ErrorCode::InvalidArgument:
        return "InvalidArgument";
    case ErrorCode::NetworkError:
        return "NetworkError";
    case ErrorCode::HashMismatch:
        return "HashMismatch";
    case ErrorCode::SignatureInvalid:
        return "SignatureInvalid";
    case ErrorCode::KeyNotTrusted:
        return "KeyNotTrusted";
    case ErrorCode::DependencyCycle:
        return "DependencyCycle";
    case ErrorCode::VersionConflict:
        return "VersionConflict";
    case ErrorCode::InstallFailed:
        return "InstallFailed";
    case ErrorCode::PermissionDenied:
        return "PermissionDenied";
    case ErrorCode::AlreadyInstalled:
        return "AlreadyInstalled";
    }
    return "Unknown";
}

} // namespace duet
