#pragma once

/*
 * Trusted route-policy resolver for live ServiceEndpoint connections.
 *
 * A public CONNECT request names only one stable manifest service identity.
 * It never supplies protocol authority.  This resolver consumes a row from
 * the already-sealed kernel manifest and intersects its fixed protocol
 * maximum with the caller's kernel-snapshotted capabilities.  The resulting
 * policy is still only a transport route ceiling; each service must continue
 * to authenticate the endpoint peer and any protocol-specific authority.
 */

#include "core/service_endpoint.h"
#include "core/service_manifest.h"
#include "proc/process.h"
#include "util/types.h"

namespace duetos::core
{

inline constexpr u64 kServicedManifestServiceIdentityV1 = 0x100;
inline constexpr u64 kExecdManifestServiceIdentityV1 = 0x200;
inline constexpr u64 kDisplaydManifestServiceIdentityV1 = 0x300;
inline constexpr u64 kRegistrydManifestServiceIdentityV1 = 0x400;
inline constexpr u64 kNetdManifestServiceIdentityV1 = 0x500;
inline constexpr u32 kServiceProtocolImmutablePolicyV1 = 1;

enum class ServiceProtocolPolicyStatus : u8
{
    Ok = 0,
    InvalidArgument,
    NotSupported,
    AccessDenied,
    AuthorityIdentityExhausted,
};

// Authority identity is intentionally absent.  A caller must first resolve a
// supported policy, verify the live directory row, and only then consume a
// non-wrapping kernel authority identity.
struct ServiceProtocolRoutePolicy
{
    u64 protocol_identity;
    u64 service_identity;
    u64 allowed_methods;
    u32 protocol_version;
    u32 wire_service_id;
};

struct [[nodiscard]] ServiceProtocolPolicyResolveResult
{
    ServiceProtocolPolicyStatus status;
    ServiceProtocolRoutePolicy policy;
};

struct [[nodiscard]] ServiceProtocolPolicyBindResult
{
    ServiceProtocolPolicyStatus status;
    ServiceEndpointProtocolAuthority authority;
};

// `service` must be a borrowed row from the sealed manifest retained by the
// bound ServiceRuntime. Unknown identity/selector pairs fail closed.
ServiceProtocolPolicyResolveResult ServiceProtocolPolicyResolveV1(const ServiceManifestServiceV1& service,
                                                                  CapSet caller_capabilities);

// Bind a successfully-resolved policy to one freshly-minted, nonzero kernel
// identity. The wire never supplies or observes this identity.
ServiceProtocolPolicyBindResult ServiceProtocolPolicyBindV1(const ServiceProtocolRoutePolicy& policy,
                                                            u64 authority_identity);

const char* ServiceProtocolPolicyStatusName(ServiceProtocolPolicyStatus status);

} // namespace duetos::core
