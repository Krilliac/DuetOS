#include "core/service_protocol_policy.h"

#include "core/serviced_protocol.h"
#include "drivers/video/gui_broker_protocol.h"
#include "loader/execd_protocol.h"

namespace duetos::core
{

namespace
{

constexpr u64 MethodBit(u32 method_id)
{
    return method_id >= 1 && method_id <= 64 ? 1ULL << (method_id - 1U) : 0;
}

constexpr ServiceProtocolPolicyResolveResult Failure(ServiceProtocolPolicyStatus status)
{
    return {status, {}};
}

constexpr bool PolicyIsCanonical(const ServiceProtocolRoutePolicy& policy)
{
    return policy.protocol_identity != 0 && policy.service_identity != 0 && policy.allowed_methods != 0 &&
           policy.protocol_version >= 1 && policy.protocol_version <= kServiceEndpointProtocolVersionMaximum &&
           policy.wire_service_id != 0;
}

constexpr ServiceProtocolRoutePolicy Policy(u64 service_identity, u32 wire_service_id, u32 protocol_version,
                                            u64 allowed_methods)
{
    // The protocol identity is a trusted kernel route-family identity.  It is
    // deliberately distinct from the stable manifest service identity even
    // though its low 32 bits equal the frozen MessageAbi service selector.
    return ServiceProtocolRoutePolicy{static_cast<u64>(wire_service_id), service_identity, allowed_methods,
                                      protocol_version, wire_service_id};
}

} // namespace

ServiceProtocolPolicyResolveResult ServiceProtocolPolicyResolveV1(const ServiceManifestServiceV1& service,
                                                                  CapSet caller_capabilities)
{
    if (service.service_identity == 0 || service.immutable_policy_selector == 0)
        return Failure(ServiceProtocolPolicyStatus::InvalidArgument);
    if (service.immutable_policy_selector != kServiceProtocolImmutablePolicyV1)
        return Failure(ServiceProtocolPolicyStatus::NotSupported);

    ServiceProtocolRoutePolicy policy{};
    switch (service.service_identity)
    {
    case kServicedManifestServiceIdentityV1:
        // Start/Stop/Restart (3..5) require the dedicated service-control
        // capability. Until that capability lands, the transport exposes only
        // non-mutating discovery. Do not alias diagnostic or thread authority.
        policy = Policy(service.service_identity, kServicedServiceId, kServicedProtocolVersion1,
                        MethodBit(static_cast<u32>(ServicedMethod::Enumerate)) |
                            MethodBit(static_cast<u32>(ServicedMethod::Query)));
        break;
    case kExecdManifestServiceIdentityV1:
        // Parsing a source object is the only frozen EXED request route. The
        // caller must retain filesystem-read authority in its kernel snapshot.
        if (!CapSetHas(caller_capabilities, kCapFsRead))
            return Failure(ServiceProtocolPolicyStatus::AccessDenied);
        policy = Policy(service.service_identity, loader::kExecdServiceId, loader::kExecdProtocolVersion1,
                        MethodBit(loader::kExecdParseMethodId));
        break;
    case kDisplaydManifestServiceIdentityV1:
        // Posting is subject to displayd's peer/rule/target policy. Mutating
        // RegisterRule/RevokeRule remain unavailable until a dedicated GUI
        // policy-administration capability exists.
        policy = Policy(service.service_identity, drivers::video::kGuiBrokerServiceId,
                        drivers::video::kGuiBrokerPayloadVersion1,
                        MethodBit(static_cast<u32>(drivers::video::GuiBrokerMethod::Post)));
        break;
    case kRegistrydManifestServiceIdentityV1:
    case kNetdManifestServiceIdentityV1:
        // These services do not yet have frozen MessageAbi route contracts.
        return Failure(ServiceProtocolPolicyStatus::NotSupported);
    default:
        return Failure(ServiceProtocolPolicyStatus::NotSupported);
    }

    return PolicyIsCanonical(policy) ? ServiceProtocolPolicyResolveResult{ServiceProtocolPolicyStatus::Ok, policy}
                                     : Failure(ServiceProtocolPolicyStatus::InvalidArgument);
}

ServiceProtocolPolicyBindResult ServiceProtocolPolicyBindV1(const ServiceProtocolRoutePolicy& policy,
                                                            u64 authority_identity)
{
    if (!PolicyIsCanonical(policy))
        return {ServiceProtocolPolicyStatus::InvalidArgument, {}};
    if (authority_identity == 0)
        return {ServiceProtocolPolicyStatus::AuthorityIdentityExhausted, {}};
    return {ServiceProtocolPolicyStatus::Ok,
            ServiceEndpointProtocolAuthority{authority_identity, policy.protocol_identity, policy.service_identity,
                                             policy.allowed_methods, policy.protocol_version, 0, policy.wire_service_id,
                                             0}};
}

const char* ServiceProtocolPolicyStatusName(ServiceProtocolPolicyStatus status)
{
    switch (status)
    {
    case ServiceProtocolPolicyStatus::Ok:
        return "Ok";
    case ServiceProtocolPolicyStatus::InvalidArgument:
        return "InvalidArgument";
    case ServiceProtocolPolicyStatus::NotSupported:
        return "NotSupported";
    case ServiceProtocolPolicyStatus::AccessDenied:
        return "AccessDenied";
    case ServiceProtocolPolicyStatus::AuthorityIdentityExhausted:
        return "AuthorityIdentityExhausted";
    }
    return "Unknown";
}

} // namespace duetos::core
