// Hosted hostile-policy coverage for core/service_protocol_policy.{h,cpp}.

#include "host_test_helper.h"

#include "core/service_protocol_policy.h"
#include "core/serviced_protocol.h"
#include "drivers/video/gui_broker_protocol.h"
#include "loader/execd_protocol.h"

namespace
{

using duetos::u32;
using duetos::u64;
using namespace duetos::core;

constexpr u64 Method(u32 id)
{
    return 1ULL << (id - 1U);
}

ServiceManifestServiceV1 Service(u64 identity, u32 selector = kServiceProtocolImmutablePolicyV1)
{
    ServiceManifestServiceV1 service{};
    service.service_identity = identity;
    service.immutable_policy_selector = selector;
    return service;
}

void ExpectNoPolicy(const ServiceProtocolPolicyResolveResult& result, ServiceProtocolPolicyStatus status)
{
    EXPECT_EQ(result.status, status);
    EXPECT_EQ(result.policy.protocol_identity, 0ULL);
    EXPECT_EQ(result.policy.service_identity, 0ULL);
    EXPECT_EQ(result.policy.allowed_methods, 0ULL);
    EXPECT_EQ(result.policy.protocol_version, 0U);
    EXPECT_EQ(result.policy.wire_service_id, 0U);
}

} // namespace

int main()
{
    using namespace duetos::core;

    ExpectNoPolicy(ServiceProtocolPolicyResolveV1(Service(0), CapSetEmpty()),
                   ServiceProtocolPolicyStatus::InvalidArgument);
    ExpectNoPolicy(ServiceProtocolPolicyResolveV1(Service(kServicedManifestServiceIdentityV1, 0), CapSetEmpty()),
                   ServiceProtocolPolicyStatus::InvalidArgument);
    ExpectNoPolicy(ServiceProtocolPolicyResolveV1(Service(kServicedManifestServiceIdentityV1, 2), CapSetTrusted()),
                   ServiceProtocolPolicyStatus::NotSupported);
    ExpectNoPolicy(ServiceProtocolPolicyResolveV1(Service(0xDEAD), CapSetTrusted()),
                   ServiceProtocolPolicyStatus::NotSupported);
    ExpectNoPolicy(ServiceProtocolPolicyResolveV1(Service(kRegistrydManifestServiceIdentityV1), CapSetTrusted()),
                   ServiceProtocolPolicyStatus::NotSupported);
    ExpectNoPolicy(ServiceProtocolPolicyResolveV1(Service(kNetdManifestServiceIdentityV1), CapSetTrusted()),
                   ServiceProtocolPolicyStatus::NotSupported);

    const ServiceProtocolPolicyResolveResult serviced =
        ServiceProtocolPolicyResolveV1(Service(kServicedManifestServiceIdentityV1), CapSetEmpty());
    ASSERT_TRUE(serviced.status == ServiceProtocolPolicyStatus::Ok);
    EXPECT_EQ(serviced.policy.service_identity, kServicedManifestServiceIdentityV1);
    EXPECT_EQ(serviced.policy.protocol_identity, static_cast<u64>(kServicedServiceId));
    EXPECT_EQ(serviced.policy.wire_service_id, kServicedServiceId);
    EXPECT_EQ(serviced.policy.protocol_version, static_cast<u32>(kServicedProtocolVersion1));
    EXPECT_EQ(serviced.policy.allowed_methods, Method(1) | Method(2));
    EXPECT_EQ(serviced.policy.allowed_methods & (Method(3) | Method(4) | Method(5)), 0ULL);

    ExpectNoPolicy(ServiceProtocolPolicyResolveV1(Service(kExecdManifestServiceIdentityV1), CapSetEmpty()),
                   ServiceProtocolPolicyStatus::AccessDenied);
    CapSet fs_read = CapSetEmpty();
    CapSetAdd(fs_read, kCapFsRead);
    const ServiceProtocolPolicyResolveResult execd =
        ServiceProtocolPolicyResolveV1(Service(kExecdManifestServiceIdentityV1), fs_read);
    ASSERT_TRUE(execd.status == ServiceProtocolPolicyStatus::Ok);
    EXPECT_EQ(execd.policy.protocol_identity, static_cast<u64>(duetos::loader::kExecdServiceId));
    EXPECT_EQ(execd.policy.wire_service_id, duetos::loader::kExecdServiceId);
    EXPECT_EQ(execd.policy.allowed_methods, Method(duetos::loader::kExecdParseMethodId));

    const ServiceProtocolPolicyResolveResult displayd =
        ServiceProtocolPolicyResolveV1(Service(kDisplaydManifestServiceIdentityV1), CapSetEmpty());
    ASSERT_TRUE(displayd.status == ServiceProtocolPolicyStatus::Ok);
    EXPECT_EQ(displayd.policy.protocol_identity, static_cast<u64>(duetos::drivers::video::kGuiBrokerServiceId));
    EXPECT_EQ(displayd.policy.wire_service_id, duetos::drivers::video::kGuiBrokerServiceId);
    EXPECT_EQ(displayd.policy.allowed_methods, Method(static_cast<u32>(duetos::drivers::video::GuiBrokerMethod::Post)));
    EXPECT_EQ(displayd.policy.allowed_methods & (Method(1) | Method(2)), 0ULL);

    const ServiceProtocolPolicyBindResult exhausted = ServiceProtocolPolicyBindV1(serviced.policy, 0);
    EXPECT_EQ(exhausted.status, ServiceProtocolPolicyStatus::AuthorityIdentityExhausted);
    EXPECT_EQ(exhausted.authority.authority_identity, 0ULL);

    ServiceProtocolRoutePolicy malformed = serviced.policy;
    malformed.allowed_methods = 0;
    EXPECT_EQ(ServiceProtocolPolicyBindV1(malformed, 1).status, ServiceProtocolPolicyStatus::InvalidArgument);
    malformed = serviced.policy;
    malformed.protocol_version = kServiceEndpointProtocolVersionMaximum + 1U;
    EXPECT_EQ(ServiceProtocolPolicyBindV1(malformed, 1).status, ServiceProtocolPolicyStatus::InvalidArgument);

    const ServiceProtocolPolicyBindResult bound = ServiceProtocolPolicyBindV1(serviced.policy, 0xA110);
    ASSERT_TRUE(bound.status == ServiceProtocolPolicyStatus::Ok);
    EXPECT_EQ(bound.authority.authority_identity, 0xA110ULL);
    EXPECT_EQ(bound.authority.protocol_identity, serviced.policy.protocol_identity);
    EXPECT_EQ(bound.authority.service_identity, serviced.policy.service_identity);
    EXPECT_EQ(bound.authority.allowed_methods, serviced.policy.allowed_methods);
    EXPECT_EQ(bound.authority.protocol_version, serviced.policy.protocol_version);
    EXPECT_EQ(bound.authority.flags, 0U);
    EXPECT_EQ(bound.authority.wire_service_id, serviced.policy.wire_service_id);
    EXPECT_EQ(bound.authority.reserved32, 0U);

    EXPECT_STREQ(ServiceProtocolPolicyStatusName(ServiceProtocolPolicyStatus::AccessDenied), "AccessDenied");
    return duetos_host_test::finish_main("service_protocol_policy");
}
