// Hosted exhaustive, hostile-input, and immutable-concurrency coverage for
// drivers/video/gui_message_policy.{h,cpp}.

#include "host_test_helper.h"
#include "drivers/video/gui_message_policy.h"

#include <array>
#include <atomic>
#include <thread>
#include <vector>

namespace
{

using duetos::u32;
using duetos::u64;
using duetos::core::Win32IntegrityLevel;
using namespace duetos::drivers::video;

GuiMessagePrincipalSnapshot Principal(u64 process, u64 task, Win32IntegrityLevel integrity)
{
    GuiMessagePrincipalSnapshot principal{};
    principal.process_identity = process;
    principal.task_identity = task;
    principal.integrity = integrity;
    return principal;
}

GuiMessageRequestSnapshot Request(u32 message = kGuiMessageApplicationFirst, u64 wparam = 0, u64 lparam = 0)
{
    GuiMessageRequestSnapshot request{};
    request.sender = Principal(0x1001, 0x1101, Win32IntegrityLevel::High);
    request.target = Principal(0x2001, 0x2101, Win32IntegrityLevel::Low);
    request.target_window_identity = 0xABCDEF0100000042ULL;
    request.message = message;
    request.wparam = wparam;
    request.lparam = lparam;
    return request;
}

GuiMessageTargetRule RuleFor(const GuiMessageRequestSnapshot& request, u64 wparam_allowed_bits = ~u64(0),
                             u64 lparam_allowed_bits = ~u64(0))
{
    return GuiMessageTargetRule{request.sender.process_identity, request.sender.task_identity, request.message,
                                kGuiMessageRuleScalarPayload,    wparam_allowed_bits,          lparam_allowed_bits};
}

GuiMessageTargetOptInSnapshot OptInFor(const GuiMessageRequestSnapshot& request)
{
    GuiMessageTargetOptInSnapshot opt_in{};
    opt_in.target_process_identity = request.target.process_identity;
    opt_in.target_task_identity = request.target.task_identity;
    opt_in.target_window_identity = request.target_window_identity;
    opt_in.rule_count = 1;
    opt_in.rules[0] = RuleFor(request);
    return opt_in;
}

GuiMessageTrustedBrokerSnapshot BrokerFor(const GuiMessageRequestSnapshot& request)
{
    return GuiMessageTrustedBrokerSnapshot{0xB001,
                                           request.sender.process_identity,
                                           request.sender.task_identity,
                                           request.target.process_identity,
                                           request.target.task_identity,
                                           request.target_window_identity,
                                           ~u64(0),
                                           ~u64(0),
                                           request.message,
                                           kGuiBrokerRightPostApplicationScalar,
                                           0,
                                           0};
}

bool IsApplicationMessage(u32 message)
{
    return message >= kGuiMessageApplicationFirst && message <= kGuiMessageApplicationLast;
}

u64 NextRandom(u64& state)
{
    state ^= state << 13;
    state ^= state >> 7;
    state ^= state << 17;
    return state;
}

} // namespace

int main()
{
    // Principal relation is exact. Task identity is never decoded, but the
    // same task cannot belong to two processes and one process cannot carry
    // conflicting immutable integrity snapshots.
    const GuiMessagePrincipalSnapshot same = Principal(1, 2, Win32IntegrityLevel::Medium);
    EXPECT_EQ(GuiMessageClassifyRelation(same, same), GuiMessageEndpointRelation::SameTask);
    EXPECT_EQ(GuiMessageClassifyRelation(same, Principal(1, 3, Win32IntegrityLevel::Medium)),
              GuiMessageEndpointRelation::SameProcess);
    EXPECT_EQ(GuiMessageClassifyRelation(same, Principal(4, 5, Win32IntegrityLevel::Medium)),
              GuiMessageEndpointRelation::CrossProcess);
    EXPECT_EQ(GuiMessageClassifyRelation(same, Principal(4, 2, Win32IntegrityLevel::Medium)),
              GuiMessageEndpointRelation::Invalid);
    EXPECT_EQ(GuiMessageClassifyRelation(same, Principal(1, 3, Win32IntegrityLevel::High)),
              GuiMessageEndpointRelation::Invalid);
    EXPECT_EQ(GuiMessageClassifyRelation(Principal(0, 2, Win32IntegrityLevel::Medium), same),
              GuiMessageEndpointRelation::Invalid);
    EXPECT_EQ(GuiMessageClassifyRelation(Principal(1, 0, Win32IntegrityLevel::Medium), same),
              GuiMessageEndpointRelation::Invalid);
    EXPECT_EQ(GuiMessageClassifyRelation(Principal(1, 2, Win32IntegrityLevel::Invalid), same),
              GuiMessageEndpointRelation::Invalid);
    GuiMessagePrincipalSnapshot dirty_principal = same;
    dirty_principal.reserved[6] = 1;
    EXPECT_EQ(GuiMessageClassifyRelation(dirty_principal, same), GuiMessageEndpointRelation::Invalid);

    EXPECT_EQ(GuiMessageClassifySecurity(0x0002), GuiMessageSecurityClass::Lifecycle);
    EXPECT_EQ(GuiMessageClassifySecurity(0x0012), GuiMessageSecurityClass::Quit);
    EXPECT_EQ(GuiMessageClassifySecurity(0x0007), GuiMessageSecurityClass::FocusActivation);
    EXPECT_EQ(GuiMessageClassifySecurity(0x0215), GuiMessageSecurityClass::Capture);
    EXPECT_EQ(GuiMessageClassifySecurity(0x0100), GuiMessageSecurityClass::Input);
    EXPECT_EQ(GuiMessageClassifySecurity(0x020A), GuiMessageSecurityClass::Input);
    EXPECT_EQ(GuiMessageClassifySecurity(0x0112), GuiMessageSecurityClass::SystemCommand);
    EXPECT_EQ(GuiMessageClassifySecurity(0x0003), GuiMessageSecurityClass::OtherSystem);
    EXPECT_EQ(GuiMessageClassifySecurity(0x0400), GuiMessageSecurityClass::PrivateUnsafe);
    EXPECT_EQ(GuiMessageClassifySecurity(0x8000), GuiMessageSecurityClass::ApplicationScalar);
    EXPECT_EQ(GuiMessageClassifySecurity(0xBFFF), GuiMessageSecurityClass::ApplicationScalar);
    EXPECT_EQ(GuiMessageClassifySecurity(0xC000), GuiMessageSecurityClass::RegisteredUnknown);
    EXPECT_EQ(GuiMessageClassifySecurity(0x10000), GuiMessageSecurityClass::Invalid);

    // Same-task and same-process traffic remains inside its existing trust
    // boundary. Malformed identities and out-of-domain messages still fail.
    GuiMessageRequestSnapshot same_task = Request(0x0010);
    same_task.target = same_task.sender;
    EXPECT_EQ(GuiMessagePolicyEvaluate(same_task, nullptr, nullptr), GuiMessagePolicyDecision::AllowSameTask);
    GuiMessageRequestSnapshot same_process = Request(0x0100);
    same_process.target = Principal(same_process.sender.process_identity, 0x1102, same_process.sender.integrity);
    EXPECT_EQ(GuiMessagePolicyEvaluate(same_process, nullptr, nullptr), GuiMessagePolicyDecision::AllowSameProcess);
    same_process.message = 0x10000;
    EXPECT_EQ(GuiMessagePolicyEvaluate(same_process, nullptr, nullptr), GuiMessagePolicyDecision::DenyUnknownMessage);
    same_process.message = 0x8000;
    same_process.reserved = 1;
    EXPECT_EQ(GuiMessagePolicyEvaluate(same_process, nullptr, nullptr), GuiMessagePolicyDecision::DenyMalformedRequest);

    // Cross-process is default deny. One exact canonical WM_APP rule permits
    // only its exact sender, task, target snapshot, message, and scalar mask.
    GuiMessageRequestSnapshot allowed = Request(0x8123, 0x34, 0x500);
    GuiMessageTargetOptInSnapshot opt_in = OptInFor(allowed);
    opt_in.rules[0].wparam_allowed_bits = 0xFF;
    opt_in.rules[0].lparam_allowed_bits = 0xFFF;
    EXPECT_TRUE(GuiMessageTargetOptInIsCanonical(opt_in));
    EXPECT_EQ(GuiMessagePolicyEvaluate(allowed, nullptr, nullptr), GuiMessagePolicyDecision::DenyNoAuthorization);
    EXPECT_EQ(GuiMessagePolicyEvaluate(allowed, &opt_in, nullptr), GuiMessagePolicyDecision::AllowTargetOptIn);
    GuiMessageRequestSnapshot payload_escape = allowed;
    payload_escape.wparam = 0x134;
    EXPECT_EQ(GuiMessagePolicyEvaluate(payload_escape, &opt_in, nullptr),
              GuiMessagePolicyDecision::DenyPayloadOutsideRule);
    payload_escape = allowed;
    payload_escape.lparam = 0x1500;
    EXPECT_EQ(GuiMessagePolicyEvaluate(payload_escape, &opt_in, nullptr),
              GuiMessagePolicyDecision::DenyPayloadOutsideRule);
    GuiMessageRequestSnapshot foreign_sender = allowed;
    foreign_sender.sender.task_identity ^= 1;
    EXPECT_EQ(GuiMessagePolicyEvaluate(foreign_sender, &opt_in, nullptr),
              GuiMessagePolicyDecision::DenyNoAuthorization);
    GuiMessageTargetOptInSnapshot wrong_target = opt_in;
    wrong_target.target_window_identity ^= 1;
    EXPECT_EQ(GuiMessagePolicyEvaluate(allowed, &wrong_target, nullptr),
              GuiMessagePolicyDecision::DenyTargetSnapshotMismatch);

    // Rule snapshots have one canonical representation: exact nonzero sender
    // identities, scalar-only WM_APP messages, strict key order, no overlap,
    // bounded count, zero reserved/unused bytes.
    GuiMessageTargetOptInSnapshot empty_rules{};
    empty_rules.target_process_identity = allowed.target.process_identity;
    empty_rules.target_task_identity = allowed.target.task_identity;
    empty_rules.target_window_identity = allowed.target_window_identity;
    EXPECT_TRUE(GuiMessageTargetOptInIsCanonical(empty_rules));
    GuiMessageTargetOptInSnapshot malformed_rules = opt_in;
    malformed_rules.rule_count = kGuiMessageTargetRuleCapacity + 1;
    EXPECT_FALSE(GuiMessageTargetOptInIsCanonical(malformed_rules));
    malformed_rules = opt_in;
    malformed_rules.reserved = 1;
    EXPECT_FALSE(GuiMessageTargetOptInIsCanonical(malformed_rules));
    malformed_rules = opt_in;
    malformed_rules.rules[1].message = 1;
    EXPECT_FALSE(GuiMessageTargetOptInIsCanonical(malformed_rules));
    malformed_rules = opt_in;
    malformed_rules.rules[0].sender_process_identity = 0;
    EXPECT_FALSE(GuiMessageTargetOptInIsCanonical(malformed_rules));
    malformed_rules = opt_in;
    malformed_rules.rules[0].sender_task_identity = 0;
    EXPECT_FALSE(GuiMessageTargetOptInIsCanonical(malformed_rules));
    malformed_rules = opt_in;
    malformed_rules.rules[0].sender_process_identity = malformed_rules.target_process_identity;
    EXPECT_FALSE(GuiMessageTargetOptInIsCanonical(malformed_rules));
    malformed_rules = opt_in;
    malformed_rules.rules[0].sender_task_identity = malformed_rules.target_task_identity;
    EXPECT_FALSE(GuiMessageTargetOptInIsCanonical(malformed_rules));
    malformed_rules = opt_in;
    malformed_rules.rules[0].message = 0x0010;
    EXPECT_FALSE(GuiMessageTargetOptInIsCanonical(malformed_rules));
    malformed_rules = opt_in;
    malformed_rules.rules[0].flags = 0;
    EXPECT_FALSE(GuiMessageTargetOptInIsCanonical(malformed_rules));
    malformed_rules = opt_in;
    malformed_rules.rules[0].flags |= 0x80000000u;
    EXPECT_FALSE(GuiMessageTargetOptInIsCanonical(malformed_rules));

    GuiMessageTargetOptInSnapshot ordered = empty_rules;
    ordered.rule_count = 3;
    ordered.rules[0] = GuiMessageTargetRule{1, 9, 0x8001, kGuiMessageRuleScalarPayload, 0, 0};
    ordered.rules[1] = GuiMessageTargetRule{2, 8, 0x8000, kGuiMessageRuleScalarPayload, 0, 0};
    ordered.rules[2] = GuiMessageTargetRule{2, 8, 0x8001, kGuiMessageRuleScalarPayload, 0, 0};
    EXPECT_TRUE(GuiMessageTargetOptInIsCanonical(ordered));
    malformed_rules = ordered;
    malformed_rules.rules[1] = malformed_rules.rules[0];
    malformed_rules.rules[1].wparam_allowed_bits = ~u64(0); // same key, overlapping payload policy
    EXPECT_FALSE(GuiMessageTargetOptInIsCanonical(malformed_rules));
    malformed_rules = ordered;
    const GuiMessageTargetRule swap = malformed_rules.rules[0];
    malformed_rules.rules[0] = malformed_rules.rules[1];
    malformed_rules.rules[1] = swap;
    EXPECT_FALSE(GuiMessageTargetOptInIsCanonical(malformed_rules));

    // Broker authority is a separate kernel snapshot tied to the actual
    // sender principal. It is not a bit in the sender-controlled request.
    GuiMessageTrustedBrokerSnapshot broker = BrokerFor(allowed);
    EXPECT_TRUE(GuiMessageTrustedBrokerIsCanonical(broker));
    EXPECT_EQ(GuiMessagePolicyEvaluate(allowed, nullptr, &broker), GuiMessagePolicyDecision::AllowTrustedBroker);
    GuiMessageTrustedBrokerSnapshot malformed_broker = broker;
    malformed_broker.authority_identity = 0;
    EXPECT_FALSE(GuiMessageTrustedBrokerIsCanonical(malformed_broker));
    EXPECT_EQ(GuiMessagePolicyEvaluate(allowed, nullptr, &malformed_broker),
              GuiMessagePolicyDecision::DenyMalformedBrokerAuthority);
    malformed_broker = broker;
    malformed_broker.rights = 0;
    EXPECT_FALSE(GuiMessageTrustedBrokerIsCanonical(malformed_broker));
    malformed_broker = broker;
    malformed_broker.rights |= 0x80000000u;
    EXPECT_FALSE(GuiMessageTrustedBrokerIsCanonical(malformed_broker));
    malformed_broker = broker;
    malformed_broker.reserved = 1;
    EXPECT_FALSE(GuiMessageTrustedBrokerIsCanonical(malformed_broker));
    malformed_broker = broker;
    malformed_broker.reserved2 = 1;
    EXPECT_FALSE(GuiMessageTrustedBrokerIsCanonical(malformed_broker));
    malformed_broker = broker;
    malformed_broker.target_task_identity = 0;
    EXPECT_FALSE(GuiMessageTrustedBrokerIsCanonical(malformed_broker));
    malformed_broker = broker;
    malformed_broker.principal_process_identity = malformed_broker.target_process_identity;
    EXPECT_FALSE(GuiMessageTrustedBrokerIsCanonical(malformed_broker));
    malformed_broker = broker;
    malformed_broker.principal_task_identity = malformed_broker.target_task_identity;
    EXPECT_FALSE(GuiMessageTrustedBrokerIsCanonical(malformed_broker));
    malformed_broker = broker;
    malformed_broker.message = 0x0010;
    EXPECT_FALSE(GuiMessageTrustedBrokerIsCanonical(malformed_broker));
    GuiMessageTrustedBrokerSnapshot wrong_broker = broker;
    wrong_broker.principal_task_identity ^= 1;
    EXPECT_EQ(GuiMessagePolicyEvaluate(allowed, nullptr, &wrong_broker),
              GuiMessagePolicyDecision::DenyBrokerPrincipalMismatch);
    wrong_broker = broker;
    wrong_broker.target_process_identity ^= 1;
    EXPECT_EQ(GuiMessagePolicyEvaluate(allowed, nullptr, &wrong_broker),
              GuiMessagePolicyDecision::DenyBrokerGrantMismatch);
    wrong_broker = broker;
    wrong_broker.target_task_identity ^= 1;
    EXPECT_EQ(GuiMessagePolicyEvaluate(allowed, nullptr, &wrong_broker),
              GuiMessagePolicyDecision::DenyBrokerGrantMismatch);
    wrong_broker = broker;
    wrong_broker.target_window_identity ^= 1;
    EXPECT_EQ(GuiMessagePolicyEvaluate(allowed, nullptr, &wrong_broker),
              GuiMessagePolicyDecision::DenyBrokerGrantMismatch);
    wrong_broker = broker;
    ++wrong_broker.message;
    EXPECT_EQ(GuiMessagePolicyEvaluate(allowed, nullptr, &wrong_broker),
              GuiMessagePolicyDecision::DenyBrokerGrantMismatch);
    GuiMessageRequestSnapshot replayed_grant = allowed;
    replayed_grant.target.process_identity ^= 1;
    EXPECT_EQ(GuiMessagePolicyEvaluate(replayed_grant, nullptr, &broker),
              GuiMessagePolicyDecision::DenyBrokerGrantMismatch);
    replayed_grant = allowed;
    replayed_grant.target.task_identity ^= 1;
    EXPECT_EQ(GuiMessagePolicyEvaluate(replayed_grant, nullptr, &broker),
              GuiMessagePolicyDecision::DenyBrokerGrantMismatch);
    replayed_grant = allowed;
    replayed_grant.target_window_identity ^= 1;
    EXPECT_EQ(GuiMessagePolicyEvaluate(replayed_grant, nullptr, &broker),
              GuiMessagePolicyDecision::DenyBrokerGrantMismatch);
    replayed_grant = allowed;
    ++replayed_grant.message;
    EXPECT_EQ(GuiMessagePolicyEvaluate(replayed_grant, nullptr, &broker),
              GuiMessagePolicyDecision::DenyBrokerGrantMismatch);
    GuiMessageTrustedBrokerSnapshot narrow_broker = broker;
    narrow_broker.wparam_allowed_bits = 0xFF;
    narrow_broker.lparam_allowed_bits = 0xFFF;
    EXPECT_EQ(GuiMessagePolicyEvaluate(allowed, nullptr, &narrow_broker), GuiMessagePolicyDecision::AllowTrustedBroker);
    GuiMessageRequestSnapshot broker_payload_escape = allowed;
    broker_payload_escape.wparam |= 1ULL << 48;
    EXPECT_EQ(GuiMessagePolicyEvaluate(broker_payload_escape, nullptr, &narrow_broker),
              GuiMessagePolicyDecision::DenyPayloadOutsideBrokerGrant);
    broker_payload_escape = allowed;
    broker_payload_escape.lparam |= 1ULL << 47;
    EXPECT_EQ(GuiMessagePolicyEvaluate(broker_payload_escape, nullptr, &narrow_broker),
              GuiMessagePolicyDecision::DenyPayloadOutsideBrokerGrant);

    // Integrity is monotonic even with both independent authorization paths.
    GuiMessageRequestSnapshot low_to_high = allowed;
    low_to_high.sender.integrity = Win32IntegrityLevel::Low;
    low_to_high.target.integrity = Win32IntegrityLevel::High;
    GuiMessageTargetOptInSnapshot low_rules = OptInFor(low_to_high);
    GuiMessageTrustedBrokerSnapshot low_broker = BrokerFor(low_to_high);
    EXPECT_EQ(GuiMessagePolicyEvaluate(low_to_high, &low_rules, nullptr),
              GuiMessagePolicyDecision::DenyLowToHighIntegrity);
    EXPECT_EQ(GuiMessagePolicyEvaluate(low_to_high, nullptr, &low_broker),
              GuiMessagePolicyDecision::DenyLowToHighIntegrity);

    // Absolute cross-process classes remain denied even if a target tries to
    // opt in and a separately valid broker capability is present.
    constexpr std::array<u32, 33> kAbsoluteMessages{
        0x0001, // create
        0x0002, // destroy
        0x0003, // move / system state
        0x0005, // size / system state
        0x0006, // activate
        0x0007, // set focus
        0x0008, // kill focus
        0x0010, // close
        0x0011, // query end session
        0x0012, // quit
        0x0016, // end session
        0x0018, // show window / system state
        0x001A, // setting change
        0x001C, // activate app
        0x001F, // cancel mode
        0x0021, // mouse activate
        0x0046, // window-pos changing
        0x0047, // window-pos changed
        0x004E, // notify
        0x007E, // display change
        0x0082, // nc destroy
        0x0086, // nc activate
        0x00FF, // raw input
        0x0100, // key down
        0x0104, // syskey down
        0x0111, // command
        0x0112, // system command
        0x0201, // mouse button
        0x020A, // mouse wheel
        0x0215, // capture changed
        0x0218, // power broadcast
        0x0240, // touch
        0x0312, // hotkey
    };
    for (u32 message : kAbsoluteMessages)
    {
        GuiMessageRequestSnapshot hostile = Request(message);
        GuiMessageTargetOptInSnapshot hostile_rules = OptInFor(hostile);
        GuiMessageTrustedBrokerSnapshot hostile_broker = BrokerFor(hostile);
        EXPECT_FALSE(GuiMessagePolicyAllowed(GuiMessagePolicyEvaluate(hostile, &hostile_rules, &hostile_broker)));
    }
    GuiMessageRequestSnapshot hostile_quit_thread = Request(0x0012);
    hostile_quit_thread.target_window_identity = 0;
    GuiMessageTargetOptInSnapshot hostile_quit_rules = OptInFor(hostile_quit_thread);
    GuiMessageTrustedBrokerSnapshot hostile_quit_broker = BrokerFor(hostile_quit_thread);
    EXPECT_FALSE(GuiMessagePolicyAllowed(
        GuiMessagePolicyEvaluate(hostile_quit_thread, &hostile_quit_rules, &hostile_quit_broker)));

    // Exhaust the entire Win32 message namespace. No unauthenticated
    // cross-process code is allowed. Broker and target-rule paths admit
    // exactly WM_APP..0xBFFF and nothing from the lifecycle, input, control-
    // private, system, or registered/unknown regions.
    for (u32 message = 0; message <= kGuiMessageMaximum; ++message)
    {
        GuiMessageRequestSnapshot exhaustive = Request(message);
        GuiMessageTargetOptInSnapshot exhaustive_rules = OptInFor(exhaustive);
        GuiMessageTrustedBrokerSnapshot exhaustive_broker = BrokerFor(exhaustive);
        EXPECT_FALSE(GuiMessagePolicyAllowed(GuiMessagePolicyEvaluate(exhaustive, nullptr, nullptr)));
        EXPECT_EQ(GuiMessagePolicyAllowed(GuiMessagePolicyEvaluate(exhaustive, &exhaustive_rules, nullptr)),
                  IsApplicationMessage(message));
        EXPECT_EQ(GuiMessagePolicyAllowed(GuiMessagePolicyEvaluate(exhaustive, nullptr, &exhaustive_broker)),
                  IsApplicationMessage(message));
    }

    // Deterministic fuzz spans the full u32 input domain. Default-deny never
    // authorizes; a canonical broker authorizes iff the random value is in the
    // sole cross-process-safe range. Payload masks are checked independently.
    u64 random = 0x9E3779B97F4A7C15ULL;
    for (u32 iteration = 0; iteration < 250000; ++iteration)
    {
        const u32 message = static_cast<u32>(NextRandom(random));
        GuiMessageRequestSnapshot fuzz = Request(message);
        GuiMessageTrustedBrokerSnapshot fuzz_broker = BrokerFor(fuzz);
        EXPECT_FALSE(GuiMessagePolicyAllowed(GuiMessagePolicyEvaluate(fuzz, nullptr, nullptr)));
        EXPECT_EQ(GuiMessagePolicyAllowed(GuiMessagePolicyEvaluate(fuzz, nullptr, &fuzz_broker)),
                  IsApplicationMessage(message));

        fuzz.message = kGuiMessageApplicationFirst + (message & 0x3FFFu);
        fuzz.wparam = NextRandom(random);
        fuzz.lparam = NextRandom(random);
        const u64 wmask = NextRandom(random);
        const u64 lmask = NextRandom(random);
        GuiMessageTargetOptInSnapshot fuzz_rules = OptInFor(fuzz);
        fuzz_rules.rules[0].wparam_allowed_bits = wmask;
        fuzz_rules.rules[0].lparam_allowed_bits = lmask;
        const bool payload_expected = (fuzz.wparam & ~wmask) == 0 && (fuzz.lparam & ~lmask) == 0;
        EXPECT_EQ(GuiMessagePolicyAllowed(GuiMessagePolicyEvaluate(fuzz, &fuzz_rules, nullptr)), payload_expected);
    }

    // Opaque identities accept full-width generations without decoding. Zero
    // HWND continues to represent a task message and is exact in the opt-in.
    GuiMessageRequestSnapshot opaque = Request(0x8ABC);
    opaque.sender.process_identity = ~u64(0);
    opaque.sender.task_identity = ~u64(0) - 1;
    opaque.target.process_identity = ~u64(0) - 2;
    opaque.target.task_identity = ~u64(0) - 3;
    opaque.target_window_identity = ~u64(0);
    GuiMessageTargetOptInSnapshot opaque_rules = OptInFor(opaque);
    EXPECT_EQ(GuiMessagePolicyEvaluate(opaque, &opaque_rules, nullptr), GuiMessagePolicyDecision::AllowTargetOptIn);
    opaque.target_window_identity = 0;
    opaque_rules = OptInFor(opaque);
    EXPECT_EQ(GuiMessagePolicyEvaluate(opaque, &opaque_rules, nullptr), GuiMessagePolicyDecision::AllowTargetOptIn);

    // Shared immutable snapshots can be evaluated concurrently with no state
    // publication, retention, or mutation inside the policy.
    const GuiMessageRequestSnapshot shared_request = Request(0x8FED, 0x55, 0xAA);
    const GuiMessageTargetOptInSnapshot shared_rules = OptInFor(shared_request);
    const GuiMessageTrustedBrokerSnapshot shared_broker = BrokerFor(shared_request);
    constexpr u32 kThreadCount = 8;
    constexpr u32 kThreadIterations = 50000;
    std::atomic<u32> thread_errors{0};
    std::vector<std::thread> threads;
    threads.reserve(kThreadCount);
    for (u32 thread = 0; thread < kThreadCount; ++thread)
    {
        threads.emplace_back(
            [&]()
            {
                for (u32 iteration = 0; iteration < kThreadIterations; ++iteration)
                {
                    if (GuiMessagePolicyEvaluate(shared_request, &shared_rules, nullptr) !=
                            GuiMessagePolicyDecision::AllowTargetOptIn ||
                        GuiMessagePolicyEvaluate(shared_request, nullptr, &shared_broker) !=
                            GuiMessagePolicyDecision::AllowTrustedBroker)
                    {
                        thread_errors.fetch_add(1, std::memory_order_relaxed);
                    }
                    GuiMessageRequestSnapshot denied = shared_request;
                    denied.message = (iteration & 1u) == 0 ? 0x0010u : 0x0100u;
                    if (GuiMessagePolicyAllowed(GuiMessagePolicyEvaluate(denied, &shared_rules, &shared_broker)))
                    {
                        thread_errors.fetch_add(1, std::memory_order_relaxed);
                    }
                }
            });
    }
    for (std::thread& thread : threads)
    {
        thread.join();
    }
    EXPECT_EQ(thread_errors.load(std::memory_order_relaxed), 0u);

    return duetos_host_test::finish_main("test_gui_message_policy");
}
