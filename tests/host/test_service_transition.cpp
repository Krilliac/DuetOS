// Hosted exact-generation properties for core/service_transition.
//
// The production primitive is deliberately lock-free: callers serialize one
// embedded state row.  The final race test supplies a host mutex and models
// the required scheduler-lock -> service-lock publication critical section.

#include "host_test_helper.h"
#include "core/service_transition.h"

#include <atomic>
#include <barrier>
#include <mutex>
#include <thread>

namespace
{

using namespace duetos::core;
using duetos::u32;
using duetos::u64;

ServiceTransitionState NewState(u64 identity)
{
    ServiceTransitionState state{};
    EXPECT_TRUE(ServiceTransitionInitialize(identity, &state));
    EXPECT_TRUE(ServiceTransitionIsCanonical(state));
    return state;
}

ServiceStartTicket Reserve(ServiceTransitionState& state)
{
    ServiceStartTicket ticket = kInvalidServiceStartTicket;
    EXPECT_EQ(ServiceTransitionReserveStart(&state, &ticket), ServiceStartReserveResult::Reserved);
    EXPECT_TRUE(ServiceStartTicketIsValid(ticket));
    EXPECT_TRUE(ServiceTransitionIsCurrentStart(state, ticket));
    EXPECT_TRUE(ServiceTransitionIsCanonical(state));
    return ticket;
}

ServiceInstanceKey Instance(u64 pid)
{
    return ServiceInstanceKey{0x8000000000000000ULL | pid, pid};
}

ServiceInstanceToken Token(ServiceStartTicket ticket, ServiceInstanceKey process)
{
    return ServiceInstanceToken{ticket, process};
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
    EXPECT_FALSE(ServiceStartTicketIsValid(kInvalidServiceStartTicket));
    EXPECT_FALSE(ServiceStartTicketIsValid(ServiceStartTicket{0, 1}));
    EXPECT_FALSE(ServiceInstanceKeyIsValid(kInvalidServiceInstanceKey));
    EXPECT_FALSE(ServiceInstanceKeyIsValid(ServiceInstanceKey{0, 1}));
    EXPECT_FALSE(ServiceInstanceKeyIsValid(ServiceInstanceKey{1, 0}));
    EXPECT_TRUE(ServiceInstanceKeyIsValid(Instance(1)));
    EXPECT_FALSE(ServiceInstanceTokenIsValid(kInvalidServiceInstanceToken));

    ServiceTransitionState invalid{};
    EXPECT_FALSE(ServiceTransitionInitialize(kInvalidServiceTransitionIdentity, &invalid));
    EXPECT_FALSE(ServiceTransitionIsCanonical(invalid));
    EXPECT_FALSE(ServiceTransitionInitialize(0, nullptr));

    ServiceTransitionState state = NewState(7);
    EXPECT_EQ(state.phase, ServiceTransitionPhase::Stopped);
    EXPECT_EQ(state.generation, 0ULL);

    ServiceStartTicket ticket = Reserve(state);
    EXPECT_EQ(ticket.service_identity, 7ULL);
    EXPECT_EQ(ticket.generation, 1ULL);
    ServiceStartTicket no_duplicate{1, 1};
    EXPECT_EQ(ServiceTransitionReserveStart(&state, &no_duplicate), ServiceStartReserveResult::AlreadyRequested);
    EXPECT_TRUE(no_duplicate == kInvalidServiceStartTicket);

    // No partial instance key, cross-service authority, or mutated generation
    // may publish.
    EXPECT_EQ(ServiceTransitionCommitAtSchedulerPublication(&state, ticket, kInvalidServiceInstanceKey),
              ServicePublicationResult::Rejected);
    EXPECT_EQ(ServiceTransitionCommitAtSchedulerPublication(&state, ticket, ServiceInstanceKey{0, 90}),
              ServicePublicationResult::Rejected);
    EXPECT_EQ(ServiceTransitionCommitAtSchedulerPublication(&state, ticket, ServiceInstanceKey{90, 0}),
              ServicePublicationResult::Rejected);
    EXPECT_EQ(
        ServiceTransitionCommitAtSchedulerPublication(&state, ServiceStartTicket{8, ticket.generation}, Instance(90)),
        ServicePublicationResult::Rejected);
    EXPECT_EQ(ServiceTransitionCommitAtSchedulerPublication(
                  &state, ServiceStartTicket{ticket.service_identity, ticket.generation + 1}, Instance(90)),
              ServicePublicationResult::Rejected);
    EXPECT_TRUE(ServiceTransitionIsCurrentStart(state, ticket));

    const ServiceInstanceKey instance90 = Instance(90);
    const ServiceInstanceToken token90 = Token(ticket, instance90);
    EXPECT_EQ(ServiceTransitionCommitAtSchedulerPublication(&state, ticket, instance90),
              ServicePublicationResult::Published);
    EXPECT_TRUE(ServiceTransitionIsCurrentRunning(state, token90));
    EXPECT_EQ(ServiceTransitionCommitAtSchedulerPublication(&state, ticket, instance90),
              ServicePublicationResult::Rejected);
    EXPECT_EQ(ServiceTransitionObserveExit(&state, Token(ticket, Instance(91))), ServiceExitResult::Rejected);
    EXPECT_EQ(ServiceTransitionObserveExit(&state, Token(ServiceStartTicket{9, ticket.generation}, instance90)),
              ServiceExitResult::Rejected);
    EXPECT_TRUE(ServiceTransitionIsCurrentRunning(state, token90));
    EXPECT_EQ(ServiceTransitionObserveExit(&state, token90), ServiceExitResult::Applied);
    EXPECT_EQ(state.phase, ServiceTransitionPhase::Exited);
    EXPECT_FALSE(ServiceTransitionIsCurrentRunning(state, token90));
    EXPECT_EQ(ServiceTransitionObserveExit(&state, token90), ServiceExitResult::Rejected);

    // A construction failure consumes only the exact current reservation.
    ticket = Reserve(state);
    EXPECT_EQ(
        ServiceTransitionRecordSpawnFailure(&state, ServiceStartTicket{ticket.service_identity, ticket.generation - 1}),
        ServiceSpawnFailureResult::Rejected);
    EXPECT_EQ(ServiceTransitionRecordSpawnFailure(&state, ticket), ServiceSpawnFailureResult::Applied);
    EXPECT_EQ(state.phase, ServiceTransitionPhase::Failed);
    EXPECT_EQ(ServiceTransitionRecordSpawnFailure(&state, ticket), ServiceSpawnFailureResult::Rejected);

    // Stop before the publication boundary invalidates the exact ticket.  A
    // later private Task must be destroyed without ever entering a runqueue.
    ticket = Reserve(state);
    ServiceInstanceToken instance_to_kill = Token(ServiceStartTicket{9, 9}, Instance(123));
    EXPECT_EQ(ServiceTransitionStop(&state, &instance_to_kill), ServiceStopResult::StartCancelled);
    EXPECT_TRUE(instance_to_kill == kInvalidServiceInstanceToken);
    EXPECT_EQ(state.phase, ServiceTransitionPhase::Stopped);
    EXPECT_EQ(ServiceTransitionCommitAtSchedulerPublication(&state, ticket, Instance(100)),
              ServicePublicationResult::Rejected);
    EXPECT_EQ(ServiceTransitionStop(&state, &instance_to_kill), ServiceStopResult::AlreadyStopped);
    EXPECT_TRUE(instance_to_kill == kInvalidServiceInstanceToken);

    // A newer reservation cannot be confused with the cancelled generation.
    const ServiceStartTicket stale = ticket;
    ticket = Reserve(state);
    EXPECT_TRUE(ticket.generation > stale.generation);
    EXPECT_EQ(ServiceTransitionCommitAtSchedulerPublication(&state, stale, Instance(101)),
              ServicePublicationResult::Rejected);
    const ServiceInstanceKey instance101 = Instance(101);
    const ServiceInstanceToken token101 = Token(ticket, instance101);
    EXPECT_EQ(ServiceTransitionCommitAtSchedulerPublication(&state, ticket, instance101),
              ServicePublicationResult::Published);
    EXPECT_EQ(ServiceTransitionStop(&state, &instance_to_kill), ServiceStopResult::KillRequired);
    EXPECT_TRUE(instance_to_kill == token101);
    EXPECT_EQ(state.phase, ServiceTransitionPhase::Stopping);
    EXPECT_FALSE(ServiceTransitionIsCurrentRunning(state, token101));
    EXPECT_TRUE(ServiceTransitionIsCurrentInstance(state, token101));
    ServiceStartTicket blocked{};
    EXPECT_EQ(ServiceTransitionReserveStart(&state, &blocked), ServiceStartReserveResult::StopInProgress);
    EXPECT_TRUE(blocked == kInvalidServiceStartTicket);
    EXPECT_EQ(ServiceTransitionStop(&state, &instance_to_kill), ServiceStopResult::AlreadyStopping);
    EXPECT_TRUE(instance_to_kill == kInvalidServiceInstanceToken);
    EXPECT_EQ(ServiceTransitionObserveExit(&state, Token(ticket, Instance(102))), ServiceExitResult::Rejected);
    EXPECT_EQ(ServiceTransitionObserveExit(&state, token101), ServiceExitResult::Applied);
    EXPECT_EQ(state.phase, ServiceTransitionPhase::Stopped);
    EXPECT_FALSE(ServiceTransitionIsCurrentInstance(state, token101));

    // Terminal generations remain Stopping until the exact instance is proven
    // absent, then fail closed permanently.
    ServiceTransitionState terminal = NewState(11);
    terminal.generation = kServiceTransitionGenerationMaximum - 1;
    ServiceStartTicket terminal_ticket = Reserve(terminal);
    EXPECT_EQ(terminal_ticket.generation, kServiceTransitionGenerationMaximum);
    const ServiceInstanceKey terminal_instance = Instance(777);
    const ServiceInstanceToken terminal_token = Token(terminal_ticket, terminal_instance);
    EXPECT_EQ(ServiceTransitionCommitAtSchedulerPublication(&terminal, terminal_ticket, terminal_instance),
              ServicePublicationResult::Published);
    EXPECT_EQ(ServiceTransitionStop(&terminal, &instance_to_kill), ServiceStopResult::KillRequired);
    EXPECT_TRUE(instance_to_kill == terminal_token);
    EXPECT_EQ(terminal.phase, ServiceTransitionPhase::Stopping);
    ServiceStartTicket refused{1, 1};
    EXPECT_EQ(ServiceTransitionReserveStart(&terminal, &refused), ServiceStartReserveResult::StopInProgress);
    EXPECT_EQ(ServiceTransitionObserveExit(&terminal, terminal_token), ServiceExitResult::Applied);
    EXPECT_EQ(terminal.phase, ServiceTransitionPhase::GenerationExhausted);
    EXPECT_TRUE(ServiceTransitionIsCanonical(terminal));
    refused = ServiceStartTicket{1, 1};
    EXPECT_EQ(ServiceTransitionReserveStart(&terminal, &refused), ServiceStartReserveResult::GenerationExhausted);
    EXPECT_TRUE(refused == kInvalidServiceStartTicket);

    // Deterministic hostile-operation churn: every rejected replay leaves a
    // canonical state, and every accepted transition is exact-generation.
    ServiceTransitionState churn = NewState(15);
    ServiceStartTicket current = kInvalidServiceStartTicket;
    ServiceInstanceKey current_instance = kInvalidServiceInstanceKey;
    ServiceInstanceToken current_token = kInvalidServiceInstanceToken;
    u64 rng = 0x7e57d00d4a11ULL;
    for (u32 iteration = 0; iteration < 250000; ++iteration)
    {
        const u64 sample = NextRandom(rng);
        switch (sample % 6)
        {
        case 0:
        {
            ServiceStartTicket candidate{};
            const ServiceStartReserveResult result = ServiceTransitionReserveStart(&churn, &candidate);
            if (result == ServiceStartReserveResult::Reserved)
                current = candidate;
            break;
        }
        case 1:
        {
            const ServiceInstanceKey candidate =
                (sample & 16) != 0 ? Instance(iteration + 1ULL) : kInvalidServiceInstanceKey;
            if (ServiceTransitionCommitAtSchedulerPublication(
                    &churn, (sample & 8) != 0 ? current : ServiceStartTicket{99, current.generation}, candidate) ==
                ServicePublicationResult::Published)
            {
                current_instance = candidate;
                current_token = Token(current, candidate);
            }
            break;
        }
        case 2:
            (void)ServiceTransitionRecordSpawnFailure(
                &churn,
                (sample & 8) != 0 ? current : ServiceStartTicket{current.service_identity, current.generation + 1});
            break;
        case 3:
        {
            const ServiceStopResult result = ServiceTransitionStop(&churn, &instance_to_kill);
            if (result == ServiceStopResult::KillRequired)
                current_token = instance_to_kill;
            if ((result == ServiceStopResult::KillRequired || result == ServiceStopResult::AlreadyStopping) &&
                (sample & 32) != 0 && ServiceInstanceTokenIsValid(current_token))
            {
                (void)ServiceTransitionObserveExit(&churn, current_token);
            }
            break;
        }
        case 4:
            (void)ServiceTransitionObserveExit(
                &churn, (sample & 8) != 0 ? current_token
                                          : Token(current, ServiceInstanceKey{current_instance.process_identity,
                                                                              current_instance.pid + 1}));
            break;
        default:
            (void)ServiceTransitionIsCurrentRunning(churn, current_token);
            break;
        }
        EXPECT_TRUE(ServiceTransitionIsCanonical(churn));
    }

    // Race the two only legal linearization orders 10,000 times.  The mutex
    // models the nested scheduler/service publication critical section: if
    // publication wins, Stop must retain and return its exact instance while
    // Stopping; if Stop wins, the gate must reject and no Task is published.
    for (u32 iteration = 0; iteration < 10000; ++iteration)
    {
        ServiceTransitionState raced = NewState(20);
        const ServiceStartTicket raced_ticket = Reserve(raced);
        const u64 raced_pid = 0x100000ULL + iteration;
        const ServiceInstanceKey raced_instance = Instance(raced_pid);
        std::mutex publication_boundary;
        std::barrier start_line(3);
        std::atomic<bool> published{false};
        std::atomic<u64> kill_pid{0};
        std::atomic<u64> kill_identity{0};
        std::atomic<u32> stop_result{static_cast<u32>(ServiceStopResult::Rejected)};

        std::thread publisher(
            [&]
            {
                start_line.arrive_and_wait();
                std::lock_guard<std::mutex> guard(publication_boundary);
                if (ServiceTransitionCommitAtSchedulerPublication(&raced, raced_ticket, raced_instance) ==
                    ServicePublicationResult::Published)
                {
                    // This assignment represents registry/runqueue publication
                    // and deliberately occurs inside the same critical section.
                    published.store(true, std::memory_order_relaxed);
                }
            });
        std::thread stopper(
            [&]
            {
                start_line.arrive_and_wait();
                std::lock_guard<std::mutex> guard(publication_boundary);
                ServiceInstanceToken observed{};
                const ServiceStopResult result = ServiceTransitionStop(&raced, &observed);
                stop_result.store(static_cast<u32>(result), std::memory_order_relaxed);
                kill_pid.store(observed.process.pid, std::memory_order_relaxed);
                kill_identity.store(observed.process.process_identity, std::memory_order_relaxed);
            });
        start_line.arrive_and_wait();
        publisher.join();
        stopper.join();

        if (published.load(std::memory_order_relaxed))
        {
            EXPECT_EQ(stop_result.load(std::memory_order_relaxed), static_cast<u32>(ServiceStopResult::KillRequired));
            EXPECT_EQ(kill_pid.load(std::memory_order_relaxed), raced_pid);
            EXPECT_EQ(kill_identity.load(std::memory_order_relaxed), raced_instance.process_identity);
            EXPECT_EQ(raced.phase, ServiceTransitionPhase::Stopping);
            EXPECT_EQ(ServiceTransitionReserveStart(&raced, &blocked), ServiceStartReserveResult::StopInProgress);
            EXPECT_EQ(ServiceTransitionObserveExit(&raced, Token(raced_ticket, raced_instance)),
                      ServiceExitResult::Applied);
        }
        else
        {
            EXPECT_EQ(stop_result.load(std::memory_order_relaxed), static_cast<u32>(ServiceStopResult::StartCancelled));
            EXPECT_EQ(kill_pid.load(std::memory_order_relaxed), 0ULL);
            EXPECT_EQ(kill_identity.load(std::memory_order_relaxed), 0ULL);
        }
        EXPECT_TRUE(ServiceTransitionIsCanonical(raced));
        EXPECT_EQ(raced.phase, ServiceTransitionPhase::Stopped);
    }

    return duetos_host_test::finish_main("service_transition");
}
