#include "core/service_transition.h"

namespace duetos::core
{

namespace
{

void ClearState(ServiceTransitionState& state)
{
    state.service_identity = kInvalidServiceTransitionIdentity;
    state.phase = ServiceTransitionPhase::GenerationExhausted;
    state.generation = 0;
    state.instance = kInvalidServiceInstanceKey;
    state.desired_running = false;
    state.start_in_flight = false;
}

bool TicketMatches(const ServiceTransitionState& state, ServiceStartTicket ticket)
{
    return ServiceStartTicketIsValid(ticket) && ticket.service_identity == state.service_identity &&
           ticket.generation == state.generation;
}

} // namespace

bool ServiceTransitionInitialize(u64 service_identity, ServiceTransitionState* out_state)
{
    if (out_state == nullptr)
    {
        return false;
    }
    ClearState(*out_state);
    if (service_identity == kInvalidServiceTransitionIdentity)
    {
        return false;
    }

    out_state->service_identity = service_identity;
    out_state->phase = ServiceTransitionPhase::Stopped;
    return true;
}

bool ServiceTransitionIsCanonical(const ServiceTransitionState& state)
{
    if (state.service_identity == kInvalidServiceTransitionIdentity)
    {
        return false;
    }

    switch (state.phase)
    {
    case ServiceTransitionPhase::Stopped:
        return state.instance == kInvalidServiceInstanceKey && !state.desired_running && !state.start_in_flight;
    case ServiceTransitionPhase::Starting:
        return state.generation != 0 && state.instance == kInvalidServiceInstanceKey && state.desired_running &&
               state.start_in_flight;
    case ServiceTransitionPhase::Running:
        return state.generation != 0 && ServiceInstanceKeyIsValid(state.instance) && state.desired_running &&
               !state.start_in_flight;
    case ServiceTransitionPhase::Stopping:
        return state.generation != 0 && ServiceInstanceKeyIsValid(state.instance) && !state.desired_running &&
               !state.start_in_flight;
    case ServiceTransitionPhase::Exited:
    case ServiceTransitionPhase::Failed:
        return state.generation != 0 && state.instance == kInvalidServiceInstanceKey && !state.desired_running &&
               !state.start_in_flight;
    case ServiceTransitionPhase::GenerationExhausted:
        return state.generation == kServiceTransitionGenerationMaximum &&
               state.instance == kInvalidServiceInstanceKey && !state.desired_running && !state.start_in_flight;
    }
    return false;
}

ServiceStartReserveResult ServiceTransitionReserveStart(ServiceTransitionState* state, ServiceStartTicket* out_ticket)
{
    if (out_ticket != nullptr)
    {
        *out_ticket = kInvalidServiceStartTicket;
    }
    if (state == nullptr || out_ticket == nullptr || !ServiceTransitionIsCanonical(*state))
    {
        return ServiceStartReserveResult::Rejected;
    }
    if ((state->phase == ServiceTransitionPhase::Starting && state->start_in_flight) ||
        (state->phase == ServiceTransitionPhase::Running && state->desired_running))
    {
        return ServiceStartReserveResult::AlreadyRequested;
    }
    if (state->phase == ServiceTransitionPhase::Stopping)
    {
        return ServiceStartReserveResult::StopInProgress;
    }
    if (state->phase == ServiceTransitionPhase::GenerationExhausted ||
        state->generation == kServiceTransitionGenerationMaximum)
    {
        state->phase = ServiceTransitionPhase::GenerationExhausted;
        state->instance = kInvalidServiceInstanceKey;
        state->desired_running = false;
        state->start_in_flight = false;
        return ServiceStartReserveResult::GenerationExhausted;
    }

    ++state->generation;
    state->phase = ServiceTransitionPhase::Starting;
    state->instance = kInvalidServiceInstanceKey;
    state->desired_running = true;
    state->start_in_flight = true;
    *out_ticket = ServiceStartTicket{state->service_identity, state->generation};
    return ServiceStartReserveResult::Reserved;
}

bool ServiceTransitionIsCurrentStart(const ServiceTransitionState& state, ServiceStartTicket ticket)
{
    return ServiceTransitionIsCanonical(state) && state.phase == ServiceTransitionPhase::Starting &&
           state.desired_running && state.start_in_flight && TicketMatches(state, ticket);
}

ServiceSpawnFailureResult ServiceTransitionRecordSpawnFailure(ServiceTransitionState* state, ServiceStartTicket ticket)
{
    if (state == nullptr || !ServiceTransitionIsCurrentStart(*state, ticket))
    {
        return ServiceSpawnFailureResult::Rejected;
    }
    state->phase = ServiceTransitionPhase::Failed;
    state->instance = kInvalidServiceInstanceKey;
    state->desired_running = false;
    state->start_in_flight = false;
    return ServiceSpawnFailureResult::Applied;
}

ServicePublicationResult ServiceTransitionCommitAtSchedulerPublication(ServiceTransitionState* state,
                                                                       ServiceStartTicket ticket,
                                                                       ServiceInstanceKey instance)
{
    if (state == nullptr || !ServiceInstanceKeyIsValid(instance) || !ServiceTransitionIsCurrentStart(*state, ticket))
    {
        return ServicePublicationResult::Rejected;
    }
    state->phase = ServiceTransitionPhase::Running;
    state->instance = instance;
    state->desired_running = true;
    state->start_in_flight = false;
    return ServicePublicationResult::Published;
}

ServiceStopResult ServiceTransitionStop(ServiceTransitionState* state, ServiceInstanceToken* out_instance_to_kill)
{
    if (out_instance_to_kill != nullptr)
    {
        *out_instance_to_kill = kInvalidServiceInstanceToken;
    }
    if (state == nullptr || out_instance_to_kill == nullptr || !ServiceTransitionIsCanonical(*state))
    {
        return ServiceStopResult::Rejected;
    }
    if (state->phase == ServiceTransitionPhase::Stopped || state->phase == ServiceTransitionPhase::Exited ||
        state->phase == ServiceTransitionPhase::Failed || state->phase == ServiceTransitionPhase::GenerationExhausted)
    {
        return ServiceStopResult::AlreadyStopped;
    }

    if (state->phase == ServiceTransitionPhase::Stopping)
    {
        return ServiceStopResult::AlreadyStopping;
    }
    if (state->phase == ServiceTransitionPhase::Running)
    {
        *out_instance_to_kill =
            ServiceInstanceToken{ServiceStartTicket{state->service_identity, state->generation}, state->instance};
        state->phase = ServiceTransitionPhase::Stopping;
        state->desired_running = false;
        state->start_in_flight = false;
        return ServiceStopResult::KillRequired;
    }

    // Starting is the only remaining canonical phase.  The private graph was
    // never published, so invalidating its phase is sufficient; the next
    // reservation advances the generation before minting new authority.
    state->instance = kInvalidServiceInstanceKey;
    state->desired_running = false;
    state->start_in_flight = false;
    if (state->generation == kServiceTransitionGenerationMaximum)
    {
        state->phase = ServiceTransitionPhase::GenerationExhausted;
    }
    else
    {
        state->phase = ServiceTransitionPhase::Stopped;
    }
    return ServiceStopResult::StartCancelled;
}

bool ServiceTransitionIsCurrentInstance(const ServiceTransitionState& state, ServiceInstanceToken instance)
{
    return ServiceInstanceTokenIsValid(instance) && ServiceTransitionIsCanonical(state) &&
           (state.phase == ServiceTransitionPhase::Running || state.phase == ServiceTransitionPhase::Stopping) &&
           state.instance == instance.process && TicketMatches(state, instance.start);
}

bool ServiceTransitionIsCurrentRunning(const ServiceTransitionState& state, ServiceInstanceToken instance)
{
    return state.phase == ServiceTransitionPhase::Running && state.desired_running &&
           ServiceTransitionIsCurrentInstance(state, instance);
}

ServiceExitResult ServiceTransitionObserveExit(ServiceTransitionState* state, ServiceInstanceToken instance)
{
    if (state == nullptr || !ServiceTransitionIsCurrentInstance(*state, instance))
    {
        return ServiceExitResult::Rejected;
    }
    const bool stop_was_requested = state->phase == ServiceTransitionPhase::Stopping;
    state->instance = kInvalidServiceInstanceKey;
    state->desired_running = false;
    state->start_in_flight = false;
    if (stop_was_requested)
    {
        state->phase = state->generation == kServiceTransitionGenerationMaximum
                           ? ServiceTransitionPhase::GenerationExhausted
                           : ServiceTransitionPhase::Stopped;
    }
    else
    {
        state->phase = ServiceTransitionPhase::Exited;
    }
    return ServiceExitResult::Applied;
}

} // namespace duetos::core
