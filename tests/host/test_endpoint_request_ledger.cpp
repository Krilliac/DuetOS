// Hosted directional-identity, replay, reset, exact-drain, and caller-lock
// concurrency coverage for ipc/endpoint_request_ledger.{h,cpp}.

#include "host_test_helper.h"
#include "ipc/endpoint_request_ledger.h"

#include <array>
#include <atomic>
#include <barrier>
#include <mutex>
#include <thread>
#include <type_traits>
#include <unordered_map>

namespace
{

using duetos::u32;
using duetos::u64;
using duetos::u8;
using namespace duetos::ipc;

EndpointRequestLedgerIdentity Identity(
    u64 epoch, EndpointRequestDirection direction = EndpointRequestDirection::InitiatorToAcceptor)
{
    return EndpointRequestLedgerIdentity{epoch, direction};
}

EndpointRequestKey Key(EndpointRequestLedgerIdentity identity, u64 request_id)
{
    return EndpointRequestKey{identity, request_id};
}

EndpointRequestKey Key(u64 epoch, u64 request_id,
                       EndpointRequestDirection direction = EndpointRequestDirection::InitiatorToAcceptor)
{
    return Key(Identity(epoch, direction), request_id);
}

EndpointRequestLedger NewLedger(u64 epoch, u64 first_request_id = 1,
                                EndpointRequestDirection direction = EndpointRequestDirection::InitiatorToAcceptor)
{
    EndpointRequestLedger ledger{};
    EXPECT_EQ(EndpointRequestLedgerInitialize(&ledger, Identity(epoch, direction), first_request_id),
              EndpointRequestLedgerStatus::Ok);
    EXPECT_TRUE(EndpointRequestLedgerIsCanonical(ledger));
    return ledger;
}

u64 NextRandom(u64& state)
{
    state ^= state << 13;
    state ^= state >> 7;
    state ^= state << 17;
    return state;
}

enum class ModelState : u8
{
    Open,
    SequenceRetired,
    Draining,
};

struct ModelLedger
{
    EndpointRequestLedgerIdentity identity;
    u64 next_request_id;
    ModelState state;
    // false=Reserved, true=Committed
    std::unordered_map<u64, bool> active;
};

ModelLedger NewModel(u64 epoch, u64 first_request_id = 1,
                     EndpointRequestDirection direction = EndpointRequestDirection::InitiatorToAcceptor)
{
    return ModelLedger{Identity(epoch, direction), first_request_id, ModelState::Open, {}};
}

EndpointRequestLedgerStatus ModelValidateKey(const ModelLedger& model, EndpointRequestKey key)
{
    if (!EndpointRequestKeyIsValid(key))
        return EndpointRequestLedgerStatus::InvalidArgument;
    if (!(key.ledger_identity == model.identity))
        return EndpointRequestLedgerStatus::StaleIdentity;
    return EndpointRequestLedgerStatus::Ok;
}

EndpointRequestLedgerStatus ModelMissing(const ModelLedger& model, EndpointRequestKey key)
{
    if (model.state == ModelState::Draining)
        return EndpointRequestLedgerStatus::Draining;
    if (model.state == ModelState::SequenceRetired)
        return EndpointRequestLedgerStatus::ReplayRejected;
    if (key.request_id < model.next_request_id)
        return EndpointRequestLedgerStatus::ReplayRejected;
    if (key.request_id > model.next_request_id)
        return EndpointRequestLedgerStatus::OutOfOrder;
    return EndpointRequestLedgerStatus::NotFound;
}

EndpointRequestLedgerStatus ModelReserve(ModelLedger& model, EndpointRequestKey key)
{
    const EndpointRequestLedgerStatus key_status = ModelValidateKey(model, key);
    if (key_status != EndpointRequestLedgerStatus::Ok)
        return key_status;
    if (model.state == ModelState::Draining)
        return EndpointRequestLedgerStatus::Draining;
    if (model.state == ModelState::SequenceRetired)
        return EndpointRequestLedgerStatus::SequenceExhausted;
    if (key.request_id < model.next_request_id)
        return EndpointRequestLedgerStatus::ReplayRejected;
    if (key.request_id > model.next_request_id)
        return EndpointRequestLedgerStatus::OutOfOrder;
    if (model.active.size() == kEndpointRequestLedgerCapacity)
        return EndpointRequestLedgerStatus::Full;

    model.active.emplace(key.request_id, false);
    if (key.request_id == kEndpointRequestIdMaximum)
    {
        model.next_request_id = 0;
        model.state = ModelState::SequenceRetired;
    }
    else
    {
        model.next_request_id = key.request_id + 1;
    }
    return EndpointRequestLedgerStatus::Ok;
}

EndpointRequestLedgerStatus ModelCommit(ModelLedger& model, EndpointRequestKey key, bool* authority_out)
{
    *authority_out = false;
    const EndpointRequestLedgerStatus key_status = ModelValidateKey(model, key);
    if (key_status != EndpointRequestLedgerStatus::Ok)
        return key_status;
    if (model.state == ModelState::Draining)
        return EndpointRequestLedgerStatus::Draining;
    const auto found = model.active.find(key.request_id);
    if (found == model.active.end())
        return ModelMissing(model, key);
    if (found->second)
        return EndpointRequestLedgerStatus::ReplayRejected;
    found->second = true;
    *authority_out = true;
    return EndpointRequestLedgerStatus::Ok;
}

EndpointRequestLedgerStatus ModelCancel(ModelLedger& model, EndpointRequestKey key)
{
    const EndpointRequestLedgerStatus key_status = ModelValidateKey(model, key);
    if (key_status != EndpointRequestLedgerStatus::Ok)
        return key_status;
    if (model.state == ModelState::Draining)
        return EndpointRequestLedgerStatus::Draining;
    const auto found = model.active.find(key.request_id);
    if (found == model.active.end())
        return ModelMissing(model, key);
    model.active.erase(found);
    return EndpointRequestLedgerStatus::Ok;
}

EndpointRequestLedgerStatus ModelComplete(ModelLedger& model, EndpointRequestKey key)
{
    const EndpointRequestLedgerStatus key_status = ModelValidateKey(model, key);
    if (key_status != EndpointRequestLedgerStatus::Ok)
        return key_status;
    if (model.state == ModelState::Draining)
        return EndpointRequestLedgerStatus::Draining;
    const auto found = model.active.find(key.request_id);
    if (found == model.active.end())
        return ModelMissing(model, key);
    if (!found->second)
        return EndpointRequestLedgerStatus::NotCommitted;
    model.active.erase(found);
    return EndpointRequestLedgerStatus::Ok;
}

u32 ModelDrain(ModelLedger& model)
{
    if (model.state == ModelState::Draining)
        return 0;
    const u32 cancelled = static_cast<u32>(model.active.size());
    model.active.clear();
    model.next_request_id = 0;
    model.state = ModelState::Draining;
    return cancelled;
}

EndpointRequestKey SelectModelKey(const ModelLedger& model, u64 sample)
{
    const u64 selector = (sample >> 8) % 6;
    if (selector == 0 && !model.active.empty())
        return Key(model.identity, model.active.begin()->first);
    if (selector == 1)
        return Key(model.identity, model.next_request_id == 0 ? 1 : model.next_request_id);
    if (selector == 2)
    {
        const u64 next = model.next_request_id == 0 ? 1 : model.next_request_id;
        return Key(model.identity, next == kEndpointRequestIdMaximum ? next : next + 1);
    }
    if (selector == 3)
    {
        const u64 next = model.next_request_id == 0 ? kEndpointRequestIdMaximum : model.next_request_id;
        return Key(model.identity, next > 1 ? next - 1 : 1);
    }
    if (selector == 4)
        return Key(Identity(model.identity.endpoint_epoch + 1, model.identity.direction),
                   model.next_request_id == 0 ? 1 : model.next_request_id);
    return (sample & 1) != 0 ? Key(0, 1) : Key(model.identity, 0);
}

void ExpectModelMatches(const EndpointRequestLedger& ledger, const ModelLedger& model)
{
    EXPECT_TRUE(EndpointRequestLedgerIsCanonical(ledger));
    EXPECT_TRUE(ledger.identity == model.identity);
    EXPECT_EQ(ledger.next_request_id, model.next_request_id);
    EXPECT_EQ(ledger.active_count, static_cast<u32>(model.active.size()));
    if (model.state == ModelState::Open)
        EXPECT_EQ(ledger.state, EndpointRequestLedgerState::Open);
    else if (model.state == ModelState::SequenceRetired)
        EXPECT_EQ(ledger.state, EndpointRequestLedgerState::SequenceRetired);
    else
        EXPECT_EQ(ledger.state, EndpointRequestLedgerState::Draining);
}

} // namespace

int main()
{
    // Commit and Drain publish bounded values rather than writing through a
    // caller-controlled address. These signature checks are the regression
    // gate for the former output-alias corruption surface.
    static_assert(std::is_same_v<decltype(EndpointRequestLedgerCommit(nullptr, kInvalidEndpointRequestKey)),
                                 EndpointRequestCommitResult>);
    static_assert(std::is_same_v<decltype(EndpointRequestLedgerDrain(nullptr)), EndpointRequestDrainResult>);

    EXPECT_FALSE(EndpointRequestLedgerIdentityIsValid(kInvalidEndpointRequestLedgerIdentity));
    EXPECT_FALSE(EndpointRequestLedgerIdentityIsValid(Identity(1, EndpointRequestDirection::Invalid)));
    EXPECT_TRUE(EndpointRequestLedgerIdentityIsValid(Identity(1)));
    EXPECT_FALSE(EndpointRequestKeyIsValid(kInvalidEndpointRequestKey));
    EXPECT_FALSE(EndpointRequestKeyIsValid(Key(0, 1)));
    EXPECT_FALSE(EndpointRequestKeyIsValid(Key(1, 0)));
    EXPECT_TRUE(EndpointRequestKeyIsValid(Key(1, 1)));
    EXPECT_FALSE(EndpointRequestCompletionAuthorityIsValid(kInvalidEndpointRequestCompletionAuthority));

    EndpointRequestLedger uninitialized{};
    EXPECT_TRUE(EndpointRequestLedgerIsCanonical(uninitialized));
    EXPECT_EQ(EndpointRequestLedgerReserve(nullptr, Key(1, 1)), EndpointRequestLedgerStatus::InvalidArgument);
    EXPECT_EQ(EndpointRequestLedgerCancel(nullptr, Key(1, 1)), EndpointRequestLedgerStatus::InvalidArgument);
    EXPECT_EQ(EndpointRequestLedgerComplete(nullptr, kInvalidEndpointRequestCompletionAuthority),
              EndpointRequestLedgerStatus::InvalidArgument);
    EXPECT_EQ(EndpointRequestLedgerReserve(&uninitialized, Key(1, 1)), EndpointRequestLedgerStatus::NotInitialized);
    EXPECT_EQ(EndpointRequestLedgerInitialize(nullptr, Identity(1)), EndpointRequestLedgerStatus::InvalidArgument);
    EXPECT_EQ(EndpointRequestLedgerReset(nullptr, Identity(2)), EndpointRequestLedgerStatus::InvalidArgument);
    EXPECT_EQ(EndpointRequestLedgerReset(&uninitialized, Identity(2)), EndpointRequestLedgerStatus::NotInitialized);
    EXPECT_EQ(EndpointRequestLedgerInitialize(&uninitialized, kInvalidEndpointRequestLedgerIdentity),
              EndpointRequestLedgerStatus::InvalidArgument);
    EXPECT_TRUE(EndpointRequestLedgerIsCanonical(uninitialized));
    EXPECT_EQ(EndpointRequestLedgerInitialize(&uninitialized, Identity(1), 0),
              EndpointRequestLedgerStatus::InvalidArgument);
    EXPECT_TRUE(EndpointRequestLedgerIsCanonical(uninitialized));

    // Initialize is one-shot and cannot erase live authority. Reset is a
    // separate transition that refuses any state other than drained+empty.
    EXPECT_EQ(EndpointRequestLedgerInitialize(&uninitialized, Identity(1)), EndpointRequestLedgerStatus::Ok);
    EXPECT_EQ(EndpointRequestLedgerReserve(&uninitialized, Key(1, 1)), EndpointRequestLedgerStatus::Ok);
    EXPECT_EQ(EndpointRequestLedgerInitialize(&uninitialized, Identity(2)),
              EndpointRequestLedgerStatus::AlreadyInitialized);
    EXPECT_EQ(EndpointRequestLedgerReset(&uninitialized, Identity(2)), EndpointRequestLedgerStatus::ResetNotDrained);
    EXPECT_TRUE(uninitialized.identity == Identity(1));
    EXPECT_EQ(uninitialized.active_count, 1U);
    EXPECT_EQ(EndpointRequestLedgerCancel(&uninitialized, Key(1, 1)), EndpointRequestLedgerStatus::Ok);
    EXPECT_EQ(EndpointRequestLedgerInitialize(&uninitialized, Identity(2)),
              EndpointRequestLedgerStatus::AlreadyInitialized);
    EXPECT_EQ(EndpointRequestLedgerReset(&uninitialized, Identity(2)), EndpointRequestLedgerStatus::ResetNotDrained);

    EndpointRequestLedger ledger = NewLedger(7);
    EXPECT_EQ(ledger.next_request_id, 1ULL);
    EXPECT_EQ(EndpointRequestLedgerReserve(&ledger, Key(0, 1)), EndpointRequestLedgerStatus::InvalidArgument);
    EXPECT_EQ(EndpointRequestLedgerReserve(&ledger, Key(8, 1)), EndpointRequestLedgerStatus::StaleIdentity);
    EXPECT_EQ(EndpointRequestLedgerReserve(&ledger, Key(7, 2)), EndpointRequestLedgerStatus::OutOfOrder);
    EXPECT_EQ(ledger.next_request_id, 1ULL);
    EXPECT_EQ(ledger.active_count, 0U);

    const EndpointRequestKey request1 = Key(7, 1);
    EXPECT_EQ(EndpointRequestLedgerReserve(&ledger, request1), EndpointRequestLedgerStatus::Ok);
    EXPECT_EQ(EndpointRequestLedgerReserve(&ledger, request1), EndpointRequestLedgerStatus::ReplayRejected);
    EXPECT_EQ(ledger.next_request_id, 2ULL);
    EXPECT_EQ(ledger.active_count, 1U);

    // A raw key cannot construct completion authority. The public default is
    // invalid until the one-shot Commit boundary mints a trusted value.
    EndpointRequestCompletionAuthority authority1{};
    EXPECT_EQ(EndpointRequestLedgerComplete(&ledger, authority1), EndpointRequestLedgerStatus::InvalidArgument);
    const EndpointRequestCommitResult commit1 = EndpointRequestLedgerCommit(&ledger, request1);
    EXPECT_EQ(commit1.status, EndpointRequestLedgerStatus::Ok);
    authority1 = commit1.completion_authority;
    EXPECT_TRUE(EndpointRequestCompletionAuthorityIsValid(authority1));
    EXPECT_TRUE(authority1.request_key() == request1);

    EndpointRequestCompletionAuthority duplicate_authority{};
    EndpointRequestCommitResult duplicate_commit = EndpointRequestLedgerCommit(&ledger, request1);
    EXPECT_EQ(duplicate_commit.status, EndpointRequestLedgerStatus::ReplayRejected);
    duplicate_authority = duplicate_commit.completion_authority;
    EXPECT_FALSE(EndpointRequestCompletionAuthorityIsValid(duplicate_authority));
    const EndpointRequestCompletionAuthority authority_copy = authority1;
    EXPECT_EQ(EndpointRequestLedgerComplete(&ledger, authority1), EndpointRequestLedgerStatus::Ok);
    EXPECT_EQ(EndpointRequestLedgerComplete(&ledger, authority_copy), EndpointRequestLedgerStatus::ReplayRejected);
    EXPECT_EQ(EndpointRequestLedgerCancel(&ledger, request1), EndpointRequestLedgerStatus::ReplayRejected);
    EXPECT_EQ(ledger.active_count, 0U);

    const EndpointRequestKey request2 = Key(7, 2);
    EXPECT_EQ(EndpointRequestLedgerReserve(&ledger, request2), EndpointRequestLedgerStatus::Ok);
    EXPECT_EQ(EndpointRequestLedgerCancel(&ledger, request2), EndpointRequestLedgerStatus::Ok);
    EXPECT_EQ(EndpointRequestLedgerCancel(&ledger, request2), EndpointRequestLedgerStatus::ReplayRejected);
    duplicate_commit = EndpointRequestLedgerCommit(&ledger, request2);
    EXPECT_EQ(duplicate_commit.status, EndpointRequestLedgerStatus::ReplayRejected);
    duplicate_authority = duplicate_commit.completion_authority;
    EXPECT_FALSE(EndpointRequestCompletionAuthorityIsValid(duplicate_authority));
    duplicate_commit = EndpointRequestLedgerCommit(&ledger, Key(7, 3));
    EXPECT_EQ(duplicate_commit.status, EndpointRequestLedgerStatus::NotFound);
    duplicate_authority = duplicate_commit.completion_authority;
    EXPECT_EQ(EndpointRequestLedgerCancel(&ledger, Key(7, 4)), EndpointRequestLedgerStatus::OutOfOrder);
    EXPECT_TRUE(EndpointRequestLedgerIsCanonical(ledger));

    EndpointRequestLedger other_epoch = NewLedger(8);
    EXPECT_EQ(EndpointRequestLedgerReserve(&other_epoch, Key(8, 1)), EndpointRequestLedgerStatus::Ok);
    const EndpointRequestCommitResult other_commit = EndpointRequestLedgerCommit(&other_epoch, Key(8, 1));
    EXPECT_EQ(other_commit.status, EndpointRequestLedgerStatus::Ok);
    EXPECT_EQ(EndpointRequestLedgerComplete(&ledger, other_commit.completion_authority),
              EndpointRequestLedgerStatus::StaleIdentity);

    // Equal request IDs in opposite directions are distinct authority domains.
    // A completion minted by one directional ledger cannot consume the other.
    EndpointRequestLedger forward = NewLedger(9, 1, EndpointRequestDirection::InitiatorToAcceptor);
    EndpointRequestLedger reverse = NewLedger(9, 1, EndpointRequestDirection::AcceptorToInitiator);
    const EndpointRequestKey forward_key = Key(9, 1, EndpointRequestDirection::InitiatorToAcceptor);
    const EndpointRequestKey reverse_key = Key(9, 1, EndpointRequestDirection::AcceptorToInitiator);
    EXPECT_EQ(EndpointRequestLedgerReserve(&forward, forward_key), EndpointRequestLedgerStatus::Ok);
    EXPECT_EQ(EndpointRequestLedgerReserve(&reverse, reverse_key), EndpointRequestLedgerStatus::Ok);
    const EndpointRequestCommitResult forward_commit = EndpointRequestLedgerCommit(&forward, forward_key);
    const EndpointRequestCommitResult reverse_commit = EndpointRequestLedgerCommit(&reverse, reverse_key);
    EXPECT_EQ(forward_commit.status, EndpointRequestLedgerStatus::Ok);
    EXPECT_EQ(reverse_commit.status, EndpointRequestLedgerStatus::Ok);
    EXPECT_EQ(EndpointRequestLedgerComplete(&reverse, forward_commit.completion_authority),
              EndpointRequestLedgerStatus::StaleIdentity);
    EXPECT_EQ(reverse.active_count, 1U);
    EXPECT_EQ(EndpointRequestLedgerComplete(&reverse, reverse_commit.completion_authority),
              EndpointRequestLedgerStatus::Ok);
    EXPECT_EQ(EndpointRequestLedgerComplete(&forward, forward_commit.completion_authority),
              EndpointRequestLedgerStatus::Ok);

    // Capacity failure must not consume the exact next sequence. Once a row is
    // released, retrying that same ID succeeds.
    EndpointRequestLedger full = NewLedger(20);
    std::array<EndpointRequestCompletionAuthority, kEndpointRequestLedgerCapacity> full_authorities{};
    for (u32 index = 0; index < kEndpointRequestLedgerCapacity; ++index)
    {
        const EndpointRequestKey key = Key(20, static_cast<u64>(index) + 1);
        EXPECT_EQ(EndpointRequestLedgerReserve(&full, key), EndpointRequestLedgerStatus::Ok);
        const EndpointRequestCommitResult committed = EndpointRequestLedgerCommit(&full, key);
        EXPECT_EQ(committed.status, EndpointRequestLedgerStatus::Ok);
        full_authorities[index] = committed.completion_authority;
    }
    EXPECT_EQ(full.active_count, kEndpointRequestLedgerCapacity);
    EXPECT_EQ(full.next_request_id, static_cast<u64>(kEndpointRequestLedgerCapacity) + 1);
    const EndpointRequestKey first_after_full = Key(20, full.next_request_id);
    EXPECT_EQ(EndpointRequestLedgerReserve(&full, first_after_full), EndpointRequestLedgerStatus::Full);
    EXPECT_EQ(full.next_request_id, first_after_full.request_id);
    EXPECT_EQ(EndpointRequestLedgerComplete(&full, full_authorities[0]), EndpointRequestLedgerStatus::Ok);
    EXPECT_EQ(EndpointRequestLedgerReserve(&full, first_after_full), EndpointRequestLedgerStatus::Ok);
    EXPECT_EQ(EndpointRequestLedgerCancel(&full, first_after_full), EndpointRequestLedgerStatus::Ok);
    for (u32 index = 1; index < kEndpointRequestLedgerCapacity; ++index)
        EXPECT_EQ(EndpointRequestLedgerComplete(&full, full_authorities[index]), EndpointRequestLedgerStatus::Ok);
    EXPECT_EQ(full.active_count, 0U);
    EXPECT_TRUE(EndpointRequestLedgerIsCanonical(full));

    // Reserving the terminal value retires the sequence without invalidating
    // already-issued completion authority. No ID can wrap to one.
    EndpointRequestLedger terminal = NewLedger(30, kEndpointRequestIdMaximum);
    const EndpointRequestKey terminal_key = Key(30, kEndpointRequestIdMaximum);
    EXPECT_EQ(EndpointRequestLedgerReserve(&terminal, terminal_key), EndpointRequestLedgerStatus::Ok);
    EXPECT_EQ(terminal.state, EndpointRequestLedgerState::SequenceRetired);
    EXPECT_EQ(terminal.next_request_id, 0ULL);
    EndpointRequestCommitResult terminal_commit = EndpointRequestLedgerCommit(&terminal, terminal_key);
    EXPECT_EQ(terminal_commit.status, EndpointRequestLedgerStatus::Ok);
    EndpointRequestCompletionAuthority terminal_authority = terminal_commit.completion_authority;
    EXPECT_EQ(EndpointRequestLedgerReserve(&terminal, Key(30, 1)), EndpointRequestLedgerStatus::SequenceExhausted);
    EXPECT_EQ(EndpointRequestLedgerComplete(&terminal, terminal_authority), EndpointRequestLedgerStatus::Ok);
    terminal_commit = EndpointRequestLedgerCommit(&terminal, terminal_key);
    EXPECT_EQ(terminal_commit.status, EndpointRequestLedgerStatus::ReplayRejected);
    terminal_authority = terminal_commit.completion_authority;
    EXPECT_FALSE(EndpointRequestCompletionAuthorityIsValid(terminal_authority));
    EXPECT_EQ(terminal.state, EndpointRequestLedgerState::SequenceRetired);
    EXPECT_TRUE(EndpointRequestLedgerIsCanonical(terminal));

    // Drain cancels every outstanding phase, is idempotent, and prevents any
    // stale completion from publishing a reply.
    EndpointRequestLedger draining = NewLedger(40);
    EXPECT_EQ(EndpointRequestLedgerReserve(&draining, Key(40, 1)), EndpointRequestLedgerStatus::Ok);
    const EndpointRequestCommitResult draining_commit = EndpointRequestLedgerCommit(&draining, Key(40, 1));
    EXPECT_EQ(draining_commit.status, EndpointRequestLedgerStatus::Ok);
    const EndpointRequestCompletionAuthority draining_authority = draining_commit.completion_authority;
    EXPECT_EQ(EndpointRequestLedgerReserve(&draining, Key(40, 2)), EndpointRequestLedgerStatus::Ok);
    const EndpointRequestDrainResult null_drain = EndpointRequestLedgerDrain(nullptr);
    EXPECT_EQ(null_drain.status, EndpointRequestLedgerStatus::InvalidArgument);
    EXPECT_EQ(null_drain.detached_count, 0U);
    const EndpointRequestDrainResult drained = EndpointRequestLedgerDrain(&draining);
    EXPECT_EQ(drained.status, EndpointRequestLedgerStatus::Ok);
    EXPECT_EQ(drained.detached_count, 2U);
    EXPECT_TRUE(drained.detached_keys[0] == Key(40, 1));
    EXPECT_TRUE(drained.detached_keys[1] == Key(40, 2));
    for (u32 index = drained.detached_count; index < kEndpointRequestLedgerCapacity; ++index)
        EXPECT_TRUE(drained.detached_keys[index] == kInvalidEndpointRequestKey);
    EXPECT_EQ(draining.state, EndpointRequestLedgerState::Draining);
    EXPECT_EQ(draining.active_count, 0U);
    EXPECT_EQ(EndpointRequestLedgerReserve(&draining, Key(40, 3)), EndpointRequestLedgerStatus::Draining);
    duplicate_commit = EndpointRequestLedgerCommit(&draining, Key(40, 1));
    EXPECT_EQ(duplicate_commit.status, EndpointRequestLedgerStatus::Draining);
    duplicate_authority = duplicate_commit.completion_authority;
    EXPECT_FALSE(EndpointRequestCompletionAuthorityIsValid(duplicate_authority));
    EXPECT_EQ(EndpointRequestLedgerCancel(&draining, Key(40, 2)), EndpointRequestLedgerStatus::Draining);
    EXPECT_EQ(EndpointRequestLedgerComplete(&draining, draining_authority), EndpointRequestLedgerStatus::Draining);
    EXPECT_EQ(EndpointRequestLedgerReserve(&draining, Key(41, 3)), EndpointRequestLedgerStatus::StaleIdentity);
    const EndpointRequestDrainResult repeated_drain = EndpointRequestLedgerDrain(&draining);
    EXPECT_EQ(repeated_drain.status, EndpointRequestLedgerStatus::Ok);
    EXPECT_EQ(repeated_drain.detached_count, 0U);
    EXPECT_TRUE(EndpointRequestLedgerIsCanonical(draining));

    // Reset is the only reuse boundary. It requires drained+empty state, keeps
    // direction immutable, and advances epoch strictly so copied authority can
    // never become valid for a new row with the same request ID.
    EndpointRequestLedger resettable = NewLedger(60);
    EXPECT_EQ(EndpointRequestLedgerReserve(&resettable, Key(60, 1)), EndpointRequestLedgerStatus::Ok);
    const EndpointRequestCommitResult old_commit = EndpointRequestLedgerCommit(&resettable, Key(60, 1));
    EXPECT_EQ(old_commit.status, EndpointRequestLedgerStatus::Ok);
    EXPECT_EQ(EndpointRequestLedgerReset(&resettable, Identity(61)), EndpointRequestLedgerStatus::ResetNotDrained);
    const EndpointRequestDrainResult old_drain = EndpointRequestLedgerDrain(&resettable);
    EXPECT_EQ(old_drain.status, EndpointRequestLedgerStatus::Ok);
    EXPECT_EQ(old_drain.detached_count, 1U);
    EXPECT_TRUE(old_drain.detached_keys[0] == Key(60, 1));
    EXPECT_EQ(EndpointRequestLedgerReset(&resettable, Identity(61), 0), EndpointRequestLedgerStatus::InvalidArgument);
    EXPECT_EQ(EndpointRequestLedgerReset(&resettable, Identity(60)), EndpointRequestLedgerStatus::StaleIdentity);
    EXPECT_EQ(EndpointRequestLedgerReset(&resettable, Identity(59)), EndpointRequestLedgerStatus::StaleIdentity);
    EXPECT_EQ(EndpointRequestLedgerReset(&resettable, Identity(61, EndpointRequestDirection::AcceptorToInitiator)),
              EndpointRequestLedgerStatus::InvalidArgument);
    EXPECT_EQ(EndpointRequestLedgerReset(&resettable, Identity(61)), EndpointRequestLedgerStatus::Ok);
    EXPECT_TRUE(resettable.identity == Identity(61));
    EXPECT_TRUE(old_drain.detached_keys[0] == Key(60, 1));
    EXPECT_EQ(EndpointRequestLedgerReserve(&resettable, Key(61, 1)), EndpointRequestLedgerStatus::Ok);
    const EndpointRequestCommitResult new_commit = EndpointRequestLedgerCommit(&resettable, Key(61, 1));
    EXPECT_EQ(new_commit.status, EndpointRequestLedgerStatus::Ok);
    EXPECT_EQ(EndpointRequestLedgerComplete(&resettable, old_commit.completion_authority),
              EndpointRequestLedgerStatus::StaleIdentity);
    EXPECT_EQ(resettable.active_count, 1U);
    EXPECT_EQ(EndpointRequestLedgerComplete(&resettable, new_commit.completion_authority),
              EndpointRequestLedgerStatus::Ok);
    EXPECT_EQ(EndpointRequestLedgerInitialize(&resettable, Identity(62)),
              EndpointRequestLedgerStatus::AlreadyInitialized);

    EndpointRequestLedger exhausted_identity = NewLedger(kEndpointRequestEpochMaximum);
    EXPECT_EQ(EndpointRequestLedgerDrain(&exhausted_identity).status, EndpointRequestLedgerStatus::Ok);
    EXPECT_EQ(EndpointRequestLedgerReset(&exhausted_identity, Identity(kEndpointRequestEpochMaximum)),
              EndpointRequestLedgerStatus::IdentityExhausted);

    // Structural corruption fails closed and returns invalid authority.
    EndpointRequestLedger corrupt = NewLedger(50);
    corrupt.active_count = 1;
    EXPECT_FALSE(EndpointRequestLedgerIsCanonical(corrupt));
    duplicate_commit = EndpointRequestLedgerCommit(&corrupt, Key(50, 1));
    EXPECT_EQ(duplicate_commit.status, EndpointRequestLedgerStatus::CorruptState);
    duplicate_authority = duplicate_commit.completion_authority;
    EXPECT_FALSE(EndpointRequestCompletionAuthorityIsValid(duplicate_authority));
    corrupt = NewLedger(50);
    corrupt.slots[0].key = Key(50, 1);
    EXPECT_FALSE(EndpointRequestLedgerIsCanonical(corrupt));
    corrupt = NewLedger(50);
    corrupt.next_request_id = 0;
    EXPECT_FALSE(EndpointRequestLedgerIsCanonical(corrupt));
    corrupt = NewLedger(50);
    corrupt.state = static_cast<EndpointRequestLedgerState>(0xFF);
    EXPECT_FALSE(EndpointRequestLedgerIsCanonical(corrupt));

    // Deterministic hostile model: compare 250k mixed reserve/commit/cancel/
    // complete/drain operations against an independent dynamic reference map.
    EndpointRequestLedger churn = NewLedger(100);
    ModelLedger model = NewModel(100);
    std::unordered_map<u64, EndpointRequestCompletionAuthority> churn_authorities;
    u64 rng = 0x9e3779b97f4a7c15ULL;
    for (u32 iteration = 0; iteration < 250000; ++iteration)
    {
        const u64 sample = NextRandom(rng);
        const EndpointRequestKey key = SelectModelKey(model, sample);
        switch (sample % 5)
        {
        case 0:
            EXPECT_EQ(EndpointRequestLedgerReserve(&churn, key), ModelReserve(model, key));
            break;
        case 1:
        {
            bool model_authority = false;
            const EndpointRequestCommitResult actual_commit = EndpointRequestLedgerCommit(&churn, key);
            EXPECT_EQ(actual_commit.status, ModelCommit(model, key, &model_authority));
            const EndpointRequestCompletionAuthority actual_authority = actual_commit.completion_authority;
            EXPECT_EQ(EndpointRequestCompletionAuthorityIsValid(actual_authority), model_authority);
            if (model_authority)
            {
                EXPECT_TRUE(actual_authority.request_key() == key);
                churn_authorities[key.request_id] = actual_authority;
            }
            break;
        }
        case 2:
        {
            const EndpointRequestLedgerStatus expected = ModelCancel(model, key);
            EXPECT_EQ(EndpointRequestLedgerCancel(&churn, key), expected);
            if (expected == EndpointRequestLedgerStatus::Ok)
                churn_authorities.erase(key.request_id);
            break;
        }
        case 3:
        {
            EndpointRequestCompletionAuthority authority{};
            if (!churn_authorities.empty())
                authority = churn_authorities.begin()->second;
            if (!EndpointRequestCompletionAuthorityIsValid(authority))
            {
                EXPECT_EQ(EndpointRequestLedgerComplete(&churn, authority),
                          EndpointRequestLedgerStatus::InvalidArgument);
            }
            else
            {
                const EndpointRequestKey completion_key = authority.request_key();
                const EndpointRequestLedgerStatus expected = ModelComplete(model, completion_key);
                EXPECT_EQ(EndpointRequestLedgerComplete(&churn, authority), expected);
                if (expected == EndpointRequestLedgerStatus::Ok)
                    churn_authorities.erase(completion_key.request_id);
            }
            break;
        }
        default:
        {
            const auto expected_detached = model.active;
            const u32 model_cancelled = ModelDrain(model);
            const EndpointRequestDrainResult actual_drain = EndpointRequestLedgerDrain(&churn);
            EXPECT_EQ(actual_drain.status, EndpointRequestLedgerStatus::Ok);
            EXPECT_EQ(actual_drain.detached_count, model_cancelled);
            std::unordered_map<u64, bool> observed_detached;
            for (u32 index = 0; index < actual_drain.detached_count; ++index)
            {
                const EndpointRequestKey detached = actual_drain.detached_keys[index];
                EXPECT_TRUE(detached.ledger_identity == model.identity);
                EXPECT_TRUE(expected_detached.find(detached.request_id) != expected_detached.end());
                EXPECT_TRUE(observed_detached.emplace(detached.request_id, true).second);
            }
            EXPECT_EQ(observed_detached.size(), expected_detached.size());
            churn_authorities.clear();
            break;
        }
        }
        ExpectModelMatches(churn, model);

        // A drained object may be reused only after its endpoint owner proves
        // quiescence and installs a strictly newer epoch.
        if (model.state == ModelState::Draining && (iteration & 7U) == 0)
        {
            const u64 next_epoch = model.identity.endpoint_epoch + 1;
            const EndpointRequestDirection direction = model.identity.direction;
            EXPECT_EQ(EndpointRequestLedgerReset(&churn, Identity(next_epoch, direction)),
                      EndpointRequestLedgerStatus::Ok);
            model = NewModel(next_epoch, 1, direction);
            churn_authorities.clear();
            ExpectModelMatches(churn, model);
        }
    }

    // The production primitive is caller-locked. Race Cancel against Complete
    // under that external lock: exactly one consumes the committed row, and a
    // copied completion authority never succeeds afterward.
    for (u32 iteration = 0; iteration < 2000; ++iteration)
    {
        EndpointRequestLedger raced = NewLedger(1000ULL + iteration);
        const EndpointRequestKey raced_key = Key(raced.identity, 1);
        EXPECT_EQ(EndpointRequestLedgerReserve(&raced, raced_key), EndpointRequestLedgerStatus::Ok);
        const EndpointRequestCommitResult raced_commit = EndpointRequestLedgerCommit(&raced, raced_key);
        EXPECT_EQ(raced_commit.status, EndpointRequestLedgerStatus::Ok);
        const EndpointRequestCompletionAuthority raced_authority = raced_commit.completion_authority;
        const EndpointRequestCompletionAuthority copied_authority = raced_authority;

        std::mutex endpoint_lock;
        std::barrier start_line(3);
        std::atomic<u32> complete_status{static_cast<u32>(EndpointRequestLedgerStatus::CorruptState)};
        std::atomic<u32> cancel_status{static_cast<u32>(EndpointRequestLedgerStatus::CorruptState)};
        std::thread completer(
            [&]
            {
                start_line.arrive_and_wait();
                std::lock_guard<std::mutex> guard(endpoint_lock);
                complete_status.store(static_cast<u32>(EndpointRequestLedgerComplete(&raced, raced_authority)),
                                      std::memory_order_relaxed);
            });
        std::thread canceller(
            [&]
            {
                start_line.arrive_and_wait();
                std::lock_guard<std::mutex> guard(endpoint_lock);
                cancel_status.store(static_cast<u32>(EndpointRequestLedgerCancel(&raced, raced_key)),
                                    std::memory_order_relaxed);
            });
        start_line.arrive_and_wait();
        completer.join();
        canceller.join();

        const u32 ok = static_cast<u32>(EndpointRequestLedgerStatus::Ok);
        const u32 replay = static_cast<u32>(EndpointRequestLedgerStatus::ReplayRejected);
        EXPECT_TRUE((complete_status.load(std::memory_order_relaxed) == ok &&
                     cancel_status.load(std::memory_order_relaxed) == replay) ||
                    (complete_status.load(std::memory_order_relaxed) == replay &&
                     cancel_status.load(std::memory_order_relaxed) == ok));
        EXPECT_EQ(EndpointRequestLedgerComplete(&raced, copied_authority), EndpointRequestLedgerStatus::ReplayRejected);
        EXPECT_EQ(raced.active_count, 0U);
        EXPECT_TRUE(EndpointRequestLedgerIsCanonical(raced));
    }

    for (u32 value = static_cast<u32>(EndpointRequestLedgerStatus::Ok);
         value <= static_cast<u32>(EndpointRequestLedgerStatus::NotCommitted); ++value)
    {
        EXPECT_TRUE(EndpointRequestLedgerStatusName(static_cast<EndpointRequestLedgerStatus>(value)) != nullptr);
    }
    EXPECT_TRUE(EndpointRequestLedgerStatusName(static_cast<EndpointRequestLedgerStatus>(0xFF)) != nullptr);

    return duetos_host_test::finish_main("endpoint_request_ledger");
}
