// Hosted exact-epoch, replay, exhaustion, drain, and caller-lock concurrency
// coverage for ipc/endpoint_request_ledger.{h,cpp}.

#include "host_test_helper.h"
#include "ipc/endpoint_request_ledger.h"

#include <array>
#include <atomic>
#include <barrier>
#include <mutex>
#include <thread>
#include <unordered_map>

namespace
{

using duetos::u32;
using duetos::u64;
using duetos::u8;
using namespace duetos::ipc;

EndpointRequestKey Key(u64 epoch, u64 request_id)
{
    return EndpointRequestKey{epoch, request_id};
}

EndpointRequestLedger NewLedger(u64 epoch, u64 first_request_id = 1)
{
    EndpointRequestLedger ledger{};
    EXPECT_EQ(EndpointRequestLedgerInitialize(&ledger, epoch, first_request_id), EndpointRequestLedgerStatus::Ok);
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
    u64 epoch;
    u64 next_request_id;
    ModelState state;
    // false=Reserved, true=Committed
    std::unordered_map<u64, bool> active;
};

ModelLedger NewModel(u64 epoch, u64 first_request_id = 1)
{
    return ModelLedger{epoch, first_request_id, ModelState::Open, {}};
}

EndpointRequestLedgerStatus ModelValidateKey(const ModelLedger& model, EndpointRequestKey key)
{
    if (!EndpointRequestKeyIsValid(key))
        return EndpointRequestLedgerStatus::InvalidArgument;
    if (key.endpoint_epoch != model.epoch)
        return EndpointRequestLedgerStatus::StaleEpoch;
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
        return Key(model.epoch, model.active.begin()->first);
    if (selector == 1)
        return Key(model.epoch, model.next_request_id == 0 ? 1 : model.next_request_id);
    if (selector == 2)
    {
        const u64 next = model.next_request_id == 0 ? 1 : model.next_request_id;
        return Key(model.epoch, next == kEndpointRequestIdMaximum ? next : next + 1);
    }
    if (selector == 3)
    {
        const u64 next = model.next_request_id == 0 ? kEndpointRequestIdMaximum : model.next_request_id;
        return Key(model.epoch, next > 1 ? next - 1 : 1);
    }
    if (selector == 4)
        return Key(model.epoch + 1, model.next_request_id == 0 ? 1 : model.next_request_id);
    return (sample & 1) != 0 ? Key(0, 1) : Key(model.epoch, 0);
}

void ExpectModelMatches(const EndpointRequestLedger& ledger, const ModelLedger& model)
{
    EXPECT_TRUE(EndpointRequestLedgerIsCanonical(ledger));
    EXPECT_EQ(ledger.endpoint_epoch, model.epoch);
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
    EXPECT_EQ(EndpointRequestLedgerInitialize(nullptr, 1), EndpointRequestLedgerStatus::InvalidArgument);
    EXPECT_EQ(EndpointRequestLedgerInitialize(&uninitialized, 0), EndpointRequestLedgerStatus::InvalidArgument);
    EXPECT_TRUE(EndpointRequestLedgerIsCanonical(uninitialized));
    EXPECT_EQ(EndpointRequestLedgerInitialize(&uninitialized, 1, 0), EndpointRequestLedgerStatus::InvalidArgument);
    EXPECT_TRUE(EndpointRequestLedgerIsCanonical(uninitialized));

    EndpointRequestLedger ledger = NewLedger(7);
    EXPECT_EQ(ledger.next_request_id, 1ULL);
    EXPECT_EQ(EndpointRequestLedgerReserve(&ledger, Key(0, 1)), EndpointRequestLedgerStatus::InvalidArgument);
    EXPECT_EQ(EndpointRequestLedgerReserve(&ledger, Key(8, 1)), EndpointRequestLedgerStatus::StaleEpoch);
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
    EXPECT_EQ(EndpointRequestLedgerCommit(&ledger, request1, nullptr), EndpointRequestLedgerStatus::InvalidArgument);
    EXPECT_EQ(EndpointRequestLedgerCommit(&ledger, request1, &authority1), EndpointRequestLedgerStatus::Ok);
    EXPECT_TRUE(EndpointRequestCompletionAuthorityIsValid(authority1));
    EXPECT_TRUE(authority1.request_key() == request1);

    EndpointRequestCompletionAuthority duplicate_authority{};
    EXPECT_EQ(EndpointRequestLedgerCommit(&ledger, request1, &duplicate_authority),
              EndpointRequestLedgerStatus::ReplayRejected);
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
    EXPECT_EQ(EndpointRequestLedgerCommit(&ledger, request2, &duplicate_authority),
              EndpointRequestLedgerStatus::ReplayRejected);
    EXPECT_FALSE(EndpointRequestCompletionAuthorityIsValid(duplicate_authority));
    EXPECT_EQ(EndpointRequestLedgerCommit(&ledger, Key(7, 3), &duplicate_authority),
              EndpointRequestLedgerStatus::NotFound);
    EXPECT_EQ(EndpointRequestLedgerCancel(&ledger, Key(7, 4)), EndpointRequestLedgerStatus::OutOfOrder);
    EXPECT_TRUE(EndpointRequestLedgerIsCanonical(ledger));

    EndpointRequestLedger other_epoch = NewLedger(8);
    EndpointRequestCompletionAuthority other_authority{};
    EXPECT_EQ(EndpointRequestLedgerReserve(&other_epoch, Key(8, 1)), EndpointRequestLedgerStatus::Ok);
    EXPECT_EQ(EndpointRequestLedgerCommit(&other_epoch, Key(8, 1), &other_authority), EndpointRequestLedgerStatus::Ok);
    EXPECT_EQ(EndpointRequestLedgerComplete(&ledger, other_authority), EndpointRequestLedgerStatus::StaleEpoch);

    // Capacity failure must not consume the exact next sequence. Once a row is
    // released, retrying that same ID succeeds.
    EndpointRequestLedger full = NewLedger(20);
    std::array<EndpointRequestCompletionAuthority, kEndpointRequestLedgerCapacity> full_authorities{};
    for (u32 index = 0; index < kEndpointRequestLedgerCapacity; ++index)
    {
        const EndpointRequestKey key = Key(20, static_cast<u64>(index) + 1);
        EXPECT_EQ(EndpointRequestLedgerReserve(&full, key), EndpointRequestLedgerStatus::Ok);
        EXPECT_EQ(EndpointRequestLedgerCommit(&full, key, &full_authorities[index]), EndpointRequestLedgerStatus::Ok);
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
    EndpointRequestCompletionAuthority terminal_authority{};
    EXPECT_EQ(EndpointRequestLedgerCommit(&terminal, terminal_key, &terminal_authority),
              EndpointRequestLedgerStatus::Ok);
    EXPECT_EQ(EndpointRequestLedgerReserve(&terminal, Key(30, 1)), EndpointRequestLedgerStatus::SequenceExhausted);
    EXPECT_EQ(EndpointRequestLedgerComplete(&terminal, terminal_authority), EndpointRequestLedgerStatus::Ok);
    EXPECT_EQ(EndpointRequestLedgerCommit(&terminal, terminal_key, &terminal_authority),
              EndpointRequestLedgerStatus::ReplayRejected);
    EXPECT_FALSE(EndpointRequestCompletionAuthorityIsValid(terminal_authority));
    EXPECT_EQ(terminal.state, EndpointRequestLedgerState::SequenceRetired);
    EXPECT_TRUE(EndpointRequestLedgerIsCanonical(terminal));

    // Drain cancels every outstanding phase, is idempotent, and prevents any
    // stale completion from publishing a reply.
    EndpointRequestLedger draining = NewLedger(40);
    EndpointRequestCompletionAuthority draining_authority{};
    EXPECT_EQ(EndpointRequestLedgerReserve(&draining, Key(40, 1)), EndpointRequestLedgerStatus::Ok);
    EXPECT_EQ(EndpointRequestLedgerCommit(&draining, Key(40, 1), &draining_authority), EndpointRequestLedgerStatus::Ok);
    EXPECT_EQ(EndpointRequestLedgerReserve(&draining, Key(40, 2)), EndpointRequestLedgerStatus::Ok);
    u32 cancelled = 99;
    EXPECT_EQ(EndpointRequestLedgerDrain(&draining, nullptr), EndpointRequestLedgerStatus::InvalidArgument);
    EXPECT_EQ(EndpointRequestLedgerDrain(nullptr, &cancelled), EndpointRequestLedgerStatus::InvalidArgument);
    EXPECT_EQ(cancelled, 0U);
    cancelled = 99;
    EXPECT_EQ(EndpointRequestLedgerDrain(&draining, &cancelled), EndpointRequestLedgerStatus::Ok);
    EXPECT_EQ(cancelled, 2U);
    EXPECT_EQ(draining.state, EndpointRequestLedgerState::Draining);
    EXPECT_EQ(draining.active_count, 0U);
    EXPECT_EQ(EndpointRequestLedgerReserve(&draining, Key(40, 3)), EndpointRequestLedgerStatus::Draining);
    EXPECT_EQ(EndpointRequestLedgerCommit(&draining, Key(40, 1), &duplicate_authority),
              EndpointRequestLedgerStatus::Draining);
    EXPECT_FALSE(EndpointRequestCompletionAuthorityIsValid(duplicate_authority));
    EXPECT_EQ(EndpointRequestLedgerCancel(&draining, Key(40, 2)), EndpointRequestLedgerStatus::Draining);
    EXPECT_EQ(EndpointRequestLedgerComplete(&draining, draining_authority), EndpointRequestLedgerStatus::Draining);
    EXPECT_EQ(EndpointRequestLedgerReserve(&draining, Key(41, 3)), EndpointRequestLedgerStatus::StaleEpoch);
    cancelled = 99;
    EXPECT_EQ(EndpointRequestLedgerDrain(&draining, &cancelled), EndpointRequestLedgerStatus::Ok);
    EXPECT_EQ(cancelled, 0U);
    EXPECT_TRUE(EndpointRequestLedgerIsCanonical(draining));

    // Structural corruption fails closed and clears authority outputs.
    EndpointRequestLedger corrupt = NewLedger(50);
    corrupt.active_count = 1;
    EXPECT_FALSE(EndpointRequestLedgerIsCanonical(corrupt));
    duplicate_authority = EndpointRequestCompletionAuthority{};
    EXPECT_EQ(EndpointRequestLedgerCommit(&corrupt, Key(50, 1), &duplicate_authority),
              EndpointRequestLedgerStatus::CorruptState);
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
            EndpointRequestCompletionAuthority actual_authority{};
            bool model_authority = false;
            EXPECT_EQ(EndpointRequestLedgerCommit(&churn, key, &actual_authority),
                      ModelCommit(model, key, &model_authority));
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
            u32 actual_cancelled = 0;
            const u32 model_cancelled = ModelDrain(model);
            EXPECT_EQ(EndpointRequestLedgerDrain(&churn, &actual_cancelled), EndpointRequestLedgerStatus::Ok);
            EXPECT_EQ(actual_cancelled, model_cancelled);
            churn_authorities.clear();
            break;
        }
        }
        ExpectModelMatches(churn, model);

        // A drained object may be reused only after its endpoint owner proves
        // quiescence and installs a strictly newer epoch.
        if (model.state == ModelState::Draining && (iteration & 7U) == 0)
        {
            const u64 next_epoch = model.epoch + 1;
            EXPECT_EQ(EndpointRequestLedgerInitialize(&churn, next_epoch), EndpointRequestLedgerStatus::Ok);
            model = NewModel(next_epoch);
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
        const EndpointRequestKey raced_key = Key(raced.endpoint_epoch, 1);
        EndpointRequestCompletionAuthority raced_authority{};
        EXPECT_EQ(EndpointRequestLedgerReserve(&raced, raced_key), EndpointRequestLedgerStatus::Ok);
        EXPECT_EQ(EndpointRequestLedgerCommit(&raced, raced_key, &raced_authority), EndpointRequestLedgerStatus::Ok);
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
