#include "ipc/endpoint_request_ledger.h"

namespace duetos::ipc
{

namespace
{

constexpr u32 kNoEndpointRequestSlot = kEndpointRequestLedgerCapacity;

void ClearSlot(EndpointRequestSlot& slot)
{
    slot.key = kInvalidEndpointRequestKey;
    slot.state = EndpointRequestSlotState::Free;
}

void ClearLedger(EndpointRequestLedger& ledger)
{
    ledger = EndpointRequestLedger{};
}

bool SlotIsClear(const EndpointRequestSlot& slot)
{
    return slot.state == EndpointRequestSlotState::Free && slot.key == kInvalidEndpointRequestKey;
}

u32 FindLiveSlot(const EndpointRequestLedger& ledger, EndpointRequestKey key)
{
    for (u32 index = 0; index < kEndpointRequestLedgerCapacity; ++index)
    {
        if (ledger.slots[index].state != EndpointRequestSlotState::Free && ledger.slots[index].key == key)
            return index;
    }
    return kNoEndpointRequestSlot;
}

u32 FindFreeSlot(const EndpointRequestLedger& ledger)
{
    for (u32 offset = 0; offset < kEndpointRequestLedgerCapacity; ++offset)
    {
        const u32 index = (ledger.next_free_hint + offset) % kEndpointRequestLedgerCapacity;
        if (ledger.slots[index].state == EndpointRequestSlotState::Free)
            return index;
    }
    return kNoEndpointRequestSlot;
}

void ConsumeSlot(EndpointRequestLedger& ledger, u32 index)
{
    ClearSlot(ledger.slots[index]);
    --ledger.active_count;
    ledger.next_free_hint = index;
}

EndpointRequestLedgerStatus ValidateLedger(const EndpointRequestLedger* ledger)
{
    if (ledger == nullptr)
        return EndpointRequestLedgerStatus::InvalidArgument;
    if (!EndpointRequestLedgerIsCanonical(*ledger))
        return EndpointRequestLedgerStatus::CorruptState;
    if (ledger->state == EndpointRequestLedgerState::Uninitialized)
        return EndpointRequestLedgerStatus::NotInitialized;
    return EndpointRequestLedgerStatus::Ok;
}

EndpointRequestLedgerStatus ValidateKeyForLedger(const EndpointRequestLedger& ledger, EndpointRequestKey key)
{
    if (!EndpointRequestKeyIsValid(key))
        return EndpointRequestLedgerStatus::InvalidArgument;
    if (key.endpoint_epoch != ledger.endpoint_epoch)
        return EndpointRequestLedgerStatus::StaleEpoch;
    return EndpointRequestLedgerStatus::Ok;
}

EndpointRequestLedgerStatus ClassifyMissingKey(const EndpointRequestLedger& ledger, EndpointRequestKey key)
{
    if (ledger.state == EndpointRequestLedgerState::Draining)
        return EndpointRequestLedgerStatus::Draining;
    if (ledger.state == EndpointRequestLedgerState::SequenceRetired)
        return EndpointRequestLedgerStatus::ReplayRejected;
    if (key.request_id < ledger.next_request_id)
        return EndpointRequestLedgerStatus::ReplayRejected;
    if (key.request_id > ledger.next_request_id)
        return EndpointRequestLedgerStatus::OutOfOrder;
    return EndpointRequestLedgerStatus::NotFound;
}

} // namespace

EndpointRequestLedgerStatus EndpointRequestLedgerInitialize(EndpointRequestLedger* ledger, u64 endpoint_epoch,
                                                            u64 first_request_id)
{
    if (ledger == nullptr)
        return EndpointRequestLedgerStatus::InvalidArgument;

    ClearLedger(*ledger);
    if (endpoint_epoch == kEndpointRequestEpochInvalid || first_request_id == kEndpointRequestIdInvalid)
        return EndpointRequestLedgerStatus::InvalidArgument;

    ledger->endpoint_epoch = endpoint_epoch;
    ledger->next_request_id = first_request_id;
    ledger->state = EndpointRequestLedgerState::Open;
    return EndpointRequestLedgerStatus::Ok;
}

bool EndpointRequestLedgerIsCanonical(const EndpointRequestLedger& ledger)
{
    if (ledger.next_free_hint >= kEndpointRequestLedgerCapacity || ledger.active_count > kEndpointRequestLedgerCapacity)
    {
        return false;
    }

    if (ledger.state == EndpointRequestLedgerState::Uninitialized)
    {
        if (ledger.endpoint_epoch != kEndpointRequestEpochInvalid ||
            ledger.next_request_id != kEndpointRequestIdInvalid || ledger.active_count != 0 ||
            ledger.next_free_hint != 0)
        {
            return false;
        }
        for (u32 index = 0; index < kEndpointRequestLedgerCapacity; ++index)
        {
            if (!SlotIsClear(ledger.slots[index]))
                return false;
        }
        return true;
    }

    if (ledger.endpoint_epoch == kEndpointRequestEpochInvalid)
        return false;
    if (ledger.state == EndpointRequestLedgerState::Open)
    {
        if (ledger.next_request_id == kEndpointRequestIdInvalid)
            return false;
    }
    else if (ledger.state == EndpointRequestLedgerState::SequenceRetired)
    {
        if (ledger.next_request_id != kEndpointRequestIdInvalid)
            return false;
    }
    else if (ledger.state == EndpointRequestLedgerState::Draining)
    {
        if (ledger.next_request_id != kEndpointRequestIdInvalid || ledger.active_count != 0)
            return false;
    }
    else
    {
        return false;
    }

    u32 observed_active = 0;
    for (u32 index = 0; index < kEndpointRequestLedgerCapacity; ++index)
    {
        const EndpointRequestSlot& slot = ledger.slots[index];
        if (slot.state == EndpointRequestSlotState::Free)
        {
            if (!SlotIsClear(slot))
                return false;
            continue;
        }
        if (ledger.state == EndpointRequestLedgerState::Draining ||
            (slot.state != EndpointRequestSlotState::Reserved && slot.state != EndpointRequestSlotState::Committed) ||
            !EndpointRequestKeyIsValid(slot.key) || slot.key.endpoint_epoch != ledger.endpoint_epoch)
        {
            return false;
        }
        if (ledger.state == EndpointRequestLedgerState::Open && slot.key.request_id >= ledger.next_request_id)
            return false;

        for (u32 previous = 0; previous < index; ++previous)
        {
            if (ledger.slots[previous].state != EndpointRequestSlotState::Free &&
                ledger.slots[previous].key == slot.key)
            {
                return false;
            }
        }
        ++observed_active;
    }
    return observed_active == ledger.active_count;
}

EndpointRequestLedgerStatus EndpointRequestLedgerReserve(EndpointRequestLedger* ledger, EndpointRequestKey key)
{
    const EndpointRequestLedgerStatus ledger_status = ValidateLedger(ledger);
    if (ledger_status != EndpointRequestLedgerStatus::Ok)
        return ledger_status;
    const EndpointRequestLedgerStatus key_status = ValidateKeyForLedger(*ledger, key);
    if (key_status != EndpointRequestLedgerStatus::Ok)
        return key_status;
    if (ledger->state == EndpointRequestLedgerState::Draining)
        return EndpointRequestLedgerStatus::Draining;
    if (ledger->state == EndpointRequestLedgerState::SequenceRetired)
        return EndpointRequestLedgerStatus::SequenceExhausted;
    if (key.request_id < ledger->next_request_id)
        return EndpointRequestLedgerStatus::ReplayRejected;
    if (key.request_id > ledger->next_request_id)
        return EndpointRequestLedgerStatus::OutOfOrder;

    const u32 slot_index = FindFreeSlot(*ledger);
    if (slot_index == kNoEndpointRequestSlot)
        return EndpointRequestLedgerStatus::Full;

    EndpointRequestSlot& slot = ledger->slots[slot_index];
    slot.key = key;
    slot.state = EndpointRequestSlotState::Reserved;
    ++ledger->active_count;
    ledger->next_free_hint = (slot_index + 1) % kEndpointRequestLedgerCapacity;

    if (key.request_id == kEndpointRequestIdMaximum)
    {
        ledger->next_request_id = kEndpointRequestIdInvalid;
        ledger->state = EndpointRequestLedgerState::SequenceRetired;
    }
    else
    {
        ledger->next_request_id = key.request_id + 1;
    }
    return EndpointRequestLedgerStatus::Ok;
}

EndpointRequestLedgerStatus EndpointRequestLedgerCommit(EndpointRequestLedger* ledger, EndpointRequestKey key,
                                                        EndpointRequestCompletionAuthority* completion_authority_out)
{
    if (completion_authority_out != nullptr)
        *completion_authority_out = kInvalidEndpointRequestCompletionAuthority;
    if (completion_authority_out == nullptr)
        return EndpointRequestLedgerStatus::InvalidArgument;

    const EndpointRequestLedgerStatus ledger_status = ValidateLedger(ledger);
    if (ledger_status != EndpointRequestLedgerStatus::Ok)
        return ledger_status;
    const EndpointRequestLedgerStatus key_status = ValidateKeyForLedger(*ledger, key);
    if (key_status != EndpointRequestLedgerStatus::Ok)
        return key_status;
    if (ledger->state == EndpointRequestLedgerState::Draining)
        return EndpointRequestLedgerStatus::Draining;

    const u32 slot_index = FindLiveSlot(*ledger, key);
    if (slot_index == kNoEndpointRequestSlot)
        return ClassifyMissingKey(*ledger, key);

    EndpointRequestSlot& slot = ledger->slots[slot_index];
    if (slot.state != EndpointRequestSlotState::Reserved)
        return EndpointRequestLedgerStatus::ReplayRejected;

    slot.state = EndpointRequestSlotState::Committed;
    *completion_authority_out = EndpointRequestCompletionAuthority(key);
    return EndpointRequestLedgerStatus::Ok;
}

EndpointRequestLedgerStatus EndpointRequestLedgerCancel(EndpointRequestLedger* ledger, EndpointRequestKey key)
{
    const EndpointRequestLedgerStatus ledger_status = ValidateLedger(ledger);
    if (ledger_status != EndpointRequestLedgerStatus::Ok)
        return ledger_status;
    const EndpointRequestLedgerStatus key_status = ValidateKeyForLedger(*ledger, key);
    if (key_status != EndpointRequestLedgerStatus::Ok)
        return key_status;
    if (ledger->state == EndpointRequestLedgerState::Draining)
        return EndpointRequestLedgerStatus::Draining;

    const u32 slot_index = FindLiveSlot(*ledger, key);
    if (slot_index == kNoEndpointRequestSlot)
        return ClassifyMissingKey(*ledger, key);

    ConsumeSlot(*ledger, slot_index);
    return EndpointRequestLedgerStatus::Ok;
}

EndpointRequestLedgerStatus EndpointRequestLedgerComplete(EndpointRequestLedger* ledger,
                                                          EndpointRequestCompletionAuthority completion_authority)
{
    const EndpointRequestLedgerStatus ledger_status = ValidateLedger(ledger);
    if (ledger_status != EndpointRequestLedgerStatus::Ok)
        return ledger_status;
    if (!EndpointRequestCompletionAuthorityIsValid(completion_authority))
        return EndpointRequestLedgerStatus::InvalidArgument;
    const EndpointRequestKey key = completion_authority.request_key();
    const EndpointRequestLedgerStatus key_status = ValidateKeyForLedger(*ledger, key);
    if (key_status != EndpointRequestLedgerStatus::Ok)
        return key_status;
    if (ledger->state == EndpointRequestLedgerState::Draining)
        return EndpointRequestLedgerStatus::Draining;

    const u32 slot_index = FindLiveSlot(*ledger, key);
    if (slot_index == kNoEndpointRequestSlot)
        return ClassifyMissingKey(*ledger, key);
    if (ledger->slots[slot_index].state != EndpointRequestSlotState::Committed)
        return EndpointRequestLedgerStatus::NotCommitted;

    ConsumeSlot(*ledger, slot_index);
    return EndpointRequestLedgerStatus::Ok;
}

EndpointRequestLedgerStatus EndpointRequestLedgerDrain(EndpointRequestLedger* ledger, u32* cancelled_request_count_out)
{
    if (cancelled_request_count_out != nullptr)
        *cancelled_request_count_out = 0;
    if (cancelled_request_count_out == nullptr)
        return EndpointRequestLedgerStatus::InvalidArgument;

    const EndpointRequestLedgerStatus ledger_status = ValidateLedger(ledger);
    if (ledger_status != EndpointRequestLedgerStatus::Ok)
        return ledger_status;
    if (ledger->state == EndpointRequestLedgerState::Draining)
        return EndpointRequestLedgerStatus::Ok;

    *cancelled_request_count_out = ledger->active_count;
    for (u32 index = 0; index < kEndpointRequestLedgerCapacity; ++index)
        ClearSlot(ledger->slots[index]);
    ledger->next_request_id = kEndpointRequestIdInvalid;
    ledger->active_count = 0;
    ledger->next_free_hint = 0;
    ledger->state = EndpointRequestLedgerState::Draining;
    return EndpointRequestLedgerStatus::Ok;
}

const char* EndpointRequestLedgerStatusName(EndpointRequestLedgerStatus status)
{
    switch (status)
    {
    case EndpointRequestLedgerStatus::Ok:
        return "ok";
    case EndpointRequestLedgerStatus::InvalidArgument:
        return "invalid-argument";
    case EndpointRequestLedgerStatus::NotInitialized:
        return "not-initialized";
    case EndpointRequestLedgerStatus::CorruptState:
        return "corrupt-state";
    case EndpointRequestLedgerStatus::Draining:
        return "draining";
    case EndpointRequestLedgerStatus::SequenceExhausted:
        return "sequence-exhausted";
    case EndpointRequestLedgerStatus::Full:
        return "full";
    case EndpointRequestLedgerStatus::StaleEpoch:
        return "stale-epoch";
    case EndpointRequestLedgerStatus::OutOfOrder:
        return "out-of-order";
    case EndpointRequestLedgerStatus::ReplayRejected:
        return "replay-rejected";
    case EndpointRequestLedgerStatus::NotFound:
        return "not-found";
    case EndpointRequestLedgerStatus::NotCommitted:
        return "not-committed";
    }
    return "unknown";
}

} // namespace duetos::ipc
