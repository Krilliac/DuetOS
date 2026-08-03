#include "syscall/service_endpoint_ingress.h"

#include "core/service_protocol_policy.h"
#include "ipc/kmessage_port.h"
#include "ipc/versioned_payload.h"

#if !defined(DUETOS_HOST_TEST)
#include "arch/x86_64/traps.h"
#include "mm/address_space.h"
#include "mm/paging.h"
#include "sched/sched.h"
#include "syscall/error.h"
#include "util/defer.h"
#endif

namespace duetos::core
{

namespace
{

using AbiStatus = duet_service_endpoint_status;

static_assert(DUET_KOBJECT_MUTEX == static_cast<u16>(ipc::KObjectType::Mutex));
static_assert(DUET_KOBJECT_EVENT == static_cast<u16>(ipc::KObjectType::Event));
static_assert(DUET_KOBJECT_SEMAPHORE == static_cast<u16>(ipc::KObjectType::Semaphore));
static_assert(DUET_KOBJECT_MAILBOX == static_cast<u16>(ipc::KObjectType::Mailbox));
static_assert(DUET_KOBJECT_WAITABLE == static_cast<u16>(ipc::KObjectType::Waitable));
static_assert(DUET_KOBJECT_FILE == static_cast<u16>(ipc::KObjectType::File));
static_assert(DUET_KOBJECT_IOCP == static_cast<u16>(ipc::KObjectType::Iocp));
static_assert(DUET_KOBJECT_MESSAGE_PORT == static_cast<u16>(ipc::KObjectType::MessagePort));
static_assert(DUET_KOBJECT_SERVICE_ENDPOINT == static_cast<u16>(ipc::KObjectType::ServiceEndpoint));
static_assert(DUET_HANDLE_RIGHT_READ == ipc::kHandleRightRead);
static_assert(DUET_HANDLE_RIGHT_WRITE == ipc::kHandleRightWrite);
static_assert(DUET_HANDLE_RIGHT_DUPLICATE == ipc::kHandleRightDuplicate);
static_assert(DUET_HANDLE_RIGHT_TRANSFER == ipc::kHandleRightTransfer);
static_assert(DUET_HANDLE_RIGHT_WAIT == ipc::kHandleRightWait);
static_assert(DUET_HANDLE_RIGHT_SIGNAL == ipc::kHandleRightSignal);
static_assert(DUET_HANDLE_RIGHT_DESTROY == ipc::kHandleRightDestroy);
static_assert(DUET_HANDLE_RIGHT_INSPECT == ipc::kHandleRightInspect);
static_assert(DUET_SERVICE_ENDPOINT_SUPPLEMENTAL_GROUP_CAPACITY == kCredentialSupplementalGroupCapacity);
static_assert(sizeof(duet_service_endpoint_protocol_authority_v1) == sizeof(ServiceEndpointProtocolAuthority));
static_assert(offsetof(duet_service_endpoint_protocol_authority_v1, wire_service_id) == 40);
static_assert(offsetof(duet_service_endpoint_protocol_authority_v1, reserved32) == 44);

#if defined(DUETOS_HOST_TEST)
class StateGuard
{
  public:
    explicit StateGuard(ServiceEndpointIngressState& state) : guard_(state.lock) {}

  private:
    std::lock_guard<std::mutex> guard_;
};
#else
class StateGuard
{
  public:
    explicit StateGuard(ServiceEndpointIngressState& state) : guard_(state.lock) {}

  private:
    sync::SpinLockGuard guard_;
};
#endif

bool ProcessMatches(ProcessKey lhs, ProcessKey rhs)
{
    return lhs.identity == rhs.identity && lhs.pid == rhs.pid;
}

bool EndpointMatches(ServiceEndpointIdentity lhs, ServiceEndpointIdentity rhs)
{
    return lhs == rhs;
}

void ClearReceipt(ServiceEndpointIngressReceiptRow* row)
{
    row->owner = kInvalidProcessKey;
    row->endpoint = kInvalidServiceEndpointIdentity;
    row->completion = ipc::kInvalidEndpointRequestCompletionAuthority;
    row->request_id = 0;
    row->state = row->generation == kServiceEndpointIngressReceiptGenerationMaximum
                     ? ServiceEndpointIngressReceiptState::Retired
                     : ServiceEndpointIngressReceiptState::Free;
    row->reserved[0] = 0;
    row->reserved[1] = 0;
    row->reserved[2] = 0;
}

void ClearCursor(ServiceEndpointIngressCursorRow* row)
{
    row->owner = kInvalidProcessKey;
    row->endpoint = kInvalidServiceEndpointIdentity;
    row->last_committed_request_sequence = 0;
    row->live = false;
    for (u8& byte : row->reserved)
        byte = 0;
}

bool StateIsCanonicalUninitialized(const ServiceEndpointIngressState& state)
{
    if (state.initialized != 0 || state.next_receipt_hint != 0 || state.next_cursor_hint != 0 ||
        state.next_connect_rollback_hint != 0 || state.next_object_identity != 0 ||
        state.next_protocol_authority_identity != 0)
    {
        return false;
    }
    for (const auto& row : state.receipts)
    {
        if (ProcessKeyIsValid(row.owner) || ServiceEndpointIdentityIsValid(row.endpoint) ||
            ipc::EndpointRequestCompletionAuthorityIsValid(row.completion) || row.request_id != 0 ||
            row.generation != 0 || row.state != ServiceEndpointIngressReceiptState::Free || row.reserved[0] != 0 ||
            row.reserved[1] != 0 || row.reserved[2] != 0)
        {
            return false;
        }
    }
    for (const auto& row : state.cursors)
    {
        if (ProcessKeyIsValid(row.owner) || ServiceEndpointIdentityIsValid(row.endpoint) ||
            row.last_committed_request_sequence != 0 || row.live)
        {
            return false;
        }
        for (u8 byte : row.reserved)
        {
            if (byte != 0)
                return false;
        }
    }
    for (const auto& row : state.connect_rollbacks)
    {
        if (row.directory != nullptr || !ServiceDirectoryOwnedChannelIsEmpty(row.channel) ||
            row.state != ServiceEndpointIngressConnectRollbackState::Free)
        {
            return false;
        }
        for (u8 byte : row.reserved)
        {
            if (byte != 0)
                return false;
        }
    }
    return true;
}

u32 EncodeReceipt(u32 slot, u32 generation)
{
    return (generation << 7U) | slot;
}

bool DecodeReceipt(u64 token, u32* slot_out, u32* generation_out)
{
    if (token == 0 || token > 0x7FFFFFFFULL)
        return false;
    const u32 value = static_cast<u32>(token);
    const u32 slot = value & 0x7FU;
    const u32 generation = value >> 7U;
    if (slot == 0 || slot >= kServiceEndpointIngressReceiptCapacity || generation == 0 ||
        generation > kServiceEndpointIngressReceiptGenerationMaximum)
    {
        return false;
    }
    if (slot_out != nullptr)
        *slot_out = slot;
    if (generation_out != nullptr)
        *generation_out = generation;
    return true;
}

u32 FindOrCreateCursorLocked(ServiceEndpointIngressState& state, ProcessKey owner, ServiceEndpointIdentity endpoint)
{
    for (u32 index = 0; index < kServiceEndpointIngressCursorCapacity; ++index)
    {
        const auto& row = state.cursors[index];
        if (row.live && ProcessMatches(row.owner, owner) && EndpointMatches(row.endpoint, endpoint))
            return index;
    }
    for (u32 offset = 0; offset < kServiceEndpointIngressCursorCapacity; ++offset)
    {
        const u32 index = (state.next_cursor_hint + offset) % kServiceEndpointIngressCursorCapacity;
        auto& row = state.cursors[index];
        if (row.live)
            continue;
        row.owner = owner;
        row.endpoint = endpoint;
        row.last_committed_request_sequence = 0;
        row.live = true;
        state.next_cursor_hint = (index + 1U) % kServiceEndpointIngressCursorCapacity;
        return index;
    }
    return kServiceEndpointIngressCursorCapacity;
}

struct PendingReceipt
{
    AbiStatus status;
    u32 token;
};

PendingReceipt ReservePendingReceipt(ServiceEndpointIngressState& state, ProcessKey owner,
                                     ServiceEndpointIdentity endpoint)
{
    StateGuard guard(state);
    u32 owned = 0;
    for (const auto& row : state.receipts)
    {
        if ((row.state == ServiceEndpointIngressReceiptState::Pending ||
             row.state == ServiceEndpointIngressReceiptState::Live ||
             row.state == ServiceEndpointIngressReceiptState::Replying) &&
            ProcessMatches(row.owner, owner))
        {
            ++owned;
        }
    }
    if (owned >= kServiceEndpointIngressReceiptPerProcess)
        return {DUET_SERVICE_ENDPOINT_STATUS_CAPACITY_EXHAUSTED, 0};

    for (u32 offset = 0; offset < kServiceEndpointIngressReceiptCapacity - 1U; ++offset)
    {
        u32 slot = state.next_receipt_hint + offset;
        while (slot >= kServiceEndpointIngressReceiptCapacity)
            slot -= kServiceEndpointIngressReceiptCapacity - 1U;
        if (slot == 0)
            slot = 1;
        auto& row = state.receipts[slot];
        if (row.state != ServiceEndpointIngressReceiptState::Free)
            continue;
        if (row.generation == kServiceEndpointIngressReceiptGenerationMaximum)
        {
            row.state = ServiceEndpointIngressReceiptState::Retired;
            continue;
        }
        const u32 cursor = FindOrCreateCursorLocked(state, owner, endpoint);
        if (cursor == kServiceEndpointIngressCursorCapacity)
            return {DUET_SERVICE_ENDPOINT_STATUS_CAPACITY_EXHAUSTED, 0};

        ++row.generation;
        row.owner = owner;
        row.endpoint = endpoint;
        row.completion = ipc::kInvalidEndpointRequestCompletionAuthority;
        row.request_id = 0;
        row.state = ServiceEndpointIngressReceiptState::Pending;
        state.next_receipt_hint = slot == kServiceEndpointIngressReceiptCapacity - 1U ? 1U : slot + 1U;
        return {DUET_SERVICE_ENDPOINT_STATUS_OK, EncodeReceipt(slot, row.generation)};
    }
    return {DUET_SERVICE_ENDPOINT_STATUS_CAPACITY_EXHAUSTED, 0};
}

void AbandonReceipt(ServiceEndpointIngressState& state, ProcessKey owner, u32 token)
{
    u32 slot = 0;
    u32 generation = 0;
    if (!DecodeReceipt(token, &slot, &generation))
        return;
    StateGuard guard(state);
    auto& row = state.receipts[slot];
    if (row.generation == generation && ProcessMatches(row.owner, owner) &&
        row.state == ServiceEndpointIngressReceiptState::Pending)
    {
        ClearReceipt(&row);
    }
}

bool PublishReceipt(ServiceEndpointIngressState& state, ProcessKey owner, ServiceEndpointIdentity endpoint, u32 token,
                    ipc::EndpointRequestCompletionAuthority completion, u64* prior_sequence_out)
{
    u32 slot = 0;
    u32 generation = 0;
    if (!DecodeReceipt(token, &slot, &generation) || !ipc::EndpointRequestCompletionAuthorityIsValid(completion) ||
        prior_sequence_out == nullptr)
    {
        return false;
    }
    StateGuard guard(state);
    auto& row = state.receipts[slot];
    if (row.generation != generation || row.state != ServiceEndpointIngressReceiptState::Pending ||
        !ProcessMatches(row.owner, owner) || !EndpointMatches(row.endpoint, endpoint))
    {
        return false;
    }
    ServiceEndpointIngressCursorRow* cursor = nullptr;
    for (auto& candidate : state.cursors)
    {
        if (candidate.live && ProcessMatches(candidate.owner, owner) && EndpointMatches(candidate.endpoint, endpoint))
        {
            cursor = &candidate;
            break;
        }
    }
    if (cursor == nullptr)
        return false;
    const u64 request_id = completion.request_key().request_id;
    *prior_sequence_out = cursor->last_committed_request_sequence;
    if (request_id > cursor->last_committed_request_sequence)
        cursor->last_committed_request_sequence = request_id;
    row.completion = completion;
    row.request_id = request_id;
    row.state = ServiceEndpointIngressReceiptState::Live;
    return true;
}

AbiStatus ClaimReceipt(ServiceEndpointIngressState& state, ProcessKey owner, ServiceEndpointIdentity endpoint,
                       u64 token, ipc::EndpointRequestCompletionAuthority* completion_out)
{
    u32 slot = 0;
    u32 generation = 0;
    if (!DecodeReceipt(token, &slot, &generation) || completion_out == nullptr)
        return DUET_SERVICE_ENDPOINT_STATUS_REPLAY_REJECTED;
    StateGuard guard(state);
    auto& row = state.receipts[slot];
    if (!ProcessMatches(row.owner, owner))
        return DUET_SERVICE_ENDPOINT_STATUS_REPLAY_REJECTED;
    if (!EndpointMatches(row.endpoint, endpoint))
        return DUET_SERVICE_ENDPOINT_STATUS_ACCESS_DENIED;
    if (row.generation != generation || row.state != ServiceEndpointIngressReceiptState::Live ||
        !ipc::EndpointRequestCompletionAuthorityIsValid(row.completion))
    {
        return generation <= row.generation ? DUET_SERVICE_ENDPOINT_STATUS_REPLAY_REJECTED
                                            : DUET_SERVICE_ENDPOINT_STATUS_STALE;
    }
    *completion_out = row.completion;
    row.state = ServiceEndpointIngressReceiptState::Replying;
    return DUET_SERVICE_ENDPOINT_STATUS_OK;
}

void FinishReceipt(ServiceEndpointIngressState& state, ProcessKey owner, u64 token, bool consumed)
{
    u32 slot = 0;
    u32 generation = 0;
    if (!DecodeReceipt(token, &slot, &generation))
        return;
    StateGuard guard(state);
    auto& row = state.receipts[slot];
    if (row.generation != generation || row.state != ServiceEndpointIngressReceiptState::Replying ||
        !ProcessMatches(row.owner, owner))
    {
        return;
    }
    if (consumed)
        ClearReceipt(&row);
    else
        row.state = ServiceEndpointIngressReceiptState::Live;
}

void CancelEndpointState(ServiceEndpointIngressState& state, ProcessKey owner, ServiceEndpointIdentity endpoint)
{
    StateGuard guard(state);
    for (auto& row : state.receipts)
    {
        if (ProcessMatches(row.owner, owner) && EndpointMatches(row.endpoint, endpoint))
            ClearReceipt(&row);
    }
    for (auto& row : state.cursors)
    {
        if (row.live && ProcessMatches(row.owner, owner) && EndpointMatches(row.endpoint, endpoint))
            ClearCursor(&row);
    }
}

u64 MintObjectIdentity(ServiceEndpointIngressState& state)
{
    StateGuard guard(state);
    const u64 identity = state.next_object_identity;
    if (identity == 0)
        return 0;
    state.next_object_identity = identity == ~u64{0} ? 0 : identity + 1U;
    return identity;
}

u64 MintProtocolAuthorityIdentity(ServiceEndpointIngressState& state)
{
    StateGuard guard(state);
    const u64 identity = state.next_protocol_authority_identity;
    if (identity == 0)
        return 0;
    state.next_protocol_authority_identity = identity == ~u64{0} ? 0 : identity + 1U;
    return identity;
}

u32 ReserveConnectRollbackSlot(ServiceEndpointIngressState& state)
{
    StateGuard guard(state);
    for (u32 offset = 0; offset < kServiceEndpointIngressConnectRollbackCapacity; ++offset)
    {
        const u32 index = (state.next_connect_rollback_hint + offset) % kServiceEndpointIngressConnectRollbackCapacity;
        auto& row = state.connect_rollbacks[index];
        if (row.state != ServiceEndpointIngressConnectRollbackState::Free)
            continue;
        if (row.directory != nullptr || !ServiceDirectoryOwnedChannelIsEmpty(row.channel))
            return kServiceEndpointIngressConnectRollbackCapacity;
        row.state = ServiceEndpointIngressConnectRollbackState::Reserved;
        state.next_connect_rollback_hint = (index + 1U) % kServiceEndpointIngressConnectRollbackCapacity;
        return index;
    }
    return kServiceEndpointIngressConnectRollbackCapacity;
}

void ReleaseConnectRollbackReservation(ServiceEndpointIngressState& state, u32 slot)
{
    if (slot >= kServiceEndpointIngressConnectRollbackCapacity)
        return;
    StateGuard guard(state);
    auto& row = state.connect_rollbacks[slot];
    if (row.state == ServiceEndpointIngressConnectRollbackState::Reserved && row.directory == nullptr &&
        ServiceDirectoryOwnedChannelIsEmpty(row.channel))
    {
        row.state = ServiceEndpointIngressConnectRollbackState::Free;
    }
}

bool RetainConnectRollback(ServiceEndpointIngressState& state, u32 slot, ServiceDirectory* directory,
                           ServiceDirectoryOwnedChannel* channel)
{
    if (slot >= kServiceEndpointIngressConnectRollbackCapacity || directory == nullptr || channel == nullptr ||
        ServiceDirectoryOwnedChannelIsEmpty(*channel))
    {
        return false;
    }
    StateGuard guard(state);
    auto& row = state.connect_rollbacks[slot];
    if (row.state != ServiceEndpointIngressConnectRollbackState::Reserved || row.directory != nullptr ||
        !ServiceDirectoryOwnedChannelIsEmpty(row.channel))
    {
        return false;
    }
    row.directory = directory;
    row.channel = *channel;
    *channel = {};
    row.state = ServiceEndpointIngressConnectRollbackState::Live;
    return true;
}

ServiceEndpointStatus DriveConnectRollbackSlot(ServiceEndpointIngressState& state, u32 slot)
{
    if (slot >= kServiceEndpointIngressConnectRollbackCapacity)
        return ServiceEndpointStatus::InvalidArgument;
    ServiceDirectoryOwnedChannel* channel = nullptr;
    {
        StateGuard guard(state);
        auto& row = state.connect_rollbacks[slot];
        if (row.state != ServiceEndpointIngressConnectRollbackState::Live || row.directory == nullptr ||
            ServiceDirectoryOwnedChannelIsEmpty(row.channel))
        {
            return ServiceEndpointStatus::InvalidArgument;
        }
        row.state = ServiceEndpointIngressConnectRollbackState::Driving;
        channel = &row.channel;
    }

    const ServiceEndpointStatus status = ServiceDirectoryDrainOwnedChannel(channel);
    {
        StateGuard guard(state);
        auto& row = state.connect_rollbacks[slot];
        if (row.state != ServiceEndpointIngressConnectRollbackState::Driving)
            return ServiceEndpointStatus::CorruptState;
        if (status == ServiceEndpointStatus::Ok)
        {
            if (!ServiceDirectoryOwnedChannelIsEmpty(row.channel))
            {
                row.state = ServiceEndpointIngressConnectRollbackState::Live;
                return ServiceEndpointStatus::CorruptState;
            }
            row = {};
        }
        else
        {
            if (ServiceDirectoryOwnedChannelIsEmpty(row.channel))
            {
                row = {};
                return ServiceEndpointStatus::CorruptState;
            }
            row.state = ServiceEndpointIngressConnectRollbackState::Live;
        }
    }
    return status;
}

bool HandleValueValid(u64 value)
{
    return value != 0 && value <= ipc::kHandlePositiveMax;
}

bool TransferTypeAllowed(u16 raw, ipc::KObjectType* type_out)
{
    const auto type = static_cast<ipc::KObjectType>(raw);
    switch (type)
    {
    case ipc::KObjectType::Mutex:
    case ipc::KObjectType::Event:
    case ipc::KObjectType::Semaphore:
    case ipc::KObjectType::Mailbox:
    case ipc::KObjectType::Waitable:
    case ipc::KObjectType::File:
    case ipc::KObjectType::Iocp:
    case ipc::KObjectType::MessagePort:
        if (type_out != nullptr)
            *type_out = type;
        return true;
    case ipc::KObjectType::Invalid:
    case ipc::KObjectType::ServiceEndpoint:
    case ipc::KObjectType::Test:
        return false;
    }
    return false;
}

bool RequestIsCanonical(const duet_service_endpoint_request_v1& request)
{
    if (request.struct_size != sizeof(request) || request.version != DUET_SERVICE_ENDPOINT_ABI_VERSION ||
        request.operation < DUET_SERVICE_ENDPOINT_OP_ACCEPT ||
        request.operation > DUET_SERVICE_ENDPOINT_OP_SEND_REQUEST ||
        request.frame_bytes > DUET_SERVICE_ENDPOINT_MAX_FRAME_BYTES || request.reserved16 != 0 ||
        request.reserved64 != 0)
    {
        return false;
    }
    if (request.operation != DUET_SERVICE_ENDPOINT_OP_CONNECT && request.target_service_identity != 0)
        return false;
    if (request.operation == DUET_SERVICE_ENDPOINT_OP_RECEIVE)
    {
        if ((request.flags & ~static_cast<u32>(DUET_SERVICE_ENDPOINT_REQUEST_NONBLOCK)) != 0)
            return false;
    }
    else if (request.flags != 0)
    {
        return false;
    }

    switch (request.operation)
    {
    case DUET_SERVICE_ENDPOINT_OP_ACCEPT:
        return request.frame_bytes == 0 && request.endpoint_handle == 0 && request.completion_receipt == 0 &&
               request.object_handle == 0 && request.requested_rights == 0 && request.transfer_reference == 0 &&
               request.object_type == 0;
    case DUET_SERVICE_ENDPOINT_OP_RECEIVE:
        return request.frame_bytes == 0 && HandleValueValid(request.endpoint_handle) &&
               request.completion_receipt == 0 && request.object_handle == 0 && request.requested_rights == 0 &&
               request.transfer_reference == 0 && request.object_type == 0;
    case DUET_SERVICE_ENDPOINT_OP_REPLY_ACK:
        return request.frame_bytes >= ipc::kMessageAbiHeaderV1Bytes && HandleValueValid(request.endpoint_handle) &&
               request.completion_receipt != 0 && request.object_handle == 0 && request.requested_rights == 0 &&
               request.transfer_reference == 0 && request.object_type == 0;
    case DUET_SERVICE_ENDPOINT_OP_EXPORT:
        return request.frame_bytes == 0 && HandleValueValid(request.endpoint_handle) &&
               request.completion_receipt == 0 && HandleValueValid(request.object_handle) &&
               request.requested_rights != 0 && request.transfer_reference == 0 && request.object_type != 0;
    case DUET_SERVICE_ENDPOINT_OP_IMPORT:
        return request.frame_bytes == 0 && HandleValueValid(request.endpoint_handle) &&
               request.completion_receipt == 0 && request.object_handle == 0 && request.requested_rights != 0 &&
               request.transfer_reference != 0 && request.object_type != 0;
    case DUET_SERVICE_ENDPOINT_OP_REVOKE_EXPORT:
        return request.frame_bytes == 0 && HandleValueValid(request.endpoint_handle) &&
               request.completion_receipt == 0 && request.object_handle == 0 && request.requested_rights == 0 &&
               request.transfer_reference != 0 && request.object_type == 0;
    case DUET_SERVICE_ENDPOINT_OP_CLOSE:
        return request.frame_bytes == 0 && HandleValueValid(request.endpoint_handle) &&
               request.completion_receipt == 0 && request.object_handle == 0 && request.requested_rights == 0 &&
               request.transfer_reference == 0 && request.object_type == 0;
    case DUET_SERVICE_ENDPOINT_OP_CONNECT:
        return request.frame_bytes == 0 && request.target_service_identity != 0 && request.endpoint_handle == 0 &&
               request.completion_receipt == 0 && request.object_handle == 0 && request.requested_rights == 0 &&
               request.transfer_reference == 0 && request.object_type == 0;
    case DUET_SERVICE_ENDPOINT_OP_SEND_REQUEST:
        return request.frame_bytes >= ipc::kMessageAbiHeaderV1Bytes && HandleValueValid(request.endpoint_handle) &&
               request.completion_receipt == 0 && request.object_handle == 0 && request.requested_rights == 0 &&
               request.transfer_reference == 0 && request.object_type == 0;
    default:
        return false;
    }
}

bool CallerIsCanonical(const ServiceEndpointIngressCaller& caller)
{
    return ProcessKeyIsValid(caller.process) && caller.handles != nullptr &&
           CredentialKeyIsValid(caller.credential_key) && CredentialSecurityContextIsCanonical(caller.credential) &&
           ResourceDomainKeyIsValid(caller.resource_domain);
}

void InitializeResult(const duet_service_endpoint_request_v1& request, duet_service_endpoint_result_v1* result)
{
    *result = {};
    result->struct_size = sizeof(*result);
    result->version = DUET_SERVICE_ENDPOINT_ABI_VERSION;
    result->operation = request.operation;
    result->status = DUET_SERVICE_ENDPOINT_STATUS_INTERNAL_ERROR;
}

void SetStatus(duet_service_endpoint_result_v1* result, AbiStatus status)
{
    result->status = static_cast<int32_t>(status);
}

AbiStatus MapEndpointStatus(ServiceEndpointStatus status)
{
    switch (status)
    {
    case ServiceEndpointStatus::Ok:
        return DUET_SERVICE_ENDPOINT_STATUS_OK;
    case ServiceEndpointStatus::InvalidArgument:
        return DUET_SERVICE_ENDPOINT_STATUS_INVALID_ARGUMENT;
    case ServiceEndpointStatus::NotInitialized:
    case ServiceEndpointStatus::NotPublished:
        return DUET_SERVICE_ENDPOINT_STATUS_NOT_READY;
    case ServiceEndpointStatus::Closing:
    case ServiceEndpointStatus::Drained:
        return DUET_SERVICE_ENDPOINT_STATUS_CLOSED;
    case ServiceEndpointStatus::Busy:
        return DUET_SERVICE_ENDPOINT_STATUS_BUSY;
    case ServiceEndpointStatus::CapacityExhausted:
    case ServiceEndpointStatus::GenerationExhausted:
        return DUET_SERVICE_ENDPOINT_STATUS_CAPACITY_EXHAUSTED;
    case ServiceEndpointStatus::StaleIdentity:
    case ServiceEndpointStatus::StaleActivation:
    case ServiceEndpointStatus::StaleOwner:
        return DUET_SERVICE_ENDPOINT_STATUS_STALE;
    case ServiceEndpointStatus::RequestRejected:
        return DUET_SERVICE_ENDPOINT_STATUS_REPLAY_REJECTED;
    case ServiceEndpointStatus::CorruptState:
    case ServiceEndpointStatus::InvalidCleanup:
        return DUET_SERVICE_ENDPOINT_STATUS_CORRUPT_STATE;
    default:
        return DUET_SERVICE_ENDPOINT_STATUS_INTERNAL_ERROR;
    }
}

AbiStatus MapDirectoryStatus(ServiceDirectoryStatus status)
{
    switch (status)
    {
    case ServiceDirectoryStatus::Ok:
        return DUET_SERVICE_ENDPOINT_STATUS_OK;
    case ServiceDirectoryStatus::QueueEmpty:
        return DUET_SERVICE_ENDPOINT_STATUS_WOULD_BLOCK;
    case ServiceDirectoryStatus::NotInitialized:
    case ServiceDirectoryStatus::NotReady:
    case ServiceDirectoryStatus::NotFound:
        return DUET_SERVICE_ENDPOINT_STATUS_NOT_READY;
    case ServiceDirectoryStatus::OwnerMismatch:
    case ServiceDirectoryStatus::CredentialMismatch:
    case ServiceDirectoryStatus::ProtocolMismatch:
        return DUET_SERVICE_ENDPOINT_STATUS_ACCESS_DENIED;
    case ServiceDirectoryStatus::Closing:
        return DUET_SERVICE_ENDPOINT_STATUS_CLOSED;
    case ServiceDirectoryStatus::Busy:
        return DUET_SERVICE_ENDPOINT_STATUS_BUSY;
    case ServiceDirectoryStatus::CapacityExhausted:
    case ServiceDirectoryStatus::AcceptedCapacityExhausted:
    case ServiceDirectoryStatus::QueueFull:
    case ServiceDirectoryStatus::GenerationExhausted:
    case ServiceDirectoryStatus::OperationIdentityExhausted:
        return DUET_SERVICE_ENDPOINT_STATUS_CAPACITY_EXHAUSTED;
    case ServiceDirectoryStatus::StaleKey:
    case ServiceDirectoryStatus::StaleOperation:
    case ServiceDirectoryStatus::StaleAcceptedChannel:
    case ServiceDirectoryStatus::ReservationConsumed:
        return DUET_SERVICE_ENDPOINT_STATUS_STALE;
    case ServiceDirectoryStatus::InvalidArgument:
        return DUET_SERVICE_ENDPOINT_STATUS_INVALID_ARGUMENT;
    case ServiceDirectoryStatus::CorruptState:
        return DUET_SERVICE_ENDPOINT_STATUS_CORRUPT_STATE;
    default:
        return DUET_SERVICE_ENDPOINT_STATUS_INTERNAL_ERROR;
    }
}

AbiStatus MapTransferStatus(ipc::ObjectTransferStatus status)
{
    switch (status)
    {
    case ipc::ObjectTransferStatus::Ok:
        return DUET_SERVICE_ENDPOINT_STATUS_OK;
    case ipc::ObjectTransferStatus::InvalidArgument:
        return DUET_SERVICE_ENDPOINT_STATUS_INVALID_ARGUMENT;
    case ipc::ObjectTransferStatus::NotInitialized:
        return DUET_SERVICE_ENDPOINT_STATUS_NOT_READY;
    case ipc::ObjectTransferStatus::Closed:
        return DUET_SERVICE_ENDPOINT_STATUS_CLOSED;
    case ipc::ObjectTransferStatus::Full:
    case ipc::ObjectTransferStatus::IdentityExhausted:
    case ipc::ObjectTransferStatus::OperationOverflow:
        return DUET_SERVICE_ENDPOINT_STATUS_CAPACITY_EXHAUSTED;
    case ipc::ObjectTransferStatus::SourceRejected:
    case ipc::ObjectTransferStatus::DestinationRejected:
        return DUET_SERVICE_ENDPOINT_STATUS_INVALID_HANDLE;
    case ipc::ObjectTransferStatus::InvalidReference:
    case ipc::ObjectTransferStatus::StaleReference:
        return DUET_SERVICE_ENDPOINT_STATUS_STALE;
    case ipc::ObjectTransferStatus::ReferenceReplayed:
        return DUET_SERVICE_ENDPOINT_STATUS_REPLAY_REJECTED;
    case ipc::ObjectTransferStatus::RightsDenied:
        return DUET_SERVICE_ENDPOINT_STATUS_RIGHTS_DENIED;
    case ipc::ObjectTransferStatus::TypeMismatch:
        return DUET_SERVICE_ENDPOINT_STATUS_TYPE_MISMATCH;
    case ipc::ObjectTransferStatus::Busy:
        return DUET_SERVICE_ENDPOINT_STATUS_BUSY;
    case ipc::ObjectTransferStatus::CorruptState:
        return DUET_SERVICE_ENDPOINT_STATUS_CORRUPT_STATE;
    default:
        return DUET_SERVICE_ENDPOINT_STATUS_INTERNAL_ERROR;
    }
}

AbiStatus MapPortFailure(const ipc::KMessagePortReceiveResult& receive)
{
    if (receive.status == ipc::KMessagePortStatus::Closed)
        return DUET_SERVICE_ENDPOINT_STATUS_CLOSED;
    if (receive.status == ipc::KMessagePortStatus::Cancelled)
        return DUET_SERVICE_ENDPOINT_STATUS_CANCELLED;
    if (receive.ring_status == ipc::MessageRingStatus::Empty)
        return DUET_SERVICE_ENDPOINT_STATUS_WOULD_BLOCK;
    if (receive.ring_status == ipc::MessageRingStatus::BufferTooSmall)
        return DUET_SERVICE_ENDPOINT_STATUS_BUFFER_TOO_SMALL;
    if (receive.ring_status == ipc::MessageRingStatus::Busy)
        return DUET_SERVICE_ENDPOINT_STATUS_BUSY;
    if (receive.ring_status == ipc::MessageRingStatus::MalformedMessage ||
        receive.ring_status == ipc::MessageRingStatus::MalformedPayload)
    {
        return DUET_SERVICE_ENDPOINT_STATUS_MALFORMED_MESSAGE;
    }
    return DUET_SERVICE_ENDPOINT_STATUS_CORRUPT_STATE;
}

AbiStatus MapSendFailure(const ipc::KMessagePortSendResult& send)
{
    if (send.status == ipc::KMessagePortStatus::Closed)
        return DUET_SERVICE_ENDPOINT_STATUS_CLOSED;
    if (send.ring.status == ipc::MessageRingStatus::Full || send.ring.status == ipc::MessageRingStatus::Busy)
        return DUET_SERVICE_ENDPOINT_STATUS_WOULD_BLOCK;
    if (send.ring.status == ipc::MessageRingStatus::MalformedMessage ||
        send.ring.status == ipc::MessageRingStatus::MalformedPayload ||
        send.ring.status == ipc::MessageRingStatus::MissingPayloadContract)
    {
        return DUET_SERVICE_ENDPOINT_STATUS_MALFORMED_MESSAGE;
    }
    return DUET_SERVICE_ENDPOINT_STATUS_CORRUPT_STATE;
}

struct AuthorizedFrameValidation
{
    AbiStatus status;
    bool envelope_valid;
    ipc::MessageView view;
};

AuthorizedFrameValidation ValidateAuthorizedFrame(const ServiceEndpointProtocolAuthority& authority, const u8* frame,
                                                  u32 frame_bytes)
{
    ipc::MessageView view{};
    if (ipc::MessageValidate(frame, frame_bytes, &view) != ipc::MessageValidationError::Ok)
        return {DUET_SERVICE_ENDPOINT_STATUS_MALFORMED_MESSAGE, false, {}};

    // Cancel is the one envelope-only control kind. Every data-bearing frame
    // is bound to the exact trusted route and payload version retained by the
    // endpoint, regardless of what validation a sender previously requested.
    if (view.kind == ipc::MessageKind::Cancel)
        return {DUET_SERVICE_ENDPOINT_STATUS_OK, true, view};
    if (!ServiceEndpointProtocolAuthorityAllowsRoute(authority, view.service_id, view.method_id) ||
        view.payload_size == 0)
    {
        return {DUET_SERVICE_ENDPOINT_STATUS_MALFORMED_MESSAGE, true, view};
    }

    const ipc::PayloadVersionRule rule{static_cast<u16>(authority.protocol_version), 0,
                                       ipc::kVersionedPayloadHeaderBytes, ipc::kVersionedPayloadMaxBytes};
    const auto* payload = frame + view.payload_offset;
    if (ipc::PayloadValidate(payload, view.payload_size, &rule, 1, nullptr) != ipc::PayloadValidationError::Ok)
        return {DUET_SERVICE_ENDPOINT_STATUS_MALFORMED_MESSAGE, true, view};
    return {DUET_SERVICE_ENDPOINT_STATUS_OK, true, view};
}

ipc::PayloadVersionRule PayloadRuleFor(const ServiceEndpointProtocolAuthority& authority)
{
    return ipc::PayloadVersionRule{static_cast<u16>(authority.protocol_version), 0, ipc::kVersionedPayloadHeaderBytes,
                                   ipc::kVersionedPayloadMaxBytes};
}

void CopyCredential(const ServiceEndpointCredentialSnapshot& source, duet_service_endpoint_credential_v1* out)
{
    out->slot = source.key.slot;
    out->generation = source.key.generation;
    out->real_uid = source.security.real_uid;
    out->effective_uid = source.security.effective_uid;
    out->saved_uid = source.security.saved_uid;
    out->fs_uid = source.security.fs_uid;
    out->real_gid = source.security.real_gid;
    out->effective_gid = source.security.effective_gid;
    out->saved_gid = source.security.saved_gid;
    out->fs_gid = source.security.fs_gid;
    out->supplemental_group_count = source.security.supplemental_group_count;
    for (u32 index = 0; index < kCredentialSupplementalGroupCapacity; ++index)
        out->supplemental_groups[index] = source.security.supplemental_groups[index];
    out->capability_effective = source.security.capability_effective;
    out->capability_permitted = source.security.capability_permitted;
    out->capability_inheritable = source.security.capability_inheritable;
    out->capability_bounding = source.security.capability_bounding;
    out->win32_integrity = static_cast<u8>(source.security.win32_integrity);
}

void FillEndpointInfo(const ServiceEndpointIdentity& identity, const ServiceEndpointProtocolAuthority& protocol,
                      const ServiceEndpointPeerSnapshot& peer, duet_service_endpoint_result_v1* result)
{
    result->flags |= DUET_SERVICE_ENDPOINT_RESULT_PEER_TASK_UNAVAILABLE;
    result->endpoint_identity = identity.channel.channel_epoch;
    result->peer_task_identity = 0;
    result->channel.slot = identity.channel.slot;
    result->channel.role = static_cast<u8>(identity.role);
    result->channel.generation = identity.channel.generation;
    result->channel.epoch = identity.channel.channel_epoch;
    result->protocol.authority_identity = protocol.authority_identity;
    result->protocol.protocol_identity = protocol.protocol_identity;
    result->protocol.service_identity = protocol.service_identity;
    result->protocol.allowed_methods = protocol.allowed_methods;
    result->protocol.protocol_version = protocol.protocol_version;
    result->protocol.flags = protocol.flags;
    result->protocol.wire_service_id = protocol.wire_service_id;
    result->protocol.reserved32 = protocol.reserved32;
    result->peer_process.identity = peer.process.identity;
    result->peer_process.pid = peer.process.pid;
    CopyCredential(peer.credential, &result->peer_credential);
}

void CopyObjectAuthority(const ipc::ObjectTransferAuthority& authority, duet_service_endpoint_result_v1* result)
{
    result->object_type = static_cast<u16>(authority.type);
    result->object_rights = authority.rights;
    result->object_metadata.identity = authority.metadata.identity;
    result->object_metadata.object_size = authority.metadata.object_size;
    for (u32 index = 0; index < sizeof(authority.metadata.content_hash); ++index)
        result->object_metadata.content_hash[index] = authority.metadata.content_hash[index];
    result->object_metadata.flags = authority.metadata.flags;
    result->object_metadata.reserved = authority.metadata.reserved;
}

struct EndpointContext
{
    ServiceEndpointOperation operation;
    ServiceEndpointIdentity identity;
    ServiceEndpointProtocolAuthority protocol;
    ServiceEndpointPeerSnapshot peer;
};

AbiStatus AcquireEndpoint(const ServiceEndpointIngressCaller& caller, u64 raw_handle, u64 rights,
                          EndpointContext* context)
{
    if (context == nullptr || !HandleValueValid(raw_handle))
        return DUET_SERVICE_ENDPOINT_STATUS_INVALID_HANDLE;
    *context = {};
    ipc::KObject* retained = ipc::HandleTableLookupRef(*caller.handles, static_cast<ipc::Handle>(raw_handle),
                                                       ipc::KObjectType::ServiceEndpoint, rights);
    if (retained == nullptr)
        return DUET_SERVICE_ENDPOINT_STATUS_INVALID_HANDLE;
    const ServiceEndpointStatus inspect =
        ServiceEndpointInspectObject(retained, &context->identity, &context->protocol, &context->peer);
    if (inspect != ServiceEndpointStatus::Ok)
    {
        ipc::KObjectRelease(retained);
        return MapEndpointStatus(inspect);
    }
    const ServiceEndpointOperationResult acquired = ServiceEndpointAcquireOperation(retained);
    ipc::KObjectRelease(retained);
    if (acquired.status != ServiceEndpointStatus::Ok)
        return MapEndpointStatus(acquired.status);
    context->operation = acquired.operation;
    return DUET_SERVICE_ENDPOINT_STATUS_OK;
}

void ReleaseEndpoint(EndpointContext* context, duet_service_endpoint_result_v1* result)
{
    if (!ServiceEndpointOperationIsValid(context->operation))
        return;
    const ServiceEndpointStatus released = ServiceEndpointReleaseOperation(&context->operation);
    if (released != ServiceEndpointStatus::Ok && result->status == DUET_SERVICE_ENDPOINT_STATUS_OK)
        SetStatus(result, DUET_SERVICE_ENDPOINT_STATUS_CORRUPT_STATE);
}

struct CallerService
{
    ServiceInstanceToken token;
    ServiceDirectoryName name;
    u64 service_identity;
    u64 transition_generation;
    u32 manifest_index;
};

struct TargetService
{
    ServiceDirectoryName name;
    ServiceProtocolRoutePolicy policy;
    u32 manifest_index;
};

AbiStatus MapProtocolPolicyStatus(ServiceProtocolPolicyStatus status)
{
    switch (status)
    {
    case ServiceProtocolPolicyStatus::Ok:
        return DUET_SERVICE_ENDPOINT_STATUS_OK;
    case ServiceProtocolPolicyStatus::NotSupported:
        return DUET_SERVICE_ENDPOINT_STATUS_UNSUPPORTED;
    case ServiceProtocolPolicyStatus::AccessDenied:
        return DUET_SERVICE_ENDPOINT_STATUS_ACCESS_DENIED;
    case ServiceProtocolPolicyStatus::AuthorityIdentityExhausted:
        return DUET_SERVICE_ENDPOINT_STATUS_CAPACITY_EXHAUSTED;
    case ServiceProtocolPolicyStatus::InvalidArgument:
        return DUET_SERVICE_ENDPOINT_STATUS_CORRUPT_STATE;
    }
    return DUET_SERVICE_ENDPOINT_STATUS_CORRUPT_STATE;
}

AbiStatus ResolveTargetService(const ServiceEndpointIngressCaller& caller, u64 target_service_identity,
                               TargetService* target)
{
    if (caller.runtime == nullptr || target == nullptr || target_service_identity == 0)
        return DUET_SERVICE_ENDPOINT_STATUS_NOT_READY;
    ServiceRuntimeActivationAuthorityV1 runtime_authority{};
    const ServiceRuntimeStatusV1 bound = ServiceRuntimeBindActivationAuthorityV1(caller.runtime, &runtime_authority);
    if (bound != ServiceRuntimeStatusV1::Ok || runtime_authority.stage == nullptr ||
        runtime_authority.directory != &caller.runtime->directory)
    {
        return bound == ServiceRuntimeStatusV1::NotInitialized ? DUET_SERVICE_ENDPOINT_STATUS_NOT_READY
                                                               : DUET_SERVICE_ENDPOINT_STATUS_CORRUPT_STATE;
    }

    const ServiceManifestDocumentV1& document = runtime_authority.stage->package.manifest_plan.document;
    if (document.service_count == 0 || document.service_count > kServiceManifestMaximumServices)
        return DUET_SERVICE_ENDPOINT_STATUS_CORRUPT_STATE;
    u32 manifest_index = document.service_count;
    for (u32 index = 0; index < document.service_count; ++index)
    {
        if (document.services[index].service_identity != target_service_identity)
            continue;
        if (manifest_index != document.service_count)
            return DUET_SERVICE_ENDPOINT_STATUS_CORRUPT_STATE;
        manifest_index = index;
    }
    if (manifest_index == document.service_count)
        return DUET_SERVICE_ENDPOINT_STATUS_UNSUPPORTED;

    const ServiceManifestServiceV1& service = document.services[manifest_index];
    const ServiceProtocolPolicyResolveResult resolved = ServiceProtocolPolicyResolveV1(service, caller.capabilities);
    if (resolved.status != ServiceProtocolPolicyStatus::Ok)
        return MapProtocolPolicyStatus(resolved.status);

    ServiceDirectoryName name{};
    if (service.name_length == 0 || service.name_length > kServiceDirectoryNameCapacity)
        return DUET_SERVICE_ENDPOINT_STATUS_CORRUPT_STATE;
    name.length = service.name_length;
    for (u32 index = 0; index < service.name_length; ++index)
        name.bytes[index] = service.name[index];
    if (!ServiceDirectoryNameIsCanonical(name))
        return DUET_SERVICE_ENDPOINT_STATUS_CORRUPT_STATE;
    *target = TargetService{name, resolved.policy, manifest_index};
    return DUET_SERVICE_ENDPOINT_STATUS_OK;
}

AbiStatus ResolveCallerService(const ServiceEndpointIngressCaller& caller, CallerService* service)
{
    if (caller.runtime == nullptr || caller.runtime->stage == nullptr || service == nullptr)
        return DUET_SERVICE_ENDPOINT_STATUS_NOT_READY;
    ServiceRuntimeSnapshotV1 runtime_snapshot{};
    if (ServiceRuntimeInspectV1(caller.runtime, &runtime_snapshot) != ServiceRuntimeStatusV1::Ok ||
        runtime_snapshot.state != ServiceRuntimeStateV1::Open)
    {
        return DUET_SERVICE_ENDPOINT_STATUS_NOT_READY;
    }
    const ServiceLifecycleBrokerInspectResult described = ServiceLifecycleBrokerDescribe(&caller.runtime->lifecycle);
    if (described.status != ServiceLifecycleStatus::Ok)
        return DUET_SERVICE_ENDPOINT_STATUS_NOT_READY;

    bool found = false;
    ServiceLifecycleSnapshot match{};
    for (u32 index = 0; index < described.snapshot.service_count; ++index)
    {
        const ServiceLifecycleInspectResult inspected =
            ServiceLifecycleBrokerInspectAt(&caller.runtime->lifecycle, index);
        if (inspected.status != ServiceLifecycleStatus::Ok)
            return DUET_SERVICE_ENDPOINT_STATUS_CORRUPT_STATE;
        if (inspected.snapshot.instance.process_identity != caller.process.identity ||
            inspected.snapshot.instance.pid != caller.process.pid)
        {
            continue;
        }
        if (found)
            return DUET_SERVICE_ENDPOINT_STATUS_CORRUPT_STATE;
        found = true;
        match = inspected.snapshot;
    }
    if (!found || match.phase != ServiceTransitionPhase::Running || match.transition_generation == 0)
        return DUET_SERVICE_ENDPOINT_STATUS_NOT_READY;

    const ServiceManifestDocumentV1& document = caller.runtime->stage->package.manifest_plan.document;
    u32 manifest_index = document.service_count;
    for (u32 index = 0; index < document.service_count; ++index)
    {
        if (document.services[index].service_identity == match.service_identity)
        {
            manifest_index = index;
            break;
        }
    }
    if (manifest_index == document.service_count)
        return DUET_SERVICE_ENDPOINT_STATUS_CORRUPT_STATE;
    const ServiceManifestServiceV1& manifest = document.services[manifest_index];
    ServiceDirectoryName name{};
    name.length = manifest.name_length;
    for (u32 index = 0; index < manifest.name_length; ++index)
        name.bytes[index] = manifest.name[index];
    if (!ServiceDirectoryNameIsCanonical(name))
        return DUET_SERVICE_ENDPOINT_STATUS_CORRUPT_STATE;

    service->token =
        ServiceInstanceToken{ServiceStartTicket{match.service_identity, match.transition_generation}, match.instance};
    service->name = name;
    service->service_identity = match.service_identity;
    service->transition_generation = match.transition_generation;
    service->manifest_index = manifest_index;
    return ServiceInstanceTokenIsValid(service->token) ? DUET_SERVICE_ENDPOINT_STATUS_OK
                                                       : DUET_SERVICE_ENDPOINT_STATUS_CORRUPT_STATE;
}

AbiStatus CloseEndpointHandle(ServiceEndpointIngressState& state, const ServiceEndpointIngressCaller& caller,
                              ipc::Handle handle, ServiceEndpointIdentity* closed_identity)
{
    ipc::KObject* recognition =
        ipc::HandleTableLookupRef(*caller.handles, handle, ipc::KObjectType::ServiceEndpoint, ipc::kHandleRightDestroy);
    if (recognition == nullptr)
        return DUET_SERVICE_ENDPOINT_STATUS_INVALID_HANDLE;
    ServiceEndpointIdentity identity{};
    ServiceEndpointProtocolAuthority protocol{};
    ServiceEndpointPeerSnapshot peer{};
    const ServiceEndpointStatus inspect = ServiceEndpointInspectObject(recognition, &identity, &protocol, &peer);
    if (caller.runtime == nullptr)
    {
        ipc::KObjectRelease(recognition);
        return DUET_SERVICE_ENDPOINT_STATUS_NOT_READY;
    }
    const ServiceDirectoryReleaseAcceptedResult accepted =
        ServiceDirectoryReleaseAcceptedHandle(&caller.runtime->directory, caller.process, handle);
    if (accepted.status != ServiceDirectoryStatus::Ok && accepted.status != ServiceDirectoryStatus::NotFound)
    {
        ipc::KObjectRelease(recognition);
        return MapDirectoryStatus(accepted.status);
    }
    auto detached =
        ipc::HandleTableDetach(*caller.handles, handle, ipc::KObjectType::ServiceEndpoint, ipc::kHandleRightDestroy);
    if (!detached.has_value())
    {
        ipc::KObjectRelease(recognition);
        return DUET_SERVICE_ENDPOINT_STATUS_INVALID_HANDLE;
    }
    ipc::KObjectRelease(recognition);
    ipc::KObjectRelease(detached.value());
    if (inspect == ServiceEndpointStatus::Ok)
    {
        CancelEndpointState(state, caller.process, identity);
        if (closed_identity != nullptr)
            *closed_identity = identity;
    }
    return inspect == ServiceEndpointStatus::Ok ? DUET_SERVICE_ENDPOINT_STATUS_OK : MapEndpointStatus(inspect);
}

void ExecuteAccept(ServiceEndpointIngressState& state, const ServiceEndpointIngressCaller& caller,
                   duet_service_endpoint_result_v1* result)
{
    CallerService service{};
    AbiStatus status = ResolveCallerService(caller, &service);
    if (status != DUET_SERVICE_ENDPOINT_STATUS_OK)
    {
        SetStatus(result, status);
        return;
    }
    const ServiceDirectoryLookupResult lookup = ServiceDirectoryLookup(&caller.runtime->directory, &service.name);
    if (lookup.status != ServiceDirectoryStatus::Ok)
    {
        SetStatus(result, MapDirectoryStatus(lookup.status));
        return;
    }
    const ServiceKey service_key = lookup.pin.service;
    ServiceDirectoryOperationPin pin = lookup.pin;
    const ServiceDirectoryStatus released = ServiceDirectoryReleaseOperation(&caller.runtime->directory, &pin);
    if (released != ServiceDirectoryStatus::Ok)
    {
        SetStatus(result, MapDirectoryStatus(released));
        return;
    }
    const ServiceEndpointCredentialSnapshot credential{caller.credential_key, caller.credential};
    const u64 rights = ipc::HandleRightsForProcess(ipc::KObjectType::ServiceEndpoint, caller.capabilities);
    const ServiceDirectoryAcceptResult accepted = ServiceDirectoryAccept(
        &caller.runtime->directory, service_key, service.token, caller.handles, caller.process, &credential, rights);
    if (accepted.status != ServiceDirectoryStatus::Ok)
    {
        SetStatus(result, MapDirectoryStatus(accepted.status));
        return;
    }

    ipc::KObject* retained = ipc::HandleTableLookupRef(*caller.handles, accepted.server_handle,
                                                       ipc::KObjectType::ServiceEndpoint, ipc::kHandleRightRead);
    ServiceEndpointIdentity identity{};
    ServiceEndpointProtocolAuthority protocol{};
    ServiceEndpointPeerSnapshot peer{};
    const ServiceEndpointStatus inspected = retained == nullptr
                                                ? ServiceEndpointStatus::CorruptState
                                                : ServiceEndpointInspectObject(retained, &identity, &protocol, &peer);
    ipc::KObjectRelease(retained);
    if (inspected != ServiceEndpointStatus::Ok)
    {
        (void)CloseEndpointHandle(state, caller, accepted.server_handle, nullptr);
        SetStatus(result, MapEndpointStatus(inspected));
        return;
    }
    result->endpoint_handle = accepted.server_handle;
    result->local_service_identity = service.service_identity;
    result->local_instance_generation = service.transition_generation;
    result->local_process_identity = caller.process.identity;
    result->local_pid = caller.process.pid;
    result->service_slot = service.manifest_index;
    FillEndpointInfo(identity, protocol, peer, result);
    SetStatus(result, DUET_SERVICE_ENDPOINT_STATUS_OK);
}

void ConsumeEndpointRequestCleanup(void*, ipc::EndpointRequestKey) {}

AbiStatus MapConnectFailure(const ServiceDirectoryConnectResult& connected)
{
    switch (connected.status)
    {
    case ServiceDirectoryStatus::EndpointCreateFailed:
    case ServiceDirectoryStatus::EndpointActivationFailed:
    case ServiceDirectoryStatus::EndpointReleaseFailed:
        return MapEndpointStatus(connected.endpoint_status);
    case ServiceDirectoryStatus::HandleReserveFailed:
        return connected.handle_status == ErrorCode::OutOfMemory ? DUET_SERVICE_ENDPOINT_STATUS_CAPACITY_EXHAUSTED
                                                                 : DUET_SERVICE_ENDPOINT_STATUS_INVALID_HANDLE;
    case ServiceDirectoryStatus::HandlePublishFailed:
        return DUET_SERVICE_ENDPOINT_STATUS_INVALID_HANDLE;
    case ServiceDirectoryStatus::HandleRollbackFailed:
        return DUET_SERVICE_ENDPOINT_STATUS_CORRUPT_STATE;
    default:
        return MapDirectoryStatus(connected.status);
    }
}

void ExecuteConnect(ServiceEndpointIngressState& state, const ServiceEndpointIngressCaller& caller,
                    const duet_service_endpoint_request_v1& request, duet_service_endpoint_result_v1* result)
{
    TargetService target{};
    AbiStatus status = ResolveTargetService(caller, request.target_service_identity, &target);
    if (status != DUET_SERVICE_ENDPOINT_STATUS_OK)
    {
        SetStatus(result, status);
        return;
    }

    // Reserve durable cleanup storage before the first directory mutation.
    // Missing policy/capability returned above without consuming this slot.
    const u32 rollback_slot = ReserveConnectRollbackSlot(state);
    if (rollback_slot == kServiceEndpointIngressConnectRollbackCapacity)
    {
        SetStatus(result, DUET_SERVICE_ENDPOINT_STATUS_CAPACITY_EXHAUSTED);
        return;
    }

    const ServiceDirectoryLookupResult lookup = ServiceDirectoryLookup(&caller.runtime->directory, &target.name);
    if (lookup.status != ServiceDirectoryStatus::Ok)
    {
        ReleaseConnectRollbackReservation(state, rollback_slot);
        SetStatus(result, MapDirectoryStatus(lookup.status));
        return;
    }
    ServiceDirectoryOperationPin pin = lookup.pin;
    const ServiceDirectoryInspectResult inspected =
        ServiceDirectoryInspectExact(&caller.runtime->directory, pin.service);
    if (inspected.status != ServiceDirectoryStatus::Ok ||
        inspected.snapshot.owner.start.service_identity != request.target_service_identity ||
        inspected.snapshot.manifest_slot != target.manifest_index)
    {
        const ServiceDirectoryStatus released = ServiceDirectoryReleaseOperation(&caller.runtime->directory, &pin);
        ReleaseConnectRollbackReservation(state, rollback_slot);
        SetStatus(result, released == ServiceDirectoryStatus::Ok ? (inspected.status == ServiceDirectoryStatus::Ok
                                                                        ? DUET_SERVICE_ENDPOINT_STATUS_ACCESS_DENIED
                                                                        : MapDirectoryStatus(inspected.status))
                                                                 : DUET_SERVICE_ENDPOINT_STATUS_CORRUPT_STATE);
        return;
    }

    // Mint only after the immutable policy and exact live directory owner are
    // both verified. The public request never contains this identity.
    const u64 authority_identity = MintProtocolAuthorityIdentity(state);
    const ServiceProtocolPolicyBindResult bound = ServiceProtocolPolicyBindV1(target.policy, authority_identity);
    if (bound.status != ServiceProtocolPolicyStatus::Ok)
    {
        const ServiceDirectoryStatus released = ServiceDirectoryReleaseOperation(&caller.runtime->directory, &pin);
        ReleaseConnectRollbackReservation(state, rollback_slot);
        SetStatus(result, released == ServiceDirectoryStatus::Ok ? MapProtocolPolicyStatus(bound.status)
                                                                 : DUET_SERVICE_ENDPOINT_STATUS_CORRUPT_STATE);
        return;
    }

    const ServiceEndpointCredentialSnapshot credential{caller.credential_key, caller.credential};
    const ServiceDirectoryRequestCleanupSink cleanup{&ConsumeEndpointRequestCleanup, nullptr};
    const u64 rights = ipc::HandleRightsForProcess(ipc::KObjectType::ServiceEndpoint, caller.capabilities);
    ServiceDirectoryConnectResult connected =
        ServiceDirectoryConnect(&caller.runtime->directory, pin, caller.resource_domain, caller.handles, caller.process,
                                &credential, &bound.authority, rights, &cleanup);
    const ServiceDirectoryStatus released = ServiceDirectoryReleaseOperation(&caller.runtime->directory, &pin);

    ServiceEndpointStatus cleanup_status = ServiceEndpointStatus::Ok;
    const bool had_rollback = !ServiceDirectoryOwnedChannelIsEmpty(connected.rollback);
    if (had_rollback)
    {
        if (!RetainConnectRollback(state, rollback_slot, &caller.runtime->directory, &connected.rollback))
            Panic("service-endpoint-ingress", "CONNECT rollback authority could not be retained");
        cleanup_status = DriveConnectRollbackSlot(state, rollback_slot);
    }
    else
    {
        ReleaseConnectRollbackReservation(state, rollback_slot);
    }

    if (released != ServiceDirectoryStatus::Ok)
        Panic("service-endpoint-ingress", "CONNECT operation pin release failed");
    if (connected.status == ServiceDirectoryStatus::Ok && had_rollback)
        Panic("service-endpoint-ingress", "successful CONNECT returned rollback ownership");
    if (cleanup_status == ServiceEndpointStatus::CorruptState)
    {
        SetStatus(result, DUET_SERVICE_ENDPOINT_STATUS_CORRUPT_STATE);
        return;
    }
    if (connected.status != ServiceDirectoryStatus::Ok)
    {
        SetStatus(result, cleanup_status != ServiceEndpointStatus::Ok ? MapEndpointStatus(cleanup_status)
                                                                      : MapConnectFailure(connected));
        return;
    }
    if (cleanup_status != ServiceEndpointStatus::Ok || !ServiceDirectoryOwnedChannelIsEmpty(connected.rollback))
    {
        SetStatus(result, DUET_SERVICE_ENDPOINT_STATUS_CORRUPT_STATE);
        return;
    }

    const ProcessKey peer_process{inspected.snapshot.owner.process.process_identity,
                                  inspected.snapshot.owner.process.pid};
    const ServiceEndpointPeerSnapshot peer{peer_process, inspected.snapshot.owner_credential};
    result->endpoint_handle = connected.client_handle;
    result->service_slot = target.manifest_index;
    FillEndpointInfo(connected.endpoint, bound.authority, peer, result);
    SetStatus(result, DUET_SERVICE_ENDPOINT_STATUS_OK);
}

void ExecuteReceive(ServiceEndpointIngressState& state, const ServiceEndpointIngressCaller& caller,
                    const duet_service_endpoint_request_v1& request, duet_service_endpoint_result_v1* result,
                    u8* result_frame, u32 result_frame_capacity)
{
    EndpointContext endpoint{};
    AbiStatus status =
        AcquireEndpoint(caller, request.endpoint_handle, ipc::kHandleRightRead | ipc::kHandleRightWait, &endpoint);
    if (status != DUET_SERVICE_ENDPOINT_STATUS_OK)
    {
        SetStatus(result, status);
        return;
    }
    result->endpoint_handle = request.endpoint_handle;
    FillEndpointInfo(endpoint.identity, endpoint.protocol, endpoint.peer, result);
    const ServiceEndpointDirectionResult direction =
        ServiceEndpointBorrowDirection(&endpoint.operation, ServiceEndpointTrafficDirection::Receive);
    if (direction.status != ServiceEndpointStatus::Ok)
    {
        SetStatus(result, MapEndpointStatus(direction.status));
        ReleaseEndpoint(&endpoint, result);
        return;
    }

    const PendingReceipt pending = ReservePendingReceipt(state, caller.process, endpoint.identity);
    if (pending.status != DUET_SERVICE_ENDPOINT_STATUS_OK)
    {
        SetStatus(result, pending.status);
        ReleaseEndpoint(&endpoint, result);
        return;
    }

    ipc::KMessagePortReceiveResult received{};
    for (;;)
    {
        received = ipc::KMessagePortTryReceive(direction.lease.port, result_frame, result_frame_capacity);
        if (received.status == ipc::KMessagePortStatus::Ok)
            break;
        if (received.ring_status != ipc::MessageRingStatus::Empty ||
            (request.flags & DUET_SERVICE_ENDPOINT_REQUEST_NONBLOCK) != 0)
        {
            result->required_frame_bytes = received.frame_size;
            SetStatus(result, MapPortFailure(received));
            AbandonReceipt(state, caller.process, pending.token);
            ReleaseEndpoint(&endpoint, result);
            return;
        }
        const ipc::KMessagePortStatus waited = ipc::KMessagePortWaitReadable(direction.lease.port);
        if (waited != ipc::KMessagePortStatus::Ok)
        {
            SetStatus(result, waited == ipc::KMessagePortStatus::Cancelled ? DUET_SERVICE_ENDPOINT_STATUS_CANCELLED
                                                                           : DUET_SERVICE_ENDPOINT_STATUS_CLOSED);
            AbandonReceipt(state, caller.process, pending.token);
            ReleaseEndpoint(&endpoint, result);
            return;
        }
    }

    const AuthorizedFrameValidation validation =
        ValidateAuthorizedFrame(endpoint.protocol, result_frame, received.copied_bytes);
    if (!validation.envelope_valid)
    {
        SetStatus(result, DUET_SERVICE_ENDPOINT_STATUS_CORRUPT_STATE);
        AbandonReceipt(state, caller.process, pending.token);
        ReleaseEndpoint(&endpoint, result);
        return;
    }
    const ipc::MessageView view = validation.view;
    if (validation.status != DUET_SERVICE_ENDPOINT_STATUS_OK)
    {
        AbiStatus rejection_status = validation.status;
        if (view.kind == ipc::MessageKind::Request)
        {
            ipc::EndpointRequestKey rejected{direction.lease.request_identity, view.request_id};
            const ServiceEndpointRequestTransitionResult rejection =
                ServiceEndpointRejectReceivedRequest(&endpoint.operation, &rejected);
            if (rejection.status != ServiceEndpointStatus::Ok || ipc::EndpointRequestKeyIsValid(rejected))
                rejection_status = DUET_SERVICE_ENDPOINT_STATUS_CORRUPT_STATE;
        }
        SetStatus(result, rejection_status);
        AbandonReceipt(state, caller.process, pending.token);
        ReleaseEndpoint(&endpoint, result);
        return;
    }
    result->frame_bytes = received.copied_bytes;
    result->required_frame_bytes = received.frame_size;
    result->message_kind = static_cast<u16>(view.kind);
    result->message_sequence = received.sequence;
    result->flags |= DUET_SERVICE_ENDPOINT_RESULT_HAS_FRAME;

    if (view.kind == ipc::MessageKind::Request)
    {
        const ipc::EndpointRequestKey key{direction.lease.request_identity, view.request_id};
        const ServiceEndpointRequestCommitResult committed =
            ServiceEndpointCommitReceivedRequest(&endpoint.operation, key);
        if (committed.status != ServiceEndpointStatus::Ok)
        {
            SetStatus(result, MapEndpointStatus(committed.status));
            AbandonReceipt(state, caller.process, pending.token);
            ReleaseEndpoint(&endpoint, result);
            return;
        }
        u64 prior = 0;
        if (!PublishReceipt(state, caller.process, endpoint.identity, pending.token, committed.completion_authority,
                            &prior))
        {
            // A concurrent teardown may already have cleared the row. If the
            // publication failed for any other reason, do not strand a
            // Pending receipt after the message was consumed.
            AbandonReceipt(state, caller.process, pending.token);
            SetStatus(result, DUET_SERVICE_ENDPOINT_STATUS_CANCELLED);
            ReleaseEndpoint(&endpoint, result);
            return;
        }
        result->completion_receipt = pending.token;
        result->last_committed_request_sequence = prior;
        result->flags |= DUET_SERVICE_ENDPOINT_RESULT_HAS_COMPLETION_RECEIPT;
    }
    else
    {
        AbandonReceipt(state, caller.process, pending.token);
    }
    SetStatus(result, DUET_SERVICE_ENDPOINT_STATUS_OK);
    ReleaseEndpoint(&endpoint, result);
}

void ExecuteReply(ServiceEndpointIngressState& state, const ServiceEndpointIngressCaller& caller,
                  const duet_service_endpoint_request_v1& request, const u8* frame,
                  duet_service_endpoint_result_v1* result)
{
    EndpointContext endpoint{};
    AbiStatus status = AcquireEndpoint(caller, request.endpoint_handle, ipc::kHandleRightWrite, &endpoint);
    if (status != DUET_SERVICE_ENDPOINT_STATUS_OK)
    {
        SetStatus(result, status);
        return;
    }
    result->endpoint_handle = request.endpoint_handle;
    FillEndpointInfo(endpoint.identity, endpoint.protocol, endpoint.peer, result);
    const AuthorizedFrameValidation validation = ValidateAuthorizedFrame(endpoint.protocol, frame, request.frame_bytes);
    if (validation.status != DUET_SERVICE_ENDPOINT_STATUS_OK || validation.view.kind != ipc::MessageKind::Reply)
    {
        SetStatus(result, DUET_SERVICE_ENDPOINT_STATUS_MALFORMED_MESSAGE);
        ReleaseEndpoint(&endpoint, result);
        return;
    }
    const ipc::MessageView view = validation.view;
    ipc::EndpointRequestCompletionAuthority completion{};
    status = ClaimReceipt(state, caller.process, endpoint.identity, request.completion_receipt, &completion);
    if (status != DUET_SERVICE_ENDPOINT_STATUS_OK)
    {
        SetStatus(result, status);
        ReleaseEndpoint(&endpoint, result);
        return;
    }
    if (completion.request_key().request_id != view.request_id)
    {
        FinishReceipt(state, caller.process, request.completion_receipt, false);
        SetStatus(result, DUET_SERVICE_ENDPOINT_STATUS_REPLAY_REJECTED);
        ReleaseEndpoint(&endpoint, result);
        return;
    }
    const ServiceEndpointDirectionResult direction =
        ServiceEndpointBorrowDirection(&endpoint.operation, ServiceEndpointTrafficDirection::Send);
    if (direction.status != ServiceEndpointStatus::Ok)
    {
        FinishReceipt(state, caller.process, request.completion_receipt, false);
        SetStatus(result, MapEndpointStatus(direction.status));
        ReleaseEndpoint(&endpoint, result);
        return;
    }
    const ipc::PayloadVersionRule rule = PayloadRuleFor(endpoint.protocol);
    const ipc::KMessagePortSendResult sent =
        ipc::KMessagePortSend(direction.lease.port, frame, request.frame_bytes, &rule, 1);
    if (sent.status != ipc::KMessagePortStatus::Ok)
    {
        FinishReceipt(state, caller.process, request.completion_receipt, false);
        SetStatus(result, MapSendFailure(sent));
        ReleaseEndpoint(&endpoint, result);
        return;
    }
    const ServiceEndpointRequestTransitionResult completed =
        ServiceEndpointCompleteReceivedRequest(&endpoint.operation, &completion);
    // The exact operation pin prevents close/drain between send and complete.
    // A failure here is corruption, so retire the receipt rather than permit a
    // duplicate reply to a frame already published to the peer.
    FinishReceipt(state, caller.process, request.completion_receipt, true);
    SetStatus(result, completed.status == ServiceEndpointStatus::Ok ? DUET_SERVICE_ENDPOINT_STATUS_OK
                                                                    : DUET_SERVICE_ENDPOINT_STATUS_CORRUPT_STATE);
    ReleaseEndpoint(&endpoint, result);
}

void ExecuteSendRequest(const ServiceEndpointIngressCaller& caller, const duet_service_endpoint_request_v1& request,
                        const u8* frame, duet_service_endpoint_result_v1* result)
{
    EndpointContext endpoint{};
    AbiStatus status = AcquireEndpoint(caller, request.endpoint_handle, ipc::kHandleRightWrite, &endpoint);
    if (status != DUET_SERVICE_ENDPOINT_STATUS_OK)
    {
        SetStatus(result, status);
        return;
    }
    result->endpoint_handle = request.endpoint_handle;
    FillEndpointInfo(endpoint.identity, endpoint.protocol, endpoint.peer, result);

    const AuthorizedFrameValidation validation = ValidateAuthorizedFrame(endpoint.protocol, frame, request.frame_bytes);
    if (validation.status != DUET_SERVICE_ENDPOINT_STATUS_OK || validation.view.kind != ipc::MessageKind::Request)
    {
        SetStatus(result, DUET_SERVICE_ENDPOINT_STATUS_MALFORMED_MESSAGE);
        ReleaseEndpoint(&endpoint, result);
        return;
    }

    const ServiceEndpointDirectionResult direction =
        ServiceEndpointBorrowDirection(&endpoint.operation, ServiceEndpointTrafficDirection::Send);
    if (direction.status != ServiceEndpointStatus::Ok)
    {
        SetStatus(result, MapEndpointStatus(direction.status));
        ReleaseEndpoint(&endpoint, result);
        return;
    }
    const ServiceEndpointRequestReserveResult reserved =
        ServiceEndpointReserveRequest(&endpoint.operation, validation.view.request_id);
    if (reserved.status != ServiceEndpointStatus::Ok)
    {
        SetStatus(result, MapEndpointStatus(reserved.status));
        ReleaseEndpoint(&endpoint, result);
        return;
    }

    ipc::EndpointRequestKey rollback = reserved.request_key;
    const ipc::PayloadVersionRule rule = PayloadRuleFor(endpoint.protocol);
    const ipc::KMessagePortSendResult sent =
        ipc::KMessagePortSend(direction.lease.port, frame, request.frame_bytes, &rule, 1);
    if (sent.status != ipc::KMessagePortStatus::Ok)
    {
        const ServiceEndpointRequestTransitionResult cancelled =
            ServiceEndpointCancelSentRequest(&endpoint.operation, &rollback);
        SetStatus(result, cancelled.status == ServiceEndpointStatus::Ok && !ipc::EndpointRequestKeyIsValid(rollback)
                              ? MapSendFailure(sent)
                              : DUET_SERVICE_ENDPOINT_STATUS_CORRUPT_STATE);
        ReleaseEndpoint(&endpoint, result);
        return;
    }

    result->message_kind = static_cast<u16>(ipc::MessageKind::Request);
    result->message_sequence = sent.ring.sequence;
    SetStatus(result, DUET_SERVICE_ENDPOINT_STATUS_OK);
    ReleaseEndpoint(&endpoint, result);
}

void ExecuteExport(ServiceEndpointIngressState& state, const ServiceEndpointIngressCaller& caller,
                   const duet_service_endpoint_request_v1& request, duet_service_endpoint_result_v1* result)
{
    ipc::KObjectType type{};
    if (!TransferTypeAllowed(request.object_type, &type))
    {
        SetStatus(result, request.object_type == DUET_KOBJECT_SERVICE_ENDPOINT
                              ? DUET_SERVICE_ENDPOINT_STATUS_UNSUPPORTED
                              : DUET_SERVICE_ENDPOINT_STATUS_TYPE_MISMATCH);
        return;
    }
    const u64 ceiling = ipc::HandleRightsForProcess(type, caller.capabilities);
    if ((request.requested_rights & ~ceiling) != 0)
    {
        SetStatus(result, DUET_SERVICE_ENDPOINT_STATUS_RIGHTS_DENIED);
        return;
    }
    EndpointContext endpoint{};
    AbiStatus status = AcquireEndpoint(caller, request.endpoint_handle, ipc::kHandleRightWrite, &endpoint);
    if (status != DUET_SERVICE_ENDPOINT_STATUS_OK)
    {
        SetStatus(result, status);
        return;
    }
    result->endpoint_handle = request.endpoint_handle;
    FillEndpointInfo(endpoint.identity, endpoint.protocol, endpoint.peer, result);
    const ServiceEndpointDirectionResult direction =
        ServiceEndpointBorrowDirection(&endpoint.operation, ServiceEndpointTrafficDirection::Send);
    if (direction.status != ServiceEndpointStatus::Ok)
    {
        SetStatus(result, MapEndpointStatus(direction.status));
        ReleaseEndpoint(&endpoint, result);
        return;
    }
    const u64 identity = MintObjectIdentity(state);
    if (identity == 0)
    {
        SetStatus(result, DUET_SERVICE_ENDPOINT_STATUS_CAPACITY_EXHAUSTED);
        ReleaseEndpoint(&endpoint, result);
        return;
    }
    ipc::ObjectTransferAuthority authority{};
    authority.type = type;
    authority.rights = request.requested_rights;
    authority.metadata.identity = identity;
    authority.metadata.flags = ipc::kObjectTransferMetadataSealed;
    const ipc::ObjectTransferExportResult exported = ipc::ObjectTransferExport(
        direction.lease.transfer_table, caller.handles, static_cast<ipc::Handle>(request.object_handle), authority);
    if (exported.status == ipc::ObjectTransferStatus::Ok)
    {
        result->transfer_reference = exported.reference;
        result->flags |= DUET_SERVICE_ENDPOINT_RESULT_HAS_TRANSFER;
        CopyObjectAuthority(authority, result);
    }
    SetStatus(result, MapTransferStatus(exported.status));
    ReleaseEndpoint(&endpoint, result);
}

void ExecuteImport(const ServiceEndpointIngressCaller& caller, const duet_service_endpoint_request_v1& request,
                   duet_service_endpoint_result_v1* result)
{
    ipc::KObjectType type{};
    if (!TransferTypeAllowed(request.object_type, &type))
    {
        SetStatus(result, request.object_type == DUET_KOBJECT_SERVICE_ENDPOINT
                              ? DUET_SERVICE_ENDPOINT_STATUS_UNSUPPORTED
                              : DUET_SERVICE_ENDPOINT_STATUS_TYPE_MISMATCH);
        return;
    }
    const u64 ceiling = ipc::HandleRightsForProcess(type, caller.capabilities);
    if ((request.requested_rights & ~ceiling) != 0)
    {
        SetStatus(result, DUET_SERVICE_ENDPOINT_STATUS_RIGHTS_DENIED);
        return;
    }
    EndpointContext endpoint{};
    AbiStatus status = AcquireEndpoint(caller, request.endpoint_handle, ipc::kHandleRightRead, &endpoint);
    if (status != DUET_SERVICE_ENDPOINT_STATUS_OK)
    {
        SetStatus(result, status);
        return;
    }
    result->endpoint_handle = request.endpoint_handle;
    FillEndpointInfo(endpoint.identity, endpoint.protocol, endpoint.peer, result);
    const ServiceEndpointDirectionResult direction =
        ServiceEndpointBorrowDirection(&endpoint.operation, ServiceEndpointTrafficDirection::Receive);
    if (direction.status != ServiceEndpointStatus::Ok)
    {
        SetStatus(result, MapEndpointStatus(direction.status));
        ReleaseEndpoint(&endpoint, result);
        return;
    }
    const ipc::ObjectTransferImportResult imported = ipc::ObjectTransferImport(
        direction.lease.transfer_table, request.transfer_reference, caller.handles, type, request.requested_rights);
    if (imported.status == ipc::ObjectTransferStatus::Ok)
    {
        result->object_handle = imported.handle;
        result->transfer_reference = request.transfer_reference;
        result->flags |= DUET_SERVICE_ENDPOINT_RESULT_HAS_TRANSFER;
        CopyObjectAuthority(imported.authority, result);
    }
    SetStatus(result, MapTransferStatus(imported.status));
    ReleaseEndpoint(&endpoint, result);
}

void ExecuteRevoke(const ServiceEndpointIngressCaller& caller, const duet_service_endpoint_request_v1& request,
                   duet_service_endpoint_result_v1* result)
{
    EndpointContext endpoint{};
    AbiStatus status = AcquireEndpoint(caller, request.endpoint_handle, ipc::kHandleRightWrite, &endpoint);
    if (status != DUET_SERVICE_ENDPOINT_STATUS_OK)
    {
        SetStatus(result, status);
        return;
    }
    result->endpoint_handle = request.endpoint_handle;
    FillEndpointInfo(endpoint.identity, endpoint.protocol, endpoint.peer, result);
    const ServiceEndpointDirectionResult direction =
        ServiceEndpointBorrowDirection(&endpoint.operation, ServiceEndpointTrafficDirection::Send);
    if (direction.status != ServiceEndpointStatus::Ok)
        SetStatus(result, MapEndpointStatus(direction.status));
    else
        SetStatus(result, MapTransferStatus(
                              ipc::ObjectTransferRevoke(direction.lease.transfer_table, request.transfer_reference)));
    ReleaseEndpoint(&endpoint, result);
}

#if !defined(DUETOS_HOST_TEST)
constinit ServiceEndpointIngressState g_kernel_ingress{};
#endif

} // namespace

ServiceEndpointIngressStatus ServiceEndpointIngressInitialize(ServiceEndpointIngressState* state)
{
    if (state == nullptr)
        return ServiceEndpointIngressStatus::InvalidArgument;
    if (state->initialized == kServiceEndpointIngressInitializedMarker)
        return ServiceEndpointIngressStatus::AlreadyInitialized;
    if (!StateIsCanonicalUninitialized(*state))
        return ServiceEndpointIngressStatus::CorruptState;
#if !defined(DUETOS_HOST_TEST)
    state->lock.next_ticket = 0;
    state->lock.now_serving = 0;
    state->lock.owner_cpu = 0xFFFFFFFFU;
    state->lock.class_id = sync::kLockClassUnclassified;
#endif
    state->receipts[0].state = ServiceEndpointIngressReceiptState::Retired;
    state->next_receipt_hint = 1;
    state->next_cursor_hint = 0;
    state->next_connect_rollback_hint = 0;
    state->next_object_identity = 1;
    state->next_protocol_authority_identity = 1;
    state->initialized = kServiceEndpointIngressInitializedMarker;
    return ServiceEndpointIngressStatus::Ok;
}

ServiceEndpointIngressStatus ServiceEndpointIngressExecute(ServiceEndpointIngressState* state,
                                                           const ServiceEndpointIngressCaller* caller,
                                                           const duet_service_endpoint_request_v1* request,
                                                           const u8* request_frame,
                                                           duet_service_endpoint_result_v1* result, u8* result_frame,
                                                           u32 result_frame_capacity)
{
    if (state == nullptr || caller == nullptr || request == nullptr || result == nullptr ||
        result_frame_capacity > DUET_SERVICE_ENDPOINT_MAX_FRAME_BYTES ||
        (result_frame_capacity != 0 && result_frame == nullptr))
    {
        return ServiceEndpointIngressStatus::InvalidArgument;
    }
    if (state->initialized != kServiceEndpointIngressInitializedMarker)
        return ServiceEndpointIngressStatus::NotInitialized;
    InitializeResult(*request, result);
    if (!CallerIsCanonical(*caller) || !RequestIsCanonical(*request) ||
        (request->frame_bytes != 0 && request_frame == nullptr))
    {
        SetStatus(result, request->version == DUET_SERVICE_ENDPOINT_ABI_VERSION
                              ? DUET_SERVICE_ENDPOINT_STATUS_INVALID_ARGUMENT
                              : DUET_SERVICE_ENDPOINT_STATUS_BAD_VERSION);
        return ServiceEndpointIngressStatus::Ok;
    }

    if (request->operation != DUET_SERVICE_ENDPOINT_OP_CONNECT)
        ServiceEndpointIngressDriveConnectRollbacks(state);

    switch (request->operation)
    {
    case DUET_SERVICE_ENDPOINT_OP_ACCEPT:
        ExecuteAccept(*state, *caller, result);
        break;
    case DUET_SERVICE_ENDPOINT_OP_RECEIVE:
        ExecuteReceive(*state, *caller, *request, result, result_frame, result_frame_capacity);
        break;
    case DUET_SERVICE_ENDPOINT_OP_REPLY_ACK:
        ExecuteReply(*state, *caller, *request, request_frame, result);
        break;
    case DUET_SERVICE_ENDPOINT_OP_EXPORT:
        ExecuteExport(*state, *caller, *request, result);
        break;
    case DUET_SERVICE_ENDPOINT_OP_IMPORT:
        ExecuteImport(*caller, *request, result);
        break;
    case DUET_SERVICE_ENDPOINT_OP_REVOKE_EXPORT:
        ExecuteRevoke(*caller, *request, result);
        break;
    case DUET_SERVICE_ENDPOINT_OP_CLOSE:
    {
        ServiceEndpointIdentity closed{};
        const AbiStatus status =
            CloseEndpointHandle(*state, *caller, static_cast<ipc::Handle>(request->endpoint_handle), &closed);
        result->endpoint_handle = request->endpoint_handle;
        if (status == DUET_SERVICE_ENDPOINT_STATUS_OK)
        {
            result->endpoint_identity = closed.channel.channel_epoch;
            result->channel.slot = closed.channel.slot;
            result->channel.role = static_cast<u8>(closed.role);
            result->channel.generation = closed.channel.generation;
            result->channel.epoch = closed.channel.channel_epoch;
        }
        SetStatus(result, status);
        break;
    }
    case DUET_SERVICE_ENDPOINT_OP_CONNECT:
        ExecuteConnect(*state, *caller, *request, result);
        break;
    case DUET_SERVICE_ENDPOINT_OP_SEND_REQUEST:
        ExecuteSendRequest(*caller, *request, request_frame, result);
        break;
    default:
        SetStatus(result, DUET_SERVICE_ENDPOINT_STATUS_UNSUPPORTED);
        break;
    }
    return ServiceEndpointIngressStatus::Ok;
}

void ServiceEndpointIngressDriveConnectRollbacks(ServiceEndpointIngressState* state)
{
    if (state == nullptr || state->initialized != kServiceEndpointIngressInitializedMarker)
        return;
    for (u32 slot = 0; slot < kServiceEndpointIngressConnectRollbackCapacity; ++slot)
        (void)DriveConnectRollbackSlot(*state, slot);
}

void ServiceEndpointIngressCancelProcess(ServiceEndpointIngressState* state, ProcessKey process)
{
    if (state == nullptr || state->initialized != kServiceEndpointIngressInitializedMarker ||
        !ProcessKeyIsValid(process))
    {
        return;
    }
    StateGuard guard(*state);
    for (auto& row : state->receipts)
    {
        if (ProcessMatches(row.owner, process))
            ClearReceipt(&row);
    }
    for (auto& row : state->cursors)
    {
        if (row.live && ProcessMatches(row.owner, process))
            ClearCursor(&row);
    }
}

#if !defined(DUETOS_HOST_TEST)
ServiceEndpointIngressStatus ServiceEndpointIngressInitializeKernel()
{
    return ServiceEndpointIngressInitialize(&g_kernel_ingress);
}

void ServiceEndpointIngressCancelProcessKernel(ProcessKey process)
{
    ServiceEndpointIngressCancelProcess(&g_kernel_ingress, process);
}

void DoServiceEndpointOp(arch::TrapFrame* frame)
{
    if (frame == nullptr)
        return;
    const u64 request_bytes = frame->rsi;
    const u64 result_capacity = frame->r10;
    if (frame->rdi == 0 || frame->rdx == 0 || request_bytes < sizeof(duet_service_endpoint_request_v1) ||
        request_bytes > sizeof(duet_service_endpoint_request_v1) + DUET_SERVICE_ENDPOINT_MAX_FRAME_BYTES ||
        result_capacity < sizeof(duet_service_endpoint_result_v1) ||
        result_capacity > sizeof(duet_service_endpoint_result_v1) + DUET_SERVICE_ENDPOINT_MAX_FRAME_BYTES)
    {
        frame->rax = static_cast<u64>(kSysErrnoEFAULT);
        return;
    }

    duet_service_endpoint_request_v1 request{};
    if (!mm::CopyFromUser(&request, reinterpret_cast<const void*>(frame->rdi), sizeof(request)))
    {
        frame->rax = static_cast<u64>(kSysErrnoEFAULT);
        return;
    }
    if (request.struct_size != sizeof(request) || request.frame_bytes > DUET_SERVICE_ENDPOINT_MAX_FRAME_BYTES ||
        request_bytes != sizeof(request) + request.frame_bytes)
    {
        frame->rax = static_cast<u64>(kSysErrnoEINVAL);
        return;
    }
    if (request.frame_bytes != 0 && frame->rdi > ~u64{0} - static_cast<u64>(sizeof(duet_service_endpoint_request_v1)))
    {
        frame->rax = static_cast<u64>(kSysErrnoEFAULT);
        return;
    }

    struct OutputBounce
    {
        duet_service_endpoint_result_v1 result;
        u8 frame[DUET_SERVICE_ENDPOINT_MAX_FRAME_BYTES];
    } bounce{};
    static_assert(offsetof(OutputBounce, frame) == sizeof(duet_service_endpoint_result_v1));
    if (request.frame_bytes != 0 &&
        !mm::CopyFromUser(bounce.frame,
                          reinterpret_cast<const void*>(frame->rdi + sizeof(duet_service_endpoint_request_v1)),
                          request.frame_bytes))
    {
        frame->rax = static_cast<u64>(kSysErrnoEFAULT);
        return;
    }

    Process* process = CurrentProcess();
    CredentialSnapshot credential{};
    if (process == nullptr || !ProcessInspectCredentials(process, &credential) ||
        credential.state != CredentialState::Live)
    {
        frame->rax = static_cast<u64>(kSysErrnoEACCES);
        return;
    }
    ServiceEndpointIngressCaller caller{
        ProcessKeySnapshot(process), &process->kobj_handles,       ProcessCredentialKeySnapshot(process),
        credential.security,         ProcessCapsSnapshot(process), process->resource_domain,
        ServiceRuntimeKernelV1(),
    };
    mm::AddressSpaceWriteLease output_lease{};
    const mm::AddressSpaceWriteLeaseStatus lease_status =
        mm::AddressSpaceAcquireWriteLease(process->as, frame->rdx, result_capacity, &output_lease);
    if (lease_status != mm::AddressSpaceWriteLeaseStatus::Ok)
    {
        frame->rax =
            static_cast<u64>(lease_status == mm::AddressSpaceWriteLeaseStatus::CapacityExhausted ? kSysErrnoEAGAIN
                             : lease_status == mm::AddressSpaceWriteLeaseStatus::TokenExhausted ||
                                     lease_status == mm::AddressSpaceWriteLeaseStatus::CorruptState
                                 ? kSysErrnoENOMEM
                                 : kSysErrnoEFAULT);
        return;
    }
    DUETOS_DEFER((void)mm::AddressSpaceReleaseWriteLease(&output_lease));

    const u32 result_frame_capacity = static_cast<u32>(result_capacity - sizeof(bounce.result));
    const ServiceEndpointIngressStatus executed = ServiceEndpointIngressExecute(
        &g_kernel_ingress, &caller, &request, bounce.frame, &bounce.result, bounce.frame, result_frame_capacity);
    if (executed != ServiceEndpointIngressStatus::Ok)
    {
        frame->rax = static_cast<u64>(executed == ServiceEndpointIngressStatus::NotInitialized ? kSysErrnoENODEV
                                                                                               : kSysErrnoEINVAL);
        return;
    }
    const u64 copied_bytes = sizeof(bounce.result) + bounce.result.frame_bytes;
    if (!mm::AddressSpaceCopyToWriteLease(output_lease, 0, &bounce, copied_bytes))
    {
        frame->rax = static_cast<u64>(kSysErrnoEFAULT);
        return;
    }
    frame->rax = 0;
}
#endif

const char* ServiceEndpointIngressStatusName(ServiceEndpointIngressStatus status)
{
    switch (status)
    {
    case ServiceEndpointIngressStatus::Ok:
        return "Ok";
    case ServiceEndpointIngressStatus::InvalidArgument:
        return "InvalidArgument";
    case ServiceEndpointIngressStatus::AlreadyInitialized:
        return "AlreadyInitialized";
    case ServiceEndpointIngressStatus::NotInitialized:
        return "NotInitialized";
    case ServiceEndpointIngressStatus::CorruptState:
        return "CorruptState";
    }
    return "Unknown";
}

} // namespace duetos::core
