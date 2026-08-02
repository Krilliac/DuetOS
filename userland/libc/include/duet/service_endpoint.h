#ifndef DUET_SERVICE_ENDPOINT_H
#define DUET_SERVICE_ENDPOINT_H

/*
 * Native ServiceEndpoint syscall ABI, v1.
 *
 * The request contains no pointers.  Optional message bytes immediately follow
 * the fixed request structure; received bytes immediately follow the fixed
 * result structure.  The kernel snapshots every input before acting and pins
 * the exact writable result mappings only for the duration of the syscall; it
 * retains no user address after return.  Handles, transfer references, and
 * completion receipts are opaque generation-bearing positive integers.
 */

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

#define DUET_SERVICE_ENDPOINT_ABI_VERSION 1U
#define DUET_SERVICE_ENDPOINT_MAX_FRAME_BYTES 4096U
#define DUET_SERVICE_ENDPOINT_SUPPLEMENTAL_GROUP_CAPACITY 16U

    enum duet_service_endpoint_operation
    {
        DUET_SERVICE_ENDPOINT_OP_ACCEPT = 1,
        DUET_SERVICE_ENDPOINT_OP_RECEIVE = 2,
        DUET_SERVICE_ENDPOINT_OP_REPLY_ACK = 3,
        DUET_SERVICE_ENDPOINT_OP_EXPORT = 4,
        DUET_SERVICE_ENDPOINT_OP_IMPORT = 5,
        DUET_SERVICE_ENDPOINT_OP_REVOKE_EXPORT = 6,
        DUET_SERVICE_ENDPOINT_OP_CLOSE = 7,
        DUET_SERVICE_ENDPOINT_OP_CONNECT = 8,
        DUET_SERVICE_ENDPOINT_OP_SEND_REQUEST = 9,
    };

    enum duet_service_endpoint_request_flags
    {
        DUET_SERVICE_ENDPOINT_REQUEST_NONBLOCK = 1U << 0,
    };

    enum duet_service_endpoint_result_flags
    {
        DUET_SERVICE_ENDPOINT_RESULT_HAS_FRAME = 1U << 0,
        DUET_SERVICE_ENDPOINT_RESULT_HAS_COMPLETION_RECEIPT = 1U << 1,
        DUET_SERVICE_ENDPOINT_RESULT_HAS_TRANSFER = 1U << 2,
        /* The current kernel endpoint snapshot is process-bound, not task-bound. */
        DUET_SERVICE_ENDPOINT_RESULT_PEER_TASK_UNAVAILABLE = 1U << 3,
    };

    enum duet_service_endpoint_status
    {
        DUET_SERVICE_ENDPOINT_STATUS_OK = 0,
        DUET_SERVICE_ENDPOINT_STATUS_INVALID_ARGUMENT = 1,
        DUET_SERVICE_ENDPOINT_STATUS_BAD_VERSION = 2,
        DUET_SERVICE_ENDPOINT_STATUS_BUFFER_TOO_SMALL = 3,
        DUET_SERVICE_ENDPOINT_STATUS_NOT_READY = 4,
        DUET_SERVICE_ENDPOINT_STATUS_ACCESS_DENIED = 5,
        DUET_SERVICE_ENDPOINT_STATUS_INVALID_HANDLE = 6,
        DUET_SERVICE_ENDPOINT_STATUS_WOULD_BLOCK = 7,
        DUET_SERVICE_ENDPOINT_STATUS_CLOSED = 8,
        DUET_SERVICE_ENDPOINT_STATUS_CANCELLED = 9,
        DUET_SERVICE_ENDPOINT_STATUS_BUSY = 10,
        DUET_SERVICE_ENDPOINT_STATUS_CAPACITY_EXHAUSTED = 11,
        DUET_SERVICE_ENDPOINT_STATUS_STALE = 12,
        DUET_SERVICE_ENDPOINT_STATUS_REPLAY_REJECTED = 13,
        DUET_SERVICE_ENDPOINT_STATUS_MALFORMED_MESSAGE = 14,
        DUET_SERVICE_ENDPOINT_STATUS_TYPE_MISMATCH = 15,
        DUET_SERVICE_ENDPOINT_STATUS_RIGHTS_DENIED = 16,
        DUET_SERVICE_ENDPOINT_STATUS_CORRUPT_STATE = 17,
        DUET_SERVICE_ENDPOINT_STATUS_UNSUPPORTED = 18,
        DUET_SERVICE_ENDPOINT_STATUS_INTERNAL_ERROR = 19,
    };

    /* Stable public mirrors of kernel KObject type tags. */
    enum duet_kobject_type
    {
        DUET_KOBJECT_INVALID = 0,
        DUET_KOBJECT_MUTEX = 1,
        DUET_KOBJECT_EVENT = 2,
        DUET_KOBJECT_SEMAPHORE = 3,
        DUET_KOBJECT_MAILBOX = 4,
        DUET_KOBJECT_WAITABLE = 5,
        DUET_KOBJECT_FILE = 6,
        DUET_KOBJECT_IOCP = 7,
        DUET_KOBJECT_MESSAGE_PORT = 8,
        DUET_KOBJECT_SERVICE_ENDPOINT = 9,
    };

    enum duet_handle_right
    {
        DUET_HANDLE_RIGHT_READ = 1U << 0,
        DUET_HANDLE_RIGHT_WRITE = 1U << 1,
        DUET_HANDLE_RIGHT_DUPLICATE = 1U << 2,
        DUET_HANDLE_RIGHT_TRANSFER = 1U << 3,
        DUET_HANDLE_RIGHT_WAIT = 1U << 4,
        DUET_HANDLE_RIGHT_SIGNAL = 1U << 5,
        DUET_HANDLE_RIGHT_DESTROY = 1U << 6,
        DUET_HANDLE_RIGHT_INSPECT = 1U << 7,
    };

    typedef struct duet_service_endpoint_request_v1
    {
        uint32_t struct_size;
        uint16_t version;
        uint16_t operation;
        uint32_t flags;
        uint32_t frame_bytes;
        uint64_t endpoint_handle;
        uint64_t completion_receipt;
        uint64_t object_handle;
        uint64_t requested_rights;
        uint32_t transfer_reference;
        uint16_t object_type;
        uint16_t reserved16;
        // CONNECT-only stable manifest selector; never protocol authority.
        uint64_t target_service_identity;
        uint64_t reserved64;
    } duet_service_endpoint_request_v1;

    typedef struct duet_service_endpoint_channel_identity_v1
    {
        uint32_t slot;
        uint8_t role;
        uint8_t reserved8[3];
        uint64_t generation;
        uint64_t epoch;
    } duet_service_endpoint_channel_identity_v1;

    typedef struct duet_service_endpoint_process_key_v1
    {
        uint64_t identity;
        uint64_t pid;
    } duet_service_endpoint_process_key_v1;

    typedef struct duet_service_endpoint_credential_v1
    {
        uint32_t slot;
        uint32_t reserved32;
        uint64_t generation;

        uint32_t real_uid;
        uint32_t effective_uid;
        uint32_t saved_uid;
        uint32_t fs_uid;
        uint32_t real_gid;
        uint32_t effective_gid;
        uint32_t saved_gid;
        uint32_t fs_gid;

        uint32_t supplemental_group_count;
        uint32_t supplemental_groups[DUET_SERVICE_ENDPOINT_SUPPLEMENTAL_GROUP_CAPACITY];
        uint32_t reserved_alignment;

        uint64_t capability_effective;
        uint64_t capability_permitted;
        uint64_t capability_inheritable;
        uint64_t capability_bounding;
        uint8_t win32_integrity;
        uint8_t reserved8[7];
    } duet_service_endpoint_credential_v1;

    typedef struct duet_service_endpoint_protocol_authority_v1
    {
        uint64_t authority_identity;
        uint64_t protocol_identity;
        uint64_t service_identity;
        uint64_t allowed_methods;
        uint32_t protocol_version;
        uint32_t flags;
        uint32_t wire_service_id;
        uint32_t reserved32;
    } duet_service_endpoint_protocol_authority_v1;

    typedef struct duet_service_endpoint_object_metadata_v1
    {
        uint64_t identity;
        uint64_t object_size;
        uint8_t content_hash[32];
        uint32_t flags;
        uint32_t reserved;
    } duet_service_endpoint_object_metadata_v1;

    typedef struct duet_service_endpoint_result_v1
    {
        uint32_t struct_size;
        uint16_t version;
        uint16_t operation;
        int32_t status;
        uint32_t flags;
        uint32_t frame_bytes;
        uint32_t required_frame_bytes;
        uint16_t message_kind;
        uint16_t reserved16;
        uint32_t transfer_reference;

        uint64_t message_sequence;
        uint64_t endpoint_handle;
        uint64_t completion_receipt;
        uint64_t object_handle;
        uint64_t object_rights;
        uint64_t last_committed_request_sequence;
        /* For an accepted service endpoint this is the globally unique channel epoch. */
        uint64_t endpoint_identity;
        /* Always zero in v1; callers must honor PEER_TASK_UNAVAILABLE. */
        uint64_t peer_task_identity;

        uint64_t local_service_identity;
        uint64_t local_instance_generation;
        uint64_t local_process_identity;
        uint64_t local_pid;
        uint32_t service_slot;
        uint16_t object_type;
        uint16_t reserved_object;

        duet_service_endpoint_channel_identity_v1 channel;
        duet_service_endpoint_protocol_authority_v1 protocol;
        duet_service_endpoint_process_key_v1 peer_process;
        duet_service_endpoint_credential_v1 peer_credential;
        duet_service_endpoint_object_metadata_v1 object_metadata;
        uint64_t reserved[2];
    } duet_service_endpoint_result_v1;

    /*
 * Invoke SYS_SERVICE_ENDPOINT_OP. request_bytes must be exactly
 * sizeof(*request) + request->frame_bytes. result_capacity may reserve up to
 * DUET_SERVICE_ENDPOINT_MAX_FRAME_BYTES immediately after *result.
 */
    long duet_service_endpoint_op(const duet_service_endpoint_request_v1* request, size_t request_bytes,
                                  duet_service_endpoint_result_v1* result, size_t result_capacity);

#if defined(__cplusplus)
    static_assert(sizeof(duet_service_endpoint_request_v1) == 72, "service endpoint request ABI changed");
    static_assert(sizeof(duet_service_endpoint_channel_identity_v1) == 24, "channel identity ABI changed");
    static_assert(sizeof(duet_service_endpoint_credential_v1) == 160, "credential ABI changed");
    static_assert(sizeof(duet_service_endpoint_protocol_authority_v1) == 48, "protocol authority ABI changed");
    static_assert(offsetof(duet_service_endpoint_protocol_authority_v1, wire_service_id) == 40,
                  "protocol wire service offset changed");
    static_assert(offsetof(duet_service_endpoint_protocol_authority_v1, reserved32) == 44,
                  "protocol reserved offset changed");
    static_assert(sizeof(duet_service_endpoint_object_metadata_v1) == 56, "object metadata ABI changed");
    static_assert(sizeof(duet_service_endpoint_result_v1) == 456, "service endpoint result ABI changed");
#else
_Static_assert(sizeof(duet_service_endpoint_request_v1) == 72, "service endpoint request ABI changed");
_Static_assert(sizeof(duet_service_endpoint_channel_identity_v1) == 24, "channel identity ABI changed");
_Static_assert(sizeof(duet_service_endpoint_credential_v1) == 160, "credential ABI changed");
_Static_assert(sizeof(duet_service_endpoint_protocol_authority_v1) == 48, "protocol authority ABI changed");
_Static_assert(offsetof(duet_service_endpoint_protocol_authority_v1, wire_service_id) == 40,
               "protocol wire service offset changed");
_Static_assert(offsetof(duet_service_endpoint_protocol_authority_v1, reserved32) == 44,
               "protocol reserved offset changed");
_Static_assert(sizeof(duet_service_endpoint_object_metadata_v1) == 56, "object metadata ABI changed");
_Static_assert(sizeof(duet_service_endpoint_result_v1) == 456, "service endpoint result ABI changed");
#endif

#ifdef __cplusplus
}
#endif

#endif /* DUET_SERVICE_ENDPOINT_H */
