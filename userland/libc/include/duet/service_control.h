#ifndef DUET_SERVICE_CONTROL_H
#define DUET_SERVICE_CONTROL_H

/*
 * Native service-control syscall ABI, v1.
 *
 * Both structures are fixed-size and pointer-free.  Every mutating operation
 * carries the exact broker incarnation and service transition generation; an
 * operation that targets a published or exited instance also carries the full
 * non-recycled ProcessKey.  These values are stale checks only.  Authority is
 * always derived by the kernel from the current process and never from a field
 * supplied here.
 */

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

#define DUET_SERVICE_CONTROL_ABI_VERSION 1U

    enum duet_service_control_operation
    {
        DUET_SERVICE_CONTROL_OP_DESCRIBE_SELF = 1,
        DUET_SERVICE_CONTROL_OP_MARK_READY = 2,
        DUET_SERVICE_CONTROL_OP_ENUMERATE = 3,
        DUET_SERVICE_CONTROL_OP_ACTIVATE = 4,
        DUET_SERVICE_CONTROL_OP_STOP = 5,
        DUET_SERVICE_CONTROL_OP_RESTAGE = 6,
        DUET_SERVICE_CONTROL_OP_EXIT_DEQUEUE = 7,
        DUET_SERVICE_CONTROL_OP_EXIT_ACK = 8,
    };

    enum duet_service_control_status
    {
        DUET_SERVICE_CONTROL_STATUS_OK = 0,
        DUET_SERVICE_CONTROL_STATUS_INVALID_ARGUMENT = 1,
        DUET_SERVICE_CONTROL_STATUS_BAD_VERSION = 2,
        DUET_SERVICE_CONTROL_STATUS_ACCESS_DENIED = 3,
        DUET_SERVICE_CONTROL_STATUS_NOT_READY = 4,
        DUET_SERVICE_CONTROL_STATUS_NOT_FOUND = 5,
        DUET_SERVICE_CONTROL_STATUS_STALE = 6,
        DUET_SERVICE_CONTROL_STATUS_REPLAY_REJECTED = 7,
        DUET_SERVICE_CONTROL_STATUS_WOULD_BLOCK = 8,
        DUET_SERVICE_CONTROL_STATUS_BUSY = 9,
        DUET_SERVICE_CONTROL_STATUS_CAPACITY_EXHAUSTED = 10,
        DUET_SERVICE_CONTROL_STATUS_GENERATION_EXHAUSTED = 11,
        DUET_SERVICE_CONTROL_STATUS_ALREADY_REQUESTED = 12,
        DUET_SERVICE_CONTROL_STATUS_ALREADY_STOPPED = 13,
        DUET_SERVICE_CONTROL_STATUS_UNSUPPORTED = 14,
        DUET_SERVICE_CONTROL_STATUS_CORRUPT_STATE = 15,
        DUET_SERVICE_CONTROL_STATUS_INTERNAL_ERROR = 16,
    };

    enum duet_service_control_result_flags
    {
        DUET_SERVICE_CONTROL_RESULT_HAS_SERVICE = 1U << 0,
        DUET_SERVICE_CONTROL_RESULT_SERVICE_READY = 1U << 1,
        DUET_SERVICE_CONTROL_RESULT_HAS_EXIT_EVENT = 1U << 2,
        DUET_SERVICE_CONTROL_RESULT_EXIT_FAILED = 1U << 3,
    };

    /* Stable public mirror of ServiceTransitionPhase. */
    enum duet_service_control_phase
    {
        DUET_SERVICE_CONTROL_PHASE_STOPPED = 0,
        DUET_SERVICE_CONTROL_PHASE_STARTING = 1,
        DUET_SERVICE_CONTROL_PHASE_RUNNING = 2,
        DUET_SERVICE_CONTROL_PHASE_EXITED = 3,
        DUET_SERVICE_CONTROL_PHASE_FAILED = 4,
        DUET_SERVICE_CONTROL_PHASE_GENERATION_EXHAUSTED = 5,
        DUET_SERVICE_CONTROL_PHASE_STOPPING = 6,
    };

    typedef struct duet_service_control_request_v1
    {
        uint32_t struct_size;
        uint16_t version;
        uint16_t operation;
        uint32_t flags;
        /* ENUMERATE-only stable manifest row index; zero for every other op. */
        uint32_t service_index;

        uint64_t broker_epoch;
        uint64_t service_identity;
        uint64_t transition_generation;
        uint64_t process_identity;
        uint64_t pid;
        /* EXIT_ACK-only public acknowledgement authority; zero otherwise. */
        uint64_t operation_token;
        /* RESTAGE/EXIT_ACK exact exit-ledger event identity; zero otherwise. */
        uint64_t event_sequence;
        uint64_t reserved[1];
    } duet_service_control_request_v1;

    typedef struct duet_service_control_result_v1
    {
        uint32_t struct_size;
        uint16_t version;
        uint16_t operation;
        int32_t status;
        uint32_t flags;

        uint32_t service_index;
        uint32_t service_count;
        uint8_t phase;
        uint8_t ready;
        uint8_t exit_failed;
        uint8_t reserved8;
        uint32_t reserved32;

        uint64_t broker_epoch;
        uint64_t service_identity;
        uint64_t transition_generation;
        uint64_t process_identity;
        uint64_t pid;
        /* Public ACK token for EXIT_DEQUEUE/EXIT_ACK; zero otherwise. */
        uint64_t operation_token;
        /* Exact factual event sequence; copy into RESTAGE/EXIT_ACK requests. */
        uint64_t event_sequence;
        int64_t exit_status;
        uint64_t reserved[2];
    } duet_service_control_result_v1;

    /*
     * Invoke SYS_SERVICE_CONTROL.  The byte counts must be exactly the fixed
     * v1 structure sizes.  Input and output may alias: the kernel snapshots the
     * complete request and leases the exact writable result mapping before any
     * lifecycle mutation.
     */
    long duet_service_control(const duet_service_control_request_v1* request, size_t request_bytes,
                              duet_service_control_result_v1* result, size_t result_capacity);

    /*
     * Two-step DESCRIBE_SELF → MARK_READY handshake.  The kernel derives the
     * caller's identity from the current process and validates the echoed fields
     * on the MARK_READY leg.  Returns 0 on success, -1 on any failure.
     */
    int duet_service_mark_ready(void);

#if defined(__cplusplus)
    static_assert(sizeof(duet_service_control_request_v1) == 80, "service-control request ABI changed");
    static_assert(offsetof(duet_service_control_request_v1, operation_token) == 56,
                  "service-control acknowledgement-token offset changed");
    static_assert(offsetof(duet_service_control_request_v1, event_sequence) == 64,
                  "service-control event-sequence offset changed");
    static_assert(sizeof(duet_service_control_result_v1) == 112, "service-control result ABI changed");
#else
_Static_assert(sizeof(duet_service_control_request_v1) == 80, "service-control request ABI changed");
_Static_assert(offsetof(duet_service_control_request_v1, operation_token) == 56,
               "service-control acknowledgement-token offset changed");
_Static_assert(offsetof(duet_service_control_request_v1, event_sequence) == 64,
               "service-control event-sequence offset changed");
_Static_assert(sizeof(duet_service_control_result_v1) == 112, "service-control result ABI changed");
#endif

#ifdef __cplusplus
}
#endif

#endif /* DUET_SERVICE_CONTROL_H */
