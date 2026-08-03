#ifndef DUETOS_REGISTRYD_STORE_H
#define DUETOS_REGISTRYD_STORE_H

/*
 * Allocation-free registryd storage and recovery core.
 *
 * The registryd actor thread owns every call.  This module performs no I/O,
 * allocation, locking, authorization, or endpoint publication.  Transport
 * code must bind client_identity to authenticated channel state, append and
 * durably flush the prepared WAL bytes, then commit the matching preparation.
 * A caller may abort a preparation only when those bytes were not made
 * durable.  Snapshot replacement and WAL truncation remain VFS operations.
 *
 * Paths and value names use a deliberately bounded ASCII v1 canonical form.
 * Input lengths exclude a trailing NUL.  Paths begin with HKLM, HKCU, HKCR,
 * HKU, or HKCC and use backslash-separated non-empty components.  The engine
 * uppercases ASCII letters so comparisons and persistence are deterministic.
 */

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

#define REGISTRYD_STORE_MAX_ENTRIES 64U
#define REGISTRYD_STORE_MAX_CLIENTS 16U
#define REGISTRYD_STORE_MAX_KEY_BYTES 127U
#define REGISTRYD_STORE_MAX_NAME_BYTES 63U
#define REGISTRYD_STORE_MAX_VALUE_BYTES 256U
#define REGISTRYD_STORE_MAX_WAL_RECORD_BYTES 640U
#define REGISTRYD_STORE_MAX_SNAPSHOT_BYTES 49152U
#define REGISTRYD_STORE_STORAGE_BYTES 65536U

    typedef enum RegistrydStoreStatus
    {
        REGISTRYD_STORE_OK = 0,
        REGISTRYD_STORE_RECOVERED_TORN_WAL,
        REGISTRYD_STORE_NULL_ARGUMENT,
        REGISTRYD_STORE_ALIASED_STORAGE,
        REGISTRYD_STORE_ALREADY_INITIALIZED,
        REGISTRYD_STORE_NOT_INITIALIZED,
        REGISTRYD_STORE_CORRUPT_STATE,
        REGISTRYD_STORE_INVALID_KEY,
        REGISTRYD_STORE_INVALID_NAME,
        REGISTRYD_STORE_INVALID_TYPE,
        REGISTRYD_STORE_INVALID_VALUE,
        REGISTRYD_STORE_INVALID_OPERATION,
        REGISTRYD_STORE_CAPACITY,
        REGISTRYD_STORE_CLIENT_CAPACITY,
        REGISTRYD_STORE_NOT_FOUND,
        REGISTRYD_STORE_VERSION_CONFLICT,
        REGISTRYD_STORE_DUPLICATE_REQUEST,
        REGISTRYD_STORE_REQUEST_ID_CONFLICT,
        REGISTRYD_STORE_REPLAYED_REQUEST,
        REGISTRYD_STORE_REQUEST_ID_EXHAUSTED,
        REGISTRYD_STORE_GENERATION_EXHAUSTED,
        REGISTRYD_STORE_PENDING_MUTATION,
        REGISTRYD_STORE_NO_PENDING_MUTATION,
        REGISTRYD_STORE_STALE_PREPARATION,
        REGISTRYD_STORE_BUFFER_TOO_SMALL,
        REGISTRYD_STORE_CORRUPT_SNAPSHOT,
        REGISTRYD_STORE_CORRUPT_WAL
    } RegistrydStoreStatus;

    typedef enum RegistrydValueType
    {
        REGISTRYD_VALUE_NONE = 0,
        REGISTRYD_VALUE_STRING = 1,
        REGISTRYD_VALUE_EXPAND_STRING = 2,
        REGISTRYD_VALUE_BINARY = 3,
        REGISTRYD_VALUE_DWORD = 4,
        REGISTRYD_VALUE_MULTI_STRING = 7,
        REGISTRYD_VALUE_QWORD = 11
    } RegistrydValueType;

    /* Value payloads are preserved byte-for-byte. String terminators are API-layer policy, not store policy. */

    typedef enum RegistrydMutationOperation
    {
        REGISTRYD_MUTATION_SET = 1,
        REGISTRYD_MUTATION_DELETE = 2
    } RegistrydMutationOperation;

    typedef union RegistrydStore
    {
        uint64_t alignment;
        uint8_t bytes[REGISTRYD_STORE_STORAGE_BYTES];
    } RegistrydStore;

    typedef struct RegistrydMutation
    {
        uint64_t client_identity;
        uint64_t request_id;
        uint64_t expected_entry_generation;
        const char* key;
        const char* name;
        const uint8_t* value;
        uint32_t key_size;
        uint32_t name_size;
        uint32_t value_size;
        uint32_t value_type;
        uint8_t operation;
        uint8_t reserved8[7];
    } RegistrydMutation;

    typedef struct RegistrydPreparedMutation
    {
        uint64_t preparation_generation;
        uint64_t commit_sequence;
        uint64_t entry_generation;
        uint64_t fingerprint;
    } RegistrydPreparedMutation;

    typedef struct RegistrydMutationResult
    {
        uint64_t commit_sequence;
        uint64_t entry_generation;
        uint8_t operation;
        uint8_t duplicate;
        uint8_t reserved8[6];
    } RegistrydMutationResult;

    typedef struct RegistrydStoredValue
    {
        uint64_t entry_generation;
        uint32_t value_type;
        uint32_t value_size;
        uint8_t value[REGISTRYD_STORE_MAX_VALUE_BYTES];
    } RegistrydStoredValue;

    typedef struct RegistrydStoreInspection
    {
        uint64_t commit_sequence;
        uint64_t last_entry_generation;
        uint32_t entry_count;
        uint32_t client_count;
        uint8_t has_pending_mutation;
        uint8_t reserved8[7];
    } RegistrydStoreInspection;

    typedef struct RegistrydRecoveryResult
    {
        uint64_t commit_sequence;
        uint64_t last_entry_generation;
        uint32_t snapshot_entries;
        uint32_t wal_records;
        uint32_t wal_bytes_consumed;
        uint32_t wal_bytes_ignored;
        uint8_t torn_wal_tail;
        uint8_t reserved8[7];
    } RegistrydRecoveryResult;

    /* [registryd actor thread] Storage must be entirely zero on first init. */
    RegistrydStoreStatus RegistrydStoreInitialize(RegistrydStore* store);

    /* [registryd actor thread] Copies a committed value; no internal pointer escapes. */
    RegistrydStoreStatus RegistrydStoreQuery(const RegistrydStore* store, const char* key, uint32_t key_size,
                                             const char* name, uint32_t name_size, RegistrydStoredValue* out_value);

    /*
     * [registryd actor thread] Copy-once validation and WAL preparation.
     * REGISTRYD_STORE_DUPLICATE_REQUEST returns the durable prior result and
     * emits zero WAL bytes.  Other replay/conflict statuses emit no bytes.
     */
    RegistrydStoreStatus RegistrydStorePrepareMutation(RegistrydStore* store, const RegistrydMutation* mutation,
                                                       uint8_t* wal_out, uint32_t wal_capacity, uint32_t* out_wal_size,
                                                       RegistrydPreparedMutation* out_prepared,
                                                       RegistrydMutationResult* out_result);

    /* [registryd actor thread] Call only after the exact prepared WAL is durable. */
    RegistrydStoreStatus RegistrydStoreCommitMutation(RegistrydStore* store, const RegistrydPreparedMutation* prepared,
                                                      RegistrydMutationResult* out_result);

    /* [registryd actor thread] Legal only when prepared WAL bytes are not durable. */
    RegistrydStoreStatus RegistrydStoreAbortMutation(RegistrydStore* store, const RegistrydPreparedMutation* prepared);

    /* [registryd actor thread] Pending state is rejected; output is canonical little-endian v1. */
    RegistrydStoreStatus RegistrydStoreEncodeSnapshot(const RegistrydStore* store, uint8_t* out, uint32_t capacity,
                                                      uint32_t* out_size);

    /*
     * [registryd startup actor] Recover into entirely-zero storage.  Snapshot
     * damage and complete-record WAL damage clear the destination and fail.
     * A physically truncated final WAL record is ignored explicitly and
     * returns REGISTRYD_STORE_RECOVERED_TORN_WAL with the valid prefix live.
     */
    RegistrydStoreStatus RegistrydStoreRecover(RegistrydStore* store, const uint8_t* snapshot, uint32_t snapshot_size,
                                               const uint8_t* wal, uint32_t wal_size,
                                               RegistrydRecoveryResult* out_result);

    /* [registryd actor thread] Exact committed-state diagnostics. */
    RegistrydStoreStatus RegistrydStoreInspect(const RegistrydStore* store, RegistrydStoreInspection* out);

    const char* RegistrydStoreStatusName(RegistrydStoreStatus status);

#ifdef __cplusplus
}
#endif

#endif
