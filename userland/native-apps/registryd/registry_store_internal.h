#ifndef DUETOS_REGISTRYD_STORE_INTERNAL_H
#define DUETOS_REGISTRYD_STORE_INTERNAL_H

#include "registry_store.h"

#define REGISTRYD_STATE_MAGIC UINT64_C(0x5245474453543031)
#define REGISTRYD_SNAPSHOT_MAGIC UINT64_C(0x313050414E534452)
#define REGISTRYD_WAL_MAGIC UINT64_C(0x3130304C41574452)
#define REGISTRYD_FORMAT_VERSION 1U
#define REGISTRYD_SNAPSHOT_HEADER_SIZE 64U
#define REGISTRYD_ENTRY_HEADER_SIZE 40U
#define REGISTRYD_CLIENT_HEADER_SIZE 80U
#define REGISTRYD_WAL_HEADER_SIZE 96U
#define REGISTRYD_SNAPSHOT_ENTRY_KIND 1U
#define REGISTRYD_SNAPSHOT_CLIENT_KIND 2U

typedef struct RegistrydCanonicalMutation
{
    uint64_t client_identity;
    uint64_t request_id;
    uint64_t expected_entry_generation;
    uint64_t fingerprint;
    uint32_t value_type;
    uint16_t key_size;
    uint16_t name_size;
    uint16_t value_size;
    uint8_t operation;
    uint8_t reserved8;
    char key[REGISTRYD_STORE_MAX_KEY_BYTES + 1U];
    char name[REGISTRYD_STORE_MAX_NAME_BYTES + 1U];
    uint8_t value[REGISTRYD_STORE_MAX_VALUE_BYTES];
} RegistrydCanonicalMutation;

typedef struct RegistrydSnapshotEntry
{
    uint64_t entry_generation;
    uint32_t value_type;
    uint16_t key_size;
    uint16_t name_size;
    uint16_t value_size;
    uint8_t active;
    uint8_t reserved8;
    char key[REGISTRYD_STORE_MAX_KEY_BYTES + 1U];
    char name[REGISTRYD_STORE_MAX_NAME_BYTES + 1U];
    uint8_t value[REGISTRYD_STORE_MAX_VALUE_BYTES];
} RegistrydSnapshotEntry;

typedef struct RegistrydSnapshotClient
{
    uint64_t commit_sequence;
    uint64_t entry_generation;
    uint8_t active;
    uint8_t reserved8[7];
    RegistrydCanonicalMutation mutation;
} RegistrydSnapshotClient;

typedef struct RegistrydPendingMutation
{
    uint64_t preparation_generation;
    uint64_t commit_sequence;
    uint64_t entry_generation;
    uint8_t active;
    uint8_t reserved8[7];
    RegistrydCanonicalMutation mutation;
} RegistrydPendingMutation;

typedef struct RegistrydStoreState
{
    uint64_t magic;
    uint64_t commit_sequence;
    uint64_t last_entry_generation;
    uint64_t preparation_generation;
    uint32_t entry_count;
    uint32_t client_count;
    RegistrydPendingMutation pending;
    RegistrydSnapshotEntry entries[REGISTRYD_STORE_MAX_ENTRIES];
    RegistrydSnapshotClient clients[REGISTRYD_STORE_MAX_CLIENTS];
} RegistrydStoreState;

_Static_assert(sizeof(RegistrydStoreState) <= REGISTRYD_STORE_STORAGE_BYTES, "registryd store storage is too small");
_Static_assert(_Alignof(RegistrydStoreState) <= _Alignof(RegistrydStore), "registryd store alignment is too small");

RegistrydStoreState* RegistrydStoreInternalState(RegistrydStore* store);
const RegistrydStoreState* RegistrydStoreInternalConstState(const RegistrydStore* store);
void RegistrydStoreInternalZero(void* destination, size_t size);
void RegistrydStoreInternalCopy(void* destination, const void* source, size_t size);
int RegistrydStoreInternalEqual(const void* left, const void* right, size_t size);
int RegistrydStoreInternalRangesOverlap(const void* first, size_t first_size, const void* second, size_t second_size);
int RegistrydStoreInternalStateIsSane(const RegistrydStoreState* state);
uint32_t RegistrydStoreInternalFindEntry(const RegistrydStoreState* state, const RegistrydCanonicalMutation* mutation);
uint32_t RegistrydStoreInternalFindFreeEntry(const RegistrydStoreState* state);
uint32_t RegistrydStoreInternalFindClient(const RegistrydStoreState* state, uint64_t identity);
uint32_t RegistrydStoreInternalFindFreeClient(const RegistrydStoreState* state);
RegistrydStoreStatus RegistrydStoreInternalCheckRequest(const RegistrydStoreState* state,
                                                        const RegistrydCanonicalMutation* mutation,
                                                        RegistrydMutationResult* out_result);
RegistrydStoreStatus RegistrydStoreInternalCheckExpected(const RegistrydStoreState* state,
                                                         const RegistrydCanonicalMutation* mutation);
RegistrydStoreStatus RegistrydStoreInternalApply(RegistrydStoreState* state, const RegistrydCanonicalMutation* mutation,
                                                 uint64_t commit_sequence, uint64_t entry_generation);

RegistrydStoreStatus RegistrydStoreInternalCanonicalize(const RegistrydMutation* input,
                                                        RegistrydCanonicalMutation* output);
RegistrydStoreStatus RegistrydStoreInternalNormalizeKey(const char* input, uint32_t size, char* output,
                                                        uint16_t* out_size);
RegistrydStoreStatus RegistrydStoreInternalNormalizeName(const char* input, uint32_t size, char* output,
                                                         uint16_t* out_size);
int RegistrydStoreInternalCanonicalIsValid(const RegistrydCanonicalMutation* mutation);
int RegistrydStoreInternalMutationIsExact(const RegistrydCanonicalMutation* left,
                                          const RegistrydCanonicalMutation* right);
int RegistrydStoreInternalEntryIsValid(const RegistrydSnapshotEntry* entry, uint64_t last_generation);
uint64_t RegistrydStoreInternalFingerprint(const RegistrydCanonicalMutation* mutation);

RegistrydStoreStatus RegistrydStoreInternalEncodeWal(const RegistrydCanonicalMutation* mutation,
                                                     uint64_t commit_sequence, uint64_t previous_sequence,
                                                     uint64_t entry_generation, uint8_t* out, uint32_t capacity,
                                                     uint32_t* out_size);

RegistrydStoreStatus RegistrydStoreInternalSnapshotInfo(const RegistrydStore* store, RegistrydStoreInspection* out);
RegistrydStoreStatus RegistrydStoreInternalEntryAt(const RegistrydStore* store, uint32_t slot,
                                                   RegistrydSnapshotEntry* out);
RegistrydStoreStatus RegistrydStoreInternalClientAt(const RegistrydStore* store, uint32_t slot,
                                                    RegistrydSnapshotClient* out);
RegistrydStoreStatus RegistrydStoreInternalRecoverBegin(RegistrydStore* store, uint64_t commit_sequence,
                                                        uint64_t last_entry_generation);
RegistrydStoreStatus RegistrydStoreInternalRecoverEntry(RegistrydStore* store, const RegistrydSnapshotEntry* entry);
RegistrydStoreStatus RegistrydStoreInternalRecoverClient(RegistrydStore* store, const RegistrydSnapshotClient* client);
RegistrydStoreStatus RegistrydStoreInternalReplay(RegistrydStore* store, const RegistrydCanonicalMutation* mutation,
                                                  uint64_t sequence, uint64_t previous_sequence,
                                                  uint64_t entry_generation);
RegistrydStoreStatus RegistrydStoreInternalRecoverFinish(RegistrydStore* store, uint32_t expected_entries,
                                                         uint32_t expected_clients);
void RegistrydStoreInternalFailClosed(RegistrydStore* store);

#endif
