#include "registry_store_internal.h"

#include <limits.h>

static RegistrydStoreState* State(RegistrydStore* store)
{
    return (RegistrydStoreState*)(void*)store->bytes;
}

static const RegistrydStoreState* ConstState(const RegistrydStore* store)
{
    return (const RegistrydStoreState*)(const void*)store->bytes;
}

static void BytesZero(void* destination, size_t size)
{
    uint8_t* bytes = (uint8_t*)destination;
    size_t index;
    for (index = 0; index < size; ++index)
    {
        bytes[index] = 0;
    }
}

static void BytesCopy(void* destination, const void* source, size_t size)
{
    uint8_t* output = (uint8_t*)destination;
    const uint8_t* input = (const uint8_t*)source;
    size_t index;
    for (index = 0; index < size; ++index)
    {
        output[index] = input[index];
    }
}

static int BytesEqual(const void* left, const void* right, size_t size)
{
    const uint8_t* lhs = (const uint8_t*)left;
    const uint8_t* rhs = (const uint8_t*)right;
    size_t index;
    for (index = 0; index < size; ++index)
    {
        if (lhs[index] != rhs[index])
        {
            return 0;
        }
    }
    return 1;
}

static int StorageIsZero(const RegistrydStore* store)
{
    uint32_t index;
    for (index = 0; index < REGISTRYD_STORE_STORAGE_BYTES; ++index)
    {
        if (store->bytes[index] != 0U)
        {
            return 0;
        }
    }
    return 1;
}

static int StorageOverlaps(const RegistrydStore* store, const void* other, size_t size)
{
    const uintptr_t store_start = (uintptr_t)store;
    const uintptr_t other_start = (uintptr_t)other;
    const uintptr_t store_end = store_start + sizeof(*store);
    const uintptr_t other_end = other_start + size;
    return size != 0U &&
           (store_end < store_start || other_end < other_start || (store_start < other_end && other_start < store_end));
}

static int EntryKeyEqual(const RegistrydSnapshotEntry* entry, const RegistrydCanonicalMutation* mutation)
{
    return entry->active && entry->key_size == mutation->key_size && entry->name_size == mutation->name_size &&
           BytesEqual(entry->key, mutation->key, entry->key_size) &&
           BytesEqual(entry->name, mutation->name, entry->name_size);
}

static uint32_t FindEntry(const RegistrydStoreState* state, const RegistrydCanonicalMutation* mutation)
{
    uint32_t slot;
    for (slot = 0; slot < REGISTRYD_STORE_MAX_ENTRIES; ++slot)
    {
        if (EntryKeyEqual(&state->entries[slot], mutation))
        {
            return slot;
        }
    }
    return UINT32_MAX;
}

static uint32_t FindFreeEntry(const RegistrydStoreState* state)
{
    uint32_t slot;
    for (slot = 0; slot < REGISTRYD_STORE_MAX_ENTRIES; ++slot)
    {
        if (!state->entries[slot].active)
        {
            return slot;
        }
    }
    return UINT32_MAX;
}

static uint32_t FindClient(const RegistrydStoreState* state, uint64_t identity)
{
    uint32_t slot;
    for (slot = 0; slot < REGISTRYD_STORE_MAX_CLIENTS; ++slot)
    {
        if (state->clients[slot].active && state->clients[slot].mutation.client_identity == identity)
        {
            return slot;
        }
    }
    return UINT32_MAX;
}

static uint32_t FindFreeClient(const RegistrydStoreState* state)
{
    uint32_t slot;
    for (slot = 0; slot < REGISTRYD_STORE_MAX_CLIENTS; ++slot)
    {
        if (!state->clients[slot].active)
        {
            return slot;
        }
    }
    return UINT32_MAX;
}

static int StateIsSane(const RegistrydStoreState* state)
{
    uint32_t entries = 0;
    uint32_t clients = 0;
    uint32_t slot;
    if (state->magic != REGISTRYD_STATE_MAGIC || state->entry_count > REGISTRYD_STORE_MAX_ENTRIES ||
        state->client_count > REGISTRYD_STORE_MAX_CLIENTS || state->pending.active > 1U)
    {
        return 0;
    }
    for (slot = 0; slot < REGISTRYD_STORE_MAX_ENTRIES; ++slot)
    {
        if (state->entries[slot].active)
        {
            uint32_t prior;
            if (!RegistrydStoreInternalEntryIsValid(&state->entries[slot], state->last_entry_generation))
            {
                return 0;
            }
            for (prior = 0; prior < slot; ++prior)
            {
                const RegistrydSnapshotEntry* left = &state->entries[prior];
                const RegistrydSnapshotEntry* right = &state->entries[slot];
                if (left->active && (left->entry_generation == right->entry_generation ||
                                     (left->key_size == right->key_size && left->name_size == right->name_size &&
                                      BytesEqual(left->key, right->key, left->key_size) &&
                                      BytesEqual(left->name, right->name, left->name_size))))
                {
                    return 0;
                }
            }
            ++entries;
        }
    }
    for (slot = 0; slot < REGISTRYD_STORE_MAX_CLIENTS; ++slot)
    {
        if (state->clients[slot].active)
        {
            const RegistrydSnapshotClient* client = &state->clients[slot];
            uint32_t prior;
            if (!RegistrydStoreInternalCanonicalIsValid(&client->mutation) || client->commit_sequence == 0U ||
                client->commit_sequence > state->commit_sequence || client->entry_generation == 0U ||
                client->entry_generation > state->last_entry_generation)
            {
                return 0;
            }
            for (prior = 0; prior < slot; ++prior)
            {
                if (state->clients[prior].active &&
                    state->clients[prior].mutation.client_identity == client->mutation.client_identity)
                {
                    return 0;
                }
            }
            ++clients;
        }
    }
    return entries == state->entry_count && clients == state->client_count &&
           (!state->pending.active ||
            (RegistrydStoreInternalCanonicalIsValid(&state->pending.mutation) &&
             state->pending.preparation_generation == state->preparation_generation &&
             state->commit_sequence != UINT64_MAX && state->pending.commit_sequence == state->commit_sequence + 1U &&
             state->last_entry_generation != UINT64_MAX &&
             state->pending.entry_generation == state->last_entry_generation + 1U));
}

static RegistrydStoreStatus CheckRequest(const RegistrydStoreState* state, const RegistrydCanonicalMutation* mutation,
                                         RegistrydMutationResult* out_result)
{
    const uint32_t client_slot = FindClient(state, mutation->client_identity);
    if (client_slot == UINT32_MAX)
    {
        return state->client_count == REGISTRYD_STORE_MAX_CLIENTS ? REGISTRYD_STORE_CLIENT_CAPACITY
                                                                  : REGISTRYD_STORE_OK;
    }
    {
        const RegistrydSnapshotClient* prior = &state->clients[client_slot];
        if (mutation->request_id < prior->mutation.request_id)
        {
            return REGISTRYD_STORE_REPLAYED_REQUEST;
        }
        if (mutation->request_id == prior->mutation.request_id)
        {
            if (!RegistrydStoreInternalMutationIsExact(mutation, &prior->mutation))
            {
                return REGISTRYD_STORE_REQUEST_ID_CONFLICT;
            }
            out_result->commit_sequence = prior->commit_sequence;
            out_result->entry_generation = prior->entry_generation;
            out_result->operation = prior->mutation.operation;
            out_result->duplicate = 1U;
            return REGISTRYD_STORE_DUPLICATE_REQUEST;
        }
        if (prior->mutation.request_id == UINT64_MAX)
        {
            return REGISTRYD_STORE_REQUEST_ID_EXHAUSTED;
        }
    }
    return REGISTRYD_STORE_OK;
}

static RegistrydStoreStatus CheckExpectedVersion(const RegistrydStoreState* state,
                                                 const RegistrydCanonicalMutation* mutation)
{
    const uint32_t entry_slot = FindEntry(state, mutation);
    if (mutation->operation == REGISTRYD_MUTATION_SET)
    {
        if (entry_slot == UINT32_MAX)
        {
            if (mutation->expected_entry_generation != 0U)
            {
                return REGISTRYD_STORE_VERSION_CONFLICT;
            }
            return state->entry_count == REGISTRYD_STORE_MAX_ENTRIES ? REGISTRYD_STORE_CAPACITY : REGISTRYD_STORE_OK;
        }
    }
    else if (entry_slot == UINT32_MAX)
    {
        return REGISTRYD_STORE_NOT_FOUND;
    }
    return state->entries[entry_slot].entry_generation == mutation->expected_entry_generation
               ? REGISTRYD_STORE_OK
               : REGISTRYD_STORE_VERSION_CONFLICT;
}

static RegistrydStoreStatus ApplyMutation(RegistrydStoreState* state, const RegistrydCanonicalMutation* mutation,
                                          uint64_t commit_sequence, uint64_t entry_generation)
{
    uint32_t entry_slot = FindEntry(state, mutation);
    uint32_t client_slot = FindClient(state, mutation->client_identity);
    if (CheckExpectedVersion(state, mutation) != REGISTRYD_STORE_OK)
    {
        return REGISTRYD_STORE_CORRUPT_STATE;
    }
    if (mutation->operation == REGISTRYD_MUTATION_SET)
    {
        RegistrydSnapshotEntry* entry;
        if (entry_slot == UINT32_MAX)
        {
            entry_slot = FindFreeEntry(state);
            if (entry_slot == UINT32_MAX)
            {
                return REGISTRYD_STORE_CORRUPT_STATE;
            }
            ++state->entry_count;
        }
        entry = &state->entries[entry_slot];
        BytesZero(entry, sizeof(*entry));
        entry->entry_generation = entry_generation;
        entry->value_type = mutation->value_type;
        entry->key_size = mutation->key_size;
        entry->name_size = mutation->name_size;
        entry->value_size = mutation->value_size;
        BytesCopy(entry->key, mutation->key, mutation->key_size + 1U);
        BytesCopy(entry->name, mutation->name, mutation->name_size + 1U);
        BytesCopy(entry->value, mutation->value, mutation->value_size);
        entry->active = 1U;
    }
    else
    {
        BytesZero(&state->entries[entry_slot], sizeof(state->entries[entry_slot]));
        --state->entry_count;
    }
    if (client_slot == UINT32_MAX)
    {
        client_slot = FindFreeClient(state);
        if (client_slot == UINT32_MAX)
        {
            return REGISTRYD_STORE_CORRUPT_STATE;
        }
        ++state->client_count;
    }
    BytesZero(&state->clients[client_slot], sizeof(state->clients[client_slot]));
    state->clients[client_slot].commit_sequence = commit_sequence;
    state->clients[client_slot].entry_generation = entry_generation;
    state->clients[client_slot].mutation = *mutation;
    state->clients[client_slot].active = 1U;
    state->commit_sequence = commit_sequence;
    state->last_entry_generation = entry_generation;
    return REGISTRYD_STORE_OK;
}

RegistrydStoreState* RegistrydStoreInternalState(RegistrydStore* store)
{
    return State(store);
}

const RegistrydStoreState* RegistrydStoreInternalConstState(const RegistrydStore* store)
{
    return ConstState(store);
}

void RegistrydStoreInternalZero(void* destination, size_t size)
{
    BytesZero(destination, size);
}

void RegistrydStoreInternalCopy(void* destination, const void* source, size_t size)
{
    BytesCopy(destination, source, size);
}

int RegistrydStoreInternalEqual(const void* left, const void* right, size_t size)
{
    return BytesEqual(left, right, size);
}

int RegistrydStoreInternalRangesOverlap(const void* first, size_t first_size, const void* second, size_t second_size)
{
    const uintptr_t first_start = (uintptr_t)first;
    const uintptr_t second_start = (uintptr_t)second;
    const uintptr_t first_end = first_start + first_size;
    const uintptr_t second_end = second_start + second_size;
    return first_end < first_start || second_end < second_start ||
           (first_size != 0U && second_size != 0U && first_start < second_end && second_start < first_end);
}

int RegistrydStoreInternalStateIsSane(const RegistrydStoreState* state)
{
    return StateIsSane(state);
}

uint32_t RegistrydStoreInternalFindEntry(const RegistrydStoreState* state, const RegistrydCanonicalMutation* mutation)
{
    return FindEntry(state, mutation);
}

uint32_t RegistrydStoreInternalFindFreeEntry(const RegistrydStoreState* state)
{
    return FindFreeEntry(state);
}

uint32_t RegistrydStoreInternalFindClient(const RegistrydStoreState* state, uint64_t identity)
{
    return FindClient(state, identity);
}

uint32_t RegistrydStoreInternalFindFreeClient(const RegistrydStoreState* state)
{
    return FindFreeClient(state);
}

RegistrydStoreStatus RegistrydStoreInternalCheckRequest(const RegistrydStoreState* state,
                                                        const RegistrydCanonicalMutation* mutation,
                                                        RegistrydMutationResult* out_result)
{
    return CheckRequest(state, mutation, out_result);
}

RegistrydStoreStatus RegistrydStoreInternalCheckExpected(const RegistrydStoreState* state,
                                                         const RegistrydCanonicalMutation* mutation)
{
    return CheckExpectedVersion(state, mutation);
}

RegistrydStoreStatus RegistrydStoreInternalApply(RegistrydStoreState* state, const RegistrydCanonicalMutation* mutation,
                                                 uint64_t commit_sequence, uint64_t entry_generation)
{
    return ApplyMutation(state, mutation, commit_sequence, entry_generation);
}

RegistrydStoreStatus RegistrydStoreInitialize(RegistrydStore* store)
{
    RegistrydStoreState* state;
    if (store == NULL)
    {
        return REGISTRYD_STORE_NULL_ARGUMENT;
    }
    state = State(store);
    if (state->magic == REGISTRYD_STATE_MAGIC)
    {
        return REGISTRYD_STORE_ALREADY_INITIALIZED;
    }
    if (!StorageIsZero(store))
    {
        return REGISTRYD_STORE_CORRUPT_STATE;
    }
    state->magic = REGISTRYD_STATE_MAGIC;
    return REGISTRYD_STORE_OK;
}

RegistrydStoreStatus RegistrydStoreQuery(const RegistrydStore* store, const char* key, uint32_t key_size,
                                         const char* name, uint32_t name_size, RegistrydStoredValue* out_value)
{
    RegistrydCanonicalMutation lookup;
    const RegistrydStoreState* state;
    RegistrydStoreStatus status;
    uint32_t slot;
    if (store == NULL || out_value == NULL)
    {
        return REGISTRYD_STORE_NULL_ARGUMENT;
    }
    if (StorageOverlaps(store, out_value, sizeof(*out_value)))
    {
        return REGISTRYD_STORE_ALIASED_STORAGE;
    }
    state = ConstState(store);
    if (!StateIsSane(state))
    {
        return state->magic == REGISTRYD_STATE_MAGIC ? REGISTRYD_STORE_CORRUPT_STATE : REGISTRYD_STORE_NOT_INITIALIZED;
    }
    BytesZero(&lookup, sizeof(lookup));
    status = RegistrydStoreInternalNormalizeKey(key, key_size, lookup.key, &lookup.key_size);
    if (status != REGISTRYD_STORE_OK)
    {
        return status;
    }
    status = RegistrydStoreInternalNormalizeName(name, name_size, lookup.name, &lookup.name_size);
    if (status != REGISTRYD_STORE_OK)
    {
        return status;
    }
    slot = FindEntry(state, &lookup);
    if (slot == UINT32_MAX)
    {
        return REGISTRYD_STORE_NOT_FOUND;
    }
    BytesZero(out_value, sizeof(*out_value));
    out_value->entry_generation = state->entries[slot].entry_generation;
    out_value->value_type = state->entries[slot].value_type;
    out_value->value_size = state->entries[slot].value_size;
    BytesCopy(out_value->value, state->entries[slot].value, out_value->value_size);
    return REGISTRYD_STORE_OK;
}

RegistrydStoreStatus RegistrydStorePrepareMutation(RegistrydStore* store, const RegistrydMutation* mutation,
                                                   uint8_t* wal_out, uint32_t wal_capacity, uint32_t* out_wal_size,
                                                   RegistrydPreparedMutation* out_prepared,
                                                   RegistrydMutationResult* out_result)
{
    RegistrydCanonicalMutation candidate;
    RegistrydStoreState* state;
    RegistrydStoreStatus status;
    uint64_t next_commit;
    uint64_t next_entry;
    uint64_t next_preparation;
    if (store == NULL || mutation == NULL || wal_out == NULL || out_wal_size == NULL || out_prepared == NULL ||
        out_result == NULL)
    {
        return REGISTRYD_STORE_NULL_ARGUMENT;
    }
    if (StorageOverlaps(store, wal_out, wal_capacity) || StorageOverlaps(store, out_wal_size, sizeof(*out_wal_size)) ||
        StorageOverlaps(store, out_prepared, sizeof(*out_prepared)) ||
        StorageOverlaps(store, out_result, sizeof(*out_result)))
    {
        return REGISTRYD_STORE_ALIASED_STORAGE;
    }
    *out_wal_size = 0U;
    BytesZero(out_prepared, sizeof(*out_prepared));
    BytesZero(out_result, sizeof(*out_result));
    state = State(store);
    if (!StateIsSane(state))
    {
        return state->magic == REGISTRYD_STATE_MAGIC ? REGISTRYD_STORE_CORRUPT_STATE : REGISTRYD_STORE_NOT_INITIALIZED;
    }
    if (state->pending.active)
    {
        return REGISTRYD_STORE_PENDING_MUTATION;
    }
    status = RegistrydStoreInternalCanonicalize(mutation, &candidate);
    if (status != REGISTRYD_STORE_OK)
    {
        return status;
    }
    status = CheckRequest(state, &candidate, out_result);
    if (status != REGISTRYD_STORE_OK)
    {
        return status;
    }
    status = CheckExpectedVersion(state, &candidate);
    if (status != REGISTRYD_STORE_OK)
    {
        return status;
    }
    if (state->commit_sequence == UINT64_MAX || state->last_entry_generation == UINT64_MAX ||
        state->preparation_generation == UINT64_MAX)
    {
        return REGISTRYD_STORE_GENERATION_EXHAUSTED;
    }
    next_commit = state->commit_sequence + 1U;
    next_entry = state->last_entry_generation + 1U;
    next_preparation = state->preparation_generation + 1U;
    status = RegistrydStoreInternalEncodeWal(&candidate, next_commit, state->commit_sequence, next_entry, wal_out,
                                             wal_capacity, out_wal_size);
    if (status != REGISTRYD_STORE_OK)
    {
        return status;
    }
    BytesZero(&state->pending, sizeof(state->pending));
    state->pending.preparation_generation = next_preparation;
    state->pending.commit_sequence = next_commit;
    state->pending.entry_generation = next_entry;
    state->pending.mutation = candidate;
    state->pending.active = 1U;
    state->preparation_generation = next_preparation;
    out_prepared->preparation_generation = next_preparation;
    out_prepared->commit_sequence = next_commit;
    out_prepared->entry_generation = next_entry;
    out_prepared->fingerprint = candidate.fingerprint;
    out_result->commit_sequence = next_commit;
    out_result->entry_generation = next_entry;
    out_result->operation = candidate.operation;
    return REGISTRYD_STORE_OK;
}

static int PreparedMatches(const RegistrydPendingMutation* pending, const RegistrydPreparedMutation* prepared)
{
    return pending->active && pending->preparation_generation == prepared->preparation_generation &&
           pending->commit_sequence == prepared->commit_sequence &&
           pending->entry_generation == prepared->entry_generation &&
           pending->mutation.fingerprint == prepared->fingerprint;
}

RegistrydStoreStatus RegistrydStoreCommitMutation(RegistrydStore* store, const RegistrydPreparedMutation* prepared,
                                                  RegistrydMutationResult* out_result)
{
    RegistrydStoreState* state;
    RegistrydStoreStatus status;
    if (store == NULL || prepared == NULL || out_result == NULL)
    {
        return REGISTRYD_STORE_NULL_ARGUMENT;
    }
    if (StorageOverlaps(store, out_result, sizeof(*out_result)))
    {
        return REGISTRYD_STORE_ALIASED_STORAGE;
    }
    state = State(store);
    if (!StateIsSane(state))
    {
        return state->magic == REGISTRYD_STATE_MAGIC ? REGISTRYD_STORE_CORRUPT_STATE : REGISTRYD_STORE_NOT_INITIALIZED;
    }
    if (!state->pending.active)
    {
        return REGISTRYD_STORE_NO_PENDING_MUTATION;
    }
    if (!PreparedMatches(&state->pending, prepared))
    {
        return REGISTRYD_STORE_STALE_PREPARATION;
    }
    status =
        ApplyMutation(state, &state->pending.mutation, state->pending.commit_sequence, state->pending.entry_generation);
    if (status != REGISTRYD_STORE_OK)
    {
        /* ApplyMutation only fails past a point where it may already have
         * touched the entries/clients tables (defensively unreachable given
         * the capacity checks Prepare/Replay already ran, but not provably
         * so from this call site) -- fail closed rather than leave a
         * partially-mutated store live under a still-recoverable status. */
        RegistrydStoreInternalFailClosed(store);
        return status;
    }
    BytesZero(out_result, sizeof(*out_result));
    out_result->commit_sequence = state->pending.commit_sequence;
    out_result->entry_generation = state->pending.entry_generation;
    out_result->operation = state->pending.mutation.operation;
    BytesZero(&state->pending, sizeof(state->pending));
    if (!StateIsSane(state))
    {
        RegistrydStoreInternalFailClosed(store);
        return REGISTRYD_STORE_CORRUPT_STATE;
    }
    return REGISTRYD_STORE_OK;
}

RegistrydStoreStatus RegistrydStoreAbortMutation(RegistrydStore* store, const RegistrydPreparedMutation* prepared)
{
    RegistrydStoreState* state;
    if (store == NULL || prepared == NULL)
    {
        return REGISTRYD_STORE_NULL_ARGUMENT;
    }
    state = State(store);
    if (!StateIsSane(state))
    {
        return state->magic == REGISTRYD_STATE_MAGIC ? REGISTRYD_STORE_CORRUPT_STATE : REGISTRYD_STORE_NOT_INITIALIZED;
    }
    if (!state->pending.active)
    {
        return REGISTRYD_STORE_NO_PENDING_MUTATION;
    }
    if (!PreparedMatches(&state->pending, prepared))
    {
        return REGISTRYD_STORE_STALE_PREPARATION;
    }
    BytesZero(&state->pending, sizeof(state->pending));
    return REGISTRYD_STORE_OK;
}

RegistrydStoreStatus RegistrydStoreInspect(const RegistrydStore* store, RegistrydStoreInspection* out)
{
    const RegistrydStoreState* state;
    if (store == NULL || out == NULL)
    {
        return REGISTRYD_STORE_NULL_ARGUMENT;
    }
    if (StorageOverlaps(store, out, sizeof(*out)))
    {
        return REGISTRYD_STORE_ALIASED_STORAGE;
    }
    state = ConstState(store);
    if (!StateIsSane(state))
    {
        return state->magic == REGISTRYD_STATE_MAGIC ? REGISTRYD_STORE_CORRUPT_STATE : REGISTRYD_STORE_NOT_INITIALIZED;
    }
    BytesZero(out, sizeof(*out));
    out->commit_sequence = state->commit_sequence;
    out->last_entry_generation = state->last_entry_generation;
    out->entry_count = state->entry_count;
    out->client_count = state->client_count;
    out->has_pending_mutation = state->pending.active;
    return REGISTRYD_STORE_OK;
}

RegistrydStoreStatus RegistrydStoreInternalSnapshotInfo(const RegistrydStore* store, RegistrydStoreInspection* out)
{
    return RegistrydStoreInspect(store, out);
}

RegistrydStoreStatus RegistrydStoreInternalEntryAt(const RegistrydStore* store, uint32_t slot,
                                                   RegistrydSnapshotEntry* out)
{
    const RegistrydStoreState* state;
    if (store == NULL || out == NULL || slot >= REGISTRYD_STORE_MAX_ENTRIES)
    {
        return REGISTRYD_STORE_NULL_ARGUMENT;
    }
    state = ConstState(store);
    if (!StateIsSane(state))
    {
        return REGISTRYD_STORE_CORRUPT_STATE;
    }
    *out = state->entries[slot];
    return REGISTRYD_STORE_OK;
}

RegistrydStoreStatus RegistrydStoreInternalClientAt(const RegistrydStore* store, uint32_t slot,
                                                    RegistrydSnapshotClient* out)
{
    const RegistrydStoreState* state;
    if (store == NULL || out == NULL || slot >= REGISTRYD_STORE_MAX_CLIENTS)
    {
        return REGISTRYD_STORE_NULL_ARGUMENT;
    }
    state = ConstState(store);
    if (!StateIsSane(state))
    {
        return REGISTRYD_STORE_CORRUPT_STATE;
    }
    *out = state->clients[slot];
    return REGISTRYD_STORE_OK;
}
