#include "registry_store_internal.h"

#include <limits.h>

RegistrydStoreStatus RegistrydStoreInternalRecoverBegin(RegistrydStore* store, uint64_t commit_sequence,
                                                        uint64_t last_entry_generation)
{
    RegistrydStoreState* state;
    RegistrydStoreStatus status = RegistrydStoreInitialize(store);
    if (status != REGISTRYD_STORE_OK)
    {
        return status;
    }
    state = RegistrydStoreInternalState(store);
    state->commit_sequence = commit_sequence;
    state->last_entry_generation = last_entry_generation;
    return REGISTRYD_STORE_OK;
}

RegistrydStoreStatus RegistrydStoreInternalRecoverEntry(RegistrydStore* store, const RegistrydSnapshotEntry* entry)
{
    RegistrydStoreState* state;
    RegistrydCanonicalMutation lookup;
    uint32_t slot;
    if (store == NULL || entry == NULL)
    {
        return REGISTRYD_STORE_NULL_ARGUMENT;
    }
    state = RegistrydStoreInternalState(store);
    if (!RegistrydStoreInternalStateIsSane(state) ||
        !RegistrydStoreInternalEntryIsValid(entry, state->last_entry_generation) ||
        state->entry_count == REGISTRYD_STORE_MAX_ENTRIES)
    {
        return REGISTRYD_STORE_CORRUPT_SNAPSHOT;
    }
    RegistrydStoreInternalZero(&lookup, sizeof(lookup));
    lookup.key_size = entry->key_size;
    lookup.name_size = entry->name_size;
    RegistrydStoreInternalCopy(lookup.key, entry->key, entry->key_size + 1U);
    RegistrydStoreInternalCopy(lookup.name, entry->name, entry->name_size + 1U);
    if (RegistrydStoreInternalFindEntry(state, &lookup) != UINT32_MAX)
    {
        return REGISTRYD_STORE_CORRUPT_SNAPSHOT;
    }
    for (slot = 0; slot < REGISTRYD_STORE_MAX_ENTRIES; ++slot)
    {
        if (state->entries[slot].active && state->entries[slot].entry_generation == entry->entry_generation)
        {
            return REGISTRYD_STORE_CORRUPT_SNAPSHOT;
        }
    }
    slot = RegistrydStoreInternalFindFreeEntry(state);
    state->entries[slot] = *entry;
    ++state->entry_count;
    return REGISTRYD_STORE_OK;
}

RegistrydStoreStatus RegistrydStoreInternalRecoverClient(RegistrydStore* store, const RegistrydSnapshotClient* client)
{
    RegistrydStoreState* state;
    uint32_t slot;
    if (store == NULL || client == NULL)
    {
        return REGISTRYD_STORE_NULL_ARGUMENT;
    }
    state = RegistrydStoreInternalState(store);
    if (!RegistrydStoreInternalStateIsSane(state) || client->active != 1U ||
        !RegistrydStoreInternalCanonicalIsValid(&client->mutation) || client->commit_sequence == 0U ||
        client->commit_sequence > state->commit_sequence || client->entry_generation == 0U ||
        client->entry_generation > state->last_entry_generation || state->client_count == REGISTRYD_STORE_MAX_CLIENTS ||
        RegistrydStoreInternalFindClient(state, client->mutation.client_identity) != UINT32_MAX)
    {
        return REGISTRYD_STORE_CORRUPT_SNAPSHOT;
    }
    slot = RegistrydStoreInternalFindFreeClient(state);
    state->clients[slot] = *client;
    ++state->client_count;
    return REGISTRYD_STORE_OK;
}

RegistrydStoreStatus RegistrydStoreInternalReplay(RegistrydStore* store, const RegistrydCanonicalMutation* mutation,
                                                  uint64_t sequence, uint64_t previous_sequence,
                                                  uint64_t entry_generation)
{
    RegistrydStoreState* state;
    RegistrydMutationResult ignored;
    if (store == NULL || mutation == NULL)
    {
        return REGISTRYD_STORE_NULL_ARGUMENT;
    }
    state = RegistrydStoreInternalState(store);
    RegistrydStoreInternalZero(&ignored, sizeof(ignored));
    if (!RegistrydStoreInternalStateIsSane(state) || !RegistrydStoreInternalCanonicalIsValid(mutation) ||
        state->pending.active || previous_sequence != state->commit_sequence || state->commit_sequence == UINT64_MAX ||
        sequence != state->commit_sequence + 1U || state->last_entry_generation == UINT64_MAX ||
        entry_generation != state->last_entry_generation + 1U ||
        RegistrydStoreInternalCheckRequest(state, mutation, &ignored) != REGISTRYD_STORE_OK ||
        RegistrydStoreInternalCheckExpected(state, mutation) != REGISTRYD_STORE_OK)
    {
        return REGISTRYD_STORE_CORRUPT_WAL;
    }
    return RegistrydStoreInternalApply(state, mutation, sequence, entry_generation) == REGISTRYD_STORE_OK
               ? REGISTRYD_STORE_OK
               : REGISTRYD_STORE_CORRUPT_WAL;
}

RegistrydStoreStatus RegistrydStoreInternalRecoverFinish(RegistrydStore* store, uint32_t expected_entries,
                                                         uint32_t expected_clients)
{
    RegistrydStoreState* state;
    if (store == NULL)
    {
        return REGISTRYD_STORE_NULL_ARGUMENT;
    }
    state = RegistrydStoreInternalState(store);
    return state->entry_count == expected_entries && state->client_count == expected_clients &&
                   RegistrydStoreInternalStateIsSane(state)
               ? REGISTRYD_STORE_OK
               : REGISTRYD_STORE_CORRUPT_SNAPSHOT;
}

void RegistrydStoreInternalFailClosed(RegistrydStore* store)
{
    if (store != NULL)
    {
        RegistrydStoreInternalZero(store, sizeof(*store));
    }
}
