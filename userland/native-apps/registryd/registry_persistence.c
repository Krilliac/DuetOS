#include "registry_store_internal.h"

#include <limits.h>

#define PersistZero RegistrydStoreInternalZero
#define PersistCopy RegistrydStoreInternalCopy
#define PersistEqual RegistrydStoreInternalEqual
#define RangesOverlap RegistrydStoreInternalRangesOverlap

static void WriteLe16(uint8_t* output, uint16_t value)
{
    output[0] = (uint8_t)value;
    output[1] = (uint8_t)(value >> 8U);
}

static void WriteLe32(uint8_t* output, uint32_t value)
{
    uint32_t index;
    for (index = 0; index < 4U; ++index)
    {
        output[index] = (uint8_t)(value >> (index * 8U));
    }
}

static void WriteLe64(uint8_t* output, uint64_t value)
{
    uint32_t index;
    for (index = 0; index < 8U; ++index)
    {
        output[index] = (uint8_t)(value >> (index * 8U));
    }
}

static uint16_t ReadLe16(const uint8_t* input)
{
    return (uint16_t)((uint16_t)input[0] | ((uint16_t)input[1] << 8U));
}

static uint32_t ReadLe32(const uint8_t* input)
{
    return (uint32_t)input[0] | ((uint32_t)input[1] << 8U) | ((uint32_t)input[2] << 16U) | ((uint32_t)input[3] << 24U);
}

static uint64_t ReadLe64(const uint8_t* input)
{
    uint64_t value = 0U;
    uint32_t index;
    for (index = 0; index < 8U; ++index)
    {
        value |= (uint64_t)input[index] << (index * 8U);
    }
    return value;
}

static uint32_t Crc32ZeroField(const uint8_t* bytes, uint32_t size, uint32_t zero_offset, uint32_t zero_size)
{
    uint32_t crc = UINT32_C(0xFFFFFFFF);
    uint32_t index;
    for (index = 0; index < size; ++index)
    {
        uint32_t bit;
        const uint8_t value = index >= zero_offset && index - zero_offset < zero_size ? 0U : bytes[index];
        crc ^= value;
        for (bit = 0; bit < 8U; ++bit)
        {
            const uint32_t mask = (uint32_t)(0U - (crc & 1U));
            crc = (crc >> 1U) ^ (UINT32_C(0xEDB88320) & mask);
        }
    }
    return ~crc;
}

static uint32_t Crc32(const uint8_t* bytes, uint32_t size)
{
    return Crc32ZeroField(bytes, size, UINT32_MAX, 0U);
}

RegistrydStoreStatus RegistrydStoreInternalEncodeWal(const RegistrydCanonicalMutation* mutation,
                                                     uint64_t commit_sequence, uint64_t previous_sequence,
                                                     uint64_t entry_generation, uint8_t* out, uint32_t capacity,
                                                     uint32_t* out_size)
{
    uint32_t cursor;
    uint32_t required;
    if (mutation == NULL || out == NULL || out_size == NULL)
    {
        return REGISTRYD_STORE_NULL_ARGUMENT;
    }
    if (!RegistrydStoreInternalCanonicalIsValid(mutation) || commit_sequence == 0U || previous_sequence == UINT64_MAX ||
        commit_sequence != previous_sequence + 1U || entry_generation == 0U)
    {
        return REGISTRYD_STORE_CORRUPT_STATE;
    }
    required = REGISTRYD_WAL_HEADER_SIZE + mutation->key_size + mutation->name_size + mutation->value_size;
    *out_size = required;
    if (required > REGISTRYD_STORE_MAX_WAL_RECORD_BYTES || capacity < required)
    {
        return REGISTRYD_STORE_BUFFER_TOO_SMALL;
    }
    PersistZero(out, required);
    WriteLe64(out + 0U, REGISTRYD_WAL_MAGIC);
    WriteLe16(out + 8U, REGISTRYD_FORMAT_VERSION);
    WriteLe16(out + 10U, REGISTRYD_WAL_HEADER_SIZE);
    WriteLe32(out + 12U, required);
    WriteLe64(out + 16U, commit_sequence);
    WriteLe64(out + 24U, previous_sequence);
    WriteLe64(out + 32U, entry_generation);
    WriteLe64(out + 40U, mutation->client_identity);
    WriteLe64(out + 48U, mutation->request_id);
    WriteLe64(out + 56U, mutation->fingerprint);
    WriteLe64(out + 64U, mutation->expected_entry_generation);
    out[72U] = mutation->operation;
    WriteLe32(out + 76U, mutation->value_type);
    WriteLe16(out + 80U, mutation->key_size);
    WriteLe16(out + 82U, mutation->name_size);
    WriteLe16(out + 84U, mutation->value_size);
    cursor = REGISTRYD_WAL_HEADER_SIZE;
    PersistCopy(out + cursor, mutation->key, mutation->key_size);
    cursor += mutation->key_size;
    PersistCopy(out + cursor, mutation->name, mutation->name_size);
    cursor += mutation->name_size;
    PersistCopy(out + cursor, mutation->value, mutation->value_size);
    WriteLe32(out + 88U, Crc32(out + REGISTRYD_WAL_HEADER_SIZE, required - REGISTRYD_WAL_HEADER_SIZE));
    WriteLe32(out + 92U, Crc32ZeroField(out, required, 92U, 4U));
    return REGISTRYD_STORE_OK;
}

static int CompareBytes(const char* left, uint16_t left_size, const char* right, uint16_t right_size)
{
    uint16_t index;
    const uint16_t common = left_size < right_size ? left_size : right_size;
    for (index = 0; index < common; ++index)
    {
        if ((uint8_t)left[index] != (uint8_t)right[index])
        {
            return (uint8_t)left[index] < (uint8_t)right[index] ? -1 : 1;
        }
    }
    return left_size == right_size ? 0 : (left_size < right_size ? -1 : 1);
}

static int CompareEntries(const RegistrydSnapshotEntry* left, const RegistrydSnapshotEntry* right)
{
    const int key_order = CompareBytes(left->key, left->key_size, right->key, right->key_size);
    return key_order != 0 ? key_order : CompareBytes(left->name, left->name_size, right->name, right->name_size);
}

static uint32_t EntryRecordSize(const RegistrydSnapshotEntry* entry)
{
    return REGISTRYD_ENTRY_HEADER_SIZE + entry->key_size + entry->name_size + entry->value_size;
}

static uint32_t ClientRecordSize(const RegistrydSnapshotClient* client)
{
    return REGISTRYD_CLIENT_HEADER_SIZE + client->mutation.key_size + client->mutation.name_size +
           client->mutation.value_size;
}

static uint32_t EncodeEntry(uint8_t* output, const RegistrydSnapshotEntry* entry)
{
    const uint32_t size = EntryRecordSize(entry);
    uint32_t cursor = REGISTRYD_ENTRY_HEADER_SIZE;
    PersistZero(output, size);
    WriteLe16(output + 0U, REGISTRYD_SNAPSHOT_ENTRY_KIND);
    WriteLe16(output + 2U, REGISTRYD_ENTRY_HEADER_SIZE);
    WriteLe32(output + 4U, size);
    WriteLe64(output + 8U, entry->entry_generation);
    WriteLe32(output + 16U, entry->value_type);
    WriteLe16(output + 20U, entry->key_size);
    WriteLe16(output + 22U, entry->name_size);
    WriteLe16(output + 24U, entry->value_size);
    PersistCopy(output + cursor, entry->key, entry->key_size);
    cursor += entry->key_size;
    PersistCopy(output + cursor, entry->name, entry->name_size);
    cursor += entry->name_size;
    PersistCopy(output + cursor, entry->value, entry->value_size);
    WriteLe32(output + 28U, Crc32(output + REGISTRYD_ENTRY_HEADER_SIZE, size - REGISTRYD_ENTRY_HEADER_SIZE));
    return size;
}

static uint32_t EncodeClient(uint8_t* output, const RegistrydSnapshotClient* client)
{
    const RegistrydCanonicalMutation* mutation = &client->mutation;
    const uint32_t size = ClientRecordSize(client);
    uint32_t cursor = REGISTRYD_CLIENT_HEADER_SIZE;
    PersistZero(output, size);
    WriteLe16(output + 0U, REGISTRYD_SNAPSHOT_CLIENT_KIND);
    WriteLe16(output + 2U, REGISTRYD_CLIENT_HEADER_SIZE);
    WriteLe32(output + 4U, size);
    WriteLe64(output + 8U, mutation->client_identity);
    WriteLe64(output + 16U, mutation->request_id);
    WriteLe64(output + 24U, mutation->fingerprint);
    WriteLe64(output + 32U, client->commit_sequence);
    WriteLe64(output + 40U, client->entry_generation);
    WriteLe64(output + 48U, mutation->expected_entry_generation);
    output[56U] = mutation->operation;
    WriteLe32(output + 60U, mutation->value_type);
    WriteLe16(output + 64U, mutation->key_size);
    WriteLe16(output + 66U, mutation->name_size);
    WriteLe16(output + 68U, mutation->value_size);
    PersistCopy(output + cursor, mutation->key, mutation->key_size);
    cursor += mutation->key_size;
    PersistCopy(output + cursor, mutation->name, mutation->name_size);
    cursor += mutation->name_size;
    PersistCopy(output + cursor, mutation->value, mutation->value_size);
    WriteLe32(output + 72U, Crc32(output + REGISTRYD_CLIENT_HEADER_SIZE, size - REGISTRYD_CLIENT_HEADER_SIZE));
    return size;
}

RegistrydStoreStatus RegistrydStoreEncodeSnapshot(const RegistrydStore* store, uint8_t* out, uint32_t capacity,
                                                  uint32_t* out_size)
{
    RegistrydStoreInspection inspection;
    RegistrydSnapshotEntry entry;
    RegistrydSnapshotEntry best_entry = {0};
    RegistrydSnapshotClient client;
    uint8_t emitted_entries[REGISTRYD_STORE_MAX_ENTRIES];
    uint8_t emitted_clients[REGISTRYD_STORE_MAX_CLIENTS];
    RegistrydStoreStatus status;
    uint32_t required = REGISTRYD_SNAPSHOT_HEADER_SIZE;
    uint32_t cursor = REGISTRYD_SNAPSHOT_HEADER_SIZE;
    uint32_t slot;
    uint32_t ordinal;
    if (store == NULL || out == NULL || out_size == NULL)
    {
        return REGISTRYD_STORE_NULL_ARGUMENT;
    }
    if (RangesOverlap(store, sizeof(*store), out_size, sizeof(*out_size)))
    {
        return REGISTRYD_STORE_ALIASED_STORAGE;
    }
    status = RegistrydStoreInternalSnapshotInfo(store, &inspection);
    if (status != REGISTRYD_STORE_OK)
    {
        return status;
    }
    if (inspection.has_pending_mutation)
    {
        return REGISTRYD_STORE_PENDING_MUTATION;
    }
    for (slot = 0; slot < REGISTRYD_STORE_MAX_ENTRIES; ++slot)
    {
        status = RegistrydStoreInternalEntryAt(store, slot, &entry);
        if (status != REGISTRYD_STORE_OK)
        {
            return status;
        }
        if (entry.active)
        {
            required += EntryRecordSize(&entry);
        }
    }
    for (slot = 0; slot < REGISTRYD_STORE_MAX_CLIENTS; ++slot)
    {
        status = RegistrydStoreInternalClientAt(store, slot, &client);
        if (status != REGISTRYD_STORE_OK)
        {
            return status;
        }
        if (client.active)
        {
            required += ClientRecordSize(&client);
        }
    }
    *out_size = required;
    if (required > REGISTRYD_STORE_MAX_SNAPSHOT_BYTES || capacity < required)
    {
        return REGISTRYD_STORE_BUFFER_TOO_SMALL;
    }
    if (RangesOverlap(store, sizeof(*store), out, required))
    {
        return REGISTRYD_STORE_ALIASED_STORAGE;
    }
    PersistZero(out, required);
    PersistZero(emitted_entries, sizeof(emitted_entries));
    PersistZero(emitted_clients, sizeof(emitted_clients));
    for (ordinal = 0; ordinal < inspection.entry_count; ++ordinal)
    {
        uint32_t best_slot = UINT32_MAX;
        for (slot = 0; slot < REGISTRYD_STORE_MAX_ENTRIES; ++slot)
        {
            RegistrydStoreInternalEntryAt(store, slot, &entry);
            if (!entry.active || emitted_entries[slot])
            {
                continue;
            }
            if (best_slot == UINT32_MAX || CompareEntries(&entry, &best_entry) < 0)
            {
                best_slot = slot;
                best_entry = entry;
            }
        }
        if (best_slot == UINT32_MAX)
        {
            return REGISTRYD_STORE_CORRUPT_STATE;
        }
        emitted_entries[best_slot] = 1U;
        cursor += EncodeEntry(out + cursor, &best_entry);
    }
    for (ordinal = 0; ordinal < inspection.client_count; ++ordinal)
    {
        RegistrydSnapshotClient best_client = {0};
        uint32_t best_slot = UINT32_MAX;
        for (slot = 0; slot < REGISTRYD_STORE_MAX_CLIENTS; ++slot)
        {
            RegistrydStoreInternalClientAt(store, slot, &client);
            if (!client.active || emitted_clients[slot])
            {
                continue;
            }
            if (best_slot == UINT32_MAX || client.mutation.client_identity < best_client.mutation.client_identity)
            {
                best_slot = slot;
                best_client = client;
            }
        }
        if (best_slot == UINT32_MAX)
        {
            return REGISTRYD_STORE_CORRUPT_STATE;
        }
        emitted_clients[best_slot] = 1U;
        cursor += EncodeClient(out + cursor, &best_client);
    }
    if (cursor != required)
    {
        return REGISTRYD_STORE_CORRUPT_STATE;
    }
    WriteLe64(out + 0U, REGISTRYD_SNAPSHOT_MAGIC);
    WriteLe16(out + 8U, REGISTRYD_FORMAT_VERSION);
    WriteLe16(out + 10U, REGISTRYD_SNAPSHOT_HEADER_SIZE);
    WriteLe32(out + 12U, required);
    WriteLe32(out + 16U, inspection.entry_count);
    WriteLe32(out + 20U, inspection.client_count);
    WriteLe64(out + 24U, inspection.commit_sequence);
    WriteLe64(out + 32U, inspection.last_entry_generation);
    WriteLe32(out + 40U, Crc32(out + REGISTRYD_SNAPSHOT_HEADER_SIZE, required - REGISTRYD_SNAPSHOT_HEADER_SIZE));
    WriteLe32(out + 44U, Crc32ZeroField(out, required, 44U, 4U));
    return REGISTRYD_STORE_OK;
}

static int ReservedIsZero(const uint8_t* bytes, uint32_t start, uint32_t end)
{
    uint32_t index;
    for (index = start; index < end; ++index)
    {
        if (bytes[index] != 0U)
        {
            return 0;
        }
    }
    return 1;
}

static RegistrydStoreStatus DecodeCanonicalMutation(const uint8_t* record, uint32_t header_size, uint32_t record_size,
                                                    uint64_t client_identity, uint64_t request_id,
                                                    uint64_t expected_generation, uint64_t fingerprint,
                                                    uint8_t operation, uint32_t type, uint16_t key_size,
                                                    uint16_t name_size, uint16_t value_size,
                                                    RegistrydCanonicalMutation* out)
{
    RegistrydMutation mutation;
    RegistrydStoreStatus status;
    uint32_t cursor = header_size;
    if (key_size > REGISTRYD_STORE_MAX_KEY_BYTES || name_size > REGISTRYD_STORE_MAX_NAME_BYTES ||
        value_size > REGISTRYD_STORE_MAX_VALUE_BYTES || record_size != header_size + key_size + name_size + value_size)
    {
        return REGISTRYD_STORE_CORRUPT_WAL;
    }
    PersistZero(&mutation, sizeof(mutation));
    mutation.client_identity = client_identity;
    mutation.request_id = request_id;
    mutation.expected_entry_generation = expected_generation;
    mutation.key = (const char*)(record + cursor);
    mutation.key_size = key_size;
    cursor += key_size;
    mutation.name = (const char*)(record + cursor);
    mutation.name_size = name_size;
    cursor += name_size;
    mutation.value = operation == REGISTRYD_MUTATION_DELETE ? NULL : record + cursor;
    mutation.value_size = value_size;
    mutation.value_type = type;
    mutation.operation = operation;
    status = RegistrydStoreInternalCanonicalize(&mutation, out);
    if (status != REGISTRYD_STORE_OK || out->fingerprint != fingerprint)
    {
        return REGISTRYD_STORE_CORRUPT_WAL;
    }
    return REGISTRYD_STORE_OK;
}

static RegistrydStoreStatus DecodeSnapshotEntry(const uint8_t* record, uint32_t available, RegistrydSnapshotEntry* out,
                                                uint32_t* consumed)
{
    uint32_t record_size;
    uint16_t key_size;
    uint16_t name_size;
    uint16_t value_size;
    uint32_t cursor;
    if (available < REGISTRYD_ENTRY_HEADER_SIZE || ReadLe16(record + 0U) != REGISTRYD_SNAPSHOT_ENTRY_KIND ||
        ReadLe16(record + 2U) != REGISTRYD_ENTRY_HEADER_SIZE)
    {
        return REGISTRYD_STORE_CORRUPT_SNAPSHOT;
    }
    record_size = ReadLe32(record + 4U);
    key_size = ReadLe16(record + 20U);
    name_size = ReadLe16(record + 22U);
    value_size = ReadLe16(record + 24U);
    if (record_size > available || key_size > REGISTRYD_STORE_MAX_KEY_BYTES ||
        name_size > REGISTRYD_STORE_MAX_NAME_BYTES || value_size > REGISTRYD_STORE_MAX_VALUE_BYTES ||
        record_size != REGISTRYD_ENTRY_HEADER_SIZE + key_size + name_size + value_size ||
        !ReservedIsZero(record, 26U, 28U) || !ReservedIsZero(record, 32U, 40U) ||
        ReadLe32(record + 28U) !=
            Crc32(record + REGISTRYD_ENTRY_HEADER_SIZE, record_size - REGISTRYD_ENTRY_HEADER_SIZE))
    {
        return REGISTRYD_STORE_CORRUPT_SNAPSHOT;
    }
    PersistZero(out, sizeof(*out));
    out->entry_generation = ReadLe64(record + 8U);
    out->value_type = ReadLe32(record + 16U);
    out->key_size = key_size;
    out->name_size = name_size;
    out->value_size = value_size;
    cursor = REGISTRYD_ENTRY_HEADER_SIZE;
    PersistCopy(out->key, record + cursor, key_size);
    cursor += key_size;
    PersistCopy(out->name, record + cursor, name_size);
    cursor += name_size;
    PersistCopy(out->value, record + cursor, value_size);
    out->active = 1U;
    *consumed = record_size;
    return REGISTRYD_STORE_OK;
}

static RegistrydStoreStatus DecodeSnapshotClient(const uint8_t* record, uint32_t available,
                                                 RegistrydSnapshotClient* out, uint32_t* consumed)
{
    RegistrydStoreStatus status;
    uint32_t record_size;
    uint16_t key_size;
    uint16_t name_size;
    uint16_t value_size;
    if (available < REGISTRYD_CLIENT_HEADER_SIZE || ReadLe16(record + 0U) != REGISTRYD_SNAPSHOT_CLIENT_KIND ||
        ReadLe16(record + 2U) != REGISTRYD_CLIENT_HEADER_SIZE)
    {
        return REGISTRYD_STORE_CORRUPT_SNAPSHOT;
    }
    record_size = ReadLe32(record + 4U);
    key_size = ReadLe16(record + 64U);
    name_size = ReadLe16(record + 66U);
    value_size = ReadLe16(record + 68U);
    if (record_size > available || record_size != REGISTRYD_CLIENT_HEADER_SIZE + key_size + name_size + value_size ||
        !ReservedIsZero(record, 57U, 60U) || !ReservedIsZero(record, 70U, 72U) || !ReservedIsZero(record, 76U, 80U) ||
        ReadLe32(record + 72U) !=
            Crc32(record + REGISTRYD_CLIENT_HEADER_SIZE, record_size - REGISTRYD_CLIENT_HEADER_SIZE))
    {
        return REGISTRYD_STORE_CORRUPT_SNAPSHOT;
    }
    PersistZero(out, sizeof(*out));
    status =
        DecodeCanonicalMutation(record, REGISTRYD_CLIENT_HEADER_SIZE, record_size, ReadLe64(record + 8U),
                                ReadLe64(record + 16U), ReadLe64(record + 48U), ReadLe64(record + 24U), record[56U],
                                ReadLe32(record + 60U), key_size, name_size, value_size, &out->mutation);
    if (status != REGISTRYD_STORE_OK)
    {
        return REGISTRYD_STORE_CORRUPT_SNAPSHOT;
    }
    out->commit_sequence = ReadLe64(record + 32U);
    out->entry_generation = ReadLe64(record + 40U);
    out->active = 1U;
    *consumed = record_size;
    return REGISTRYD_STORE_OK;
}

static RegistrydStoreStatus ValidateSnapshotHeader(const uint8_t* snapshot, uint32_t size,
                                                   RegistrydStoreInspection* inspection)
{
    if (size < REGISTRYD_SNAPSHOT_HEADER_SIZE || size > REGISTRYD_STORE_MAX_SNAPSHOT_BYTES ||
        ReadLe64(snapshot + 0U) != REGISTRYD_SNAPSHOT_MAGIC || ReadLe16(snapshot + 8U) != REGISTRYD_FORMAT_VERSION ||
        ReadLe16(snapshot + 10U) != REGISTRYD_SNAPSHOT_HEADER_SIZE || ReadLe32(snapshot + 12U) != size ||
        ReadLe32(snapshot + 16U) > REGISTRYD_STORE_MAX_ENTRIES ||
        ReadLe32(snapshot + 20U) > REGISTRYD_STORE_MAX_CLIENTS || !ReservedIsZero(snapshot, 48U, 64U) ||
        ReadLe32(snapshot + 40U) !=
            Crc32(snapshot + REGISTRYD_SNAPSHOT_HEADER_SIZE, size - REGISTRYD_SNAPSHOT_HEADER_SIZE) ||
        ReadLe32(snapshot + 44U) != Crc32ZeroField(snapshot, size, 44U, 4U))
    {
        return REGISTRYD_STORE_CORRUPT_SNAPSHOT;
    }
    PersistZero(inspection, sizeof(*inspection));
    inspection->entry_count = ReadLe32(snapshot + 16U);
    inspection->client_count = ReadLe32(snapshot + 20U);
    inspection->commit_sequence = ReadLe64(snapshot + 24U);
    inspection->last_entry_generation = ReadLe64(snapshot + 32U);
    return REGISTRYD_STORE_OK;
}

static RegistrydStoreStatus RecoverSnapshot(RegistrydStore* store, const uint8_t* snapshot, uint32_t snapshot_size,
                                            RegistrydStoreInspection* inspection)
{
    RegistrydSnapshotEntry entry;
    RegistrydSnapshotEntry previous_entry;
    RegistrydSnapshotClient client;
    RegistrydStoreStatus status;
    uint64_t previous_client_identity = 0U;
    uint32_t cursor = REGISTRYD_SNAPSHOT_HEADER_SIZE;
    uint32_t consumed;
    uint32_t index;
    int have_previous_entry = 0;
    if (snapshot_size == 0U)
    {
        PersistZero(inspection, sizeof(*inspection));
        return RegistrydStoreInternalRecoverBegin(store, 0U, 0U);
    }
    status = ValidateSnapshotHeader(snapshot, snapshot_size, inspection);
    if (status != REGISTRYD_STORE_OK)
    {
        return status;
    }
    status = RegistrydStoreInternalRecoverBegin(store, inspection->commit_sequence, inspection->last_entry_generation);
    if (status != REGISTRYD_STORE_OK)
    {
        return status;
    }
    for (index = 0; index < inspection->entry_count; ++index)
    {
        status = DecodeSnapshotEntry(snapshot + cursor, snapshot_size - cursor, &entry, &consumed);
        if (status != REGISTRYD_STORE_OK || (have_previous_entry && CompareEntries(&previous_entry, &entry) >= 0))
        {
            RegistrydStoreInternalFailClosed(store);
            return REGISTRYD_STORE_CORRUPT_SNAPSHOT;
        }
        status = RegistrydStoreInternalRecoverEntry(store, &entry);
        if (status != REGISTRYD_STORE_OK)
        {
            RegistrydStoreInternalFailClosed(store);
            return REGISTRYD_STORE_CORRUPT_SNAPSHOT;
        }
        previous_entry = entry;
        have_previous_entry = 1;
        cursor += consumed;
    }
    for (index = 0; index < inspection->client_count; ++index)
    {
        status = DecodeSnapshotClient(snapshot + cursor, snapshot_size - cursor, &client, &consumed);
        if (status != REGISTRYD_STORE_OK ||
            (index != 0U && client.mutation.client_identity <= previous_client_identity))
        {
            RegistrydStoreInternalFailClosed(store);
            return REGISTRYD_STORE_CORRUPT_SNAPSHOT;
        }
        status = RegistrydStoreInternalRecoverClient(store, &client);
        if (status != REGISTRYD_STORE_OK)
        {
            RegistrydStoreInternalFailClosed(store);
            return REGISTRYD_STORE_CORRUPT_SNAPSHOT;
        }
        previous_client_identity = client.mutation.client_identity;
        cursor += consumed;
    }
    if (cursor != snapshot_size || RegistrydStoreInternalRecoverFinish(store, inspection->entry_count,
                                                                       inspection->client_count) != REGISTRYD_STORE_OK)
    {
        RegistrydStoreInternalFailClosed(store);
        return REGISTRYD_STORE_CORRUPT_SNAPSHOT;
    }
    return REGISTRYD_STORE_OK;
}

typedef struct RegistrydWalHeader
{
    uint32_t record_size;
    uint64_t sequence;
    uint64_t previous_sequence;
    uint64_t entry_generation;
    uint64_t client_identity;
    uint64_t request_id;
    uint64_t fingerprint;
    uint64_t expected_generation;
    uint32_t value_type;
    uint16_t key_size;
    uint16_t name_size;
    uint16_t value_size;
    uint8_t operation;
} RegistrydWalHeader;

static int WalPrefixCanBeTorn(const uint8_t* record, uint32_t available)
{
    uint8_t prefix[12];
    uint32_t comparable = available < sizeof(prefix) ? available : (uint32_t)sizeof(prefix);
    PersistZero(prefix, sizeof(prefix));
    WriteLe64(prefix + 0U, REGISTRYD_WAL_MAGIC);
    WriteLe16(prefix + 8U, REGISTRYD_FORMAT_VERSION);
    WriteLe16(prefix + 10U, REGISTRYD_WAL_HEADER_SIZE);
    return comparable != 0U && PersistEqual(record, prefix, comparable);
}

/*
 * A torn tail with at least this many bytes physically includes the
 * sequence/previous_sequence/entry_generation triplet (offsets 16..39), so
 * generation continuity can -- and must -- still be checked against the
 * recovered state even though the full REGISTRYD_WAL_HEADER_SIZE header
 * is not present. Without this, a corrupted (not genuinely truncated) tail
 * that happens to match only the 12-byte magic/version/header-size prefix
 * would be silently accepted as a benign torn write instead of rejected.
 */
#define REGISTRYD_WAL_TORN_SEQUENCE_BYTES 40U

static RegistrydStoreStatus DecodeWalHeader(const uint8_t* record, uint32_t available, RegistrydWalHeader* header,
                                            int* torn)
{
    PersistZero(header, sizeof(*header));
    *torn = 0;
    if (available < REGISTRYD_WAL_HEADER_SIZE)
    {
        if (!WalPrefixCanBeTorn(record, available))
        {
            return REGISTRYD_STORE_CORRUPT_WAL;
        }
        if (available >= REGISTRYD_WAL_TORN_SEQUENCE_BYTES)
        {
            header->sequence = ReadLe64(record + 16U);
            header->previous_sequence = ReadLe64(record + 24U);
            header->entry_generation = ReadLe64(record + 32U);
        }
        *torn = 1;
        return REGISTRYD_STORE_RECOVERED_TORN_WAL;
    }
    if (ReadLe64(record + 0U) != REGISTRYD_WAL_MAGIC || ReadLe16(record + 8U) != REGISTRYD_FORMAT_VERSION ||
        ReadLe16(record + 10U) != REGISTRYD_WAL_HEADER_SIZE || !ReservedIsZero(record, 73U, 76U) ||
        !ReservedIsZero(record, 86U, 88U))
    {
        return REGISTRYD_STORE_CORRUPT_WAL;
    }
    header->record_size = ReadLe32(record + 12U);
    header->key_size = ReadLe16(record + 80U);
    header->name_size = ReadLe16(record + 82U);
    header->value_size = ReadLe16(record + 84U);
    header->sequence = ReadLe64(record + 16U);
    header->previous_sequence = ReadLe64(record + 24U);
    header->entry_generation = ReadLe64(record + 32U);
    header->client_identity = ReadLe64(record + 40U);
    header->request_id = ReadLe64(record + 48U);
    header->fingerprint = ReadLe64(record + 56U);
    header->expected_generation = ReadLe64(record + 64U);
    header->operation = record[72U];
    header->value_type = ReadLe32(record + 76U);
    if (header->record_size < REGISTRYD_WAL_HEADER_SIZE || header->record_size > REGISTRYD_STORE_MAX_WAL_RECORD_BYTES ||
        header->key_size == 0U || header->key_size > REGISTRYD_STORE_MAX_KEY_BYTES ||
        header->name_size > REGISTRYD_STORE_MAX_NAME_BYTES || header->value_size > REGISTRYD_STORE_MAX_VALUE_BYTES ||
        header->record_size != REGISTRYD_WAL_HEADER_SIZE + header->key_size + header->name_size + header->value_size ||
        header->sequence == 0U || header->previous_sequence == UINT64_MAX ||
        header->sequence != header->previous_sequence + 1U || header->entry_generation == 0U ||
        header->client_identity == 0U || header->request_id == 0U)
    {
        return REGISTRYD_STORE_CORRUPT_WAL;
    }
    if (header->operation == REGISTRYD_MUTATION_DELETE)
    {
        if (header->value_type != REGISTRYD_VALUE_NONE || header->value_size != 0U)
        {
            return REGISTRYD_STORE_CORRUPT_WAL;
        }
    }
    else if (header->operation != REGISTRYD_MUTATION_SET ||
             !((header->value_type == REGISTRYD_VALUE_NONE) || (header->value_type == REGISTRYD_VALUE_STRING) ||
               (header->value_type == REGISTRYD_VALUE_EXPAND_STRING) ||
               (header->value_type == REGISTRYD_VALUE_BINARY) || (header->value_type == REGISTRYD_VALUE_MULTI_STRING) ||
               ((header->value_type == REGISTRYD_VALUE_DWORD) && header->value_size == 4U) ||
               ((header->value_type == REGISTRYD_VALUE_QWORD) && header->value_size == 8U)))
    {
        return REGISTRYD_STORE_CORRUPT_WAL;
    }
    if (header->record_size > available)
    {
        *torn = 1;
        return REGISTRYD_STORE_RECOVERED_TORN_WAL;
    }
    return REGISTRYD_STORE_OK;
}

static RegistrydStoreStatus DecodeAndReplayWal(RegistrydStore* store, const uint8_t* record,
                                               const RegistrydWalHeader* header)
{
    RegistrydCanonicalMutation mutation;
    RegistrydStoreStatus status;
    if (ReadLe32(record + 88U) !=
            Crc32(record + REGISTRYD_WAL_HEADER_SIZE, header->record_size - REGISTRYD_WAL_HEADER_SIZE) ||
        ReadLe32(record + 92U) != Crc32ZeroField(record, header->record_size, 92U, 4U))
    {
        return REGISTRYD_STORE_CORRUPT_WAL;
    }
    status =
        DecodeCanonicalMutation(record, REGISTRYD_WAL_HEADER_SIZE, header->record_size, header->client_identity,
                                header->request_id, header->expected_generation, header->fingerprint, header->operation,
                                header->value_type, header->key_size, header->name_size, header->value_size, &mutation);
    if (status != REGISTRYD_STORE_OK)
    {
        return REGISTRYD_STORE_CORRUPT_WAL;
    }
    return RegistrydStoreInternalReplay(store, &mutation, header->sequence, header->previous_sequence,
                                        header->entry_generation);
}

RegistrydStoreStatus RegistrydStoreRecover(RegistrydStore* store, const uint8_t* snapshot, uint32_t snapshot_size,
                                           const uint8_t* wal, uint32_t wal_size, RegistrydRecoveryResult* out_result)
{
    RegistrydStoreInspection snapshot_info;
    RegistrydStoreInspection final_info;
    RegistrydWalHeader header;
    RegistrydStoreStatus status;
    uint32_t cursor = 0U;
    uint32_t records = 0U;
    if (store == NULL || out_result == NULL || (snapshot_size != 0U && snapshot == NULL) ||
        (wal_size != 0U && wal == NULL))
    {
        return REGISTRYD_STORE_NULL_ARGUMENT;
    }
    if (RangesOverlap(store, sizeof(*store), out_result, sizeof(*out_result)) ||
        (snapshot_size != 0U && RangesOverlap(store, sizeof(*store), snapshot, snapshot_size)) ||
        (wal_size != 0U && RangesOverlap(store, sizeof(*store), wal, wal_size)))
    {
        return REGISTRYD_STORE_ALIASED_STORAGE;
    }
    PersistZero(out_result, sizeof(*out_result));
    status = RecoverSnapshot(store, snapshot, snapshot_size, &snapshot_info);
    if (status != REGISTRYD_STORE_OK)
    {
        return status;
    }
    while (cursor < wal_size)
    {
        int torn = 0;
        status = DecodeWalHeader(wal + cursor, wal_size - cursor, &header, &torn);
        if (status == REGISTRYD_STORE_RECOVERED_TORN_WAL && torn)
        {
            status = RegistrydStoreInspect(store, &final_info);
            if (status != REGISTRYD_STORE_OK)
            {
                RegistrydStoreInternalFailClosed(store);
                return REGISTRYD_STORE_CORRUPT_WAL;
            }
            if (wal_size - cursor >= REGISTRYD_WAL_TORN_SEQUENCE_BYTES &&
                (final_info.commit_sequence == UINT64_MAX || final_info.last_entry_generation == UINT64_MAX ||
                 header.previous_sequence != final_info.commit_sequence ||
                 header.sequence != final_info.commit_sequence + 1U ||
                 header.entry_generation != final_info.last_entry_generation + 1U))
            {
                RegistrydStoreInternalFailClosed(store);
                return REGISTRYD_STORE_CORRUPT_WAL;
            }
            out_result->commit_sequence = final_info.commit_sequence;
            out_result->last_entry_generation = final_info.last_entry_generation;
            out_result->snapshot_entries = snapshot_info.entry_count;
            out_result->wal_records = records;
            out_result->wal_bytes_consumed = cursor;
            out_result->wal_bytes_ignored = wal_size - cursor;
            out_result->torn_wal_tail = 1U;
            return REGISTRYD_STORE_RECOVERED_TORN_WAL;
        }
        if (status != REGISTRYD_STORE_OK || DecodeAndReplayWal(store, wal + cursor, &header) != REGISTRYD_STORE_OK)
        {
            RegistrydStoreInternalFailClosed(store);
            PersistZero(out_result, sizeof(*out_result));
            return REGISTRYD_STORE_CORRUPT_WAL;
        }
        cursor += header.record_size;
        ++records;
    }
    status = RegistrydStoreInspect(store, &final_info);
    if (status != REGISTRYD_STORE_OK)
    {
        RegistrydStoreInternalFailClosed(store);
        return REGISTRYD_STORE_CORRUPT_WAL;
    }
    out_result->commit_sequence = final_info.commit_sequence;
    out_result->last_entry_generation = final_info.last_entry_generation;
    out_result->snapshot_entries = snapshot_info.entry_count;
    out_result->wal_records = records;
    out_result->wal_bytes_consumed = cursor;
    return REGISTRYD_STORE_OK;
}
