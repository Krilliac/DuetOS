// Hostile hosted coverage for registryd's allocation-free store and codecs.

#include "host_test_helper.h"
#include "registry_store.h"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <limits>
#include <thread>
#include <vector>

namespace
{

RegistrydStore g_stores[12]{};
std::uint8_t g_snapshots[5][REGISTRYD_STORE_MAX_SNAPSHOT_BYTES]{};
std::uint8_t g_wal_records[8][REGISTRYD_STORE_MAX_WAL_RECORD_BYTES]{};
std::uint8_t g_wal_chain[REGISTRYD_STORE_MAX_WAL_RECORD_BYTES * 3U]{};

struct CommitCapture
{
    RegistrydMutationResult result{};
    std::uint32_t wal_size{};
};

RegistrydMutation Set(std::uint64_t client, std::uint64_t request, std::uint64_t expected, const char* key,
                      const char* name, std::uint32_t type, const void* value, std::uint32_t value_size)
{
    RegistrydMutation mutation{};
    mutation.client_identity = client;
    mutation.request_id = request;
    mutation.expected_entry_generation = expected;
    mutation.key = key;
    mutation.name = name;
    mutation.value = static_cast<const std::uint8_t*>(value);
    mutation.key_size = static_cast<std::uint32_t>(std::strlen(key));
    mutation.name_size = static_cast<std::uint32_t>(std::strlen(name));
    mutation.value_size = value_size;
    mutation.value_type = type;
    mutation.operation = REGISTRYD_MUTATION_SET;
    return mutation;
}

RegistrydMutation Delete(std::uint64_t client, std::uint64_t request, std::uint64_t expected, const char* key,
                         const char* name)
{
    auto mutation = Set(client, request, expected, key, name, REGISTRYD_VALUE_NONE, nullptr, 0);
    mutation.operation = REGISTRYD_MUTATION_DELETE;
    return mutation;
}

CommitCapture Commit(RegistrydStore& store, const RegistrydMutation& mutation, std::uint8_t* wal)
{
    CommitCapture capture{};
    RegistrydPreparedMutation prepared{};
    EXPECT_EQ(RegistrydStorePrepareMutation(&store, &mutation, wal, REGISTRYD_STORE_MAX_WAL_RECORD_BYTES,
                                            &capture.wal_size, &prepared, &capture.result),
              REGISTRYD_STORE_OK);
    RegistrydMutationResult committed{};
    EXPECT_EQ(RegistrydStoreCommitMutation(&store, &prepared, &committed), REGISTRYD_STORE_OK);
    EXPECT_EQ(committed.commit_sequence, capture.result.commit_sequence);
    EXPECT_EQ(committed.entry_generation, capture.result.entry_generation);
    capture.result = committed;
    return capture;
}

std::uint32_t Crc32ZeroField(const std::uint8_t* bytes, std::uint32_t size, std::uint32_t zero_offset,
                             std::uint32_t zero_size)
{
    std::uint32_t crc = 0xFFFFFFFFU;
    for (std::uint32_t index = 0; index < size; ++index)
    {
        const auto value = index >= zero_offset && index - zero_offset < zero_size ? 0U : bytes[index];
        crc ^= value;
        for (std::uint32_t bit = 0; bit < 8U; ++bit)
        {
            const auto mask = 0U - (crc & 1U);
            crc = (crc >> 1U) ^ (0xEDB88320U & mask);
        }
    }
    return ~crc;
}

void WriteLe32(std::uint8_t* bytes, std::uint32_t value)
{
    for (std::uint32_t index = 0; index < 4U; ++index)
    {
        bytes[index] = static_cast<std::uint8_t>(value >> (index * 8U));
    }
}

void WriteLe64(std::uint8_t* bytes, std::uint64_t value)
{
    for (std::uint32_t index = 0; index < 8U; ++index)
    {
        bytes[index] = static_cast<std::uint8_t>(value >> (index * 8U));
    }
}

void RechecksumSnapshot(std::uint8_t* snapshot, std::uint32_t size)
{
    WriteLe32(snapshot + 44U, Crc32ZeroField(snapshot, size, 44U, 4U));
}

void RechecksumWal(std::uint8_t* wal, std::uint32_t size)
{
    WriteLe32(wal + 92U, Crc32ZeroField(wal, size, 92U, 4U));
}

RegistrydStoredValue Query(RegistrydStore& store, const char* key, const char* name)
{
    RegistrydStoredValue value{};
    EXPECT_EQ(RegistrydStoreQuery(&store, key, static_cast<std::uint32_t>(std::strlen(key)), name,
                                  static_cast<std::uint32_t>(std::strlen(name)), &value),
              REGISTRYD_STORE_OK);
    return value;
}

void TestValidationVersionsAndDedup()
{
    auto& store = g_stores[0];
    const std::uint8_t one[] = {1, 0, 0, 0};
    const std::uint8_t two[] = {2, 0, 0, 0};
    RegistrydPreparedMutation prepared{};
    RegistrydMutationResult result{};
    std::uint32_t wal_size = 0;
    EXPECT_EQ(RegistrydStoreInitialize(nullptr), REGISTRYD_STORE_NULL_ARGUMENT);
    EXPECT_EQ(RegistrydStoreInitialize(&store), REGISTRYD_STORE_OK);
    EXPECT_EQ(RegistrydStoreInitialize(&store), REGISTRYD_STORE_ALREADY_INITIALIZED);

    auto invalid = Set(1, 1, 0, "SOFTWARE\\DUET", "VALUE", REGISTRYD_VALUE_DWORD, one, sizeof(one));
    EXPECT_EQ(RegistrydStorePrepareMutation(&store, &invalid, g_wal_records[0], sizeof(g_wal_records[0]), &wal_size,
                                            &prepared, &result),
              REGISTRYD_STORE_INVALID_KEY);
    invalid = Set(1, 1, 0, "HKLM\\DUET\\\\BAD", "VALUE", REGISTRYD_VALUE_DWORD, one, sizeof(one));
    EXPECT_EQ(RegistrydStorePrepareMutation(&store, &invalid, g_wal_records[0], sizeof(g_wal_records[0]), &wal_size,
                                            &prepared, &result),
              REGISTRYD_STORE_INVALID_KEY);
    invalid = Set(1, 1, 0, "HKLM/DUET", "VALUE", REGISTRYD_VALUE_DWORD, one, sizeof(one));
    EXPECT_EQ(RegistrydStorePrepareMutation(&store, &invalid, g_wal_records[0], sizeof(g_wal_records[0]), &wal_size,
                                            &prepared, &result),
              REGISTRYD_STORE_INVALID_KEY);
    invalid = Set(1, 1, 0, "HKLM\\..\\DUET", "VALUE", REGISTRYD_VALUE_DWORD, one, sizeof(one));
    EXPECT_EQ(RegistrydStorePrepareMutation(&store, &invalid, g_wal_records[0], sizeof(g_wal_records[0]), &wal_size,
                                            &prepared, &result),
              REGISTRYD_STORE_INVALID_KEY);
    invalid = Set(1, 1, 0, "HKLM\\DUET", "BAD\\NAME", REGISTRYD_VALUE_DWORD, one, sizeof(one));
    EXPECT_EQ(RegistrydStorePrepareMutation(&store, &invalid, g_wal_records[0], sizeof(g_wal_records[0]), &wal_size,
                                            &prepared, &result),
              REGISTRYD_STORE_INVALID_NAME);
    invalid = Set(1, 1, 0, "HKLM\\DUET", "VALUE", REGISTRYD_VALUE_DWORD, one, 3);
    EXPECT_EQ(RegistrydStorePrepareMutation(&store, &invalid, g_wal_records[0], sizeof(g_wal_records[0]), &wal_size,
                                            &prepared, &result),
              REGISTRYD_STORE_INVALID_VALUE);
    const std::uint8_t unterminated[] = {'n', 'o'};
    invalid = Set(1, 1, 0, "HKLM\\DUET", "VALUE", 99U, unterminated, sizeof(unterminated));
    EXPECT_EQ(RegistrydStorePrepareMutation(&store, &invalid, g_wal_records[0], sizeof(g_wal_records[0]), &wal_size,
                                            &prepared, &result),
              REGISTRYD_STORE_INVALID_TYPE);

    auto first = Set(1, 1, 0, "hklm\\software\\duetos", "answer", REGISTRYD_VALUE_DWORD, one, sizeof(one));
    const auto first_commit = Commit(store, first, g_wal_records[0]);
    EXPECT_EQ(first_commit.result.commit_sequence, 1ULL);
    EXPECT_EQ(first_commit.result.entry_generation, 1ULL);
    auto queried = Query(store, "HKLM\\SOFTWARE\\DUETOS", "ANSWER");
    EXPECT_EQ(queried.value_type, static_cast<std::uint32_t>(REGISTRYD_VALUE_DWORD));
    EXPECT_EQ(queried.value[0], 1U);

    wal_size = 99;
    EXPECT_EQ(RegistrydStorePrepareMutation(&store, &first, g_wal_records[1], sizeof(g_wal_records[1]), &wal_size,
                                            &prepared, &result),
              REGISTRYD_STORE_DUPLICATE_REQUEST);
    EXPECT_EQ(wal_size, 0U);
    EXPECT_EQ(result.duplicate, 1U);
    EXPECT_EQ(result.commit_sequence, 1ULL);
    auto conflict = first;
    conflict.value = two;
    EXPECT_EQ(RegistrydStorePrepareMutation(&store, &conflict, g_wal_records[1], sizeof(g_wal_records[1]), &wal_size,
                                            &prepared, &result),
              REGISTRYD_STORE_REQUEST_ID_CONFLICT);

    auto stale = Set(1, 2, 0, "HKLM\\SOFTWARE\\DUETOS", "ANSWER", REGISTRYD_VALUE_DWORD, two, sizeof(two));
    EXPECT_EQ(RegistrydStorePrepareMutation(&store, &stale, g_wal_records[1], sizeof(g_wal_records[1]), &wal_size,
                                            &prepared, &result),
              REGISTRYD_STORE_VERSION_CONFLICT);
    stale.expected_entry_generation = queried.entry_generation;
    const auto second_commit = Commit(store, stale, g_wal_records[1]);
    EXPECT_EQ(second_commit.result.entry_generation, 2ULL);
    EXPECT_EQ(Query(store, "hklm\\software\\duetos", "answer").value[0], 2U);

    EXPECT_EQ(RegistrydStorePrepareMutation(&store, &first, g_wal_records[2], sizeof(g_wal_records[2]), &wal_size,
                                            &prepared, &result),
              REGISTRYD_STORE_REPLAYED_REQUEST);
}

void TestPrepareAbortDeleteAndDeterminism()
{
    auto& store = g_stores[0];
    const std::uint8_t one[] = {1, 0, 0, 0};
    auto update = Set(1, 3, 2, "HKLM\\SOFTWARE\\DUETOS", "ANSWER", REGISTRYD_VALUE_DWORD, one, sizeof(one));
    RegistrydPreparedMutation prepared{};
    RegistrydPreparedMutation stale_token{};
    RegistrydMutationResult result{};
    std::uint32_t wal_size = 0;
    std::uint32_t snapshot_size = 0;
    EXPECT_EQ(RegistrydStorePrepareMutation(&store, &update, g_wal_records[2], 8, &wal_size, &prepared, &result),
              REGISTRYD_STORE_BUFFER_TOO_SMALL);
    EXPECT_TRUE(wal_size > 8U);
    EXPECT_EQ(RegistrydStorePrepareMutation(&store, &update, g_wal_records[2], sizeof(g_wal_records[2]), &wal_size,
                                            &prepared, &result),
              REGISTRYD_STORE_OK);
    EXPECT_EQ(RegistrydStoreEncodeSnapshot(&store, g_snapshots[0], sizeof(g_snapshots[0]), &snapshot_size),
              REGISTRYD_STORE_PENDING_MUTATION);
    stale_token = prepared;
    ++stale_token.fingerprint;
    EXPECT_EQ(RegistrydStoreAbortMutation(&store, &stale_token), REGISTRYD_STORE_STALE_PREPARATION);
    const auto first_wal_size = wal_size;
    std::memcpy(g_wal_records[3], g_wal_records[2], wal_size);
    EXPECT_EQ(RegistrydStoreAbortMutation(&store, &prepared), REGISTRYD_STORE_OK);
    EXPECT_EQ(RegistrydStoreAbortMutation(&store, &prepared), REGISTRYD_STORE_NO_PENDING_MUTATION);
    EXPECT_EQ(RegistrydStorePrepareMutation(&store, &update, g_wal_records[2], sizeof(g_wal_records[2]), &wal_size,
                                            &prepared, &result),
              REGISTRYD_STORE_OK);
    EXPECT_EQ(wal_size, first_wal_size);
    EXPECT_EQ(std::memcmp(g_wal_records[2], g_wal_records[3], wal_size), 0);
    EXPECT_EQ(RegistrydStoreCommitMutation(&store, &stale_token, &result), REGISTRYD_STORE_STALE_PREPARATION);
    EXPECT_EQ(RegistrydStoreCommitMutation(&store, &prepared, &result), REGISTRYD_STORE_OK);

    const auto deletion = Delete(1, 4, result.entry_generation, "HKLM\\SOFTWARE\\DUETOS", "ANSWER");
    Commit(store, deletion, g_wal_records[3]);
    RegistrydStoredValue missing{};
    EXPECT_EQ(RegistrydStoreQuery(&store, "HKLM\\SOFTWARE\\DUETOS", 20, "ANSWER", 6, &missing),
              REGISTRYD_STORE_NOT_FOUND);

    auto& first = g_stores[1];
    auto& second = g_stores[2];
    EXPECT_EQ(RegistrydStoreInitialize(&first), REGISTRYD_STORE_OK);
    EXPECT_EQ(RegistrydStoreInitialize(&second), REGISTRYD_STORE_OK);
    const std::uint8_t text[] = {'D', 'u', 'e', 't', 0};
    const auto mutation = Set(9, 1, 0, "HKCU\\SOFTWARE\\DUET", "NAME", REGISTRYD_VALUE_STRING, text, sizeof(text));
    const auto first_capture = Commit(first, mutation, g_wal_records[4]);
    const auto second_capture = Commit(second, mutation, g_wal_records[5]);
    EXPECT_EQ(first_capture.wal_size, second_capture.wal_size);
    EXPECT_EQ(std::memcmp(g_wal_records[4], g_wal_records[5], first_capture.wal_size), 0);

    std::uint32_t first_size = 0;
    std::uint32_t second_size = 0;
    EXPECT_EQ(RegistrydStoreEncodeSnapshot(&first, g_snapshots[0], sizeof(g_snapshots[0]), &first_size),
              REGISTRYD_STORE_OK);
    EXPECT_EQ(RegistrydStoreEncodeSnapshot(&first, g_snapshots[1], sizeof(g_snapshots[1]), &second_size),
              REGISTRYD_STORE_OK);
    EXPECT_EQ(first_size, second_size);
    EXPECT_EQ(std::memcmp(g_snapshots[0], g_snapshots[1], first_size), 0);
    EXPECT_EQ(RegistrydStoreEncodeSnapshot(&first, first.bytes, sizeof(first.bytes), &second_size),
              REGISTRYD_STORE_ALIASED_STORAGE);

    RegistrydRecoveryResult recovery{};
    auto& recovered = g_stores[3];
    EXPECT_EQ(RegistrydStoreRecover(&recovered, g_snapshots[0], first_size, nullptr, 0, &recovery), REGISTRYD_STORE_OK);
    EXPECT_EQ(Query(recovered, "hkcu\\software\\duet", "name").value[0], static_cast<std::uint8_t>('D'));
    EXPECT_EQ(RegistrydStoreEncodeSnapshot(&recovered, g_snapshots[2], sizeof(g_snapshots[2]), &second_size),
              REGISTRYD_STORE_OK);
    EXPECT_EQ(first_size, second_size);
    EXPECT_EQ(std::memcmp(g_snapshots[0], g_snapshots[2], first_size), 0);

    wal_size = 55;
    EXPECT_EQ(RegistrydStorePrepareMutation(&recovered, &mutation, g_wal_records[6], sizeof(g_wal_records[6]),
                                            &wal_size, &prepared, &result),
              REGISTRYD_STORE_DUPLICATE_REQUEST);
    EXPECT_EQ(wal_size, 0U);
}

void TestBoundsAndCapacity()
{
    auto& entries = g_stores[4];
    const std::uint8_t value[] = {7};
    EXPECT_EQ(RegistrydStoreInitialize(&entries), REGISTRYD_STORE_OK);
    for (std::uint32_t index = 0; index < REGISTRYD_STORE_MAX_ENTRIES; ++index)
    {
        char name[16]{};
        std::snprintf(name, sizeof(name), "VALUE%02u", index);
        const auto mutation =
            Set(100, index + 1U, 0, "HKLM\\CAPACITY", name, REGISTRYD_VALUE_BINARY, value, sizeof(value));
        Commit(entries, mutation, g_wal_records[0]);
    }
    auto overflow = Set(100, REGISTRYD_STORE_MAX_ENTRIES + 1U, 0, "HKLM\\CAPACITY", "OVERFLOW", REGISTRYD_VALUE_BINARY,
                        value, sizeof(value));
    RegistrydPreparedMutation prepared{};
    RegistrydMutationResult result{};
    std::uint32_t wal_size = 0;
    EXPECT_EQ(RegistrydStorePrepareMutation(&entries, &overflow, g_wal_records[0], sizeof(g_wal_records[0]), &wal_size,
                                            &prepared, &result),
              REGISTRYD_STORE_CAPACITY);

    auto& clients = g_stores[5];
    EXPECT_EQ(RegistrydStoreInitialize(&clients), REGISTRYD_STORE_OK);
    for (std::uint32_t index = 0; index < REGISTRYD_STORE_MAX_CLIENTS; ++index)
    {
        char name[16]{};
        std::snprintf(name, sizeof(name), "CLIENT%02u", index);
        const auto mutation =
            Set(index + 1U, 1, 0, "HKCU\\CLIENTS", name, REGISTRYD_VALUE_BINARY, value, sizeof(value));
        Commit(clients, mutation, g_wal_records[0]);
    }
    overflow = Set(999, 1, 0, "HKCU\\CLIENTS", "EXTRA", REGISTRYD_VALUE_BINARY, value, sizeof(value));
    EXPECT_EQ(RegistrydStorePrepareMutation(&clients, &overflow, g_wal_records[0], sizeof(g_wal_records[0]), &wal_size,
                                            &prepared, &result),
              REGISTRYD_STORE_CLIENT_CAPACITY);

    char oversized_key[REGISTRYD_STORE_MAX_KEY_BYTES + 2U]{};
    std::memset(oversized_key, 'A', sizeof(oversized_key));
    std::memcpy(oversized_key, "HKLM\\", 5);
    RegistrydMutation malformed{};
    malformed.client_identity = 1;
    malformed.request_id = 2;
    malformed.key = oversized_key;
    malformed.name = "VALUE";
    malformed.value = value;
    malformed.key_size = sizeof(oversized_key);
    malformed.name_size = 5;
    malformed.value_size = sizeof(value);
    malformed.value_type = REGISTRYD_VALUE_BINARY;
    malformed.operation = REGISTRYD_MUTATION_SET;
    EXPECT_EQ(RegistrydStorePrepareMutation(&clients, &malformed, g_wal_records[0], sizeof(g_wal_records[0]), &wal_size,
                                            &prepared, &result),
              REGISTRYD_STORE_INVALID_KEY);

    std::uint8_t oversized_value[REGISTRYD_STORE_MAX_VALUE_BYTES + 1U]{};
    malformed =
        Set(1, 2, 0, "HKLM\\VALUES", "TOO_BIG", REGISTRYD_VALUE_BINARY, oversized_value, sizeof(oversized_value));
    EXPECT_EQ(RegistrydStorePrepareMutation(&clients, &malformed, g_wal_records[0], sizeof(g_wal_records[0]), &wal_size,
                                            &prepared, &result),
              REGISTRYD_STORE_INVALID_VALUE);
}

void TestSnapshotWalRecoveryAndCorruption()
{
    auto& source = g_stores[6];
    const std::uint8_t one[] = {1, 0, 0, 0};
    const std::uint8_t two[] = {2, 0, 0, 0};
    const std::uint8_t three[] = {3, 0, 0, 0};
    EXPECT_EQ(RegistrydStoreInitialize(&source), REGISTRYD_STORE_OK);
    auto mutation = Set(55, 1, 0, "HKLM\\RECOVERY", "VALUE", REGISTRYD_VALUE_DWORD, one, sizeof(one));
    Commit(source, mutation, g_wal_records[0]);
    std::uint32_t snapshot_size = 0;
    EXPECT_EQ(RegistrydStoreEncodeSnapshot(&source, g_snapshots[3], sizeof(g_snapshots[3]), &snapshot_size),
              REGISTRYD_STORE_OK);

    mutation = Set(55, 2, 1, "HKLM\\RECOVERY", "VALUE", REGISTRYD_VALUE_DWORD, two, sizeof(two));
    const auto second = Commit(source, mutation, g_wal_records[1]);
    mutation = Set(55, 3, 2, "HKLM\\RECOVERY", "VALUE", REGISTRYD_VALUE_DWORD, three, sizeof(three));
    const auto third = Commit(source, mutation, g_wal_records[2]);
    std::memcpy(g_wal_chain, g_wal_records[1], second.wal_size);
    std::memcpy(g_wal_chain + second.wal_size, g_wal_records[2], third.wal_size);
    const auto chain_size = second.wal_size + third.wal_size;

    RegistrydRecoveryResult recovery{};
    auto& recovered = g_stores[7];
    EXPECT_EQ(RegistrydStoreRecover(&recovered, g_snapshots[3], snapshot_size, g_wal_chain, chain_size, &recovery),
              REGISTRYD_STORE_OK);
    EXPECT_EQ(recovery.wal_records, 2U);
    EXPECT_EQ(recovery.commit_sequence, 3ULL);
    EXPECT_EQ(Query(recovered, "hklm\\recovery", "value").value[0], 3U);

    auto& torn = g_stores[8];
    const auto torn_size = second.wal_size + third.wal_size / 2U;
    EXPECT_EQ(RegistrydStoreRecover(&torn, g_snapshots[3], snapshot_size, g_wal_chain, torn_size, &recovery),
              REGISTRYD_STORE_RECOVERED_TORN_WAL);
    EXPECT_EQ(recovery.wal_records, 1U);
    EXPECT_EQ(recovery.wal_bytes_consumed, second.wal_size);
    EXPECT_EQ(recovery.wal_bytes_ignored, third.wal_size / 2U);
    EXPECT_EQ(Query(torn, "HKLM\\RECOVERY", "VALUE").value[0], 2U);

    for (std::uint32_t cut = 1; cut < third.wal_size; ++cut)
    {
        std::memset(&torn, 0, sizeof(torn));
        const auto boundary_size = second.wal_size + cut;
        EXPECT_EQ(RegistrydStoreRecover(&torn, g_snapshots[3], snapshot_size, g_wal_chain, boundary_size, &recovery),
                  REGISTRYD_STORE_RECOVERED_TORN_WAL);
        EXPECT_EQ(recovery.wal_bytes_consumed, second.wal_size);
        EXPECT_EQ(recovery.wal_bytes_ignored, cut);
    }

    auto& corrupt = g_stores[9];
    RegistrydStoreInspection inspection{};
    for (std::uint32_t byte = 0; byte < third.wal_size; ++byte)
    {
        std::memset(&corrupt, 0, sizeof(corrupt));
        std::memcpy(g_wal_chain, g_wal_records[1], second.wal_size);
        std::memcpy(g_wal_chain + second.wal_size, g_wal_records[2], third.wal_size);
        g_wal_chain[second.wal_size + byte] ^= 1U;
        EXPECT_EQ(RegistrydStoreRecover(&corrupt, g_snapshots[3], snapshot_size, g_wal_chain, chain_size, &recovery),
                  REGISTRYD_STORE_CORRUPT_WAL);
        EXPECT_EQ(RegistrydStoreInspect(&corrupt, &inspection), REGISTRYD_STORE_NOT_INITIALIZED);
    }

    std::memset(&corrupt, 0, sizeof(corrupt));
    std::memcpy(g_wal_records[7], g_wal_records[1], second.wal_size);
    WriteLe64(g_wal_records[7] + 16U, 9U);
    RechecksumWal(g_wal_records[7], second.wal_size);
    EXPECT_EQ(
        RegistrydStoreRecover(&corrupt, g_snapshots[3], snapshot_size, g_wal_records[7], second.wal_size, &recovery),
        REGISTRYD_STORE_CORRUPT_WAL);

    auto& garbage = g_stores[10];
    const std::uint8_t bad_tail[] = {0xAA};
    EXPECT_EQ(RegistrydStoreRecover(&garbage, g_snapshots[3], snapshot_size, bad_tail, sizeof(bad_tail), &recovery),
              REGISTRYD_STORE_CORRUPT_WAL);

    auto& damaged_snapshot = g_stores[11];
    for (std::uint32_t byte = 0; byte < snapshot_size; ++byte)
    {
        std::memset(&damaged_snapshot, 0, sizeof(damaged_snapshot));
        std::memcpy(g_snapshots[4], g_snapshots[3], snapshot_size);
        g_snapshots[4][byte] ^= 1U;
        EXPECT_EQ(RegistrydStoreRecover(&damaged_snapshot, g_snapshots[4], snapshot_size, nullptr, 0, &recovery),
                  REGISTRYD_STORE_CORRUPT_SNAPSHOT);
        EXPECT_EQ(RegistrydStoreInspect(&damaged_snapshot, &inspection), REGISTRYD_STORE_NOT_INITIALIZED);
    }
    EXPECT_EQ(RegistrydStoreRecover(&damaged_snapshot, g_snapshots[3], snapshot_size - 1U, nullptr, 0, &recovery),
              REGISTRYD_STORE_CORRUPT_SNAPSHOT);
}

void TestGenerationExhaustion()
{
    auto& empty = g_stores[10];
    auto& recovered = g_stores[11];
    std::memset(&empty, 0, sizeof(empty));
    std::memset(&recovered, 0, sizeof(recovered));
    EXPECT_EQ(RegistrydStoreInitialize(&empty), REGISTRYD_STORE_OK);
    std::uint32_t snapshot_size = 0;
    EXPECT_EQ(RegistrydStoreEncodeSnapshot(&empty, g_snapshots[4], sizeof(g_snapshots[4]), &snapshot_size),
              REGISTRYD_STORE_OK);
    EXPECT_EQ(snapshot_size, 64U);

    RegistrydRecoveryResult recovery{};
    WriteLe64(g_snapshots[4] + 24U, std::numeric_limits<std::uint64_t>::max());
    WriteLe64(g_snapshots[4] + 32U, 0U);
    RechecksumSnapshot(g_snapshots[4], snapshot_size);
    EXPECT_EQ(RegistrydStoreRecover(&recovered, g_snapshots[4], snapshot_size, nullptr, 0, &recovery),
              REGISTRYD_STORE_OK);
    const std::uint8_t value[] = {1};
    auto mutation = Set(1, 1, 0, "HKLM\\LIMIT", "VALUE", REGISTRYD_VALUE_BINARY, value, sizeof(value));
    RegistrydPreparedMutation prepared{};
    RegistrydMutationResult result{};
    std::uint32_t wal_size = 0;
    EXPECT_EQ(RegistrydStorePrepareMutation(&recovered, &mutation, g_wal_records[0], sizeof(g_wal_records[0]),
                                            &wal_size, &prepared, &result),
              REGISTRYD_STORE_GENERATION_EXHAUSTED);

    std::memset(&recovered, 0, sizeof(recovered));
    WriteLe64(g_snapshots[4] + 24U, 0U);
    WriteLe64(g_snapshots[4] + 32U, std::numeric_limits<std::uint64_t>::max());
    RechecksumSnapshot(g_snapshots[4], snapshot_size);
    EXPECT_EQ(RegistrydStoreRecover(&recovered, g_snapshots[4], snapshot_size, nullptr, 0, &recovery),
              REGISTRYD_STORE_OK);
    EXPECT_EQ(RegistrydStorePrepareMutation(&recovered, &mutation, g_wal_records[0], sizeof(g_wal_records[0]),
                                            &wal_size, &prepared, &result),
              REGISTRYD_STORE_GENERATION_EXHAUSTED);
}

void TestConcurrentIndependentStores()
{
    // No API in this module is documented as safe for concurrent callers on
    // the *same* RegistrydStore -- "the registryd actor thread owns every
    // call" (registry_store.h). What must hold is the weaker, still load
    // bearing property: independent stores driven concurrently by
    // independent threads never interfere with each other, i.e. there is no
    // hidden shared mutable state (a stray `static` buffer, a shared
    // lookup table) behind the allocation-free facade. This drives many
    // threads, each owning one store and one WAL scratch buffer that no
    // other thread ever touches, and checks every store lands exactly where
    // a single-threaded run would have left it.
    constexpr std::size_t kThreadCount = 8;
    constexpr std::uint32_t kMutationsPerThread = 40;
    static RegistrydStore thread_stores[kThreadCount]{};

    std::vector<std::thread> threads;
    threads.reserve(kThreadCount);
    for (std::size_t slot = 0; slot < kThreadCount; ++slot)
    {
        threads.emplace_back(
            [slot]()
            {
                RegistrydStore& store = thread_stores[slot];
                std::uint8_t wal[REGISTRYD_STORE_MAX_WAL_RECORD_BYTES];
                EXPECT_EQ(RegistrydStoreInitialize(&store), REGISTRYD_STORE_OK);
                for (std::uint32_t index = 0; index < kMutationsPerThread; ++index)
                {
                    char name[16]{};
                    std::snprintf(name, sizeof(name), "VALUE%02u", index);
                    const std::uint8_t value[] = {static_cast<std::uint8_t>(slot), static_cast<std::uint8_t>(index)};
                    const auto mutation = Set(static_cast<std::uint64_t>(slot) + 1U, index + 1U, 0, "HKLM\\THREADRACE",
                                              name, REGISTRYD_VALUE_BINARY, value, sizeof(value));
                    Commit(store, mutation, wal);
                }
            });
    }
    for (auto& thread : threads)
    {
        thread.join();
    }

    for (std::size_t slot = 0; slot < kThreadCount; ++slot)
    {
        RegistrydStoreInspection inspection{};
        EXPECT_EQ(RegistrydStoreInspect(&thread_stores[slot], &inspection), REGISTRYD_STORE_OK);
        EXPECT_EQ(inspection.entry_count, kMutationsPerThread);
        EXPECT_EQ(inspection.client_count, 1U);
        EXPECT_EQ(inspection.commit_sequence, static_cast<std::uint64_t>(kMutationsPerThread));
        for (std::uint32_t index = 0; index < kMutationsPerThread; ++index)
        {
            char name[16]{};
            std::snprintf(name, sizeof(name), "VALUE%02u", index);
            const auto value = Query(thread_stores[slot], "HKLM\\THREADRACE", name);
            EXPECT_EQ(value.value_size, 2U);
            EXPECT_EQ(value.value[0], static_cast<std::uint8_t>(slot));
            EXPECT_EQ(value.value[1], static_cast<std::uint8_t>(index));
        }
    }
}

} // namespace

int main()
{
    TestValidationVersionsAndDedup();
    TestPrepareAbortDeleteAndDeterminism();
    TestBoundsAndCapacity();
    TestSnapshotWalRecoveryAndCorruption();
    TestGenerationExhaustion();
    TestConcurrentIndependentStores();
    return duetos_host_test::finish_main("registryd_store");
}
