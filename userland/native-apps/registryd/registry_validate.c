#include "registry_store_internal.h"

static char UpperAscii(char value)
{
    if (value >= 'a' && value <= 'z')
    {
        return (char)(value - ('a' - 'A'));
    }
    return value;
}

static int RootIsAllowed(const char* key, uint16_t root_size)
{
    static const char* const roots[] = {"HKLM", "HKCU", "HKCR", "HKU", "HKCC"};
    static const uint8_t sizes[] = {4U, 4U, 4U, 3U, 4U};
    uint32_t root;
    for (root = 0; root < (uint32_t)(sizeof(roots) / sizeof(roots[0])); ++root)
    {
        if (root_size == sizes[root] && RegistrydStoreInternalEqual(key, roots[root], root_size))
        {
            return 1;
        }
    }
    return 0;
}

static int ComponentIsDot(const char* text, uint16_t start, uint16_t size)
{
    return size == 1U ? text[start] == '.' : (size == 2U && text[start] == '.' && text[start + 1U] == '.');
}

RegistrydStoreStatus RegistrydStoreInternalNormalizeKey(const char* input, uint32_t size, char* output,
                                                        uint16_t* out_size)
{
    uint16_t component_start = 0;
    uint16_t root_size = 0;
    uint32_t index;
    if (input == NULL || output == NULL || out_size == NULL || size == 0U || size > REGISTRYD_STORE_MAX_KEY_BYTES)
    {
        return REGISTRYD_STORE_INVALID_KEY;
    }
    for (index = 0; index < size; ++index)
    {
        const unsigned char raw = (unsigned char)input[index];
        if (raw < 0x20U || raw >= 0x7FU || raw == '/' || raw == '*' || raw == '?' || raw == '"' || raw == '<' ||
            raw == '>' || raw == '|' || raw == ':')
        {
            return REGISTRYD_STORE_INVALID_KEY;
        }
        output[index] = UpperAscii((char)raw);
        if (raw == '\\')
        {
            const uint16_t component_size = (uint16_t)index - component_start;
            if (component_size == 0U || ComponentIsDot(output, component_start, component_size))
            {
                return REGISTRYD_STORE_INVALID_KEY;
            }
            if (root_size == 0U)
            {
                root_size = (uint16_t)index;
            }
            component_start = (uint16_t)index + 1U;
        }
    }
    if (component_start == size || ComponentIsDot(output, component_start, (uint16_t)size - component_start))
    {
        return REGISTRYD_STORE_INVALID_KEY;
    }
    if (root_size == 0U)
    {
        root_size = (uint16_t)size;
    }
    if (!RootIsAllowed(output, root_size))
    {
        return REGISTRYD_STORE_INVALID_KEY;
    }
    output[size] = '\0';
    *out_size = (uint16_t)size;
    return REGISTRYD_STORE_OK;
}

RegistrydStoreStatus RegistrydStoreInternalNormalizeName(const char* input, uint32_t size, char* output,
                                                         uint16_t* out_size)
{
    uint32_t index;
    if (output == NULL || out_size == NULL || size > REGISTRYD_STORE_MAX_NAME_BYTES || (size != 0U && input == NULL))
    {
        return REGISTRYD_STORE_INVALID_NAME;
    }
    for (index = 0; index < size; ++index)
    {
        const unsigned char raw = (unsigned char)input[index];
        if (raw < 0x20U || raw >= 0x7FU || raw == '\\' || raw == '/' || raw == '*' || raw == '?' || raw == '"' ||
            raw == '<' || raw == '>' || raw == '|')
        {
            return REGISTRYD_STORE_INVALID_NAME;
        }
        output[index] = UpperAscii((char)raw);
    }
    if (ComponentIsDot(output, 0U, (uint16_t)size))
    {
        return REGISTRYD_STORE_INVALID_NAME;
    }
    output[size] = '\0';
    *out_size = (uint16_t)size;
    return REGISTRYD_STORE_OK;
}

static RegistrydStoreStatus ValidateValue(uint32_t type, const uint8_t* value, uint32_t size)
{
    if (size > REGISTRYD_STORE_MAX_VALUE_BYTES || (size != 0U && value == NULL))
    {
        return REGISTRYD_STORE_INVALID_VALUE;
    }
    if (type == REGISTRYD_VALUE_NONE || type == REGISTRYD_VALUE_STRING || type == REGISTRYD_VALUE_EXPAND_STRING ||
        type == REGISTRYD_VALUE_BINARY || type == REGISTRYD_VALUE_MULTI_STRING)
    {
        return REGISTRYD_STORE_OK;
    }
    if (type == REGISTRYD_VALUE_DWORD || type == REGISTRYD_VALUE_QWORD)
    {
        return size == (type == REGISTRYD_VALUE_DWORD ? 4U : 8U) ? REGISTRYD_STORE_OK : REGISTRYD_STORE_INVALID_VALUE;
    }
    return REGISTRYD_STORE_INVALID_TYPE;
}

RegistrydStoreStatus RegistrydStoreInternalCanonicalize(const RegistrydMutation* input,
                                                        RegistrydCanonicalMutation* output)
{
    RegistrydStoreStatus status;
    uint32_t index;
    if (input == NULL || output == NULL)
    {
        return REGISTRYD_STORE_NULL_ARGUMENT;
    }
    for (index = 0; index < sizeof(input->reserved8); ++index)
    {
        if (input->reserved8[index] != 0U)
        {
            return REGISTRYD_STORE_INVALID_OPERATION;
        }
    }
    if (input->client_identity == 0U || input->request_id == 0U)
    {
        return REGISTRYD_STORE_REPLAYED_REQUEST;
    }
    RegistrydStoreInternalZero(output, sizeof(*output));
    output->client_identity = input->client_identity;
    output->request_id = input->request_id;
    output->expected_entry_generation = input->expected_entry_generation;
    output->operation = input->operation;
    status = RegistrydStoreInternalNormalizeKey(input->key, input->key_size, output->key, &output->key_size);
    if (status != REGISTRYD_STORE_OK)
    {
        return status;
    }
    status = RegistrydStoreInternalNormalizeName(input->name, input->name_size, output->name, &output->name_size);
    if (status != REGISTRYD_STORE_OK)
    {
        return status;
    }
    if (input->operation == REGISTRYD_MUTATION_DELETE)
    {
        if (input->value_type != REGISTRYD_VALUE_NONE || input->value_size != 0U || input->value != NULL)
        {
            return REGISTRYD_STORE_INVALID_VALUE;
        }
    }
    else if (input->operation == REGISTRYD_MUTATION_SET)
    {
        status = ValidateValue(input->value_type, input->value, input->value_size);
        if (status != REGISTRYD_STORE_OK)
        {
            return status;
        }
        output->value_type = input->value_type;
        output->value_size = (uint16_t)input->value_size;
        RegistrydStoreInternalCopy(output->value, input->value, input->value_size);
    }
    else
    {
        return REGISTRYD_STORE_INVALID_OPERATION;
    }
    output->fingerprint = RegistrydStoreInternalFingerprint(output);
    return REGISTRYD_STORE_OK;
}

static uint64_t HashBytes(uint64_t hash, const void* data, size_t size)
{
    const uint8_t* bytes = (const uint8_t*)data;
    size_t index;
    for (index = 0; index < size; ++index)
    {
        hash ^= bytes[index];
        hash *= UINT64_C(1099511628211);
    }
    return hash;
}

static uint64_t HashU64(uint64_t hash, uint64_t value)
{
    uint8_t bytes[8];
    uint32_t index;
    for (index = 0; index < 8U; ++index)
    {
        bytes[index] = (uint8_t)(value >> (index * 8U));
    }
    return HashBytes(hash, bytes, sizeof(bytes));
}

uint64_t RegistrydStoreInternalFingerprint(const RegistrydCanonicalMutation* mutation)
{
    uint64_t hash = UINT64_C(14695981039346656037);
    if (mutation == NULL)
    {
        return 0U;
    }
    hash = HashU64(hash, mutation->client_identity);
    hash = HashU64(hash, mutation->request_id);
    hash = HashU64(hash, mutation->expected_entry_generation);
    hash = HashU64(hash, mutation->operation);
    hash = HashU64(hash, mutation->value_type);
    hash = HashU64(hash, mutation->key_size);
    hash = HashU64(hash, mutation->name_size);
    hash = HashU64(hash, mutation->value_size);
    hash = HashBytes(hash, mutation->key, mutation->key_size);
    hash = HashBytes(hash, mutation->name, mutation->name_size);
    return HashBytes(hash, mutation->value, mutation->value_size);
}

int RegistrydStoreInternalMutationIsExact(const RegistrydCanonicalMutation* left,
                                          const RegistrydCanonicalMutation* right)
{
    return left->client_identity == right->client_identity && left->request_id == right->request_id &&
           left->expected_entry_generation == right->expected_entry_generation && left->operation == right->operation &&
           left->value_type == right->value_type && left->key_size == right->key_size &&
           left->name_size == right->name_size && left->value_size == right->value_size &&
           RegistrydStoreInternalEqual(left->key, right->key, left->key_size) &&
           RegistrydStoreInternalEqual(left->name, right->name, left->name_size) &&
           RegistrydStoreInternalEqual(left->value, right->value, left->value_size);
}

int RegistrydStoreInternalCanonicalIsValid(const RegistrydCanonicalMutation* mutation)
{
    RegistrydMutation public_mutation;
    RegistrydCanonicalMutation copy;
    if (mutation == NULL || mutation->key_size > REGISTRYD_STORE_MAX_KEY_BYTES ||
        mutation->name_size > REGISTRYD_STORE_MAX_NAME_BYTES || mutation->value_size > REGISTRYD_STORE_MAX_VALUE_BYTES)
    {
        return 0;
    }
    RegistrydStoreInternalZero(&public_mutation, sizeof(public_mutation));
    public_mutation.client_identity = mutation->client_identity;
    public_mutation.request_id = mutation->request_id;
    public_mutation.expected_entry_generation = mutation->expected_entry_generation;
    public_mutation.key = mutation->key;
    public_mutation.name = mutation->name;
    public_mutation.value = mutation->operation == REGISTRYD_MUTATION_DELETE ? NULL : mutation->value;
    public_mutation.key_size = mutation->key_size;
    public_mutation.name_size = mutation->name_size;
    public_mutation.value_size = mutation->value_size;
    public_mutation.value_type = mutation->value_type;
    public_mutation.operation = mutation->operation;
    return RegistrydStoreInternalCanonicalize(&public_mutation, &copy) == REGISTRYD_STORE_OK &&
           RegistrydStoreInternalMutationIsExact(mutation, &copy) && mutation->fingerprint == copy.fingerprint;
}

int RegistrydStoreInternalEntryIsValid(const RegistrydSnapshotEntry* entry, uint64_t last_generation)
{
    char key[REGISTRYD_STORE_MAX_KEY_BYTES + 1U];
    char name[REGISTRYD_STORE_MAX_NAME_BYTES + 1U];
    uint16_t key_size;
    uint16_t name_size;
    return entry != NULL && entry->active == 1U && entry->entry_generation != 0U &&
           entry->entry_generation <= last_generation && entry->key_size <= REGISTRYD_STORE_MAX_KEY_BYTES &&
           entry->name_size <= REGISTRYD_STORE_MAX_NAME_BYTES && entry->value_size <= REGISTRYD_STORE_MAX_VALUE_BYTES &&
           RegistrydStoreInternalNormalizeKey(entry->key, entry->key_size, key, &key_size) == REGISTRYD_STORE_OK &&
           RegistrydStoreInternalNormalizeName(entry->name, entry->name_size, name, &name_size) == REGISTRYD_STORE_OK &&
           key_size == entry->key_size && name_size == entry->name_size &&
           RegistrydStoreInternalEqual(key, entry->key, key_size + 1U) &&
           RegistrydStoreInternalEqual(name, entry->name, name_size + 1U) &&
           ValidateValue(entry->value_type, entry->value, entry->value_size) == REGISTRYD_STORE_OK;
}

const char* RegistrydStoreStatusName(RegistrydStoreStatus status)
{
    static const char* const names[] = {"ok",
                                        "recovered_torn_wal",
                                        "null_argument",
                                        "aliased_storage",
                                        "already_initialized",
                                        "not_initialized",
                                        "corrupt_state",
                                        "invalid_key",
                                        "invalid_name",
                                        "invalid_type",
                                        "invalid_value",
                                        "invalid_operation",
                                        "capacity",
                                        "client_capacity",
                                        "not_found",
                                        "version_conflict",
                                        "duplicate_request",
                                        "request_id_conflict",
                                        "replayed_request",
                                        "request_id_exhausted",
                                        "generation_exhausted",
                                        "pending_mutation",
                                        "no_pending_mutation",
                                        "stale_preparation",
                                        "buffer_too_small",
                                        "corrupt_snapshot",
                                        "corrupt_wal"};
    const uint32_t index = (uint32_t)status;
    return index < (uint32_t)(sizeof(names) / sizeof(names[0])) ? names[index] : "unknown";
}
