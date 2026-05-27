#pragma once

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

    enum
    {
        DUETOS_BCM_FW_TYPE_UCODE = 0x75,
        DUETOS_BCM_FW_TYPE_PCM = 0x70,
        DUETOS_BCM_FW_TYPE_IV = 0x69,
        DUETOS_BCM_FW_RECORD_HEADER_BYTES = 8,
        DUETOS_BCM_MAX_RECORDS = 8,
    };

    typedef struct DuetosBcmFwRecord
    {
        uint8_t type;
        uint8_t version;
        uint8_t _pad[2];
        uint32_t size;
        const uint8_t* payload;
    } DuetosBcmFwRecord;

    typedef struct DuetosBcmFirmwareParsed
    {
        bool valid;
        bool truncated;
        uint8_t _pad0[2];
        DuetosBcmFwRecord records[DUETOS_BCM_MAX_RECORDS];
        uint32_t record_count;
        // Pointer indices into the records array. Set to -1 (UINT32_MAX) when not present.
        uint32_t ucode_index;
        uint32_t pcm_index;
        uint32_t iv_index;
        uint32_t walked_bytes;
        uint32_t dropped_records;
    } DuetosBcmFirmwareParsed;

    // Returns 0 on Ok, 1 on InvalidArgument (null/short input), 2
    // on Corrupt. Always populates `parsed`.
    int32_t duetos_bcm43xx_fw_parse(const uint8_t* blob, uint32_t blob_size, DuetosBcmFirmwareParsed* parsed);

#ifdef __cplusplus
}
#endif
