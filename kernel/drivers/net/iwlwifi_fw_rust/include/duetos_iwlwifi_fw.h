#pragma once

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

    enum
    {
        DUETOS_IWL_HUMAN_READABLE_LEN = 64,
    };

    typedef struct DuetosIwlFwSection
    {
        const uint8_t* data;
        uint32_t size;
        uint32_t _pad;
    } DuetosIwlFwSection;

    typedef struct DuetosIwlFirmwareParsed
    {
        bool valid;
        uint8_t _pad0[3];

        char human_readable[DUETOS_IWL_HUMAN_READABLE_LEN + 1];
        uint8_t _pad1[3]; // align to u32 boundary
        uint32_t ver_packed;
        uint32_t build;

        DuetosIwlFwSection inst;
        DuetosIwlFwSection data;
        DuetosIwlFwSection init;
        DuetosIwlFwSection init_data;
        DuetosIwlFwSection sec_rt_first;
        uint32_t sec_rt_count;

        uint32_t flags;
        uint32_t num_of_cpu;
        uint32_t fw_version;
        uint32_t phy_sku;
        uint32_t hw_type;

        uint32_t total_records;
        uint32_t unknown_records;
        uint32_t walked_bytes;
        uint32_t invalid_records;
    } DuetosIwlFirmwareParsed;

    int32_t duetos_iwlwifi_fw_parse(const uint8_t* blob, uint32_t blob_size, DuetosIwlFirmwareParsed* parsed);

#ifdef __cplusplus
}
#endif
