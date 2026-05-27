#pragma once

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

    enum
    {
        DUETOS_RTL_FW_HEADER_BYTES = 32,
        DUETOS_RTL_FW_GEN_UNKNOWN = 0,
        DUETOS_RTL_FW_GEN_RTLWIFI = 1,
        DUETOS_RTL_FW_GEN_RTW88 = 2,
        DUETOS_RTL_FW_GEN_RTW89 = 3,
    };

    typedef struct DuetosRtlFirmwareParsed
    {
        bool valid;
        uint8_t generation;
        uint8_t _pad0[2];

        uint16_t signature;
        uint8_t category;
        uint8_t function;
        uint16_t version;
        uint8_t subversion;
        uint8_t subsubversion;

        uint8_t date_month;
        uint8_t date_day;
        uint8_t date_hour;
        uint8_t date_minute;

        uint16_t ramcode_size;
        uint16_t _pad1;
        uint32_t svn_index;

        const uint8_t* payload;
        uint32_t payload_size;

        bool size_mismatch;
        uint8_t _pad2[3];
    } DuetosRtlFirmwareParsed;

    int32_t duetos_rtl88xx_fw_parse(const uint8_t* blob, uint32_t blob_size, DuetosRtlFirmwareParsed* parsed);

#ifdef __cplusplus
}
#endif
