#pragma once

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

    // reject_reason bit codes — mirror kAmdFwReject* in
    // kernel/drivers/gpu/amd_gfx_fw.h.
    enum
    {
        DUETOS_AMD_FW_REJECT_BLOB_TOO_SHORT = 1u << 0,
        DUETOS_AMD_FW_REJECT_HEADER_SHORT = 1u << 1,
        DUETOS_AMD_FW_REJECT_HEADER_INCONSISTENT = 1u << 2,
        DUETOS_AMD_FW_REJECT_UCODE_OVERFLOW = 1u << 3,
        DUETOS_AMD_FW_REJECT_JT_OVERFLOW = 1u << 4,
        DUETOS_AMD_FW_REJECT_OVERSIZE = 1u << 5,
    };

    typedef struct DuetosAmdGfxFwParsed
    {
        bool valid;
        bool is_v1_gfx_header;
        uint8_t _pad0[2];

        uint32_t size_bytes;
        uint32_t header_size_bytes;
        uint16_t header_version_major;
        uint16_t header_version_minor;
        uint16_t ip_version_major;
        uint16_t ip_version_minor;
        uint32_t ucode_version;
        uint32_t ucode_size_bytes;
        uint32_t ucode_array_offset;
        uint32_t crc32;

        uint32_t ucode_feature_version;
        uint32_t jt_offset_dwords;
        uint32_t jt_size_dwords;

        const uint32_t* ucode;
        uint32_t ucode_dword_count;

        uint32_t reject_reason;
    } DuetosAmdGfxFwParsed;

    // Returns 0 on Ok, 1 on InvalidArgument (null/short input), 2
    // on Corrupt (structural check failed). `parsed` is always
    // populated; on error its reject_reason indicates which check
    // tripped.
    int32_t duetos_amd_gfx_fw_parse(const uint8_t* blob, uint32_t blob_size, DuetosAmdGfxFwParsed* parsed);

#ifdef __cplusplus
}
#endif
