#pragma once

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

    // reject_reason bit codes — mirror kNvFwReject* in
    // kernel/drivers/gpu/nvidia_gsp_fw.h.
    enum
    {
        DUETOS_NV_FW_REJECT_BLOB_TOO_SHORT = 1u << 0,
        DUETOS_NV_FW_REJECT_BAD_MAGIC = 1u << 1,
        DUETOS_NV_FW_REJECT_BAD_VERSION = 1u << 2,
        DUETOS_NV_FW_REJECT_HEADER_OFFSET = 1u << 3,
        DUETOS_NV_FW_REJECT_DATA_BOUNDS = 1u << 4,
        DUETOS_NV_FW_REJECT_DESC_TOO_SMALL = 1u << 5,
        DUETOS_NV_FW_REJECT_OVERSIZE = 1u << 6,
    };

    // arch_class enum values — mirror NvidiaGspArchClass.
    enum
    {
        DUETOS_NV_FW_ARCH_UNKNOWN = 0,
        DUETOS_NV_FW_ARCH_TURING_GA100 = 1,
        DUETOS_NV_FW_ARCH_GA102_PLUS = 2,
    };

    // Parsed view. Layout matches NvidiaGspFwParsed in
    // kernel/drivers/gpu/nvidia_gsp_fw.h. The C++ caller copies
    // fields into its public-API struct so the kernel-side
    // signature doesn't change.
    typedef struct DuetosNvidiaGspFwParsed
    {
        bool valid;

        uint32_t bin_magic;
        uint32_t bin_ver;
        uint32_t bin_size;
        uint32_t header_offset;
        uint32_t data_offset;
        uint32_t data_size;

        uint32_t descriptor_offset;
        uint32_t descriptor_size;
        uint8_t arch_class;
        uint8_t _pad0[3];

        const uint8_t* payload;
        uint32_t payload_size;

        bool payload_looks_elf;
        uint8_t _pad1[3];

        uint32_t reject_reason;
    } DuetosNvidiaGspFwParsed;

    // Returns 0 on Ok, 1 on InvalidArgument (null/short input),
    // 2 on Corrupt (structural check failed). `parsed` is always
    // populated; on error its reject_reason indicates which check
    // tripped.
    int32_t duetos_nvidia_gsp_fw_parse(const uint8_t* blob, uint32_t blob_size, DuetosNvidiaGspFwParsed* parsed);

#ifdef __cplusplus
}
#endif
