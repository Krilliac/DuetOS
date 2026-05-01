#include "drivers/net/rtl88xx_fw.h"

#include <cstddef>
#include <cstdint>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size > (1u << 20))
        return 0;
    duetos::drivers::net::RtlFirmwareParsed parsed;
    duetos::drivers::net::RtlFirmwareParse(reinterpret_cast<const duetos::u8*>(data), static_cast<duetos::u32>(size),
                                           &parsed);
    return 0;
}
