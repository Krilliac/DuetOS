#include "net/wireless/beacon.h"

#include <cstddef>
#include <cstdint>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size > (1u << 16))
        return 0;
    duetos::net::wireless::BeaconParsed parsed;
    duetos::net::wireless::BeaconParse(reinterpret_cast<const duetos::u8*>(data), static_cast<duetos::u32>(size),
                                       &parsed);
    return 0;
}
