#include "net/wireless/eapol.h"

#include <cstddef>
#include <cstdint>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size > (1u << 16))
        return 0;
    duetos::net::wireless::EapolKeyFrame parsed;
    duetos::net::wireless::EapolKeyParse(reinterpret_cast<const duetos::u8*>(data), static_cast<duetos::u32>(size),
                                         &parsed);
    return 0;
}
