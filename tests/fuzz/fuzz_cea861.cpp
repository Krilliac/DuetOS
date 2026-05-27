// DuetOS — CEA-861 EDID-extension-block parser fuzz harness.
//
// Cea861ParseBlock walks a 128-byte CEA-861 (a.k.a. CTA-861)
// extension block referenced from EDID 1.4 byte 126 ("number of
// extension blocks"). The Data Block Collection walks audio /
// video / vendor-specific / speaker-allocation / extended tags,
// each with its own byte-length-prefixed sub-walker — exactly
// the TLV recursion shape that historically eats vendor drivers.
// "Pure compute, no allocations, no IRQ" per cea861.h.

#include "drivers/gpu/cea861.h"

#include <cstddef>
#include <cstdint>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size > 4096)
        return 0;

    (void)duetos::drivers::gpu::Cea861ParseBlock(reinterpret_cast<const duetos::u8*>(data),
                                                 static_cast<duetos::u64>(size));
    return 0;
}
