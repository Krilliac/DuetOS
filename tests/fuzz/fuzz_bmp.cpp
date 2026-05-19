// DuetOS — BMP header parser fuzz harness.
//
// BmpParseHeader reads the 14-byte BITMAPFILEHEADER + DIB header
// off the front of a .BMP that ImageView opened from the FAT32
// root — attacker-controlled bytes. The byte-level validation
// (signature, DIB size, dimension caps, top-down flag) lives in
// the memory-safe `duetos_img_meta` Rust crate; this harness
// drives the C++ wrapper so a Rust-side bounds/overflow bug also
// aborts as a libFuzzer crash.

#include "util/bmp.h"

#include <cstddef>
#include <cstdint>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    // Parser reads the fixed 54-byte canonical header; anything
    // shorter can't form one.
    if (size < duetos::util::kBmpHeaderBytes || size > (1u << 16))
        return 0;

    (void)duetos::util::BmpParseHeader(reinterpret_cast<const duetos::u8*>(data));
    return 0;
}
