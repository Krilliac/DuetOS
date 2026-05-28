// DuetOS — JPEG decoder fuzz harness.
//
// JpegParseHeader hops SOI → segment → segment until the first
// Start-of-Frame, validating every segment length against the
// remaining slice; JpegDecode then walks DHT/DQT/SOS, builds
// Huffman tables, and reconstructs MCUs. The bytes come from a
// .JPG ImageView opened — attacker-controlled. The header walk
// is the memory-safe `duetos_img_meta` Rust crate; the C++ side
// does the heavy decode. The harness drives parse + bounded
// decode so the Rust segment hopper and the C++ entropy decoder
// both see hostile input.

#include "util/jpeg.h"

#include <cstddef>
#include <cstdint>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size < 2 || size > (1u << 20))
        return 0;

    const duetos::u8* src = reinterpret_cast<const duetos::u8*>(data);
    duetos::util::JpegInfo info = duetos::util::JpegParseHeader(src, static_cast<duetos::u32>(size));
    if (!info.ok)
        return 0;

    const duetos::u64 px = static_cast<duetos::u64>(info.width) * info.height;
    if (px == 0 || px > (4ull * 1024u * 1024u))
        return 0;

    const duetos::u64 need = duetos::util::JpegEstimateScratch(info);
    static duetos::u8 scratch[24u * 1024u * 1024u];
    if (need > sizeof(scratch))
        return 0;

    static duetos::u32 out[4u * 1024u * 1024u];
    // Fuzzer cares about crashes / OOB reads, not the return value
    // — drop the Result intentionally. `.has_value()` keeps the
    // [[nodiscard]] contract honoured without further branching.
    (void)duetos::util::JpegDecode(src, static_cast<duetos::u32>(size), info, scratch, sizeof(scratch), out)
        .has_value();
    return 0;
}
