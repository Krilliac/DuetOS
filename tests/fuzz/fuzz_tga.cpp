// DuetOS — TGA decoder fuzz harness.
//
// TgaParseHeader reads the 18-byte Truevision header (image
// type, dimensions, bpp, descriptor) off a .TGA wallpaper/icon
// ImageView opened — attacker-controlled bytes. The header
// validation lives in the memory-safe `duetos_img_meta` Rust
// crate; the C++ wrapper then runs TgaDecodeUncompressed, which
// walks the pixel area honouring the parsed offset/dimensions.
// The harness drives parse + (bounded) decode so both the Rust
// header walker and the C++ pixel copy / row-flip see hostile
// input.

#include "util/tga.h"

#include <cstddef>
#include <cstdint>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size < duetos::util::kTgaHeaderBytes || size > (1u << 20))
        return 0;

    const duetos::u8* src = reinterpret_cast<const duetos::u8*>(data);
    duetos::util::TgaInfo info = duetos::util::TgaParseHeader(src);
    if (!info.ok)
        return 0;

    // Decode needs width*height u32s of output. Cap the product
    // so a valid-but-huge header can't OOM the fuzzer (the parser
    // already enforces kTgaMaxDim per-axis; the product can still
    // be 256M px). 4M px == 16 MiB output is plenty for coverage.
    const duetos::u64 px = static_cast<duetos::u64>(info.width) * info.height;
    if (px == 0 || px > (4u * 1024u * 1024u))
        return 0;

    static duetos::u32 out[4u * 1024u * 1024u];
    // Fuzzer cares about crashes / out-of-bounds reads, not return
    // value — drop the Result intentionally. `.has_value()` keeps
    // the [[nodiscard]] contract honoured without further branching.
    (void)duetos::util::TgaDecodeUncompressed(src, static_cast<duetos::u32>(size), info, out).has_value();
    return 0;
}
