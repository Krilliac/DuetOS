// DuetOS — PNG decoder fuzz harness.
//
// PngParseHeader validates the 8-byte signature + IHDR (+ IHDR
// CRC); PngDecode walks the IDAT chunks, runs each through
// zlib-wrapped DEFLATE, and unwinds the per-scanline filter. The
// bytes are a .PNG ImageView opened — attacker-controlled. The
// IHDR validation is the memory-safe `duetos_img_meta` Rust
// crate; the chunk walk + zlib + filter unwind are C++ (and pull
// the real util/gzip + util/deflate + util/crc32 + util/adler32,
// so this harness also re-exercises those on PNG-shaped input).

#include "util/png.h"

#include <cstddef>
#include <cstdint>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size < duetos::util::kPngSignatureBytes || size > (1u << 20))
        return 0;

    const duetos::u8* src = reinterpret_cast<const duetos::u8*>(data);
    duetos::util::PngInfo info = duetos::util::PngParseHeader(src, static_cast<duetos::u32>(size));
    if (!info.ok)
        return 0;

    const duetos::u64 px = static_cast<duetos::u64>(info.width) * info.height;
    if (px == 0 || px > (4ull * 1024u * 1024u))
        return 0;

    // Upper bound from png.h: src_len + (width*4 + 1) * height.
    const duetos::u64 need =
        static_cast<duetos::u64>(size) + (static_cast<duetos::u64>(info.width) * 4u + 1u) * info.height;
    static duetos::u8 scratch[24u * 1024u * 1024u];
    if (need > sizeof(scratch))
        return 0;

    static duetos::u32 out[4u * 1024u * 1024u];
    // Fuzzer cares about crashes / out-of-bounds reads, not return
    // value — drop the Result intentionally. `.has_value()` keeps
    // the [[nodiscard]] contract honoured without further branching.
    (void)duetos::util::PngDecode(src, static_cast<duetos::u32>(size), info, scratch, sizeof(scratch), out).has_value();
    return 0;
}
