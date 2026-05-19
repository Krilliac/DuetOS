// DuetOS — DEFLATE inflater fuzz harness.
//
// DeflateInflate consumes a raw RFC-1951 bit stream — stored,
// fixed-Huffman, dynamic-Huffman — that arrives from inside a
// PNG IDAT, a gzip/zlib wrapper, or a ZIP entry, i.e. fully
// attacker-controlled bytes. The harness drives the real
// inflater into a fixed output buffer; libFuzzer + ASan catch
// OOB reads on the bit stream, Huffman-table overruns, and
// LZ77 back-reference distances that point before the window.

#include "util/deflate.h"

#include <cstddef>
#include <cstdint>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size > (1u << 20))
        return 0;

    // 256 KiB output ceiling: large enough that a legitimate
    // stream decompresses, bounded so a decompression-bomb input
    // can't wedge the fuzzer on allocation.
    static duetos::u8 out[256u * 1024u];
    (void)duetos::util::DeflateInflate(reinterpret_cast<const duetos::u8*>(data), static_cast<duetos::u32>(size), out,
                                       sizeof(out));
    return 0;
}
