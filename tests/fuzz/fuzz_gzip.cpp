// DuetOS — GZIP / zlib wrapper fuzz harness.
//
// GzipInflate (RFC 1952) and ZlibInflate (RFC 1950) parse a
// variable-length header + a trailing checksum around the
// DEFLATE inflater. The header (FLG/MTIME/XFL/OS, optional
// FEXTRA/FNAME/FCOMMENT/FHCRC fields; zlib CMF/FLG + preset
// dictionary bit) is attacker-controlled — a gzip-compressed
// initramfs or an HTTP Content-Encoding payload. The harness
// splits the first input byte to pick which wrapper to exercise
// so one corpus covers both header walkers and both checksum
// gates (CRC-32 / Adler-32) on hostile input.

#include "util/gzip.h"

#include <cstddef>
#include <cstdint>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size < 1 || size > (1u << 20))
        return 0;

    const bool use_zlib = (data[0] & 1u) != 0;
    const duetos::u8* body = reinterpret_cast<const duetos::u8*>(data) + 1;
    const duetos::u32 body_len = static_cast<duetos::u32>(size - 1);

    static duetos::u8 out[256u * 1024u];
    if (use_zlib)
        (void)duetos::util::ZlibInflate(body, body_len, out, sizeof(out));
    else
        (void)duetos::util::GzipInflate(body, body_len, out, sizeof(out));
    return 0;
}
