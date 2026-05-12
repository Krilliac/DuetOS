#include "util/jpeg.h"

#include "img_meta_rust.h"

namespace duetos::util
{

JpegInfo JpegParseHeader(const u8* src, u32 src_len)
{
    // Header walking lives in the Rust crate `duetos_img_meta`.
    // Same segment hop pattern, same SOF marker classifier, same
    // SOS-before-SOF rejection, same dimension cap. The C++
    // wrapper does field-by-field copy on the way out so layout
    // drift between Rust and C++ can't silently break callers.
    JpegInfo info = {};
    img_meta::DuetosJpegInfo r{};
    if (!img_meta::duetos_img_meta_parse_jpeg(src, static_cast<usize>(src_len), &r))
        return info;
    info.width = r.width;
    info.height = r.height;
    info.precision = r.precision;
    info.components = r.components;
    info.sof_marker = r.sof_marker;
    info.ok = (r.ok != 0);
    return info;
}

} // namespace duetos::util
