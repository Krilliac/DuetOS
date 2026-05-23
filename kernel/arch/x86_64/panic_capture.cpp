#include "arch/x86_64/panic_capture.h"

// C-linkage storage so the .S shim can reference it by an
// un-mangled name. Aligned to a cache line so the .S shim's
// quadword writes don't straddle two lines.
extern "C"
{
alignas(64) duetos::arch::PanicFrame panic_frame_raw{};
}

namespace duetos::arch
{

const PanicFrame* PanicFrameLast()
{
    return &panic_frame_raw;
}

PanicFrame* PanicFrameStorage()
{
    return &panic_frame_raw;
}

} // namespace duetos::arch
