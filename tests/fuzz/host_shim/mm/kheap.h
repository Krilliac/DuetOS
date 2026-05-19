#pragma once

// Host fuzz shim for the kernel heap. The GPT parse path
// (GptProbe) uses static .bss scratch buffers and never calls
// these; only the write path (GptInitDisk, not fuzzed) does. They
// exist so the gpt.cpp TU links — back them with the host
// allocator so ASan still tracks any (unexpected) use.

#include "util/types.h"

#include <cstdlib>

namespace duetos::mm
{
inline void* KMalloc(u64 bytes)
{
    return std::malloc(bytes);
}
inline void KFree(void* ptr)
{
    std::free(ptr);
}
} // namespace duetos::mm
