#pragma once

#include "util/types.h"

namespace duetos::fs::fat32::internal
{

inline constexpr u64 kFat32MaxFileSize = 0xFFFFFFFFull;

// Compute offset + len without ever evaluating an overflowing addition.
// `limit` is inclusive: an end exactly at the FAT32 32-bit size ceiling is
// valid. The caller may safely use `*out_end` only after a true result.
[[nodiscard]] constexpr bool CheckedWriteEnd(u64 offset, u64 len, u64 limit, u64* out_end)
{
    if (out_end == nullptr || offset > limit || len > limit - offset)
        return false;
    *out_end = offset + len;
    return true;
}

} // namespace duetos::fs::fat32::internal
