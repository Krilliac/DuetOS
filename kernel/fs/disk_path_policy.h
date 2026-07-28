#pragma once

#include "util/types.h"

namespace duetos::fs
{

inline bool ParseBoundedDiskPath(const char* path, u32 max_volumes, u32* out_idx, const char** out_rest)
{
    if (path == nullptr || out_idx == nullptr || out_rest == nullptr || max_volumes == 0)
        return false;
    if (path[0] != '/' || path[1] != 'd' || path[2] != 'i' || path[3] != 's' || path[4] != 'k' || path[5] != '/')
        return false;

    const char* cursor = path + 6;
    u32 index = 0;
    bool any = false;
    while (*cursor >= '0' && *cursor <= '9')
    {
        const u32 digit = static_cast<u32>(*cursor - '0');
        if (digit >= max_volumes || index > (max_volumes - 1 - digit) / 10)
            return false;
        index = index * 10 + digit;
        any = true;
        ++cursor;
    }
    if (!any || (*cursor != '/' && *cursor != '\0'))
        return false;

    *out_idx = index;
    *out_rest = cursor;
    return true;
}

} // namespace duetos::fs
