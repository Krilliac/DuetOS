#pragma once

#include <cassert>

#define KASSERT(cond, subsys, msg) assert((cond) && (subsys " :: " msg))
#define KASSERT_WITH_VALUE(cond, subsys, msg, value) assert((cond) && (subsys " :: " msg))

namespace duetos::core
{
inline void Panic(const char* /*subsystem*/, const char* /*message*/)
{
    assert(false);
}
inline void PanicWithValue(const char* /*subsystem*/, const char* /*message*/, unsigned long long /*value*/)
{
    assert(false);
}
} // namespace duetos::core
