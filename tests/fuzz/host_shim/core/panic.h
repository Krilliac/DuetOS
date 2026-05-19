#pragma once

#include <cassert>

#define KASSERT(cond, subsys, msg) assert((cond) && (subsys " :: " msg))
#define KASSERT_WITH_VALUE(cond, subsys, msg, value) assert((cond) && (subsys " :: " msg))

namespace duetos::core
{
// The real core/panic.h declares these [[noreturn]]; mirror that
// so a [[noreturn]] caller (e.g. util/string.cpp's bounds-check
// abort) doesn't warn "function should not return". assert() is
// not noreturn under NDEBUG, so trap unconditionally afterwards.
[[noreturn]] inline void Panic(const char* /*subsystem*/, const char* /*message*/)
{
    assert(false);
    __builtin_trap();
}
[[noreturn]] inline void PanicWithValue(const char* /*subsystem*/, const char* /*message*/,
                                        unsigned long long /*value*/)
{
    assert(false);
    __builtin_trap();
}
} // namespace duetos::core
