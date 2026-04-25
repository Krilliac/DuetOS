#pragma once

#include "types.h"

namespace duetos::core
{

inline constexpr u32 kCleanroomTraceCapacity = 256;
inline constexpr u32 kCleanroomTraceTextMax = 31;

struct CleanroomTraceEntry
{
    char subsystem[kCleanroomTraceTextMax + 1];
    char event[kCleanroomTraceTextMax + 1];
    u64 a;
    u64 b;
    u64 c;
};

void CleanroomTraceRecord(const char* subsystem, const char* event, u64 a, u64 b, u64 c);
u32 CleanroomTraceCount();
bool CleanroomTraceRead(u32 index, CleanroomTraceEntry* out);
void CleanroomTraceClear();
u64 CleanroomTraceHashToken(const char* text);

} // namespace duetos::core
