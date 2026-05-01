#pragma once

#include "util/types.h"

namespace duetos::arch
{
// Fuzz harness: serial output is silent (would otherwise dominate
// fuzz throughput).
inline void SerialWrite(const char*) {}
inline void SerialWriteHex(u64) {}
inline void SerialWriteHex(u32) {}
inline void SerialWriteHex(u16) {}
inline void SerialWriteHex(u8) {}
} // namespace duetos::arch
