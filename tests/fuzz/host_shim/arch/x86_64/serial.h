#pragma once

#include "util/types.h"

namespace duetos::arch
{
// Fuzz harness: serial output is silent (would otherwise dominate
// fuzz throughput).
inline void SerialWrite(const char*) {}
inline void SerialWriteByte(u8) {}
inline void SerialWriteN(const char*, u64) {}
inline void SerialWriteHex(u64) {}
inline void SerialWriteHex(u32) {}
inline void SerialWriteHex(u16) {}
inline void SerialWriteHex(u8) {}

// RAII atomic-line lock in the real kernel; a no-op here (the
// fuzz harness is single-threaded and serial output is silenced).
class SerialLineGuard
{
  public:
    SerialLineGuard() = default;
    ~SerialLineGuard() = default;
    SerialLineGuard(const SerialLineGuard&) = delete;
    SerialLineGuard& operator=(const SerialLineGuard&) = delete;
    SerialLineGuard(SerialLineGuard&&) = delete;
    SerialLineGuard& operator=(SerialLineGuard&&) = delete;
};
} // namespace duetos::arch
