#pragma once

// Host fuzz shim for the DuetOS block layer. Serves the libFuzzer
// input as a single read-only disk so the real GPT parser
// (kernel/fs/gpt.cpp) walks attacker-controlled sector bytes —
// the exact threat model for any disk/USB stick plugged into a
// machine. The fuzz harness sets g_fuzz_block_img / _len before
// each GptProbe; everything here reads from that.

#include "util/result.h"
#include "util/types.h"

namespace duetos::fuzz
{
// Defined in the harness TU (fuzz_gpt.cpp).
extern const duetos::u8* g_fuzz_block_img;
extern duetos::u64 g_fuzz_block_len;
inline constexpr duetos::u32 kFuzzSectorSize = 512;
} // namespace duetos::fuzz

namespace duetos::drivers::storage
{

inline constexpr u32 kBlockHandleInvalid = 0xFFFFFFFFu;

inline u32 BlockDeviceCount()
{
    return 1;
}

inline const char* BlockDeviceName(u32)
{
    return "fuzz0";
}

inline u32 BlockDeviceSectorSize(u32)
{
    return ::duetos::fuzz::kFuzzSectorSize;
}

inline u64 BlockDeviceSectorCount(u32)
{
    return ::duetos::fuzz::g_fuzz_block_len / ::duetos::fuzz::kFuzzSectorSize;
}

inline bool BlockDeviceIsWritable(u32)
{
    return false;
}

// Real contract: returns 0 on success, non-zero on failure. The
// GPT reader treats any non-zero as "I/O error" and bails — so an
// out-of-range LBA here exercises gpt.cpp's read-failure path
// rather than over-reading the fuzz buffer.
inline i32 BlockDeviceRead(u32, u64 lba, u32 count, void* buf)
{
    const u64 ss = ::duetos::fuzz::kFuzzSectorSize;
    const u64 start = lba * ss;
    const u64 bytes = static_cast<u64>(count) * ss;
    if (count == 0 || start / ss != lba || start + bytes < start) // overflow
        return -1;
    if (start + bytes > ::duetos::fuzz::g_fuzz_block_len)
        return -1;
    auto* dst = static_cast<u8*>(buf);
    for (u64 i = 0; i < bytes; ++i)
        dst[i] = ::duetos::fuzz::g_fuzz_block_img[start + i];
    return 0;
}

inline i32 BlockDeviceWrite(u32, u64, u32, const void*)
{
    return -1; // read-only fuzz disk; GptInitDisk is not fuzzed
}

// Real contract: returns 0 on success. The fuzz disk is read-only, so a
// flush has nothing to commit — report success so the FS write paths that
// flush after a (no-op) write don't spuriously surface an I/O error.
inline i32 BlockDeviceFlush(u32)
{
    return 0;
}

inline u32 PartitionBlockDeviceCreate(const char*, u32, u64, u64)
{
    return 0;
}

inline u32 RamBlockDeviceCreate(const char*, u32, u64)
{
    return 0;
}

// Block-layer owned-write chokepoint registration. The kernel uses
// this to mark a DuetOS-owned partition as write-permitted; the
// fuzz harness has no write-enforcement layer, so it is a no-op.
inline void BlockOwnedRegionAdd(u32, u64, u64, const char*) {}

inline ::duetos::core::Result<void> TryBlockDeviceRead(u32 handle, u64 lba, u32 count, void* buf)
{
    if (BlockDeviceRead(handle, lba, count, buf) < 0)
        return ::duetos::core::Err{::duetos::core::ErrorCode::IoError};
    return {};
}

inline ::duetos::core::Result<void> TryBlockDeviceWrite(u32 handle, u64 lba, u32 count, const void* buf)
{
    if (BlockDeviceWrite(handle, lba, count, buf) < 0)
        return ::duetos::core::Err{::duetos::core::ErrorCode::IoError};
    return {};
}

} // namespace duetos::drivers::storage
