// DuetFS — Device builder helpers (memory + block-handle backed).
//
// The Rust crate's FFI takes a `Device` descriptor with read/write
// callbacks. This file provides the two backends the kernel uses:
//
//   1. MakeMemoryDevice  — points at a kernel-owned u8 buffer.
//      Used by the boot self-test scratch image.
//
//   2. MakeBlockHandleDevice — wraps a kernel block-device handle
//      (kernel/drivers/storage/block.h). Sector translation is
//      done here; Rust always sees 4 KiB blocks.
//
// Cookie storage: per-device. The memory backend's cookie is a
// pointer to a small struct kept in .bss; the block-handle backend
// stores the handle in the cookie pointer itself (cast through
// uptr to avoid a heap alloc).

#include "drivers/storage/block.h"
#include "fs/duetfs.h"
#include "fs/duetfs/include/duetfs.h"
#include "util/types.h"

namespace duetos::fs::duetfs
{

namespace
{

// ---- Memory backend -------------------------------------------------

struct MemCookie
{
    u8* buf;
    u32 block_count;
    bool read_only;
};

// One static cookie slot per concurrent memory device; v1 uses two
// (boot image + scratch image). Bumping this is a one-line change.
constexpr u32 kMaxMemDevices = 4;
MemCookie g_mem_cookies[kMaxMemDevices];
u32 g_mem_cookie_next = 0;

i32 MemRead(void* cookie, u32 lba, u8* dst)
{
    auto* c = static_cast<MemCookie*>(cookie);
    if (c == nullptr || lba >= c->block_count)
    {
        return -1;
    }
    const u8* src = c->buf + static_cast<usize>(lba) * kBlockSize;
    for (u32 i = 0; i < kBlockSize; ++i)
    {
        dst[i] = src[i];
    }
    return 0;
}

i32 MemWrite(void* cookie, u32 lba, const u8* src)
{
    auto* c = static_cast<MemCookie*>(cookie);
    if (c == nullptr || c->read_only || lba >= c->block_count)
    {
        return -1;
    }
    u8* dst = c->buf + static_cast<usize>(lba) * kBlockSize;
    for (u32 i = 0; i < kBlockSize; ++i)
    {
        dst[i] = src[i];
    }
    return 0;
}

// ---- Block-handle backend -------------------------------------------

i32 BlockHandleRead(void* cookie, u32 lba, u8* dst)
{
    const u32 handle = static_cast<u32>(reinterpret_cast<uptr>(cookie));
    const u32 ssz = drivers::storage::BlockDeviceSectorSize(handle);
    if (ssz == 0 || (kBlockSize % ssz) != 0)
    {
        return -1;
    }
    const u32 sectors_per_block = kBlockSize / ssz;
    const u64 sector_lba = static_cast<u64>(lba) * sectors_per_block;
    return drivers::storage::BlockDeviceRead(handle, sector_lba, sectors_per_block, dst);
}

i32 BlockHandleWrite(void* cookie, u32 lba, const u8* src)
{
    const u32 handle = static_cast<u32>(reinterpret_cast<uptr>(cookie));
    const u32 ssz = drivers::storage::BlockDeviceSectorSize(handle);
    if (ssz == 0 || (kBlockSize % ssz) != 0)
    {
        return -1;
    }
    const u32 sectors_per_block = kBlockSize / ssz;
    const u64 sector_lba = static_cast<u64>(lba) * sectors_per_block;
    return drivers::storage::BlockDeviceWrite(handle, sector_lba, sectors_per_block, src);
}

} // namespace

Device MakeMemoryDevice(u8* buf, usize len, bool read_only)
{
    if (g_mem_cookie_next >= kMaxMemDevices)
    {
        // Out of cookie slots — return a Device the crate will reject.
        return Device{nullptr, 0, 1, nullptr, nullptr};
    }
    MemCookie& c = g_mem_cookies[g_mem_cookie_next++];
    c.buf = buf;
    c.block_count = static_cast<u32>(len / kBlockSize);
    c.read_only = read_only;
    return Device{
        .cookie = &c,
        .block_count = c.block_count,
        .read_only = read_only ? 1u : 0u,
        .read = &MemRead,
        .write = &MemWrite,
    };
}

Device MakeBlockHandleDevice(u32 block_handle)
{
    const u32 ssz = drivers::storage::BlockDeviceSectorSize(block_handle);
    const u64 sector_count = drivers::storage::BlockDeviceSectorCount(block_handle);
    if (ssz == 0 || (kBlockSize % ssz) != 0 || sector_count == 0)
    {
        return Device{nullptr, 0, 1, nullptr, nullptr};
    }
    const u32 sectors_per_block = kBlockSize / ssz;
    const u32 block_count = static_cast<u32>(sector_count / sectors_per_block);
    const bool read_only = !drivers::storage::BlockDeviceIsWritable(block_handle);
    return Device{
        .cookie = reinterpret_cast<void*>(static_cast<uptr>(block_handle)),
        .block_count = block_count,
        .read_only = read_only ? 1u : 0u,
        .read = &BlockHandleRead,
        .write = &BlockHandleWrite,
    };
}

bool ProbeBlockHandle(u32 block_handle)
{
    const Device dev = MakeBlockHandleDevice(block_handle);
    return duetfs_probe(&dev) != 0;
}

} // namespace duetos::fs::duetfs
