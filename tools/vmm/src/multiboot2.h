// Multiboot2 information structure builder. boot.S enters in 32-bit
// protected mode expecting EAX = 0x36D76289 and EBX -> this blob.
// We emit only the tags DuetOS consumes: cmdline (1), basic-meminfo
// (4), memory-map (6), framebuffer (8), ACPI-new RSDP (15), end (0).
#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace duetos::vmm
{

constexpr uint32_t kMultiboot2BootloaderMagic = 0x36D76289;

struct Mb2Params
{
    std::string          cmdline;
    uint64_t             ramBytes = 0;
    // [0, reservedEnd) is marked reserved in the e820/mmap so the
    // kernel's frame allocator never reclaims the firmware blobs,
    // ACPI tables, the MB2 info itself, or the loaded kernel image.
    uint64_t             reservedEnd = 0;
    std::vector<uint8_t> rsdp;       // 36-byte ACPI 2.0 RSDP

    // Framebuffer (multiboot2 tag 8). Emitted only when fbAddr != 0.
    // 32bpp BGRA (blue at bit 0) so the host StretchDIBits path needs
    // no per-pixel swizzle.
    uint64_t fbAddr   = 0;
    uint32_t fbPitch  = 0; // bytes per scanline
    uint32_t fbWidth  = 0;
    uint32_t fbHeight = 0;
    uint8_t  fbBpp    = 32;
};

// Returns the serialised Multiboot2 information blob (8-byte aligned,
// length-prefixed) to be written verbatim into guest RAM.
std::vector<uint8_t> BuildMultiboot2Info(const Mb2Params& p);

} // namespace duetos::vmm
